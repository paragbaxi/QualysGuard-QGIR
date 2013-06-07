try:
  from xml.etree import ElementTree
except ImportError:
  from elementtree import ElementTree
import gdata.spreadsheet.service
import gdata.service
import atom.service
import gdata.spreadsheet
import atom
# My imports
import argparse
import datetime
import ConfigParser
import operator
import pygooglechart
import jira
import logging
import os
import re
import string
from collections import defaultdict
import cluster
import numpy
import colorsys




def PrintFeed2(feed):
    values = defaultdict((lambda : defaultdict(str)))
    for i, entry in enumerate(feed.entry):
        if isinstance(feed, gdata.spreadsheet.SpreadsheetsCellsFeed):
            print '%s %s\n' % (entry.title.text, entry.content.text)
        elif isinstance(feed, gdata.spreadsheet.SpreadsheetsListFeed):
#            print '%s %s %s' % (i, entry.title.text, entry.content.text)
#            # Print this row's value for each column (the custom dictionary is
#            # built from the gsx: elements in the entry.) See the description of
#            # gsx elements in the protocol guide.
#            print 'Contents:'
#            for key in entry.custom:
#              print '  %s: %s' % (key, entry.custom[key].text)
#            print '\n',
            logging.debug('%s = %s' % (entry.custom['office'].text, entry.custom['vulnsreported'].text))
            # Add all numbers
            if is_number(entry.custom['vulnsreported'].text):
                values[entry.custom['office'].text]['vulns_reported'] = int(entry.custom['vulnsreported'].text)
                values[entry.custom['office'].text]['percent_vulns_closed'] = round(float(entry.custom['percentvulnsclosed'].text[:-1]), 1)
        else:
            print '%s %s\n' % (i, entry.title.text)
    logging.debug('values = %s' % (values))
    # Convert to flat tuple for K-Means Clustering.
    data = []
    for item in values:
        data.append((1, values[item]['vulns_reported']))
    # Cluster into 5 groups.
    cl = cluster.KMeansClustering(data)
    clusters = cl.getclusters(5)
    # Remove tuple value.
    sorted_clusters = defaultdict(list)
    for c in clusters:
        values_stripped = []
        for i in c:
            values_stripped.append(i[1])
            # What's the range?
        sorted_clusters['%s-%s' % (str(min(values_stripped)), str(max(values_stripped)))] = values_stripped
    logging.debug('sorted_clusters = %s' % (sorted_clusters))
    # Reassociate values with sites and sort.
    cluster_sites = defaultdict(list)
    for c in sorted_clusters:
        for i in sorted_clusters[c]:
            for site in values:
                if i == values[site]['vulns_reported']:
                    cluster_sites[c].append({'site': site, 'vulns_reported': i, 'percent_vulns_closed': values[site]['percent_vulns_closed']})
                    values = remove_key(values, site)
                    break
#            matching_sites = [k for k, v in values.iteritems() if v == i[0]]
#            for site in matching_sites:
#                cluster_sites[c].append({'site': site, 'vulns_reported': i, 'percent_vulns_closed': values[site]['percent_vulns_closed']})
#                remove_key(values, site)
    logging.debug('cluster_sites = %s' % (cluster_sites))
    # Sort values.
    for c in cluster_sites:
        cluster_sites[c] = sorted(cluster_sites[c], key = operator.itemgetter('site'), reverse = True)
    # Obtain associated percentages of vulnerabilities closed.
    logging.debug('cluster_sites = %s' % (cluster_sites))
    # Print values and charts.
    for c in cluster_sites:
        print '%s: %s sites' % (c, str(len(sorted_clusters[c])))
        chart_bar_width = 15
        chart = pygooglechart.GroupedHorizontalBarChart(596, len(sorted_clusters[c]) * (chart_bar_width + 8) + 60, y_range = (c[:c.find('-')], c[c.find('-') + 1:]))
        chart.set_bar_width(chart_bar_width)
        chart_data = []
        chart_labels = []
        for i in cluster_sites[c]:
            print '%s (%s)  ' % (i['site'], str(i['percent_vulns_closed'])),
            print i
            chart_data.append(i['percent_vulns_closed'])
            chart_labels.append(i['site'])
#        print 'chart_data = ', chart_data
#        print 'chart_labels = ', chart_labels
#        print 'chart.data = ', chart.data
        chart.set_axis_labels(pygooglechart.Axis.LEFT, chart_labels)
        chart.set_axis_labels(pygooglechart.Axis.BOTTOM, ['0%', '20%', '40%', '60%', '80%', '100%'])
        print
        url = chart.get_url()
        # Add distinct colors.
        colors = _get_colors2(len(chart_data))
        url += '&chco='
        # Format to Google Charts API.
        for d in colors:
            url += '%s|' % (d[1:])
        url = url[:-1]
        # Add title with date.
        url += '&chtt=Sites+issued+%s+to+%s+vulnerabilities+for+%s' % (c[:c.find('-')], c[c.find('-') + 1:], datetime.datetime.today().strftime('%B %d, %Y').replace(' ', '+'))
        # Add chart data manually.
#        chart.add_data(chart_data)
        chart_data_url = ''
        chart_data.reverse()
        for v in chart_data:
#            print 'Add %s' % (v)
            chart_data_url += '%s,' % (str(v))
        chart_data_url = chart_data_url[:-1]
        # Add values to url.
        url += '&chd=t:%s' % chart_data_url
        # Add markers to url.
        url += '&chm=N+**%,000000,0,-1,11'
        print url
        print '\n'
    return True


def _get_colors(num_colors):
    colors = []
    for i in numpy.arange(0., 360., 360. / num_colors):
        hue = i / 360.
        lightness = (50 + numpy.random.rand() * 10) / 100.
        saturation = (90 + numpy.random.rand() * 10) / 100.
        rgb = colorsys.hls_to_rgb(hue, lightness, saturation)
        # Convert to Hex.
        rgb = (rgb[0] * 255, rgb[1] * 255, rgb[2] * 255)
        hex = '#%02x%02x%02x' % rgb
        colors.append(hex)
    return colors



def _get_colors2(num_colors):
    colors = []
    HSV_tuples = [(x * 1.0 / num_colors, 0.5, 0.5) for x in range(num_colors)]
    RGB_tuples = map(lambda x: colorsys.hsv_to_rgb(*x), HSV_tuples)
    for rgb in RGB_tuples:
        # Convert to Hex.
        rgb = (rgb[0] * 255, rgb[1] * 255, rgb[2] * 255)
        hex = '#%02x%02x%02x' % rgb
        colors.append(hex)
    return colors




def remove_key(d, key):
    """Deletes key and returns a new dictionary, after making a copy of the dictionary."""
    r = dict(d)
    del r[key]
    return r


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False
    except TypeError:
        return False

def PrintFeed(feed):
    for i, entry in enumerate(feed.entry):
        if isinstance(feed, gdata.spreadsheet.SpreadsheetsCellsFeed):
            print '%s %s\n' % (entry.title.text, entry.content.text)
        elif isinstance(feed, gdata.spreadsheet.SpreadsheetsListFeed):
            print '%s %s %s' % (i, entry.title.text, entry.content.text)
            # Print this row's value for each column (the custom dictionary is
            # built from the gsx: elements in the entry.) See the description of
            # gsx elements in the protocol guide.
            print 'Contents:'
            for key in entry.custom:
              print '  %s: %s' % (key, entry.custom[key].text)
            print '\n',
        else:
            print '%s %s\n' % (i, entry.title.text)
    return True


def jira_issues(feed, issue_type, priority, summary, description):
    """Print offices from Google Docs to screen."""
    # Go row by row of Google spreadsheet.
    print issue_type, priority, summary, description
    for i, entry in enumerate(feed.entry):
        try:
            region = entry.custom['region'].text
            office = '%s - %s' % (region, entry.custom['office'].text)
            print office
            print region, entry.custom['itdirectore-mail'].text, entry.custom['reactionimpactedlocation'].text
            #jira_create(region, issue_type, entry.custom['itdirectore-mail'].text, priority, summary, description, entry.custom['reactionimpactedlocation'].text)
        except AttributeError:
            None
    return True


def index_of_first_digit(s):
    m = re.search("\d", s)
    if m:
        return m.start()
    #No digit in that string.
    return False


def gdocs_column_to_number(c):
    """Return number corresponding to excel-style column."""
    number = -25
    for l in c:
        if not l in string.ascii_letters:
            return False
        number += ord(l.upper()) - 64 + 25
    return number


def gdocs_column_headers(feed):
    gdocs_headers = defaultdict(str)
    for i, entry in enumerate(feed.entry):
        cell = ''.join(entry.content.text.replace('%', '').lower().split())
        cell_id = entry.title.text
        cell_column = cell_id[:index_of_first_digit(cell_id)]
        if not cell_id[index_of_first_digit(cell_id)] == '1':
            break
        # print '%s %s\n' % (cell_id, ''.join(cell.lower().split()))
        gdocs_headers[cell] = gdocs_column_to_number(cell_column)
    return gdocs_headers


def search_feed2(feed, column, query):
    found = False
    for i, entry in enumerate(feed.entry):
        if entry.custom[column].text == query:
            found = i
            print entry
            print
            print '%s %s %s' % (i, entry.title.text, entry.content.text)
            # Print this row's value for each column (the custom dictionary is
            # built from the gsx: elements in the entry.) See the description of
            # gsx elements in the protocol guide.
            print 'Contents:'
            for key in entry.custom:
              print '  %s: %s' % (key, entry.custom[key].text)
            print '\n',
            break
    return found


def gdocs_search_office(feed, which_office):
    found = False
    for i, entry in enumerate(feed.entry):
        if '%s - %s' % (entry.custom['region'].text, entry.custom['office'].text) == which_office:
            found = i
            break
    return found


def gdocs_update_office(feed, which_office, column, data):
    found = False
    for i, entry in enumerate(feed.entry):
        if '%s - %s' % (entry.custom['region'].text, entry.custom['office'].text) == which_office:
            found = i + 2
            entry.custom[column].text = data
            #ListUpdateAction2(i, entry)
            CellsUpdateAction2(found, gdocs_headers[column], data)
            break
    return found


def ListUpdateAction2(index, row_data):
  global gd_client, gdocs_key, wksht_id
  feed = gd_client.GetListFeed(gdocs_key, wksht_id)
  entry = gd_client.UpdateRow(
      feed.entry[string.atoi(index)],
      StringToDictionary(row_data))
  if isinstance(entry, gdata.spreadsheet.SpreadsheetsList):
    print 'Updated!'


def CellsGetAction(gd_client, key, wksht_id):
  # Get the feed of cells
  feed = gd_client.GetCellsFeed(key, wksht_id)
  return feed


def ListGetAction(gd_client, key, wksht_id):
  # Get the list feed
  feed = gd_client.GetListFeed(key, wksht_id)
  return feed


def StringToDictionary(row_data):
  result = {}
  for param in row_data.split():
    name, value = param.split('=')
    result[name] = value
  return result


def CellsUpdateAction(gd_client, key, wksht_id, row, col, inputValue):
  entry = gd_client.UpdateCell(row = row, col = col, inputValue = inputValue,
      key = key, wksht_id = wksht_id)
  if isinstance(entry, gdata.spreadsheet.SpreadsheetsCell):
    print 'Updated!'


def CellsUpdateAction2(row, col, inputValue):
    global gd_client, gdocs_key, wksht_id
    entry = gd_client.UpdateCell(row = row, col = col, inputValue = inputValue,
        key = gdocs_key, wksht_id = wksht_id)
    if isinstance(entry, gdata.spreadsheet.SpreadsheetsCell):
        print 'Updated!'
        return True
    else:
        return False


def ConfigSectionMap(section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1


# Declare the command line flags/options we want to allow.
parser = argparse.ArgumentParser(description = 'Learn to integrate Google Spreadsheets with JIRA.')
parser.add_argument('-c', '--config', default = 'config.ini',
                    help = 'Configuration file for login & JIRA issues.')
parser.add_argument('-d', '--description',
                    help = 'Specify description for JIRA issues.')
parser.add_argument('-j', '--jira', action = 'store_true',
                    help = 'Create JIRA issues.')
parser.add_argument('-p', '--priority', default = '3',
                    help = 'Specify priority for JIRA issues (default = Medium).')
parser.add_argument('-s', '--summary',
                    help = 'Specify summary for JIRA issues.')
parser.add_argument('-t', '--test', action = 'store_true',
                    help = 'Test on rm2 tracker copy.')
parser.add_argument('-y', '--issue_type', default = '14',
                    help = 'Specify issue type for JIRA issues (default = Service Request).')
# Parse arguments.
c_args = parser.parse_args()
# Start
# Read from configuration file.
Config = ConfigParser.ConfigParser()
Config.read(c_args.config)
# Google login information
gd_client = gdata.spreadsheet.service.SpreadsheetsService()
gd_client.email = ConfigSectionMap('Google')['username']
gd_client.password = ConfigSectionMap('Google')['password']
gd_client.source = 'exampleCo-exampleApp-1'
gd_client.ProgrammaticLogin()
# JIRA login information
jira_username = ConfigSectionMap('JIRA')['username']
jira_password = ConfigSectionMap('JIRA')['password']
print 'Logged in...'
# Actual rm2 tracker.
gdocs_key = ConfigSectionMap('Google')['qgir_report']
if c_args.test:
    # Copy of rm2 tracker.
    gdocs_key = ConfigSectionMap('Google')['gdocs_key_test']
# Worksheet number.
wksht_id = 4
# Get cell feed for numbering column headers.
feed = CellsGetAction(gd_client, gdocs_key, '1')
gdocs_headers = gdocs_column_headers(feed)
#for key in gdocs_headers:
#    print '%s %s' % (key, gdocs_headers[key])
# Get list feed.
feed = gd_client.GetListFeed(gdocs_key, wksht_id)
# Check for issue command
# Print feed
PrintFeed2(feed)
# Do something with feed.
#office = 'NA - New York'
#print gdocs_search_office(feed, office)
#search_feed2(feed, 'office', 'New York')
#gdocs_update_office(feed, office, 'sev.5ticketsissued', '1')
