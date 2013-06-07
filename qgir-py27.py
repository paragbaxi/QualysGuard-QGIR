#!/usr/bin/env python

'''Issue Jira incidents of QualysGuard reports.

Available functions:
function_name(parameters)
    description

Examples:
>>> qg_jirajira.issue('New York')
15 P1s have been issued.

'''

'''To do:
Add flag for sev3-5 vulnerabilities to delete instead of always assuming yes to them.
Add commenting to tickets.
'''

import argparse
import csv
import datetime
import itertools
import jira
import json
import logging
import lxml.html
import os
import re
import sqlite3
import string
import subprocess
import sys
import time
import types
import urllib
import urllib2
import unicodedata
from collections import defaultdict
from collections import OrderedDict
from lxml import etree
from lxml import objectify
from operator import itemgetter
from suds.client import Client
from types import NoneType
# Google API services
try:
  from xml.etree import ElementTree
except ImportError:
  from elementtree import ElementTree
import atom
import gdata.spreadsheet.service
import gdata.service
import atom.service
import gdata.spreadsheet
import unicodedata


def qg_ticket_list(asset_group, severity, qids = None):
    """Return dictionary of each vulnerability reported against asset_group of severity."""
    global asset_group_details, c_args
    # All vulnerabilities imported to list of dictionaries.
    vulns = qg_remediation_tickets(asset_group, 'OPEN', qids)    # vulns now holds all open remediation tickets.
    if not vulns:
        # No tickets to report.
        return False
    #
    # Sort the vulnerabilities in order of prevalence -- number of hosts affected.
    vulns = OrderedDict(sorted(vulns.items(), key = lambda t: len(t[1]['hosts'])))
    logging.debug('vulns sorted = %s' % (vulns))
    #
    # Remove QIDs that have duplicate patches.
    #
    # Read in patch report.
    # TODO:  Allow for lookup of report_template.
    # Report template is Patch report "Sev 5 confirmed patchable".
    logging.debug('Retrieving patch report from QualysGuard.')
    print 'Retrieving patch report from QualysGuard.'
    report_template = '1063695'
    # Call QualysGuard for patch report.
    csv_output = qg_command(2, 'report', {'action': 'launch', 'output_format': 'csv', 'asset_group_ids':asset_group_details['qg_asset_group_id'], 'template_id':report_template, 'report_title':'QGIR Patch %s' % (asset_group)})
    logging.debug('csv_output =')
    logging.debug(csv_output)
    # Check for debug_qg_xml parameter, and do not report vulns.
    if c_args.debug_qg_xml:
        # Write vulns xml file to disk.
        filename = 'debug/' + ('debug-vulns-%s-info-%s.txt' % (asset_group, datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))).replace('/', '-')
        print 'Vulnerabilities: %s' % (filename)
        with open(filename, 'w') as f:
            f.write(vulns)
        # Write patch CSV file to disk.
        filename = 'debug/' + ('debug-patch_csv-%s-info-%s.csv' % (asset_group, datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))).replace('/', '-')
        print 'Patch CSV file: %s' % (filename)
        return False
    logging.debug('Improving remediation efficiency by removing unneeded, redundant patches.')
    print 'Improving remediation efficiency by removing unneeded, redundant patches.'
    # Find the line for Patches by Host data.
    starting_pos = csv_output.find('Patch QID, IP, DNS, NetBIOS, OS, OS CPE, Vulnerability Count') + 60
    logging.debug('Header found at %s.' % str(starting_pos - 60))
    logging.debug('starting_pos = %s' % str(starting_pos))
    # Data resides between line ending in 'Vulnerability Count' and a blank line.
    patches_by_host = csv_output[starting_pos:csv_output[starting_pos:].find('Host Vulnerabilities Fixed by Patch') + starting_pos - 3]
    logging.debug('patches_by_host =')
    logging.debug(patches_by_host)
    # Read in string patches_by_host csv to a dictionary.
    f = patches_by_host.split(os.linesep)
    reader = csv.DictReader(f, ['Patch QID', 'IP', 'DNS', 'NetBIOS', 'OS', ' OS CPE', 'Vulnerability Count'], delimiter = ',')
    # Mark Patch QIDs that fix multiple vulnerabilities with associated IP addresses.
    redundant_qids = defaultdict(list)
    for row in reader:
        logging.debug(row)
        if int(row['Vulnerability Count']) > 1:
            # Add to list of redundant QIDs.
            redundant_qids[row['Patch QID']].append(row['IP'])
            logging.debug('%s, %s, %s, %s' % (row['Patch QID'], row['IP'], int(row['Vulnerability Count']), redundant_qids[row['Patch QID']]))
    # Log for debugging.
    logging.debug('len(redundant_qids) = %s, redundant_qids =' % (len(redundant_qids)))
    for patch_qid in redundant_qids.keys():
        logging.debug('%s, %s' % (str(patch_qid), str(redundant_qids[patch_qid])))
    # Extract redundant QIDs with associated IP addresses.
    # Find the line for Patches by Host data.
    starting_pos = csv_output.find('Patch QID, IP, QID, Severity, Type, Title, Instance, Last Detected') + 66
    # Data resides between line ending in 'Vulnerability Count' and end of string.
    host_vulnerabilities_fixed_by_patch = csv_output[starting_pos:]
    # Read in string host_vulnerabilities_fixed_by_patch csv to a dictionary.
    f = host_vulnerabilities_fixed_by_patch.split(os.linesep)
    reader = csv.DictReader(f, ['Patch QID', 'IP', 'QID', 'Severity', 'Type', 'Title', 'Instance', 'Last Detected'], delimiter = ',')
    # Remove IP addresses associated with redundant QIDs.
    qids_to_remove = defaultdict(list)
    for row in reader:
        # If the row's IP address's Patch QID was found to have multiple vulnerabilities... 
        if len(redundant_qids[row['Patch QID']]) > 0 and redundant_qids[row['Patch QID']].count(row['IP']) > 0:
            # Add the QID column to the list of dictionaries {QID: [IP address, IP address, ...], QID2: [IP address], ...}
            qids_to_remove[row['QID']].append(row['IP'])
    # Log for debugging.
    logging.debug('len(qids_to_remove) = %s, qids_to_remove =' % (len(qids_to_remove)))
    for a_qid in qids_to_remove.keys():
        logging.debug('%s, %s' % (str(a_qid), str(qids_to_remove[a_qid])))
    #
    # Diff vulns against qids_to_remove and against open incidents.
    #
    vulns_length = len(vulns)
    # Iterate over list of keys rather than original dictionary as some keys may be deleted changing the size of the dictionary.
    for a_qid in vulns.keys():
        # Debug log original qid's hosts.
        logging.debug('Before diffing vulns[%s] =' % (a_qid))
        logging.debug(vulns[a_qid]['hosts'])
        # Pop each host.
        # The [:] returns a "slice" of x, which happens to contain all its elements, and is thus effectively a copy of x.
        for host in vulns[a_qid]['hosts'][:]:
            # If the QID for the host is a dupe or if a there is an open Jira incident.
            if qids_to_remove[a_qid].count(host['ip']) > 0 or jira_open_issue(host['vuln_id']):
                # Remove the host from the QID's list of target hosts.
                logging.debug('Removing remediation ticket %s.' % (host['vuln_id']))
                vulns[a_qid]['hosts'].remove(host)
            else:
                # Do not remove this vuln
                logging.debug('Will report remediation %s.' % (host['vuln_id']))
        # Debug log diff'd qid's hosts.
        logging.debug('After diffing vulns[%s]=' % (a_qid))
        logging.debug(vulns[a_qid]['hosts'])
        # If there are no more hosts left to patch for the qid.
        if len(vulns[a_qid]['hosts']) == 0:
            # Remove the QID.
            logging.debug('Deleting vulns[%s].' % (a_qid))
            del vulns[a_qid]
    # Diff completed
    if not vulns_length == len(vulns):
        print 'A count of %s vulnerabilities have been consolidated to %s vulnerabilities, a reduction of %s%%.' % (int(vulns_length), int(len(vulns)), int(round((int(vulns_length) - int(len(vulns))) / float(vulns_length) * 100)))
    else:
        print 'A count of %s vulnerabilities will be issued.' % (int(len(vulns)))
    #
    # scanning
    #rt open
    #1.  rt not issued
    #        issue new (keep in vulns)
    #2.  rt issued open
    #        do not issue
    #3a. rt issued resolved, ticket not validated
    #        mark ticket for validation
    #3b. rt issued resolved, ticket validated/closed
    #        issue new (keep in vulns)
    #
    #val-check
    #resolve
    #scheduled scan (validate before issuing)
    #val-check
    #
    #rt closed/fixed
    #1.  rt not issued
    #        ignore
    #2.  rt issued open
    #        ignore
    #3.  rt issued resolved
    #        validate
    #4.  rt issued closed
    #        ignore
    #
    #rt closed/ignore
    #1.  rt not issued
    #    ignore
    #2.  rt issued open
    #    ignore host, mark to reissue CSV
    #3.  rt issued resolved
    #    ignore
    #4.  rt issued closed
    #    ignore
    #
    # Return vulns to report.
    logging.debug('vulns =')
    logging.debug(vulns)
    return vulns


def qg_remediation_tickets(asset_group, states, qids = None):
    """Return defaultdict of all vulnerabilities of status STATUS."""
    global qg_username, qg_password
#    asset_group's vulnerability data map:
#    {'qid_number': {
#                    # CSV info
#                    'hosts': [{'ip': '10.28.0.1', 'dns': 'hostname', 'netbios': 'blah', 'vuln_id': 'remediation_ticket_number'}, {'ip': '10.28.0.3', 'dns': 'hostname2', 'netbios': '', 'vuln_id': 'remediation_ticket_number'}, ...],
#                    'solution': '',
#                    'impact': '',
#                    'threat': '', 
#                    'severity': '',
#                   }
#     'qid_number2': ...
#     }
    # Add all vulnerabilities to list of dictionaries.
    vulns = defaultdict(dict)
    # Start searching at initial ticket #1.
    since_ticket_number = 1
    while True:
        command_parameter = 'show_vuln_details=1&states=%s&asset_groups=%s&since_ticket_number=%s' % (states, asset_group.replace(' ', '+'), since_ticket_number)
        if not qids == None:
            command_parameter += '&qids=%s' % (qids)
        args_sub = [
            'curl',
            '-H', 'X-Requested-With: QGIR',
            '-d', command_parameter,
            'https://%s:%s@qualysapi.qualys.com/msp/ticket_list.php' % (qg_username, qg_password)
        ]
        logging.debug('args_sub: %s' % (args_sub))
        # Call API.
        # TODO:  Incorporate timeout of 5 minutes.
        xml_output = subprocess.check_output(args_sub)
        logging.debug('qg_remediation_tickets.xml_output =')
        logging.debug(xml_output)
        # Objectify XML.
        tree = objectify.fromstring(xml_output)
        # Parse vulnerabilities.
        try:
            for ticket in tree.TICKET_LIST.TICKET:
                # Use defaultdict in case a new QID is encountered.
                # Extract possible extra hostname information.
                try:
                    netbios = unicodedata.normalize('NFKD', unicode(ticket.DETECTION.NBHNAME)).encode('ascii', 'ignore').strip()
                except AttributeError:
                    netbios = ''
                try:
                    dns = unicodedata.normalize('NFKD', unicode(ticket.DETECTION.DNSNAME)).encode('ascii', 'ignore').strip()
                except AttributeError:
                    dns = ''
                try:
                    result = unicodedata.normalize('NFKD', unicode(ticket.DETAILS.RESULT)).encode('ascii', 'ignore').strip()
                except AttributeError:
                    result = ''
                vuln_id = unicodedata.normalize('NFKD', unicode(ticket.NUMBER)).encode('ascii', 'ignore').strip()
                ip = unicodedata.normalize('NFKD', unicode(ticket.DETECTION.IP)).encode('ascii', 'ignore').strip()
                qid = unicodedata.normalize('NFKD', unicode(ticket.VULNINFO.QID)).encode('ascii', 'ignore').strip()
                # Attempt to add host to QID's list of affected hosts.
                try:
                    vulns[qid]['hosts'].append({'ip': '%s' % (ip),
                                                            'dns': '%s' % (dns),
                                                            'netbios': '%s' % (netbios),
                                                            'vuln_id': '%s' % (vuln_id),
                                                            'result': '%s' % (result), })
                except KeyError:
                    # New QID.
                    logging.debug('New QID found: %s' % (qid))
                    vulns[qid]['hosts'] = []
                    vulns[qid]['hosts'].append({'ip': '%s' % (ip),
                                                            'dns': '%s' % (dns),
                                                            'netbios': '%s' % (netbios),
                                                            'vuln_id': '%s' % (vuln_id),
                                                            'result': '%s' % (result), })
                    # Add all other qid information
                    vulns[qid]['title'] = unicodedata.normalize('NFKD', unicode(ticket.VULNINFO.TITLE)).encode('ascii', 'ignore').strip()
                    vulns[qid]['severity'] = unicodedata.normalize('NFKD', unicode(ticket.VULNINFO.SEVERITY)).encode('ascii', 'ignore').strip()
                    vulns[qid]['solution'] = qg_html_to_ascii(unicodedata.normalize('NFKD', unicode(ticket.DETAILS.SOLUTION)).encode('ascii', 'ignore').strip())
                    vulns[qid]['threat'] = qg_html_to_ascii(unicodedata.normalize('NFKD', unicode(ticket.DETAILS.DIAGNOSIS)).encode('ascii', 'ignore').strip())
                    vulns[qid]['impact'] = qg_html_to_ascii(unicodedata.normalize('NFKD', unicode(ticket.DETAILS.CONSEQUENCE)).encode('ascii', 'ignore').strip())
        except AttributeError, e:
            logging.debug('No QualysGuard tickets to report.')
            return False
        # All vulnerabilities added.
        try:
            # See if the API call was truncated due to API limit of 1000 records at a time.
            since_ticket_number = tree.TRUNCATION.get('last')
        except AttributeError:
            # No more API calls necessary.
            break
#    logging.debug('initial xml vulns = %s' % (vulns))
    # 
    # vulns now holds all remediation tickets.
    return vulns


def jira_open_issue(remediation_number):
    """Return true if remediation vuln_id already exists in Jirajira in an open issue."""
    global conn
    global cursor
    # Fetch issues
    unresolved_remediation_tickets = cursor.execute('SELECT COUNT(*) FROM remediation WHERE remediation_ticket = ? LIMIT 1', (remediation_number,)).fetchall()[0][0]
    logging.debug('unresolved_remediation_tickets = %s' % (unresolved_remediation_tickets))
    if unresolved_remediation_tickets > 0:
        logging.debug('Ticket %s already open.' % (remediation_number))
        return True
    logging.debug('Ticket %s not open.' % (remediation_number))
    return False


def jira_report(vulns, flag_info = False):
    """Create incident files for each vulnerability."""
    # Keep track of how many vulnerabilities issued.
    total_issues = 0
    # While there are more vulnerabilities.
    while len(vulns) > 0:
        # Create issue from top of vulnerabilities queue and increment number of issues issued.
        vuln = vulns.popitem()
        # vuln is ('qid#', {'solution': 'Solution.', ...})
        modified_vuln = vuln[1]
        modified_vuln['qid'] = vuln[0]
        # vuln is {'qid': #, solution: 'Solution', ...}
        if not jira_report_vuln(modified_vuln, flag_info):
            # Did not create a issue.
            continue
        # Issue created, increment issue counter.
        total_issues += 1
        # Stop creating issues if we have hit the maximum.
        if total_issues >= c_args.max and not c_args.max == None:
            logging.info("Maximum creation of issues reached.")
            print "Maximum creation of issues reached."
            break
    # Completed all QIDs
    return total_issues


def qg_ag_list():
    """Return list of dictionaries of current QualysGuard asset groups with their associated QualysGuard asset group id #.
       Example:
       [{'office': 'NA - New York', 'id': 902109}, ... ]
    """
    logging.debug('qg_ag_list()')
    xml_output = qg_command(1, 'asset_group_list')
    logging.debug('QualysGuard asset_group_list XML = ')
    logging.debug(xml_output)
    # Objectify XML string.
    tree = objectify.fromstring(xml_output)
    # Parse tree for each asset group title.
    logging.debug('Parsing XML asset group report...')
    qg_ag = []
    for a in tree.ASSET_GROUP:
        # Extract asset group titles.
        try:
            qg_ag.append({'office': unicodedata.normalize('NFKD', unicode(a.TITLE.text)).encode('ascii', 'ignore').strip(), 'id': unicodedata.normalize('NFKD', unicode(a.ID.text)).encode('ascii', 'ignore').strip()})
        except AttributeError:
            print 'Could not decipher:  %s' % (a.TITLE.text)
    # Sort asset groups.
    qg_ag = sorted(qg_ag, key = itemgetter('office'))
    return qg_ag


def asset_group_lookup(asset_group):
    """Return parameters of asset_group for creating an issue in JIRA."""
    global c_args, qg_asset_groups
    param = False
    # Check against current list of asset groups
    qg_asset_group_id = 0
    # Traverse list of dictionaries of asset group office names and ID.
    for a in qg_asset_groups:
        if a['office'] == asset_group:
            # Found asset group dictionary.
            qg_asset_group_id = a['id']
            break
    if qg_asset_group_id == 0:
        logging.error('Asset group not found in QualysGuard.')
        return False
    # Traverse Google Docs rows for matching data.
    found_in_gdocs = False
    for i, entry in enumerate(feed.entry):
        try:
            region = entry.custom['region'].text
            office = '%s - %s' % (region, entry.custom['office'].text)
            if office == asset_group:
                param = {'project': '%sSEC' % (region), 'assignee': entry.custom['itdirectore-mail'].text, 'Impacted Location': entry.custom['jiraimpactedlocation'].text, 'qg_asset_group_id': qg_asset_group_id, }
                found_in_gdocs = True
                break
            # Not the office we're looking for.
            continue
        except AttributeError:
            pass
    # Check if asset group was found in Google Docs.
    if not found_in_gdocs:
        logging.error('Asset group not found in Google Docs.')
        return False
    # Check for assignee override.
    if not c_args.assign == None:
        logging.debug('Assignee overridden by global c_args parameter: %s' % c_args.assign)
        param['assignee'] = c_args.assign
    logging.debug('param = %s' % (param))
    return param


def jira_report_vuln(vuln, flag_info):
    """Create issue in JIRA for vuln."""
    global asset_group, asset_group_details, c_args, PATH_DATA
    # vuln is {'qid': #, solution: 'Solution', ...}
    # Combine variables for full description
    logging.debug('jira_create(vuln) called.')
    logging.debug('vuln = %s' % (vuln))
    description = 'Please find the zip file attached listing the vulnerable hosts.\n\nSolution:\n%s\n\nThreat:\n%s\n\nImpact:\n%s' % (vuln['solution'], vuln['threat'], vuln['impact'])
    logging.debug('description = %s' % (description))
    # Translate QID Severity to ITIL priority level
    priority = jira_priority_translate(vuln['severity'])
    # Form text of summary.
    summary = 'Priority %s, QID %s, %s' % (priority, vuln['qid'], vuln['title'])
    # Create incident.
    issue_key = jira_create(asset_group_details['project'], '11', asset_group_details['assignee'], priority, summary, description, asset_group_details['Impacted Location'])
    logging.debug('issue_key = %s' % (issue_key))
    # Initiate CSV header
    logging.debug('Writing CSV attachment.')
    csv_filename = csv_write_attachment(vuln, flag_info)
    logging.debug('Done writing CSV attachment: %s' % (csv_filename))
    # Attach CSV file to incident.
    if not jira_attach(issue_key, csv_filename):
        # In case attaching CSV failed
        logging.error('Attaching CSV file failed.')
        print "Error creating issue for QID #%s" % (qid)
        jira_delete(issue_key)
        return False
    if flag_info:
        # Add issue to db incident.
        db_add_incident(issue_key, vuln['qid'], flag_info)
    else:
        # Severity 3-5 vulnerability.
        # Add issue to db remediation.
        for host in vuln['hosts']:
            db_add_remediation(host, issue_key)
        # Add issue to db incident.
        db_add_incident(issue_key, vuln['qid'])
    # Finished creating issue for QID.
    if c_args.test_stage:
        logging.debug('Created %s on Stage Jira for QID %s.' % (issue_key, vuln['qid']))
        print 'Created %s on Stage Jira for QID %s.' % (issue_key, vuln['qid'])
    else:
        logging.debug('Created %s for QID %s.' % (issue_key, vuln['qid']))
        print 'Created %s for QID %s.' % (issue_key, vuln['qid'])
    return True


def csv_write_attachment(vuln, flag_info = False):
    """Write E's CSV attachment content for Jira issue. Returns True if successful."""
    global PATH_DATA
    # Incorporate safeguards in case multiple scripts are running simultaneously
#    csv_file = csv.writer(open('%s/qid_%s.csv' % (PATH_DATA, E.text.encode('ascii', 'ignore')), 'a', newline = '')) # python3
    csv_filename = 'qgir_vulnerable_hosts-%s_%s.csv' % (datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'), vuln['qid'])
    logging.debug('file:  %s/%s' % (PATH_DATA, csv_filename))
    with open('%s/%s' % (PATH_DATA, csv_filename), 'wb') as ifile:
        # Write header of CSV file.
        csv_file = csv.writer(ifile)
        if flag_info:
            # Informational QID -- no vuln_id
            csv_file.writerow(('IP', 'DNS', 'Result'))
        else:
            # Not an informational QID
            csv_file.writerow(('Vulnerability ID #', 'IP', 'DNS', 'Result'))
        # Write one row per host
        for host in vuln['hosts']:
            # Debug log values
            logging.debug(host)
            logging.debug('file %s; vuln_id %s; qid %s; ip %s; dns %s; result %s' %
                         ('%s/%s' % (PATH_DATA, csv_filename),
                          host['vuln_id'],
                          vuln['qid'],
                          host['ip'],
                          host['dns'],
                          host['result']))
            if flag_info:
                # Informational QID -- no vuln_id
                csv_file.writerow((host['ip'],
                                   host['dns'],
                                   host['result']))
            else:
                # Not an informational QID
                csv_file.writerow((host['vuln_id'],
                                   host['ip'],
                                   host['dns'],
                                   host['result']))
    return csv_filename


def jira_attach(issue_key, filename):
    """Attach CSV to incident"""
    global PATH_DATA
    # Compress attachment with zip
    filename_zip = '%s.zip' % (filename)
    # Delete zip file in case it already exists due to crash
    if os.path.exists('%s/%s' % (PATH_DATA, filename_zip)):
        os.remove('%s/%s' % (PATH_DATA, filename_zip))
    # Compress from working directory of data to avoid subdirectory in zip file
    args_sub = [
            'zip',
            filename_zip,
            filename,
            ]
    logging.debug(args_sub)
    output_zip = subprocess.check_output(args_sub, cwd = PATH_DATA).decode("utf-8")
    logging.debug('zip command result:  %s' % (output_zip))
    # Attach compressed CSV
    # Maximum number of times to attach csv:  5.  About 1 minute before timing out.
    MAX_CHECKS = 10
    attempts = 0
    for n in range(0, MAX_CHECKS):
        try:
            output_attach = client.service.addBase64EncodedAttachmentsToIssue(auth, issue_key, [filename_zip.encode("utf-8")], [open('%s/%s' % (PATH_DATA, filename_zip), "rb").read().encode('base64')])
            break
        except:
            #  raise URLError(err)
            # urllib2.URLError: <urlopen error [Errno 60] Operation timed out>
            if attempts == MAX_CHECKS:
                print 'Error threshold reached.'
                exit(1)
            continue
    logging.debug('Attach command result:  %s' % (output_attach))
    if not output_attach:
        logging.error('Attachment failed.')
        print 'Attachment failed. Exiting...'
        exit()
    # Clean up files
    os.remove('%s/%s' % (PATH_DATA, filename_zip))
    os.remove('%s/%s' % (PATH_DATA, filename))
    logging.debug('CSV (%s) and compressed CSV (%s) files deleted' % (filename, filename_zip))
    # Return if file was successfully attached
    return (not 'zip error:' in output_zip)


def db_add_remediation(host, issue_key):
    """Add incident into db."""
    logging.debug('db_add_remediation called.')
    global asset_group, conn, cursor, round_number, run_number
    # Add remediation ticket into remediation.
    logging.debug('Insert %s into remediation.' % (host['vuln_id']))
    cursor.execute('INSERT into remediation values (?,?,?,?)', (host['vuln_id'], run_number, issue_key, round_number))
    logging.debug('Insert successful.')
    return conn.commit()


def db_add_incident(issue_key, qid, flag_info = False):
    """Add incident into db."""
    logging.debug('db_add_issue called.')
    global asset_group, asset_group_details, conn, cursor, round_number, run_number
    # Add incident into sqlite's incidents
    logging.debug('Insert %s into sqlite.' % (issue_key))
    # Insert into correct table.
    if flag_info:
        cursor.execute('INSERT into info_incidents values (?,?,?,?,?,?,?)',
                       (issue_key,
                        asset_group,
                        qid,
                        0,
                        run_number,
                        0,
                        round_number)
                       )
    else:
        cursor.execute('INSERT into incidents values (?,?,?,?,?,?,?)',
                       (issue_key,
                        asset_group,
                        qid,
                        0,
                        run_number,
                        0,
                        round_number)
                       )
    logging.debug('Insert successful.')
    return conn.commit()


def db_current_run_number():
    global cursor
    # TODO:  Static run_number, no longer incrementing by one.
    # Check if rows exist to bypass SQL error.
    if cursor.execute('SELECT Count(*) FROM incidents').fetchall()[0][0] < 1:
        # No rows exist.
        return 0
    else:
        return (cursor.execute('SELECT max(run_number) FROM incidents').fetchall()[0][0])


def db_initiate():
    """Initiate database, return the run_number value."""
    global cursor
    # Log all triage requests
    # issue_key = Jira's issue key.
    # asset_group = Asset group.
    # qid = QID vulnerability.
    # run_number = QGIR run number.
    # remediation_numbers = Remediation numbers linked to vulnerability.  Used in validation of resolved issues.
    # reopen = Number of times incident has been reopened.
    # status = Status of QID:  open, approved, rejected.
    # validated = Whether Jira issue's resolved state has been confirmed.
    cursor.execute('''create table if not exists triage
    (issue_key text primary key, office text, qid text, run_number int, remediation_numbers text, reopen int, status text, round_number int)''')
    # Log all incidents created
    cursor.execute('''create table if not exists remediation
    (remediation_ticket text primary key, run_number int, issue_key text, round_number int)''')
    # Table 'incidents' holds incidents that have been marked complete by the assignee and need to be validated by QGIR.
    cursor.execute('''create table if not exists incidents
    (issue_key text primary key, office text, qid text, reopen int, run_number int, validated int, round_number int)''')
    # Table 'info_incidents' holds incidents that have been marked complete by the assignee and need to be validated by QGIR.
    cursor.execute('''create table if not exists info_incidents
    (issue_key text primary key, office text, qid text, reopen int, run_number int, validated int, round_number int)''')
    # Check to see if this is the first issue for run_number
    return True


def db_round_number():
    """Return the round_number value."""
    global asset_group, asset_group_details
    # Round number.
    try:
        round_number = db_query(q_select = 'MAX(round_number)', q_where = 'office', q_value = (asset_group,)).pop()
    except TypeError, e:
        # No asset group specified.  Use current round number.
        round_number = db_query(q_select = 'MAX(round_number)').pop()
    if not round_number:
        # First round for office.
        round_number = 1
    logging.debug('round_number = %s' % (round_number))
    return round_number


def delete_issue(issue_key):
    """Return true after deleting issue from SQLite DB & JIRA."""
    # Initiate SQLite db
    global auth, conn, cursor
    if issue_key[1]:
        # Information vulnerability.  Fetch rows from info_incidents table.
        table_name = 'info_incidents'
    else:
        # Severity 3-5 vulnerability.  Fetch rows from incidents table.
        table_name = 'incidents'
    rows_incidents = cursor.execute('SELECT issue_key FROM %s WHERE issue_key = ?' % (table_name), (issue_key[0],)).fetchall()
    # Delete issues from incidents table from the DB.
    for i in rows_incidents:
        # Delete db rows in incidents
        cursor.execute('DELETE FROM %s WHERE issue_key = ?' % (table_name), (i[0],))
        logging.debug('DB: Deleted %s from %s.' % (i[0], table_name))
    if not issue_key[1]:
        # Fetch rows from remediation table.
        rows_remediation = cursor.execute('SELECT remediation_ticket FROM remediation WHERE issue_key = ?', (issue_key[0],)).fetchall()
        # Delete issues from remediation table from the DB.
        for i in rows_remediation:
            # Severity 3-5 vulnerability.  Delete db rows in remediation.
            while(True):
                try:
                    cursor.execute('DELETE FROM remediation WHERE remediation_ticket = ?', (i[0],))
                except sqlite3.OperationalError:
                    logging.error('Database locked. Trying again.')
                    print 'Database locked. Trying again.'
                    continue
                break
            logging.debug('DB: Deleted %s from remediation.' % (i[0]))
    # Commit changes
    try:
        conn.commit()
    except:
        logging.warning('SQLite file may not have committed.')
    # Delete issue_key in JIRA
    return jira_delete(issue_key[0])


def is_positive_integer(s):
    """Returns whether a value passed is a positive integer."""
    try:
        return (int(s) > 0)
    except ValueError:
        return False


def jira_assign(assignee, issue_key):
    """Assign JIRA issue_key to asssignee via SOAP API."""
    global auth, client
    # Assign issue.
    MAX_CHECKS = 10
    attempts = 0
    for n in range(0, MAX_CHECKS):
        try:
            client.service.updateIssue(
                auth,
                str(issue_key),
                [
                 {'id': 'assignee', 'values': [assignee]},
                 ])
            return True
            break
        except urllib2.URLError, e:
            attempts += 1
            print 'urllib2 %d: %s' % (e.args[0], e.args[1])
            logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
            if attempts == MAX_CHECKS:
                print 'Error threshold reached.'
                exit(1)
            continue
    # Was not able to update assignee.
    return False


def jira_close(issue_key):
    """Close JIRA issue_key via SOAP API."""
    global auth, client
    # Assign issue.
    MAX_CHECKS = 10
    attempts = 0
    for n in range(0, MAX_CHECKS):
        try:
            client.service.updateIssue(
                auth,
                str(issue_key),
                [
                 {'id': 'assignee', 'values': [assignee]},
                 ])
            return True
            break
        except urllib2.URLError, e:
            attempts += 1
            print 'urllib2 %d: %s' % (e.args[0], e.args[1])
            logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
            if attempts == MAX_CHECKS:
                print 'Error threshold reached.'
                exit(1)
            continue
    # Was not able to update assignee.
    return False


def jira_comment(comment, issue_key):
    """Assign JIRA issue_key to asssignee via SOAP API."""
    global auth, client
    # Assign issue.
    MAX_CHECKS = 10
    attempts = 0
    for n in range(0, MAX_CHECKS):
        try:
            client.service.addComment(
                auth,
                str(issue_key),
                {'body': comment},
                )
            return True
            break
        except urllib2.URLError, e:
            attempts += 1
            print 'urllib2 %d: %s' % (e.args[0], e.args[1])
            logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
            if attempts == MAX_CHECKS:
                print 'Error threshold reached.'
                exit(1)
            continue
    # Was not able to update assignee.
    return False

def jira_create(project, issue_type, assignee, priority, summary, description, impacted_location):
    """Create JIRA issue via SOAP API."""
    # SOAP configuration
    global c_args, auth, client
    # Differences between Stage Jira and production Jira.
    if c_args.test_stage:
        impacted_location_city_field = 'customfield_10100'
        impacted_service_child = '11768'
    else:
        impacted_location_city_field = 'customfield_10134'
        impacted_service_child = '11974'
    # Create new issue
    MAX_CHECKS = 10
    attempts = 0
    for n in range(0, MAX_CHECKS):
        try:
            new_issue = client.service.createIssue(
                auth,
                {
                    'project': project,
                    # issue_type = Incident Report.
                    'type': issue_type,
                    'assignee': assignee,
                    'priority': priority,
                    'summary': summary,
                    'description': description,
                    'customFieldValues': [
                        # Reporter region = NA.
                        {'customfieldId':'customfield_10074', 'values':['NA']},
                        # Impacted Service/System = Security Services.
                        {'customfieldId':'customfield_10026', 'values':['10315']},
                        # Impacted Service/System child = Security Services - QGIR hosts.
                        {'customfieldId':'customfield_10026', 'key': '1', 'values':[impacted_service_child]},
                        # Issue Descriptor = Security Vulnerability.
                        {'customfieldId':'customfield_10025', 'values':['Security Vulnerability']},
                        # Impacted Location(s) = City associated with asset_group.  In Stage Jira this is customfield_10134.
                        {'customfieldId':impacted_location_city_field, 'values':[impacted_location]},
                        ]
            })
            break
        except urllib2.URLError, e:
            attempts += 1
            print 'urllib2 %d: %s' % (e.args[0], e.args[1])
            logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
            if attempts == MAX_CHECKS:
                print 'Error threshold reached.'
                exit(1)
            continue
    # Assign issue.
    jira_assign(assignee, str(new_issue.key))
    # Return the incident identifier.  E.g.: "NAHLP-33232"
    return str(new_issue.key)


def jira_delete(issue_key):
    """Delete Jira issue_key issue and return whether it was successful."""
    try:
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                issue = client.service.getIssue(auth, issue_key)
                break
            except urllib2.URLError, e:
                attempts += 1
                print 'urllib2 %d: %s' % (e.args[0], e.args[1])
                logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                continue
        if issue['reporter'] != 'qgir@company.com':
            # QGIR did not report this issue.  Do not delete.
            logging.error('Issue %s not reported by QGIR, will not delete.' % (issue_key))
            print 'Issue %s not reported by QGIR, will not delete issue from Jira.  Trying to delete from db...' % (issue_key)
            return False
        # Delete issue
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                client.service.deleteIssue(auth, issue_key)
                break
            except urllib2.URLError, e:
                attempts += 1
                print 'urllib2 %d: %s' % (e.args[0], e.args[1])
                logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                continue
        logging.debug('JIRA: Deleted %s.' % (issue_key))
        print 'Deleted %s.' % (issue_key)
        return True
    except:
        logging.warning('Unable to delete Jira issue %s.' % (issue_key))
        print 'Unable to delete %s.' % (issue_key)
        return False


def jira_priority_translate(severity):
    """Return QualysGuard's severity scale (5-1) translated to ITIL's priority scale (1-5)."""
    if severity == 5 or severity == '5':
        # P2 (High)
        return '2'
    elif severity == 4 or severity == '4':
        # P3 (Medium)
        return '3'
    elif severity == 3 or severity == '3':
        # P4 (Low)
        return '4'
    elif severity == 2 or severity == '2':
        # P4 (Low)
        return '4'
    elif severity == 1 or severity == '1':
        # P4 (Low)
        return '4'
    else:
        logging.error('Unknown severity encountered: %s' % (severity))
        print 'Unknown severity encountered: %s' % (severity)
        logging.error('Exiting.')
        print 'Exiting'
        exit()


def parse_int_set(nputstr = ''):
    """Return a set of selected values when a string in the form:
    1-4,6
    would return:
    1,2,3,4,6
    as expected.
    http://stackoverflow.com/questions/712460/interpreting-number-ranges-in-python """
    selection = set()
    invalid = set()
    # tokens are comma seperated values
    tokens = [x.strip() for x in nputstr.split(',')]
    for i in tokens:
        if len(i) > 0:
            if i[:1] == "<":
                i = "1-%s" % (i[1:])
        try:
            # typically tokens are plain old integers
            selection.add(int(i))
        except:
            # if not, then it might be a range
            try:
                token = [int(k.strip()) for k in i.split('-')]
                if len(token) > 1:
                    token.sort()
                    # we have items seperated by a dash
                    # try to build a valid range
                    first = token[0]
                    last = token[len(token) - 1]
                    for x in range(first, last + 1):
                        selection.add(x)
            except:
                # not an int and not a range...
                invalid.add(i)
    # Report invalid tokens before returning valid selection
    if len(invalid) > 0:
        print "Invalid set: " + str(invalid)
    return selection


def qg_command(api_version, command, command_options = {}):
    """Run QualysGuard command and return status."""
    global session_id, qg_username, qg_password
    # Debug parameters.
    logging.debug('qg_command(%s, %s, %s)' % (api_version, command, command_options))
    # Format asset group for curl call.
    # Replace all spaces in command options with plus sign.
    for item in command_options:
        try:
            command_options[item] = command_options[item].replace(' ', '+')
        except AttributeError:
            # Value of item may be an integer.  Skip replacing character.
            continue
    # Serialize dictionary with ampsersand interater.
    command_parameter = urllib.urlencode(command_options)
    logging.debug('command_parameter = %s' % (command_parameter))
    # Check if still logged in.
    if api_version == 1:
        #Return xml file for scan of asset_group for qid.
        # Set paramaters for QualysGuard API v1
        args_sub = [
            'curl',
            '-H', 'X-Requested-With: QGIR',
            '-d', command_parameter,
            'https://%s:%s@qualysapi.qualys.com/msp/%s.php' % (qg_username, qg_password, command)
        ]
    elif api_version == 2:
        # Set paramaters for QualysGuard API v2
        args_sub = [
            'curl',
            '-H', 'X-Requested-With: QGIR',
            #'-b', session_id,
            '-d', command_parameter,
            'https://%s:%s@qualysapi.qualys.com/api/2.0/fo/%s/' % (qg_username, qg_password, command),
        ]

        logging.debug('command_parameter: %s' % (command_parameter))
    # Call API.
    logging.debug('args_sub = %s' % (args_sub))
    xml_output = subprocess.check_output(args_sub)
    logging.debug('qg_command first xml_output =')
    logging.debug(xml_output)
    # Specific report commmand.
    if command == 'report':
        #=======================================================================
        # Poll the Report Center until the report with the passed id shows
        # up with statue "Finished", or is not found for more than 5 minutes
        # (suggesting that it was never actually launched), or is "Running"
        # for more than 3 days (suggesting that it is hung), or shows up
        # as having Errors or having been Cancelled, in which case we exit
        # gracefully with an error (don't leave any dangling FO sessions).
        #=======================================================================
        # XML xml_output contains the report id.
        report_id = etree.XML(xml_output).find('.//VALUE').text
        logging.debug('report_id: %s' % (report_id))
        # Wait for report to finish spooling.
        # Time in seconds to wait between checks.
        POLLING_DELAY = 120
        # Time in seconds to wait before checking.
        STARTUP_DELAY = 60
        # Maximum number of times to check for report.  About 10 minutes.
        MAX_CHECKS = 10
        print 'Report sent to spooler.  Checking for report in %s seconds.' % (STARTUP_DELAY)
        time.sleep(STARTUP_DELAY)
        for n in range(0, MAX_CHECKS):
            # Call API.
            args_sub = [
                'curl',
                '-H', 'X-Requested-With: QGIR',
                #'-b', session_id,
                '-d', 'action=list&id=%s' % (report_id),
                'https://%s:%s@qualysapi.qualys.com/api/2.0/fo/report/' % (qg_username, qg_password),
            ]
            logging.debug('args_sub: %s' % (args_sub))
            xml_output = subprocess.check_output(args_sub)
            logging.debug('qg_command report poll xml_output: %s' % (xml_output))
            tag_status = etree.XML(xml_output).findtext(".//STATE")
            logging.debug('tag_status: %s' % (tag_status))
            if not type(tag_status) == types.NoneType:
                # Report is showing up in the Report Center.
                if tag_status == 'Finished':
                    # Report creation complete.
                    break
            # Report not finished, wait.
            print 'Report still spooling.  Trying again in %s seconds.' % (POLLING_DELAY)
            time.sleep(POLLING_DELAY)
        # We now have to fetch the report.  Use the report id.
        args_sub = [
            'curl',
            '-H', 'X-Requested-With: QGIR',
            #'-b', session_id,
            '-d', 'action=fetch&id=%s' % (report_id),
            'https://%s:%s@qualysapi.qualys.com/api/2.0/fo/report/' % (qg_username, qg_password),
        ]
        xml_output = subprocess.check_output(args_sub)
        logging.debug('qg_command report download xml_output =')
        logging.debug(xml_output)
        if 'QGIR+Patch' in command_options['report_title']:
            # Patch report
            logging.debug('Returning patch CSV file.')
            return xml_output
        else:
            # Scan report
            filename = 'data/xml/%s_%s.txt' % (datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'), asset_group)
            logging.debug('report filename: %s' % (filename))
            with open(filename, 'w') as f:
                f.write(xml_output)
            return filename
    return xml_output

def qg_html_to_ascii(qg_html_text):
    """Convert and return QualysGuard's quasi HTML text to ASCII text."""
    text = qg_html_text
    # Handle tagged line breaks (<p>, <br>)
    text = re.sub(r'(?i)<br>[ ]*', '\n', text)
    text = re.sub(r'(?i)<p>[ ]*', '\n', text)
    # Remove consecutive line breaks
    text = re.sub(r"^\s+", "", text, flags = re.MULTILINE)
    # Remove empty lines at the end.
    text = re.sub('[\n]+$', '$', text)
    # Store anchor tags href attribute
    links = list(lxml.html.iterlinks(text))
    # Remove anchor tags
    html_element = lxml.html.fromstring(text)
    # Convert anchor tags to "link_text (link: link_url )".
    logging.debug('Converting anchor tags...')
    text = html_element.text_content().encode('ascii', 'ignore')
    # Convert each link.
    for l in links:
        # Find and replace each link.
        link_text = l[0].text_content().encode('ascii', 'ignore').strip()
        link_url = l[2].strip()
        # Replacing link_text
        if link_text != link_url:
            # Link text is different, most likely a description.
            text = string.replace(text, link_text, '%s (link: %s )' % (link_text, link_url))
        else:
            # Link text is the same as the href.  No need to duplicate link.
            text = string.replace(text, link_text, '%s' % (link_url))
    logging.debug('Done.')
    return text


def qg_report(asset_group, severity):
    """Fetch report for all vulnerabilities of level severity against asset_group and return filename of report XML."""
    global asset_group_details
    # Retrieve XML report
    if severity == 5 or severity == '5':
        # Report template "API Sev 5 confirmed -camera -phone -printer -scanner"
        report_template = '1067877'
    elif severity == 4 or severity == '4':
        report_template = '1077407'
    elif severity == 3 or severity == '3':
        report_template = '1077408'
    elif severity == 2 or severity == '2':
        report_template = '1077408'
    elif severity == 1 or severity == '1':
        report_template = '1058182'
    logging.debug('report_template: %s' % (report_template))
    # Retrieve from QualysGuard
    return qg_command(2, 'report', {'action': 'launch', 'report_type':'Scan', 'output_format': 'xml', 'asset_group_ids': asset_group_details['qg_asset_group_id'], 'template_id':report_template, 'report_title':'QGIR %s' % (asset_group)})


def qg_parse_informational_qids(xml_report):
    """Return vulnerabilities of severity 1 and 2 levels due to a restriction of QualysGuard's inability to report them in the internal ticketing system."""
#    asset_group's vulnerability data map:
#    {'qid_number': {
#                    # CSV info
#                    'hosts': [{'ip': '10.28.0.1', 'dns': 'hostname', 'netbios': 'blah', 'vuln_id': 'remediation_ticket_number'}, {'ip': '10.28.0.3', 'dns': 'hostname2', 'netbios': '', 'vuln_id': 'remediation_ticket_number'}, ...],
#                    'solution': '',
#                    'impact': '',
#                    'threat': '', 
#                    'severity': '',
#                   }
#     'qid_number2': ...
#     }
    # Add all vulnerabilities to list of dictionaries.
    # Use defaultdict in case a new QID is encountered.    
    info_vulns = defaultdict(dict)
    ## Objectify XML file.
    #tree = objectify.fromstring(xml_report)
    # Parse vulnerabilities in xml string.
    tree = objectify.fromstring(xml_report)
    # Write IP, DNS, & Result into each QID CSV file.
    logging.debug('Parsing report...')
    # TODO:  Check against c_args.max to prevent creating CSV content for QIDs that we won't use.
    for host in tree.HOST_LIST.HOST:
        # Extract possible extra hostname information.
        try:
            netbios = unicodedata.normalize('NFKD', unicode(host.NETBIOS)).encode('ascii', 'ignore').strip()
        except AttributeError:
            netbios = ''
        try:
            dns = unicodedata.normalize('NFKD', unicode(host.DNS)).encode('ascii', 'ignore').strip()
        except AttributeError:
            dns = ''
        ip = unicodedata.normalize('NFKD', unicode(host.IP)).encode('ascii', 'ignore').strip()
        # Extract vulnerabilities host is affected by.
        for vuln in host.VULN_INFO_LIST.VULN_INFO:
            try:
                result = unicodedata.normalize('NFKD', unicode(vuln.RESULT)).encode('ascii', 'ignore').strip()
            except AttributeError:
                result = ''
            qid = unicodedata.normalize('NFKD', unicode(vuln.QID)).encode('ascii', 'ignore').strip()
            # Attempt to add host to QID's list of affected hosts.
            try:
                info_vulns[qid]['hosts'].append({'ip': '%s' % (ip),
                                                        'dns': '%s' % (dns),
                                                        'netbios': '%s' % (netbios),
                                                        'vuln_id': '', # Informational QIDs do not have vuln_id numbers.  This is a flag to write the CSV file.
                                                        'result': '%s' % (result), })
            except KeyError:
                # New QID.
                logging.debug('New QID found: %s' % (qid))
                info_vulns[qid]['hosts'] = []
                info_vulns[qid]['hosts'].append({'ip': '%s' % (ip),
                                                        'dns': '%s' % (dns),
                                                        'netbios': '%s' % (netbios),
                                                        'vuln_id': '', # Informational QIDs do not have vuln_id numbers.  This is a flag to write the CSV file. 
                                                        'result': '%s' % (result), })
    # All vulnerabilities added.
    # Add all vulnerabilty information.
    for vuln_details in tree.GLOSSARY.VULN_DETAILS_LIST.VULN_DETAILS:
        qid = unicodedata.normalize('NFKD', unicode(vuln_details.QID)).encode('ascii', 'ignore').strip()
        info_vulns[qid]['title'] = unicodedata.normalize('NFKD', unicode(vuln_details.TITLE)).encode('ascii', 'ignore').strip()
        info_vulns[qid]['severity'] = unicodedata.normalize('NFKD', unicode(vuln_details.SEVERITY)).encode('ascii', 'ignore').strip()
        info_vulns[qid]['solution'] = qg_html_to_ascii(unicodedata.normalize('NFKD', unicode(vuln_details.SOLUTION)).encode('ascii', 'ignore').strip())
        info_vulns[qid]['threat'] = qg_html_to_ascii(unicodedata.normalize('NFKD', unicode(vuln_details.THREAT)).encode('ascii', 'ignore').strip())
        info_vulns[qid]['impact'] = qg_html_to_ascii(unicodedata.normalize('NFKD', unicode(vuln_details.IMPACT)).encode('ascii', 'ignore').strip())
    # Ready to report informational vulnerabilities.
    return info_vulns


def qg_scan(asset_group, qid, incident):
    """Return xml file for scan of asset_group for qid."""
    global qg_username
    global qg_password
    logging.debug('qg_scan(%s, %s, %s) called' % (asset_group, qid, incident))
    # Format asset group for curl call.
    asset_group_curl = asset_group.replace(' ', '+')
    logging.debug('asset_group_curl: %s' % (asset_group_curl))
    # Add host scan data
    qid += ',45017,82023,82004,6,82044'
    # Add authentication scan data
    qid += '105015,105053,105192,105193,105296,105297,105298,105299,105329,105330,115263'
    # Change qid to option profile "QGIR - Authenticated", id # 484629
    command_parameter = 'https://%s:%s@qualysapi.qualys.com/msp/scan.php?asset_groups=%s&specific_vulns=%s&iscanner_name=NA_New_York&scan_title=QGIR+validating+%s&save_report=yes' % (qg_username, qg_password, asset_group_curl, qid, incident)
    logging.debug('command_parameter: %s' % (command_parameter))
    # Fetch new scan
    args_sub = [
        'curl',
        '-H', 'X-Requested-With: QGIR',
        # Scan the entire office in the case that DHCP is in use.
        command_parameter,
    ]
    return subprocess.check_output(args_sub)

def qg_scan_check(asset_group, state, launch_date):
    """Return whether a vulnerability scan initiated by user against asset_group launched after launch_date has completed."""
    global qg_username
    xml_output = qg_command(2, 'scan', {'action': 'list', 'state': state, 'user_login': qg_username, 'launched_after_datetime': launch_date, 'show_ags': 1, 'show_last': 1})
    root = etree.parse(xml_output)
    for E in root.findall("//ASSET_GROUP_TITLE"):
        if E.text == asset_group:
            return True
    return False


def qg_tickets_processed(validate_asset_group):
    """Return whether QualysGuard ticketing for a vulnerability scan has been completed."""
    return True

def qg_ticket_validate(qg_tickets_to_validate):
    """Download QualysGuard tickets."""
    logging.debug('qg_ticket_validate.qg_tickets_to_validate = %s' % (qg_tickets_to_validate))
    # Store tickets and current state in defaultdict.
    vulns = defaultdict(dict)
    # Extract ticket numbers from set.
    ticket_numbers = ''
    for t in qg_tickets_to_validate:
        ticket_numbers += '%s,' % (t)
    ticket_numbers = ticket_numbers[:-1]
    # Retrieve tickets from API.
    since_ticket_number = 1
    while True:
        command_parameter = 'show_vuln_details=1&ticket_numbers=%s&since_ticket_number=%s' % (ticket_numbers, since_ticket_number)
        args_sub = [
            'curl',
            '-H', 'X-Requested-With: QGIR',
            '-d', command_parameter,
            'https://%s:%s@qualysapi.qualys.com/msp/ticket_list.php' % (qg_username, qg_password)
        ]
        logging.debug('args_sub: %s' % (args_sub))
        # Call API.
        # TODO:  Incorporate timeout of 5 minutes.
        xml_output = subprocess.check_output(args_sub)
        logging.debug('xml_output =')
        logging.debug(xml_output)
        # Objectify XML.
        tree = objectify.fromstring(xml_output)
        # Parse vulnerabilities.
        try:
            for ticket in tree.TICKET_LIST.TICKET:
                state = unicodedata.normalize('NFKD', unicode(ticket.CURRENT_STATE)).encode('ascii', 'ignore').lower().strip()
                # Extract possible extra hostname information.
                try:
                    netbios = unicodedata.normalize('NFKD', unicode(ticket.DETECTION.NBHNAME)).encode('ascii', 'ignore').strip()
                except AttributeError:
                    netbios = ''
                try:
                    dns = unicodedata.normalize('NFKD', unicode(ticket.DETECTION.DNSNAME)).encode('ascii', 'ignore').strip()
                except AttributeError:
                    dns = ''
                try:
                    result = unicodedata.normalize('NFKD', unicode(ticket.DETAILS.RESULT)).encode('ascii', 'ignore').strip()
                except AttributeError:
                    result = ''
                vuln_id = unicodedata.normalize('NFKD', unicode(ticket.NUMBER)).encode('ascii', 'ignore').strip()
                ip = unicodedata.normalize('NFKD', unicode(ticket.DETECTION.IP)).encode('ascii', 'ignore').strip()
                qid = unicodedata.normalize('NFKD', unicode(ticket.VULNINFO.QID)).encode('ascii', 'ignore').strip()
                # Document QID
                vulns[qid]
                # Attempt to add host to QID's list of affected hosts if open state.
                if state == 'open':
                    try:
                        vulns[qid]['hosts'].append({'ip': '%s' % (ip),
                                                    'dns': '%s' % (dns),
                                                    'netbios': '%s' % (netbios),
                                                    'vuln_id': '%s' % (vuln_id),
                                                    'result': '%s' % (result), })
                    except KeyError:
                        # New QID.
                        logging.debug('New QID found: %s' % (qid))
                        vulns[qid]['hosts'] = []
                        vulns[qid]['hosts'].append({'ip': '%s' % (ip),
                                                    'dns': '%s' % (dns),
                                                    'netbios': '%s' % (netbios),
                                                    'vuln_id': '%s' % (vuln_id),
                                                    'result': '%s' % (result), })
        except AttributeError, e:
            logging.debug('No QualysGuard tickets to report.')
            break
        # All vulnerabilities added.
        try:
            # See if the API call was truncated due to API limit of 1000 records at a time.
            since_ticket_number = tree.TRUNCATION.get('last')
        except AttributeError:
            # No more API calls necessary.
            break
    # Downloaded requested tickets.
    logging.debug('qg_ticket_validate.vulns = %s', vulns)
    return vulns


def jira_get_issue(i):
    """Return JIRA issue i"""
    global auth
    MAX_CHECKS = 10
    attempts = 0
    for n in range(0, MAX_CHECKS):
        try:
            issue = client.service.getIssue(auth, i)
            break
        except urllib2.URLError, e:
            attempts += 1
            print 'urllib2 %d: %s' % (e.args[0], e.args[1])
            logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
            if attempts == MAX_CHECKS:
                print 'Error threshold reached.'
                exit(1)
            continue
    return issue


def validate(incidents, qg_scan_check = False, qg_tickets_processed = False):
    """Return whether incidents has been accurately restored, and reopen incidents if not accurately restored."""
    #Validate:
    #check all open tickets, according to sqlite
    #check if all rts for tickets marked resolved are closed/fixed.
    #if so, move ticket to closed state.
    #if not, check scan date by QG_user of asset group's date against resolved date.  if scan date is later than asset_group date
    #run/queue a scan against each asset group, mark in sqlite table which asset groups
    #
    #Validate:
    #check if any scans are completed from sqlite table,
    #
    # Global varibales
    global asset_group_details, auth, c_args, conn, cursor
    # Keep track of restore dates to see if a QualysGuard scan has run since then.
    # No way to retrieve when an issue is marked resolved through SOAP.
#    restore_date=defaultdict(str)
    logging.debug('validate(): all incidents = %s' % (incidents))
    incidents_copy = []
    # Remove all incidents not marked resolved.
    for i in sorted(incidents):
        logging.debug('Traversing issue:  %s' % (i[0]))
        # Check status of Jira issue.
        issue = jira_get_issue(i[0])
        # Status of incidents:
        # '1' = Initial status
        # '3' = In progress
        # '4' = Reopened
        # '5' = Resolved
        # '6' = Closed
        if issue['status'] == '5':
            # Issue is not marked resolved.
            logging.debug('validate(): Issue %s is marked as resolved.' % (i[0]))
            incidents_copy.append(i)
        else:
            # This incident has been marked resolved.
            logging.debug('validate(): Issue %s is not marked as resolved.' % (i[0]))
            print 'Issue %s is not marked as resolved.' % (i[0])
    incidents = incidents_copy
    logging.debug('validate(): incidents = %s' % (incidents))
    #
    # Store remediation tickets in a dictionary.
    qg_tickets_to_validate = defaultdict(dict)
    # Build query for QualysGuard status against all remediation tickets associated with remaining resolved Jira tickets.
    incident_query_tuple = ()
    # Combine all tickets for QualysGuard query.
    all_tickets = set()
    for i in sorted(incidents):
        # Build query for all remaining resolved remediation tickets.
        incident_query_tuple = (i[0],)
        logging.debug('validate(): incident_query_tuple = %s' % (str(incident_query_tuple)))
        # Query remediation tickets against multiple issues.  
        # Each Jira issue's ticket is in dictionary of that ticket.  
        # E.g.: qg_tickets_to_validate['NASEC-11'] = [(NASEC-11)'s tickets].
        qg_tickets_to_validate[i[0]]['qid'] = db_query(q_select = 'qid', q_table = 'incidents', q_where = 'issue_key', q_where_operator = '==', q_value = incident_query_tuple).pop()
        qg_tickets_to_validate[i[0]]['tickets'] = db_query(q_select = 'remediation_ticket', q_table = 'remediation', q_where = 'issue_key', q_where_operator = 'IN', q_value = incident_query_tuple)
        all_tickets = all_tickets.union(qg_tickets_to_validate[i[0]]['tickets'])
    logging.debug('all_tickets = %s' % (all_tickets))
    logging.debug('validate(): qg_tickets_to_validate = %s' % (qg_tickets_to_validate))
    # Obtain state status of all tickets.
    qg_tickets = qg_ticket_validate(all_tickets)
    # Keep track of total number of vulnerabilities closed.
    total_closed = 0
    total_still_open = 0
    issues_open = 0
    issues_closed = 0
    qg_tickets_to_validate_final = defaultdict(set)
    # User jira class
    j = jira.jira(logging, 'production', 'qgir@company.com')
    j.auth = auth
    # Link QualysGuard tickets with status to Jira ticket.
    for i in sorted(qg_tickets_to_validate):
        qg_tickets[qg_tickets_to_validate[i]['qid']]['jira'] = i
    logging.debug('validate.qg_tickets = %s' % (qg_tickets))
    # Close Jira tickets.
    for r in qg_tickets:
        issue_key = qg_tickets[r]['jira']
        try:
            num_open_tickets = len(qg_tickets[r]['hosts'])
        except:
            num_open_tickets = False
        if not num_open_tickets:
            # Close this ticket.
            issues_closed += 1
            j.close(issue_key)
            print '%s closed.' % (issue_key)
            logging.debug('%s closed.' % (issue_key))
        else:
            # Reopen this ticket.
            issues_open += 1
            total_still_open += num_open_tickets
            # Prepare vuln data for CSV writing.
            qg_tickets[r]['qid'] = r
            # Initiate CSV header
            logging.debug('Writing CSV attachment.')
            csv_filename = csv_write_attachment(qg_tickets[r])
            logging.debug('Done writing CSV attachment: %s' % (csv_filename))
            # Attach CSV file to incident.
            if not jira_attach(issue_key, csv_filename):
                # In case attaching CSV failed
                logging.error('Attaching CSV file to %s failed.' % (issue_key))
                print 'Error attaching CSV to issue %s' % (issue_key)
                continue
            # Reopen ticket
            if not c_args.close_only:
                j.reopen(issue_key)
            print '%s reopened: %s remain.' % (issue_key, num_open_tickets)
            logging.debug('%s reopened: %s remain.' % (issue_key, num_open_tickets))
    total_closed = len(all_tickets) - total_still_open
    print
    print 'Total vulnerability statistics: %s/%s (%s%%) resolved.' % (total_closed, (total_closed + total_still_open), round(total_closed / float(total_closed + total_still_open) * 100, 1))
    print 'Jira issue statistics: %s/%s (%s%%) closed.' % (issues_closed, (issues_closed + issues_open), round(issues_closed / float(issues_closed + issues_open) * 100, 1))



#    
#        # Build query for all remaining resolved remediation tickets.
#    incident_query_tuple = ()
#    for i in incidents:
#        incident_query_tuple += (i[0],)
#    logging.debug('incident_query_tuple = %s' % (str(incident_query_tuple)))
#    # Query remediation tickets against multiple issues.
#    qg_tickets_to_validate = db_query(q_select = 'remediation_ticket', q_table = 'remediation', q_where = 'issue_key', q_where_operator = 'IN', q_value = incident_query_tuple)
#    logging.debug('qg_tickets_to_validate = %s' % (qg_tickets_to_validate))
#    # Obtain state status of each ticket.
#    qg_tickets = qg_ticket_validate(qg_tickets_to_validate)
#    # Remove all tickets that are verified resolved.
#    closed = 0
#    still_open = 0
#    for t in qg_tickets:
#        logging.debug('validate(): Validating % s.' % (qg_tickets))
#        print t, qg_tickets[t]
#        if qg_tickets[t].lower() == 'closed':
#            closed += 1
#        else:
#            still_open += 1
#    print 'Closed: %s' % (closed)
#    print 'Open: %s' % (still_open)
#    print 'Closed / Total = %s%' % (round((closed / (closed + still_open)) * 100, 1))
#    # Append all remediation ticket not resolved to newly attached CSV.

    # Append all remediation ticket not resolved to newly attached CSV.

#
#    # Reopen incident if there are tickets that were not resolved.
#    if hosts[qid][0] != []:
#        logging.info('Restored incident successfully validated.')
#        return True
#
#    # Close ticket
#
#    logging.info('Restored incident successfully validated.')
    return True

def db_issue_type_info(issue_key):
    """Return True if issue_key is an information gathered vulnerability from SQLite DB."""
    # Initiate SQLite db
    global auth, conn, cursor
    # Check if issue is nformation gathered vulnerability.  Fetch rows from info_incidents table.
    table_name = 'info_incidents'
    rows_incidents = cursor.execute('SELECT issue_key FROM %s WHERE issue_key = ?' % (table_name), (issue_key,)).fetchall()
    # Delete issues from incidents table from the DB.
    if not rows_incidents:
        return False
    return True


def param_change_assignee(assignee, issues):
    """Reassign issues."""
    # Flag for successful reassignment.
    successful = True
    for issue_key in issues:
        # Reassign issue.
        if not jira_assign(assignee, issue_key[0]):
            successful = False
        else:
            print 'Reassigned %s.' % (issue_key[0])
    # Reassignment complete.    
    return successful


def param_comment(comment, issues):
    """Add comment to issues."""
    # Flag for successful reassignment.
    successful = True
    # Reassign all issues in set.
    for issue_key in issues:
        # Reassign issue.
        if not jira_comment(comment, issue_key[0]):
            successful = False
        else:
            print 'Commenting on %s.' % (issue_key[0])
    # Reassignment complete.    
    return successful


def param_delete(issues):
    """Delete issues."""
    # Flag for successful deletion.
    successful = True
    # Delete all issues in set.
    for issue_key in issues:
        # Delete issue.
        if not delete_issue(issue_key):
            successful = False
    # Deletion complete.
    return successful


def param_issues(targets):
    """Returns set of issues being targeted.
       Example:  'NASEC-100-102' returns 'NASEC-100, NASEC-101, NASEC-102'."""
    logging.debug('param_issues(%s)' % (targets))
    issues = set()
    if not targets[0].isdigit():
        project_ends = targets.find('-') + 1
        project = targets[0:project_ends]
        set_of_issue_numbers = parse_int_set(targets[project_ends:])
        set_of_issues = set()
        # Prepend project to each issue number.
        for issue in set_of_issue_numbers:
            set_of_issues.add(project + str(issue))
    else:
        logging.error('Error: Project not specified.')
        print 'Error: Project not specified.'
        return issues
    # Convert to a set of tuples with information gathered flag.
    for i in set_of_issues:
        flag_info = db_issue_type_info(i)
        issues.add((i, flag_info))
    if not issues:
        logging.debug('No issues found by param_issues \'%s\'' % (targets))
        print 'No issues found in \'%s\'' % (targets)
    logging.debug('param_issues.issues = %s' % (issues))
    return issues


def param_list(issues):
    """Print list of issues."""
    # Flag for successful deletion.
    successful = True
    # Delete all issues in set.
    for issue_key in issues:
        # Delete issue.
        print issue_key
    # Deletion complete.
    return successful


def param_office(office, flag_info, flag_vuln):
    """Returns set of issues from office.
       Example:  'NA - New York' returns set('NASEC-100, NASEC-101, NASEC-102') owned by New York."""
    logging.debug('param_office(%s, %s, %s)' % (office, flag_info, flag_vuln))
    # Retrieve information gathered issues from SQlite.
    issues = set()
    if flag_info:
        issues = issues.union(db_query(q_table = 'info_incidents', q_where = 'office', q_value = (office,), flag_info = True, flag_vuln = False))
    # Retrieve severity 3-5 issues from SQlite.
    if flag_vuln:
        issues = issues.union(db_query(q_where = 'office', q_value = (office,), flag_info = False, flag_vuln = True))
    if not issues:
        logging.debug('No issues found by param_office \'%s\'' % (office))
        #print 'No issues found from office \'%s\'' % (office)
    logging.debug('param_office.issues = %s' % (issues))
    return issues


def param_run_number(my_run_number, flag_info, flag_vuln):
    """Returns set of tuples of all issues matching my_run_number from SQLite DB.
       Tuple format = ('ISSUE_KEY', is_info_vuln)
       
       Example:    set(('NASEC-101', True), ('NASEC-102', False))
                   where NASEC-101 is an informational vuln and NASEC-102 is severity 3-5 vuln.
    """
    # Initiate SQLite db
    global auth, conn, cursor
    logging.debug('param_run_number(%s, %s, %s)' % (my_run_number, flag_info, flag_vuln))
    # Set issues will hold all issues combined.
    issues = set()
    # Fetch issues.
    if is_positive_integer(my_run_number):
        if flag_info:
            # Fetch authentication information issues.
            issues = issues.union(db_query(q_table = 'info_incidents', q_where = 'run_number', q_value = (my_run_number,)))
        if flag_vuln:
            # Fetch bad issues.
            issues = issues.union(db_query(q_where = 'run_number', q_value = (my_run_number,)))
    elif my_run_number.lower() == 'all':
        # All run_numbers.
        if flag_info:
            issues = issues.union(db_query(q_table = 'info_incidents'))
        else:
            issues = issues.union(db_query(q_where = 'run_number', q_value = (my_run_number,)))
    else:
        logging.error('%s not valid.' % (my_run_number))
        print '\'%s\' not valid.' % (my_run_number)
    if not issues:
        logging.debug('No issues found by run_number \'%s\'.' % (my_run_number))
        print 'No issues found by run_number \'%s\'.' % (my_run_number)
    logging.debug('param_run_number.issues = %s' % (issues))
    return issues


def param_round_number(my_round_number, flag_info, flag_vuln):
    """Returns set of tuples of all issues matching my_round_number from SQLite DB.
       Tuple format = ('ISSUE_KEY', is_info_vuln)
       
       Example:    set(('NASEC-101', True), ('NASEC-102', False))
                   where NASEC-101 is an informational vuln and NASEC-102 is severity 3-5 vuln.
    """
    # Initiate SQLite db.
    global auth, conn, cursor
    logging.debug('param_round_number(%s, %s, %s)' % (my_round_number, flag_info, flag_vuln))
    # Set issues will hold all issues combined.
    issues = set()
    # Fetch issues.
    if is_positive_integer(my_round_number):
        if flag_info:
            # Fetch authentication information issues.
            issues = issues.union(db_query(q_table = 'info_incidents', q_where = 'round_number', q_value = (my_round_number,)))
        if flag_vuln:
            # Fetch bad issues.
            issues = issues.union(db_query(q_where = 'round_number', q_value = (my_round_number,)))
    else:
        logging.error('%s not valid.' % (my_round_number))
        print '\'%s\' not valid.' % (my_round_number)
    if not issues:
        logging.debug('No issues found by round_number \'%s\'.' % (my_round_number))
        print 'No issues found by round_number \'%s\'.' % (my_round_number)
    logging.debug('param_round_number.issues = %s' % (issues))
    return issues


def office_id(office):
    global qg_asset_groups
    logging.debug('office_id(\'%s\')' % (office))
    for a in qg_asset_groups:
        if a['office'] == office:
            # Found asset group dictionary.
            return a['id']
    logging.debug('\'office_id(%s)\' not found.' % (office))
    return False


def office_name(id):
    global qg_asset_groups
    logging.debug('office_name(\'%s\')' % (id))
    for a in qg_asset_groups:
        if a['id'] == id:
            # Found asset group dictionary.
            return a['office']
    logging.debug('office_name(%s) not found.' % (id))
    return False


def index_of_first_digit(s):
    m = re.search("\d", s)
    if m:
        return m.start()
    #No digit in that string.
    return False


def CellsGetAction(gd_client, key, wksht_id):
  # Get the feed of cells
  feed = gd_client.GetCellsFeed(key, wksht_id)
  return feed


def ListGetAction(gd_client, key, wksht_id):
  # Get the list feed
  feed = gd_client.GetListFeed(key, wksht_id)
  return feed


def gdocs_column_to_number(c):
    """Return number corresponding to excel-style column."""
    sum = 0
    for l in c:
      if not l in string.ascii_letters:
        return False
      sum *= 26
      sum += ord(l.upper()) - 64
    return sum


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


def gdocs_update_office(feed, which_office, column, data):
    global gdocs_headers
    logging.debug('gdocs_update_office(feed, %s, %s, %s)' % (which_office, column, data))
    found = False
    for i, entry in enumerate(feed.entry):
        if '%s - %s' % (entry.custom['region'].text, entry.custom['office'].text) == which_office:
            found = i + 2
            logging.debug('Found row for which_office: %s' % (found))
            CellsUpdateAction2(found, gdocs_headers[column], data)
            break
    return found


def CellsUpdateAction2(row, col, inputValue):
    global gd_client, gdocs_key, wksht_id
    logging.debug('%s, %s, %s' % (row, col, inputValue))
    entry = gd_client.UpdateCell(row = row, col = col, inputValue = inputValue, key = gdocs_key, wksht_id = wksht_id)
    if isinstance(entry, gdata.spreadsheet.SpreadsheetsCell):
        logging.debug('Updated %s' % (inputValue))
        return True
    else:
        return False


def gdocs_offices():
    """Return list of offices from Google Docs."""
    global feed
    # Retrieve list of asset groups from Google Docs.
    gdocs_offices = set()
    # Traverse Google Docs rows for matching data.
    for i, entry in enumerate(feed.entry):
        try:
            region = entry.custom['region'].text
            office = '%s - %s' % (region, entry.custom['office'].text)
            logging.debug('Adding \'%s\' to gdocs_offices' % (office))
            gdocs_offices.add(office)
        except AttributeError:
            pass
    logging.debug('gdocs_offices = %s' % (gdocs_offices))
    return gdocs_offices


def jira_date_issued(issues):
    """Return date that QGIR tickets were issued against office for round round_number."""
    global auth
    if not issues:
        logging.error('No tickets issued for this round.')
        return False
    # Retrive issue information.
    issue = jira_get_issue(issues[0][0])
    # Convert 'datetime.datetime' object to string.
    created = str(issue['created'])
    # Return created date without the time.  Example: '2011-08-16 09:19:32' --> '2011-08-16'.
    return created[:created.find(' ')]

def jira_count_resolved(issues):
    """Return number of QGIR tickets marked resolved against office for round round_number."""
    issue_count = 0
    if not issues:
        logging.error('No tickets issued for this round.')
        return 'N/A'
    # Traverse issues.
    for i in issues:
        issue = jira_get_issue(i[0])
        if issue['status'] == '5':
            # Issue is marked resolved.
            issue_count += 1
    return issue_count


def offices_from_round(round_number = None, flag_info = None, flag_vuln = None, missing = False, feed = False):
    """Print asset groups missing or reported from round round_number."""
    # Initiate SQLite db.
    global conn, cursor
    logging.debug('offices_from_round(%s, flag_info = %s, flag_vuln = %s, missing = %s)' % (round_number, flag_info, flag_vuln, missing))
    # Retrieve list of offices from Google Docs.
    current_offices = gdocs_offices()
    # Print asset_groups remaining for information gathered.
    if flag_info:
        requested_offices = set()
        # Fetch authentication information asset_groups.
        requested_offices = db_query(q_select = 'DISTINCT office', q_table = 'info_incidents', q_where = 'round_number', q_value = (round_number,))
        if missing:
            # Take difference from list of current offices.  
            requested_offices = current_offices.difference(requested_offices)
        if missing:
            request_type = 'pending'
        else:
            request_type = 'reported'
        print 'Information gathered asset groups %s (count of %s):' % (request_type, len(requested_offices))
        for o in sorted(requested_offices):
            if missing:
                print o
            else:
                issues = populate_issues_specified(None, None, o, True, False, round_number)
                if issues:
                    date_issued = jira_date_issued(issues)
                    number_of_issues_resolved = jira_count_resolved(issues)
                    issues_resolved = '%s of %s marked resolved' % (number_of_issues_resolved, len(issues))
                    # Calculate percent of tickets marked resolved.
                    try:
                        percent_resolved = '(%s%%)' % (100 - int(round((len(issues) - number_of_issues_resolved) / float(len(issues)) * 100)))
                    except ZeroDivisionError, e:
                        # There are no issues.
                        percent_resolved = ''
                    resolved_stats = '%s %s' % (issues_resolved, percent_resolved)
                    statistics = 'issued on %s, %s' % (date_issued, resolved_stats)
                else:
                    statistics = 'N/A'
                # Print office and office statistics.
                print '%s: %s' (o, statistics)
        print
    # Print asset_groups remaining for bad vulnerabilites.
    if flag_vuln:
        requested_offices = set()
        # Fetch reported bad offices.
        requested_offices = db_query(q_select = 'DISTINCT office', q_where = 'round_number', q_value = (round_number,))
        if missing:
            # Take difference from list of current offices.  
            requested_offices = current_offices.difference(requested_offices)
        if missing:
            request_type = 'pending'
        else:
            request_type = 'reported'
        print 'Severity 3 through 5 asset groups %s (count of %s):' % (request_type, len(requested_offices))
        for o in sorted(requested_offices):
            if missing:
                print o
            else:
                issues = populate_issues_specified(None, None, o, False, True, round_number)
                if issues:
                    date_issued = jira_date_issued(issues)
                    number_of_issues_resolved = jira_count_resolved(issues)
                    issues_resolved = '%s of %s marked resolved' % (number_of_issues_resolved, len(issues))
                    # Calculate percent of tickets marked resolved.
                    try:
                        percent_resolved = '(%s%%)' % (100 - int(round((len(issues) - number_of_issues_resolved) / float(len(issues)) * 100)))
                    except ZeroDivisionError, e:
                        # There are no issues.
                        percent_resolved = ''
                    resolved_stats = '%s %s' % (issues_resolved, percent_resolved)
                    statistics = 'issued on %s, %s' % (date_issued, resolved_stats)
                else:
                    statistics = 'N/A'
                # Print office and office statistics.
                print '%s: %s' % (o, statistics)
                logging.critical('%s: %s' % (o, statistics))
                if feed:
                    # Update Google spreadsheet.
                    gdocs_update_office(feed, o, 'dateissued', date_issued)
                    gdocs_update_office(feed, o, 'sev.5ticketsissued', str(len(issues)))
                    gdocs_update_office(feed, o, 'sev.5markedresolved', str(number_of_issues_resolved))
        print
    return True


#def offices_from_round_old(round_number = None, flag_info = None, flag_vuln = None, missing = False):
#    """Print asset groups missing or reported from round round_number."""
#    # Initiate SQLite db.
#    global auth, conn, cursor, qg_asset_groups
#    logging.debug('offices_from_round(%s, flag_info = %s, flag_vuln = %s)' % (round_number, flag_info, flag_vuln))
#    if not is_positive_integer(round_number):
#        logging.error('%s not valid.' % (round_number))
#        print '\'%s\' not valid.' % (round_number)
#        return False
#    # Retrieve list of asset groups from Google Docs.
#    gdocs_offices = set()
#    # Traverse Google Docs rows for matching data.
#    for i, entry in enumerate(feed.entry):
#        try:
#            region = entry.custom['region'].text
#            office = '%s - %s' % (region, entry.custom['office'].text)
#            logging.debug('Adding \'%s\' to gdocs_offices' % (office))
#            gdocs_offices.add(office)
#        except AttributeError:
#            pass
#    logging.debug('gdocs_offices = %s' % (gdocs_offices))
#    # Add all asset group ID numbers.
#    all_office_qg_ids = set()
#    # Traverse list of dictionaries of asset group office names and ID.
#    for o in sorted(gdocs_offices):
#        logging.debug('%s: %s' % (o, office_id(o)))
#        all_office_qg_ids.add(office_id(o))
#    logging.debug('all_office_qg_ids = %s' % (all_office_qg_ids))
#    # Print asset_groups remaining for information gathered.
#    if flag_info:
#        offices_qg_ids = set()
#        offices = set()
#        # Fetch authentication information asset_groups.
#        asset_groups = db_query(q_select = 'office', q_table = 'info_incidents', q_where = 'round_number', q_value = (round_number,))
#        for i in sorted(all_office_qg_ids):
#            if missing:
#                if i not in asset_groups:
#                    offices_qg_ids.add(i)
#            else:
#                if i in asset_groups:
#                    offices_qg_ids.add(i)
#        for i in offices_qg_ids:
#            offices.add(office_name(i))
#        print 'Information gathered asset groups pending (count of %s):' % (len(offices))
#        for o in sorted(offices):
#            print o
#        print
#    if flag_vuln:
#        offices_qg_ids = set()
#        offices = set()
#        # Fetch bad asset_groups.
#        asset_groups = db_query(q_select = 'office', q_where = 'round_number', q_value = (round_number,))
#        for i in sorted(all_office_qg_ids):
#            if missing:
#                if i not in asset_groups:
#                    offices_qg_ids.add(i)
#            else:
#                if i in asset_groups:
#                    offices_qg_ids.add(i)
#        for i in offices_qg_ids:
#            offices.add(office_name(i))
#        print 'Severity 3 through 5 asset groups pending (count of %s):' % (len(offices))
#        for o in sorted(offices):
#            print o
#        print
#    return True


def vuln_count(issues_specified, print_to, stats):
    """Return number of vulnerabilities from issues_specified in tuple format (total_info, total_bad)."""
    logging.debug('vuln_count(%s, %s, %s)' % (issues_specified, print_to, stats))
    total_info = 0
    total_bad = 0
    remediation_tickets = []
    for i in issues_specified:
        if i[1]:
            # Information gathered vulnerability.
            continue
        # Severity 3 through 5 vulnerability.
        count_query = cursor.execute('SELECT COUNT(*) FROM remediation WHERE issue_key = ?', (i[0],)).fetchall().pop()[0]
        if print_to:
            for ticket in cursor.execute('SELECT remediation_ticket FROM remediation WHERE issue_key = ?', (i[0],)).fetchall():
                remediation_tickets.append(int(ticket[0]))
        total_bad += int(count_query)
    # Sort ticket numbers
    remediation_tickets = sorted(remediation_tickets)
    logging.debug('remediation_tickets = %s' % (remediation_tickets))
    # Print out each Qualys Remediation vulnerability.
    if remediation_tickets and print_to.lower() == 'screen':
        # Print remediation tickets to screen.
        for ticket in remediation_tickets:
            print ticket
    elif remediation_tickets:
        # Print remediation tickets to file.
        with open(print_to, 'w') as f:
            for ticket in remediation_tickets:
                print >> f, ticket
    # Store tickets values.
    vulns_open = len(remediation_tickets)
    vulns_resolved = False
    if stats:
        # Convert to ranges notation. E.g.: [1,2,3,4,6,7,8,9,12,13,19,20,22,23,40,44] --> '1-4,6-9,12-13,19-20,22-23,40,44'
        print '\nConverting to range notation...'
        # The idea here is to pair each element with count(). Then the difference between the value and count() is constant for consecutive values.
        paired_with_count = (list(x) for _, x in itertools.groupby(remediation_tickets, lambda x, c = itertools.count(): next(c) - x))
        # Finish off conversion with group_by.
        remediation_tickets_ranges = ','.join('-'.join(map(str, (g[0], g[-1])[:len(g)])) for g in paired_with_count)
        # Track vulnerability metrics.
        print 'Retrieving status of tickets...'
        vulns_open = set()
        vulns_closed = set()
        vulns_ignored = set()
        # Call Qualysguard
        import urllib2
        # Create a password manager.
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        # Add the username and password.
        top_level_url = 'https://qualysapi.qualys.com'
        username = 'qg_username'
        password = 'password'
        password_mgr.add_password(None, top_level_url, username, password)
        handler = urllib2.HTTPBasicAuthHandler(password_mgr)
        # Create "opener" (OpenerDirector instance).
        opener = urllib2.build_opener(handler)
        # Install the opener.
        # Now all calls to urllib2.urlopen use our opener.
        urllib2.install_opener(opener)
        # Create request.
        headers = {'X-Requested-With':'QGIR'}
        uri = 'https://qualysapi.qualys.com/msp/ticket_list.php'
        # Start searching at initial ticket #1.
        since_ticket_number = 1
        while True:
            # Set the request.
            data = 'ticket_numbers=%s&since_ticket_number=%s' % (remediation_tickets_ranges, since_ticket_number)
            # Make request to fetch url.
            req = urllib2.Request(uri, data, headers)
            result = urllib2.urlopen(req)
            # Read xml results.
            xml_output = result.read()
            logging.debug('qg_remediation_tickets.xml_output =')
            logging.debug(xml_output)
            # Objectify XML.
            tree = objectify.fromstring(xml_output)
            # Parse vulnerabilities.
            try:
                for ticket in tree.TICKET_LIST.TICKET:
                    vuln_id = int(unicodedata.normalize('NFKD', unicode(ticket.NUMBER)).encode('ascii', 'ignore').strip())
                    state = unicodedata.normalize('NFKD', unicode(ticket.CURRENT_STATE)).encode('ascii', 'ignore').lower().strip()
                    logging.debug('Vulnerability %s: %s' % (vuln_id, state))
                    # Attempt to add host to QID's list of affected hosts if open state.
                    if state == 'open':
                        remediation_tickets.remove(vuln_id)
                        vulns_open.add(vuln_id)
                    else:
                        # Ticket is closed.  Discern if ticket is ignored versus fixed.
                        current_status = unicodedata.normalize('NFKD', unicode(ticket.CURRENT_STATUS)).encode('ascii', 'ignore').lower().strip()
                        logging.debug('Vulnerability %s: %s' % (vuln_id, current_status))
                        if current_status == 'fixed':
                            remediation_tickets.remove(vuln_id)
                            vulns_closed.add(vuln_id)
                        elif current_status == 'ignored':
                            remediation_tickets.remove(vuln_id)
                            vulns_ignored.add(vuln_id)
                        else:
                            logging.error('ERROR: Ticket %s has state %s' % (state))
            except AttributeError, e:
                logging.debug('No QualysGuard tickets to report.')
                break
            # All vulnerabilities counted.
            try:
                # See if the API call was truncated due to API limit of 1000 records at a time.
                since_ticket_number = tree.TRUNCATION.get('last')
            except AttributeError:
                # No more API calls necessary.
                break
            # Report metrics.
        logging.debug('vulns_open = %s' % (vulns_open))
        logging.debug('vulns_closed = %s' % (vulns_closed))
        logging.debug('vulns_ignored = %s' % (vulns_ignored))
        print 'Vulns open: ', len(vulns_open)
        print 'Vulns closed: ', len(vulns_closed)
        print 'Vulns ignored: ', len(vulns_ignored)
        print
        vulns_resolved = len(vulns_closed) + len(vulns_ignored)
        print 'Vulns resolved: ', len(vulns_closed) + len(vulns_ignored)
    # Return count of both informational tickets and severity 3-5 vulnerabilities. 
    return (total_info, total_bad, vulns_resolved)


def db_query(q_table = 'incidents', q_select = 'issue_key', q_where = None, q_where_operator = '=', q_value = None, flag_info = False, flag_vuln = False):
    """Perform query against sqlite table:  'SELECT issue_key FROM q_table WHERE q_where q_where_operator q_value'.
       Return set of matched issues, or whatever.
       
       Example:    set(('168780', '168882', '169124', '168767')   
                   where the set is filled with remediation ticket numbers.
    """
    logging.debug('db_query(q_table = %s, q_where = %s, q_where_operator = %s, q_value = %s, flag_info = %s, flag_vuln = %s)' % (q_table, q_where, q_where_operator, q_value, flag_info, flag_vuln))
    if not q_where or q_value == 'all':
        logging.debug('SELECT %s FROM %s' % (q_select, q_table))
        rows_incidents = cursor.execute('SELECT %s FROM %s' % (q_select, q_table)).fetchall()
    else:
        logging.debug('SELECT %s FROM %s WHERE %s %s %s' % (q_select, q_table, q_where, q_where_operator, q_value))
        rows_incidents = cursor.execute('SELECT %s FROM %s WHERE %s %s (%s)' % (q_select, q_table, q_where, q_where_operator, ('?, ' * len(q_value))[:-2]), q_value).fetchall()
    if rows_incidents == []:
        return set()
    values = set()
    for i in rows_incidents:
        try:
            value_to_add = unicodedata.normalize('NFKD', i[0]).encode('ascii', 'ignore')
        except TypeError, e:
            # Value is None.
            value_to_add = False
        if q_select == 'issue_key':
            # Add issue key and whether the issue was informational. 
            values.add((value_to_add, flag_info))
        else:
            # Not an issue key, just add the value.
            values.add(value_to_add)
    logging.debug('db_query.values = %s' % (values))
    return values


def populate_issues_specified(issues = None, run_number = None, office = None, flag_info = None, flag_vuln = None, round_number = None):
    """Returns sorted list of tuples of all issues requested.
       Tuple format = ('ISSUE_KEY', is_info_vuln)
       
       Example:  [('NASEC-101', True), ('NASEC-102', False)]
                 where NASEC-101 is an informational vuln and NASEC-102 is severity 3-5 vuln."""
    set_of_issues = set()
    issues_info = set()
    issues_sev3_5 = set()
    # Check for run_number argument.
    if run_number:
        # Populate issues matching run_number.
        logging.debug('post-run_number set: set_of_issues = ')
        if run_number.lower() == 'all':
            set_of_issues = set_of_issues.union(param_run_number(run_number, flag_info, flag_vuln))
        else:
            for n in parse_int_set(run_number):
                set_of_issues = set_of_issues.union(param_run_number(run_number, flag_info, flag_vuln))
    # Check for issue argument.
    if issues:
        logging.debug('post-issues set: set_of_issues =')
        set_of_issues = set_of_issues.union(param_issues(issues))
    # Check for round argument.
    if round_number:
        logging.debug('post-round_number set: set_of_issues =')
        set_of_issues = set_of_issues.union(param_round_number(round_number, flag_info, flag_vuln))
    # Check for office argument.
    if office:
        logging.debug('issues_office =')
        issues_office = param_office(office, flag_info, flag_vuln)
        # Select subset of issues chosen that match the asset group.
        logging.debug('post-office set: set_of_issues =')
        set_of_issues = set_of_issues.intersection(issues_office)
    # Sort issues alphabetically.
    if not set_of_issues:
        return False
    list_of_issues = sort_naturally(list(set_of_issues), itemgetter(0))
    logging.debug('list_of_issues = %s' % (list_of_issues))
    if list_of_issues == [()]:
        return False
    return list_of_issues


def sort_naturally(l, key):
    """ Sort the given iterable in the way that humans expect."""
    convert = lambda text: int(text) if text.isdigit() else text
    alphanum_key = lambda item: [ convert(c) for c in re.split('([0-9]+)', key(item)) ]
    return sorted(l, key = alphanum_key)


#
#
# Start of QGIR
#
#
# Declare the command line flags/options we want to allow.
parser = argparse.ArgumentParser(description = 'Issue Jira incidents of QualysGuard reports.')
#parser.add_argument('--scan_xml',
#                    help = 'Manually use SCAN_XML QualysGuard scan report XML file.')
parser.add_argument('-0', '--close_only', action = 'store_true',
                    help = 'Do not reopen validated issues.')
parser.add_argument('-1', '--info_gathered', action = 'store_true', default = False,
                    help = 'Report informational gathered vulnerabilities related to failed authentication.')
parser.add_argument('-a', '--assign',
                    help = 'Assign issues specified or reported vulnerabilies to ASSIGN.')
parser.add_argument('-b', '--bad', action = 'store_true',
                    help = 'Add all severity 3 through 5 vulnerabilities.')
parser.add_argument('-c', '--comment',
                    help = 'Add COMMENT to issues specified.')
parser.add_argument('--debug', action = 'store_true',
                    help = 'Outputs additional information to log.')
parser.add_argument('--debug_qg_xml', action = 'store_true',
                    help = 'Save QualysGuard XML and ignore reporting issues.')
parser.add_argument('-d', '--delete', action = 'store_true',
                    help = 'Delete issues specified.')
parser.add_argument('-f', '--finished', action = 'store_true',
                    help = 'Print offices that have been reported for round ROUND.')
parser.add_argument('-i', '--issues',
                    help = 'Specify ISSUES to act on.')
parser.add_argument('-l', '--list', action = 'store_true',
                    help = 'List issues specified.')
parser.add_argument('-m', '--max', type = int,
                    help = 'Maximum QIDs to issue issues for (default = infinite).')
parser.add_argument('-n', '--run_number',
                    help = 'Specify RUN_NUMBER issues to act on.')
parser.add_argument('-o', '--office', default = False,
                    help = 'Asset group to scan. (E.g.: \'NA - New York\')')
parser.add_argument('-p', '--pending', action = 'store_true',
                    help = 'Print offices that have not yet been reported for round ROUND.')
parser.add_argument('-q', '--qids',
                    help = 'Only report QID vulnerabilities.')
parser.add_argument('-r', '--report', action = 'store_true',
                    help = 'Report vulnerabilities into Jira.')
parser.add_argument('-t', '--test_stage', action = 'store_true',
                    help = 'Test QGIR run on Stage Jira.')
parser.add_argument('-u', '--round_number',
                    help = 'Specify issues in round ROUND to act on.')
parser.add_argument('-v', '--validate', action = 'store_true',
                    help = 'Validate incidents marked restored.')
parser.add_argument('-#', '--vuln_count',
                    help = 'Print number of vulnerabilities issued, and print ticket numbers to "screen" or to VULN_COUNT file.')
parser.add_argument('-s', '--statistics', action = 'store_true',
                    help = 'Print number of vulnerabilities closed.')
parser.add_argument('-z', '--z_all_offices', action = 'store_true',
                    help = 'Print all offices.')
parser.add_argument('-w', '--what_run_number', action = 'store_true',
                    help = 'Print current run_number.')
# Parse arguments.
c_args = parser.parse_args()
# Create log directory.
PATH_LOG = 'log'
if not os.path.exists(PATH_LOG):
    os.makedirs(PATH_LOG)
# Set log options.
now = datetime.datetime.now()
LOG_FILENAME = '%s/%s-%s.log' % (PATH_LOG,
                                 __file__,
                                 datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))
if c_args.debug:
    # Enable debug level of logging.
    print "Logging level set to debug."
    logging.basicConfig(filename = LOG_FILENAME, format = '%(asctime)s %(message)s',
                        level = logging.DEBUG)
    logging.getLogger('suds').setLevel(logging.INFO)
else:
    logging.basicConfig(filename = LOG_FILENAME, format = '%(asctime)s %(message)s',
                        level = logging.INFO)
# Create output directory.
# TODO: Grab asset group ID and use that as subdirectory to data
PATH_DATA = 'data'
if not os.path.exists(PATH_DATA):
    logging.info('Creating output directory %s.' % (PATH_DATA))
    os.makedirs(PATH_DATA)
# Set values.
asset_group = c_args.office
logging.debug('asset_group = %s' % (asset_group))
# Validate input.
if c_args.round_number and not is_positive_integer(c_args.round_number):
    logging.error('ROUND_NUMBER %s not valid.' % (c_args.round_number))
    print 'ROUND_NUMBER \'%s\' not valid.' % (c_args.round_number)
    exit(1)
if not (c_args.what_run_number or \
        (c_args.max is not None and c_args.max > 0) or \
        ((c_args.info_gathered or c_args.bad or c_args.validate) and asset_group) or \
        ((c_args.assign or c_args.comment or c_args.delete or c_args.list or c_args.vuln_count or c_args.validate) and (c_args.issues or c_args.run_number or c_args.round_number or c_args.office)) or \
        ((c_args.pending or c_args.finished) and c_args.round_number) or \
        (c_args.report and c_args.office)):
    parser.print_help()
    logging.error('Invalid run parameters.')
    exit(1)
# Google Docs Login information
gd_client = gdata.spreadsheet.service.SpreadsheetsService()
gd_client.email = 'Google Username'
gd_client.password = 'Google password'
gd_client.source = 'QGIR'
gd_client.ProgrammaticLogin()
# Obtain spreadsheet tracker feed.
feed = gd_client.GetListFeed('g_spreadsheet_id', 1)
# Initiate variables.
if c_args.qids and c_args.max > 1:
    # Overwrite maximum QIDs to report.
    logging.debug('Resetting maximum QIDs to 1.')
    print 'Resetting maximum QIDs to 1.'
    c_args.max = 1
total_issues = 0
# Initiate SQLite db
logging.debug('Connecting to database...')
if c_args.test_stage:
    conn = sqlite3.connect('data/stage-qgir.sqlite')
    jira_wsdl_url = 'file://%s/stage-jirasoapservice-v2.xml' % (os.getcwd())
    jira_password = 'jira_pw'
    j = jira.jira(logging, 'stage', 'qgir@email.com')
else:
#    conn = sqlite3.connect('data/qgir.sqlite')
    # Using old db data.
    conn = sqlite3.connect('data/db/qgir_round_1_old.sqlite')
    jira_wsdl_url = 'file://%s/jirasoapservice-v2.xml' % (os.getcwd())
    jira_password = 'jira_pw'
    j = jira.jira(logging, 'production', 'qgir@company.com')
cursor = conn.cursor()
# Initiate suds configuration.
logging.debug('Done connecting to database.')
logging.debug('Connecting to Jira...')
# Server WSDL pointing to WAF, use WSDL file that references https://jira-ocd.stage.company.com instead of https://jira.stage.company.com.
#jira_wsdl_url = 'https://jira-ocd.stage.company.com/rpc/soap/jirasoapservice-v2?wsdl'
client = Client(jira_wsdl_url)
client.set_options(cache = None)
jira_username = 'qgir@company.com'
#jira_auth = jira_login('file://%s/%s' % (os.getcwd(), ConfigSectionMap('JIRA')['wsdl']), ConfigSectionMap('JIRA')['username'], ConfigSectionMap('JIRA')['password'])
MAX_CHECKS = 10
attempts = 0
for n in range(0, MAX_CHECKS):
    try:
        auth = client.service.login(jira_username, jira_password)
        break
    except urllib2.URLError, e:
        attempts += 1
        print 'urllib2 %d: %s' % (e.args[0], e.args[1])
        logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
        if attempts == MAX_CHECKS:
            print 'Error threshold reached.'
            exit(1)
        continue
j.auth = auth
# Log in to QualysGuard API.
qg_username = 'qg_username'
qg_password = 'password'
#session_id = qg_login(qg_username, qg_password)
#if not session_id:
#    print 'Unable to authenticate to QualysGuard. Quitting...'
#    exit(1)
# Initiate db.
db_initiate()
# Retreive current list of asset groups
qg_asset_groups = qg_ag_list()
logging.debug('qg_asset_groups = %s' % (qg_asset_groups))
# Retrieve asset group's details.
asset_group_details = asset_group_lookup(asset_group)
if not asset_group_details and (c_args.report or c_args.office):
    print 'Asset group \'%s\' not found! Exiting.' % (asset_group)
    exit(1)
# Grab run_number from db.
run_number = 1 + db_current_run_number()
logging.debug('run_number = %s' % (run_number))
# Retrieve round_number from db.
round_number = db_round_number()
logging.debug('round_number = %s' % (round_number))
logging.debug('Done connecting to Jira.')
# Default to both run_number & info_gathered if run_number is True.
if (c_args.run_number or c_args.round_number) and not (c_args.info_gathered or c_args.bad):
    c_args.info_gathered = True
    c_args.bad = True
# Check for issues specified argument.
if c_args.issues or c_args.run_number or c_args.round_number:
    # Populate issues specified.
    issues_specified = populate_issues_specified(issues = c_args.issues, run_number = c_args.run_number, office = c_args.office, flag_info = c_args.info_gathered, flag_vuln = c_args.bad, round_number = c_args.round_number)
    logging.debug('issues_specified = %s' % (issues_specified))
    if not issues_specified:
        print 'No issues specified.  Exiting.'
        exit(0)
# Check for list argument.
if c_args.list:
    param_list(issues_specified)
# Check for delete issue argument.
if c_args.delete:
    if not c_args.test_stage:
        sure_to_delete = raw_input('Are you sure you want to delete from PRODUCTION jira (\'Yes\' to continue)? ')
        if not sure_to_delete == 'Yes':
            print 'Exiting without deleting.'
            exit(0)
    if param_delete(issues_specified):
        print 'Deletion successful.'
    else:
        print 'Deletion (possibly partly) unsuccessful.'
# Check for run_number paramter.
if c_args.what_run_number:
    print (run_number - 1)
# Check for assign paramter.
if c_args.assign and not c_args.report:
    if param_change_assignee(c_args.assign, issues_specified):
        print 'Reassignment successful.'
    else:
        print 'Reassignment (possibly partly) unsuccessful.'
# Check for assign paramter.
if c_args.comment:
    if param_comment(c_args.comment, issues_specified):
        print 'Commenting successful.'
    else:
        print 'Commenting (possibly partly) unsuccessful.'
# Check for validate paramter.
if c_args.validate:
    validate(issues_specified)
# Check for validate paramter.
if c_args.pending:
    offices_from_round(c_args.round_number, flag_info = c_args.info_gathered, flag_vuln = c_args.bad, missing = True)
if c_args.finished:
    # QGIR report.
    gdocs_key = '0AlYIuKbX9Nf_dDZ6MFEzRXAwY0lFemFIRXluYVRTYkE'
    # Worksheet number refers to which round we are reporting.
    wksht_id = round_number
    # Get cell feed for numbering column headers.
    feed = CellsGetAction(gd_client, gdocs_key, wksht_id + 3)
    gdocs_headers = gdocs_column_headers(feed)
    logging.debug('Headers for Google Spreadsheet')
    for key in sorted(gdocs_headers.iterkeys()):
        logging.debug('%s %s' % (key, gdocs_headers[key]))
    # Get list feed.
    feed = ListGetAction(gd_client, gdocs_key, wksht_id)
    # Retrive stats.
    offices_from_round(c_args.round_number, flag_info = c_args.info_gathered, flag_vuln = c_args.bad, feed = feed)
if c_args.vuln_count:
    if c_args.z_all_offices:
        key = '0AlYIuKbX9Nf_dDZ6MFEzRXAwY0lFemFIRXluYVRTYkE'
        feed2 = gd_client.GetListFeed(key, 4)
        for i, entry in enumerate(feed2.entry):
            try:
                region = entry.custom['region'].text
                office = '%s - %s' % (region, entry.custom['office'].text)
                if entry.custom['dateissued'].text:
                    print office
                    issues_specified = populate_issues_specified(issues = c_args.issues, run_number = c_args.run_number, office = office, flag_info = c_args.info_gathered, flag_vuln = c_args.bad, round_number = c_args.round_number)
                    total_vulns = vuln_count(issues_specified, c_args.vuln_count, c_args.statistics)
                    print 'Total information gathered vulnerabilities = %s' % (total_vulns[0])
                    print 'Total severity 3 through 5 vulnerabilities = %s' % (total_vulns[1])
                    print 'Total vulnerabilities = %s' % (total_vulns[0] + total_vulns[1])
                    # Update vulnerability count.
                    #entry.custom['vulnsclosed'].text = static_ip_range
                    # Change static range in Google Docs.
                    gd_client.UpdateCell(row = i + 2, col = 13, inputValue = datetime.datetime.now().strftime('%m-%d-%Y'), key = key, wksht_id = 4)
                    gd_client.UpdateCell(row = i + 2, col = 14, inputValue = str(total_vulns[2]), key = key, wksht_id = 4)
                    gd_client.UpdateCell(row = i + 2, col = 15, inputValue = str(total_vulns[1]), key = key, wksht_id = 4)
            except AttributeError:
                print 'Failed.'
                exit()
    else:
        total_vulns = vuln_count(issues_specified, c_args.vuln_count, c_args.statistics)
        print 'Total information gathered vulnerabilities = %s' % (total_vulns[0])
        print 'Total severity 3 through 5 vulnerabilities = %s' % (total_vulns[1])
        print 'Total vulnerabilities = %s' % (total_vulns[0] + total_vulns[1])
    exit()
if not c_args.qids == None:
    c_args.qids = ','.join([str(x) for x in parse_int_set(c_args.qids)])
    logging.debug('Parsed c_args.qid = %s' % (c_args.qids))
if c_args.report and c_args.info_gathered:
    # Report informational QIDs pertaining to failed authentication.
    xml_info_gathered = qg_command(2, 'report', {'action': 'launch', 'report_type':'Scan', 'output_format': 'xml', 'asset_group_ids': asset_group_details['qg_asset_group_id'], 'template_id':'1138845', 'report_title':'QGIR Authentication Failed - %s' % (asset_group)})
    info_vulns = qg_parse_informational_qids(xml_info_gathered)
    print 'Reporting informational vulnerabilities.'
    # Report vulnerabilities.
    if not info_vulns:
        print 'No information gathered vulnerabilities to report.'
    if info_vulns and not c_args.debug_qg_xml:
        jira_report(info_vulns, True)
    else:
        # There are no vulnerabilities to report.
        # Write xml file to disk.
        filename = 'debug/' + ('debug-%s-info-%s.xml' % (asset_group, datetime.datetime.now().strftime('%Y-%m-%d.%H-%M-%S'))).replace('/', '-')
        print filename
        with open(filename, 'w') as f:
            f.write(xml_info_gathered)
if c_args.report and c_args.bad:
    # Initiate ticketing processing.
    vulns = qg_ticket_list(asset_group, 5, c_args.qids)
    logging.debug('final vulns =')
    logging.debug(vulns)
    if not vulns:
        # There are no vulnerabilities to report.
        print 'No severity 3 through severity 5 vulnerabilities to report.'
    if vulns and not c_args.debug_qg_xml:
        # Report vulnerabilities.
        print 'Reporting severity 3 through severity 5 vulnerabilities.'
        jira_report(vulns)

# Close db
logging.debug('Closing database connection...')
cursor.close()
conn.close()
logging.debug('done.')
exit()

# Exit if we have reported the maximum number of vulnerabilities.
logging.debug('Done.')
logging.info('Priority 1 vulnerabilities issued:  %s' % total_issues)
print 'Done. Priority 1 vulnerabilities issued:  %s' % total_issues
if total_issues >= c_args.max and not c_args.max == None:
    logging.info('Met or exceeded max vulnerabilities (%s).  Exiting.' % (c_args.max))
    print 'Met or exceeded max vulnerabilities (%s).  Exiting.' % (c_args.max)
    exit()
elif total_issues < c_args.max and not c_args.max == None:
    logging.info('Have not met or exceeded max vulnerabilities (%s).' % (c_args.max))
    print 'Have not met or exceeded max vulnerabilities (%s).' % (c_args.max)


# Done for now.
exit()





# Copyright (c) 2011, Parag Baxi, All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
