#!/usr/bin/env python
"""Class to connect QualysGuard to JIRA. Derived from https://marketplace.atlassian.com/10751.

Creating, assigning, attaching files to, and deleting tickets avaiable.
Prerequisites:
JIRA
"""

import logging
import os
import re
import suds
import sys
import unicodedata
import urllib2
import zipfile
from collections import defaultdict


__author__ = "Parag Baxi"
__copyright__ = "Copyright 2012"
__credits__ = ["Parag Baxi"]
__license__ = "Lesser GNU General Public License (LGPL)"
__version__ = "2012.08.10.0"
__maintainer__ = "Parag Baxi"
__email__ = "parag.baxi@gmail.com"
__status__ = "Production"


if __name__ == '__main__':    #code to execute if called from command-line
    pass    #do nothing

class jira:
    def __init__(self, wsdl, username, password, logger = logging):
        """Connect to JIRA instance's SOAP wsdl.
        """
        # logger configuration, suds can be very noisy if debug level is enabled.
        self.logging = logger
        self.logging.getLogger('suds').setLevel(self.logging.INFO)
        # Initiate suds configuration.
        # Server WSDL file.
        self.client = suds.client.Client(wsdl)
        self.client.set_options(cache = None)
        # JIRA login.
        self.username = username
        self.password = password
        self.reporter = username
        self.auth = self._login(self.password)
        # Get associated values for resolution.
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                resolution_types = self.client.service.getResolutions(self.auth)
                break
            except urllib2.URLError, e:
                attempts += 1
                print 'ERROR urllib2: %s' % (str(e))
                self.logging.error('ERROR urllib2: %s' % (str(e)))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                    return False
                continue
        # Dictionary for resolutions
        self.resolutions = defaultdict(str)
        for i, v in enumerate(resolution_types):
            self.resolutions[v['name']] = v['id']
        # Get associated values for statuses.
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                statuses = self.client.service.getStatuses(self.auth)
                break
            except urllib2.URLError, e:
                attempts += 1
                print 'ERROR urllib2: %s' % (str(e))
                self.logging.error('ERROR urllib2: %s' % (str(e)))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                    return False
                continue
        # Dictionary for statuses
        self.statuses = defaultdict(str)
        for i, v in enumerate(statuses):
            self.statuses[v['name']] = v['id']


    def _action_id(self, issue_key, action = None, resolution = None):
        """Return action_id to change status and resolution.
        """
        self.logging.debug('jira._action_id(%s, %s, %s)' % (issue_key, action, resolution))
        # Check if session timed out.
        self._session_renew()
        # Get available actions for status.
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                actions = self.client.service.getAvailableActions(self.auth, issue_key)
                break
            except urllib2.URLError, e:
                attempts += 1
                print 'ERROR urllib2: %s' % (str(e))
                self.logging.error('ERROR urllib2: %s' % (str(e)))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                    return False
                continue
        # Set up return dictionary.
        action_ids = defaultdict(str)
        if action:
            for i, v in enumerate(actions):
                if v['name'] == action:
                    action_ids['status'] = v['id']
                    break
        if resolution:
            action_ids['resolution'] = self.resolutions[resolution]
        if not action_ids:
            self.logging.error('Unable to perform action: ' + action)
            self.logging.error('Choices are: ')
            for i, v in enumerate(actions):
                self.logging.error(v['name'] + ' (' + v['id'] + ')')
            return False
        return action_ids

    def _login(self, password):
        """Return SOAP auth key upon successful login.
        """
        self.logging.debug('jira.login()')
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                auth = self.client.service.login(self.username, password)
                break
            except urllib2.URLError, e:
                attempts += 1
                print 'ERROR urllib2: %s' % (str(e))
                self.logging.error('ERROR urllib2: %s' % (str(e)))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                    return False
                continue
        self.auth = auth
        return auth

    def _session_renew(self):
        """Renew authentication session if it has timed out."""
        try:
            self.client.service.getPriorities(self.auth)
        except suds.WebFault, e:
            if 'com.atlassian.jira.rpc.exception.RemoteAuthenticationException' in str(e):
                # Reauthenticate.
                self.logging.error('Need to reauthenticate, session timed out.')
                self.auth = self._login(self.password)
        return True

    def assign(self, assignee, issue_key):
        """Assign JIRA issue_key to asssignee via SOAP API.
        """
        self.logging.debug('jira.assign(%s, %s)' % (assignee, issue_key))
        # Check if session timed out.
        self._session_renew()
        # Assign issue.
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                self.client.service.updateIssue(
                    self.auth,
                    issue_key,
                    [
                     {'id': 'assignee', 'values': [assignee]},
                     ])
                return True
                break
            except suds.WebFault, e:
                # Try assigning to reporter
                print e
                MAX_CHECKS = 10
                attempts = 0
                for n in range(0, MAX_CHECKS):
                    try:
                        self.client.service.updateIssue(
                            self.auth,
                            issue_key,
                            [
                             {'id': 'assignee', 'values': [self.reporter]},
                             ])
                        print 'Assigned to reporter, %s' % (self.reporter)
                        return True
                        break
                    except urllib2.URLError, e:
                        attempts += 1
                        print 'urllib2 %d: %s' % (e.args[0], e.args[1])
                        self.logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
                        if attempts == MAX_CHECKS:
                            print 'Error threshold reached.'
                            return False
                        continue
                return False
            except urllib2.URLError, e:
                attempts += 1
                print 'urllib2 %d: %s' % (e.args[0], e.args[1])
                self.logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                    return False
                continue
        # Was not able to update assignee.
        return False

    def attach(self, issue_key, filename):
        """Attach CSV to incident.
        """
        self.logging.debug('jira.attach(%s, %s)' % (issue_key, filename))
        # Check if session timed out.
        self._session_renew()
        # Remember current working directory.
        cwd = os.getcwd()
        # Change to directory of file to zip.
        os.chdir(filename[0:filename.rfind('/')])
        # Remove path from filename.
        filename = filename[filename.rfind('/') + 1:]
        # Compress attachment with zip
        filename_zip = '%s.zip' % (filename)
        # Delete zip file in case it already exists due to crash
        if os.path.exists(filename_zip):
            os.remove(filename_zip)
        # Compress from working directory of data to avoid subdirectory in zip file
        with zipfile.ZipFile(filename_zip, 'w') as myzip:
            myzip.write(filename)
        self.logging.debug('zip result: %s' % (filename_zip))
        # Attach compressed CSV
        # Maximum number of times to attach csv:  5.  About 1 minute before timing out.
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                output_attach = self.client.service.addBase64EncodedAttachmentsToIssue(self.auth, issue_key, [filename_zip.encode("utf-8")], [open(filename_zip, "rb").read().encode('base64')])
                break
            except Exception, e:
                self.logging.error(str(e))
                print str(e)
                output_attach = False
                #  raise URLError(err)
                # urllib2.URLError: <urlopen error [Errno 60] Operation timed out>
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                    return False
                continue
        self.logging.debug('Attach command result: %s' % (output_attach))
        # Clean up files
        os.remove(filename_zip)
        os.remove(filename)
        self.logging.debug('CSV (%s) and compressed CSV (%s) files deleted.' % (filename, filename_zip))
        # Return to original working directory.
        os.chdir(cwd)
        return True

    def change_status(self, issue_key, new_status, new_resolution):
        """Close JIRA issue_key via SOAP API.
        """
        self.logging.debug('jira.change_status(%s, %s, %s)' % (issue_key, new_status, new_resolution))
        issue_key = str(issue_key)
        # Check if session timed out.
        self._session_renew()
        # If marking a 'Resolved' issue as Closed/Incomplete...
        if self.get_issue(issue_key)['status'] in [self.statuses['Resolved'],
                                                   self.statuses['Waiting on Request'],
                                                   ] and new_resolution == 'Incomplete':
            self.logging.debug('Reopening %s to mark ticket Closed/Incomplete.' % (issue_key))
            # Reopen issue first to avoid Resolved tickets from being marked Closed/Resolved.
            action_values_reopen = self._action_id(issue_key, 'Reopen Issue', 'Incomplete')
            self.logging.debug('action_values_reopen = %s' % (action_values_reopen))
            MAX_CHECKS = 10
            attempts = 0
            for n in range(0, MAX_CHECKS):
                try:
                    self.logging.debug(self.client.service.progressWorkflowAction(self.auth,
                                                               issue_key,
                                                               action_values_reopen['status'],
                                                               [{'id': 'resolution', 'values': [action_values_reopen['resolution']], }, ],
                                                               ))
                    self.logging.debug('Success in reopening %s to mark ticket Closed/Incomplete.' % (issue_key))
                    break
                except urllib2.URLError, e:
                    attempts += 1
                    print 'urllib2 %d: %s' % (e.args[0], e.args[1])
                    self.logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
                    if attempts == MAX_CHECKS:
                        print 'Error threshold reached.'
                        return False
                    continue
        # Find associated values for action and resolution.
        action_values = self._action_id(issue_key, new_status, new_resolution)
        self.logging.debug('action_values = %s' % (action_values))
        if not action_values:
            print 'Error. No action matches.'
            self.logging.error('Error. No action matches.')
            return False
        # Progress issue.
        self.logging.debug('Progressing %s.' % (issue_key))
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                self.logging.debug(self.client.service.progressWorkflowAction(
                    self.auth,
                    issue_key,
                    action_values['status'],
                    [
                     {'id': 'resolution', 'values': [action_values['resolution']],
                      },
                     ]))
                self.logging.debug('Success in progressing %s.' % (issue_key))
                return True
                break
            except urllib2.URLError, e:
                attempts += 1
                print 'urllib2 %d: %s' % (e.args[0], e.args[1])
                self.logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                    return False
                continue
        # Was not able to update assignee.
        self.logging.debug('Unable to progress %s.' % (issue_key))
        return False

    def close(self, issue_key):
        """Close JIRA issue_key via SOAP API.
        """
        self.logging.debug('jira.close(%s)' % (issue_key))
        self.change_status(issue_key, 'Close Issue', 'Resolved')

    def comment(self, comment, issue_key):
        """Add comment to JIRA issue_key via SOAP API.
        """
        self.logging.debug('jira.comment(%s, %s)' % (comment, issue_key))
        # Check if session timed out.
        self._session_renew()
        # Add comment.
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                self.logging.debug(self.client.service.addComment(
                    self.auth,
                    str(issue_key),
                    {'body': comment},
                    ))
                return True
                break
            except urllib2.URLError, e:
                attempts += 1
                print 'urllib2 %d: %s' % (e.args[0], e.args[1])
                self.logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                    return False
                continue
        # Was not able to update assignee.
        return False

    def create(self, ticket):
        """Create JIRA issue via SOAP API.
        Ticket values in defaultdict(str):
        Summary = ticket['summary']
        Description = ticket['description']
        Issue type = ticket['issue type'].  Values include 'incident', 'service request', 'QualysGuard ticket'.
        Priority = ticket['priority'].  Values include 'critical', 'high', 'medium', 'low', 'planning'.
        Impacted service = ticket['impacted service']
        Impacted service child = ticket['impacted service child']
        Assignee = ticket['assignee']
        Impacted Location(s) = ticket['impacted location']
        Issue descriptor = ticket['issue descriptor']
        """
        self.logging.debug('jira.create(%s)' % (ticket))
        # Check if session timed out.
        self._session_renew()
        # JIRA or suds cannot handle Unicode data.  Sanitize Unicode characters.
        for option in ticket:
            before = ticket[option]
            ticket[option] = unicodedata.normalize('NFKD', unicode(ticket[option])).encode('ascii', 'ignore').strip()
            self.logging.debug('Normalized %s: %s --> %s' % (option, before, ticket[option]))
        # Make data easier to compare.
        ticket['issue type'] = ticket['issue type'].lower()
        ticket['impacted service'] = ticket['impacted service'].lower()
        ticket['impacted service child'] = ticket['impacted service child'].lower()
        # Translate ticket type.  Default "service request".
        ticket['issue type value'] = {
                'service request': 14,
                'QualysGuard ticket': 24,
                }.get(ticket['issue type'], 14)
        self.logging.debug('issue type value = %s' % (ticket['issue type value']))
        # Priority.  Default "Planning"
        ticket['priority value'] = {
                'critical': 1, # P1 (Critical)
                'high': 2, # P2 (High)
                'medium': 3, # P3 (Medium)
                'low': 4, # P4 (Low)
                'planning': 5, # P5 (Planning)
                }.get(ticket['priority'], 5)
        self.logging.debug('priority value = %s' % (ticket['priority value']))
        # Impacted Service.  Default "Security Services"
        ticket['impacted service value'] = {
                'security services': 10315,
                }.get(ticket['impacted service'], 10315)
        self.logging.debug('impacted service value = %s' % (ticket['impacted service value']))
        # Impacted Service child.  Default "QRadar"
        ticket['impacted service child value'] = {
                'QualysGuard hosts': 11974,
                }.get(ticket['impacted service child'], 12007)
        self.logging.debug('impacted service child value = %s' % (ticket['impacted service child value']))
        # Store list of dictionary for custom field values.
        customFieldValues = [
                             # Impacted Service/System
                             {'customfieldId':'customfield_10026', 'values':[ticket['impacted service value']]},
                             # Impacted Service/System child
                             {'customfieldId':'customfield_10026', 'key': '1', 'values':[ticket['impacted service child value']]},
                             # Issue Descriptor = Security Vulnerability.
                             {'customfieldId':'customfield_10025', 'values':[ticket['issue descriptor']]},
                             # Impacted Location(s).
                             {'customfieldId':'customfield_10134', 'values':[ticket['impacted location']]},
                             # QualysGuard Round #.
                             {'customfieldId':'customfield_10220', 'values':[ticket['QualysGuard round']]},
                            ]
        # Create issue
        self.logging.debug('jira.create(): customFieldValues = %s' % (customFieldValues))
        self.logging.debug('jira.create(): ticket = %s' % (ticket))
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                new_issue = self.client.service.createIssue(
                    self.auth,
                    {
                        'project': ticket['project'],
                        'type': ticket['issue type value'],
                        'priority': ticket['priority value'],
                        'summary': ticket['summary'],
                        'description': ticket['description'],
                        'customFieldValues': customFieldValues
                })
                break
            except suds.WebFault, e:
                print e
                self.logging.error('ERROR suds.WebFault: %s ' % (e))
                print 'Issue not created for %s' % (ticket['impacted location'])
                return False
            except urllib2.URLError, e:
                attempts += 1
                print 'urllib2 %d: %s' % (e.args[0], e.args[1])
                self.logging.error('ERROR urllib2 %d: %s' % (e.args[0], e.args[1]))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                    return False
                continue
        self.logging.debug('New issue created: %s' % (str(new_issue)))
        # Assign issue.
        if not self.assign(ticket['assignee'], str(new_issue.key)):
            print 'Unable to assign new issue, %s' % (str(new_issue.key))
            self.logging.error('Unable to assign new issue, %s' % (str(new_issue.key)))
            return False
        # Return the incident identifier.  E.g.: "NAHLP-33232"
        return str(new_issue.key)

    def date_issued(self, issue):
        """Return date that issue was issued.
        """
        self.logging.debug('jira.date_issued(%s)' % (issue))
        if not issue:
            self.logging.error('No tickets issued for this round.')
            return False
        # Retrive issue information.
        issue = self.get_issue(issue[0])
        # Convert 'datetime.datetime' object to string.
        created = str(issue['created'])
        # Return created date without the time.  Example: '2011-08-16 09:19:32' --> '2011-08-16'.
        return created[:created.find(' ')]

    def delete(self, issue_key):
        """Delete JIRA issue_key issue and return whether it was successful."""
        self.logging.debug('jira.delete(%s)' % (issue_key))
        # Check if session timed out.
        self._session_renew()
        # Get issue.
        try:
            issue = self.client.service.getIssue(self.auth, issue_key)
            self.client.service.deleteIssue(self.auth, issue_key)
            print 'JIRA: Deleted %s.' % (issue_key)
            return True
        except:
            print 'Unable to delete JIRA issue %s.' % (issue_key)
            return False

    def get_issue(self, issue_requested):
        """Return JIRA issue i.
        """
        self.logging.debug('jira.get_issue(%s)' % (issue_requested))
        # Check if session timed out.
        self._session_renew()
        # Get issue.
        MAX_CHECKS = 10
        attempts = 0
        for n in range(0, MAX_CHECKS):
            try:
                issue = self.client.service.getIssue(self.auth, issue_requested)
                break
            except urllib2.URLError, e:
                attempts += 1
                print 'urllib2 %d: %s' % (e.args[0], e.args[1])
                self.logging.error('urllib2 %d: %s' % (e.args[0], e.args[1]))
                if attempts == MAX_CHECKS:
                    print 'Error threshold reached.'
                    return False
                continue
        self.logging.debug('%s = %s' % (issue_requested, issue))
        return issue

    def parse_issues(self, targets):
        """Returns set of issues being targeted.
           Example:  'PROJ-100-102' returns 'PROJ-100, PROJ-101, PROJ-102'.
           """
        self.logging.debug('jira.parse_issues(%s)' % (targets))
        issues = set()
        if not targets[0].isdigit():
            project_ends = targets.find('-') + 1
            project = targets[0:project_ends]
            set_of_issue_numbers = self.parse_int_set(targets[project_ends:])
            # Prepend project to each issue number.
            for issue in set_of_issue_numbers:
                issues.add(project + str(issue))
        else:
            self.logging.error('Error: Project not specified.')
            print 'Error: Project not specified.'
        if not issues:
            self.logging.debug('No issues found by param_issues \'%s\'' % (targets))
            print 'No issues found in \'%s\'' % (targets)
        list_of_issues = sorted(issues, key = lambda item: (int(item.partition(' ')[0])
                                                          if item[0].isdigit() else float('inf'), item))
        self.logging.debug('parse_issues.list_of_issues = %s' % (list_of_issues))
        return list_of_issues

    def parse_int_set(self, nputstr = ''):
        """Return a set of selected values when a string in the form:
        1-4,6
        would return:
        1,2,3,4,6
        as expected.
        http://stackoverflow.com/questions/712460/interpreting-number-ranges-in-python """
        self.logging.debug('jira.parse_int_set(%s)' % (nputstr))
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
            except Exception, e:
                self.logging.error(str(e))
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
                except Exception, e:
                    self.logging.error(str(e))
                    # not an int and not a range...
                    invalid.add(i)
        # Report invalid tokens before returning valid selection
        if len(invalid) > 0:
            print "Invalid set: " + str(invalid)
        return selection

    def reopen(self, issue_key):
        """Reopen JIRA issue_key via SOAP API."""
        self.logging.debug('jira.reopen(%s)' % (issue_key))
        self.change_status(issue_key, 'Reopen Issue', 'Incomplete')

def decode(e):
    """Process an exception for useful feedback"""
    # TODO how to log the fact it is an error, but allow info to be unchanged?
    # TODO now fault not faultstring?
    # The faultType class has faultcode, faultstring and detail
    s = str(e)
    if s == 'java.lang.NullPointerException':
        return "Invalid issue key?"
    return s


# TODO using defaults for resolution and timetracking but should
    # accept values from args too
#    resolution = '1'
#    timetracking = '1m'
#    try:
#        return soap.service.(auth, issue_key, , [
#            {"id": "assignee", "values": [jira_env['jirauser']]},
#            {"id": "resolution", "values": [resolution]},
#            {"id": "timetracking", "values": [timetracking]},
#            ])
#    except Exception, e:
#        logger.error(decode(e))













