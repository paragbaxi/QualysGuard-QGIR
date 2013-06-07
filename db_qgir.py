#!/usr/bin/env python
"""Class to connect to QGIR DB.

Creating, assigning, attaching files to, and deleting tickets avaiable.
Prerequisites:
QGIR
"""

__author__ = "Parag Baxi"
__copyright__ = "Copyright 2012"
__credits__ = ["Parag Baxi"]
__license__ = "GPLv3"
__version__ = "2011.10.20.1"
__maintainer__ = "Parag Baxi"
__email__ = "parag.baxi@gmail.com"
__status__ = "Production"


import logging
import os
import qgir_tools
import shutil
import sqlite3
import unicodedata

if __name__ == '__main__':    #code to execute if called from command-line
    pass    #do nothing

class db_qgir:
    def __init__(self, db_file, asset_group, test, test_db_verify_file, logger = logging):
        """Initiate database, return the run_number value."""
        # logger configuration
        self.logging = logger
        self.logging.debug('db_qgir(%s, %s, %s, %s)' % (db_file, asset_group, test, test_db_verify_file))
        self.asset_group = asset_group
        # Connect to db_file.
        # Create DB file, if does not exist.
        if not os.path.isfile(db_file):
            # Create empty DB file.
            self.logging.debug('Creating QGIR DB file.')
            f = open(db_file, 'w')
            f.close()
        # Use copy if testing QGIR.
        self.test = test
        if self.test:
            test_db_file = 'test/test_qgir.sqlite'
            self.logging.debug('Test DB file = %s' % (test_db_file))
            # Check if using an existing test DB.
            if (test_db_file != test_db_verify_file):
                # Not using existing test DB, copy production QGIR db.
                # Delete old test DB file, if exists.
                if os.path.isfile(test_db_file):
                    self.logging.debug('Deleting old test QGIR DB file.')
                    os.remove(test_db_file)
                # Copy production DB file.
                self.logging.info('Copying QGIR DB file for test DB file.')
                shutil.copy2(db_file, test_db_file)
                db_file = test_db_file
            else:
                db_file = test_db_verify_file
        # Connect to DB file.
        self.logging.debug('db_file = %s' % (db_file))
        self.conn = sqlite3.connect(db_file)
        # Store cursor for access to DB.
        self.cursor = self.conn.cursor()
        self._initiate_db()
        # Store current run_number from db.
        self.run_number = self._get_run_number()
        # Store current round_number from db.
        self.round_number = self._get_round_number()

    def _get_round_number(self):
        """Return the round_number value."""
        round_number = self.query(q_select = 'MAX(round_number)').pop()
        if not round_number:
            self.logging.debug('No round number exists. Start with round 2.')
            # First round for office.
            round_number = 2
        self.logging.debug('round_number = %s' % (round_number))
        return round_number

    def _get_run_number(self):
        """Return this run's run_number."""
        # TODO:  Static run_number, no longer incrementing by one.
        # Check if rows exist to bypass SQL error.
        if self.cursor.execute('SELECT Count(*) FROM incidents').fetchall()[0][0] < 1:
            # No rows exist.  QGIR Round 1 completed, start with round 2.
            run_number = 2
        else:
            run_number = (self.cursor.execute('SELECT max(run_number) FROM incidents').fetchall()[0][0]) + 1
        self.logging.debug('run_number = %s' % (run_number))
        return run_number

    def _initiate_db(self):
        """Create tables if they do not exist"""
        # issue_key = Reaction's issue key.
        # asset_group = Asset group.
        # qid = QID vulnerability.
        # run_number = QGIR run number.
        # remediation_numbers = Remediation numbers linked to vulnerability.  Used in validation of resolved issues.
        # reopen = Number of times incident has been reopened.
        # status = Status of QID:  open, approved, rejected.
        # validated = Whether Reaction issue's resolved state has been confirmed.
        # Log all incidents created
        self.cursor.execute('''create table if not exists remediation
        (remediation_ticket text primary key, run_number int, issue_key text, round_number int)''')
        # Table 'incidents' holds incidents that have been marked complete by the assignee and need to be validated by QGIR.
        self.cursor.execute('''create table if not exists incidents
        (issue_key text primary key, office text, qid text, reopen int, run_number int, validated int, round_number int)''')

    def add_remediation(self, host, issue_key):
        """Add incident into db."""
        self.logging.debug('db_add_remediation called.')
        # Add remediation ticket into remediation.
        self.logging.debug('INSERT OR REPLACE %s into remediation.' % (host['vuln_id']))
        self.cursor.execute('INSERT OR REPLACE into remediation values (?,?,?,?)',
                       (host['vuln_id'],
                        self.run_number,
                        issue_key,
                        self.round_number))
        self.logging.debug('INSERT OR REPLACE successful.')
        return self.conn.commit()
        if self.test:
            print 'INSERT OR REPLACE into remediation values (?,?,?,?)' % (host['vuln_id'],
                                                                self.run_number,
                                                                issue_key,
                                                                self.round_number)
        return True

    def add_incident(self, asset_group_details, issue_key, qid):
        """Add incident into db."""
        self.logging.debug('db.add_incident(%s, %s, %s, %s)' % (self.asset_group, asset_group_details, issue_key, qid))
        # Add incident into sqlite's incidents
        self.logging.debug('Insert %s into sqlite.' % (issue_key))
        # Insert into correct table.
        self.logging.debug('INSERT into incidents values (%s,%s,%s,%s,%s,%s,%s)' % (issue_key, self.asset_group, qid, 0, self.run_number, 0, self.round_number))
        if not self.test:
            self.cursor.execute('INSERT into incidents values (?,?,?,?,?,?,?)',
                               (issue_key,
                                self.asset_group,
                                qid,
                                0, # reopen
                                self.run_number,
                                0, # validated
                                self.round_number))
            self.logging.debug('Insert successful.')
            return self.conn.commit()
        else:
            print 'INSERT into incidents values (%s,%s,%s,%s,%s,%s,%s)' % (issue_key, self.asset_group, qid, 0, self.run_number, 0, self.round_number)
            return True

    def delete_issue(self, issue_key):
        """Return true after deleting issue from SQLite DB."""
        self.logging.debug('DB: Delete %s from incidents table.' % (issue_key))
        if not self.test:
            self.cursor.execute('DELETE FROM incidents WHERE issue_key = ?', (issue_key,))
        else:
            print 'DB: Delete %s from incidents table.' % (issue_key)
        # Fetch associated remediation tickets from remediation table.
        rows_remediation = self.query(q_table = 'remediation', q_select = 'remediation_ticket', q_where = 'issue_key', q_value = [issue_key])
        # Delete issues from remediation table from the DB.
        for i in rows_remediation:
            # Severity 3-5 vulnerability.  Delete db rows in remediation.
            if not self.test:
                while(True):
                    try:
                        self.logging.debug('Delete remediation ticket %s.' % (i))
                        self.cursor.execute('DELETE FROM remediation WHERE remediation_ticket = ?', (i,))
                    except sqlite3.OperationalError:
                        self.logging.error('Database locked. Trying again.')
                        print 'Database locked. Trying again.'
                        continue
                    break
                self.logging.debug('DB: Deleted %s from remediation.' % (i))
            else:
                print 'Delete remediation ticket %s.' % (i)
        # Commit changes
        try:
            self.conn.commit()
        except:
            self.logging.warning('SQLite file may not have committed.')
        return True

    def query(self, q_table = 'incidents', q_select = 'issue_key', q_where = None, q_where_operator = '=', q_value = None, round_number = None):
        """Perform query against sqlite table:  'SELECT issue_key FROM q_table WHERE q_where q_where_operator q_value'.
           Return set of matched issues, or whatever.
           
           Example:    set(('168780', '168882', '169124', '168767')   
                       where the set is filled with remediation ticket numbers.
        """
        self.logging.debug('query(q_table = %s, q_where = %s, q_where_operator = %s, q_value = %s)' % (q_table, q_where, q_where_operator, q_value))
        if not q_where or q_value == 'all':
            self.logging.debug('SELECT %s FROM %s' % (q_select, q_table))
            rows_incidents = self.cursor.execute('SELECT %s FROM %s' % (q_select, q_table)).fetchall()
        elif round_number:
            self.logging.debug('SELECT %s FROM %s WHERE %s %s %s AND round_number = %s' % (q_select, q_table, q_where, q_where_operator, q_value, round_number))
            rows_incidents = self.cursor.execute('SELECT %s FROM %s WHERE %s %s (%s) AND round_number = %s' % (q_select, q_table, q_where, q_where_operator, ('?, ' * len(q_value))[:-2], str(round_number)), q_value).fetchall()
        else:
            self.logging.debug('SELECT %s FROM %s WHERE %s %s %s' % (q_select, q_table, q_where, q_where_operator, q_value))
            rows_incidents = self.cursor.execute('SELECT %s FROM %s WHERE %s %s (%s)' % (q_select, q_table, q_where, q_where_operator, ('?, ' * len(q_value))[:-2]), q_value).fetchall()
        if rows_incidents == []:
            return set()
        values = set()
        for i in rows_incidents:
            # Check if result is integer.
            if not isinstance(i[0], (int, long)):
                # Not an integer, convert unicode string.
                try:
                    value_to_add = unicodedata.normalize('NFKD', i[0]).encode('ascii', 'ignore')
                except TypeError, e:
                    # Value is None.
                    self.logging.debug('Value is None')
                    value_to_add = False
            else:
                value_to_add = i[0]
            values.add(value_to_add)
        self.logging.debug('query.values = %s' % (values))
        return values

    def param_office(self, office, round_number):
        """Returns set of issues from office.
           Example:  'NA - New York' returns set('INFOSEC-100, INFOSEC-101, INFOSEC-102') owned by New York."""
        self.logging.debug('db_qgir.param_office(%s)' % (office))
        # Retrieve information gathered issues from SQlite.
        issues = set()
        # Retrieve severity 3-5 issues from SQlite.
        issues = issues.union(self.query(q_where = 'office', q_value = (office,), round_number = round_number))
        if not issues:
            self.logging.debug('No issues found by param_office \'%s\'' % (office))
            return False
        self.logging.debug('param_office.issues = %s' % (issues))
        return issues

    def param_run_number(self, my_run_number):
        """Returns set of all issues matching my_run_number from SQLite DB.
           
           Example:    set('INFOSEC-101', 'INFOSEC-102')
        """
        # Initiate SQLite db
        self.logging.debug('db_qgir.param_run_number(%s)' % (my_run_number))
        # Set issues will hold all issues combined.
        issues = set()
        # Fetch issues.
        if qgir_tools.is_positive_integer(my_run_number):
            # Fetch issues.
            issues = issues.union(self.query(q_where = 'run_number', q_value = (my_run_number,)))
        elif my_run_number.lower() == 'all':
            # All run_numbers.
            issues = issues.union(self.query(q_where = 'run_number', q_value = (my_run_number,)))
        else:
            self.logging.error('%s not valid.' % (my_run_number))
            print '\'%s\' not valid.' % (my_run_number)
            return set()
        if not issues:
            self.logging.debug('No issues found by run_number \'%s\'.' % (my_run_number))
            return set()
        return issues

    def param_round_number(self, my_round_number):
        """Returns set of all issues matching my_round_number from SQLite DB.
           
           Example:    set('INFOSEC-101', 'INFOSEC-102')
        """
        # Initiate SQLite db.
        self.logging.debug('db_qgir.param_round_number(%s)' % (my_round_number))
        # Set issues will hold all issues combined.
        issues = set()
        # Fetch issues.
        if qgir_tools.is_positive_integer(my_round_number):
            # Fetch bad issues.
            issues = issues.union(self.query(q_where = 'round_number', q_value = (my_round_number,)))
        else:
            self.logging.error('%s not valid.' % (my_round_number))
            print '\'%s\' not valid.' % (my_round_number)
            return set()
        if not issues:
            self.logging.debug('No issues found by round_number \'%s\'.' % (my_round_number))
            return set()
        self.logging.debug('param_round_number.issues = %s' % (issues))
        return issues

    def set_round_number(self):
        """Return True if this a new round, False if this is the same round."""

        self.logging.debug('Check to see if this a new round.')
        try:
            latest_site_round_number = max(self.query(q_select = 'round_number', q_where = 'office', q_value = (self.asset_group,)))
        except ValueError:
            # This site has never been issued tickets by QGIR.
            latest_site_round_number = 0
        self.logging.debug('latest_site_round_number = %s' % (latest_site_round_number))
        if latest_site_round_number == self.round_number:
            # Latest round of site is equal to the current round number.  Increase round.
            self.round_number += 1
            self.logging.debug('New round: %s' % (self.round_number))
            return True
        else:
            self.logging.debug('Same round: %s' % (self.round_number))
            return False
