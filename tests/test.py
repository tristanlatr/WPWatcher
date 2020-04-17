#! /usr/bin/env python3
#
# Wordpress Watcher test script
#
# DISCLAIMER - USE AT YOUR OWN RISK.
"""
Requirements

# pip install pytest
# pip install codecov
# pip install pytest-cov

# Enumerating tests
# Core
- Test WPScan:
    -  Info, warnings and alerts
- Fixed item logic
- Errors handler
    - Follow redirect
    -  API wait
- Email notification trigger and sending
- Interrupt timeout
# WPScan wrapper
# Parser
# Cli
# config
# utils
"""

import json
import re
import sys
import os
import argparse
from datetime import datetime, timedelta
import unittest
from wpwatcher.scan import WPScanWrapper
from wpwatcher.core import WPWatcher
from wpwatcher.config import WPWatcherConfig
# Constants
NUMBER_OF_CONFIG_VALUES=29
# Change test urls file
SITES="./sites.txt.conf"
def get_sites():
    s=[]
    with open(SITES, 'r') as f:
        [ s.append({'url':url.strip()}) for url in f.readlines() ]
    return s
WP_SITES=get_sites()

DEFAULT_CONFIG="""
[wpwatcher]
wp_sites=%s
"""%(json.dumps(get_sites()))

MORE_OPTIONS_CONFIG="""
[wpwatcher]
wp_sites=%s
verbose=Yes
resend_emails_after=5d
"""%(json.dumps(get_sites()))

ILLEGAL_CONFIG="""
[wpwatcher]
wp_sites=%s
"""%(json.dumps(get_sites()))

SPECIFIC_WP_REPORTS_FILE_CONFIG = DEFAULT_CONFIG+"\nwp_reports=%s"

def parse_args():
    parser = argparse.ArgumentParser(description='WPWatcher test script')
    # parser.add_argument('--input', metavar='path', help="WPScan Json or CLI output", required=True)
    # parser.add_argument('--search', metavar='Keyword', required=True)
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    os.system('python3 -m unittest tests.test')

class WPWatcherTests(unittest.TestCase):

    def test_config(self):

        # Test minimal config
        config_object=WPWatcherConfig(string=DEFAULT_CONFIG)
        self.assertEqual(0, len(config_object.files), "Files seems to hve been loaded even if custom string passed to config oject")
        config_dict, files=config_object.build_config()
        self.assertEqual(0, len(files), "Files seems to have been loaded even if custom string passed to config oject")
        self.assertEqual(NUMBER_OF_CONFIG_VALUES, len(config_dict), "The number of config values if not right or you forgot to change the value of NUMBER_OF_CONFIG_VALUES")
        
        # Test config template file
        config_object=WPWatcherConfig(string=WPWatcherConfig.TEMPLATE_FILE)
        self.assertEqual(0, len(config_object.files), "Files seems to hve been loaded even if custom string passed to config oject")
        config_dict, files=config_object.build_config()
        self.assertEqual(0, len(files), "Files seems to have been loaded even if custom string passed to config oject")
        self.assertEqual(NUMBER_OF_CONFIG_VALUES, len(config_dict), "The number of config values if not right or you forgot to change the value of NUMBER_OF_CONFIG_VALUES")
        
        # Test config template file
        config_object=WPWatcherConfig(string=WPWatcherConfig.TEMPLATE_FILE)
        self.assertEqual(0, len(config_object.files), "Files seems to hve been loaded even if custom string passed to config oject")
        config_dict, files=config_object.build_config()
        self.assertEqual(0, len(files), "Files seems to have been loaded even if custom string passed to config oject")
        self.assertEqual(NUMBER_OF_CONFIG_VALUES, len(config_dict), "The number of config values if not right or you forgot to change the value of NUMBER_OF_CONFIG_VALUES")

        # Test find config file
        paths_found=WPWatcherConfig.find_config_files()
        existent_files=[]
        if len(paths_found)==0:
            paths_found=WPWatcherConfig.find_config_files(create=True)
        else:
            existent_files=paths_found
            for p in paths_found:
                os.rename(p,'%s.temp'%p)
            paths_found=WPWatcherConfig.find_config_files(create=True)
        config_object=WPWatcherConfig()
        config_object2=WPWatcherConfig(files=paths_found)
        self.assertEqual(config_object.build_config(), config_object2.build_config(), "Config built with config path and without are dirrent even if files are the same")
        for f in paths_found: 
            os.remove(f)
        for f in existent_files:
            os.rename('%s.temp'%f , f)

    def test_wp_reports(self):
        # Compare with config and no config
        wpwatcher=WPWatcher(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0])
        paths_found=wpwatcher.find_wp_reports_file()
        wpwatcher2=WPWatcher(WPWatcherConfig(string=SPECIFIC_WP_REPORTS_FILE_CONFIG%(paths_found)).build_config()[0])
        self.assertEqual(wpwatcher.wp_reports, wpwatcher2.wp_reports, "WP reports database are different even if files are the same")
        
        # Test Reports database 
        reports = [
            {
                "site": "exemple.com",
                "status": "WARNING",
                "datetime": "2020-04-08T16-05-16",
                "last_email": None,
                "errors": [],
                "infos": [
                    "[+]","blablabla"],
                "warnings": [
                    "[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).\n| Found By: Emoji Settings (Passive Detection)\n",
                    "[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.\n[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"
                ],
                "alerts": [],
                "fixed": []
            },
            {
                "site": "exemple2.com",
                "status": "INFO",
                "datetime": "2020-04-08T16-05-16",
                "last_email": None,
                "errors": [],
                "infos": [
                    "[+]","blablabla"],
                "warnings": [],
                "alerts": [],
                "fixed": []
            }
        ]
        wpwatcher=WPWatcher(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0])
        wpwatcher.update_and_write_wp_reports(reports)
        # Test update 
        for r in reports:
            self.assertIn(r, wpwatcher.wp_reports, "The report do not seem to have been saved into WPWatcher.wp_report list")
        # Test write method
        wrote_db=wpwatcher.build_wp_reports()
        with open(wpwatcher.conf['wp_reports'],'r') as db:
            wrote_db_alt=json.load(db)
        for r in reports:
            self.assertIn(r, wrote_db, "The report do not seem to have been saved into db file")
            self.assertIn(r, wrote_db_alt, "The report do not seem to have been saved into db file")
        self.assertEqual(wpwatcher.wp_reports, wrote_db_alt, "The database file wrote differ from in memory database")
        self.assertEqual(wpwatcher.wp_reports, wrote_db, "The database file wrote differ from in memory database")

    def test_init_wpwatcher(self):
        # Init deafult watcher
        wpwatcher=WPWatcher(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0])
        self.assertEqual(wpwatcher.conf, WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0], "Config doesn't seem to hae been loaded")
        self.assertEqual(type(wpwatcher.wpscan), WPScanWrapper, "WPScanWrapper doesn't seem to have been initialized")
        self.assertEqual(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0]['wpscan_path'], wpwatcher.wpscan.path, "WPScan path seems to be wrong")

    def test_wpscan_output_folder(self):
        pass

    def test_send_report(self):
        # test from_email
        pass

    def test_update_report(self):
        # Fixed issues
        pass

    def test_handle_wpscan_err(self):
        # test API wait, test Follow redirect
        pass

    def test_notify(self):
        # test send_errors, send_infos, send_warnings, resend_emails_after, email_errors_to
        pass

    def test_scan_site(self):
        # test info, warnings and alerts
        pass

    def test_interrupt(self):
        # test timeout
        # test all childs are killed
        pass

    def test_run_scans_and_notify(self):
        # test returned results
        pass

    def test_cli(self):
        # test argparsing
        pass

    def test_parser(self):
        # false positives
        pass

    def test_utils(self):
        pass

    def test_asynch_exec(self):
        # test max number of threads respected
        pass

    def test_daemon(self):
        # test daemon_loop_sleep and daemon mode
        pass

    def test_fail_fast(self):
        pass