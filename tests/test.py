#! /usr/bin/env python3
#
# Wordpress Watcher test script
#
# DISCLAIMER - USE AT YOUR OWN RISK.
#
# MUST READ FILE ./wpwatcher-test-sites.txt.conf
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
import shutil
import argparse
import subprocess
import shlex
import smtpd
import time
import asyncore
import concurrent.futures
from datetime import datetime, timedelta
import unittest
import copy
from wpwatcher.scan import WPScanWrapper
from wpwatcher.core import WPWatcher
from wpwatcher.config import WPWatcherConfig
from wpwatcher.utils import get_valid_filename
# Constants
NUMBER_OF_CONFIG_VALUES=29

# Read URLS file
URLS="./wpwatcher-test-sites.txt.conf"
WP_SITES=[]
with open(URLS, 'r') as f: [ WP_SITES.append({'url':url.strip()}) for url in f.readlines() ]

DEFAULT_CONFIG="""
[wpwatcher]
wp_sites=%s
smtp_server=localhost:1025
from_email=testing-wpwatcher@exemple.com
email_to=["test@mail.com"]
"""%json.dumps(WP_SITES)

# MORE_OPTIONS_CONFIG="""
# [wpwatcher]
# wp_sites=%s
# verbose=Yes
# resend_emails_after=5d
# """%(json.dumps(get_sites()))

class WPWatcherTests(unittest.TestCase):

    def test_config(self):

        # Test minimal config
        config_object=WPWatcherConfig(string=DEFAULT_CONFIG)
        self.assertEqual(0, len(config_object.files), "Files seems to have been loaded even if custom string passed to config oject")
        config_dict, files=config_object.build_config()
        self.assertEqual(0, len(files), "Files seems to have been loaded even if custom string passed to config oject")
        self.assertEqual(NUMBER_OF_CONFIG_VALUES, len(config_dict), "The number of config values if not right or you forgot to change the value of NUMBER_OF_CONFIG_VALUES")
        
        # Test config template file
        config_object=WPWatcherConfig(string=WPWatcherConfig.TEMPLATE_FILE)
        self.assertEqual(0, len(config_object.files), "Files seems to have been loaded even if custom string passed to config oject")
        config_dict, files=config_object.build_config()
        self.assertEqual(0, len(files), "Files seems to have been loaded even if custom string passed to config oject")
        self.assertEqual(NUMBER_OF_CONFIG_VALUES, len(config_dict), "The number of config values if not right or you forgot to change the value of NUMBER_OF_CONFIG_VALUES")
        
        # Test config template file
        config_object=WPWatcherConfig(string=WPWatcherConfig.TEMPLATE_FILE)
        self.assertEqual(0, len(config_object.files), "Files seems to have been loaded even if custom string passed to config oject")
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
        SPECIFIC_WP_REPORTS_FILE_CONFIG = DEFAULT_CONFIG+"\nwp_reports=%s"

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
        flag=WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0]
        for k in WPWatcherConfig.DEFAULT_CONFIG:
            if k != 'wp_reports':
                self.assertEqual(str(wpwatcher.conf[k]), str(flag[k]), "Config doesn't seem to hae been loaded")

        self.assertEqual(type(wpwatcher.wpscan), WPScanWrapper, "WPScanWrapper doesn't seem to have been initialized")
        self.assertEqual(shlex.split(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0]['wpscan_path']), wpwatcher.wpscan.wpscan_executable, "WPScan path seems to be wrong")

    
    def test_wpscan_output_folder(self):
        RESULTS_FOLDER="./results/"
        WPSCAN_OUTPUT_CONFIG = DEFAULT_CONFIG+"\nwpscan_output_folder=%s"%RESULTS_FOLDER
        wpwatcher=WPWatcher(WPWatcherConfig(string=WPSCAN_OUTPUT_CONFIG).build_config()[0])
        self.assertTrue(os.path.isdir(RESULTS_FOLDER),"WPscan results folder doesn't seem to have been init")
        for s in WP_SITES:
            report={
                "site": s['url'],
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
                "fixed": [],
                "wpscan_output":"This is real%s"%(s)
            }
            f=wpwatcher.write_wpscan_output(report)
            f1=os.path.join(RESULTS_FOLDER, get_valid_filename('WPScan_output_%s_%s.txt' % (s['url'], "2020-04-08T16-05-16")))
            self.assertEqual(f, f1, "Inconsistent WPScan output filenames")
            self.assertTrue(os.path.isfile(f1),"WPscan output file doesn't exist")
            with open(f1, 'r') as out:
                self.assertEqual(out.read(), "This is real%s"%(s))
        shutil.rmtree(RESULTS_FOLDER)

    def test_send_report(self):
        # Launch SMPT debbug server
        smtpd.DebuggingServer(('localhost',1025), None )
        executor = concurrent.futures.ThreadPoolExecutor(1)
        executor.submit(asyncore.loop)
        # # Init WPWatcher
        wpwatcher = WPWatcher(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0])
        # Send mail
        for s in WP_SITES:
            report={
                "site": s['url'],
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
                "fixed": ["This issue was fixed"],
                "wpscan_output":"This is real%s"%(s)
            }
            wpwatcher.send_report(wpwatcher.format_site(s), report)
            self.assertEqual(report['fixed'], [], "Fixed item wasn't remove after email sent")
            self.assertNotEqual(report['last_email'], None)
            
        # Close mail server
        asyncore.close_all()

    def test_update_report(self):
        old={}

        new={}

        expected={}
        
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

if __name__ == '__main__':
    os.system('python3 -m unittest tests.test')