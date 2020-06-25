#! /usr/bin/env python3
#
# Wordpress Watcher test script
#
# DISCLAIMER - USE AT YOUR OWN RISK.
"""
Requirements

pip install pytest
pip install codecov
pip install pytest-cov

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
import requests
import concurrent.futures
from datetime import datetime, timedelta
import unittest
import copy
from wpwatcher.wpscan import WPScanWrapper
from wpwatcher.core import WPWatcher
from wpwatcher.config import WPWatcherConfig
from wpwatcher.utils import get_valid_filename
from wpwatcher.parser import parse_results
from wpwatcher.notification import WPWatcherNotification
from wpwatcher.scan import WPWatcherScanner
import random
import linecache


# Constants
NUMBER_OF_CONFIG_VALUES=31

# Read URLS file
# URLS="./wpwatcher-test-sites.txt.conf"
WP_SITES=[ WPWatcher.format_site(s) for s in [ {"url":"exemple.com"},
              {"url":"exemple2.com"}  ] ]
# with open(URLS, 'r') as f: [ WP_SITES.append({'url':url.strip()}) for url in f.readlines() ]

DEFAULT_CONFIG="""
[wpwatcher]
wp_sites=%s
smtp_server=localhost:1025
from_email=testing-wpwatcher@exemple.com
email_to=["test@mail.com"]
"""%json.dumps(WP_SITES)



class WPWatcherTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
         # Launch SMPT debbug server
        smtpd.DebuggingServer(('localhost',1025), None )
        executor = concurrent.futures.ThreadPoolExecutor(1)
        executor.submit(asyncore.loop)

    @classmethod
    def tearDownClass(cls):
        # Close mail server
        asyncore.close_all()

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

        # Test find config file, rename default file if already exist and restore after test
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
        paths_found=wpwatcher.wp_reports.find_wp_reports_file()
        wpwatcher2=WPWatcher(WPWatcherConfig(string=SPECIFIC_WP_REPORTS_FILE_CONFIG%(paths_found)).build_config()[0])
        self.assertEqual(wpwatcher.wp_reports._data, wpwatcher2.wp_reports._data, "WP reports database are different even if files are the same")
        
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
        wpwatcher.wp_reports.update_and_write_wp_reports(reports)
        # Test update 
        for r in reports:
            self.assertIn(r, wpwatcher.wp_reports._data, "The report do not seem to have been saved into WPWatcher.wp_report list")
        # Test write method
        wrote_db=wpwatcher.wp_reports.build_wp_reports(wpwatcher.wp_reports.filepath)
        with open(wpwatcher.wp_reports.filepath,'r') as db:
            wrote_db_alt=json.load(db)
        for r in reports:
            self.assertIn(r, wrote_db, "The report do not seem to have been saved into db file")
            self.assertIn(r, wrote_db_alt, "The report do not seem to have been saved into db file")
        self.assertEqual(wpwatcher.wp_reports._data, wrote_db_alt, "The database file wrote differ from in memory database")
        self.assertEqual(wpwatcher.wp_reports._data, wrote_db, "The database file wrote differ from in memory database")

    def test_init_wpwatcher(self):
        # Init deafult watcher
        wpwatcher=WPWatcher(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0])
        flag=WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0]

        # for k in WPWatcherConfig.DEFAULT_CONFIG:
        #     if k != 'wp_reports':
        #         self.assertEqual(str(wpwatcher.conf[k]), str(flag[k]), "Config doesn't seem to hae been loaded")
        self.assertEqual(type(wpwatcher.scanner), WPWatcherScanner, "WPWatcherScanner doesn't seem to have been initialized")
        self.assertEqual(type(wpwatcher.scanner.mail), WPWatcherNotification, "WPWatcherNotification doesn't seem to have been initialized")
        self.assertEqual(type(wpwatcher.scanner.wpscan), WPScanWrapper, "WPScanWrapper doesn't seem to have been initialized")
        self.assertEqual(shlex.split(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0]['wpscan_path']), wpwatcher.scanner.wpscan.wpscan_executable, "WPScan path seems to be wrong")

    
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
            f=wpwatcher.scanner.write_wpscan_output(report)
            f1=os.path.join(RESULTS_FOLDER, 'warning/', get_valid_filename('WPScan_output_%s_%s.txt' % (s['url'], "2020-04-08T16-05-16")))
            self.assertEqual(f, f1, "Inconsistent WPScan output filenames")
            self.assertTrue(os.path.isfile(f1),"WPscan output file doesn't exist")
            with open(f1, 'r') as out:
                self.assertEqual(out.read(), "This is real%s"%(s))
        shutil.rmtree(RESULTS_FOLDER)

    def test_send_report(self):
       
        # Init WPWatcher
        wpwatcher = WPWatcher(WPWatcherConfig(string=DEFAULT_CONFIG+"\nattach_wpscan_output=Yes").build_config()[0])


        print(wpwatcher.__dict__)
        print(wpwatcher.scanner.__dict__)
        print(wpwatcher.scanner.mail.__dict__)

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

            

            # notif=WPWatcherNotification(WPWatcherConfig(string=DEFAULT_CONFIG+"\nattach_wpscan_output=Yes").build_config()[0])
            wpwatcher.scanner.mail.send_report(report, email_to='test')

            # self.assertEqual(report['fixed'], [], "Fixed item wasn't remove after email sent")
            # self.assertNotEqual(report['last_email'], None)

    def test_update_report(self):
        # Init WPWatcher
        wpwatcher = WPWatcher(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0])
        for s in WP_SITES:
            old={
                    "site": s['url'],
                    "status": "WARNING",
                    "datetime": "2020-04-08T16-05-16",
                    "last_email": "2020-04-08T16-05-17",
                    "errors": [],
                    "infos": [
                        "[+]","blablabla"],
                    "warnings": [
                        "[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).\nblablabla\n",
                        "[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.\n[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"
                    ],
                    "alerts": [],
                    "fixed": ["This issue was fixed"],
                    "wpscan_output":""
                }

            new={
                    "site": s['url'],
                    "status": "",
                    "datetime": "2020-04-10T16-00-00",
                    "last_email": None,
                    "errors": [],
                    "infos": [
                        "[+]","blablabla"],
                    "warnings": [
                        "[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.\n[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"
                    ],
                    "alerts": [],
                    "fixed": [],
                    "wpscan_output":""
                }

            expected={
                    "site": s['url'],
                    "status": "",
                    "datetime": "2020-04-10T16-00-00",
                    "last_email": "2020-04-08T16-05-17",
                    "errors": [],
                    "infos": [
                        "[+]","blablabla"],
                    "warnings": [
                        "[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.\n[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"
                    ],
                    "alerts": [],
                    "fixed": [
                        "This issue was fixed",
                        'Issue regarding component "%s" has been fixed since last report.\nLast report sent the %s.\nFix detected the %s\nIssue details:\n[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).\nblablabla\n'%("[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).",old['last_email'] ,new['datetime'])    
                    ],
                    "wpscan_output":""
                }
            
            wpwatcher.scanner.update_report(new,old,s)
            print(new)
            print(expected)
            self.assertEqual(new, expected, "There is an issue with fixed issues feature: the expected report do not match the report returned by update_report()")
        
    def test_handle_wpscan_err(self):
        # test API wait, test Follow redirect
        # TODO
        pass

    def test_notify(self):
        # test send_errors, send_infos, send_warnings, resend_emails_after, email_errors_to
        # Init WPWatcher
        CONFIG=DEFAULT_CONFIG+"\nsend_infos=Yes\nsend_errors=Yes\nsend_warnings=No"
        wpwatcher = WPWatcher(WPWatcherConfig(string=CONFIG).build_config()[0])
        # wpwatcher.scanner.mail

    def test_wpscan(self):
        # lazy_init
        wpscan=WPScanWrapper('wpscan')
        ex,_=wpscan.wpscan("--url","wp.exemple.com")
        self.assertEqual(ex,4,"Scanning wp.exemple.com successful, that's weird !")
        ex,_=wpscan.wpscan("--version")
        self.assertEqual(ex,0,"WPScan failed when printing version")

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
        out = open("tests/static/wordpress_no_vuln.json").read()
        messages, warnings, alerts=parse_results(out)
        self.assertEqual(0, len(alerts))
        out = open("tests/static/wordpress_one_vuln.json").read()
        messages, warnings, alerts=parse_results(out)
        self.assertEqual(1, len(alerts))
        out = open("tests/static/wordpress_many_vuln.json").read()
        messages, warnings, alerts=parse_results(out)
        self.assertEqual(3, len(alerts))

        out = open("tests/static/wordpress_no_vuln.txt").read()
        messages, warnings, alerts=parse_results(out)
        self.assertEqual(0, len(alerts))
        out = open("tests/static/wordpress_one_warning.txt").read()
        messages, warnings, alerts=parse_results(out)
        self.assertEqual(2, len(warnings))
        out = open("tests/static/wordpress_many_vuln.txt").read()
        messages, warnings, alerts=parse_results(out)
        self.assertEqual(8, len(alerts))
        out = open("tests/static/wordpress_one_vuln.txt").read()
        messages, warnings, alerts=parse_results(out)
        self.assertEqual(1, len(alerts))

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