#! /usr/bin/env python3
#
# Wordpress Watcher test script
#
# DISCLAIMER - USE AT YOUR OWN RISK.
#
# THIS TEST MIGHT BE ILLEGAL IN YOUR COUNTRY

import json
import os
import requests
import asyncore
import smtpd
import unittest
import random
import linecache
import concurrent.futures

from wpwatcher.wpscan import WPScanWrapper
from wpwatcher.core import WPWatcher
from wpwatcher.config import Config

# WORDPRESS SITES SOURCE LIST FILE
SOURCE="https://gist.githubusercontent.com/ahmadawais/e6cd20acdc4f7ad304a3e90ad44a663c/raw/ca95a83bc6e45f018189f8f73bc0b73d310a31f7/wordpress-sites.csv"

# How many radom potential WordPress site to scan 
HOW_MANY=15

class WPWatcherScanTests(unittest.TestCase):

    def test_scan_radom_sites(self):
        # This test might be illegal in your country
        
        # Get list of Wordpress sites if not already downloaded
        filename='/tmp/wp_sites'
        if not os.path.isfile(filename):
            myfile = requests.get(SOURCE)
            open(filename, 'wb').write(myfile.content)

        # Select X from the 50M
        idxs = random.sample(range(50000), HOW_MANY)
        urls=[linecache.getline(filename, i) for i in idxs]

        # Prepare scan config
        CONFIG1="""
[wpwatcher]
wp_sites=%s
smtp_server=localhost:1025
from_email=testing-wpwatcher@exemple.com
email_to=["test@mail.com"]
wpscan_args=["--rua", "--stealthy", "--format", "cli", "--no-banner", "--disable-tls-checks"]
false_positive_strings=["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]
send_email_report=Yes
log_file=./TEST-wpwatcher.log.conf
wp_reports=./TEST-wp_reports.json.conf
asynch_workers=10
follow_redirect=Yes
wpscan_output_folder=./TEST-wpscan-results/
send_infos=Yes
"""%json.dumps([{'url':s.strip()} for s in urls])

        # Select X from the 50M
        idxs = random.sample(range(50000), HOW_MANY)
        urls=[linecache.getline(filename, i) for i in idxs]

        # Prepare scan config
        CONFIG2="""
[wpwatcher]
wp_sites=%s
smtp_server=localhost:1025
from_email=testing-wpwatcher@exemple.com
email_to=["test@mail.com"]
wpscan_args=["--rua", "--stealthy", "--format", "json", "--no-banner", "--disable-tls-checks"]
false_positive_strings=["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]
send_email_report=Yes
log_file=./TEST-wpwatcher.log.conf
wp_reports=./TEST-wp_reports.json.conf
asynch_workers=10
follow_redirect=Yes
wpscan_output_folder=./TEST-wpscan-results/
attach_wpscan_output=Yes
send_infos=Yes
send_errors=Yes
email_errors_to=["admins@domain"]
# prescan_without_api_token=Yes
"""%json.dumps([{'url':s.strip()} for s in urls])

        # Select X from the 50M
        idxs = random.sample(range(50000), HOW_MANY)
        urls=[linecache.getline(filename, i) for i in idxs]

        # Prepare scan config
        CONFIG3="""
[wpwatcher]
wp_sites=%s
smtp_server=localhost:1025
from_email=testing-wpwatcher@exemple.com
email_to=["test@mail.com"]
wpscan_args=["--rua", "--stealthy", "--format", "json", "--no-banner", "--disable-tls-checks"]
false_positive_strings=["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]
send_email_report=Yes
log_file=./TEST-wpwatcher.log.conf
wp_reports=./TEST-wp_reports.json.conf
asynch_workers=10
follow_redirect=Yes
wpscan_output_folder=./TEST-wpscan-results/
attach_wpscan_output=Yes
send_warnings=No
send_errors=Yes
fail_fast=Yes
"""%json.dumps([{'url':s.strip()} for s in urls])
        
        # Launch SMPT debbug server
        smtpd.DebuggingServer(('localhost',1025), None )
        executor = concurrent.futures.ThreadPoolExecutor(1)
        executor.submit(asyncore.loop)

        # Init WPWatcher
        w1 = WPWatcher(Config.fromstring(CONFIG1))

        # Run scans
        res1=w1.run_scans_and_notify()

        # Init WPWatcher
        w2 = WPWatcher(Config.fromstring(CONFIG2))

        # Run scans
        res2=w2.run_scans_and_notify()

        # Init WPWatcher
        w3 = WPWatcher(Config.fromstring(CONFIG3))

        # Run scans
        res3=w3.run_scans_and_notify()

        # Close mail server
        asyncore.close_all()

        self.assertEqual(type(res1), tuple, "run_scans_and_notify returned an invalied result")
