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
from wpwatcher.core import WPWatcher
from wpwatcher.config import WPWatcherConfig

def parse_args():
    parser = argparse.ArgumentParser(description='WPWatcher test script')
    # parser.add_argument('--input', metavar='path', help="WPScan Json or CLI output", required=True)
    # parser.add_argument('--search', metavar='Keyword', required=True)
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    os.system('python3 -m unittest test')

class WPWatcherTests(unittest.TestCase):
    def get_sites(self):
        s=[]
        with open('./sites.conf', 'r') as f:
            [ s.append({'url':url.strip()}) for url in f.readlines() ]
        return s

    def test_config(self):
        config="""
[wpwatcher]
wpscan_args=[   "--format", "cli",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks" ]
wp_sites=%s
send_email_report=Yes
send_infos=Yes
send_errors=Yes
send_warnings=No
attach_wpscan_output=Yes
resend_emails_after=5d
wp_reports=./test.json
follow_redirect=Yes
"""%(json.dumps(self.get_sites()))
        w=WPWatcher(WPWatcherConfig(string=config).build_config()[0])
        exit_code, results=w.run_scans_and_notify()
        self.assertEqual(0, exit_code)