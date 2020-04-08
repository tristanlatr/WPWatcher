
import json
import re
import sys
import argparse
from datetime import datetime, timedelta
import unittest
import wpwatcher
from wpwatcher import WPWatcher, build_config_files

def parse_args():
    parser = argparse.ArgumentParser(description='WPWatcher test script')
    # parser.add_argument('--input', metavar='path', help="WPScan Json or CLI output", required=True)
    # parser.add_argument('--search', metavar='Keyword', required=True)
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    # Init scan messages
    ( messages, warnings, alerts ) = ([],[],[])
    args=parse_args()

SITES="""epoxiemktg.com
driveinteractivepdx.com
protodave.com
affiliatesbootcamp.com
serviceproeastidaho.com
"""

class WPWatcherTests(unittest.TestCase):

    def test_simple(self):
        w=WPWatcher({
            'wp_sites' :[{'url':v} for v in SITES.splitlines()],
            'false_positive_strings' : ['No WPVulnDB API Token given, as a result vulnerability data has not been output'],                        
            'wpscan_path':'wpscan',
            'log_file':"",
            'wpscan_args':["--no-banner","--random-user-agent"],
            'send_email_report':False,
            'send_errors':False,
            'email_to':[],
            'email_errors_to':[],
            'send_warnings':True,
            'send_infos':False,
            'attach_wpscan_output':False,
            'smtp_server':"",
            'smtp_auth':False,
            'smtp_user':"",
            'smtp_pass':"",
            'smtp_ssl':False,
            'from_email':"",
            'quiet':False,
            'verbose':False,
            'fail_fast':False,
            'api_limit_wait':False,
            'daemon':False,
            'daemon_loop_sleep':timedelta(seconds=0),
            'resend_emails_after':timedelta(seconds=0),
            'wp_reports':'null',
            'asynch_workers':3
        })
        exit_code, results=w.run_scans_and_notify()
        self.assertEqual(0, exit_code)


