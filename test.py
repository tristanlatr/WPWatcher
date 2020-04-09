
import json
import re
import sys
import argparse
from datetime import datetime, timedelta
import unittest
import wpwatcher
from wpwatcher import WPWatcher, build_config

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

SITES=[{'url':''}]

class WPWatcherTests(unittest.TestCase):

    def test_simple(self):
        w=WPWatcher({
            'wp_sites' :SITES,
            'false_positive_strings' : ['No WPVulnDB API Token given, as a result vulnerability data has not been output'],                        
            'wpscan_path':'wpscan',
            'log_file':"",
            'wpscan_args':["--no-banner","--random-user-agent"],
            'send_email_report':False,
            'send_errors':False,
            'email_to':[],
            'email_errors_to':[],
            'send_warnings':True,
            'send_infos':True,
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
            'wp_reports':'./test.json',
            'asynch_workers':3,
            'follow_redirect':False
        })
        exit_code, results=w.run_scans_and_notify()
        self.assertEqual(0, exit_code)
    
    def test_error(self):
        w=WPWatcher({
            'wp_sites' :[{'url':'exemple.com'}],
            'false_positive_strings' : ['No WPVulnDB API Token given, as a result vulnerability data has not been output'],                        
            'wpscan_path':'wpscan',
            'log_file':"",
            'wpscan_args':["--no-banner","--random-user-agent"],
            'send_email_report':False,
            'send_errors':False,
            'email_to':[],
            'email_errors_to':[],
            'send_warnings':True,
            'send_infos':True,
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
            'wp_reports':'',
            'asynch_workers':3,
            'follow_redirect':False
        })
        exit_code, results=w.run_scans_and_notify()
        self.assertEqual(-1, exit_code)

    def test_json(self):
        w=WPWatcher({
            'wp_sites' :SITES,
            'false_positive_strings' : ['No WPVulnDB API Token given, as a result vulnerability data has not been output'],                        
            'wpscan_path':'wpscan',
            'log_file':"",
            'wpscan_args':["--no-banner","--random-user-agent", "--format", "json"],
            'send_email_report':False,
            'send_errors':False,
            'email_to':[],
            'email_errors_to':[],
            'send_warnings':True,
            'send_infos':True,
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
            'wp_reports':'./test-parse-json.json',
            'asynch_workers':3,
            'follow_redirect':False
        })
        exit_code, results=w.run_scans_and_notify()
        self.assertEqual(0, exit_code)

    def test_config(self):
        config="""
[wpwatcher]
wpscan_args=[   "--format", "cli",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks" ]

# False positive string matches
# false_positive_strings=["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]

# Sites (--url or --urls)
wp_sites=%s

# Notifications (--send , --em , --infos , --errors , --attach , --resend)
send_email_report=Yes
# email_to=["you@domain"]
send_infos=Yes
send_errors=Yes
send_warnings=No
attach_wpscan_output=Yes
resend_emails_after=5d
# email_errors_to=["admins@domain"]

# Sleep when API limit reached (--wait)
# api_limit_wait=Yes

# Daemon settings (recommended to use --daemon)
# daemon=No
daemon_loop_sleep=5m

# Output (-q , -v)
# log_file=./wpwatcher.log
# quiet=Yes
# verbose=Yes

# Custom database (--reports)
wp_reports=./test.json

# Exit if any errors (--ff)
# fail_fast=Yes 

"""%(json.dumps(SITES))
        with open('./wpwatcher.conf', 'w') as configfile:
            configfile.write(config)
        w=WPWatcher(build_config({ 'quiet':True }))
        exit_code, results=w.run_scans_and_notify()
        self.assertEqual(0, exit_code)



