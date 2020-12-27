import unittest
import smtpd
import asyncore
import concurrent.futures
from . import DEFAULT_CONFIG, WP_SITES
from wpwatcher.email import EmailSender
from wpwatcher.core import WPWatcher
from wpwatcher.config import Config

class T(unittest.TestCase):

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

    def test_send_report(self):
           
        # Init WPWatcher
        wpwatcher = WPWatcher(Config.fromstring(DEFAULT_CONFIG+"\nattach_wpscan_output=Yes"))


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
                "error": '',
                "infos": [
                    "[+]","blablabla"],
                "warnings": [
                    "[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).\n| Found By: Emoji Settings (Passive Detection)\n",
                    "[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.\n[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"
                ],
                "alerts": [],
                "fixed": ["This issue was fixed"],
                "summary":None,
                "wpscan_output":"This is real%s"%(s)
            }

            wpwatcher.scanner.mail._send_report(report, email_to='test', wpscan_command= 'just testing')

            # self.assertEqual(report['fixed'], [], "Fixed item wasn't remove after email sent")
            # self.assertNotEqual(report['last_email'], None)

    def test_should_notify(self):
        # test send_errors, send_infos, send_warnings, resend_emails_after, email_errors_to
        # Init WPWatcher
        CONFIG=DEFAULT_CONFIG+"\nsend_infos=Yes\nsend_errors=Yes\nsend_warnings=No"
        wpwatcher = WPWatcher(Config.fromstring(CONFIG))
        # wpwatcher.scanner.mail
        # TODO
