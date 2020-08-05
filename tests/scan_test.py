import unittest
import os
import shutil
from wpwatcher.scan import WPWatcherScanner, WPWatcherConfig, WPScanWrapper
from wpwatcher.utils import get_valid_filename
from . import WP_SITES, DEFAULT_CONFIG

class T(unittest.TestCase):
    
    def test_update_report(self):
        # Init Scanner
        scanner = WPWatcherScanner(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0])
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
                        'Issue regarding component "%s" has been fixed since last report.\nLast report sent the %s'%("[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).",old['last_email'])    
                    ],
                    "wpscan_output":""
                }
            
            scanner.update_report(new,old,s)
            print(new)
            print(expected)
            self.assertEqual(new, expected, "There is an issue with fixed issues feature: the expected report do not match the report returned by update_report()")

    def test_wpscan_output_folder(self):
        RESULTS_FOLDER="./results/"
        WPSCAN_OUTPUT_CONFIG = DEFAULT_CONFIG+"\nwpscan_output_folder=%s"%RESULTS_FOLDER
        scanner=WPWatcherScanner(WPWatcherConfig(string=WPSCAN_OUTPUT_CONFIG).build_config()[0])
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
            f=scanner.write_wpscan_output(report)
            f1=os.path.join(RESULTS_FOLDER, 'warning/', get_valid_filename('WPScan_output_%s_%s.txt' % (s['url'], "2020-04-08T16-05-16")))
            self.assertEqual(f, f1, "Inconsistent WPScan output filenames")
            self.assertTrue(os.path.isfile(f1),"WPscan output file doesn't exist")
            with open(f1, 'r') as out:
                self.assertEqual(out.read(), "This is real%s"%(s))
        shutil.rmtree(RESULTS_FOLDER)



    def test_handle_wpscan_err(self):
            # test API wait, test Follow redirect
        # TODO
        pass

    def test_scan_site(self):
        # test info, warnings and alerts
        pass
