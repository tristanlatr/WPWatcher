import unittest
import os
import shutil
import http.server
import concurrent.futures
from wpwatcher.core import WPWatcher
from wpwatcher.scan import Scanner
from wpwatcher.config import Config
from wpwatcher.site import Site
from wpwatcher.report import ScanReport
from wpwatcher.utils import get_valid_filename
from . import WP_SITES, DEFAULT_CONFIG

from wpscan_out_parse import WPScanJsonParser

executor=None
server=None
class T(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Launch SMPT debbug server
        global executor
        global server
        server=http.server.HTTPServer(('localhost',8080), http.server.BaseHTTPRequestHandler )
        executor=concurrent.futures.ThreadPoolExecutor(1)
        executor.submit(server.serve_forever)

    @classmethod
    def tearDownClass(cls):
        # Close mail server
        global executor
        global server
        server.shutdown()
        executor.shutdown()
    
    def test_update_report(self):
        # Init Scanner
        scanner = Scanner(Config.fromstring(DEFAULT_CONFIG))
        for s in WP_SITES:
            old=ScanReport({
                    "site": s['url'],
                    "status": "WARNING",
                    "datetime": "2020-04-08T16-05-16",
                    "last_email": "2020-04-08T16-05-17",
                    "error": '',
                    "infos": [
                        "[+]","blablabla"],
                    "warnings": [
                        "[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).\nblablabla\n",
                        "[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.\n[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"
                    ],
                    "alerts": [],
                    "fixed": ["This issue was fixed"],
                    "summary":None,
                    "wpscan_output":""
                })
            parser = WPScanJsonParser(data={})
            new=ScanReport({
                    "site": s['url'],
                    "status": "",
                    "datetime": "2020-04-10T16-00-00",
                    "last_email": None,
                    "error": '',
                    "infos": [
                        "[+]","blablabla"],
                    "warnings": [
                        "[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.\n[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"
                    ],
                    "alerts": [],
                    "fixed": [],
                    "summary":None,
                    "wpscan_parser": parser,
                    "wpscan_output":""
                })

            expected=ScanReport({
                    "site": s['url'],
                    "status": "WARNING",
                    "datetime": "2020-04-10T16-00-00",
                    "last_email": "2020-04-08T16-05-17",
                    "error": '',
                    "infos": [
                        "[+]","blablabla"],
                    "warnings": [
                        "[!] No WPVulnDB API Token given, as a result vulnerability data has not been output.\n[!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up\nThis issue is unfixed since 2020-04-08T16-05-16"
                    ],
                    "alerts": [],
                    "fixed": [
                        "This issue was fixed",
                        'Issue regarding component "%s" has been fixed since the last scan.'%("[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).")    
                    ],
                    "summary":None,
                    "wpscan_parser": parser,
                    "wpscan_output":""
                })
            
            new.update_report(old)
            self.assertEqual(dict(new), dict(expected), "There is an issue with fixed issues feature: the expected report do not match the report returned by update_report()")

    def test_wpscan_output_folder(self):
        RESULTS_FOLDER="./results/"
        WPSCAN_OUTPUT_CONFIG = DEFAULT_CONFIG+"\nwpscan_output_folder=%s"%RESULTS_FOLDER
        scanner=Scanner(Config.fromstring(WPSCAN_OUTPUT_CONFIG))
        self.assertTrue(os.path.isdir(RESULTS_FOLDER),"WPscan results folder doesn't seem to have been init")
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
                "fixed": [],
                "summary":None,
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

    def test_scan_localhost_error_not_wordpress(self):
        # test info, warnings and alerts
        scanner=Scanner(Config.fromstring(DEFAULT_CONFIG))
        report=scanner.scan_site(Site({'url':'http://localhost:8080'}))
        self.assertEqual(report['status'], 'ERROR')
        self.assertRegex(report['error'], 'does not seem to be running WordPress')

    # def test_scan_localhost_error_not_wordpress_old_way(self):
    #     # test info, warnings and alerts
    #     scanner=Scanner(Config(string=DEFAULT_CONFIG).build_config()[0])
    #     report=scanner.scan_site(Site({'url':'http://localhost:8080'}))
    #     self.assertEqual(report['status'], 'ERROR')
    #     self.assertRegex(report['error'], 'does not seem to be running WordPress')
