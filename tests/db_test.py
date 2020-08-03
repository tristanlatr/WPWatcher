import unittest
import json
from wpwatcher.scan import WPWatcherConfig
from wpwatcher.utils import get_valid_filename
from wpwatcher.db import WPWatcherDataBase
from . import WP_SITES, DEFAULT_CONFIG

class T(unittest.TestCase):

    def test_wp_reports_read_write(self):
        SPECIFIC_WP_REPORTS_FILE_CONFIG = DEFAULT_CONFIG+"\nwp_reports=%s"

        # Compare with config and no config
        db=WPWatcherDataBase()
        paths_found=db.find_wp_reports_file()
        db2=WPWatcherDataBase(WPWatcherConfig(string=SPECIFIC_WP_REPORTS_FILE_CONFIG%(paths_found)).build_config()[0]['wp_reports'])
        self.assertEqual(db._data, db2._data, "WP reports database are different even if files are the same")
        
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

        db=WPWatcherDataBase()
        db.update_and_write_wp_reports(reports)

        # Test internal _data gets updated after update_and_write_wp_reports() method
        for r in reports:
            self.assertIn(r, db._data, "The report do not seem to have been saved into WPWatcher.wp_report list")

        # Test write method
        wrote_db=db.build_wp_reports(db.filepath)
        with open(db.filepath,'r') as dbf:
            wrote_db_alt=json.load(dbf)
        for r in reports:
            self.assertIn(r, wrote_db, "The report do not seem to have been saved into db file")
            self.assertIn(r, wrote_db_alt, "The report do not seem to have been saved into db file (directly read with json.load)")
        self.assertEqual(db._data, wrote_db_alt, "The database file wrote (directly read with json.load) differ from in memory database")
        self.assertEqual(db._data, wrote_db, "The database file wrote differ from in memory database")