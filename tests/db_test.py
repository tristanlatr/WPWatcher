import unittest
import json
from wpwatcher.config import Config
from wpwatcher.db import DataBase
from wpwatcher.report import ScanReport, ReportCollection
from . import WP_SITES, DEFAULT_CONFIG

class T(unittest.TestCase):

    def test_wp_reports_read_write(self):
        SPECIFIC_WP_REPORTS_FILE_CONFIG = DEFAULT_CONFIG+"\nwp_reports=%s"

        # Compare with config and no config
        db=DataBase()
        paths_found=db._find_db_file()
        db2=DataBase(
            filepath = Config.fromstring(SPECIFIC_WP_REPORTS_FILE_CONFIG%(paths_found))['wp_reports'])
        self.assertEqual(db._data, db2._data, "WP reports database are different even if files are the same")
        
        # Test Reports database 
        reports = [
            ScanReport({
                "site": "exemple.com",
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
                "fixed": []
            }),
            ScanReport({
                "site": "exemple2.com",
                "status": "INFO",
                "datetime": "2020-04-08T16-05-16",
                "last_email": None,
                "error": '',
                "infos": [
                    "[+]","blablabla"],
                "warnings": [],
                "alerts": [],
                "fixed": []
            })
        ]

        db=DataBase()
        db.open()
        db.write(reports)
        db.close()

        # Test internal _data gets updated after write() method
        for r in reports:
            self.assertIn(r, db._data, "The report do not seem to have been saved into WPWatcher.wp_report list")

        # Test write method
        wrote_db=ReportCollection(ScanReport(item) for item in db._build_db(db.filepath))
        with open(db.filepath,'r') as dbf:
            wrote_db_alt=ReportCollection(ScanReport(item) for item in json.load(dbf))
        for r in reports:
            self.assertIn(r, list(wrote_db), "The report do not seem to have been saved into db file")
            self.assertIn(r, list(wrote_db_alt), "The report do not seem to have been saved into db file (directly read with json.load)")
            self.assertIsNotNone(db.find(ScanReport(site=r['site'])), "The report do not seem to have been saved into db, cannot find it using find(). ")
        self.assertEqual(list(db._data), list(wrote_db_alt), "The database file wrote (directly read with json.load) differ from in memory database")
        self.assertEqual(list(db._data), list(wrote_db), "The database file wrote differ from in memory database")

