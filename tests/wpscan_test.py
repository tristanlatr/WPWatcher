import unittest
from wpwatcher.scan import  WPScanWrapper

class T(unittest.TestCase):

    def test_wpscan(self):
        wpscan = WPScanWrapper('wpscan')
        p = wpscan.wpscan("--url", "wp.exemple.com")
        self.assertEqual(p.returncode, 4, "Scanning wp.exemple.com successful, that's weird !")
        p = wpscan.wpscan("--version")
        self.assertEqual(p.returncode, 0, "WPScan failed when printing version")