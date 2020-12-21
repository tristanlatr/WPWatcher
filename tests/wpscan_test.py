import unittest
from wpwatcher.scan import  WPScanWrapper

class T(unittest.TestCase):

    def test_wpscan(self):
        wpscan=WPScanWrapper('wpscan')
        ex,out,err=wpscan.wpscan("--url","wp.exemple.com")
        self.assertEqual(ex,4,"Scanning wp.exemple.com successful, that's weird !")
        ex,out,err=wpscan.wpscan("--version")
        self.assertEqual(ex,0,"WPScan failed when printing version")