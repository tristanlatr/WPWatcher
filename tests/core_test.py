import unittest
import os
import shlex
from . import DEFAULT_CONFIG
from wpwatcher.core import WPWatcher
from wpwatcher.config import Config
from wpwatcher.scan import Scanner
from wpwatcher.email import EmailSender
from wpwatcher.wpscan import WPScanWrapper

class T(unittest.TestCase):
    
    def test_interrupt(self):
        wpwatcher=WPWatcher(Config.fromstring(DEFAULT_CONFIG))

        with self.assertRaises(SystemExit):
            wpwatcher.interrupt()

    def test_init_wpwatcher(self):
        # Init deafult watcher
        wpwatcher=WPWatcher(Config.fromstring(DEFAULT_CONFIG))

        self.assertEqual(type(wpwatcher.scanner), Scanner, "Scanner doesn't seem to have been initialized")
        self.assertEqual(type(wpwatcher.scanner.mail), EmailSender, "EmailSender doesn't seem to have been initialized")
        self.assertEqual(type(wpwatcher.scanner.wpscan), WPScanWrapper, "WPScanWrapper doesn't seem to have been initialized")
        self.assertEqual(shlex.split(Config.fromstring(DEFAULT_CONFIG)['wpscan_path']), wpwatcher.scanner.wpscan._wpscan_executable, "WPScan path seems to be wrong")

    def test_asynch_exec(self):
        # test max number of threads respected
        pass

    def test_daemon(self):
        # test daemon_loop_sleep and daemon mode
        pass

    def test_fail_fast(self):
        pass

    def test_run_scans_and_notify(self):
        # test returned results
        pass
