import unittest
import os
import shlex
from . import DEFAULT_CONFIG
from wpwatcher.core import WPWatcher
from wpwatcher.config import WPWatcherConfig
from wpwatcher.scan import WPWatcherScanner
from wpwatcher.notification import WPWatcherNotification
from wpwatcher.wpscan import WPScanWrapper

class T(unittest.TestCase):
    
    def test_interrupt(self):
        wpwatcher=WPWatcher(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0])

        with self.assertRaises(SystemExit):
            wpwatcher.interrupt()

    def test_init_wpwatcher(self):
        # Init deafult watcher
        wpwatcher=WPWatcher(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0])
        flag=WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0]

        self.assertEqual(type(wpwatcher.scanner), WPWatcherScanner, "WPWatcherScanner doesn't seem to have been initialized")
        self.assertEqual(type(wpwatcher.scanner.mail), WPWatcherNotification, "WPWatcherNotification doesn't seem to have been initialized")
        self.assertEqual(type(wpwatcher.scanner.wpscan), WPScanWrapper, "WPScanWrapper doesn't seem to have been initialized")
        self.assertEqual(shlex.split(WPWatcherConfig(string=DEFAULT_CONFIG).build_config()[0]['wpscan_path']), wpwatcher.scanner.wpscan.wpscan_executable, "WPScan path seems to be wrong")

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