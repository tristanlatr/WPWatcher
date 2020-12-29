
from typing import Dict, Any, Optional
import time
import signal 
import sys
import os
from datetime import datetime, timedelta

from wpwatcher import log
from wpwatcher.core import WPWatcher
from wpwatcher.config import Config
from wpwatcher.report import ScanReport
from wpwatcher.site import Site

from daemon import DaemonContext
from filelock import FileLock, Timeout

# Date format used everywhere
DATE_FORMAT = "%Y-%m-%dT%H-%M-%S"

class Daemon:
    """
    Daemonizer for `WPWatcher.run_scans`. 
    """
    def __init__(self, conf: Config) -> None:
        self._daemon_loop_sleep = conf['daemon_loop_sleep']
        # Make sure the daemon mode is enabled
        conf['daemon'] = True
        self.wpwatcher = WPWatcherDaemonMode(conf)
        self.pidfile = '/tmp/wpwatcher.daemon.pid.lock'
        self.pidfilelock = FileLock(self.pidfile, timeout=1)
        self.context = DaemonContext(
            pidfile = self.pidfilelock, 
            signal_map = {
                signal.SIGTERM: self.wpwatcher.interrupt,
                },
            detach_process = False,
            # stdout = sys.stdout, 
            # stderr = sys.stderr, 
            )
        self._running: bool = False
        self._stopping: bool = False
        self._start_time: datetime
        
    def loop(self, ttl:Optional[timedelta]=None, fake:bool=False) -> None:
        "Turn the process into a unix daemon and enter the infinite loop that is calling `WPWatcher.run_scans`. "
        self._running = True
        self._start_time = datetime.now()
        log.info("Daemon mode selected, looping for ever...")
        try:
            with (self.context if not fake else self.pidfilelock):
                while self._running:
                    # Run scans for ever
                    self.wpwatcher.run_scans()
                    if ttl and datetime.now() - self._start_time > ttl:
                        self._running = False
                        self._stopping = True
                    if not self._stopping:
                        log.info(
                            f"Sleeping {self._daemon_loop_sleep} and scanning again..."
                        )
                        time.sleep(self._daemon_loop_sleep.total_seconds())
        except Timeout as err:
            log.error("The WPWatcher daemon is already running")
            raise RuntimeError("The WPWatcher daemon is already running") from err
        finally:
            self._running = False
            self._stopping = False
    
    def stop(self) -> None:
        "Interrupt the scans and stop the loop, do NOT raise SystemExit. "
        self._stopping = True
        self._running = False
        self.wpwatcher.interrupt_scans()

class WPWatcherDaemonMode(WPWatcher):

    def __init__(self, conf: Config):
        super().__init__(conf)
        self._daemon_loop_sleep: timedelta = conf["daemon_loop_sleep"]

    def scan_site(self, wp_site: Site) -> Optional[ScanReport]:
        "Skips a site if it has already been scanned lately. "

        last_wp_report = self.wp_reports.find(ScanReport(site=wp_site["url"]))
        # Skip if the daemon mode is enabled and scan already happend in the last configured `daemon_loop_wait`
        if last_wp_report and self._skip_this_site(last_wp_report):
            return None

        return super().scan_site(wp_site)

    def _skip_this_site(self, last_wp_report: ScanReport) -> bool:
        """Return true if the daemon mode is enabled and scan already happend in the last configured `daemon_loop_wait`"""
        if (
            datetime.now()
            - datetime.strptime(last_wp_report["datetime"], DATE_FORMAT)
            < self._daemon_loop_sleep
        ):
            log.info(
                f"Daemon skipping site {last_wp_report['site']} because already scanned in the last {self._daemon_loop_sleep}"
            )
            return True
        return False
