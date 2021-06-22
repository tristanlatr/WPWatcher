"""
Wordpress Watcher core object. 
"""
from typing import Dict, Iterable, List, Sequence, Tuple, Any, Optional
import os
import threading
import shutil
import concurrent.futures
import traceback
import signal
import sys


from wpwatcher import log, _init_log
from wpwatcher.db import DataBase
from wpwatcher.scan import Scanner
from wpwatcher.utils import safe_log_wpscan_args, print_progress_bar, timeout
from wpwatcher.site import Site
from wpwatcher.report import ReportCollection, ScanReport
from wpwatcher.config import Config

# Date format used everywhere
DATE_FORMAT = "%Y-%m-%dT%H-%M-%S"

# WPWatcher class ---------------------------------------------------------------------
class WPWatcher:
    """WPWatcher object

    Usage exemple:

    .. python::

        from wpwatcher.config import Config
        from wpwatcher.core import WPWatcher
        config = Config.fromenv()
        config.update({ 'send_infos':   True,
                        'wp_sites':     [   {'url':'exemple1.com'},
                                            {'url':'exemple2.com'}  ],
                        'wpscan_args': ['--format', 'json', '--stealthy']
                    })
        watcher = WPWatcher(config)
        exit_code, reports = watcher.run_scans()
        for r in reports:
            print("%s\t\t%s"%( r['site'], r['status'] ))
    """

    # WPWatcher must use a configuration dict
    def __init__(self, conf: Config):
        """
        Arguments:
        - `conf`: the configuration dict. Required
        """
        # (Re)init logger with config
        _init_log(verbose=conf["verbose"], quiet=conf["quiet"], logfile=conf["log_file"])

        self._delete_tmp_wpscan_files()

        # Init DB interface
        self.wp_reports: DataBase = DataBase(filepath=conf["wp_reports"], daemon=conf['daemon'])

        # Update config before passing it to WPWatcherScanner
        conf.update({"wp_reports": self.wp_reports.filepath})

        # Init scanner
        self.scanner: Scanner = Scanner(conf)

        # Save sites
        conf["wp_sites"] = [
            Site(site_conf) for site_conf in conf["wp_sites"]
        ]
        self.wp_sites: List[Site] = conf["wp_sites"]
        

        # Asynchronous executor
        self._executor: concurrent.futures.ThreadPoolExecutor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=conf["asynch_workers"])
        )

        # List of conccurent futures
        self._futures: List[concurrent.futures.Future] = []  # type: ignore [type-arg]

        # Register the signals to be caught ^C , SIGTERM (kill) , service restart , will trigger interrupt()
        signal.signal(signal.SIGINT, self.interrupt)
        signal.signal(signal.SIGTERM, self.interrupt)

        self.new_reports = ReportCollection()
        """New reports, reset when running `run_scans`."""

        # Dump config
        log.debug(f"Configuration:{repr(conf)}")

    @staticmethod
    def _delete_tmp_wpscan_files() -> None:
        """Delete temp wpcan files"""
        # Try delete temp files.
        if os.path.isdir("/tmp/wpscan"):
            try:
                shutil.rmtree("/tmp/wpscan")
                log.info("Deleted temp WPScan files in /tmp/wpscan/")
            except (FileNotFoundError, OSError, Exception):
                log.info(
                    f"Could not delete temp WPScan files in /tmp/wpscan/\n{traceback.format_exc()}"
                )

    def _cancel_pending_futures(self) -> None:
        """Cancel all asynchronous jobs"""
        for f in self._futures:
            if not f.done():
                f.cancel()

    def interrupt_scans(self) -> None:
        """
        Interrupt the scans and append finished scan reports to self.new_reports
        """
        # Cancel all scans
        self._cancel_pending_futures()  # future scans
        self.scanner.interrupt()  # running scans
        self._rebuild_rew_reports()

    def _rebuild_rew_reports(self) -> None:
        "Recover reports from futures results"
        self.new_reports = ReportCollection()
        for f in self._futures:
            if f.done():
                try:
                    self.new_reports.append(f.result())
                except Exception:
                    pass

    def interrupt(self, sig=None, frame=None) -> None:  # type: ignore [no-untyped-def]
        """Interrupt the program and exit. """
        log.error("Interrupting...")
        # If called inside ThreadPoolExecutor, raise Exeception
        if not isinstance(threading.current_thread(), threading._MainThread):  # type: ignore [attr-defined]
            raise InterruptedError()
        
        self.interrupt_scans()

        # Give a 5 seconds timeout to buggy WPScan jobs to finish or ignore them
        try:
            timeout(5, self._executor.shutdown, kwargs=dict(wait=True))
        except TimeoutError:
            pass

        # Display results 
        log.info(repr(self.new_reports))
        log.info("Scans interrupted.")

        # and quit
        sys.exit(-1)


    def _log_db_reports_infos(self) -> None:
        if len(self.new_reports) > 0 and repr(self.new_reports) != "No scan report to show":
            if self.wp_reports.filepath != "null":
                log.info(f"Updated reports in database: {self.wp_reports.filepath}")
            else:
                log.info("Local database disabled, no reports updated.")


    def _scan_site(self, wp_site: Site) -> Optional[ScanReport]:
        """
        Helper method to wrap the scanning process of `WPWatcherScanner.scan_site` and add the following:
        
        - Find the last report in the database and launch the scan
        - Write it in DB after scan.
        - Print progress bar

        This function can be called asynchronously.
        """

        last_wp_report = self.wp_reports.find(ScanReport(site=wp_site["url"]))

        # Launch scanner
        wp_report = self.scanner.scan_site(wp_site, last_wp_report)
        
        # Save report in global instance database and to file when a site has been scanned
        if wp_report:
            self.wp_reports.write([wp_report])
        else:
            log.info(f"No report saved for site {wp_site['url']}")
        
        # Print progress
        print_progress_bar(len(self.scanner.scanned_sites), len(self.wp_sites))
        return wp_report

    def _run_scans(self, wp_sites: List[Site]) -> ReportCollection:
        """
        Helper method to deal with :

        - executor, concurent futures
        - Trigger self.interrupt() on InterruptedError (raised if fail fast enabled)
        - Append result to `self.new_reports` list.
        """

        log.info(f"Starting scans on {len(wp_sites)} configured sites")

        # reset new reports and scanned sites list. 
        self._futures.clear()
        self.new_reports.clear()
        self.scanner.scanned_sites.clear()

        for wp_site in wp_sites:
            self._futures.append(self._executor.submit(self._scan_site, wp_site))
        for f in self._futures:
            try:
                self.new_reports.append(f.result())
            except concurrent.futures.CancelledError:
                pass
        # Ensure everything is down
        self._cancel_pending_futures()
        return self.new_reports

    def run_scans(self) -> Tuple[int, ReportCollection]:
        """
        Run WPScan on defined websites and send notifications.

        :Returns: `tuple (exit code, reports)`
        """

        # Check sites are in the config
        if len(self.wp_sites) == 0:
            log.error(
                "No sites configured, please provide wp_sites in config file or use arguments --url URL [URL...] or --urls File path"
            )
            return (-1, self.new_reports)

        self.wp_reports.open()
        try:
            self._run_scans(self.wp_sites)
        # Handle interruption from inside threads when using --ff
        except InterruptedError:
            self.interrupt()
        finally:
            self.wp_reports.close()

        # Print results and finish
        log.info(repr(self.new_reports))

        if not any([r["status"] == "ERROR" for r in self.new_reports if r]):
            log.info("Scans finished successfully.")
            return (0, self.new_reports)
        else:
            log.info("Scans finished with errors.")
            return (-1, self.new_reports)

    # run_scans_and_notify = run_scans