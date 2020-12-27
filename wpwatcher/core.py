"""
Wordpress Watcher core object. 
"""
from typing import Dict, List, Tuple, Any, Optional
import os
import threading
import shutil
import concurrent.futures
import traceback
import signal
import sys


from wpwatcher import log, _init_log
from wpwatcher.db import WPWatcherDataBase
from wpwatcher.scan import WPWatcherScanner
from wpwatcher.utils import safe_log_wpscan_args, print_progress_bar, timeout
from wpwatcher.site import WPWatcherSite
from wpwatcher.report import WPWatcherReportCollection

# Date format used everywhere
DATE_FORMAT = "%Y-%m-%dT%H-%M-%S"

# WPWatcher class ---------------------------------------------------------------------
class WPWatcher:
    """WPWatcher object

    Usage exemple:

    .. python::

        from wpwatcher.config import WPWatcherConfig
        from wpwatcher.core import WPWatcher
        config = WPWatcherConfig.fromenv()
        config.update({ 'send_infos':   True,
                        'wp_sites':     [   {'url':'exemple1.com'},
                                            {'url':'exemple2.com'}  ],
                        'wpscan_args': ['--format', 'json', '--stealthy']
                    })
        watcher = WPWatcher(config)
        exit_code, reports = watcher.run_scans_and_notify()
        for r in reports:
            print("%s\t\t%s"%( r['site'], r['status'] ))
    """

    # WPWatcher must use a configuration dict
    def __init__(self, conf: Dict[str, Any]):
        """
        Arguments:
        - `conf`: the configuration dict. Required
        """
        # (Re)init logger with config
        _init_log(verbose=conf["verbose"], quiet=conf["quiet"], logfile=conf["log_file"])

        self.delete_tmp_wpscan_files()

        # Init DB interface
        self.wp_reports: WPWatcherDataBase = WPWatcherDataBase(conf["wp_reports"])

        # Update config before passing it to WPWatcherScanner
        conf.update({"wp_reports": self.wp_reports.filepath})

        # Init scanner
        self.scanner: WPWatcherScanner = WPWatcherScanner(conf)

        # Dump config
        log.info(f"Configuration:{repr(conf)}")

        # Save sites
        self.wp_sites: List[Dict[str, Any]] = [
            WPWatcherSite(site_conf) for site_conf in conf["wp_sites"]
        ]

        # Asynchronous executor
        self.executor: concurrent.futures.ThreadPoolExecutor = (
            concurrent.futures.ThreadPoolExecutor(max_workers=conf["asynch_workers"])
        )

        # List of conccurent futures
        self.futures: List[concurrent.futures.Future] = []  # type: ignore [type-arg]

        # Register the signals to be caught ^C , SIGTERM (kill) , service restart , will trigger interrupt()
        signal.signal(signal.SIGINT, self.interrupt)
        signal.signal(signal.SIGTERM, self.interrupt)

        # new reports
        self.new_reports: WPWatcherReportCollection

    @staticmethod
    def delete_tmp_wpscan_files() -> None:
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

    def cancel_pending_futures(self) -> None:
        """Cancel all asynchronous jobs"""
        for f in self.futures:
            if not f.done():
                f.cancel()

    def interrupt(self, sig=None, frame=None) -> None:  # type: ignore [no-untyped-def]
        """Interrupt sequence"""
        log.error("Interrupting...")
        # If called inside ThreadPoolExecutor, raise Exeception
        if not isinstance(threading.current_thread(), threading._MainThread):  # type: ignore [attr-defined]
            raise InterruptedError()
        
        # Cancel all scans
        self.cancel_pending_futures()  # future scans
        self.scanner.interrupt()  # running scans

        # Give a 5 seconds timeout to buggy WPScan jobs to finish or ignore them
        try:
            timeout(5, self.executor.shutdown, kwargs=dict(wait=True))
        except TimeoutError:
            pass

        # Recover reports from futures results
        new_reports: WPWatcherReportCollection = WPWatcherReportCollection()
        for f in self.futures:
            if f.done():
                try:
                    new_reports.append(f.result())
                except Exception:
                    pass

        # Display results and quit
        self.print_new_reports_results(new_reports)
        log.info("Scans interrupted.")
        sys.exit(-1)

    def print_new_reports_results(self, new_reports: List[Dict[str, Any]]) -> None:
        """Print the result summary for the scanned sites"""
        new_reports = WPWatcherReportCollection(n for n in new_reports if n)
        if len(new_reports) > 0:
            log.info(repr(new_reports))
            if self.wp_reports.filepath != "null":
                log.info(
                    f"Updated {len(new_reports)} reports in database: {self.wp_reports.filepath}"
                )
            else:
                log.info("Local database disabled, no reports updated.")
        else:
            log.info("No reports updated.")

    def scan_site(self, wp_site: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Helper method to wrap the scanning process of `WPWatcherScanner.scan_site` and add the following:
        - Find the last report in the database and launch the scan
        - Write it in DB after scan.
        - Print progress bar

        This function will be called asynchronously.
        Return one report
        """

        last_wp_report = self.wp_reports.find_last_wp_report({"site": wp_site["url"]})

        # Launch scanner
        wp_report = self.scanner.scan_site(wp_site, last_wp_report)
        # Save report in global instance database and to file when a site has been scanned
        if wp_report:
            self.wp_reports.update_and_write_wp_reports([wp_report])
        else:
            log.info(f"No report saved for site {wp_site['url']}")
        # Print progress
        print_progress_bar(len(self.scanner.scanned_sites), len(self.wp_sites))
        return wp_report

    def _run_scans(self, wp_sites: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Helper method to deal with :
        - executor, concurent futures
        - Trigger self.interrupt() on InterruptedError (raised if fail fast enabled)
        - Append result to `self.new_reports` list.
        """

        log.info(f"Starting scans on {len(wp_sites)} configured sites")
        for wp_site in wp_sites:
            self.futures.append(self.executor.submit(self.scan_site, wp_site))
        for f in self.futures:
            try:
                self.new_reports.append(f.result())
            # Handle interruption from inside threads when using --ff
            except InterruptedError:
                self.interrupt()
            except concurrent.futures.CancelledError:
                pass
        # Ensure everything is down
        self.cancel_pending_futures()
        return self.new_reports

    def run_scans(self) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Run WPScan on defined websites and send notifications.

        :Returns: `tuple (exit code, reports)`
        """

        # reset new reports
        self.new_reports = WPWatcherReportCollection()

        # Check sites are in the config
        if len(self.wp_sites) == 0:
            log.error(
                "No sites configured, please provide wp_sites in config file or use arguments --url URL [URL...] or --urls File path"
            )
            return (-1, self.new_reports)

        self.wp_reports.open()
        try:
            self._run_scans(self.wp_sites)
        finally:
            self.wp_reports.close()

        # Print results and finish
        self.print_new_reports_results(self.new_reports)

        if not any([r["status"] == "ERROR" for r in self.new_reports if r]):
            log.info("Scans finished successfully.")
            return (0, self.new_reports)
        else:
            log.info("Scans finished with errors.")
            return (-1, self.new_reports)

    run_scans_and_notify = run_scans