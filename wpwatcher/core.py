""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
from typing import Mapping, List, Tuple, Any
import copy
import os
import json
import threading
import shutil
import concurrent.futures
import traceback
import signal
import sys


from wpwatcher import log, init_log
from wpwatcher.db import WPWatcherDataBase
from wpwatcher.scan import WPWatcherScanner
from wpwatcher.utils import safe_log_wpscan_args, print_progress_bar, timeout
from wpwatcher.site import WPWatcherSite
from wpwatcher.report import WPWatcherReport, WPWatcherReportCollection

# Date format used everywhere
DATE_FORMAT = "%Y-%m-%dT%H-%M-%S"

# WPWatcher class ---------------------------------------------------------------------
class WPWatcher:
    """WPWacther object

    Usage exemple::

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
    def __init__(self, conf:Mapping[str, Any]):
        """
        Arguments:
        - `conf`: the configuration dict. Required
        """
        # (Re)init logger with config
        init_log(verbose=conf["verbose"], quiet=conf["quiet"], logfile=conf["log_file"])

        self.delete_tmp_wpscan_files()

        # Init DB interface
        self.wp_reports:WPWatcherDataBase = WPWatcherDataBase(conf["wp_reports"])

        # Update config before passing it to WPWatcherScanner
        conf.update({"wp_reports": self.wp_reports.filepath})

        # Init scanner
        self.scanner:WPWatcherScanner = WPWatcherScanner(conf)

        # Dump config
        log.info("WPWatcher configuration:{}".format(repr(conf)))

        # Save sites
        self.wp_sites:List[WPWatcherSite] = [ WPWatcherSite(site_conf) for site_conf in conf["wp_sites"] ]

        # Asynchronous executor
        self.executor:concurrent.futures.ThreadPoolExecutor = concurrent.futures.ThreadPoolExecutor(
            max_workers=conf["asynch_workers"]
        )

        # List of conccurent futures
        self.futures:List[concurrent.futures.Future] = []

        # Register the signals to be caught ^C , SIGTERM (kill) , service restart , will trigger interrupt()
        signal.signal(signal.SIGINT, self.interrupt)
        signal.signal(signal.SIGTERM, self.interrupt)

        # new reports
        self.new_reports:WPWatcherReportCollection

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
                    "Could not delete temp WPScan files in /tmp/wpscan/\n%s"
                    % (traceback.format_exc())
                )

    

    def cancel_pending_futures(self) -> None:
        """Cancel all asynchronous jobs"""
        for f in self.futures:
            if not f.done():
                f.cancel()

    def interrupt(self, sig=None, frame=None) -> None:
        """Interrupt sequence"""
        log.error("Interrupting...")
        # If called inside ThreadPoolExecutor, raise Exeception
        if not isinstance(threading.current_thread(), threading._MainThread):
            raise InterruptedError()
        # Cancel all scans
        self.cancel_pending_futures()  # future scans
        # Wait all scans finished
        self.scanner.cancel_scans()  # running scans

        # Give a 5 seconds timeout to buggy WPScan jobs to finish or ignore them
        try:
            timeout(5, self.executor.shutdown, kwargs=dict(wait=True))
        except TimeoutError:
            pass

        # Recover reports from futures results
        new_reports = []
        for f in self.futures:
            if f.done():
                try:
                    new_reports.append(f.result())
                except Exception:
                    pass

        # Display results and quit
        self.print_scanned_sites_results(new_reports)
        log.info("Scans interrupted.")
        sys.exit(-1)

    def print_scanned_sites_results(self, new_reports:WPWatcherReportCollection) -> None:
        """Print the result summary for the scanned sites"""
        new_reports = [n for n in new_reports if n]
        if len(new_reports) > 0:
            log.info(repr(new_reports))
            if self.wp_reports.filepath != "null":
                log.info(
                    "Updated %s reports in database: %s"
                    % (len(new_reports), self.wp_reports.filepath)
                )
            else:
                log.info("Local database disabled, no reports updated.")
        else:
            log.info("No reports updated.")

    def scan_site_wrapper(self, wp_site:WPWatcherSite) -> WPWatcherReport:
        """
        Helper method to wrap the raw scanning process of `WPWatcherScanner.scan_site` and add the following:
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
            log.info("No report saved for site %s" % wp_site["url"])
        # Print progress
        print_progress_bar(len(self.scanner.scanned_sites), len(self.wp_sites))
        return wp_report

    def run_scans_wrapper(self, wp_sites:List[WPWatcherSite]) -> WPWatcherReportCollection:
        """
        Helper method to deal with :
        - executor, concurent futures
        - Trigger self.interrupt() on InterruptedError (raised if fail fast enabled)
        - Append result to `self.new_reports` list. 
        """

        log.info("Starting scans on %s configured sites" % (len(wp_sites)))
        for wp_site in wp_sites:
            self.futures.append(self.executor.submit(self.scan_site_wrapper, wp_site))
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

    def run_scans_and_notify(self) -> Tuple[int, WPWatcherReportCollection]:
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
            return (-1, [])

        new_reports = self.run_scans_wrapper(self.wp_sites)
        # Print results and finish
        self.print_scanned_sites_results(new_reports)

        if not any([r["status"] == "ERROR" for r in new_reports if r]):
            log.info("Scans finished successfully.")
            return (0, new_reports)
        else:
            log.info("Scans finished with errors.")
            return (-1, new_reports)
