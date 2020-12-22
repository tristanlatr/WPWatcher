"""
Scanner utility. 
"""
from typing import Optional, BinaryIO, List, Tuple, Dict, Any
import threading
import re
import os
import time
import traceback
import json
from smtplib import SMTPException
from datetime import timedelta, datetime

from wpscan_out_parse.parser import WPScanJsonParser

from wpwatcher import log
from wpwatcher.__version__ import __version__
from wpwatcher.utils import (
    get_valid_filename,
    safe_log_wpscan_args,
    oneline,
    timeout,
    remove_color,
)
from wpwatcher.notification import WPWatcherNotification
from wpwatcher.wpscan import WPScanWrapper
from wpwatcher.syslogout import WPSyslogOutput
from wpwatcher.report import WPWatcherReport

# Wait when API limit reached
API_WAIT_SLEEP = timedelta(hours=24)

# Send kill signal after X seconds when cancelling
INTERRUPT_TIMEOUT = 5

# Date format used everywhere
DATE_FORMAT = "%Y-%m-%dT%H-%M-%S"


class WPWatcherScanner:
    """Scanner class create reports and handles the scan and notification process and build report. """

    def __init__(self, conf: Dict[str, Any]):

        # Create (lazy) wpscan link
        self.wpscan: WPScanWrapper = WPScanWrapper(conf["wpscan_path"])
        # Init mail client
        self.mail: WPWatcherNotification = WPWatcherNotification(conf)
        # Storing the Event object to wait for api limit to be reset and cancel the waiting enventually
        self.api_wait: threading.Event = threading.Event()
        # Toogle if aborting so other errors doesnt get triggerred and exit faster
        self.interrupting: bool = False
        # List of scanned URLs
        self.scanned_sites: List[Optional[str]] = []

        # Save required config options
        self.api_limit_wait: bool = conf["api_limit_wait"]
        self.follow_redirect: bool = conf["follow_redirect"]
        self.wpscan_output_folder: str = conf["wpscan_output_folder"]
        self.wpscan_args: List[str] = conf["wpscan_args"]
        self.fail_fast: bool = conf["fail_fast"]
        self.false_positive_strings: List[str] = conf["false_positive_strings"]
        self.daemon: bool = conf["daemon"]
        self.daemon_loop_sleep: timedelta = conf["daemon_loop_sleep"]

        # Scan timeout
        self.scan_timeout: timedelta = conf["scan_timeout"]

        # Init wpscan output folder
        if self.wpscan_output_folder:
            os.makedirs(self.wpscan_output_folder, exist_ok=True)
            os.makedirs(
                os.path.join(self.wpscan_output_folder, "error/"), exist_ok=True
            )
            os.makedirs(
                os.path.join(self.wpscan_output_folder, "alert/"), exist_ok=True
            )
            os.makedirs(
                os.path.join(self.wpscan_output_folder, "warning/"), exist_ok=True
            )
            os.makedirs(os.path.join(self.wpscan_output_folder, "info/"), exist_ok=True)

        self.syslog: Optional[WPSyslogOutput] = None
        if conf["syslog_server"]:
            self.syslog = WPSyslogOutput(conf)

    def check_fail_fast(self) -> None:
        """Fail fast, triger InterruptedError if fail_fast and not already interrupting."""
        if self.fail_fast and not self.interrupting:
            raise InterruptedError()

    def cancel_scans(self) -> None:
        """
        Send SIGTERM to all WPScan processes.
        Escape api limit wait if the program is sleeping.
        """
        self.interrupting = True
        # Send ^C to all WPScan not finished
        for p in self.wpscan.processes:
            p.terminate()
        # Wait for all processes to finish , kill after timeout
        try:
            timeout(INTERRUPT_TIMEOUT, self.wait_all_wpscan_process)
        except TimeoutError:
            for p in self.wpscan.processes:
                p.kill()
        # Unlock api wait
        self.api_wait.set()

    def wait_all_wpscan_process(self) -> None:
        """Wait all WPScan processes. To be called with timeout() function"""
        while len(self.wpscan.processes) > 0:
            time.sleep(0.5)

    # Scan process

    def update_report(
        self, wp_report: Dict[str, Any], last_wp_report: Optional[Dict[str, Any]]
    ) -> None:
        """Update new report considering last report:
        - Save already fixed issues but not reported yet
        - Fill out fixed issues and last_email datetime
        """
        if last_wp_report:
            # Save already fixed issues but not reported yet
            wp_report["fixed"] = last_wp_report["fixed"]

            # Fill out last_email datetime if any
            if last_wp_report["last_email"]:
                wp_report["last_email"] = last_wp_report["last_email"]

            # Fill out fixed issues if the scan is not an error
            if wp_report["status"] != "ERROR":
                fixed, unfixed = self.get_fixed_n_unfixed_issues(
                    wp_report, last_wp_report, issue_type="alerts"
                )
                wp_report["fixed"].extend(fixed)
                self.add_unfixed_warnings(
                    wp_report, last_wp_report, unfixed, issue_type="alerts"
                )

                fixed, unfixed = self.get_fixed_n_unfixed_issues(
                    wp_report, last_wp_report, issue_type="warnings"
                )
                wp_report["fixed"].extend(fixed)
                self.add_unfixed_warnings(
                    wp_report, last_wp_report, unfixed, issue_type="warnings"
                )

    def add_unfixed_warnings(
        self,
        wp_report: Dict[str, Any],
        last_wp_report: Dict[str, Any],
        unfixed_items: List[str],
        issue_type: str,
    ) -> None:
        """
        A line will be added at the end of the warning like:
        "Warning: This issue is unfixed since {date}"
        """

        for unfixed_item in unfixed_items:
            try:
                # Get unfixd issue
                issue_index = [
                    alert.splitlines()[0] for alert in wp_report[issue_type]
                ].index(unfixed_item.splitlines()[0])
            except ValueError as e:
                log.error(e)
            else:
                wp_report[issue_type][issue_index] += "\n"
                try:
                    # Try to get older issue if it exists
                    older_issue_index = [
                        alert.splitlines()[0] for alert in last_wp_report[issue_type]
                    ].index(unfixed_item.splitlines()[0])
                except ValueError as e:
                    log.error(e)
                else:
                    older_warn_last_line = last_wp_report[issue_type][
                        older_issue_index
                    ].splitlines()[-1]
                    if "Warning: This issue is unfixed" in older_warn_last_line:
                        wp_report[issue_type][issue_index] += older_warn_last_line
                    else:
                        wp_report[issue_type][
                            issue_index
                        ] += f"Warning: This issue is unfixed since {last_wp_report['datetime']}"

    def get_fixed_n_unfixed_issues(
        self, wp_report: Dict[str, Any], last_wp_report: Dict[str, Any], issue_type: str
    ) -> Tuple[List[str], List[str]]:
        """Return list of fixed issue texts to include in mails"""
        fixed_issues = []
        unfixed_issues = []
        for last_alert in last_wp_report[issue_type]:
            if not wp_report["wpscan_parser"].is_false_positive(last_alert):

                if last_alert.splitlines()[0] not in [
                    alert.splitlines()[0] for alert in wp_report[issue_type]
                ]:
                    fixed_issues.append(
                        f'Issue regarding component "{last_alert.splitlines()[0]}" has been fixed since the last scan.'
                    )
                else:
                    unfixed_issues.append(last_alert)

        return fixed_issues, unfixed_issues

    @staticmethod
    def _write_wpscan_output(wp_report: Dict[str, Any], fpwpout: BinaryIO) -> None:
        """Helper method to write output to file"""
        nocolor_output = re.sub(
            r"(\x1b|\[[0-9][0-9]?m)", "", wp_report["wpscan_output"]
        )
        try:
            fpwpout.write(nocolor_output.encode("utf-8"))
        except UnicodeEncodeError:
            fpwpout.write(nocolor_output.encode("latin1"))

    def write_wpscan_output(self, wp_report: Dict[str, Any]) -> Optional[str]:
        """Write WPScan output to configured place with `wpscan_output_folder` if configured"""
        # Subfolder
        folder = f"{wp_report['status'].lower()}/"
        # Write wpscan output
        if self.wpscan_output_folder:
            wpscan_results_file = os.path.join(
                self.wpscan_output_folder,
                folder,
                get_valid_filename(
                    f"WPScan_output_{wp_report['site']}_{wp_report['datetime']}.txt"
                ),
            )
            log.info(f"Saving WPScan output to file {wpscan_results_file}")
            with open(wpscan_results_file, "wb") as wpout:
                self._write_wpscan_output(wp_report, wpout)
                return wpout.name
        else:
            return None

    def skip_this_site(
        self, wp_report: Dict[str, Any], last_wp_report: Dict[str, Any]
    ) -> bool:
        """Return true if the daemon mode is enabled and scan already happend in the last configured `daemon_loop_wait`"""
        if (
            self.daemon
            and datetime.strptime(wp_report["datetime"], DATE_FORMAT)
            - datetime.strptime(last_wp_report["datetime"], DATE_FORMAT)
            < self.daemon_loop_sleep
        ):
            log.info(
                f"Daemon skipping site {wp_report['site']} because already scanned in the last {self.daemon_loop_sleep}"
            )
            self.scanned_sites.append(None)
            return True
        return False

    def log_report_results(self, wp_report: Dict[str, Any]) -> None:
        """Print WPScan findings"""
        for info in wp_report["infos"]:
            log.info(oneline(f"** WPScan INFO {wp_report['site']} ** {info}"))
        for fix in wp_report["fixed"]:
            log.info(oneline(f"** FIXED Issue {wp_report['site']} ** {fix}"))
        for warning in wp_report["warnings"]:
            log.warning(oneline(f"** WPScan WARNING {wp_report['site']} ** {warning}"))
        for alert in wp_report["alerts"]:
            log.critical(oneline(f"** WPScan ALERT {wp_report['site']} ** {alert}"))

    def fill_report_status(self, wp_report: Dict[str, Any]) -> None:
        """Fill Report status according to the number of items n alerts, watnings, infos, errors and fixed"""
        if len(wp_report["error"]) > 0:
            wp_report["status"] = "ERROR"
        elif len(wp_report["warnings"]) > 0 and len(wp_report["alerts"]) == 0:
            wp_report["status"] = "WARNING"
        elif len(wp_report["alerts"]) > 0:
            wp_report["status"] = "ALERT"
        else:
            wp_report["status"] = "INFO"

    def handle_wpscan_err_api_wait(
        self, wp_site: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], bool]:
        """
        Sleep 24 hours with asynchronous event.
        Ensure wpscan update next time wpscan() is called.
        Return a `tuple (wp_report or None , Bool error handled?)`
        If interrupting, return (None, True). True not to trigger errors.
        """
        log.info(
            f"API limit has been reached after {len(self.scanned_sites)} sites, sleeping {API_WAIT_SLEEP} and continuing the scans..."
        )
        self.wpscan.init_check_done = (
            False  # will re-trigger wpscan update next time wpscan() is called
        )
        self.api_wait.wait(API_WAIT_SLEEP.total_seconds())
        if self.interrupting:
            return (None, True)

        new_report = self.scan_site(wp_site)
        return (new_report, new_report != None)

    def handle_wpscan_err_follow_redirect(
        self, wp_site: Dict[str, Any], wp_report: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], bool]:
        """Parse URL in WPScan output and relaunch scan.
        Return a `tuple (wp_report or None , Bool error handled?)`
        """
        url = re.findall(
            r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
            wp_report["wpscan_output"].split("The URL supplied redirects to")[1],
        )

        if len(url) == 1:
            wp_site["url"] = url[0].strip()
            log.info(f"Following redirection to {wp_site['url']}")
            new_report = self.scan_site(wp_site)
            return (new_report, new_report != None)

        else:
            err_str = "Could not parse the URL to follow in WPScan output after words 'The URL supplied redirects to'"
            log.error(err_str)
            wp_report["error"] += err_str
            return (wp_report, False)

    def handle_wpscan_err(
        self, wp_site: Dict[str, Any], wp_report: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], bool]:
        """Handle API limit and Follow redirection errors based on output strings.
        Return a `tuple (wp_report or None , Bool error handled?)`
        """
        if (
            "API limit has been reached" in str(wp_report["wpscan_output"])
            and self.api_limit_wait
        ):
            return self.handle_wpscan_err_api_wait(wp_site)

        # Handle Following redirection
        elif (
            "The URL supplied redirects to" in str(wp_report["wpscan_output"])
            and self.follow_redirect
        ):
            return self.handle_wpscan_err_follow_redirect(wp_site, wp_report)

        else:
            return (wp_report, False)

    def _load_parser_results(
        self, parser: WPScanJsonParser, wp_report: Dict[str, Any]
    ) -> None:
        results = parser.get_results()
        # Save WPScan result dict
        (
            wp_report["infos"],
            wp_report["warnings"],
            wp_report["alerts"],
            wp_report["summary"],
        ) = (
            results["infos"],
            results["warnings"],
            results["alerts"],
            results["summary"],
        )
        # Including error if not None
        if results["error"]:
            if wp_report["error"]:
                wp_report["error"] += "\n\n"
            wp_report["error"] += results["error"]

    def _wpscan_site(
        self, wp_site: Dict[str, Any], wp_report: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Handled WPScan scanning , parsing, errors and reporting.
        Returns filled wp_report, None if interrupted or killed.
        Can raise `RuntimeError` if any errors.
        """

        # WPScan arguments
        wpscan_arguments = (
            self.wpscan_args + wp_site["wpscan_args"] + ["--url", wp_site["url"]]
        )

        # Output
        log.info(f"Scanning site {wp_site['url']}")

        # Launch WPScan
        wpscan_exit_code, wp_report["wpscan_output"], stderr = self.wpscan.wpscan(
            *wpscan_arguments
        )
        log.debug(f"WPScan raw output:\n{wp_report['wpscan_output']}")
        log.debug("Parsing WPScan output")

        try:
            # Use wpscan_out_parse module
            parser = WPScanJsonParser(
                json.loads(wp_report["wpscan_output"]),
                self.false_positive_strings
                + wp_site["false_positive_strings"]
                + ["No WPVulnDB API Token given"],
            )
            wp_report["wpscan_parser"] = parser
            self._load_parser_results(parser, wp_report)

        except Exception as err:
            raise RuntimeError(
                f"Could not parse WPScan output for site {wp_site['url']}"
            ) from err

        # Exit code 0: all ok. Exit code 5: Vulnerable. Other exit code are considered as errors
        if wpscan_exit_code in [0, 5]:
            return wp_report

        # Quick return if interrupting and/or if user cacelled scans
        if self.interrupting or wpscan_exit_code in [2, -2, -9]:
            return None

        # Other errors codes : 127, etc, simply raise error
        err_str = f"WPScan failed with exit code {wpscan_exit_code}. \nArguments: {safe_log_wpscan_args(wpscan_arguments)}. \nOutput: \n{remove_color(wp_report['wpscan_output'])}\nError: \n{stderr}"
        raise RuntimeError(err_str)

    def wpscan_site(
        self, wp_site: Dict[str, Any], wp_report: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Timeout wrapper arround `WPWatcherScanner._wpscan_site()`.
        Launch WPScan.
        Returns filled wp_report or None.
        Can raise `RuntimeError` if any errors.
        """
        try:
            wp_report_new = timeout(
                self.scan_timeout.total_seconds(),
                self._wpscan_site,
                args=(wp_site, wp_report),
            )
            if wp_report_new:
                wp_report.update(wp_report_new)
            else:
                return None
        except TimeoutError as err:
            # Kill process
            for p in self.wpscan.processes:
                if (wp_site["url"] in p.args) and not p.returncode:
                    log.info(
                        f"Killing WPScan process {safe_log_wpscan_args(str(a) for a in p.args)}"
                    )
                    p.kill()
            # Raise error
            err_str = f"Timeout scanning site {wp_site['url']} after {self.scan_timeout.total_seconds()} seconds. Setup scan_timeout in config file to allow more time. "
            raise RuntimeError(err_str) from err
        return wp_report

    def _fail_scan(self, wp_report: Dict[str, Any], err_str: str) -> None:
        """
        Common manipulations when a scan fail. This will not stop the scan
        process unless --fail_fast if enabled.
        """
        log.error(err_str)
        if wp_report["error"]:
            wp_report["error"] += "\n\n"
        wp_report["error"] += err_str
        wp_report["status"] = "ERROR"
        # Fail fast
        self.check_fail_fast()

    def scan_site(
        self, wp_site: Dict[str, Any], last_wp_report: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Orchestrate the scanning of a site.

        :Return: The scan report or `None` if something happened.
        """

        # Init report variables
        wp_report: WPWatcherReport = WPWatcherReport(
            {"site": wp_site["url"], "datetime": datetime.now().strftime(DATE_FORMAT)}
        )

        # Skip if the daemon mode is enabled and scan already happend in the last configured `daemon_loop_wait`
        if last_wp_report and self.skip_this_site(wp_report, last_wp_report):
            return None

        # Launch WPScan
        try:
            # If report is None, return None right away
            if not self.wpscan_site(wp_site, wp_report):
                return None

        except RuntimeError:

            # Try to handle error and return, will recall scan_site()
            wp_report_new, handled = self.handle_wpscan_err(wp_site, wp_report)

            if handled:
                return wp_report_new

            elif not self.interrupting:
                self._fail_scan(
                    wp_report,
                    f"Could not scan site {wp_site['url']} \n{traceback.format_exc()}",
                )

            else:
                return None

        self.fill_report_status(wp_report)

        # Updating report entry with data from last scan and append
        self.update_report(wp_report, last_wp_report)

        self.log_report_results(wp_report)

        wpscan_command = " ".join(
            safe_log_wpscan_args(
                ["wpscan"]
                + self.wpscan_args
                + wp_site["wpscan_args"]
                + ["--url", wp_site["url"]]
            )
        )

        # Print parsed readable Alerts, Warnings, etc as they will appear in email reports
        log.debug(
            f"{WPWatcherNotification.build_message(wp_report, wpscan_command=wpscan_command)}\n"
        )

        try:

            # Notify recepients if match triggers
            if self.mail.notify(
                wp_site, wp_report, last_wp_report, wpscan_command=wpscan_command
            ):
                # Store report time
                wp_report["last_email"] = wp_report["datetime"]
                # Discard fixed items because infos have been sent
                wp_report["fixed"] = []

        # Handle sendmail errors
        except (SMTPException, ConnectionRefusedError, TimeoutError):
            self._fail_scan(
                wp_report,
                f"Could not send mail report for site {wp_site['url']}\n{traceback.format_exc()}",
            )

        # Discard wpscan_output from report
        if "wpscan_output" in wp_report:
            del wp_report["wpscan_output"]

        # Discard wpscan_parser from report
        if "wpscan_parser" in wp_report:
            del wp_report["wpscan_parser"]

        # Send syslog if self.syslog is not None
        if self.syslog:
            try:
                self.syslog.emit_messages(wp_report)
            except Exception:
                self._fail_scan(
                    wp_report,
                    f"Could not send syslog messages for site {wp_site['url']}\n{traceback.format_exc()}",
                )

        # Save scanned site
        self.scanned_sites.append(wp_site["url"])

        return wp_report
