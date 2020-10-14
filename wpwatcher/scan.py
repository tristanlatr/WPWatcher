""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import threading
import re
import os
import time
import traceback
from smtplib import SMTPException
from datetime import timedelta, datetime
from wpwatcher import log
from wpwatcher.__version__ import __version__
from wpwatcher.utils import get_valid_filename, safe_log_wpscan_args, oneline, timeout
from wpscan_out_parse.parser import parse_results_from_string, WPScanJsonParser
from wpwatcher.notification import WPWatcherNotification
from wpwatcher.wpscan import WPScanWrapper
from wpwatcher.syslogout import WPSyslogOutput

# Wait when API limit reached
API_WAIT_SLEEP = timedelta(hours=24)

# Send kill signal after X seconds when cancelling
INTERRUPT_TIMEOUT = 5

# Date format used everywhere
DATE_FORMAT = "%Y-%m-%dT%H-%M-%S"


class WPWatcherScanner:
    """Scanner class create reports and handles the scan and notification process"""

    def __init__(self, conf):

        # Create (lazy) wpscan link
        self.wpscan = WPScanWrapper(conf["wpscan_path"])
        # Init mail client
        self.mail = WPWatcherNotification(conf)
        # Storing the Event object to wait for api limit to be reset and cancel the waiting enventually
        self.api_wait = threading.Event()
        # Toogle if aborting so other errors doesnt get triggerred and exit faster
        self.interrupting = False
        # List of scanned URLs
        self.scanned_sites = []

        # Save required config options
        self.api_limit_wait = conf["api_limit_wait"]
        self.follow_redirect = conf["follow_redirect"]
        self.wpscan_output_folder = conf["wpscan_output_folder"]
        self.wpscan_args = conf["wpscan_args"]
        self.fail_fast = conf["fail_fast"]
        self.false_positive_strings = conf["false_positive_strings"]
        self.daemon = conf["daemon"]
        self.daemon_loop_sleep = conf["daemon_loop_sleep"]

        # Scan timeout
        self.scan_timeout = conf["scan_timeout"]

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

        self.syslog = None
        if conf["syslog_server"]:
            self.syslog = WPSyslogOutput(conf)

    def check_fail_fast(self):
        """Fail fast, triger InterruptedError if fail_fast and not already interrupting."""
        if self.fail_fast and not self.interrupting:
            raise InterruptedError()
        return None  # Interrupt will generate other errors

    def cancel_scans(self):
        """
        Send ^C to all WPScan processes.
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

    def wait_all_wpscan_process(self):
        """Wait all WPScan processes. To be called with timeout() function"""
        while len(self.wpscan.processes) > 0:
            time.sleep(0.5)

    # Scan process

    def update_report(self, wp_report, last_wp_report, wp_site):
        """Update new report considering last report:
        - Save already fixed issues but not reported yet
        - Fill out fixed issues and last_email datetime
        """
        if last_wp_report:
            # Save already fixed issues but not reported yet
            wp_report["fixed"] = last_wp_report["fixed"]
            
            # Fill out fixed issues if the scan is not an error
            if wp_report['status'] != 'ERROR':

                wp_report["fixed"].extend(
                    self.get_fixed_issues(
                        wp_report, last_wp_report, wp_site, issue_type="alerts"
                    )
                )
                if self.mail.send_warnings:
                    wp_report["fixed"].extend(
                        self.get_fixed_issues(
                            wp_report, last_wp_report, wp_site, issue_type="warnings"
                        )
                    )

            # Fill out last_email datetime if any
            if last_wp_report["last_email"]:
                wp_report["last_email"] = last_wp_report["last_email"]

    @staticmethod
    def _write_wpscan_output(wp_report, fpwpout):
        """Helper method to write output to file"""
        nocolor_output = re.sub(
            r"(\x1b|\[[0-9][0-9]?m)", "", wp_report["wpscan_output"]
        )
        try:
            fpwpout.write(nocolor_output.encode("utf-8"))
        except UnicodeEncodeError:
            fpwpout.write(nocolor_output.encode("latin1"))

    def write_wpscan_output(self, wp_report):
        """Write WPScan output to configured place with `wpscan_output_folder` or return None"""
        # Subfolder
        folder = "%s/" % wp_report["status"].lower()
        # Write wpscan output
        wpscan_results_file = None
        if self.wpscan_output_folder:
            wpscan_results_file = os.path.join(
                self.wpscan_output_folder,
                folder,
                get_valid_filename(
                    "WPScan_output_%s_%s.txt"
                    % (wp_report["site"], wp_report["datetime"])
                ),
            )
            with open(wpscan_results_file, "wb") as wpout:
                self._write_wpscan_output(wp_report, wpout)
        return wpscan_results_file

    def get_fixed_issues(self, wp_report, last_wp_report, wp_site, issue_type="alerts"):
        """Return list of fixed issue texts to include in mails"""
        issues = []
        for last_alert in last_wp_report[issue_type]:
            if not WPScanJsonParser(
                None, self.false_positive_strings + wp_site["false_positive_strings"]
            ).is_false_positive(last_alert):
                if last_alert.splitlines()[0] not in [
                    a.splitlines()[0] for a in wp_report[issue_type]
                ]:
                    issues.append(
                        '%s regarding component "%s" has been fixed since last report.\nLast report datetime is: %s'
                        % (
                            "Alert" if issue_type == "alerts" else "Issue",
                            last_alert.splitlines()[0],
                            last_wp_report["last_email"],
                        )
                    )
        return issues

    def skip_this_site(self, wp_report, last_wp_report):
        """Return true if the daemon mode is enabled and scan already happend in the last configured `daemon_loop_wait`"""
        if (
            self.daemon
            and datetime.strptime(wp_report["datetime"], DATE_FORMAT)
            - datetime.strptime(last_wp_report["datetime"], DATE_FORMAT)
            < self.daemon_loop_sleep
        ):
            log.info(
                "Daemon skipping site %s because already scanned in the last %s"
                % (wp_report["site"], self.daemon_loop_sleep)
            )
            self.scanned_sites.append(None)
            return True
        return False

    def log_report_results(self, wp_report):
        """Print WPScan findings"""
        for info in wp_report["infos"]:
            log.info(oneline("** WPScan INFO %s ** %s" % (wp_report["site"], info)))
        for fix in wp_report["fixed"]:
            log.info(oneline("** FIXED Issue %s ** %s" % (wp_report["site"], fix)))
        for warning in wp_report["warnings"]:
            log.warning(
                oneline("** WPScan WARNING %s ** %s" % (wp_report["site"], warning))
            )
        for alert in wp_report["alerts"]:
            log.critical(
                oneline("** WPScan ALERT %s ** %s" % (wp_report["site"], alert))
            )

    def fill_report_status(self, wp_report):
        """Fill Report status according to the number of items n alerts, watnings, infos, errors and fixed"""
        if len(wp_report["error"]) > 0:
            wp_report["status"] = "ERROR"
        elif len(wp_report["warnings"]) > 0 and len(wp_report["alerts"]) == 0:
            wp_report["status"] = "WARNING"
        elif len(wp_report["alerts"]) > 0:
            wp_report["status"] = "ALERT"
        else:
            wp_report["status"] = "INFO"

    def handle_wpscan_err_api_wait(self, wp_site, wp_report):
        """
        Sleep 24 hours with asynchronous event.
        Ensure wpscan update next time wpscan() is called.
        Return a `tuple (wp_report or None , Bool error handled?)`
        If interrupting, return (None, True). True not to trigger errors.
        """
        log.info(
            "API limit has been reached after %s sites, sleeping %s and continuing the scans..."
            % (len(self.scanned_sites), API_WAIT_SLEEP)
        )
        self.wpscan.init_check_done = (
            False  # will re-trigger wpscan update next time wpscan() is called
        )
        self.api_wait.wait(API_WAIT_SLEEP.total_seconds())
        if self.interrupting:
            return (None, True)

        new_report = self.scan_site(wp_site)
        return (new_report, new_report != None)

    def handle_wpscan_err_follow_redirect(self, wp_site, wp_report):
        """Parse URL in WPScan output and relaunch scan.
        Return a `tuple (wp_report or None , Bool error handled?)`
        """
        url = re.findall(
            r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",
            wp_report["wpscan_output"].split("The URL supplied redirects to")[1],
        )

        if len(url) == 1:
            wp_site["url"] = url[0].strip()
            log.info("Following redirection to %s" % wp_site["url"])
            new_report = self.scan_site(wp_site)
            return (new_report, new_report != None)

        else:
            err_str = "Could not parse the URL to follow in WPScan output after words 'The URL supplied redirects to'"
            log.error(err_str)
            wp_report["error"] += err_str
            return (wp_report, False)

    def handle_wpscan_err(self, wp_site, wp_report):
        """Handle API limit and Follow redirection errors based on output strings.
        Return a `tuple (wp_report or None , Bool error handled?)`
        """
        if (
            "API limit has been reached" in str(wp_report["wpscan_output"])
            and self.api_limit_wait
        ):
            return self.handle_wpscan_err_api_wait(wp_site, wp_report)

        # Handle Following redirection
        elif (
            "The URL supplied redirects to" in str(wp_report["wpscan_output"])
            and self.follow_redirect
        ):
            return self.handle_wpscan_err_follow_redirect(wp_site, wp_report)

        else:
            return (wp_report, False)

    def _wpscan_site(self, wp_site, wp_report):
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
        log.info("Scanning site %s" % wp_site["url"])

        # Launch WPScan
        wpscan_exit_code, wp_report["wpscan_output"] = self.wpscan.wpscan(
            *wpscan_arguments
        )
        log.debug("WPScan raw output:\n" + wp_report["wpscan_output"])
        log.debug("Parsing WPScan output")

        try:
            # Call parse_results_from_string from wpscan_out_parse module
            results = parse_results_from_string(
                wp_report["wpscan_output"],
                self.false_positive_strings
                + wp_site["false_positive_strings"]
                + ["No WPVulnDB API Token given"],
            )
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
                wp_report["error"] = results["error"]

        except Exception as err:
            raise RuntimeError(
                "Could not parse WPScan output for site %s" % (wp_site["url"])
            ) from err

        # Exit code 0: all ok. Exit code 5: Vulnerable. Other exit code are considered as errors
        if wpscan_exit_code in [0, 5]:
            return wp_report

        # Quick return if interrupting and/or if user cacelled scans
        if self.interrupting or wpscan_exit_code in [2, -2, -9]:
            return None

        # Other errors codes : 127, etc, simply raise error
        err_str = "WPScan failed with exit code %s. \nArguments: %s. \nOutput: \n%s" % (
            wpscan_exit_code,
            safe_log_wpscan_args(wpscan_arguments),
            re.sub(r"(\x1b|\[[0-9][0-9]?m)", "", wp_report["wpscan_output"]),
        )
        raise RuntimeError(err_str)

    def wpscan_site(self, wp_site, wp_report):
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
                        "Killing WPScan process %s" % (safe_log_wpscan_args(p.args))
                    )
                    p.kill()
            # Raise error
            err_str = (
                "Timeout scanning site %s after %s seconds. Setup scan_timeout in config file to allow more time. "
                % (wp_site["url"], self.scan_timeout.total_seconds())
            )
            raise RuntimeError(err_str) from err
        return wp_report

    def scan_site(self, wp_site, last_wp_report=None):
        """
        Orchestrate the scanning of a site.
        Return the final wp_report or None if something happened.
        """

        # Init report variables
        wp_report = {
            "site": wp_site["url"],
            "status": None,
            "datetime": datetime.now().strftime(DATE_FORMAT),
            "last_email": None,
            "error": "",
            "infos": [],
            "warnings": [],
            "alerts": [],
            "fixed": [],
            "summary": None,
            "wpscan_output": "",  # will be deleted
        }

        # Skip if the daemon mode is enabled and scan already happend in the last configured `daemon_loop_wait`
        if last_wp_report and self.skip_this_site(wp_report, last_wp_report):
            return None

        # Launch WPScan
        try:
            # If report is None, return None right away
            if not self.wpscan_site(wp_site, wp_report):
                return None

        except RuntimeError as err:

            # Try to handle error and return, will recall scan_site()
            wp_report_new, handled = self.handle_wpscan_err(wp_site, wp_report)

            if handled:
                wp_report = wp_report_new
                return wp_report

            elif not self.interrupting:

                log.error(
                    "Could not scan site %s \n%s"
                    % (wp_site["url"], traceback.format_exc())
                )
                if wp_report["error"]:
                    wp_report["error"] += "\n\n"
                wp_report["error"] += str(err)

                # Fail fast
                self.check_fail_fast()

            else:
                return None

        self.fill_report_status(wp_report)

        self.log_report_results(wp_report)

        # Write wpscan output
        wpscan_results_file = self.write_wpscan_output(wp_report)
        if wpscan_results_file:
            log.info("WPScan output saved to file %s" % wpscan_results_file)

        # Updating report entry with data from last scan
        self.update_report(wp_report, last_wp_report, wp_site)

        wpscan_command=' '.join(safe_log_wpscan_args(['wpscan'] + 
            self.wpscan_args + wp_site["wpscan_args"] + ["--url", wp_site["url"]]))

        try:
            # Will print parsed readable Alerts, Warnings, etc as they will appear in email reports
            log.debug(
                "%s\n"
                % (
                    WPWatcherNotification.build_message(
                        wp_report,
                        wpscan_command=wpscan_command
                    )
                )
            )

            # Notify recepients if match triggers
            if self.mail.notify(wp_site, wp_report, last_wp_report,
                wpscan_command=wpscan_command
                ):
                # Store report time
                wp_report["last_email"] = wp_report["datetime"]
                # Discard fixed items because infos have been sent
                wp_report["fixed"] = []

        # Handle sendmail errors
        except (SMTPException, ConnectionRefusedError, TimeoutError):
            err_str = (
                "Unable to send mail report for site "
                + wp_site["url"]
                + "\n"
                + traceback.format_exc()
            )
            log.error(err_str)
            if wp_report["error"]:
                wp_report["error"] += "\n\n"
            wp_report["error"] += err_str
            wp_report["status"] = "ERROR"
            # Fail fast
            self.check_fail_fast()

        # Discard wpscan_output from report
        if "wpscan_output" in wp_report:
            del wp_report["wpscan_output"]

        # Send syslog if self.syslog is not None
        if self.syslog:
            try:
                self.syslog.emit_messages(wp_report)
            except Exception as err:
                err_str = (
                    "Unable to send syslog messages for site "
                    + wp_site["url"]
                    + "\n"
                    + traceback.format_exc()
                )
                log.error(err_str)
                if wp_report["error"]:
                    wp_report["error"] += "\n\n"
                wp_report["error"] += err_str
                wp_report["status"] = "ERROR"
                self.check_fail_fast()

        # Save scanned site
        self.scanned_sites.append(wp_site["url"])

        return wp_report
