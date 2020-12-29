"""
Scanner utility. 
"""
from typing import Optional, BinaryIO, List, Tuple, Dict, Any, Union
import threading
import re
import os
import traceback
import json
from smtplib import SMTPException
from datetime import timedelta, datetime

from wpscan_out_parse import WPScanJsonParser, WPScanCliParser

from wpwatcher import log
from wpwatcher.__version__ import __version__
from wpwatcher.utils import (
    get_valid_filename,
    safe_log_wpscan_args,
    oneline,
    remove_color,
)
from wpwatcher.email import EmailSender
from wpwatcher.wpscan import WPScanWrapper
from wpwatcher.syslog import SyslogOutput
from wpwatcher.report import ScanReport
from wpwatcher.site import Site
from wpwatcher.config import Config


# Date format used everywhere
DATE_FORMAT = "%Y-%m-%dT%H-%M-%S"


class Scanner:
    """Scanner class create reports and handles the scan process. """

    def __init__(self, conf: Config):

        # Create (lazy) wpscan link
        self.wpscan = WPScanWrapper(
            wpscan_path=conf["wpscan_path"], 
            scan_timeout=conf["scan_timeout"],
            api_limit_wait=conf["api_limit_wait"],
            follow_redirect=conf["follow_redirect"], )

        # Init mail client
        self.mail: EmailSender = EmailSender(conf)
        
        # Toogle if aborting so other errors doesnt get triggerred and exit faster
        self.interrupting: bool = False
        # List of scanned URLs
        self.scanned_sites: List[Optional[str]] = []

        # Save required config options
        self.wpscan_output_folder: str = conf["wpscan_output_folder"]
        self.wpscan_args: List[str] = conf["wpscan_args"]
        self.fail_fast: bool = conf["fail_fast"]
        self.false_positive_strings: List[str] = conf["false_positive_strings"]

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

        self.syslog: Optional[SyslogOutput] = None
        if conf["syslog_server"]:
            self.syslog = SyslogOutput(conf)
        

    def interrupt(self) -> None:
        """
        Call `WPScanWrapper.interrupt`. 

        This do NOT raise SystemExit. 
        """
        self.interrupting = True
        self.wpscan.interrupt()

    # Scan process

    @staticmethod
    def _write_wpscan_output(wp_report: ScanReport, fpwpout: BinaryIO) -> None:
        """Helper method to write output to file"""
        nocolor_output = remove_color(wp_report["wpscan_output"])
        try:
            fpwpout.write(nocolor_output.encode("utf-8"))
        except UnicodeEncodeError:
            fpwpout.write(nocolor_output.encode("latin1", errors='replace'))

    def write_wpscan_output(self, wp_report: ScanReport) -> Optional[str]:
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

    
    def log_report_results(self, wp_report: ScanReport) -> None:
        """Print WPScan findings"""
        for info in wp_report["infos"]:
            log.info(oneline(f"** WPScan INFO {wp_report['site']} ** {info}"))
        for fix in wp_report["fixed"]:
            log.info(oneline(f"** FIXED Issue {wp_report['site']} ** {fix}"))
        for warning in wp_report["warnings"]:
            log.warning(oneline(f"** WPScan WARNING {wp_report['site']} ** {warning}"))
        for alert in wp_report["alerts"]:
            log.critical(oneline(f"** WPScan ALERT {wp_report['site']} ** {alert}"))

    def _scan_site(
        self, wp_site: Site, wp_report: ScanReport
    ) -> Optional[ScanReport]:
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
        wpscan_process = self.wpscan.wpscan(
            *wpscan_arguments
        )
        wp_report["wpscan_output"] = wpscan_process.stdout

        log.debug(f"WPScan raw output:\n{wp_report['wpscan_output']}")
        log.debug("Parsing WPScan output")

        try:
            # Use wpscan_out_parse module
            try:
                parser = WPScanJsonParser(
                    json.loads(wp_report["wpscan_output"]),
                    self.false_positive_strings
                    + wp_site["false_positive_strings"] 
                    + ["No WPVulnDB API Token given", "No WPScan API Token given"]
                )
            except ValueError as err:
                parser = WPScanCliParser(
                    wp_report["wpscan_output"],
                    self.false_positive_strings
                    + wp_site["false_positive_strings"]
                    + ["No WPVulnDB API Token given", "No WPScan API Token given"]
                )
            finally:
                wp_report.load_parser(parser)

        except Exception as err:
            raise RuntimeError(
                f"Could not parse WPScan output for site {wp_site['url']}\nOutput:\n{wp_report['wpscan_output']}"
            ) from err

        # Exit code 0: all ok. Exit code 5: Vulnerable. Other exit code are considered as errors
        if wpscan_process.returncode in [0, 5]:
            return wp_report

        # Quick return if interrupting and/or if user cancelled scans
        if self.interrupting or wpscan_process.returncode in [2, -2, -9]:
            return None

        # Other errors codes : 127, etc, simply raise error
        err_str = f"WPScan failed with exit code {wpscan_process.returncode}. \nArguments: {safe_log_wpscan_args(wpscan_arguments)}. \nOutput: \n{remove_color(wp_report['wpscan_output'])}\nError: \n{wpscan_process.stderr}"
        raise RuntimeError(err_str)


    def _fail_scan(self, wp_report: ScanReport, err_str: str) -> None:
        """
        Common manipulations when a scan fail. This will not stop the scans
        unless --fail_fast if enabled.

        Triger InterruptedError if fail_fast and not already interrupting.
        """
        
        wp_report.fail(err_str)
        if self.fail_fast and not self.interrupting:
            raise InterruptedError()

    def scan_site(
        self, wp_site: Site, last_wp_report: Optional[ScanReport] = None
    ) -> Optional[ScanReport]:
        """
        Orchestrate the scanning of a site.

        :Return: The scan report or `None` if something happened.
        """

        # Init report variables
        wp_report: ScanReport = ScanReport(
            {"site": wp_site["url"], "datetime": datetime.now().strftime(DATE_FORMAT)}
        )

        # Launch WPScan
        try:
            # If report is None, return None right away
            if not self._scan_site(wp_site, wp_report):
                return None

        except RuntimeError:

            self._fail_scan(
                wp_report,
                f"Could not scan site {wp_site['url']} \n{traceback.format_exc()}",
            )


        # Updating report entry with data from last scan
        wp_report.update_report(last_wp_report)

        self.log_report_results(wp_report)

        wpscan_command = " ".join(
            safe_log_wpscan_args(
                ["wpscan"]
                + self.wpscan_args
                + wp_site["wpscan_args"]
                + ["--url", wp_site["url"]]
            )
        )

        try:

            # Notify recepients if match triggers
            if self.mail.notify(
                wp_site, wp_report, 
                last_wp_report, wpscan_command=wpscan_command
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

        # Discard wpscan_output from report
        if "wpscan_output" in wp_report:
            del wp_report["wpscan_output"]

        # Discard wpscan_parser from report
        if "wpscan_parser" in wp_report:
            del wp_report["wpscan_parser"]


        return wp_report
