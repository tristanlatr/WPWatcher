"""
CEF Syslog output support. 
"""
from typing import Dict, Any, List
import socket
import logging
from wpwatcher import log
from wpwatcher.__version__ import __version__


class SyslogOutput:
    """
    Send CEF messages based on reports. 
    """
    def __init__(self, conf: Dict[str, Any]):
        # Keep syslog dependency optionnal by importing at init time
        from rfc5424logging import Rfc5424SysLogHandler

        sh: Rfc5424SysLogHandler = Rfc5424SysLogHandler(
            address=(conf["syslog_server"], conf["syslog_port"]),
            socktype=getattr(socket, conf["syslog_stream"]),  # Use TCP or UDP
            appname="WPWatcher",
            **conf["syslog_kwargs"],
        )
        self.syslog = logging.getLogger("wpwatcher-syslog")
        self.syslog.setLevel(logging.DEBUG)
        self.syslog.addHandler(sh)

    DEVICE_VENDOR = "Github"
    DEVICE_PRODUCT = "WPWatcher"
    DEVICE_VERSION = __version__

    # Dict of  # report_key: (signatureId, name, severiry)
    # This definition must not change!
    EVENTS = {
        "infos": ("100", "WPScan INFO", 4),
        "fixed": ("101", "WPScan issue FIXED", 4),
        "error": ("102", "WPScan ERROR", 6),
        "warnings": ("103", "WPScan WARNING", 6),
        "alerts": ("104", "WPScan ALERT", 9),
    }

    def emit_messages(self, wp_report: Dict[str, Any]) -> None:
        """
        Sends the CEF syslog messages for the report.
        """
        log.debug(f"Sending Syslog messages for site {wp_report['site']}")
        for m in self.get_messages(wp_report):
            self.syslog.info(m)

    def get_messages(self, wp_report: Dict[str, Any]) -> List[str]:
        """
        Return a list of CEF formatted messages
        """
        from cefevent import CEFEvent

        messages = []
        for v in self.EVENTS.keys():
            # make sure items is a list, cast error string to list
            items = wp_report[v] if isinstance(wp_report[v], list) else [wp_report[v]]
            for msg_data in items:
                if msg_data:
                    log.debug(f"Message data: {msg_data}")
                    c = CEFEvent()
                    # WPWatcher related fields
                    c.set_prefix("deviceVendor", self.DEVICE_VENDOR)
                    c.set_prefix("deviceProduct", self.DEVICE_PRODUCT)
                    c.set_prefix("deviceVersion", self.DEVICE_VERSION)
                    # Message common fields
                    c.set_prefix("signatureId", self.EVENTS[v][0])
                    c.set_prefix("name", self.EVENTS[v][1])
                    c.set_prefix("severity", self.EVENTS[v][2])
                    # Message supp infos
                    c.set_field("message", msg_data[:1022])
                    c.set_field("sourceHostName", wp_report["site"][:1022])
                    msg = c.build_cef()
                    log.debug(f"Message CEF: {msg}")
                    messages.append(msg)
        return messages

    def emit_test_messages(self) -> None:
        wp_report = {
            "site": "https://exemple.com",
            "error": "WPScan Failed ... (TESTING)",
            "infos": [
                "Plugin: wpdatatables\nThe version could not be determined (latest is 2.1.2) (TESTING)"
            ],
            "warnings": [
                "Outdated Wordpress version: 5.1.1\nRelease Date: 2019-03-13 (TESTING)"
            ],
            "alerts": [
                "Vulnerability: WooCommerce < 4.1.0 - Unescaped Metadata when Duplicating Products (TESTING)"
            ],
            "fixed": [
                "Issue regarding component 123 has been fixed since last report. (TESTING)"
            ],
        }
        self.emit_messages(wp_report)
