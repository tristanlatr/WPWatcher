"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import shlex
import subprocess
import json
import time
import threading
from datetime import datetime
from wpwatcher import log
from wpwatcher.utils import safe_log_wpscan_args, parse_timedelta

UPDATE_DB_INTERVAL = parse_timedelta("1h")
init_lock = threading.Lock()

# WPScan helper class -----------
class WPScanWrapper:
    def __init__(self, wpscan_executable):
        self.wpscan_executable = shlex.split(wpscan_executable)
        # List of current WPScan processes
        self.processes = []
        self.init_check_done = False

    def _lazy_init(self):
        # Check if WPScan exists
        wp_version = [ "--version", "--format", "json", "--no-banner" ]
        try:
            exit_code, version_info = self._wpscan(
                *wp_version )
        except FileNotFoundError as err:
            raise FileNotFoundError(
                "Could not find WPScan executale. "
                "Make sure wpscan in you PATH or configure full path to executable in config file. "
                "If you're using RVM, the path should point to the WPScan wrapper like '/usr/local/rvm/gems/ruby-2.6.0/wrappers/wpscan'"
            ) from err
        if exit_code != 0:
            raise RuntimeError(
                "There is an issue with WPScan. Non-zero exit code when requesting 'wpscan {}' \nOutput:\n{}".format(
                    " ".join(wp_version), 
                    version_info
                )
            )

        version_info = json.loads(version_info)
        if (
            not version_info["last_db_update"]
            or datetime.now()
            - datetime.strptime(
                version_info["last_db_update"].split(".")[0], "%Y-%m-%dT%H:%M:%S"
            )
            > UPDATE_DB_INTERVAL
        ):
            self.update_wpscan()

        self.init_check_done = True

    def update_wpscan(self):
        # Update wpscan database
        log.info("Updating WPScan")
        exit_code, out = self._wpscan("--update", "--format", "json", "--no-banner")
        if exit_code != 0:
            raise RuntimeError("Error updating WPScan.\nOutput:\n{}".format(out))

    # Wrapper for lazy initiation
    def wpscan(self, *args):
        if not self.init_check_done:
            while init_lock.locked():
                time.sleep(0.01)
            with init_lock:
                if not self.init_check_done:  # Re-check in case of concurrent scanning
                    self._lazy_init()
        return self._wpscan(*args)

    # Helper method: actually wraps wpscan
    def _wpscan(self, *args):
        # WPScan arguments
        cmd = self.wpscan_executable + list(args)
        # Log wpscan command without api token
        log.debug("Running WPScan command: %s" % " ".join(safe_log_wpscan_args(cmd)))
        # Run wpscan
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Append process to current process list and launch
        self.processes.append(process)
        wpscan_output, stderr = process.communicate()
        self.processes.remove(process)
        try:
            wpscan_output = wpscan_output.decode("utf-8")
        except UnicodeDecodeError:
            wpscan_output = wpscan_output.decode("latin1")
        return (process.returncode, wpscan_output)

