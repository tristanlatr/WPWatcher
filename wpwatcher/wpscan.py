"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
from typing import List, Tuple
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
    def __init__(self, wpscan_executable:str) -> None:
        """
        :Param wpscan_executable: Path to WPScan executable. Exemple: '/usr/local/rvm/gems/default/wrappers/wpscan'
        """
        self.wpscan_executable:List[str] = shlex.split(wpscan_executable)
        # List of current WPScan processes
        self.processes:List[subprocess.Popen] = [] # type: ignore [type-arg]
        self.init_check_done:bool = False

    def _lazy_init(self) -> None:
        # Check if WPScan exists
        wp_version_args = [ "--version", "--format", "json", "--no-banner" ]
        try:
            exit_code, out, stderr = self._wpscan(
                *wp_version_args )
        except FileNotFoundError as err:
            raise FileNotFoundError(
                "Could not find WPScan executale. "
                "Make sure wpscan in you PATH or configure full path to executable in config file. "
                "If you're using RVM+bundler, the path should point to the WPScan wrapper like '/usr/local/rvm/gems/default/wrappers/wpscan'"
            ) from err
        else:
            if exit_code != 0:
                raise RuntimeError(
                    f"There is an issue with WPScan. Non-zero exit code when requesting 'wpscan {' '.join(wp_version_args)}' \nOutput:\n{out}\nError:\n{stderr}"
                )

        version_info = json.loads(out)
        if (
            not version_info["last_db_update"]
            or datetime.now()
            - datetime.strptime(
                version_info["last_db_update"].split(".")[0], "%Y-%m-%dT%H:%M:%S"
            )
            > UPDATE_DB_INTERVAL
        ):
            self._update_wpscan()

        self.init_check_done = True

    def _update_wpscan(self) -> None:
        # Update wpscan database
        log.info("Updating WPScan")
        exit_code, out, err = self._wpscan("--update", "--format", "json", "--no-banner")
        if exit_code != 0:
            raise RuntimeError(f"Error updating WPScan.\nOutput:{out}\nError:\n{err}")

    def wpscan(self, *args:str) -> Tuple[int, str, str]:
        """
        Run WPScan and return raw results. 
        :Param args: Sequence of arguments to pass to WPScan. 
        :Return: `Tuple[Exit code, Output, Stderr]`
        """
        if not self.init_check_done: # for lazy initiation
            while init_lock.locked():
                time.sleep(0.01)
            with init_lock:
                if not self.init_check_done:  # Re-check in case of concurrent scanning
                    self._lazy_init()
        return self._wpscan(*args)

    # Helper method: actually wraps wpscan
    def _wpscan(self, *args:str) -> Tuple[int, str, str]:
        # WPScan arguments
        cmd = self.wpscan_executable + list(args)
        # Log wpscan command without api token
        log.debug(f"Running WPScan command: {' '.join(safe_log_wpscan_args(cmd))}")
        # Run wpscan
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Append process to current process list and launch
        self.processes.append(process)
        wpscan_output, stderr = process.communicate()
        self.processes.remove(process)
        try:
            out_decoded = wpscan_output.decode("utf-8")
            err_decoded = stderr.decode("utf-8")
        except UnicodeDecodeError:
            out_decoded = wpscan_output.decode("latin1", errors='replace')
            err_decoded = stderr.decode("latin1", errors='replace')
        finally:
            return (process.returncode, out_decoded, err_decoded)
