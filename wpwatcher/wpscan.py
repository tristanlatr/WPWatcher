from typing import List, Tuple, Optional
import shlex
import subprocess
import json
import time
import threading
from datetime import datetime, timedelta
from wpwatcher import log
from wpwatcher.utils import safe_log_wpscan_args, parse_timedelta, timeout

UPDATE_DB_INTERVAL: timedelta = parse_timedelta("1h")
"1h"


INTERRUPT_TIMEOUT: int = 5
"Send kill signal after 5 seconds when interrupting."

# WPScan helper class -----------
class WPScanWrapper:
    """
    Process level wrapper for WPScan with a few additions: 

    - Auto-update the WPSCan database on interval 
    - Supports multi-threading (update is done with a lock)
    - Use a timeout for the scans, kills the process and raise error if reached
    """


    _NO_VAL = datetime(year=2000, month=1, day=1)
    def __init__(self, wpscan_executable: str, scan_timeout: Optional[timedelta] = None) -> None:
        """
        :param wpscan_executable: Path to WPScan executable. 
                                  Exemple: ``'/usr/local/rvm/gems/default/wrappers/wpscan'``
        :param scan_timeout: Timeout
        """
        self.processes: List[subprocess.Popen[bytes]] = []
        "List of running WPScan processes"

        self._wpscan_executable: List[str] = shlex.split(wpscan_executable)
        self._scan_timeout: Optional[timedelta] = scan_timeout

        self._update_lock: threading.Lock = threading.Lock()
        self._lazy_last_db_update: Optional[datetime] = self._NO_VAL


    def wpscan(self, *args: str) -> subprocess.CompletedProcess: # type: ignore [type-arg]
        """
        Run WPScan and return process results. Automatically update WPScan database. 
        
        :param args: Sequence of arguments to pass to WPScan. 
                     Exemple: ``"--update", "--format", "json", "--no-banner"``
        
        :returns: `subprocess.CompletedProcess`
        """
        if self._needs_update():  # for lazy update
            while self._update_lock.locked():
                time.sleep(0.01)
            with self._update_lock:
                if self._needs_update():  # Re-check in case of concurrent scanning
                    self._update_wpscan()
        return self._wpscan(*args)


    def interrupt(self) -> None:
        "Send SIGTERM to all currently running WPScan processes."
        for p in self.processes:
            p.terminate()
        # Wait for all processes to finish , kill after timeout
        try:
            timeout(INTERRUPT_TIMEOUT, self._wait_all_wpscan_process)
        except TimeoutError:
            for p in self.processes:
                p.kill()
    
    def _wait_all_wpscan_process(self) -> None:
        """
        Wait all WPScan processes. 
        Should be called with timeout() function
        """
        while len(self.processes) > 0:
            time.sleep(0.5)


    @property
    def _last_db_update(self) -> Optional[datetime]: 
        if self._lazy_last_db_update == self._NO_VAL:
            self._lazy_last_db_update = self._get_last_db_update()
        return self._lazy_last_db_update


    def _get_last_db_update(self) -> Optional[datetime]:

        wp_version_args = ["--version", "--format", "json", "--no-banner"]
        try:
            process = self._wpscan(*wp_version_args)
        except FileNotFoundError as err:
            raise FileNotFoundError(
                "Could not find WPScan executale. "
                "Make sure wpscan in you PATH or configure full path to executable in config file. "
                "If you're using RVM+bundler, the path should point to the WPScan wrapper like '/usr/local/rvm/gems/default/wrappers/wpscan'"
            ) from err
        else:
            if process.returncode != 0:
                raise RuntimeError(
                    f"There is an issue with WPScan. Non-zero exit code when requesting 'wpscan {' '.join(wp_version_args)}' \nOutput:\n{process.stdout}\nError:\n{process.stderr}"
                )

        version_info = json.loads(process.stdout)

        if not version_info.get("last_db_update", None):
            return None
        else:
            return datetime.strptime(
                version_info["last_db_update"].split(".")[0], "%Y-%m-%dT%H:%M:%S"
            )

    def _update_wpscan(self) -> None:
        # Update wpscan database
        log.info("Updating WPScan")
        process = self._wpscan(
            "--update", "--format", "json", "--no-banner"
        )
        if process.returncode != 0:
            raise RuntimeError(f"Error updating WPScan.\nOutput:{process.stdout}\nError:\n{process.stderr}")
        self._lazy_last_db_update = datetime.now()
    

    def _needs_update(self) -> bool:
        return (
            self._last_db_update == None or 
            ( datetime.now() # type: ignore [operator]
            - self._last_db_update
            > UPDATE_DB_INTERVAL )
        )


    # Helper method: actually wraps wpscan
    def _wpscan(self, *args: str) -> subprocess.CompletedProcess: # type: ignore [type-arg]
        # WPScan arguments
        cmd = self._wpscan_executable + list(args)
        # Log wpscan command without api token
        log.debug(f"Running WPScan command: {' '.join(safe_log_wpscan_args(cmd))}")
        # Run wpscan
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Append process to current process list and launch
        self.processes.append(process)

        if self._scan_timeout:
            try:
                stdout, stderr = timeout(self._scan_timeout.total_seconds(),
                    process.communicate)
            except TimeoutError as err:
                process.kill()
                # Raise error
                err_str = f"WPScan process '{safe_log_wpscan_args(cmd)}' timed out after {self._scan_timeout.total_seconds()} seconds. Setup 'scan_timeout' to allow more time. "
                raise RuntimeError(err_str) from err
        else:
            stdout, stderr = process.communicate()

        self.processes.remove(process)
        try:
            out_decoded = stdout.decode("utf-8")
            err_decoded = stderr.decode("utf-8")
        except UnicodeDecodeError:
            out_decoded = stdout.decode("latin1", errors="replace")
            err_decoded = stderr.decode("latin1", errors="replace")
        finally:
            return subprocess.CompletedProcess(
                args = safe_log_wpscan_args(cmd),
                returncode = process.returncode, 
                stdout = out_decoded, 
                stderr = err_decoded)
