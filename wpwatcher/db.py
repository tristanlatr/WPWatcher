"""
Interface to JSON file storing scan results. 
"""

from typing import Iterable, List, Dict, Any, Optional
import os
import json
import time
import threading
from wpwatcher import log
from wpwatcher.config import Config
from wpwatcher.report import ScanReport, ReportCollection

from filelock import FileLock, Timeout

# Database default files
DEFAULT_REPORTS = ".wpwatcher/wp_reports.json"
DEFAULT_REPORTS_DAEMON = ".wpwatcher/wp_reports.daemon.json"

class DataBase:
    """
    Interface to JSON database file. 
    Write all reports in a thread safe way. 
    """

    def __repr__(self) -> str:
        return repr(self._data)

    def __init__(self, filepath: Optional[str] = None, daemon: bool = False):

        if not filepath:
            filepath = self._find_db_file(daemon=daemon)

        self.no_local_storage: bool = filepath == "null"
        "True if the DB is disabled"
        self.filepath = filepath

        self._data = ReportCollection()
        self._data.extend(self._build_db(self.filepath))

        # Writing into the database file is thread safe
        self._wp_report_lock: threading.Lock = threading.Lock()

        # Only once instance of WPWatcher can use a database file at a time. 
        self._wp_report_file_lock: FileLock = FileLock(f"{self.filepath}.lock")
        

    def open(self) -> None:
        """
        Acquire the file lock for the DB file. 
        """
        try:
            self._wp_report_file_lock.acquire(timeout=1)
        except Timeout as err:
            raise RuntimeError(f"Could not use the database file '{self.filepath}' because another instance of WPWatcher is using it. ") from err
        log.debug(f"Acquired DB lock file '{self.filepath}.lock'")
        try:
            self.write()
        except:
            log.error(
                f"Could not write wp_reports database: {self.filepath}. Use '--reports null' to ignore local Json database."
            )
            raise

    def close(self) -> None:
        """
        Release the file lock.
        """
        self._wp_report_file_lock.release()
        log.debug(f"Released DB lock file '{self.filepath}.lock'")

    @staticmethod
    def _find_db_file(daemon: bool = False) -> str:
        files = [DEFAULT_REPORTS] if not daemon else [DEFAULT_REPORTS_DAEMON]
        env = ["HOME", "PWD", "XDG_CONFIG_HOME", "APPDATA"]
        return Config.find_files(env, files, "[]", create=True)[0]

    # Read wp_reports database
    def _build_db(self, filepath: str) -> ReportCollection:
        """Load reports database and return the complete structure"""
        wp_reports = ReportCollection()
        if self.no_local_storage:
            return wp_reports

        if os.path.isfile(filepath):
            try:
                with open(filepath, "r") as reportsfile:
                    wp_reports.extend(
                        ScanReport(item) for item in json.load(reportsfile)
                    )
                log.info(f"Load wp_reports database: {filepath}")
            except Exception:
                log.error(
                    f"Could not read wp_reports database: {filepath}. Use '--reports null' to ignore local Json database"
                )
                raise
        else:
            log.info(f"The database file {filepath} do not exist. It will be created.")
        return wp_reports

    def write(
        self, wp_reports: Optional[Iterable[ScanReport]] = None
    ) -> bool:
        """
        Write the reports to the database. 

        Returns `True` if the reports have been successfully written. 
        """

        if not self._wp_report_file_lock.is_locked:
            raise RuntimeError("The file lock must be acquired before writing data. ")

        if not wp_reports:
            wp_reports = self._data

        for newr in wp_reports:
            new = True
            for r in self._data:
                if r["site"] == newr["site"]:
                    self._data[self._data.index(r)] = newr
                    new = False
                    break
            if new:
                self._data.append(newr)
        # Write to file if not null
        if not self.no_local_storage:
            # Write method thread safe
            while self._wp_report_lock.locked():
                time.sleep(0.01)
            self._wp_report_lock.acquire()
            with open(self.filepath, "w") as reportsfile:
                json.dump(self._data, reportsfile, indent=4)
                self._wp_report_lock.release()
            return True
        else:
            return False

    def find(self, wp_report: ScanReport) -> Optional[ScanReport]:
        """
        Find the pre-existing report if any.
        """
        last_wp_reports = [r for r in self._data if r["site"] == wp_report["site"]]
        last_wp_report: Optional[ScanReport]
        if len(last_wp_reports) > 0:
            last_wp_report = last_wp_reports[0]
        else:
            last_wp_report = None
        return last_wp_report
