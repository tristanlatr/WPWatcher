"""
Interface to JSON file storing scan results. 
"""
from typing import List, Dict, Any, Optional
import os
import json
import time
import threading
from wpwatcher import log
from wpwatcher.config import WPWatcherConfig

# Database default files
DEFAULT_REPORTS = ".wpwatcher/wp_reports.json"
DEFAULT_REPORTS_DAEMON = ".wpwatcher/wp_reports.daemon.json"
# Writing into the database file is thread safe
wp_report_lock = threading.Lock()


class WPWatcherDataBase:
    """Interface to JSON database file. Work to write all reports to file in a thread safe way"""

    def __init__(self, wp_reports_filepath: Optional[str] = None, daemon: bool = False):

        self.no_local_storage: bool = wp_reports_filepath == "null"
        if not wp_reports_filepath:
            wp_reports_filepath = self.find_wp_reports_file(daemon=daemon)
        self.filepath = wp_reports_filepath
        self._data = self.build_wp_reports(self.filepath)

        try:
            self.update_and_write_wp_reports(self._data)
        except:
            log.error(
                f"Could not write wp_reports database: {self.filepath}. Use '--reports null' to ignore local Json database"
            )
            raise

    @staticmethod
    def find_wp_reports_file(daemon: bool = False) -> str:
        files = [DEFAULT_REPORTS] if not daemon else [DEFAULT_REPORTS_DAEMON]
        env = ["HOME", "PWD", "XDG_CONFIG_HOME", "APPDATA"]
        return WPWatcherConfig.find_files(env, files, "[]", create=True)[0]

    # Read wp_reports database
    def build_wp_reports(self, filepath: str) -> List[Dict[str, Any]]:
        """Load reports database and return the complete structure"""
        wp_reports: List[Dict[str, Any]] = []
        if self.no_local_storage:
            return wp_reports

        if os.path.isfile(filepath):
            try:
                with open(filepath, "r") as reportsfile:
                    wp_reports.extend(json.load(reportsfile))
                log.info(f"Load wp_reports database: {filepath}")
            except Exception:
                log.error(
                    f"Could not read wp_reports database: {filepath}. Use '--reports null' to ignore local Json database"
                )
                raise
        else:
            log.info(f"The database file {filepath} do not exist. It will be created.")
        return wp_reports

    def update_and_write_wp_reports(
        self, new_wp_report_list: List[Dict[str, Any]]
    ) -> None:
        """Update the sites that have been scanned based on the report list.
        Keep same report order add append new sites at the bottom.
        Return None if wp_reports is null"""
        if not new_wp_report_list:
            return

        for newr in [dict(r) for r in new_wp_report_list]:
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
            while wp_report_lock.locked():
                time.sleep(0.01)
            wp_report_lock.acquire()
            with open(self.filepath, "w") as reportsfile:
                json.dump(self._data, reportsfile, indent=4)
                wp_report_lock.release()

    def find_last_wp_report(
        self, wp_report: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Find last site result if any.
        Return last_wp_report or None"""
        last_wp_reports = [r for r in self._data if r["site"] == wp_report["site"]]
        last_wp_report: Optional[Dict[str, Any]]
        if len(last_wp_reports) > 0:
            last_wp_report = last_wp_reports[0]
        else:
            last_wp_report = None
        return last_wp_report
