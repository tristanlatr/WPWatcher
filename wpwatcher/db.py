""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import os
import json
import time
import threading
from wpwatcher import log
from wpwatcher.config import WPWatcherConfig

# Database default files
DEFAULT_REPORTS='.wpwatcher/wp_reports.json'
DEFAULT_REPORTS_DAEMON='.wpwatcher/wp_reports.daemon.json'
# Writing into the database file is thread safe
wp_report_lock = threading.Lock()

class WPWatcherDataBase():

    def __init__(self, wp_reports_filepath="", daemon=False):
        
        self.no_local_storage=wp_reports_filepath=='null'
        if not wp_reports_filepath : 
            wp_reports_filepath=self.find_wp_reports_file(create=True,daemon=daemon)
        self.filepath=wp_reports_filepath
        self._data=self.build_wp_reports(self.filepath)

        try: self.update_and_write_wp_reports(self._data)
        except:
            log.error("Could not write wp_reports database: {}. Use '--reports null' to ignore local Json database".format(self.filepath))
            raise

    def find_wp_reports_file(self, create=False, daemon=False):
        files=[DEFAULT_REPORTS] if not daemon else [DEFAULT_REPORTS_DAEMON]
        env=['HOME', 'PWD', 'XDG_CONFIG_HOME', 'APPDATA']
        return(WPWatcherConfig.find_files(env, files, "[]", create=True)[0])

    # Read wp_reports database
    def build_wp_reports(self, filepath):
        wp_reports=[]
        if self.no_local_storage: return wp_reports

        if os.path.isfile(filepath):
            try:
                with open(filepath, 'r') as reportsfile:
                    wp_reports=json.load(reportsfile)
                log.info("Load wp_reports database: %s"%filepath)
            except Exception:
                log.error("Could not read wp_reports database: {}. Use '--reports null' to ignore local Json database".format(filepath))
                raise
        else:
            log.info("The database file %s do not exist. It will be created."%(filepath))
        return wp_reports

    def update_and_write_wp_reports(self, new_wp_report_list=[]):
        # Update the sites that have been scanned, keep others
        # Keep same report order add append new sites at the bottom
        for newr in new_wp_report_list:
            new=True
            for r in self._data:
                if r['site']==newr['site']:
                    self._data[self._data.index(r)]=newr
                    new=False
                    break
            if new: 
                self._data.append(newr)
        # Write to file if not null
        if not self.no_local_storage :
            # Write method thread safe
            while wp_report_lock.locked():
                time.sleep(0.01)
            wp_report_lock.acquire()
            with open(self.filepath,'w') as reportsfile:
                json.dump(self._data, reportsfile, indent=4)
                wp_report_lock.release()

    def find_last_wp_report(self, wp_report):
        # Find last site result if any
        last_wp_report=[r for r in self._data if r['site']==wp_report['site']]
        if len(last_wp_report)>0: 
            last_wp_report=last_wp_report[0]
        else: last_wp_report=None
        return last_wp_report
