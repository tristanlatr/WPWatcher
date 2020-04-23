""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import copy
import os
import json
import threading
import time
import io
import shutil
import concurrent.futures
import traceback
import re
import subprocess
import signal
from urllib.parse import urlparse

from datetime import datetime, timedelta

from wpwatcher import log, init_log
from wpwatcher.config import WPWatcherConfig
from wpwatcher.db import WPWatcherDataBase
from wpwatcher.scan import WPWatcherScanner
from wpwatcher.utils import safe_log_wpscan_args, get_valid_filename, print_progress_bar, oneline, results_summary, timeout

# Send kill signal after X seconds when cancelling
INTERRUPT_TIMEOUT=10

# Date format used everywhere
DATE_FORMAT='%Y-%m-%dT%H-%M-%S'

# WPWatcher class ---------------------------------------------------------------------
class WPWatcher():

    # WPWatcher must use a configuration dict
    def __init__(self, conf):
        # (Re)init logger with config
        init_log(verbose=conf['verbose'],
            quiet=conf['quiet'],
            logfile=conf['log_file'])
        
        self.delete_tmp_wpscan_files()
        
        # Init DB interface
        self.wp_reports=WPWatcherDataBase(conf['wp_reports'])

        # Init scanner
        self.scanner=WPWatcherScanner(conf)
        
        # Save sites
        self.wp_sites=conf['wp_sites']

        # Dump config
        conf.update({'wp_reports':self.wp_reports.filepath})
        log.info("WPWatcher configuration:{}".format(self.dump_config(conf)))

        # Asynchronous executor
        self.executor=concurrent.futures.ThreadPoolExecutor(max_workers=conf['asynch_workers'])
        # List of conccurent futures
        self.futures=[] 
        
        # Register the signals to be caught ^C , SIGTERM (kill) , service restart , will trigger interrupt() 
        signal.signal(signal.SIGINT, self.interrupt)
        signal.signal(signal.SIGTERM, self.interrupt)
        
    @staticmethod
    def delete_tmp_wpscan_files():
        # Try delete temp files.
        if os.path.isdir('/tmp/wpscan'):
            try: 
                shutil.rmtree('/tmp/wpscan')
                log.info("Deleted temp WPScan files in /tmp/wpscan/")
            except (FileNotFoundError, OSError, Exception) : 
                log.info("Could not delete temp WPScan files in /tmp/wpscan/\n%s"%(traceback.format_exc()))
    
    @staticmethod
    def dump_config(conf):
        bump_conf=copy.deepcopy(conf)
        string=''
        for k in bump_conf:
            v=bump_conf[k]
            if k == 'wpscan_args':
                v=safe_log_wpscan_args(v)
            if k == 'smtp_pass' and bump_conf[k] != "" :
                v = '***'
            if isinstance(v, (list, dict)):
                v=json.dumps(v)
            else: v=str(v)
            string+=("\n{:<25}\t=\t{}".format(k,v))
        return(string)
    
    def wait_all_wpscan_process(self):
        while len(self.scanner.wpscan.processes)>0:
            time.sleep(0.05)

    def interrupt(self, sig=None, frame=None):
        # If called inside ThreadPoolExecutor, raise Exeception
        if not isinstance(threading.current_thread(), threading._MainThread):
            raise InterruptedError()

        log.error("Interrupting...")
        # Lock for interrupting
        self.interrupting=True
        # Cancel all jobs
        for f in self.futures:
            if not f.done(): f.cancel()
        # Send ^C to all WPScan not finished
        for p in self.scanner.wpscan.processes: p.send_signal(signal.SIGINT)
        # Wait for all processes to finish , kill after timeout
        try: 
            with timeout(INTERRUPT_TIMEOUT): self.wait_all_wpscan_process()
        except TimeoutError:
            log.error("Interrupt timeout reached, killing WPScan processes")
            for p in self.scanner.wpscan.processes: p.kill()

        # Unlock api wait
        self.scanner.api_wait.set()
        # Wait all scans finished, print results and quit
        self.wait_and_finish_interrupt()
    
    def wait_and_finish_interrupt(self):
        try: 
            with timeout(INTERRUPT_TIMEOUT): self.executor.shutdown(wait=True)
        except TimeoutError: pass
        self.print_scanned_sites_results()
        log.info("Scans interrupted.")
        exit(-1)

    def get_scanned_sites_reports(self):
        return [ e for e in [ self.wp_reports.find_last_wp_report({'site':s}) for s in self.scanner.scanned_sites ] if e ]

    def print_scanned_sites_results(self):
        new_reports=self.get_scanned_sites_reports()
        if len(new_reports)>0:
            log.info(results_summary(new_reports))
            log.info("Updated %s reports in database: %s"%(len(new_reports),self.wp_reports.filepath))
    
    @staticmethod
    def format_site(wp_site):
        if 'url' not in wp_site :
            log.error("Invalid site %s"%wp_site)
            wp_site={'url':''}
        else:
            # Format sites with scheme indication
            p_url=list(urlparse(wp_site['url']))
            if p_url[0]=="": 
                wp_site['url']='http://'+wp_site['url']
        # Read the wp_site dict and assing default values if needed
        optionals=['email_to','false_positive_strings','wpscan_args']
        for op in optionals:
            if op not in wp_site or wp_site[op] is None: wp_site[op]=[]
       
        return wp_site

    # Orchestrate the scanning of a site
    def scan_site(self, wp_site):
        wp_site=self.format_site(wp_site)
        last_wp_report=self.wp_reports.find_last_wp_report({'site':wp_site['url']})
        wp_report=self.scanner.scan_site(wp_site,  last_wp_report)
        # Save report in global instance database and to file when a site has been scanned
        if wp_report: self.wp_reports.update_and_write_wp_reports([wp_report])
        # Print progress
        print_progress_bar(len(self.scanner.scanned_sites), len(self.wp_sites)) 
        return(wp_report)

    # Run WPScan on defined websites
    def run_scans_and_notify(self):
        # Check sites are in the config
        if len(self.wp_sites)==0:
            log.error("No sites configured, please provide wp_sites in config file or use arguments --url URL [URL...] or --urls File path")
            return((-1, []))

        log.info("Starting scans on %s configured sites"%(len(self.wp_sites)))
        new_reports=[]
        # Sumbit all scans jobs and start scanning
        for s in self.wp_sites:
            # Find last site result if any
            self.futures.append(self.executor.submit(self.scan_site, s))
        # Loops while scans are running and read results
        for f in self.futures:
            try: new_reports.append(f.result())
            # Handle interruption from inside threads when using --ff
            except (InterruptedError):
                self.interrupt()
        # Print results and finish
        self.print_scanned_sites_results()
        if not any ([r['status']=='ERROR' for r in new_reports if r]):
            log.info("Scans finished successfully.")
            return((0, new_reports))
        else:
            log.info("Scans finished with errors.") 
            return((-1, new_reports))
