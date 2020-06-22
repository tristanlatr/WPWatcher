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
import shutil
import concurrent.futures
import traceback
import signal
from urllib.parse import urlparse

from wpwatcher import log, init_log
from wpwatcher.config import WPWatcherConfig
from wpwatcher.db import WPWatcherDataBase
from wpwatcher.scan import WPWatcherScanner
from wpwatcher.utils import safe_log_wpscan_args, print_progress_bar, results_summary, timeout

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

        # Dump config
        conf.update({'wp_reports':self.wp_reports.filepath})
        log.debug("WPWatcher configuration:{}".format(self.dump_config(conf)))

        # Init scanner
        self.scanner=WPWatcherScanner(conf)

        # Save sites
        self.wp_sites=conf['wp_sites']

        # Asynchronous executor
        self.executor=concurrent.futures.ThreadPoolExecutor(max_workers=conf['asynch_workers'])
        # List of conccurent futures
        self.futures=[] 
        
        # Register the signals to be caught ^C , SIGTERM (kill) , service restart , will trigger interrupt() 
        signal.signal(signal.SIGINT, self.interrupt)
        signal.signal(signal.SIGTERM, self.interrupt)

        # Scan timeout
        self.scan_timeout=conf['scan_timeout']

        #new reports
        self.new_reports=[]

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
        
        dump_conf=copy.deepcopy(conf)
        string=''
        for k in dump_conf:
            v=dump_conf[k]
            if k == 'wpscan_args':
                v=safe_log_wpscan_args(v)
            if k == 'smtp_pass' and v != "" :
                v = '***'
            if isinstance(v, (list, dict)):
                v=json.dumps(v)
            else: v=str(v)
            string+=("\n{:<25}\t=\t{}".format(k,v))
        return(string)
    
    # def wait_all_wpscan_process(self):
        
    #     while len(self.scanner.wpscan.processes)>0:
    #         time.sleep(0.05)

    def tear_down_jobs(self):
        # Cancel all jobs
        for f in self.futures:
            if not f.done(): f.cancel()
        
    
    def interrupt(self, sig=None, frame=None):
        # Lock for interrupting
        log.error("Interrupting...")
        # If called inside ThreadPoolExecutor, raise Exeception
        if not isinstance(threading.current_thread(), threading._MainThread): raise InterruptedError()
        # Cancel all scans
        self.scanner.cancel_scans()
        # Wait all scans finished, print results and quit
        self.tear_down_jobs()
        # Give a 5 seconds timeout to buggy WPScan jobs to finish or ignore them
        try: timeout(5, self.executor.shutdown, kwargs=dict(wait=True))
        except TimeoutError : pass
        new_reports=[]
        for f in self.futures:
             if f.done():
                try: new_reports.append(f.result())
                except Exception: pass
        self.print_scanned_sites_results(new_reports)
        log.info("Scans interrupted.")
        exit(-1)

    def print_scanned_sites_results(self, new_reports):
        new_reports = [n for n in new_reports if n]
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
    def scan_site_wrapper(self, wp_site, with_api_token=False):
        
        wp_site=self.format_site(wp_site)
        last_wp_report=self.wp_reports.find_last_wp_report({'site':wp_site['url']})
        if with_api_token: wp_site['wpscan_args'].extend([ "--api-token", self.scanner.api_token ])

        # Launch scanner
        wp_report= self.scanner.scan_site(wp_site,  last_wp_report, timeout_seconds=self.scan_timeout.total_seconds())
        # Save report in global instance database and to file when a site has been scanned
        if wp_report: self.wp_reports.update_and_write_wp_reports([wp_report])
        else: log.info("No report saved for site %s"%wp_site['url'])
        # Print progress
        print_progress_bar(len(self.scanner.scanned_sites), len(self.wp_sites))     
        return(wp_report)

    def run_scans_wrapper(self, wp_sites, **kwargs):
        log.info("Starting scans on %s configured sites"%(len(wp_sites)))
        for wp_site in wp_sites:
            self.futures.append(self.executor.submit(self.scan_site_wrapper, wp_site, **kwargs))
        for f in self.futures:
            try: self.new_reports.append(f.result())
            # Handle interruption from inside threads when using --ff
            except InterruptedError:
                self.interrupt()
            except concurrent.futures.CancelledError: pass
        # Ensure everything is down
        self.tear_down_jobs()
        return self.new_reports

    # Run WPScan on defined websites
    def run_scans_and_notify(self):
        
        # Check sites are in the config
        if len(self.wp_sites)==0:
            log.error("No sites configured, please provide wp_sites in config file or use arguments --url URL [URL...] or --urls File path")
            return((-1, []))

        new_reports=self.run_scans_wrapper(self.wp_sites)
        # Print results and finish
        self.print_scanned_sites_results(new_reports)

        # Second scans if needed
        if len(self.scanner.prescanned_sites_warn)>0:
            new_reports+=self.re_run_scans(self.scanner.prescanned_sites_warn)
            self.print_scanned_sites_results(new_reports)

        if not any ([r['status']=='ERROR' for r in new_reports if r]):
            log.info("Scans finished successfully.")
            return((0, new_reports))
        else:
            log.info("Scans finished with errors.") 
            return((-1, new_reports))

    def re_run_scans(self, wp_sites):
        self.scanner.scanned_sites=[]
        self.futures=[]
        self.wp_sites=wp_sites
        return self.run_scans_wrapper(wp_sites, with_api_token=True)
        