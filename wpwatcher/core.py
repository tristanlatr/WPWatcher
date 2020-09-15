""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import copy
import os
import json
import threading
import shutil
import concurrent.futures
import traceback
import signal
import sys
from urllib.parse import urlparse

from wpwatcher import log, init_log
from wpwatcher.db import WPWatcherDataBase
from wpwatcher.scan import WPWatcherScanner
from wpwatcher.utils import safe_log_wpscan_args, print_progress_bar, timeout

# Date format used everywhere
DATE_FORMAT='%Y-%m-%dT%H-%M-%S'

# WPWatcher class ---------------------------------------------------------------------
class WPWatcher():
    '''WPWacther object  

    Arguments:
    - `conf`: the configuration dict. Required

    Usage exemple:

        from wpwatcher.config import WPWatcherConfig
        from wpwatcher.core import WPWatcher
        config, files = WPWatcherConfig().build_config()
        config.update({ 'send_infos':   True,
                        'wp_sites':     [   {'url':'exemple1.com'},
                                            {'url':'exemple2.com'}  ],
                        'wpscan_args': ['--format', 'json', '--stealthy']
                    })
        w=WPWatcher(config)
        exit_code, reports = w.run_scans_and_notify()
        for r in reports:
            print("%s\t\t%s"%( r['site'], r['status'] ))
    '''
    # WPWatcher must use a configuration dict
    def __init__(self, conf):
        # (Re)init logger with config
        init_log(verbose=conf['verbose'],
            quiet=conf['quiet'],
            logfile=conf['log_file'])
        
        self.delete_tmp_wpscan_files()
        
        # Init DB interface
        self.wp_reports=WPWatcherDataBase(conf['wp_reports'])

        # Update config before passing it to WPWatcherScanner
        conf.update({'wp_reports':self.wp_reports.filepath})

        # Init scanner
        self.scanner=WPWatcherScanner(conf)

        # Dump config
        log.debug("WPWatcher configuration:{}".format(self.dump_config(conf)))

        # Save sites
        self.wp_sites=conf['wp_sites']

        # Asynchronous executor
        self.executor=concurrent.futures.ThreadPoolExecutor(max_workers=conf['asynch_workers'])
        
        # List of conccurent futures
        self.futures=[] 
        
        # Register the signals to be caught ^C , SIGTERM (kill) , service restart , will trigger interrupt() 
        signal.signal(signal.SIGINT, self.interrupt)
        signal.signal(signal.SIGTERM, self.interrupt)

        #new reports
        self.new_reports=[]

    @staticmethod
    def delete_tmp_wpscan_files():
        '''Delete temp wpcan files'''
        # Try delete temp files.
        if os.path.isdir('/tmp/wpscan'):
            try: 
                shutil.rmtree('/tmp/wpscan')
                log.info("Deleted temp WPScan files in /tmp/wpscan/")
            except (FileNotFoundError, OSError, Exception) : 
                log.info("Could not delete temp WPScan files in /tmp/wpscan/\n%s"%(traceback.format_exc()))
    
    @staticmethod
    def dump_config(conf):
        '''Print the config without passwords'''
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

    def cancel_pending_futures(self):
        '''Cancel all asynchronous jobs'''
        for f in self.futures:
            if not f.done(): 
                f.cancel()
        
    def interrupt(self, sig=None, frame=None):
        '''Interrupt sequence'''
        log.error("Interrupting...")
        # If called inside ThreadPoolExecutor, raise Exeception
        if not isinstance(threading.current_thread(), threading._MainThread): 
            raise InterruptedError()
        # Cancel all scans
        self.cancel_pending_futures() # future scans
        # Wait all scans finished
        self.scanner.cancel_scans() # running scans
        
        # Give a 5 seconds timeout to buggy WPScan jobs to finish or ignore them
        try: timeout(5, self.executor.shutdown, kwargs=dict(wait=True))
        except TimeoutError : pass

        # Recover reports from futures results
        new_reports=[]
        for f in self.futures:
             if f.done():
                try: new_reports.append(f.result())
                except Exception: pass

        # Display results and quit
        self.print_scanned_sites_results(new_reports)
        log.info("Scans interrupted.")
        sys.exit(-1)

    def print_scanned_sites_results(self, new_reports):
        '''Print the result summary for the scanned sites'''
        new_reports = [n for n in new_reports if n]
        if len(new_reports)>0:
            log.info(self.results_summary(new_reports))
            if self.wp_reports.filepath != "null":
                log.info("Updated %s reports in database: %s"%(len(new_reports), self.wp_reports.filepath))
            else: 
                log.info("No reports updated in local database")
    
    @staticmethod
    def results_summary(results):
        '''Print the summary table of all sites.  
        Columns : "Site", "Status", "Last scan", "Last email", "Issues", "Problematic component(s)"
        '''
        string='Results summary\n'
        header = ("Site", "Status", "Last scan", "Last email", "Issues", "Problematic component(s)")
        sites_w=20
        # Determine the longest width for site column
        for r in results:
            sites_w=len(r['site'])+4 if r and len(r['site'])>sites_w else sites_w
        frow="{:<%d} {:<8} {:<20} {:<20} {:<8} {}"%sites_w
        string+=frow.format(*header)
        for row in results:
            pb_components=[]
            for m in row['alerts']+row['warnings']:
                pb_components.append(m.splitlines()[0])
            if row['error']:
                pb_components.append("Scan failed")
            string+='\n'
            string+=frow.format(str(row['site']), 
                str(row['status']),
                str(row['datetime']),
                str(row['last_email']),
                len(row['alerts']+row['warnings']),
                ', '.join(pb_components) )
        return string

    @staticmethod
    def format_site(wp_site):
        '''Make sure the site structure is correct, parse 'url', init optionals 'email_to','false_positive_strings','wpscan_args' to empty list if not present.
        Raise ValueError if url key is not present'''
        if 'url' not in wp_site :
            raise ValueError("Invalid site %s\nMust contain 'url' key"%wp_site)
        else:
            # Strip URL string
            wp_site['url']=wp_site['url'].strip()
            # Format sites with scheme indication
            p_url=list(urlparse(wp_site['url']))
            if p_url[0]=="": 
                wp_site['url']='http://'+wp_site['url']
        # Read the wp_site dict and assing default values if needed
        optionals=['email_to','false_positive_strings','wpscan_args']
        for op in optionals:
            if op not in wp_site or wp_site[op] is None: wp_site[op]=[]
       
        return wp_site

    def scan_site_wrapper(self, wp_site):
        """Helper method to wrap the raw scanning process that offer WPWatcherScanner.scan_site() and add the following:  
        - Handle site structure formatting  
        - Find the last report in the database and launch the scan
        - Write it in DB after scan.   
        - Print progress bar  
        This function will be called asynchronously.  
        Return one report"""
        
        wp_site=self.format_site(wp_site)
        last_wp_report=self.wp_reports.find_last_wp_report({'site':wp_site['url']})

        # Launch scanner
        wp_report= self.scanner.scan_site(wp_site,  last_wp_report)
        # Save report in global instance database and to file when a site has been scanned
        if wp_report: 
            self.wp_reports.update_and_write_wp_reports([wp_report])
        else: 
            log.info("No report saved for site %s"%wp_site['url'])
        # Print progress
        print_progress_bar(len(self.scanner.scanned_sites), len(self.wp_sites))     
        return(wp_report)

    def run_scans_wrapper(self, wp_sites):
        """Helper method to deal with : 
        - executor, concurent futures
        - Trigger self.interrupt() on InterruptedError (raised if fail fast enabled)
        
        Pass `kwargs` arguments to scan_site_wrapper() """

        log.info("Starting scans on %s configured sites"%(len(wp_sites)))
        for wp_site in wp_sites:
            self.futures.append(self.executor.submit(self.scan_site_wrapper, wp_site))
        for f in self.futures:
            try: 
                self.new_reports.append(f.result())
            # Handle interruption from inside threads when using --ff
            except InterruptedError:
                self.interrupt()
            except concurrent.futures.CancelledError: pass
        # Ensure everything is down
        self.cancel_pending_futures()
        return self.new_reports

    def run_scans_and_notify(self):
        """
        Run WPScan on defined websites and send notifications.  
        Returns a `tuple (exit code, reports)`"""
        
        # Check sites are in the config
        if len(self.wp_sites)==0:
            log.error("No sites configured, please provide wp_sites in config file or use arguments --url URL [URL...] or --urls File path")
            return((-1, []))

        new_reports=self.run_scans_wrapper(self.wp_sites)
        # Print results and finish
        self.print_scanned_sites_results(new_reports)

        if not any ([r['status']=='ERROR' for r in new_reports if r]):
            log.info("Scans finished successfully.")
            return((0, new_reports))
        else:
            log.info("Scans finished with errors.") 
            return((-1, new_reports))
        

        