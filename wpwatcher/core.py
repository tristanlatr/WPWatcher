""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import copy
import shutil
import traceback
import os
import json
import threading
import time
import io
import concurrent.futures
import unicodedata
import smtplib
import re
import subprocess
import signal
from urllib.parse import urljoin, urlparse, urlunparse
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta

from wpwatcher import log
from wpwatcher.parser import parse_results
from wpwatcher.scan import WPScanWrapper
from wpwatcher.utils import init_log, safe_log_wpscan_args, build_message, get_valid_filename, print_progress_bar, oneline, results_summary

# Will send sigterm after 2s , then kill signal after 2 seconds when cancelling
INTERRUPT_SLEEP=2
# Wait when API limit reached
API_WAIT_SLEEP=timedelta(hours=24)
# Writing into the database file is thread safe
wp_report_lock = threading.Lock()

# WPWatcher class ---------------------------------------------------------------------
class WPWatcher():

    # WPWatcher must use a configuration dict
    def __init__(self, conf):
        # Copy config dict as is. Copy not to edit initial dict
        self.conf=copy.deepcopy(conf)
        # (Re)init logger with config
        init_log(verbose=self.conf['verbose'],
            quiet=self.conf['quiet'],
            logfile=self.conf['log_file'])
        # Dump config
        log.info("WordPress sites and configuration:{}".format(self.dump_config()))
        # Create wpscan link
        self.wpscan=WPScanWrapper(path=self.conf['wpscan_path'])
        # Check if WPScan exists
        if not self.wpscan.is_wpscan_installed():
            log.error("There is an issue with your WPScan installation or WPScan not installed. Make sure wpscan in you PATH or configure full path to executable in config files. If you're using RVM, the path should point to the WPScan wapper like /usr/local/rvm/gems/ruby-2.6.0/wrappers/wpscan . Fix wpscan on your system. See https://wpscan.org for installation steps.")
            exit(-1)
        # Update wpscan database
        self.wpscan.update_wpscan()
        # Try delete temp files.
        if os.path.isdir('/tmp/wpscan'):
            try: 
                shutil.rmtree('/tmp/wpscan')
                log.info("Deleted temp WPScan files in /tmp/wpscan/")
            except (FileNotFoundError, OSError, Exception) : 
                log.info("Could not delete temp WPScan files in /tmp/wpscan/. Error:\n%s"%(traceback.format_exc()))
        # Read DB
        self.wp_reports=self.build_wp_reports()
        # Try if local Json databse is accessible
        try: self.update_and_write_wp_reports(self.wp_reports)
        except:
            log.error("Could not write wp_reports database: {}. Use '--reports null' to ignore local Json database".format(self.conf['wp_reports']))
            raise
        
        # Init wpscan output folder
        if self.conf['wpscan_output_folder'] : 
            os.makedirs(self.conf['wpscan_output_folder'], exist_ok=True)

        # Executor, will be created when calling run_scans_and_notify
        self.executor=None
        self.futures=[]
        self.scanned_sites=[]
        self.interrupting=False # Toogle if aborting so other errors doesnt get triggerred if using --ff
        # register the signals to be caught ^C and kill will trigger interrupt()
        signal.signal(signal.SIGINT, self.interrupt)
        signal.signal(signal.SIGTERM, self.interrupt)

    def dump_config(self):
        bump_conf=copy.deepcopy(self.conf)
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

    def find_wp_reports_file(self, create=False):
        wp_reports=None
        if 'APPDATA' in os.environ: 
            if self.conf['daemon']: p=os.path.join(os.environ['APPDATA'],'.wpwatcher/wp_reports.daemon.json')
            else: p=os.path.join(os.environ['APPDATA'],'.wpwatcher/wp_reports.json')
            if os.path.isfile(p) or create: wp_reports=p
        elif 'HOME' in os.environ: 
            if self.conf['daemon']: p=os.path.join(os.environ['HOME'],'.wpwatcher/wp_reports.daemon.json')
            else: p=os.path.join(os.environ['HOME'],'.wpwatcher/wp_reports.json')
            if os.path.isfile(p) or create: wp_reports=p
        elif 'XDG_CONFIG_HOME' in os.environ: 
            if self.conf['daemon']: p=os.path.join(os.environ['XDG_CONFIG_HOME'],'.wpwatcher/wp_reports.daemon.json')
            else: p=os.path.join(os.environ['XDG_CONFIG_HOME'],'.wpwatcher/wp_reports.json')
            if os.path.isfile(p) or create: wp_reports=p
        # if os.path.isfile('./wp_reports.json'): 
        #     wp_reports='./wp_reports.json'
        if create:
            os.makedirs(os.path.join(os.environ['HOME'],'.wpwatcher'), exist_ok=True)
            if not os.path.isfile(wp_reports):
                with open(wp_reports,'w') as reportsfile:
                    json.dump([],reportsfile)
                    log.info("Init new wp_reports database: %s"%(wp_reports))
        return(wp_reports)
    # Read wp_reports database
    def build_wp_reports(self):
        wp_reports=[]
        if self.conf['wp_reports']!='null':
            if not self.conf['wp_reports']:
                self.conf['wp_reports']=self.find_wp_reports_file(create=True)
            if self.conf['wp_reports']:
                if os.path.isfile(self.conf['wp_reports']):
                    try:
                        with open(self.conf['wp_reports'], 'r') as reportsfile:
                            wp_reports=json.load(reportsfile)
                        log.info("Load wp_reports database: %s"%self.conf['wp_reports'])
                    except Exception:
                        log.error("Could not read wp_reports database: {}. Use '--reports null' to ignore local Json database".format(self.conf['wp_reports']))
                        raise
                else:
                    log.info("The database file %s do not exist. It will be created."%(self.conf['wp_reports']))
        return wp_reports

    def update_and_write_wp_reports(self, new_wp_report_list=[]):
        # Update the sites that have been scanned, keep others
        # Keep same report order add append new sites at the bottom
        for newr in new_wp_report_list:
            new=True
            for r in self.wp_reports:
                if r['site']==newr['site']:
                    self.wp_reports[self.wp_reports.index(r)]=newr
                    new=False
                    break
            if new: 
                self.wp_reports.append(newr)
        # Write to file if not null
        if self.conf['wp_reports']!='null':
            # Write method should be thread safe
            while wp_report_lock.locked():
                time.sleep(0.01)
                continue
            wp_report_lock.acquire()
            with open(self.conf['wp_reports'],'w') as reportsfile:
                json.dump(self.wp_reports, reportsfile, indent=4)
                wp_report_lock.release()
    
    # Send email report with status and timestamp
    def send_report(self, wp_site, wp_report):
        # To
        if len(self.conf['email_errors_to'])>0 and wp_report['status']=='ERROR':
            to_email = ','.join( self.conf['email_errors_to'] )
        else: 
            to_email = ','.join( wp_site['email_to'] + self.conf['email_to'] )
        
        if to_email != "":
           
            # Building message
            message = MIMEMultipart("html")
            message['Subject'] = 'WPWatcher %s report - %s - %s' % (  wp_report['status'], wp_site['url'], wp_report['datetime'])
            message['From'] = self.conf['from_email']
            message['To'] = to_email

            # Email body
            body=build_message(wp_report, 
                warnings=self.conf['send_warnings'] or self.conf['send_infos'], # switches to include or not warnings and infos
                infos=self.conf['send_infos'])

            message.attach(MIMEText(body))
            
            # Attachment log if attach_wpscan_output
            if self.conf['attach_wpscan_output']:
                # Remove color
                wp_report['wpscan_output'] = re.sub(r'(\x1b|\[[0-9][0-9]?m)','', str(wp_report['wpscan_output']))
                # Read the WPSCan output
                attachment=io.BytesIO(wp_report['wpscan_output'].encode())
                part = MIMEBase("application", "octet-stream")
                part.set_payload(attachment.read())
                # Encode file in ASCII characters to send by email    
                encoders.encode_base64(part)
                # Sanitize WPScan report filename 
                wpscan_report_filename=get_valid_filename('WPScan_results_%s_%s' % (wp_site['url'], wp_report['datetime']))
                # Add header as key/value pair to attachment part
                part.add_header(
                    "Content-Disposition",
                    "attachment; filename=%s.txt"%(wpscan_report_filename),
                )
                # Attach the report
                message.attach(part)

            # Connecting and sending
            log.info("Sending %s to %s" % (message['Subject'], to_email))

            # SMTP Connection
            s = smtplib.SMTP(self.conf['smtp_server'])
            s.ehlo()
            # SSL
            if self.conf['smtp_ssl']:
                s.starttls()
            # SMTP Auth
            if self.conf['smtp_auth']:
                s.login(self.conf['smtp_user'], self.conf['smtp_pass'])
            # Send Email
            s.sendmail(self.conf['from_email'], to_email, message.as_string())
            s.quit()
            # Store report time
            wp_report['last_email']=datetime.now().strftime('%Y-%m-%dT%H-%M-%S')
            # Discard fixed items
            wp_report['fixed']=[]
        else:
            log.info("Not sending WPWatcher %s email report because no email are configured for site %s"%(wp_report['status'], wp_site['url']))
    
    def update_report(self, wp_report, last_wp_report):
        # Fill out fixed issues and last_email datetime
        # Save already fixed issues but not reported yet
        wp_report['fixed']=last_wp_report['fixed']
        # Figure out fixed issues : compare firt line of alerts and warnings and see if they are still present
        for last_alert in last_wp_report['alerts']:
            if last_alert.splitlines()[0] not in [a.splitlines()[0] for a in wp_report['alerts']]:
                wp_report['fixed'].append('Alert regarding component "%s" has been fixed since last report.\nLast report sent the %s.\nFix detected the %s'%(last_alert.splitlines()[0], 
                    last_wp_report['last_email'], wp_report['datetime']))
        if self.conf['send_warnings']:
            for last_warn in last_wp_report['warnings']:
                if last_warn.splitlines()[0] not in [a.splitlines()[0] for a in wp_report['warnings']]:
                    wp_report['fixed'].append('Warning regarding component "%s" has been fixed since last report.\nLast report sent the %s.\nFix detected the %s'%(last_warn.splitlines()[0], 
                        last_wp_report['last_email'], wp_report['datetime']))
        # Save last email datetime if any
        if last_wp_report['last_email']:
            wp_report['last_email']=last_wp_report['last_email']
    
    def format_site(self, wp_site):
        if 'url' not in wp_site :
            log.error("Invalid site %s"%wp_site)
            wp_site={'url':''}
        else:
            # Format sites with scheme indication
            p_url=list(urlparse(wp_site['url']))
            if p_url[0]=="": 
                wp_site['url']='http://'+wp_site['url']
        # Read the wp_site dict and assing default values if needed
        if 'email_to' not in wp_site or wp_site['email_to'] is None: wp_site['email_to']=[]
        if 'false_positive_strings' not in wp_site or wp_site['false_positive_strings'] is None: wp_site['false_positive_strings']=[]
        if 'wpscan_args' not in wp_site or wp_site['wpscan_args'] is None: wp_site['wpscan_args']=[]
        return wp_site

    def scan_site(self, wp_site):
        wp_site=self.format_site(wp_site)
        # Init report variables
        wp_report={
            "site":wp_site['url'],
            "status":None,
            "datetime": datetime.now().strftime('%Y-%m-%dT%H-%M-%S'),
            "last_email":None,
            "errors":[],
            "infos":[],
            "warnings":[],
            "alerts":[],
            "fixed":[],
            "wpscan_output":None # will be deleted
        }

        # Find last site result if any
        last_wp_report=[r for r in self.wp_reports if r['site']==wp_site['url']]
        if len(last_wp_report)>0: 
            last_wp_report=last_wp_report[0]
            # Skip if the daemon mode is enabled and scan already happend in the last configured `daemon_loop_wait`
            if ( self.conf['daemon'] and 
                datetime.strptime(wp_report['datetime'],'%Y-%m-%dT%H-%M-%S') - datetime.strptime(last_wp_report['datetime'],'%Y-%m-%dT%H-%M-%S') < self.conf['daemon_loop_sleep']):
                log.info("Daemon skipping site %s because already scanned in the last %s"%(wp_site['url'] , self.conf['daemon_loop_sleep']))
                self.scanned_sites.append(None)
                return None
        else: last_wp_report=None
        
        # WPScan arguments
        wpscan_arguments=self.conf['wpscan_args']+wp_site['wpscan_args']+['--url', wp_site['url']]

        # Output
        log.info("Scanning site %s"%wp_site['url'] )
        # Launch WPScan -------------------------------------------------------
        (wpscan_exit_code, wp_report["wpscan_output"]) = self.wpscan.wpscan(*wpscan_arguments)
        
        # Exit code 0: all ok. Exit code 5: Vulnerable. Other exit code are considered as errors
        # Handle scan errors
        if wpscan_exit_code not in [0,5]:
            # Quick return if interrupting
            if self.interrupting: return None

            # Handle API limit
            if "API limit has been reached" in str(wp_report["wpscan_output"]) and self.conf['api_limit_wait']: 
                log.info("API limit has been reached after %s sites, sleeping %s and continuing the scans..."%(len(self.scanned_sites),API_WAIT_SLEEP))
                time.sleep(API_WAIT_SLEEP.total_seconds())
                self.wpscan.update_wpscan()
                return self.scan_site(wp_site)

            # Handle Following redirection
            if "The URL supplied redirects to" in str(wp_report["wpscan_output"]) and self.conf['follow_redirect']: 
                url = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                    wp_report["wpscan_output"].split("The URL supplied redirects to")[1] )
                if len(url)==1:
                    wp_site['url']=url[0].strip()
                    log.info("Following redirection to %s"%wp_site['url'])
                    return self.scan_site(wp_site)
                else:
                    err_str="Could not parse the URL to follow in WPScan output after words 'The URL supplied redirects to'"
                    log.error(err_str)
                    wp_report['errors'].append(err_str)

            # Quick return if user cacelled scans
            if wpscan_exit_code in [2]: return None

            # Fail fast
            if self.conf['fail_fast']:
                if not self.interrupting: 
                    log.error("Failure")
                    self.interrupt()
                else: return None # Interrupt will generate other errors

            # If WPScan error, add the error to the reports
            # This types if errors will be written into the Json database file
            if wpscan_exit_code in [1,3,4]:
                err_str="WPScan failed with exit code %s. \nWPScan arguments: %s. \nWPScan output: \n%s"%((wpscan_exit_code, safe_log_wpscan_args(wpscan_arguments), wp_report['wpscan_output']))
                wp_report['errors'].append(err_str)
                log.error("Could not scan site %s"%wp_site['url'])
            
            # Other errors codes : -9, -2, 127, etc: Just return None right away
            else: return None 
            
        # Parse the results if no errors with wpscan -----------------------------
        else:
            # Write wpscan output 
            wpscan_results_file=None
            if self.conf['wpscan_output_folder'] :
                wpscan_results_file=os.path.join(self.conf['wpscan_output_folder'],
                    get_valid_filename('WPScan_results_%s_%s.txt' % (wp_site['url'], wp_report['datetime'])))
                with open(wpscan_results_file, 'w') as wpout:
                    wpout.write(re.sub(r'(\x1b|\[[0-9][0-9]?m)','', str(wp_report['wpscan_output'])))
            
            log.debug("Parsing WPScan output")
            # Call parse_result from parser.py ------------------------
            wp_report['infos'], wp_report['warnings'] , wp_report['alerts']  = parse_results(wp_report['wpscan_output'] , 
                self.conf['false_positive_strings']+wp_site['false_positive_strings'] )
            
            # Updating report entry with data from last scan if any
            if last_wp_report:
                self.update_report(wp_report, last_wp_report)
            
            # Print WPScan findings ------------------------------------------------------
            for info in wp_report['infos']:
                log.info(oneline("** WPScan INFO %s ** %s" % (wp_site['url'], info )))
            for fix in wp_report['fixed']:
                log.info(oneline("** FIXED %s ** %s" % (wp_site['url'], fix )))
            for warning in wp_report['warnings']:
                log.warning(oneline("** WPScan WARNING %s ** %s" % (wp_site['url'], warning )))
            for alert in wp_report['alerts']:
                log.critical(oneline("** WPScan ALERT %s ** %s" % (wp_site['url'], alert )))

            if wpscan_results_file: log.info("Write wpscan output to file %s"%wpscan_results_file)
        
        # Report status ------------------------------------------------
        if len(wp_report['errors'])>0:wp_report['status']="ERROR"
        elif len(wp_report['warnings'])>0 and len(wp_report['alerts']) == 0: wp_report['status']='WARNING'
        elif len(wp_report['alerts'])>0: wp_report['status']='ALERT'
        elif len(wp_report['fixed'])>0: wp_report['status']='FIXED'
        else: wp_report['status']='INFO'

        # Will print parsed readable Alerts, Warnings, etc as they will appear in email reports
        log.debug("\n%s\n"%(build_message(wp_report, 
                warnings=self.conf['send_warnings'] or self.conf['send_infos'], # switches to include or not warnings and infos
                infos=self.conf['send_infos'])))

        # Sending report
        if self.conf['send_email_report']:
            try:
                # Email error report -------------------------------------------------------
                if wp_report['status']=="ERROR":
                    if self.conf['send_errors']:
                        self.send_report(wp_site, wp_report)
                    else:
                        log.info("No WPWatcher ERROR email report have been sent for site %s. If you want to receive error emails, set send_errors=Yes in the config or use --errors."%(wp_site['url']))
                # Or email regular report if conditions ------------------------------------------
                else:
                    if ( self.conf['send_infos'] or 
                        ( wp_report['status']=="WARNING" and self.conf['send_warnings'] ) or 
                        wp_report['status']=='ALERT' or wp_report['status']=='FIXED' ) :

                        if ( not wp_report['last_email'] or ( wp_report['last_email'] and ( 
                            datetime.strptime(wp_report['datetime'],'%Y-%m-%dT%H-%M-%S') - datetime.strptime(wp_report['last_email'],'%Y-%m-%dT%H-%M-%S') > self.conf['resend_emails_after'] 
                            or last_wp_report['status']!=wp_report['status'] ) ) ):
                            # Send the report
                            self.send_report(wp_site, wp_report)
                        else:
                            log.info("Not sending WPWatcher %s email report because already sent in the last %s (at %s) for site %s"%(wp_report['status'], self.conf['resend_emails_after'], wp_report['last_email'], wp_site['url']))
                    else: 
                        # No report notice
                        log.info("No WPWatcher %s email report have been sent for site %s. If you want to receive more emails, send_warnings=Yes, set send_infos=Yes in the config or use --infos."%(wp_report['status'],wp_site['url']))
            
            # Handle send mail error
            except Exception:
                log.error("Unable to send mail report for site " + wp_site['url'] + ". Error: \n"+traceback.format_exc())
                wp_report['errors'].append("Unable to send mail report for site %s"%wp_site['url'])
                if self.conf['fail_fast'] and not self.interrupting: 
                    log.error("Failure")
                    self.interrupt()
        else:
            # No report notice
            log.info("No WPWatcher %s email report have been sent for site %s. To receive emails, setup mail server settings in the config and enable send_email_report or use --send."%(wp_report['status'], wp_site['url']))
        # Save scanned site
        self.scanned_sites.append(wp_site['url'])
        # Discard wpscan_output from report
        del wp_report['wpscan_output']
        # Save report in global instance database and to file when a site has been scanned
        self.update_and_write_wp_reports([wp_report])
        # Print progress
        print_progress_bar(len(self.scanned_sites), len(self.conf['wp_sites'])) 
        return(wp_report)

    def interrupt(self, sig=None, frame=None):
        log.error("Interrupting...")

        # Lock for interrupting
        self.interrupting=True
        
        # Cancel all jobs
        for f in self.futures:
            if not f.done(): f.cancel()
        
        # Send ^C to all WPScan
        for p in self.wpscan.processes: 
            p.send_signal(signal.SIGINT)
        # Send SIGTERM
        time.sleep(INTERRUPT_SLEEP)
        if len(self.wpscan.processes)>0:
            for p in self.wpscan.processes: 
                p.terminate()
            time.sleep(INTERRUPT_SLEEP)
        # Kill after 4 seconds
        if len(self.wpscan.processes)>0:
            for p in self.wpscan.processes: 
                p.kill()
        # If called inside ThreadPoolExecutor, raise Exeception
        if not isinstance(threading.current_thread(), threading._MainThread):
            raise InterruptedError()
        
        # Wait all scans finished, print results and quit
        else:
            self.executor.shutdown(wait=True)
            self.print_scanned_sites_results()
            log.info("Scans interrupted.")
            exit(-1)

    def print_scanned_sites_results(self):
        if len(self.scanned_sites)>0:
            new_reports=[r for r in self.wp_reports if r['site'] in self.scanned_sites]
            log.info(results_summary(new_reports))

    # Run WPScan on defined websites
    def run_scans_and_notify(self):
        # Check sites are in the config
        if len(self.conf['wp_sites'])==0:
            log.error("No sites configured, please provide wp_sites in config file or use arguments --url URL [URL...] or --urls File path")
            return((-1, self.wp_reports))

        log.info("Starting scans on %s configured sites"%(len(self.conf['wp_sites'])))
        
        new_reports=[]
        
        self.executor=concurrent.futures.ThreadPoolExecutor(max_workers=self.conf['asynch_workers'])
        # Sumbit all scans jobs and start scanning
        for s in self.conf['wp_sites']:
            self.futures.append(self.executor.submit(self.scan_site, s))
        # Loops while scans are running and read results
        for f in self.futures:
            try: new_reports.append(f.result())
            # Handle interruption from inside threads when using --ff
            except (InterruptedError):
                self.executor.shutdown(wait=True)
                self.print_scanned_sites_results()
                log.info("Scans interrupted.")
                exit(-1)
        # Print results and finish
        self.print_scanned_sites_results()
        if not any ([r['status']=='ERROR' for r in new_reports if r]):
            log.info("Scans finished successfully.")
            return((0, self.wp_reports))
        else:
            log.info("Scans finished with errors.") 
            return((-1, self.wp_reports))

       