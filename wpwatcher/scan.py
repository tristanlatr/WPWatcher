""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import threading
import re
import smtplib
import traceback
import os

from datetime import timedelta, datetime
from urllib.parse import urlparse
from . import log
from .utils import get_valid_filename, safe_log_wpscan_args, oneline
from .parser import parse_results
from .config import WPWatcherConfig
from .email import WPWatcherNotification
# Wait when API limit reached
API_WAIT_SLEEP=timedelta(hours=24)

# Date format used everywhere
DATE_FORMAT='%Y-%m-%dT%H-%M-%S'

class WPWatcherScanner():
    
    def __init__(self, conf, wpscan):
        self.conf=conf
        self.wpscan=wpscan
        # Storing the Event object to wait and cancel the waiting
        self.api_wait=threading.Event()
        # Toogle if aborting so other errors doesnt get triggerred and exit faster
        self.interrupting=False 
        # List of urls scanend
        self.scanned_sites=[]
        # Init mail link
        self.mail = WPWatcherNotification(self.conf)

    @staticmethod
    def get_fixed_issues(wp_report, last_wp_report, issue_type='alerts'):
        issues=[]
        for last_alert in last_wp_report[issue_type]:
            if last_alert.splitlines()[0] not in [ a.splitlines()[0] for a in wp_report[issue_type] ]:
                issues.append('%s regarding component "%s" has been fixed since last report.\nLast report sent the %s.\nFix detected the %s\nIssue details:\n%s'%('Alert' if issue_type=='alerts' else 'Issue', 
                    last_alert.splitlines()[0], last_wp_report['last_email'], wp_report['datetime'], last_alert))
        return issues

    def update_report(self, wp_report, last_wp_report):
        if last_wp_report:
            # Fill out fixed issues and last_email datetime
            # Save already fixed issues but not reported yet
            wp_report['fixed']=last_wp_report['fixed']
            wp_report['fixed'].extend( self.get_fixed_issues(wp_report, last_wp_report, 'alerts') )
            if self.conf['send_warnings']: wp_report['fixed'].extend( self.get_fixed_issues(wp_report, last_wp_report, 'warnings') )

            # Save last email datetime if any
            if last_wp_report['last_email']:
                wp_report['last_email']=last_wp_report['last_email']
    
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

    def handle_wpscan_err_api_wait(self,wp_site, wp_report):
        log.info("API limit has been reached after %s sites, sleeping %s and continuing the scans..."%(len(self.scanned_sites),API_WAIT_SLEEP))
        self.wpscan.init_check_done=False # will re-trigger wpscan update next time wpscan() is called 
        self.api_wait.wait(API_WAIT_SLEEP.total_seconds())
        if self.interrupting: return ((None, True))
        return ((self.scan_site(wp_site), True))

    def handle_wpscan_err_follow_redirect(self,wp_site, wp_report):
        url = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            wp_report["wpscan_output"].split("The URL supplied redirects to")[1] )
        if len(url)==1:
            wp_site['url']=url[0].strip()
            log.info("Following redirection to %s"%wp_site['url'])
            return ((self.scan_site(wp_site), True))
        else:
            err_str="Could not parse the URL to follow in WPScan output after words 'The URL supplied redirects to'"
            log.error(err_str)
            wp_report['errors'].append(err_str)
            return ((wp_report, False))

    def handle_wpscan_err(self, wp_site, wp_report):
        # Handle API limit
        if "API limit has been reached" in str(wp_report["wpscan_output"]) and self.conf['api_limit_wait']: 
            return self.handle_wpscan_err_api_wait(wp_site, wp_report)

        # Handle Following redirection
        elif "The URL supplied redirects to" in str(wp_report["wpscan_output"]) and self.conf['follow_redirect']: 
            return self.handle_wpscan_err_follow_redirect(wp_site, wp_report)

        else: return ((wp_report, False))

    # def should_notify(self, wp_report, last_wp_report):
    #     should=True
    #     # Return if email seding is disable
    #     if not self.conf['send_email_report']:
    #         # No report notice
    #         log.info("Not sending WPWatcher %s email report for site %s. To receive emails, setup mail server settings in the config and enable send_email_report or use --send."%(wp_report['status'], wp_report['site']))
    #         should=False
        
    #     # Return if error email and disabled
    #     if wp_report['status']=="ERROR" and not self.conf['send_errors']:
    #         log.info("Not sending WPWatcher ERROR email report for site %s because send_errors=No. If you want to receive error emails, set send_errors=Yes in the config or use --errors."%(wp_report['site']))
    #         should=False
        
    #     # Regular mail filter with --warnings or --infos
    #     if not ( ( self.conf['send_infos'] ) or 
    #         ( wp_report['status']=="WARNING" and self.conf['send_warnings'] ) or 
    #         ( wp_report['status']=='ALERT' or wp_report['status']=='FIXED' ) ) :
    #         # No report notice
    #         log.info("Not sending WPWatcher %s email report for site %s because there's nothing wrong or send_warnings=No. If you want to receive more emails, send_warnings=Yes or set send_infos=Yes in the config or use --infos."%(wp_report['status'],wp_report['site']))
    #         should=False

    #     # resend_emails_after config implementation
    #     if not ( not wp_report['last_email'] or ( wp_report['last_email'] and ( 
    #         datetime.strptime(wp_report['datetime'],DATE_FORMAT) - datetime.strptime(wp_report['last_email'],DATE_FORMAT) > self.conf['resend_emails_after'] 
    #         or last_wp_report['status']!=wp_report['status'] ) ) ):
    #         # No report notice
    #         log.info("Not sending WPWatcher %s email report for site %s because already sent in the last %s."%(wp_report['status'], wp_report['site'], self.conf['resend_emails_after']))
    #         should=False
        
    #     return should

    # def notify(self, wp_site, wp_report, last_wp_report):

    #     # Send the report to
    #     if len(self.conf['email_errors_to'])>0 and wp_report['status']=='ERROR':
    #         to = ','.join( self.conf['email_errors_to'] )
    #     else: 
    #         to = ','.join( wp_site['email_to'] + self.conf['email_to'] )

    #     mail=WPWatcherNotification(self.conf)

    #     try:
    #         mail.send_report(wp_report, to, send_infos=self.conf['send_infos'], 
    #             send_warnings=self.conf['send_warnings'], 
    #             send_errors=self.conf['send_errors'], 
    #             attach_wpscan_output=self.conf['attach_wpscan_output'])
    #         return True
                
    #     # Handle send mail error
    #     except smtplib.SMTPException:
    #         log.error("Unable to send mail report for site " + wp_site['url'] + ". Error: \n"+traceback.format_exc())
    #         wp_report['errors'].append("Unable to send mail report for site " + wp_site['url'] + ". Error: \n"+traceback.format_exc())
    #         # Fail fast
    #         if not self.check_fail_fast(): return False 
    
    def write_wpscan_output(self, wp_report):
        # Subfolder
        folder="%s/"%wp_report['status'].lower() if wp_report['status']!='FIXED' else 'info/'
        # Write wpscan output 
        wpscan_results_file=None
        if self.conf['wpscan_output_folder'] :
            wpscan_results_file=os.path.join(self.conf['wpscan_output_folder'], folder , 
                get_valid_filename('WPScan_output_%s_%s.txt' % (wp_report['site'], wp_report['datetime'])))
            with open(wpscan_results_file, 'w') as wpout:
                wpout.write(re.sub(r'(\x1b|\[[0-9][0-9]?m)','', str(wp_report['wpscan_output'])))
        return(wpscan_results_file)

    def check_fail_fast(self):
        # Fail fast
        if self.conf['fail_fast'] and not self.interrupting: 
            log.error("Failure")
            raise InterruptedError
        return None # Interrupt will generate other errors

    def wpscan_site(self, wp_site, wp_report):
        # WPScan arguments
        wpscan_arguments=self.conf['wpscan_args']+wp_site['wpscan_args']+['--url', wp_site['url']]
        # Output
        log.info("Scanning site %s"%wp_site['url'] )
        # Launch WPScan 
        (wpscan_exit_code, wp_report["wpscan_output"]) = self.wpscan.wpscan(*wpscan_arguments)

        # Exit code 0: all ok. Exit code 5: Vulnerable. Other exit code are considered as errors
        if wpscan_exit_code in [0,5]:
            # Call parse_result from parser.py 
            log.debug("Parsing WPScan output")
            wp_report['infos'], wp_report['warnings'] , wp_report['alerts']  = parse_results(wp_report['wpscan_output'] , self.conf['false_positive_strings']+wp_site['false_positive_strings'] )
            return wp_report

        # Handle scan errors
        # Quick return if interrupting and Quick return if user cacelled scans and Other errors codes : -9, -2, 127, etc: Just return None
        if self.interrupting or wpscan_exit_code in [2] or wpscan_exit_code not in [1,3,4] : return None

        # If WPScan error, add the error to the reports
        # This types if errors will be written into the Json database file exit codes 1,3,4
        err_str="WPScan failed with exit code %s. \nWPScan arguments: %s. \nWPScan output: \n%s"%((wpscan_exit_code, safe_log_wpscan_args(wpscan_arguments), wp_report['wpscan_output']))
        wp_report['errors'].append(err_str)
        raise RuntimeError("WPscan failure")

    def skip_this_site(self, wp_report, last_wp_report):
        # Skip if the daemon mode is enabled and scan already happend in the last configured `daemon_loop_wait`
        if ( self.conf['daemon'] and 
            datetime.strptime(wp_report['datetime'],DATE_FORMAT) - datetime.strptime(last_wp_report['datetime'],DATE_FORMAT) < self.conf['daemon_loop_sleep']):
            log.info("Daemon skipping site %s because already scanned in the last %s"%(wp_report['site'] , self.conf['daemon_loop_sleep']))
            self.scanned_sites.append(None)
            return True
        return False

    def log_report_results(self, wp_report):
         # Print WPScan findings ------------------------------------------------------
        for info in wp_report['infos']: log.info(oneline("** WPScan INFO %s ** %s" % (wp_report['site'], info )))
        for fix in wp_report['fixed']: log.info(oneline("** FIXED %s ** %s" % (wp_report['site'], fix )))
        for warning in wp_report['warnings']: log.warning(oneline("** WPScan WARNING %s ** %s" % (wp_report['site'], warning )))
        for alert in wp_report['alerts']: log.critical(oneline("** WPScan ALERT %s ** %s" % (wp_report['site'], alert )))

    def fill_report_status(self, wp_report):
        # Report status ------------------------------------------------
        if len(wp_report['errors'])>0:wp_report['status']="ERROR"
        elif len(wp_report['warnings'])>0 and len(wp_report['alerts']) == 0: wp_report['status']='WARNING'
        elif len(wp_report['alerts'])>0: wp_report['status']='ALERT'
        elif len(wp_report['fixed'])>0: wp_report['status']='FIXED'
        else: wp_report['status']='INFO'

    # Orchestrate the scanning of a site
    def scan_site(self, wp_site, last_wp_report=None):
        wp_site=self.format_site(wp_site)
        # Init report variables
        wp_report={
            "site":wp_site['url'],
            "status":None,
            "datetime": datetime.now().strftime(DATE_FORMAT),
            "last_email":None,
            "errors":[],
            "infos":[],
            "warnings":[],
            "alerts":[],
            "fixed":[],
            "wpscan_output":None # will be deleted
        }

        # Skip if the daemon mode is enabled and scan already happend in the last configured `daemon_loop_wait`
        if last_wp_report and self.skip_this_site(wp_report, last_wp_report): return None
        
        # Launch WPScan
        try:
            wp_report = self.wpscan_site(wp_site, wp_report)
        except RuntimeError:
             # Try to handle error and return
            wp_report, handled = self.handle_wpscan_err(wp_site, wp_report)
            if handled: return wp_report
            else: 
                log.error("Could not scan site %s"%wp_site['url'])
                # Fail fast
                self.check_fail_fast()

        # Abnormal failure exit codes not in 0-5 and not while tearing down program
        if not wp_report: return None

        self.fill_report_status(wp_report)
        self.log_report_results(wp_report)
        
        # Write wpscan output 
        wpscan_results_file=self.write_wpscan_output(wp_report)
        if wpscan_results_file: log.info("WPScan output saved to file %s"%wpscan_results_file)
        
        # Updating report entry with data from last scan 
        self.update_report(wp_report, last_wp_report)

        # Notify recepients if match triggers and no errors
        try:
            self.mail.notify(wp_site, wp_report, last_wp_report)
        except RuntimeError: 
            # Fail fast
            self.check_fail_fast()

        # Save scanned site
        self.scanned_sites.append(wp_site['url'])
        # Discard wpscan_output from report
        del wp_report['wpscan_output']
        return(wp_report)