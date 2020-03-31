#! /usr/bin/env python3
#
# Wordpress Watcher
# Automating WPscan to scan and report vulnerable Wordpress sites
#
# DISCLAIMER - USE AT YOUR OWN RISK.
#
# Standards libraries
import os
import sys
import re
import json
import smtplib
import traceback
import subprocess
import logging
import shutil
from subprocess import CalledProcessError
import argparse
import configparser
import io
import unicodedata
import collections.abc
import time
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
# Local modules
from wpscan_parser import parse_results

# Setup configuration, will be parsed by setup.py -------------------
# Values must be in one line
# Project version.
VERSION='0.5.2.dev0'
# URL that will be displayed in help
GIT_URL="https://github.com/tristanlatr/WPWatcher"
# Authors
AUTHORS="Florian Roth, Tristan Landès"

# WPWatcher class ---------------------------------------------------------------------
class WPWatcher():

    # WPWatcher must use a configuration dict
    def __init__(self, conf):
        
        # Save config dict as is
        self.conf=conf
        # Check sites are in the config
        if len(self.conf['wp_sites'])==0:
            log.info("No sites configured, please provide wp_sites in config file or use --url URL [URL...]")
            exit(-1)
        # Check if WPScan exists
        if not self.is_wpscan_installed():
            log.error("There is an issue with your WPScan installation or WPScan not installed. Fix wpscan on your system. See https://wpscan.org for installation steps.")
            exit(-1)
        # Update wpscan database
        self.update_wpscan()
        # Try delete temp files.
        if os.path.isdir('/tmp/wpscan'):
            try: 
                shutil.rmtree('/tmp/wpscan')
                log.info("Deleted temp WPScan files in /tmp/wpscan/")
            except (FileNotFoundError, OSError, Exception) as err: 
                log.info("Could not delete temp WPScan files in /tmp/wpscan/. Error: %s"%(err))

    # Helper method: actually wraps wpscan
    def wpscan(self, *args):
        (exit_code, output)=(0,"")
        # WPScan arguments
        cmd=[self.conf['wpscan_path']] + list(args) 
        # Log wpscan command without api token
        logged_cmd=[self.conf['wpscan_path']] + list(args) 
        # Replace --api-token param with *** for safe logging
        if "--api-token" in logged_cmd :
            logged_cmd[logged_cmd.index("--api-token")+1]="***"
        log.debug("Running WPScan command: %s" % ' '.join(logged_cmd) )
        # Run wpscan -------------------------------------------------------------------
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE )
            wpscan_output, _  = process.communicate()
            wpscan_output=wpscan_output.decode("utf-8")

            # Error when wpscan failed, except exit code 5: means the target has at least one vulnerability.
            #   See https://github.com/wpscanteam/CMSScanner/blob/master/lib/cms_scanner/exit_code.rb
            if process.returncode not in [0,5]:
                # Handle error
                err_string="WPScan failed with exit code %s. WPScan output: \n%s" % (str(process.returncode), wpscan_output)
                log.error(self.oneline(err_string))
            else :
                # WPScan comamnd success
                log.debug("WPScan raw output:\n"+wpscan_output)

            (exit_code, output)=(process.returncode, wpscan_output)

        except CalledProcessError as err:
            # Handle error --------------------------------------------------
            wpscan_output=str(err.output)
            err_string="WPScan failed with exit code %s. WPScan output: \n%s" % (str(process.returncode), wpscan_output)
            log.error(self.oneline(err_string))
            (exit_code, output)=(err.returncode, wpscan_output)

        return((exit_code, output))

    # Helper method that transform multiline string to one line for grepable output
    @staticmethod
    def oneline(string):
        return( " ".join(line.strip() for line in string.splitlines()) )

    # Check if WPScan is installed
    def is_wpscan_installed(self):
        exit_code, _ = self.wpscan("--version")
        if exit_code!=0: return False
        else: return True

    # Update WPScan database
    def update_wpscan(self):
        log.info("Updating WPScan")
        exit_code, _ = self.wpscan("--update")
        if exit_code!=0: 
            log.error("Error updating WPScan")
            exit(-1)

    # Send email report with status and timestamp
    def send_report(self, wp_site, wp_report):
        # To
        if len(self.conf['email_errors_to'])>0 and wp_report['status']=='ERROR':
            to_email = ','.join( self.conf['email_errors_to'] )
        else: 
            to_email = ','.join( wp_site['email_to'] + self.conf['email_to'] )

        if to_email != "":
            datetimenow=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # Building message
            message = MIMEMultipart("alternative")
            message['Subject'] = 'WPWatcher %s report on %s - %s' % (  wp_report['status'], wp_site['url'], datetimenow)
            message['From'] = self.conf['from_email']
            message['To'] = to_email

            # Email body
            body=self.build_message(wp_report, wp_site)
            message.attach(MIMEText(body, "plain"))
            
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
                wpscan_report_filename='WPScan_report_%s_%s' % (wp_site['url'], datetimenow)
                wpscan_report_filename=wpscan_report_filename.strip().replace(' ', '_')
                wpscan_report_filename=re.sub(r'(?u)[^-\w.]', '', wpscan_report_filename)
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

        else:
            log.info("Not sending WPWatcher %s email report because no email are configured for site %s"%(wp_report['status'], wp_site['url']))
    
    @staticmethod
    def build_message(wp_report, wp_site):
        
        message="WordPress security scan report for site: %s\n\n" % (wp_site['url'])
        
        if wp_report['errors'] : message += "An error occurred."
        elif wp_report['alerts'] : message += "Issues have been detected by WPScan. Your WordPress site is vulnerable."
        elif wp_report['warnings']: message += "Issues have been detected by WPScan."
        else: message += "WPScan found some informations."
        
        if wp_report['errors']:
            message += "\n\n\tErrors\n\n"
            message += "\n\n".join(wp_report['errors'])
        if wp_report['alerts']:
            message += "\n\n\tAlerts\n\n"
            message += "\n\n".join(wp_report['alerts'])
        if wp_report['warnings']:
            message += "\n\n\tWarnings\n\n"
            message += "\n\n".join(wp_report['warnings'])
        if wp_report['infos']:
            message += "\n\n\tInformations\n\n"
            message += "\n\n".join(wp_report['infos'])

        return message

    # Run WPScan on defined websites
    def run_scans_and_notify(self):

        log.info("Starting scans on configured sites")
        exit_code=0
        for wp_site in self.conf['wp_sites']:
            
            # Init report variables
            wp_report={
                "wpscan_output":None,
                "errors":[],
                "infos":[],
                "warnings":[],
                "alerts":[],
                "status":None
            }

            # Check if url is present and fail if not  
            if 'url' not in wp_site or wp_site['url']=="":
                log.error("Site must have valid a 'url' key: %s" % (str(wp_site)))
                exit_code=-1
                # Fail fast
                if self.conf['fail_fast']: 
                    log.info("Failure. Scans aborted.") 
                    exit(-1)
                continue
            # Read the wp_site dict and assing default values if needed -------------
            if 'email_to' not in wp_site or wp_site['email_to'] is None: wp_site['email_to']=[]
            if 'false_positive_strings' not in wp_site or wp_site['false_positive_strings'] is None: wp_site['false_positive_strings']=[]
            if 'wpscan_args' not in wp_site or wp_site['wpscan_args'] is None: wp_site['wpscan_args']=[]
            
            # WPScan arguments
            wpscan_arguments=self.conf['wpscan_args']+wp_site['wpscan_args']+['--url', wp_site['url']]
            log.info("Scanning site %s"%wp_site['url'] )
            
            # Launch WPScan -------------------------------------------------------
            (wpscan_exit_code, wp_report["wpscan_output"]) = self.wpscan(*wpscan_arguments)

            # Replace --api-token param with *** for safe logging
            if "--api-token" in wpscan_arguments:
                wpscan_arguments[wpscan_arguments.index("--api-token")+1]="***"

            # Exit code 0: all ok. Exit code 5: Vulnerable. Other exit code are considered as errors
            if wpscan_exit_code not in [0,5]:
                # Handle scan error
                log.error("Could not scan site %s"%wp_site['url'])
                wp_report['errors'].append("Could not scan site %s. \nWPScan failed with exit code %s. \nWPScan arguments: %s. \nWPScan output: \n%s"%((wp_site['url'], wpscan_exit_code, wpscan_arguments, wp_report['wpscan_output'])))
                # Handle API limit
                if "API limit has been reached" in str(wp_report["wpscan_output"]) and self.conf['api_limit_wait']: 
                    pass
                    log.info("WPVulDB API limit has been reached, waiting 24h and continuing the scans...")
                    time.sleep(86400)
                    # Instanciating a new WPWatcher object and continue scans
                    delayed=WPWatcher(self.conf)
                    return(delayed.run_scans_and_notify()+exit_code)
                # Fail fast
                elif self.conf['fail_fast']: 
                    log.info("Failure. Scans aborted.")
                    exit(-1)
                else:
                    exit_code=-1
            
            # Parse the results if no errors with wpscan -----------------------------
            else:
                try:
                    log.debug("Parsing WPScan output")
                    # Call parse_result from wpscan_parser.py ------------------------
                    wp_report['infos'], wp_report['warnings'] , wp_report['alerts']  = parse_results(wp_report['wpscan_output'] , 
                        self.conf['false_positive_strings']+wp_site['false_positive_strings'] )

                except Exception as err:
                    # Handle parsing error
                    err_string="Could not parse the results from wpscan command for site {}.\nError: {}\nWPScan output:\n{}".format(wp_site['url'],str(err), wp_report['wpscan_output'])
                    log.error(err_string)
                    wp_report['errors'].append(err_string)
                    exit_code=-1
                    # Fail fast
                    if self.conf['fail_fast']: 
                        log.info("Failure. Scans aborted.")
                        raise

                # Logfile ------------------------------------------------------
                for info in wp_report['infos']:
                    log.info(self.oneline("** WPScan INFO %s ** %s" % (wp_site['url'], info )))
                for warning in wp_report['warnings']:
                    log.warning(self.oneline("** WPScan WARNING %s ** %s" % (wp_site['url'], warning )))
                for alert in wp_report['alerts']:
                    log.critical(self.oneline("** WPScan ALERT %s ** %s" % (wp_site['url'], alert )))
                # log.debug("Readable parsed report:\n%s"%self.build_message(warnings, alerts, messages))
            
            # Report status ------------------------------------------------
            if len(wp_report['errors'])>0:wp_report['status']="ERROR"
            elif len(wp_report['warnings'])>0 and len(wp_report['alerts']) == 0: wp_report['status']='WARNING'
            elif len(wp_report['alerts'])>0: wp_report['status']='ALERT'
            else: wp_report['status']='INFO'

            # Deleting unwanted informations in report text
            wp_report['warnings']=wp_report['warnings'] if self.conf['send_warnings'] or self.conf['send_infos'] else None
            wp_report['infos']=wp_report['infos'] if self.conf['send_infos'] else None

            # Printing to stdout if not quiet
            # Will print parsed readable Alerts, Warnings, etc as they will appear in email reports
            if self.conf['quiet']==False: 
                print("\n"+self.build_message(wp_report, wp_site)+"\n")

            # Sending report
            if self.conf['send_email_report']:
                try:
                    # Email error report -------------------------------------------------------
                    if wp_report['status']=="ERROR":
                        if self.conf['send_errors']:
                            self.send_report(wp_site, wp_report)
                        else:
                            log.info("No WPWatcher ERROR email report have been sent for site %s. If you want to receive error emails, set send_errors=Yes in the config."%(wp_site['url']))
                    # Or email regular report --------------------------------------------------
                    else:
                        if self.conf['send_infos'] or ( wp_report['status']=="WARNING" and self.conf['send_warnings'] ) or wp_report['status']=='ALERT':
                            self.send_report(wp_site, wp_report)
                        else: 
                            # No report notice
                            log.info("No WPWatcher %s email report have been sent for site %s. If you want to receive more emails, send_warnings=Yes or set send_infos=Yes in the config."%(wp_report['status'],wp_site['url']))
                
                # Handle send mail error
                except Exception as err:
                    log.error("Unable to send mail report for site " + wp_site['url'] + ". Error: "+str(err))
                    exit_code=-1
                    if self.conf['fail_fast']: 
                        log.info("Failure. Scans aborted.")
                        raise
            else:
                # No report notice
                log.info("No WPWatcher %s email report have been sent for site %s. If you want to receive emails, set send_email_report=Yes in the config."%(wp_report['status'], wp_site['url']))
            
            # To support reccursive calling and scanning all sites in several days
            # Remove site from conf since it's been processed 
            self.conf.remove(wp_site)
        if exit_code == 0:
            log.info("Scans finished successfully.") 
        else:
            log.info("Scans finished with errors.") 
        return(exit_code)

# Configuration template -------------------------
TEMPLATE_FILE="""[wpwatcher]
# WPWatcher configuration file
# WordPress Watcher is a Python wrapper for WPScan that manages scans on multiple sites and reports by email
# For more infos check %s

wp_sites=   [
            {"url":"exemple.com"},
            {"url":"exemple2.com"},
            {"url":"exemple3.com"}
    ]
wpscan_path=wpscan
wpscan_args=[   "--format", "cli",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks" ]
# false_positive_strings=["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]
send_email_report=No
send_warnings=Yes
send_infos=No
send_errors=No
attach_wpscan_output=No
email_to=["you@domain"]
from_email=WordPressWatcher@domain.com
# email_errors_to=["admins@domain"]
smtp_server=mailserver.de:25
smtp_auth=No
smtp_user=
smtp_pass=
smtp_ssl=Yes
log_file=
quiet=No
verbose=No
fail_fast=No
api_limit_wait=No
"""%(GIT_URL)
# Config default values
DEFAULT_CONFIG={
    'wp_sites' :'null',
    'false_positive_strings' : 'null',                        
    'wpscan_path':'wpscan',
    'log_file':"",
    'wpscan_args':'''["--no-banner","--random-user-agent"]''',
    'send_email_report':'No',
    'send_errors':'No',
    'email_to':'null',
    'email_errors_to':'null',
    'send_warnings':'Yes',
    'send_infos':'No',
    'attach_wpscan_output':'No',
    'smtp_server':"",
    'smtp_auth':'No',
    'smtp_user':"",
    'smtp_pass':"",
    'smtp_ssl':'No',
    'from_email':"",
    'quiet':'No',
    'verbose':'No',
    'fail_fast':'No',
    'api_limit_wait':'No'
}

# Configuration handling -------------------------------------------------------
def getjson(conf, key):
    string_val=conf.get('wpwatcher', key)
    try:
        loaded=json.loads(string_val)
        return loaded if loaded else []
    except Exception as err:
        log.error("Could not read config JSON value for: '%s' and string: '%s'. Error: %s" % (key, conf.get('wpwatcher',key), str(err)))
        raise

def getbool(conf, key):
    try:
        return conf.getboolean('wpwatcher', key)
    except Exception as err:
        log.error("Could not read boolean value in config for: '{}' and string '{}'. Must be Yes/No. Error: {}".format(key, conf.get('wpwatcher',key), str(err)))
        raise

def find_config_file():
    '''
    Returns the location of existing `wpwatcher.conf` files at ./wpwatcher.conf and/or ~/wpwatcher.conf
    '''
    paths=[]
    if os.path.isfile('./wpwatcher.conf'): 
        paths.append('./wpwatcher.conf')
    if 'APPDATA' in os.environ: 
        p=os.path.join(os.environ['APPDATA'],'wpwatcher.conf')
        if os.path.isfile(p): paths.append(p)
    elif 'XDG_CONFIG_HOME' in os.environ: 
        p=os.path.join(os.environ['XDG_CONFIG_HOME'],'wpwatcher.conf')
        if os.path.isfile(p): paths.append(p)
    elif 'HOME' in os.environ: 
        p=os.path.join(os.environ['HOME'],'wpwatcher.conf')
        if os.path.isfile(p): paths.append(p)
    return(paths)

def build_config_dict(files=None):
    config_dict={}
    try:
        # Load the configuration file
        conf_parser = configparser.ConfigParser()
        # Applying default conf
        conf_parser.read_dict({'wpwatcher':DEFAULT_CONFIG})
        # Search wpwatcher.conf file(s) if --conf not specified
        if not files or len(files)==0:
            files=find_config_file()
        # No config file notice
        if not files or len(files)==0: 
            log.info("No config file selected and could not find default config at ./wpwatcher.conf or ~/wpwatcher.conf. The script must read a configuration file to setup mail server settings, WPScan options and other features.")
        # Reading config 
        else:
            read_files=conf_parser.read(files)
            if len(read_files) < len(files):
                log.error("Could not read config " + str(list(set(files)-set(read_files))) + ". Make sure the file exists, the format is OK and you have correct access right.")
                exit(-1)
        # Saving config file in right dict format - no 'wpwatcher' section, just config options
        config_dict = {
            # Configurable witg cli arguments
            'wp_sites' :getjson(conf_parser,'wp_sites'),
            'send_email_report':getbool(conf_parser, 'send_email_report'),
            'send_errors':getbool(conf_parser, 'send_errors'),
            'email_to':getjson(conf_parser,'email_to'),
            'send_infos':getbool(conf_parser, 'send_infos'),
            'quiet':getbool(conf_parser, 'quiet'),
            'verbose':getbool(conf_parser, 'verbose'),
            'attach_wpscan_output':getbool(conf_parser, 'attach_wpscan_output'),
            'fail_fast':getbool(conf_parser, 'fail_fast'),
            'api_limit_wait':getbool(conf_parser, 'api_limit_wait'),
            # Not configurable with cli arguments
            'send_warnings':getbool(conf_parser, 'send_warnings'),
            'false_positive_strings' : getjson(conf_parser,'false_positive_strings'), 
            'email_errors_to':getjson(conf_parser,'email_errors_to'),
            'wpscan_path':conf_parser.get('wpwatcher','wpscan_path'),
            'wpscan_args':getjson(conf_parser,'wpscan_args'),
            'log_file':conf_parser.get('wpwatcher','log_file'),
            'smtp_server':conf_parser.get('wpwatcher','smtp_server'),
            'smtp_auth':getbool(conf_parser, 'smtp_auth'),
            'smtp_user':conf_parser.get('wpwatcher','smtp_user'),
            'smtp_pass':conf_parser.get('wpwatcher','smtp_pass'),
            'smtp_ssl':getbool(conf_parser, 'smtp_ssl'),
            'from_email':conf_parser.get('wpwatcher','from_email')
        }
        return config_dict

    except Exception as err: 
        log.error("Could not read config " + str(files) + ". Error: "+str(err))
        raise

# Setup stdout logger
log = logging.getLogger('wpwatcher')
def init_log(verbose=False, quiet=False, logfile=None):
    format_string='%(asctime)s - %(levelname)s - %(message)s'
    format_string_cli='%(levelname)s - %(message)s'
    if verbose : verb_level=logging.DEBUG
    elif quiet : verb_level=logging.ERROR
    else : verb_level=logging.INFO
    # Add stdout: configurable
    log.setLevel(verb_level)
    std = logging.StreamHandler(sys.stdout)
    std.setLevel(verb_level)
    std.setFormatter(logging.Formatter(format_string_cli))
    log.handlers=[]
    log.addHandler(std)
    if logfile :
        fh = logging.FileHandler(logfile)
        fh.setLevel(verb_level)
        fh.setFormatter(logging.Formatter(format_string))
        log.addHandler(fh)
    if verbose and quiet :
        log.info("Verbose and quiet values are both set to True. By default, verbose value has priority.")
    return (log)

# Arguments can overwrite config file values
def parse_args():
    parser = argparse.ArgumentParser(description="""WordPress Watcher is a Python wrapper for WPScan that manages scans on multiple sites and reports by email.
Some config arguments can be passed to the command.
It will overwrite previous values from config file(s).
Check %s for more informations."""%(GIT_URL), formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--conf', '-c', metavar='File path', help="""The script * must read a configuration file to set mail server settings, WPScan path and arguments *.     
If no config file is found, mail server settings, WPScan path and arguments and other config values will have default values.  
Setup mail server settings and turn on `send_email_report` in the config file if you want to receive reports.  
You can specify multiple files `--conf File path [File path ...]`. Will overwrites the keys with each successive file.
All options keys can be missing from config file.
If not specified with `--conf` parameter, will try to load config from file `./wpwatcher.conf` or `~/wpwatcher.conf`.
All options can be missing from config file.\n\n""", nargs='+', default=None)
    parser.add_argument('--template_conf', '--tmpconf', help="""Print a template config file.
Use `wpwatcher --template_conf > ~/wpwatcher.conf && vim ~/wpwatcher.conf` to create (or overwrite) and edit the new default config file.""", action='store_true')
    parser.add_argument('--version', '-V', help="Print WPWatcher version", action='store_true')
    # Declare arguments that will overwrite config options
    parser.add_argument('--wp_sites', '--url', metavar="URL", help="Configure wp_sites", nargs='+', default=None)
    parser.add_argument('--wp_sites_list', '--urls', metavar="File path", help="Configure wp_sites from a list of URLs", default=None)
    parser.add_argument('--email_to', '--em', metavar="Email", help="Configure email_to", nargs='+', default=None)
    parser.add_argument('--send_email_report', '--send', help="Configure send_email_report=Yes", action='store_true')
    parser.add_argument('--send_infos', '--infos', help="Configure send_infos=Yes", action='store_true')
    parser.add_argument('--send_errors', '--errors', help="Configure send_errors=Yes", action='store_true')
    parser.add_argument('--attach_wpscan_output', '--attach', help="Configure attach_wpscan_output=Yes", action='store_true')
    parser.add_argument('--fail_fast', '--ff', help="Configure fail_fast=Yes", action='store_true')
    parser.add_argument('--api_limit_wait', '--wait', help="Configure api_limit_wait=Yes", action='store_true')
    parser.add_argument('--verbose', '-v', help="Configure verbose=Yes", action='store_true')
    parser.add_argument('--quiet', '-q', help="Configure quiet=Yes", action='store_true')
    args = parser.parse_args()
    return(args)

# Main program, parse the args, read config and launch scans
def wpwatcher():
    init_log()
    args=parse_args()
    # If template conf , print and exit
    if args.template_conf:
        print(TEMPLATE_FILE)
        exit(0)
    # If version, print and exit
    if args.version:
        log.info("Version:\t\t%s"%VERSION)
        log.info("Authors:\t\t%s"""%AUTHORS)
        exit(0)
    # Configuration variables
    conf_files=args.conf
     # Init config dict: read config files
    configuration=build_config_dict(files=conf_files)
    conf_args={}
    # Sorting out only args that matches config options and that are not None or False
    for k in vars(args): 
        if k in DEFAULT_CONFIG.keys() and vars(args)[k]:
            conf_args.update({k:vars(args)[k]})  
    # Append or init list of urls from file if any
    if args.wp_sites_list:
        with open(args.wp_sites_list, 'r') as urlsfile:
            sites=[ site.replace('\n','') for site in urlsfile.readlines() ]
            conf_args['wp_sites']= sites if 'wp_sites' not in conf_args else conf_args['wp_sites']+sites
    # Adjust special case of urls that are list of dict
    if 'wp_sites' in conf_args:
        conf_args['wp_sites']=[ {"url":site} for site in conf_args['wp_sites'] ]
    # Overwrite with conf dict biult from CLI Args
    if conf_args: configuration.update(conf_args)
    # (Re)init logger with config
    init_log(verbose=configuration['verbose'],
        quiet=configuration['quiet'],
        logfile=configuration['log_file'])
    # Logging debug list of sites
    log.debug("WP sites: %s"%(json.dumps(configuration['wp_sites'], indent=4)))
    # Create main object
    wpwatcher=WPWatcher(configuration)
    # Run scans and quit
    exit(wpwatcher.run_scans_and_notify())

if __name__ == '__main__':
    wpwatcher()