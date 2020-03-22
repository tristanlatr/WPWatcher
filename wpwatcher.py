#! /usr/bin/env python3
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Wordpress Watcher
# Automating WPscan to scan and report vulnerable Wordpress sites
# DISCLAIMER - USE AT YOUR OWN RISK.
__version__='0.3'

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
from email.mime.text import MIMEText
from datetime import datetime

# Local module
from wpscan_parser import parse_results

configuration=None
log = logging.getLogger('wpwatcher')

# Setup logger
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
        log.warning("Verbose and quiet values are both set to True. By default, verbose value has priority.")
    return (log)

# Check if WPScan is installed
def is_wpscan_installed():
    try:
        wpscan_output = subprocess.Popen([conf('wpscan_path'), '--version'], stdout=subprocess.PIPE).communicate()[0]
        if 'WordPress Security Scanner' in str(wpscan_output): return 1
        else: return 0
    except CalledProcessError:
        return 0

# Update WPScan database
def update_wpscan():
    log.info("Updating WPScan")
    try:
        process = subprocess.Popen([conf('wpscan_path'), '--update'], stdout=subprocess.PIPE)
        wpscan_output, _  = process.communicate()
        if process.returncode :
            log.error("WPScan failed with exit code: %s \n %s" % ( str(process.returncode), str(wpscan_output.decode("utf-8") ) ) )
            log.error("Error updating wpscan")
            exit(-1)
    except CalledProcessError as err:
        log.error("WPScan failed: %s" % ( str(err) ) ) 
        log.error("Error updating wpscan")
        exit(-1)

# Send email report
def send_report(wp_site, warnings=None, alerts=None, infos=None, errors=None, emails=None, status=None):
    if emails: to_email=','.join( emails )
    else: to_email = ','.join( wp_site['email_to'] + conf('email_to') )
    if to_email != "":
        # Building message
        if (warnings or alerts) :message = "Issues have been detected by WPScan.\nSite: %s" % (wp_site['url'])
        else: message = "WPScan report\nSite: %s" % (wp_site['url'])
        if errors:
            message += "\n\n\tErrors\n\n"
            message += "\n\n".join(errors)
        if alerts:
            message += "\n\n\tAlerts\n\n"
            message += "\n\n".join(alerts)
        if warnings:
            message += "\n\n\tWarnings\n\n"
            message += "\n\n".join(warnings)
        if infos:
            message += "\n\n\tInformations\n\n"
            message += "\n\n".join(infos)
        mime_msg = MIMEText(message)
        mime_msg['Subject'] = 'WPWatcher%s report on %s - %s' % (' '+status if status else '',wp_site['url'], get_timestamp())
        mime_msg['From'] = conf('from_email')
        mime_msg['To'] = to_email
        # Connecting and sending
        log.info("Sending %s to %s" % (mime_msg['Subject'], to_email))
        # SMTP Connection
        s = smtplib.SMTP(conf('smtp_server'))
        s.ehlo()
        # SSL
        if conf('smtp_ssl'):
            s.starttls()
        # SMTP Auth
        if conf('smtp_auth'):
            s.login(conf('smtp_user'), conf('smtp_pass'))
        # Send Email
        s.sendmail(conf('from_email'), to_email, mime_msg.as_string())
        s.quit()
        return(True)
    else:
        log.warning("Not sending WPWatcher email report because no email are configured")
        return(True)

def get_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def find_config_file():
        '''
        Returns the location of a existing `wpwatcher.conf` file.  
        Will return ./wpwatcher.conf or ~/wpwatcher.conf
        '''
        if os.path.isfile('./wpwatcher.conf'): conf_path='./wpwatcher.conf'
        elif 'APPDATA' in os.environ: conf_path=(os.path.join(os.environ['APPDATA'],'wpwatcher.conf'))
        elif 'XDG_CONFIG_HOME' in os.environ: conf_path=(os.path.join(os.environ['XDG_CONFIG_HOME'],'wpwatcher.conf'))
        elif 'HOME' in os.environ: conf_path=(os.path.join(os.environ['HOME'],'wpwatcher.conf'))
        if not os.path.isfile(conf_path) : return False
        return(conf_path)

def read_config(configpath):
    global configuration
    # Load the configuration file
    try:
        configuration = configparser.ConfigParser()
        #Default config
        configuration.read_dict({
                'wpwatcher':{
                        'wp_sites' :'null',
                        'false_positive_strings' : """["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]""",                        
                        'wpscan_path':'wpscan',
                        'log_file':"",
                        'wpscan_args':'null',
                        'send_email_report':'No',
                        'send_errors':'No',
                        'email_to':'null',
                        'email_errors_to':'null',
                        'send_warnings':'Yes',
                        'send_infos':'No',
                        'smtp_server':"",
                        'smtp_auth':'No',
                        'smtp_user':"",
                        'smtp_pass':"",
                        'smtp_ssl':'No',
                        'from_email':"",
                        'quiet':'No',
                        'verbose':'No'
                }
        })
        if len(configuration.read(configpath))==0:
            return False
    except Exception as err: 
        log.error(err)
        return False
    return True

# Wrapper to get config in the right data type
def conf(key):
    if configuration:
        # Boolean conf values
        if key in ['send_email_report', 'smtp_auth', 'smtp_ssl', 'verbose', 'quiet', 'send_errors', 'send_infos', 'send_warnings']:
            try:
                return configuration.getboolean('wpwatcher', key)
            except Exception as err:
                log.error("Could not read boolean value in config for key: '{}' and string '{}' must be Yes/No. Comment it to use defaults. Error: {}".format(key, configuration.get('wpwatcher',key), err))
                exit(-1)
        # JSON lists conf values
        elif key in ['wp_sites', 'email_to', 'wpscan_args', 'false_positive_strings', 'email_errors_to']:
            string_val=configuration.get('wpwatcher', key)
            try:
                loaded=json.loads(string_val)
            except Exception as err:
                log.error("Could not read config JSON value for: '%s' and string: '%s'. Error: %s" % (key, configuration.get('wpwatcher',key), str(err)))
                exit(-1)
            return loaded if loaded else []
        # Default conf values
        else:
            return configuration.get('wpwatcher', key)
    else:
        log.error("No configuration")
        exit(-1)

def parse_args():

    parser = argparse.ArgumentParser(description='Wordpress Watcher. Automating WPscan to scan and report vulnerable Wordpress sites')
    parser.add_argument('--conf', metavar='Config file', help="Path to the config file. Will use ./wpwatcher.conf or ~/wpwatcher.conf if left none")
    args = parser.parse_args()
    return args

# Run WPScan on defined domains
def run_scan():
    log.info("Starting scans on configured sites")
    exit_code=0
    for wp_site in conf('wp_sites'):
        # Init scan variables
        errors=[]
        (messages, warnings, alerts)=([],[],[])
        # Read the wp_site dict and assing default values if needed ----------
        if 'url' not in wp_site or wp_site['url']=="":
            log.error("Site must have valid a 'url' key: %s" % (str(wp_site)))
            exit_code=-1
            continue
        if 'email_to' not in wp_site or wp_site['email_to'] is None: wp_site['email_to']=[]
        if 'false_positive_strings' not in wp_site or wp_site['false_positive_strings'] is None: wp_site['false_positive_strings']=[]
        if 'wpscan_args' not in wp_site or wp_site['wpscan_args'] is None: wp_site['wpscan_args']=[]
        wordpress_arguments=conf('wpscan_args')+wp_site['wpscan_args']
        
        # Scan ----------------------------------------------------------------
        try:
            cmd=[conf('wpscan_path')] + wordpress_arguments + ['--url', wp_site['url']]
            log.info("Scanning '%s' with command: %s" % (wp_site['url'], ' '.join(cmd)))
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE )
            wpscan_output, _  = process.communicate()
            if process.returncode :
                # Handle scan error
                wpscan_output=wpscan_output.decode("utf-8")
                err_string="WPScan failed with exit code for site %s: %s. WPScan output: \n%s" % (wp_site['url'], str(process.returncode), wpscan_output)
                log.error(" ".join(line.strip() for line in err_string.splitlines()))
                errors.append(err_string)
                exit_code=-1
            
            else:
                # Scan success
                wpscan_output=wpscan_output.decode("utf-8")
                log.debug("WPScan raw output:\n"+wpscan_output)
                pass
        except CalledProcessError as err:
            # Handle scan error
            wpscan_output=str(err)
            err_string="WPScan failed with exit code for site %s: %s. WPScan Output: \n%s" % (wp_site['url'], str(process.returncode), wpscan_output)
            log.error(" ".join(line.strip() for line in err_string.splitlines()))
            errors.append(err_string)
            exit_code=-1
        
        # Parse the results if no errors with wpscan ---------------------------
        if len(errors)==0:
            try:
                # Test if Json selectted in wpscan args, get last '--format' element occurrence and check if the next parameter is 'json'
                if '--format' in wordpress_arguments: 
                    format_index=len(wordpress_arguments) - 1 - wordpress_arguments[::-1].index('--format')
                    is_json=wordpress_arguments[format_index+1]=='json'
                else: is_json=False
                log.debug("Parsing WPScan %s output" % 'json' if is_json else 'cli')
                # Call parse_result from wpscanparser.py --------
                (messages, warnings, alerts) = parse_results(wpscan_output , conf('false_positive_strings')+wp_site['false_positive_strings'] , is_json )

            except Exception as err:
                err_string="Could not parse the results from wpscan command for site {}.\nError: {}\nWPScan output: {}".format(wp_site['url'],str(err), wpscan_output)
                log.error(err_string)
                errors.append(err_string)
                exit_code=-1
                
            # Report Options ------------------------------------------------------
            # Logfile
            for message in messages:
                log.info("** WPScan INFO %s ** %s" % (wp_site['url'], " ".join(line.strip() for line in str(message).splitlines())))
            for warning in warnings:
                log.warning("** WPScan WARNING %s ** %s" % (wp_site['url'], " ".join(line.strip() for line in str(warning).splitlines()) ))
            for alert in alerts:
                log.critical("** WPScan ALERT %s ** %s" % (wp_site['url'], " ".join(line.strip() for line in str(alert).splitlines())))
        
        if conf('send_email_report'):
            try:
                # Email errors -------------------------------------------------------
                if len(errors)>0:
                    if conf('send_errors'):
                        if len(conf('email_errors_to'))>0:
                            send_report(wp_site, warnings, alerts, infos=messages, errors=errors, emails=conf('email_errors_to'), status="ERROR")
                        else: 
                            send_report(wp_site, warnings, alerts, infos=messages, errors=errors, status="ERROR")
                    else:
                        log.info("No WPWatcher ERROR email report have been sent for site %s. If you want to receive error emails, set send_errors=Yes in the config."%(wp_site['url']))
                # Email -------------------------------------------------------------------
                else:
                    status=None
                    if len(warnings)>0 and len(alerts) == 0: status='WARNING'
                    elif len(alerts)>0: status='ALERT'
                    else: status='INFO'
                    if conf('send_infos') or ( status=="WARNING" and conf('send_warnings') ) or status=='ALERT':
                        send_report(wp_site, alerts=alerts,
                            warnings=warnings if conf('send_warnings') or conf('send_infos') else None,
                            infos=messages if conf('send_infos') else None,
                            status=status)
                    else: 
                        log.info("No WPWatcher %s email report have been sent for site %s. If you want to receive more emails, set send_infos=Yes or send_warnings=Yes in the config."%(status,wp_site['url']))
            except Exception as err:
                log.error("Unable to send mail report on site " + wp_site['url'] + ". Error: "+str(err))
                exit_code=12
        else:
            log.info("No WPWatcher email report have been sent for site %s. If you want to receive emails, set send_email_report=Yes in the config."%(wp_site['url']))
    if exit_code == 0:
        log.info("Scans finished successfully.") 
    else:
        log.info("Scans finished with errors.") 
    return(exit_code)

def wpwatcher():
    init_log()
    args=parse_args()
    # Read config
    configpath=None
    if args.conf: 
        configpath=args.conf
    else:
        if not find_config_file():
            log.error("Could not find config file ./wpwatcher.conf or ~/wpwatcher.conf. Please make sure the file exist or use '--conf <path>' to define custom config file.")
            exit(-1)
        else:
            configpath=find_config_file()
    if not read_config(configpath):
        log.error("Could not read config " + str(configpath) + ". Make sure the file exists, the format is OK and you have correct access right.")
        exit(-1)
    # Init logger with config
    init_log(verbose=conf('verbose'),
        quiet=conf('quiet'),
        logfile=conf('log_file'))
    log.info("Read config file %s" % (configpath))

    # Check if WPScan exists
    if not is_wpscan_installed():
        log.error("WPScan not installed. Please install wpscan on your system. See https://wpscan.org for installation steps.")
        exit(-1)
    else:
        update_wpscan()
        try: 
            shutil.rmtree('/tmp/wpscan')
            log.info("Deleted temp WPScan files in /tmp/wpscan/")
        except FileNotFoundError: pass
    if conf('wp_sites') and type(conf('wp_sites')) is list and len(conf('wp_sites'))>0:
        # Run Scan
        exit(run_scan())
    else:
        log.error("No site to monitor. Please configure monitored sites in the config file: wp_sites")
        exit(-1)

if __name__ == '__main__':
    wpwatcher()