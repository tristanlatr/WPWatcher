#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Wordpress Watcher
# Automating WPscan to scan and report vulnerable Wordpress sites
# v0.3
# DISCLAIMER - USE AT YOUR OWN RISK.

import os
import re
import json
import smtplib
import traceback
import subprocess
import logging
from subprocess import CalledProcessError
import argparse
import configparser
import io
from email.mime.text import MIMEText
from datetime import datetime

configuration=None
log = logging.getLogger('wpwatcher')

# Setup logger
def init_log(verbose=False, quiet=False, logfile=None):
    format_string='%(asctime)s - %(levelname)s - %(message)s'
    if verbose : verb_level=logging.DEBUG
    elif quiet : verb_level=logging.ERROR
    else : verb_level=logging.INFO
    log.setLevel(verb_level)
    std = logging.StreamHandler()
    std.setLevel(verb_level)
    std.setFormatter(logging.Formatter(format_string))
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
        result = subprocess.Popen([conf('wpscan_path'), '--version'], stdout=subprocess.PIPE).communicate()[0]
        if 'WordPress Security Scanner' in str(result): return 1
        else: return 0
    except CalledProcessError:
        return 0

# Update WPScan from github
def update_wpscan():
    log.info("Updating WPScan")
    try:
        process = subprocess.Popen([conf('wpscan_path'), '--update'], stdout=subprocess.PIPE)
        result, _  = process.communicate()
        if process.returncode :
            log.error("WPScan failed with exit code: %s \n %s" % ( str(process.returncode), str(result.decode("utf-8") ) ) )
            log.error("Error updating wpscan")
    except CalledProcessError as exc:
        log.error("WPScan failed with exit code: %s \n %s" % ( str(exc.returncode), str(exc.output) ) ) 
        log.error("Error updating wpscan")
    log.debug(result.decode("utf-8"))

# Run WPScan on defined domains
def run_scan():
    log.info("Starting scans on configured sites")
    for wp_site in conf('wp_sites'):
        exit_code=0
        # Read the wp_site dict and assing default values if needed ----------
        if 'url' not in wp_site or wp_site['url']=="":
            log.error("Site must have valid a 'url' key: %s" % (str(wp_site)))
            exit_code=-1
            continue
        if 'email_to' not in wp_site or wp_site['email_to'] is None: wp_site['email_to']=[]
        if 'false_positive_strings' not in wp_site or wp_site['false_positive_strings'] is None: wp_site['false_positive_strings']=[]
        if 'wpscan_args' not in wp_site or wp_site['wpscan_args'] is None: wp_site['wpscan_args']=[]

        # Scan ----------------------------------------------------------------
        try:
            
            cmd=[conf('wpscan_path')] + conf('wpscan_args') + wp_site['wpscan_args'] + ['--url', wp_site['url']]
            log.info("Scanning '%s' with command: %s" % (wp_site['url'], ' '.join(cmd)))
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE )
            result, _  = process.communicate()
            if process.returncode :
                log.error("WPScan failed with exit code: %s. Output: %s" % ( str(process.returncode), " ".join(line.strip() for line in str(result.decode("utf-8")).splitlines()) ) )
                exit_code=-1
            else:
                # Print results
                log.debug(result.decode("utf-8"))
        
        except CalledProcessError as exc:
            log.error("WPScan failed with exit code: %s %s" % ( str(exc.returncode), " ".join(line.strip() for line in str(exc.output).splitlines()) ) )
            exit_code=-1

        # Parse the results ---------------------------------------------------
        (warnings, alerts) = parse_results(result.decode("utf-8") , wp_site['false_positive_strings'] )

        # Report Options ------------------------------------------------------
        # Email
        if conf('send_email_report') and ( len(warnings)>0 or len(alerts)>0 or conf('always_send_reports')):
            if not send_report(wp_site, warnings, alerts,
                fulloutput=result.decode("utf-8") if conf('verbose') else None):
                exit_code=-1

        # Logfile
        for warning in warnings:
            log.warning("** WPScan INFO ** %s %s" % (wp_site['url'], warning))
        for alert in alerts:
            log.warning("** WPScan ALERT ** %s %s" % (wp_site['url'], alert))
    if exit_code == 0:
        log.info("Scans finished successfully.") 
    else:
        log.info("Scans finished with errors.") 
    return(exit_code)

# Is the line defined as false positive
def is_false_positive(string, site_false_positives):
    # False Positive Detection
    for fp_string in conf('false_positive_strings')+site_false_positives:
        if fp_string in string:
            # print fp_string, string
            return 1
    return 0

# Parsing the results
def parse_results(results, site_false_positives):
    warnings = []
    alerts = []
    warning_on = False
    alert_on = False
    message=str()
    # Parse the lines
    for line in results.splitlines():
        # Remove colorization snd strip
        line = re.sub(r'(\x1b|\[[0-9][0-9]?m)','',line).strip()
        # [+] = Begin of the message
        if line.startswith("[+]") or line.startswith("[i]") or line.startswith("[!]"):
            if warning_on:
                if not is_false_positive(message, site_false_positives):
                    warnings.append(message)
                warning_on = False
            if alert_on:
                if not is_false_positive(message, site_false_positives):
                    alerts.append(message)
                alert_on = False
            message=str()        
        # Start Warning/Alert
        if "[i]" in line:
            warning_on = True
        if "[!]" in line:
            alert_on = True
        # Append message line
        message+='\n'+line
    return ( warnings, alerts )


# Send email report
def send_report(wp_site, warnings, alerts, fulloutput=None):

    to_email = ','.join( wp_site['email_to'] + conf('email_to') )

    log.info("Sending email report stating items found on %s to %s" % (wp_site['url'], to_email))

    try:
        if (warnings or alerts) :message = "Issues have been detected by WPScan on one of your sites: %s" % (wp_site['url'])
        else: message = "Here is the last WPScan report of your site"
        
        if alerts:
            message += "\n\n\tAlerts\n\n"
            message += "\n\n".join(alerts)

        if warnings:
            message += "\n\n\tWarnings\n\n"
            message += "\n\n".join(warnings)

        if fulloutput:
            message += "\n\n\tFull WPScan output\n\n"
            message += fulloutput

        mime_msg = MIMEText(message)

        mime_msg['Subject'] = 'WPWatcher report on %s - %s' % (wp_site['url'], get_timestamp())
        mime_msg['From'] = conf('from_email')
        mime_msg['To'] = to_email

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
        return(0)

    except Exception as err:
        log.error(str(err))
        log.error("Unable to send mail report of " + wp_site['url'] + "to " + to_email)
        return(False)


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
        configuration.read(configpath)
    except Exception as err: 
        log.error(err)
        return False
    return True

def conf(key):
    if configuration:
        # Boolean conf values
        if key in ['send_email_report', 'smtp_auth', 'smtp_ssl', 'verbose', 'quiet']:
            return configuration.getboolean('wpwatcher', key)
        # JSON lists conf values
        elif key in ['wp_sites', 'email_to', 'wpscan_args', 'false_positive_strings']:
            try:
                loaded=json.loads(configuration.get('wpwatcher', key))
            except Exception as err:
                log.error(err)
                log.error("Could not read JSON value of key: %s for string: %s" % (key, configuration.get('wpwatcher', key)))
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

if __name__ == '__main__':
    init_log()
    args=parse_args()
    # Read config
    configpath=None
    if args.conf: 
        configpath=args.conf
    else:
        if not find_config_file():
            log.error("Could not find config file")
            exit(-1)
        else:
            configpath=find_config_file()
    if not read_config(configpath):
        log.error("Could not read config " + str(configpath))
        exit(-1)
    # Init logger with config
    init_log(verbose=conf('verbose'),
        quiet=conf('quiet'),
        logfile=conf('log_file'))
    log.info("Read config file %s" % (configpath))

    # Check if WPScan exists
    if not is_wpscan_installed():
        log.error("WPScan not installed.\nPlease install wpscan on your system.\nSee https://wpscan.org for installation steps.")
        exit(-1)
    else:
        update_wpscan()

    # Run Scan
    exit(run_scan())