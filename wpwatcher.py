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
from subprocess import CalledProcessError
import argparse
import configparser
import io
from email.mime.text import MIMEText
from datetime import datetime

configuration=None

# Check if WPScan is installed
def is_wpscan_installed():
    try:
        result = subprocess.Popen([configuration.get('wpscan','wpscan_path'), '--version'], stdout=subprocess.PIPE).communicate()[0]
        if 'WordPress Security Scanner' in str(result): return 1
        else: return 0
        #result = check_output(r'./wpscan.rb --batch --url %s' % wp_site, stderr=STDOUT, shell=True, universal_newlines=True)
    except CalledProcessError:
        return 0

# Update WPScan from github
def update_wpscan():
    print("[INFO] Updating WPScan")
    try:
        result = subprocess.Popen([configuration.get('wpscan','wpscan_path'), '--update'], stdout=subprocess.PIPE).communicate()[0]
    except CalledProcessError as exc:
        print("[ERROR]", exc.returncode, exc.output)
    print(result.decode("utf-8"))

# Run WPScan on defined domains
def run_scan():
    print("[INFO] Starting scans on configured sites")
    # os.chdir(wpscan_dir)
    for wp_site in json.loads(configuration.get('wpscan','wp_sites')):

        # Scan ----------------------------------------------------------------
        try:
            print("[INFO] Scanning '%s'" % wp_site)
            result = subprocess.Popen([configuration.get('wpscan','wpscan_path')] + json.loads(configuration.get('wpscan','wpscan_args')) + ['--url', wp_site], stdout=subprocess.PIPE).communicate()[0]
            #result = check_output(r'./wpscan.rb --batch --url %s' % wp_site, stderr=STDOUT, shell=True, universal_newlines=True)
        except CalledProcessError as exc:
            print("[ERROR]", exc.returncode, exc.output)

        # Parse the results ---------------------------------------------------
        (warnings, alerts) = parse_results(result.decode("utf-8") )

        # Report Options ------------------------------------------------------
        # Email
        if configuration.getboolean('wpscan','send_email_report') and ( warnings or alerts ):
            send_report(wp_site, warnings, alerts)
        # Logfile
        try:
            with open(configuration.get('wpscan','log_file'), 'a') as log:
                for warning in warnings:
                    log.write("%s %s WARNING: %s\n" % (get_timestamp(), wp_site, warning))
                for alert in alerts:
                    log.write("%s %s ALERT: %s\n" % (get_timestamp(), wp_site, alert))
        except Exception as e:
            traceback.print_exc()
            print("[ERROR] Cannot write to log file")


# Parsing the results
def parse_results(results):

    warnings = []
    alerts = []
    warning_on = False
    alert_on = False
    last_message = ""

    # Parse the lines
    for line in results.splitlines():

        # Remove colorization
        line = re.sub(r'(\x1b|\[[0-9][0-9]?m)','',line)

        # Empty line = end of message
        if line == "" or line.startswith("[+]"):
            if warning_on:
                if not is_false_positive(warning):
                    warnings.append(warning)
                warning_on = False
            if alert_on:
                if not is_false_positive(alert):
                    alerts.append(alert)
                alert_on = False

        # Add to warning/alert
        if warning_on:
            warning += " / %s" % line.lstrip(" ")
        if alert_on:
            alert += " / %s" % line.lstrip(" ")

        # Start Warning/Alert
        if line.startswith("[i]"):
            # Warning message
            warning = "%s / %s" % ( last_message, line )
            warning_on = True
        if line.startswith("[!]"):
            # Warning message
            alert = line
            alert_on = True

        # Store lase message
        last_message = line

    return ( warnings, alerts )


# Send email report
def send_report(wp_site, warnings, alerts):

    to_email = json.loads(configuration.get('wpscan','wp_sites'))[wp_site] + ' ' +configuration.get('wpscan','email_report_recepient')

    print("[INFO] Sending email report stating items found on %s to %s" % (wp_site, to_email))

    try:
        message = "Issues have been detected by WPScan on one of your sites\n"

        if warnings:
            message += "\nWarnings\n"
            message += "\n".join(warnings)

        if alerts:
            message += "\nAlerts\n"
            message += "\n".join(alerts)

        mime_msg = MIMEText(message)

        mime_msg['Subject'] = 'WPWatcher report on %s - %s' % (wp_site, get_timestamp())
        mime_msg['From'] = configuration.get('wpscan','from_email')
        mime_msg['To'] = to_email

        # SMTP Connection
        s = smtplib.SMTP(configuration.get('wpscan','smtp_server'))
        s.ehlo()
        # SSL
        if configuration.getboolean('wpscan','smtp_ssl'):
            s.starttls()
        # SMTP Auth
        if configuration.getboolean('wpscan','smtp_auth'):
            s.login(configuration.get('wpscan','smtp_user'), configuration.get('wpscan','smtp_pass'))
        # Send Email
        s.sendmail(configuration.get('wpscan','from_email'), to_email, mime_msg.as_string())
        s.quit()

    except Exception as e:
        traceback.print_exc()


# Is the line defined as false positive
def is_false_positive(string):
    # False Positive Detection
    for fp_string in json.loads(configuration.get('wpscan','false_positive_strings')):
        if fp_string in string:
            # print fp_string, string
            return 1
    return 0


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
    except: return False
    return True

def parse_args():

    parser = argparse.ArgumentParser(description='Wordpress Watcher. Automating WPscan to scan and report vulnerable Wordpress sites')
    parser.add_argument('--conf', metavar='Config file', help="Path to the config file. Will use ./wpwatcher.conf or ~/wpwatcher.conf if left none")
    args = parser.parse_args()
    return args

if __name__ == '__main__':
    args=parse_args()

    if args.conf: 
        if not read_config(args.conf):
            print("[ERROR] Could not read config " + str(args.conf))
            exit(128)
    else:
        if not find_config_file():
            print("[ERROR] Could not find config file ")
            exit(128)
        else:
            if not read_config(find_config_file()):
                print("[ERROR] Could not read config " + str(find_config_file()))
                exit(128)

    # Check if WPScan exists
    if not is_wpscan_installed():
        print("[ERROR] WPScan not installed.\nPlease install wpscan on your system.\nSee https://wpscan.org for installation steps.")
        exit(128)
    else:
        update_wpscan()

    # Run Scan
    run_scan()
