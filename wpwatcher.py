#! /usr/bin/env python3
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# Wordpress Watcher
# Automating WPscan to scan and report vulnerable Wordpress sites
# DISCLAIMER - USE AT YOUR OWN RISK.

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
import collections.abc
from email.mime.text import MIMEText
from datetime import datetime

# Local module
from wpscan_parser import parse_results

# WPWatcher class ---------------------------------------------------------------------

class WPWatcher():

    # WPWatcher must use a configuration dict
    def __init__(self, conf):
        self.conf=conf

         # Init logger with config
        init_log(verbose=self.conf['verbose'],
            quiet=self.conf['quiet'],
            logfile=self.conf['log_file'])

        # Check if WPScan exists
        if not self.is_wpscan_installed():
            log.error("WPScan not installed. Please install wpscan on your system. See https://wpscan.org for installation steps.")
            exit(-1)

        # Update wpscan database
        self.update_wpscan()

        # Delete temp files.
        try: 
            shutil.rmtree('/tmp/wpscan')
            log.info("Deleted temp WPScan files in /tmp/wpscan/")
        except FileNotFoundError: pass

    # Check if WPScan is installed
    def is_wpscan_installed(self):
        try:
            wpscan_output = subprocess.Popen([self.conf['wpscan_path'], '--version'], stdout=subprocess.PIPE).communicate()[0]
            if 'WordPress Security Scanner' in str(wpscan_output): return 1
            else: return 0
        except CalledProcessError:
            return 0

    # Update WPScan database
    def update_wpscan(self):
        log.info("Updating WPScan")
        try:
            process = subprocess.Popen([self.conf['wpscan_path'], '--update'], stdout=subprocess.PIPE)
            wpscan_output, _  = process.communicate()
            if process.returncode :
                log.error("WPScan failed with exit code: %s \n %s" % ( str(process.returncode), str(wpscan_output.decode("utf-8") ) ) )
                log.error("Error updating wpscan")
                exit(-1)
        except CalledProcessError as err:
            log.error("WPScan failed: %s" % ( str(err) ) ) 
            log.error("Error updating wpscan")
            exit(-1)

    # Send email report with status and timestamp
    def send_report(self, wp_site, warnings=None, alerts=None, infos=None, errors=None, emails=None, status=None):
        if emails: to_email=','.join( emails )
        else: to_email = ','.join( wp_site['email_to'] + self.conf['email_to'] )
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
            mime_msg['Subject'] = 'WPWatcher%s report on %s - %s' % (   ' '+status if status else '',
                                                                        wp_site['url'],
                                                                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            mime_msg['From'] = self.conf['from_email']
            mime_msg['To'] = to_email
            # Connecting and sending
            log.info("Sending %s to %s" % (mime_msg['Subject'], to_email))
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
            s.sendmail(self.conf['from_email'], to_email, mime_msg.as_string())
            s.quit()
            return(True)
        else:
            log.warning("Not sending WPWatcher %s email report because no email are configured for site %s"%(status,wp_site['url']))
            return(True)

    # Run WPScan on defined websites
    def run_scans_and_notify(self):

        log.info("Starting scans on configured sites")
        exit_code=0
        for wp_site in self.conf['wp_sites']:
            # Init scan variables
            errors=[]
            (messages, warnings, alerts)=([],[],[])
            # Read the wp_site dict and assing default values if needed -------------
            if 'url' not in wp_site or wp_site['url']=="":
                log.error("Site must have valid a 'url' key: %s" % (str(wp_site)))
                exit_code=-1
                continue
            if 'email_to' not in wp_site or wp_site['email_to'] is None: wp_site['email_to']=[]
            if 'false_positive_strings' not in wp_site or wp_site['false_positive_strings'] is None: wp_site['false_positive_strings']=[]
            if 'wpscan_args' not in wp_site or wp_site['wpscan_args'] is None: wp_site['wpscan_args']=[]
            
            # WPScan arguments
            wpscan_arguments=self.conf['wpscan_args']+wp_site['wpscan_args']
            cmd=[self.conf['wpscan_path']] + wpscan_arguments + ['--url', wp_site['url']]
            log.info("Scanning site %s with command: %s" % (wp_site['url'], ' '.join(cmd)))
            
            # Scan -------------------------------------------------------------------
            try:
                # Launch wpscan command
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE )
                wpscan_output, _  = process.communicate()
                wpscan_output=wpscan_output.decode("utf-8")
                log.debug("WPScan raw output:\n"+wpscan_output)

                # The target has at least one vulnerability.
                # Currently, the interesting findings do not count as vulnerable things
                # Vulnerable WordPress See https://github.com/wpscanteam/CMSScanner/blob/master/lib/cms_scanner/exit_code.rb

                if process.returncode in [1,2,3,4]:
                    # Handle scan error
                    err_string="WPScan failed with exit code %s for site: %s. WPScan output: \n%s" % (str(process.returncode), wp_site['url'], wpscan_output)
                    log.error(" ".join(line.strip() for line in err_string.splitlines()))
                    errors.append(err_string)
                    exit_code=-1

                # Even is the scan is a success, WPScan can return code 0 or 5 (vulnerable)

            except CalledProcessError as err:
                # Handle scan error --------------------------------------------------
                wpscan_output=str(err.output)
                err_string="Failed to launch WPScan command with exit code %s for site: %s. WPScan output: \n%s"  % (str(process.returncode), wp_site['url'], wpscan_output)
                log.error(" ".join(line.strip() for line in err_string.splitlines()))
                errors.append(err_string)
                exit_code=-1
            
            # Parse the results if no errors with wpscan -----------------------------
            if len(errors)==0:
                try:
                    log.debug("Parsing WPScan output")
                    # Call parse_result from wpscan_parser.py ------------------------
                    (messages, warnings, alerts) = parse_results(wpscan_output , 
                        self.conf['false_positive_strings']+wp_site['false_positive_strings'] )

                except Exception as err:
                    err_string="Could not parse the results from wpscan command for site {}.\nError: {}\nWPScan output: {}".format(wp_site['url'],str(err), wpscan_output)
                    log.error(err_string)
                    errors.append(err_string)
                    exit_code=-1
                    
                # Logfile ------------------------------------------------------
                for message in messages:
                    log.info("** WPScan INFO %s ** %s" % (wp_site['url'], " ".join(line.strip() for line in str(message).splitlines())))
                for warning in warnings:
                    log.warning("** WPScan WARNING %s ** %s" % (wp_site['url'], " ".join(line.strip() for line in str(warning).splitlines()) ))
                for alert in alerts:
                    log.critical("** WPScan ALERT %s ** %s" % (wp_site['url'], " ".join(line.strip() for line in str(alert).splitlines())))
            
            # Determining status ------------------------------------------------
            status=None
            if len(errors)>0:status="ERROR"
            elif len(warnings)>0 and len(alerts) == 0: status='WARNING'
            elif len(alerts)>0: status='ALERT'
            else: status='INFO'

            if self.conf['send_email_report']:
                try:
                    # Email errors -------------------------------------------------------
                    if len(errors)>0:
                        if self.conf['send_errors']:
                            if len(self.conf['email_errors_to'])>0:
                                self.send_report(wp_site, warnings, alerts, infos=messages, errors=errors, emails=self.conf['email_errors_to'], status=status)
                            else: 
                                self.send_report(wp_site, warnings, alerts, infos=messages, errors=errors, status=status)
                        else:
                            log.info("No WPWatcher ERROR email report have been sent for site %s. If you want to receive error emails, set send_errors=Yes in the config."%(wp_site['url']))
                    # Email -------------------------------------------------------------------
                    else:
                        
                        if self.conf['send_infos'] or ( status=="WARNING" and self.conf['send_warnings'] ) or status=='ALERT':
                            self.send_report(wp_site, alerts=alerts,
                                warnings=warnings if self.conf['send_warnings'] or self.conf['send_infos'] else None,
                                infos=messages if self.conf['send_infos'] else None,
                                status=status)
                        else: 
                            # No report notice
                            log.info("No WPWatcher %s email report have been sent for site %s. If you want to receive more emails, send_warnings=Yes or set send_infos=Yes in the config."%(status,wp_site['url']))
                # Handle send mail error
                except Exception as err:
                    log.error("Unable to send mail report for site " + wp_site['url'] + ". Error: "+str(err))
                    exit_code=12
            else:
                # No report notice
                log.info("No WPWatcher %s email report have been sent for site %s. If you want to receive emails, set send_email_report=Yes in the config."%(status, wp_site['url']))
        
        if exit_code == 0:
            log.info("Scans finished successfully.") 
        else:
            log.info("Scans finished with errors.") 
        return(exit_code)

# WPWatcherConfig class -------------------------------------------------------

class WPWatcherConfig(collections.abc.Mapping):

    def __init__(self, files=None, conf=None):
        super().__init__()
        self._conf={}
        try:
            # Load the configuration file
            conf_parser = configparser.ConfigParser()
            # Applying default conf
            conf_parser.read_dict({
                    'wpwatcher':{
                            'wp_sites' :'null',
                            'false_positive_strings' : 'null',                        
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
            # Search ~/wpwatcher.conf if file is not specified
            if not files or len(files)==0:
                default_config_file=self.find_config_file()
                if default_config_file:
                    files=[default_config_file]

            if not files: 
                log.info("Could not find default config at ./wpwatcher.conf or ~/wpwatcher.conf.")
                log.info("No config file is configured, mail server settings, WPScan path and arguments can't be configured with CLI parameters.")

            # Reading config 
    
            # File
            if files:
                if len(conf_parser.read(files))==0:
                    log.error("Could not read config " + str(files) + ". Make sure the file exists, the format is OK and you have correct access right.")
                    exit(-1)

            # Saving config file in right dict format - no 'wpwatcher' item, just config
            self._conf = {
                'wp_sites' :self.getjson(conf_parser,'wp_sites'),
                'false_positive_strings' : self.getjson(conf_parser,'false_positive_strings'), 
                'wpscan_args':self.getjson(conf_parser,'wpscan_args'),
                'send_email_report':self.getbool(conf_parser, 'send_email_report'),
                'send_errors':self.getbool(conf_parser, 'send_errors'),
                'email_to':self.getjson(conf_parser,'email_to'),
                'email_errors_to':self.getjson(conf_parser,'email_errors_to'),
                'send_warnings':self.getbool(conf_parser, 'send_warnings'),
                'send_infos':self.getbool(conf_parser, 'send_infos'),
                'quiet':self.getbool(conf_parser, 'quiet'),
                'verbose':self.getbool(conf_parser, 'verbose'),
                # not configurable with cli params
                'log_file':conf_parser.get('wpwatcher','log_file'),
                'wpscan_path':conf_parser.get('wpwatcher','wpscan_path'),
                'smtp_server':conf_parser.get('wpwatcher','smtp_server'),
                'smtp_auth':self.getbool(conf_parser, 'smtp_auth'),
                'smtp_user':conf_parser.get('wpwatcher','smtp_user'),
                'smtp_pass':conf_parser.get('wpwatcher','smtp_pass'),
                'smtp_ssl':self.getbool(conf_parser, 'smtp_ssl'),
                'from_email':conf_parser.get('wpwatcher','from_email')
            }

            # WPWatcherConfig conf Args
            if conf:
                # Apply arguments
                # log.info("Applying config from aguments: "+str(conf))
                self._conf.update(conf)

        except Exception as err: 
            log.error("Could not read config " + str(files) + ". Error: "+str(err))
            exit(-1)
    
    def __getitem__(self, key): 
        return self._conf[key]
    def __len__(self):
        return len(self._conf)
    def __iter__(self):
        return iter(self._conf)

    @staticmethod
    def getjson(conf, key):
        string_val=conf.get('wpwatcher', key)
        try:
            loaded=json.loads(string_val)
            return loaded if loaded else []
        except Exception as err:
            log.error("Could not read config JSON value for: '%s' and string: '%s'. Error: %s" % (key, conf.get('wpwatcher',key), str(err)))
            exit(-1)
    @staticmethod
    def getbool(conf, key):
        try:
            return conf.getboolean('wpwatcher', key)
        except Exception as err:
            log.error("Could not read boolean value in config for: '{}' and string '{}'. Must be Yes/No. Error: {}".format(key, conf.get('wpwatcher',key), str(err)))
            exit(-1)

    @staticmethod
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

# Main module 

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
        log.warning("Verbose and quiet values are both set to True. By default, verbose value has priority.")
    return (log)

# Arguments can overwrite config file values
def parse_args():
    parser = argparse.ArgumentParser(description='WordPress Watcher is a Python wrapper for WPScan that manages scans on multiple sites and reports by email. Some config arguments can be passed to the command. Warning: it will overwrite previous values from config file. Check https://github.com/tristanlatr/WPWatcher for more informations.')
    parser.add_argument('--conf', metavar='File path', help="Path to the config file(s). You can specify multiple files. Will try ./wpwatcher.conf or ~/wpwatcher.conf if left none. If no config file is found, mail server settings, WPScan path and arguments will have default values.", nargs='+', default=[])
    parser.add_argument('--send_email_report', help="", action='store_true')
    parser.add_argument('--send_infos', help="", action='store_true')
    parser.add_argument('--send_errors', help="", action='store_true')
    parser.add_argument('--wp_sites',  metavar="URL", help="", nargs='+', default=[])
    parser.add_argument('--email_to',  metavar="Email", help="", nargs='+', default=[])
    parser.add_argument('--email_errors_to', metavar="Email", help="", nargs='+', default=[])
    parser.add_argument('--false_positive_strings',  metavar="String", help="", nargs='+', default=[])
    parser.add_argument('-v','--verbose', help="", action='store_true')
    parser.add_argument('-q','--quiet', help="", action='store_true')
    args = parser.parse_args()
    return(args)

# Main program
def wpwatcher():
    init_log()
    args=parse_args()
    # Config file
    conf_files=args.conf
    # Parse config from args
    conf_from_args={}
    if args.quiet:
        conf_from_args['quiet']=True
        init_log(quiet=True)
    if args.verbose:
        conf_from_args['verbose']=True
        init_log(verbose=True)
    if args.send_email_report:
        conf_from_args['send_email_report']=True
    if args.send_infos:
        conf_from_args['send_infos']=True
    if args.send_errors:
        conf_from_args['send_errors']=True
    if len(args.wp_sites)>0:
        conf_from_args['wp_sites']=[ {"url":site} for site in args.wp_sites ]
    if len(args.false_positive_strings)>0:
        conf_from_args['false_positive_strings']=args.false_positive_strings
    if len(args.email_to)>0:
        conf_from_args['email_to']=args.email_to
    if len(args.email_errors_to)>0:
        conf_from_args['email_errors_to']=args.email_errors_to
    # Init config dict: read config file and overwrite with config params
    conf=WPWatcherConfig(files=conf_files, conf=conf_from_args)
    # Create main object
    wpwatcher=WPWatcher(conf)
    # Launch scans and quit
    exit(wpwatcher.run_scans_and_notify())

if __name__ == '__main__':
    wpwatcher()