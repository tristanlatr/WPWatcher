"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import logging
import re
import os
import sys
import socket
import copy
from datetime import timedelta

from wpwatcher import VERSION, log

# Few static helper methods -------------------

# Setup stdout logger
def init_log(verbose=False, quiet=False, logfile=None, nostd=False):
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
    if not nostd: log.addHandler(std)
    else: log.addHandler(logging.StreamHandler(open(os.devnull,'w')))
    if logfile :
        fh = logging.FileHandler(logfile)
        fh.setLevel(verb_level)
        fh.setFormatter(logging.Formatter(format_string))
        log.addHandler(fh)
    if verbose and quiet :
        log.info("Verbose and quiet values are both set to True. By default, verbose value has priority.")
    return (log)

# Replace --api-token param with *** for safe logging
def safe_log_wpscan_args(wpscan_args):
    logged_cmd=copy.deepcopy(wpscan_args)
    if "--api-token" in logged_cmd :
        logged_cmd[logged_cmd.index("--api-token")+1]="***"
    return logged_cmd

# Helper method that transform multiline string to one line for grepable output
def oneline(string):
    return( " ".join(line.strip() for line in string.splitlines()) )

# Return the given string converted to a string that can be used for a clean filename
def get_valid_filename(s):
    s = str(s).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w.]', '', s)

# Build the email report string
def build_message(wp_report, warnings=True, infos=False):
    
    message="WordPress security scan report for site: %s\n" % (wp_report['site'])
    message+="Scan datetime: %s\n" % (wp_report['datetime'])
    
    if wp_report['errors'] : message += "\nAn error occurred."
    elif wp_report['alerts'] : message += "\nVulnerabilities have been detected by WPScan."
    elif wp_report['warnings']: message += "\nIssues have been detected by WPScan."
    if wp_report['fixed']: message += "\nSome issues have been fixed since last scan."
    
    if wp_report['errors']:
        message += "\n\n\tErrors\n\t------\n\n"
        message += "\n\n".join(wp_report['errors'])
    if wp_report['alerts']:
        message += "\n\n\tAlerts\n\t------\n\n"
        message += "\n\n".join(wp_report['alerts'])
    if wp_report['fixed']:
        message += "\n\n\tFixed\n\t-----\n\n"
        message += "\n\n".join(wp_report['fixed'])
    if wp_report['warnings'] and warnings :
        message += "\n\n\tWarnings\n\t--------\n\n"
        message += "\n\n".join(wp_report['warnings'])
    if wp_report['infos'] and infos :
        message += "\n\n\tInformations\n\t------------\n\n"
        message += "\n\n".join(wp_report['infos'])
    
    message += "\n\n--"
    message += "\nWPWatcher -  Automating WPscan to scan and report vulnerable Wordpress sites"
    message += "\nServer: %s - Version: %s\n"%(socket.gethostname(),VERSION)
    return message

def print_progress_bar(count,total):
    size=0.3 #size of progress bar
    percent = int(float(count)/float(total)*100)
    log.info( "Progress - [{}{}] {}% - {} / {}".format('='*int(int(percent)*size), ' '*int((100-int(percent))*size), percent, count, total) )

def results_summary(results):
    string='Results summary\n'
    header = ("Site", "Status", "Last email", "Issues", "Problematic component(s)")
    sites_w=20
    # Determine the longest width for site column
    for r in results:
        sites_w=len(r['site'])+4 if r and len(r['site'])>sites_w else sites_w
    frow="{:<%d} {:<8} {:<20} {:<8} {}"%sites_w
    string+=frow.format(*header)
    for row in results:
        pb_components=[]
        for m in row['alerts']+row['warnings']+row['errors']:
            pb_components.append(m.splitlines()[0])
        string+='\n'
        string+=frow.format(row['site'], 
            row['status'],
            str(row['last_email']),
            len(row['alerts']+row['warnings']+row['errors']),
            ', '.join(pb_components) )
    return string

def parse_timedelta(time_str):
    """
    Parse a time string e.g. (2h13m) into a timedelta object.
    """
    regex = re.compile(r'^((?P<days>[\.\d]+?)d)?((?P<hours>[\.\d]+?)h)?((?P<minutes>[\.\d]+?)m)?((?P<seconds>[\.\d]+?)s)?$')
    parts = regex.match(time_str)
    assert parts is not None, "Could not parse any time information from '{}'.  Examples of valid strings: '8h', '2d8h5m20s', '2m4s'".format(time_str)
    time_params = {name: float(param) for name, param in parts.groupdict().items() if param}
    return timedelta(**time_params)
