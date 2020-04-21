"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import logging
import re
import os
import sys
import copy
import signal
from contextlib import contextmanager
from datetime import timedelta
from . import log
# Few static helper methods -------------------
@contextmanager
def timeout(time):
    # Register a function to raise a TimeoutError on the signal.
    # Code from https://www.jujens.eu/posts/en/2018/Jun/02/python-timeout-function/
    signal.signal(signal.SIGALRM, raise_timeout)
    # Schedule the signal to be sent after ``time``.
    signal.alarm(time)
    try: yield
    except TimeoutError: raise
    finally:
        # Unregister the signal so it won't be triggered
        # if the timeout is not reached.
        signal.signal(signal.SIGALRM, signal.SIG_IGN)

def raise_timeout(signum, frame):
    raise TimeoutError

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
