"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import re
import threading
import copy
import signal
import time
import threading
import concurrent.futures
from contextlib import contextmanager
from datetime import timedelta
from wpwatcher import log

# Few static helper methods -------------------

def timeout(timeout, func, args=(), kwargs={}):
    """ Run func with the given timeout. If func didn't finish running
        within the timeout, raise TimeoutError
    """
    class FuncThread(threading.Thread):
        def __init__(self):
            threading.Thread.__init__(self)
            self.result = None

        def run(self):
            self.result = func(*args, **kwargs)

    it = FuncThread()
    it.start()
    it.join(timeout)
    if it.isAlive():
        raise TimeoutError()
    else:
        return it.result

# Replace --api-token param with *** for safe logging
def safe_log_wpscan_args(wpscan_args):
    logged_cmd=copy.deepcopy(wpscan_args)
    if "--api-token" in "".join(logged_cmd) :
        logged_cmd=[ val.strip() for val in logged_cmd ]
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
    header = ("Site", "Status", "Last scan", "Last email", "Issues", "Problematic component(s)")
    sites_w=20
    # Determine the longest width for site column
    for r in results:
        sites_w=len(r['site'])+4 if r and len(r['site'])>sites_w else sites_w
    frow="{:<%d} {:<8} {:<20} {:<20} {:<8} {}"%sites_w
    string+=frow.format(*header)
    for row in results:
        pb_components=[]
        for m in row['alerts']+row['warnings']+row['errors']:
            pb_components.append(m.splitlines()[0])
        string+='\n'
        string+=frow.format(str(row['site']), 
            str(row['status']),
            str(row['datetime']),
            str(row['last_email']),
            len(row['alerts']+row['warnings']+row['errors']),
            ', '.join(pb_components) )
    return string

def parse_timedelta(time_str):
    """
    Parse a time string e.g. (2h13m) into a timedelta object.
    """
    regex = re.compile(r'^((?P<days>[\.\d]+?)d)?((?P<hours>[\.\d]+?)h)?((?P<minutes>[\.\d]+?)m)?((?P<seconds>[\.\d]+?)s)?$')
    time_str=replace(time_str,{
        'sec':'s',
        'second': 's',
        'seconds': 's',
        'minute':'m',
        'minutes':'m',
        'min':'m',
        'mn':'m',
        'days':'d',
        'day':'d',
        'hours':'h',
        'hour':'h'})
    parts = regex.match(time_str)
    if parts is None: raise ValueError("Could not parse any time information from '{}'.  Examples of valid strings: '8h', '2d8h5m20s', '2m4s'".format(time_str))
    time_params = {name: float(param) for name, param in parts.groupdict().items() if param}
    return timedelta(**time_params)

def replace(text, conditions):
    # rep = {"condition1": "", "condition2": "text"} # define desired replacements here
    rep=conditions
    # use these three lines to do the replacement
    rep = dict((re.escape(k), rep[k]) for k in rep ) 
    #Python 3 renamed dict.iteritems to dict.items so use rep.items() for latest versions
    pattern = re.compile("|".join(rep.keys()))
    text = pattern.sub(lambda m: rep[re.escape(m.group(0))], text)
    return text