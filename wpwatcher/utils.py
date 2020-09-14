"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import re
import threading
import sys
import copy
import threading
import queue
from datetime import timedelta
from wpwatcher import log

# Few static helper methods -------------------

def timeout(timeout, func, args=(), kwargs={}):
    """ Run func with the given timeout. If func didn't finish running
        within the timeout, raise TimeoutError
    """
    class FuncThread(threading.Thread):
        def __init__(self, bucket):
            threading.Thread.__init__(self)
            self.result = None
            self.bucket = bucket
            self.err = None

        def run(self):
            try: self.result = func(*args, **kwargs)
            except Exception as err: 
                self.bucket.put(sys.exc_info())
                self.err=err
   
    bucket=queue.Queue()
    it = FuncThread(bucket)
    it.start()
    it.join(timeout)
    if it.is_alive(): raise TimeoutError()
    else:
        try: _, _, exc_trace = bucket.get(block=False)
        except queue.Empty: return it.result
        else: raise it.err.with_traceback(exc_trace)

def safe_log_wpscan_args(wpscan_args):
    '''Replace --api-token param with *** for safe logging'''
    logged_cmd=copy.deepcopy(wpscan_args)
    if "--api-token" in "".join(logged_cmd) :
        logged_cmd=[ val.strip() for val in logged_cmd ]
        logged_cmd[logged_cmd.index("--api-token")+1]="***"
    return logged_cmd

def oneline(string):
    '''Helper method that transform multiline string to one line for grepable output'''
    return( " ".join(line.strip() for line in string.splitlines()) )

def get_valid_filename(s):
    '''Return the given string converted to a string that can be used for a clean filename.  Stolen from Django I think'''
    s = str(s).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w.]', '', s)

def print_progress_bar(count,total):
    """Helper method to print progress bar.  Stolen on the web"""
    size=0.3 #size of progress bar
    percent = int(float(count)/float(total)*100)
    log.info( "Progress - [{}{}] {}% - {} / {}".format('='*int(int(percent)*size), ' '*int((100-int(percent))*size), percent, count, total) )

def results_summary(results):
    '''Print the summary table of all sites.  
    Columns : "Site", "Status", "Last scan", "Last email", "Issues", "Problematic component(s)"
    '''
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
        for m in row['alerts']+row['warnings']:
            pb_components.append(m.splitlines()[0])
        if row['error']:
            pb_components.append("Scan failed")
        string+='\n'
        string+=frow.format(str(row['site']), 
            str(row['status']),
            str(row['datetime']),
            str(row['last_email']),
            len(row['alerts']+row['warnings']),
            ', '.join(pb_components) )
    return string

def parse_timedelta(time_str):
    """
    Parse a time string e.g. (2h13m) into a timedelta object.  Stolen on the web
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
    '''Multiple replacements helper method.  Stolen on the web'''
    rep=conditions
    rep = dict((re.escape(k), rep[k]) for k in rep ) 
    pattern = re.compile("|".join(rep.keys()))
    text = pattern.sub(lambda m: rep[re.escape(m.group(0))], text)
    return text