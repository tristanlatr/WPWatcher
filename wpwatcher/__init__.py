# -*- coding: utf-8 -*-
"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import logging
import sys
import os
# Setup configuration: will be parsed by setup.py -------------------
# Values must be in one line
# Project version.
VERSION='2.1.dev'
# URL that will be displayed in help and other places
GIT_URL="https://github.com/tristanlatr/WPWatcher"
# Authors
AUTHORS="Florian Roth, Tristan Landès"
# Global variables ------------------
# Global log handler
log = logging.getLogger('wpwatcher')

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