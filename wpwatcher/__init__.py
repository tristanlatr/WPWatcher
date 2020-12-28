# -*- coding: utf-8 -*-
"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import logging
import sys
import os
from typing import Optional

log = logging.getLogger("wpwatcher")
"Log handler"

# Setup stdout logger
def _init_log(
    verbose: bool = False,
    quiet: bool = False,
    logfile: Optional[str] = None,
    nostd: bool = False,
) -> logging.Logger:

    format_string = "%(asctime)s - %(levelname)s - %(message)s"
    format_string_cli = "%(levelname)s - %(message)s"
    if verbose:
        verb_level = logging.DEBUG
    elif quiet:
        verb_level = logging.ERROR
    else:
        verb_level = logging.INFO
    
    # Add stdout: configurable
    log.setLevel(verb_level)
    std = logging.StreamHandler(sys.stdout)
    std.setLevel(verb_level)
    std.setFormatter(logging.Formatter(format_string_cli))
    log.handlers = []
    if not nostd:
        log.addHandler(std)
    else:
        log.addHandler(logging.StreamHandler(open(os.devnull, "w")))
    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setLevel(verb_level)
        fh.setFormatter(logging.Formatter(format_string))
        log.addHandler(fh)
    if verbose and quiet:
        log.info(
            "Verbose and quiet values are both set to True. By default, verbose value has priority."
        )
    return log
