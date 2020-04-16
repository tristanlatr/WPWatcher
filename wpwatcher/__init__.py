# -*- coding: utf-8 -*-
"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import logging
# Setup configuration: will be parsed by setup.py -------------------
# Values must be in one line
# Project version.
VERSION='2.0.2'
# URL that will be displayed in help and other places
GIT_URL="https://github.com/tristanlatr/WPWatcher"
# Authors
AUTHORS="Florian Roth, Tristan Landès"
# Global variables ------------------
# Global log handler
log = logging.getLogger('wpwatcher')
