#! /usr/bin/env python3
""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
from .cli import WPWatcherCLI
if __name__ == '__main__':
    WPWatcherCLI()