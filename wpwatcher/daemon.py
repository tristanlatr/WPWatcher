""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import time
from . import log
from .core import WPWatcher
from .db import WPWatcherDataBase

# WPWatcher class ---------------------------------------------------------------------
class WPWatcherDaemon():
    def __init__(self, conf):
        log.info("Daemon mode selected, looping for ever...")
        # keep data in memory
        wpwatcher=WPWatcher(conf)
        while True:
            # Run scans for ever
            wpwatcher.run_scans_and_notify()
            log.info("Daemon sleeping %s and scanning again..."%conf['daemon_loop_sleep'])
            time.sleep(conf['daemon_loop_sleep'].total_seconds())
            