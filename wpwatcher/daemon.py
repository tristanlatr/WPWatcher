""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import time
from wpwatcher import log
from wpwatcher.core import WPWatcher


class WPWatcherDaemon:
    def __init__(self, conf):
        log.info("Daemon mode selected, looping for ever...")
        # keep data in memory
        wpwatcher = WPWatcher(conf)
        while True:
            # Run scans for ever
            wpwatcher.run_scans_and_notify()
            log.info(
                f"Daemon sleeping {conf['daemon_loop_sleep']} and scanning again..."
            )
            time.sleep(conf["daemon_loop_sleep"].total_seconds())
