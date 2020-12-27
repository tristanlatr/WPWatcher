"""
Deamon. 
"""
from typing import Dict, Any
import time
from wpwatcher import log
from wpwatcher.core import WPWatcher
from wpwatcher.config import Config


class Daemon:
    """
    Creating the object will trigger infinite scanning loop. 
    """
    def __init__(self, conf: Config) -> None:
        log.info("Daemon mode selected, looping for ever...")
        # keep data in memory
        wpwatcher = WPWatcher(conf)
        while True:
            # Run scans for ever
            wpwatcher.run_scans()
            log.info(
                f"Daemon sleeping {conf['daemon_loop_sleep']} and scanning again..."
            )
            time.sleep(conf["daemon_loop_sleep"].total_seconds())
