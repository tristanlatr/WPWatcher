"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import shlex
import os 
import traceback
import subprocess
from subprocess import CalledProcessError
from wpwatcher import log
from wpwatcher.utils import safe_log_wpscan_args, oneline
# WPScan helper class -----------
class WPScanWrapper():

    def __init__(self, path):
        self.path=path
        # List of current WPScan processes
        self.processes=[]

    # Helper method: actually wraps wpscan
    def wpscan(self, *args):
        (exit_code, output)=(0,"")
        # WPScan arguments
        cmd=shlex.split(self.path) + list(args)
        # Log wpscan command without api token
        log.debug("Running WPScan command: %s" % ' '.join(safe_log_wpscan_args(cmd)) )
        # Run wpscan -------------------------------------------------------------------
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=open(os.devnull,'w') )
            # Append process to current process list and launch
            self.processes.append(process)
            wpscan_output, _  = process.communicate()
            self.processes.remove(process)
            try: wpscan_output=wpscan_output.decode("utf-8")
            except UnicodeDecodeError: wpscan_output=wpscan_output.decode("latin1")
            # Error when wpscan failed, except exit code 5: means the target has at least one vulnerability.
            #   See https://github.com/wpscanteam/CMSScanner/blob/master/lib/cms_scanner/exit_code.rb
            if process.returncode not in [0,5]:
                # Handle error
                err_string="WPScan command '%s' failed with exit code %s %s" % (' '.join(cmd) ,str(process.returncode), ". WPScan output: %s"%wpscan_output if wpscan_output else '')
                log.error(oneline(err_string))
            else :
                # WPScan comamnd success
                log.debug("WPScan raw output:\n"+wpscan_output)
            (exit_code, output)=(process.returncode, wpscan_output)
        except (CalledProcessError) as err:
            # Handle error --------------------------------------------------
            wpscan_output=str(err.output)
            err_string="WPScan command '%s' failed with exit code %s %s\nError:\n%s" % (' '.join(cmd) ,str(process.returncode), ". WPScan output: %s"%wpscan_output if wpscan_output else '', traceback.format_exc())

            log.error(oneline(err_string))
            (exit_code, output)=(err.returncode, wpscan_output)
        except FileNotFoundError as err:
            err_string="Could not find wpscan executable. \nError:\n%s" % (traceback.format_exc())
            log.error(oneline(err_string))
            (exit_code, output)=(-1, "")
        return((exit_code, output))
    
    # Check if WPScan is installed
    def is_wpscan_installed(self):
        exit_code, _ = self.wpscan("--version")
        if exit_code!=0: return False
        else: return True

    # Update WPScan database
    def update_wpscan(self):
        log.info("Updating WPScan")
        exit_code, _ = self.wpscan("--update")
        if exit_code!=0: 
            log.error("Error updating WPScan")
            exit(-1)
