"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""

# Main program, parse the args, read config and launch scans
import argparse
import shlex

from wpwatcher import VERSION, AUTHORS, GIT_URL, log, init_log
from wpwatcher.utils import parse_timedelta, results_summary
from wpwatcher.config import WPWatcherConfig
from wpwatcher.core import WPWatcher
from wpwatcher.db import WPWatcherDataBase
from wpwatcher.daemon import WPWatcherDaemon

class WPWatcherCLI():
    """Main program class"""

    def __init__(self):
        """Main program entrypoint"""
        
        # Parse arguments
        args=self.parse_args()
        # Init logger with CLi arguments
        init_log(args.verbose, args.quiet)
        # If template conf , print and exit
        if args.template_conf: self.template_conf()
        # Print "banner"
        log.info("WPWatcher -  Automating WPscan to scan and report vulnerable Wordpress sites")
        # If version, print and exit
        if args.version: self.verion()
        # Init WPWatcher obhect and dump reports
        if args.wprs!=False: self.wprs(args.wprs, args.daemon)
        
        # Read config
        configuration=self.build_config_cli(args)
        
        # If daemon lopping
        if configuration['daemon']: 
            # Run 4 ever
            WPWatcherDaemon(configuration)
           
        else:
            # Run scans and quit
            # Create main object
            wpwatcher=WPWatcher(configuration)
            exit_code,_=wpwatcher.run_scans_and_notify()
            exit(exit_code)
            
    @staticmethod
    def wprs(filepath=None, daemon=False):
        """Generate JSON file database summary"""
        db=WPWatcherDataBase(filepath, daemon=daemon)
        print(results_summary(db._data))
        exit(0)

    @staticmethod
    def verion():
        """Print version and contributors"""
        log.info("Version:\t\t%s"%VERSION)
        log.info("Authors:\t\t%s"""%AUTHORS)
        exit(0)

    @staticmethod
    def template_conf():
        """Print template configuration"""
        print(WPWatcherConfig.TEMPLATE_FILE)
        exit(0)

    @staticmethod
    def parse_args():
        """Parse CLI arguments, arguments can overwrite config file values"""

        parser = argparse.ArgumentParser(description="""WordPress Watcher is a Python wrapper for WPScan that manages scans on multiple sites and reports by email.
    Some config arguments can be passed to the command.
    It will overwrite previous values from config file(s).
    Check %s for more informations."""%(GIT_URL))
        parser.add_argument('--conf', '-c', metavar='File path', help="""Configuration file. You can specify multiple files, it will overwrites the keys with each successive file.
    If not specified, will try to load config from file `~/.wpwatcher/wpwatcher.conf`, `~/wpwatcher.conf` and `./wpwatcher.conf`.
    All options can be missing from config file.""", nargs='+', default=None)
        parser.add_argument('--template_conf', '--tmpconf', help="""Print a template config file.""", action='store_true')
        
        # Declare arguments that will overwrite config options
        parser.add_argument('--wp_sites', '--url', metavar="URL", help="Site(s) to scan, you can pass multiple values", nargs='+', default=None)
        parser.add_argument('--wp_sites_list', '--urls', metavar="Path", help="Read URLs from a text file. File must contain one URL per line", default=None)
        parser.add_argument('--send_email_report', '--send', help="Enable email report sending", action='store_true')
        parser.add_argument('--email_to', '--em', metavar="Email", help="Email the specified receipent(s) you can pass multiple values", nargs='+', default=None)
        parser.add_argument('--send_infos', '--infos', help="Email INFO reports", action='store_true')
        parser.add_argument('--send_errors', '--errors', help="Email ERROR reports", action='store_true')
        parser.add_argument('--attach_wpscan_output', '--attach', help="Attach WPScan output to emails", action='store_true')
        parser.add_argument('--fail_fast', '--ff', help="Interrupt scans if any WPScan or sendmail failure", action='store_true')
        parser.add_argument('--api_limit_wait', '--wait', help="Sleep 24h if API limit reached", action='store_true')
        parser.add_argument('--daemon',  help="Loop and scan for ever", action='store_true')
        parser.add_argument('--daemon_loop_sleep','--loop', metavar='Time string', help="Time interval to sleep in daemon loop")
        parser.add_argument('--wp_reports', '--reports', metavar="Path", help="Database Json file", default=None)
        parser.add_argument('--resend_emails_after','--resend', metavar="Time string", help="Minimum time interval to resend email report with same status")
        parser.add_argument('--asynch_workers','--workers', metavar="Number", help="Number of asynchronous workers", type=int)
        parser.add_argument('--log_file','--log', metavar="Path", help="Logfile replicates all output with timestamps")
        parser.add_argument('--follow_redirect','--follow',  help="Follow site redirection if causes WPscan failure", action='store_true')
        parser.add_argument('--wpscan_output_folder','--wpout', metavar="Path", help="Write all WPScan results in sub directories 'info', 'warning', 'alert' and 'error'")
        parser.add_argument('--wpscan_args','--wpargs', metavar='Arguments', help="WPScan arguments as string. See 'wpscan --help' for more infos")
        parser.add_argument('--false_positive_strings','--fpstr', metavar='String', help='False positive strings, you can pass multiple values', nargs='+', default=None)
        parser.add_argument('--prescan_without_api_token','--prescan', help='Scan without API token first and use API token on sites that triggered warnings', action='store_true')
        parser.add_argument('--verbose', '-v', help="Verbose output, print WPScan raw output and parsed WPScan results.", action='store_true')
        parser.add_argument('--quiet', '-q', help="Print only errors and WPScan ALERTS", action='store_true')

        parser.add_argument('--version', '-V', help="Print WPWatcher version", action='store_true')
        parser.add_argument('--wprs', metavar="Path", help="Print database (wp_reports in config) summary. Leave path blank to find default file. Can be used with --daemon to print default daemon databse.", nargs='?', default=False)

        args = parser.parse_args()
        return(args)

    @staticmethod
    def build_config_cli(args):
        """Assemble the config dict from args and from file.  
        Arguments:  
        - 'args': Namespace from ArgumentParser.parse_args()
        """

        args=vars(args) #if hasattr(args, '__dict__') and not type(args)==dict else args
        # Configuration variables
        conf_files=args['conf'] if 'conf' in args else None
        
        # Init config dict: read config files
        configuration, files = WPWatcherConfig(files=conf_files).build_config()
        if files: 
            log.info("Load config file(s) : %s"%files)
        
        # Sorting out only args that matches config options and that are not None or False
        conf_args={}
        for k in args: 
            if k in WPWatcherConfig.DEFAULT_CONFIG.keys() and args[k]:
                conf_args.update({k:args[k]})  

        # Append or init list of urls from file if any
        if 'wp_sites_list' in args and args['wp_sites_list'] :
            with open(args['wp_sites_list'], 'r') as urlsfile:
                sites=[ site.replace('\n','') for site in urlsfile.readlines() ]
                conf_args['wp_sites']= sites if 'wp_sites' not in conf_args else conf_args['wp_sites']+sites

        conf_args=WPWatcherCLI.adjust_special_cli_args(conf_args)
        # Overwrite with conf dict biult from CLI Args
        if conf_args: configuration.update(conf_args)
        return configuration

    @staticmethod
    def adjust_special_cli_args(conf_args):
        """Adjust special CLI arguments types.  
        Arguments:  
        - 'conf_args': Configuration dict with CLI parsed values only"""

        # Adjust special case of urls that are list of dict
        if 'wp_sites' in conf_args: conf_args['wp_sites']=[ {"url":site} for site in conf_args['wp_sites'] ]
        # Adjust special case of resend_emails_after
        if 'resend_emails_after' in conf_args: conf_args['resend_emails_after']=parse_timedelta(conf_args['resend_emails_after'])
        # Adjust special case of daemon_loop_sleep
        if 'daemon_loop_sleep' in conf_args: conf_args['daemon_loop_sleep']=parse_timedelta(conf_args['daemon_loop_sleep'])
        # Adjust special case of wpscan_args
        if 'wpscan_args' in conf_args: conf_args['wpscan_args']=shlex.split(conf_args['wpscan_args'])
        return conf_args

def main(): 
    """Main program"""
    WPWatcherCLI()

"""Main program if called with wpwatcher/cli.py"""
if __name__ == '__main__':
    WPWatcherCLI()