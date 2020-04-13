"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import configparser
import os
import json
from wpwatcher import log, GIT_URL
from wpwatcher.utils import parse_timedelta

# Configuration handling -------------------------------------------------------
class WPWatcherConfig():

    def __init__(self, files=None, string=None):
        self.files=files
        # Init config parser
        self.parser=configparser.ConfigParser()
        # Load default configuration
        self.parser.read_dict({'wpwatcher':self.DEFAULT_CONFIG})

        if string: 
            self.parser.read_string(string)

        if (not self.files or len(self.files)==0) and not string :
            self.files=self.find_config_files()

        if self.files:
            read_files=self.parser.read(self.files)
            if len(read_files) < len(self.files):
                log.error("Could not read config " + str(list(set(self.files)-set(read_files))) + ". Make sure the file exists, the format is OK and you have correct access right.")
                exit(-1)

        # No config file notice
        else :
            log.info("No config file loaded and could not find default config `~/.wpwatcher/wpwatcher.conf`, `~/wpwatcher.conf` or `./wpwatcher.conf`")
    
    def build_config(self):
        config_dict={}
        try:
            # Saving config file in right dict format - no 'wpwatcher' section, just config options
            config_dict = {
                # Configurable witg cli arguments
                'wp_sites' :self.getjson(self.parser,'wp_sites'),
                'send_email_report':self.getbool(self.parser, 'send_email_report'),
                'send_errors':self.getbool(self.parser, 'send_errors'),
                'email_to':self.getjson(self.parser,'email_to'),
                'send_infos':self.getbool(self.parser, 'send_infos'),
                'quiet':self.getbool(self.parser, 'quiet'),
                'verbose':self.getbool(self.parser, 'verbose'),
                'attach_wpscan_output':self.getbool(self.parser, 'attach_wpscan_output'),
                'fail_fast':self.getbool(self.parser, 'fail_fast'),
                'api_limit_wait':self.getbool(self.parser, 'api_limit_wait'),
                'daemon':self.getbool(self.parser, 'daemon'),
                'daemon_loop_sleep':parse_timedelta(self.parser.get('wpwatcher','daemon_loop_sleep')),
                'resend_emails_after':parse_timedelta(self.parser.get('wpwatcher','resend_emails_after')),
                'wp_reports':self.parser.get('wpwatcher','wp_reports'),
                'asynch_workers':self.parser.getint('wpwatcher','asynch_workers'),
                'log_file':self.parser.get('wpwatcher','log_file'),
                'follow_redirect':self.getbool(self.parser, 'follow_redirect'),
                'wpscan_output_folder':self.parser.get('wpwatcher','wpscan_output_folder'),
                'wpscan_args':self.getjson(self.parser,'wpscan_args'),
                # Not configurable with cli arguments
                'send_warnings':self.getbool(self.parser, 'send_warnings'),
                'false_positive_strings' : self.getjson(self.parser,'false_positive_strings'), 
                'email_errors_to':self.getjson(self.parser,'email_errors_to'),
                'wpscan_path':self.parser.get('wpwatcher','wpscan_path'),
                'smtp_server':self.parser.get('wpwatcher','smtp_server'),
                'smtp_auth':self.getbool(self.parser, 'smtp_auth'),
                'smtp_user':self.parser.get('wpwatcher','smtp_user'),
                'smtp_pass':self.parser.get('wpwatcher','smtp_pass'),
                'smtp_ssl':self.getbool(self.parser, 'smtp_ssl'),
                'from_email':self.parser.get('wpwatcher','from_email')
            }
            return ((config_dict, self.files))

        except Exception as err: 
            log.error("Could not read config " + str(self.files) + ". Error: "+str(err))
            raise

    # Configuration template -------------------------
    TEMPLATE_FILE="""[wpwatcher]
# WPWatcher configuration file
# WordPress Watcher is a Python wrapper for WPScan that manages scans on multiple sites and reports by email
# Options configurable with CLI args, see 'wpwatcher --help'
# For more infos check %s

# WPScan configuration
# wpscan_path=/usr/local/rvm/gems/default/wrappers/wpscan
wpscan_args=[   "--format", "cli",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks" ]

# False positive string matches
# false_positive_strings=["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]

# Sites (--url or --urls)
# wp_sites=   [ {"url":"exemple.com"}, {"url":"exemple2.com"} ]

# Notifications (--send , --em , --infos , --errors , --attach , --resend)
send_email_report=No
email_to=["you@domain"]

# send_infos=Yes
# send_errors=Yes
# send_warnings=No
# attach_wpscan_output=Yes
# resend_emails_after=5d
# email_errors_to=["admins@domain"]

# Email server settings
from_email=WordPressWatcher@domain.com
smtp_server=mailserver.de:587
smtp_auth=Yes
smtp_user=me@domain
smtp_pass=P@assw0rd
smtp_ssl=Yes

# Sleep when API limit reached (--wait)
# api_limit_wait=Yes

# Daemon settings (recommended to use --daemon)
# daemon=No
# daemon_loop_sleep=12h

# Output (-q , -v)
# log_file=/home/user/.wpwatcher/wpwatcher.log
# quiet=Yes
# verbose=Yes
# wpscan_output_folder=/home/user/.wpwatcher/wpscan-results/

# Custom database (--reports)
# wp_reports=/home/user/.wpwatcher/wp_reports.json

# Exit if any errors (--ff)
# fail_fast=Yes 

# Number of asynchronous WPScan executions
# asynch_workers=5

# Follow main redirection when WPScan failed
# follow_redirect=Yes

"""%(GIT_URL)

    # Config default values
    DEFAULT_CONFIG={
        'wp_sites' :'null',
        'false_positive_strings' : 'null',                        
        'wpscan_path':'wpscan',
        'log_file':"",
        'wpscan_args':'''["--no-banner","--random-user-agent"]''',
        'send_email_report':'No',
        'send_errors':'No',
        'email_to':'null',
        'email_errors_to':'null',
        'send_warnings':'Yes',
        'send_infos':'No',
        'attach_wpscan_output':'No',
        'smtp_server':"",
        'smtp_auth':'No',
        'smtp_user':"",
        'smtp_pass':"",
        'smtp_ssl':'No',
        'from_email':"",
        'quiet':'No',
        'verbose':'No',
        'fail_fast':'No',
        'api_limit_wait':'No',
        'daemon':'No',
        'daemon_loop_sleep':'0s',
        'resend_emails_after':'0s',
        'wp_reports':'',
        'asynch_workers':'1',
        'follow_redirect':'No',
        'wpscan_output_folder':''
    }

    @staticmethod
    def getjson(conf, key):
        string_val=conf.get('wpwatcher', key)
        try:
            loaded=json.loads(string_val)
            return loaded if loaded else []
        except Exception as err:
            log.error("Could not read config JSON value for: '%s' and string: '%s'. Error: %s" % (key, conf.get('wpwatcher',key), str(err)))
            raise
    @staticmethod
    def getbool(conf, key):
        try:
            return conf.getboolean('wpwatcher', key)
        except Exception as err:
            log.error("Could not read boolean value in config for: '{}' and string '{}'. Must be Yes/No. Error: {}".format(key, conf.get('wpwatcher',key), str(err)))
            raise
    @staticmethod
    def find_config_files(create=False):
        '''
        Returns the location of existing `wpwatcher.conf` and `wp_reports.json` files at ./wpwatcher.conf and/or ~/wpwatcher.conf or under ~/.wpwatcher/ folder
        '''
        paths=[]
        if create:
            os.makedirs(os.path.join(os.environ['HOME'],'.wpwatcher'), exist_ok=True)
        if 'APPDATA' in os.environ: 
            p=os.path.join(os.environ['APPDATA'],'.wpwatcher/wpwatcher.conf')
            if os.path.isfile(p): paths.append(p)
            elif create: 
                with open(p,'w') as config_file:
                    config_file.write(WPWatcherConfig.TEMPLATE_FILE)
                    log.info("Init new config file from template: %s"%(p))
            p=os.path.join(os.environ['APPDATA'],'wpwatcher.conf')
            if os.path.isfile(p): paths.append(p)
        elif 'HOME' in os.environ: 
            p=os.path.join(os.environ['HOME'],'.wpwatcher/wpwatcher.conf')
            if os.path.isfile(p): paths.append(p)
            elif create: 
                with open(p,'w') as config_file:
                    config_file.write(WPWatcherConfig.TEMPLATE_FILE)
                    log.info("Init new config file: %s"%(p))
            p=os.path.join(os.environ['HOME'],'wpwatcher.conf')
            if os.path.isfile(p): paths.append(p)
        elif 'XDG_CONFIG_HOME' in os.environ: 
            p=os.path.join(os.environ['XDG_CONFIG_HOME'],'.wpwatcher/wpwatcher.conf')
            if os.path.isfile(p): paths.append(p)
            elif create: 
                with open(p,'w') as config_file:
                    config_file.write(WPWatcherConfig.TEMPLATE_FILE)
                    log.info("Init new config file: %s"%(p))
            p=os.path.join(os.environ['XDG_CONFIG_HOME'],'wpwatcher.conf')
            if os.path.isfile(p): paths.append(p)
        if os.path.isfile('./wpwatcher.conf'): 
            paths.append('./wpwatcher.conf')
        return(paths)