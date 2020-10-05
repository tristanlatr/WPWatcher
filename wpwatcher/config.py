"""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""
import configparser
import os
import json
from wpwatcher import log
from wpwatcher.__version__ import __url__
from wpwatcher.utils import parse_timedelta

# Configuration handling -------------------------------------------------------
class WPWatcherConfig():
    '''Init WPWatcherConfig from file or string.  
    Arguments:  
    - `files`: List of filenames. Exemple: ["/home/user/Documents/wpwatcher.conf"]
    - `string`: Complete configuration string, will NOT read `files` argument. Passed as docstring would be more redable like :

            conf = WPWatcherConfig(string="""
                    wp_sites=   [ {"url":"exemple.com"}, {"url":"exemple2.com"} ]
                    send_email_report=No
                    email_to=["you@domain"]
                    from_email=WordPressWatcher@domain.com
                    smtp_server=mailserver.de:587
                    smtp_auth=Yes
                    smtp_user=me@domain
                    smtp_pass=P@assw0rd
                    smtp_ssl=Yes
            """)
    '''

    def __init__(self, files=None, string=None):

        self.files=files if files else []
        # Init config parser
        self.parser=configparser.ConfigParser()
        # Load default configuration
        self.parser.read_dict({'wpwatcher':self.DEFAULT_CONFIG})

        if string: 
            self.parser.read_string(string)
        else:
            if not self.files:
                self.files=self.find_config_files()
                if not self.files:
                    log.info("Could not find default config: `~/.wpwatcher/wpwatcher.conf`, `~/wpwatcher.conf` or `./wpwatcher.conf`")
            else:
                for f in self.files:
                    try :
                        with open(f,'r') as fp:
                            self.parser.read_file(fp)
                    except (FileNotFoundError, OSError) as err :
                       raise ValueError("Could not read config %s. Make sure the file exists and you have correct access right."%(f)) from err
 
    def build_config(self):
        '''Parse the config file(s) and return WPWatcher config.  
        Return a tuple (config dict, read files list).  
        The dict returned contain all possible config values. Default values are applied if not specified in the file(s) or string.
        '''
        # Saving config file in right dict format and types - no 'wpwatcher' section, just config options
        config_dict = {
            # Configurable witg cli arguments
            'wp_sites' :self.getjson('wp_sites'),
            'send_email_report':self.getbool('send_email_report'),
            'send_errors':self.getbool('send_errors'),
            'email_to':self.getjson('email_to'),
            'send_infos':self.getbool('send_infos'),
            'quiet':self.getbool('quiet'),
            'verbose':self.getbool('verbose'),
            'attach_wpscan_output':self.getbool('attach_wpscan_output'),
            'fail_fast':self.getbool('fail_fast'),
            'api_limit_wait':self.getbool( 'api_limit_wait'),
            'daemon':self.getbool( 'daemon'),
            'daemon_loop_sleep':parse_timedelta(self.parser.get('wpwatcher','daemon_loop_sleep')),
            'resend_emails_after':parse_timedelta(self.parser.get('wpwatcher','resend_emails_after')),
            'wp_reports':self.parser.get('wpwatcher','wp_reports'),
            'asynch_workers':self.parser.getint('wpwatcher','asynch_workers'),
            'log_file':self.parser.get('wpwatcher','log_file'),
            'follow_redirect':self.getbool( 'follow_redirect'),
            'wpscan_output_folder':self.parser.get('wpwatcher','wpscan_output_folder'),
            'wpscan_args':self.getjson('wpscan_args'),
            'scan_timeout':parse_timedelta(self.parser.get('wpwatcher', 'scan_timeout')),
            'false_positive_strings' : self.getjson('false_positive_strings'), 
            # Not configurable with cli arguments
            'send_warnings':self.getbool('send_warnings'),
            'email_errors_to':self.getjson('email_errors_to'),
            'wpscan_path':self.parser.get('wpwatcher','wpscan_path'),
            'smtp_server':self.parser.get('wpwatcher','smtp_server'),
            'smtp_auth':self.getbool( 'smtp_auth'),
            'smtp_user':self.parser.get('wpwatcher','smtp_user'),
            'smtp_pass':self.parser.get('wpwatcher','smtp_pass'),
            'smtp_ssl':self.getbool('smtp_ssl'),
            'from_email':self.parser.get('wpwatcher','from_email'),
            'use_monospace_font':self.getbool('use_monospace_font'),
            'syslog_server':self.parser.get('wpwatcher','syslog_server'),
            'syslog_port':self.getint('syslog_port'),
            'syslog_stream':self.parser.get('wpwatcher','syslog_stream'),
            'syslog_kwargs':self.getjson('syslog_kwargs'),

        }
        return ((config_dict, self.files))
    
    def getjson(self, key):
        '''Return json loaded structure from a configparser object. Empty list if the loaded value is null.   
        Arguments:  
        - `conf`: configparser object  
        - `key`: wpwatcher config key
        '''
        try:
            loaded=json.loads(self.parser.get('wpwatcher', key))
            return loaded if loaded else []
        except ValueError as err:
            raise ValueError("Could not read JSON value in config file for key '{}' and string: '{}'".format(key, self.parser.get('wpwatcher',key))) from err

    def getbool(self, key):
        '''Return bool value from a configparser object.  
        Arguments:  
        - `conf`: configparser object  
        - `key`: wpwatcher config key
        '''
        try:
            return self.parser.getboolean('wpwatcher', key)
        except ValueError as err:
            raise ValueError("Could not read boolean value in config file for key '{}' and string '{}'. Must be Yes/No".format(key, self.parser.get('wpwatcher',key))) from err

    def getint(self, key):
        '''Return int value from a configparser object.  
        Arguments:  
        - `conf`: configparser object  
        - `key`: alt_job config key
        '''
        try:
            return self.parser.getint('wpwatcher', key)
        except ValueError as err:
            raise ValueError("Could not read int value in config file for key '{}' and string '{}'. Must be an integer".format(key, self.parser.get('wpwatcher',key))) from err


    # Configuration template -------------------------
    TEMPLATE_FILE="""[wpwatcher]
# WPWatcher configuration file
# WordPress Watcher is a Python wrapper for WPScan that manages scans on multiple sites and reports by email
# Options configurable with CLI args, see 'wpwatcher --help'
# For more infos check %s

# WPScan configuration
# wpscan_path=/usr/local/rvm/gems/default/wrappers/wpscan
# wpscan_args=[ "--format", "json", "--random-user-agent" ]

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
# use_monospace_font=Yes

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

# Number of asynchronous WPScan executions (--workers)
# asynch_workers=5

# Follow main redirection when WPScan fails (--follow)
# follow_redirect=Yes

# Scan timeout
# scan_timeout=5m

# Syslog settings
# syslog_server=
# syslog_port=514
# syslog_stream=SOCK_STREAM
# syslog_kwargs={"enterprise_id":42, "msg_as_utf8":true, "utc_timestamp":true}

"""%(__url__)

    # Config default values
    DEFAULT_CONFIG={
        'wp_sites' :'null',
        'false_positive_strings' : 'null',                        
        'wpscan_path':'wpscan',
        'log_file':"",
        'wpscan_args':'''["--random-user-agent", "--format", "json"]''',
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
        'wpscan_output_folder':'',
        'scan_timeout':'15m',
        'use_monospace_font':'No',
        'syslog_server':'',
        'syslog_port':'514',
        'syslog_stream':'SOCK_STREAM',
        'syslog_kwargs':'{"enterprise_id":42, "msg_as_utf8":true, "utc_timestamp":true}'
    }

    @staticmethod
    def find_files(env_location, potential_files, default_content="", create=False):
        '''Find existent files based on folders name and file names.  

        Arguments:  
        - `env_location`: list of environment variable to use as a base path. Exemple: ['HOME', 'XDG_CONFIG_HOME', 'APPDATA', 'PWD']  
        - `potential_files`: list of filenames. Exemple: ['.wpwatcher/wpwatcher.conf', 'wpwatcher.conf']  
        - `default_content`: Write default content if the file does not exist  
        - `create`: Create the file in the first existing env_location with default content if the file does not exist  
        '''
        potential_paths=[]
        existent_files=[]
        # build potential_paths of config file
        for env_var in env_location:
            if env_var in os.environ:
                for file_path in potential_files:
                    potential_paths.append(os.path.join(os.environ[env_var],file_path))
        # If file exist, add to list
        for p in potential_paths:
            if os.path.isfile(p):
                existent_files.append(p)
        # If no file foud and create=True, init new template config
        if len(existent_files)==0 and create:
            os.makedirs(os.path.dirname(potential_paths[0]), exist_ok=True)
            with open(potential_paths[0],'w') as config_file:
                config_file.write(default_content)
            log.info("Init new file: %s"%(p))
            existent_files.append(potential_paths[0])
        return(existent_files)

    @staticmethod
    def find_config_files(create=False):
        '''
        Returns the location of existing `wpwatcher.conf` file at `./wpwatcher.conf` and/or `~/wpwatcher.conf` or under `~/.wpwatcher/` folder
        '''
        files=['.wpwatcher/wpwatcher.conf', 'wpwatcher.conf']
        env=['HOME', 'XDG_CONFIG_HOME', 'APPDATA', 'PWD']
        
        return(WPWatcherConfig.find_files(env, files, WPWatcherConfig.TEMPLATE_FILE))
