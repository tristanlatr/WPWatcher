"""
Configuration dict. 
"""
from typing import Iterable, Tuple, Union, Optional, List, Dict, Any
import configparser
import os
import json
import argparse
import shlex
import copy
import warnings
from wpwatcher import log
from wpwatcher.__version__ import __url__
from wpwatcher.utils import parse_timedelta, safe_log_wpscan_args

# Configuration handling -------------------------------------------------------
class Config(Dict[str, Any]): 
    """
    Dict-Like object.

    Use classmethods to create the config dict.

    Default values are applied to fields if not specified.

    If a value is deleted it will probably create a key error using `WPWatcher`.
    """

    # Configuration template -------------------------
    TEMPLATE_FILE: str = """[wpwatcher]
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

""" % (
        __url__
    )

    # Config default values
    DEFAULT_CONFIG: Dict[str, str] = {
        "wp_sites": "null",
        "false_positive_strings": "null",
        "wpscan_path": "wpscan",
        "log_file": "",
        "wpscan_args": """["--random-user-agent", "--format", "json", "--cache-ttl", "0"]""",
        "send_email_report": "No",
        "send_errors": "No",
        "email_to": "null",
        "email_errors_to": "null",
        "send_warnings": "Yes",
        "send_infos": "No",
        "attach_wpscan_output": "No",
        "smtp_server": "",
        "smtp_auth": "No",
        "smtp_user": "",
        "smtp_pass": "",
        "smtp_ssl": "No",
        "from_email": "",
        "quiet": "No",
        "verbose": "No",
        "fail_fast": "No",
        "api_limit_wait": "No",
        "daemon": "No",
        "daemon_loop_sleep": "0s",
        "resend_emails_after": "0s",
        "wp_reports": "",
        "asynch_workers": "1",
        "follow_redirect": "No",
        "wpscan_output_folder": "",
        "scan_timeout": "30m",
        "use_monospace_font": "No",
        "syslog_server": "",
        "syslog_port": "514",
        "syslog_stream": "SOCK_STREAM",
        "syslog_kwargs": '{"enterprise_id":42, "msg_as_utf8":true, "utc_timestamp":true}',
    }

    FIELDS: Iterable[str] = list(DEFAULT_CONFIG.keys())

    @classmethod
    def default(cls) -> 'Config':
        """
        Get the default Config. 
        """
        parser: configparser.ConfigParser = configparser.ConfigParser()
        parser.read_dict(dict(wpwatcher=Config.DEFAULT_CONFIG))
        return cls.fromparser(parser)

    @classmethod
    def fromenv(cls) -> 'Config':
        """
        Get the default Config (from environement).
        Look for files: `./wpwatcher.conf` and/or `~/wpwatcher.conf` or under `~/.wpwatcher/` folder.
        """
        files = Config.find_config_files()
        if not files:
            log.info(
                "Could not find default config: `~/.wpwatcher/wpwatcher.conf`, `~/wpwatcher.conf` or `./wpwatcher.conf`"
            )
            return cls.default()
        else:
            return cls.fromfiles(files)

    @classmethod
    def fromfiles(cls, files: List[str]) -> 'Config':
        """
        Get config dict from file(s).

        :Parameters:
            - `files`: List of filenames. 
        
        Exemple:

        >>> conf = Config.fromfiles(["/home/user/Documents/wpwatcher.conf"])
        """
        parser: configparser.ConfigParser = configparser.ConfigParser()
        parser.read_dict(dict(wpwatcher=Config.DEFAULT_CONFIG))
        for f in files:
            try:
                with open(f, "r") as fp:
                    parser.read_file(fp)
            except (FileNotFoundError, OSError) as err:
                raise ValueError(
                    f"Could not read config {f}. Make sure the file exists and you have correct access right."
                ) from err
            else:
                log.info(f"Load config file: {f}")
        return Config.fromparser(parser)

    @classmethod
    def fromstring(cls, string: str) -> 'Config':
        """
        Get the config dict from string.

        :Parameters:
            - `string`: Complete configuration string

        .. python::

            conf = Config.fromstring('''
                    wp_sites=   [ {"url":"exemple.com"}, {"url":"exemple2.com"} ]
                    send_email_report=No
                    email_to=["you@domain"]
                    from_email=WordPressWatcher@domain.com
                    smtp_server=mailserver.de:587
                    smtp_auth=Yes
                    smtp_user=me@domain
                    smtp_pass=P@assw0rd
                    smtp_ssl=Yes
            ''')
        """
        parser: configparser.ConfigParser = configparser.ConfigParser()
        parser.read_dict(dict(wpwatcher=Config.DEFAULT_CONFIG))
        parser.read_string(string)
        return cls.fromparser(parser)

    @classmethod
    def fromparser(cls, parser: configparser.ConfigParser) -> 'Config':
        """
        Get config from ConfigParser, the parser should contain all values.
        """
        return cls(Config._build_config(parser))

    @classmethod
    def fromcliargs(cls, cliargs: argparse.Namespace) -> 'Config':
        """
        Get the config dict from CLI arguments.
        """
        config_object: Dict[str, Any]

        if cliargs.conf:
            config_object = cls.fromfiles(cliargs.conf)
        else:
            config_object = cls.fromenv()

        # Figuring the config fields that have been overwritten by the args
        # The args must have the same name than the config options.
        cli_conf_args = {}
        vars_cli_args = vars(cliargs)
        for k in vars_cli_args:
            if k in Config.FIELDS and vars_cli_args[k]:
                cli_conf_args.update({k: vars_cli_args[k]})

        # Append or init list of urls from file if any
        if cliargs.wp_sites_list:
            with open(cliargs.wp_sites_list, "r") as urlsfile:
                sites = [site.replace("\n", "") for site in urlsfile.readlines()]
                cli_conf_args["wp_sites"] = (
                    sites
                    if "wp_sites" not in cli_conf_args
                    else cli_conf_args["wp_sites"] + sites
                )

        cli_conf_args = Config._adjust_special_cli_args(cli_conf_args)

        # Overwrite or append with conf dict built from CLI Args
        if cli_conf_args:
            for k in cli_conf_args:
                if k == "wpscan_args":
                    # Make sure to append new WPScan arguments after defaults
                    config_object[k].extend(cli_conf_args[k])
                else:
                    config_object[k] = cli_conf_args[k]

        return config_object

    def __repr__(self) -> str:
        """Get the config representation without passwords, ready for printing. """
        dump_conf = copy.deepcopy(self)
        string = ""
        for k in dump_conf:
            v = dump_conf[k]
            if k == "wpscan_args":
                v = safe_log_wpscan_args(v)
            if k == "smtp_pass" and v != "":
                v = "***"
            if isinstance(v, (list, dict)):
                v = json.dumps(v)
            else:
                v = str(v)
            string += f"\n{k:<25}\t=\t{v}"
        return string

    @staticmethod
    def _adjust_special_cli_args(conf_args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Adjust special CLI arguments types.

        Arguments:

        - 'conf_args': Configuration dict with CLI parsed values only
        """

        # Adjust special case of urls that are list of dict
        if "wp_sites" in conf_args:
            conf_args["wp_sites"] = [{"url": site} for site in conf_args["wp_sites"]]

        # Adjust special case of resend_emails_after
        if "resend_emails_after" in conf_args:
            conf_args["resend_emails_after"] = parse_timedelta(
                conf_args["resend_emails_after"]
            )
        # Adjust special case of daemon_loop_sleep
        if "daemon_loop_sleep" in conf_args:
            conf_args["daemon_loop_sleep"] = parse_timedelta(
                conf_args["daemon_loop_sleep"]
            )
        # Adjust special case of wpscan_args
        if "wpscan_args" in conf_args:
            conf_args["wpscan_args"] = shlex.split(conf_args["wpscan_args"])
        return conf_args

    @staticmethod
    def _build_config(parser: configparser.ConfigParser) -> Dict[str, Any]:
        """"""
        # Saving config file in right dict format and types - no 'wpwatcher' section, just config options
        config_dict: Dict[str, Any] = {
            # Configurable with cli arguments
            "wp_sites": Config._getjson(parser, "wp_sites"),
            "send_email_report": Config._getbool(parser, "send_email_report"),
            "send_errors": Config._getbool(parser, "send_errors"),
            "email_to": Config._getjson(parser, "email_to"),
            "send_infos": Config._getbool(parser, "send_infos"),
            "quiet": Config._getbool(parser, "quiet"),
            "verbose": Config._getbool(parser, "verbose"),
            "attach_wpscan_output": Config._getbool(
                parser, "attach_wpscan_output"
            ),
            "fail_fast": Config._getbool(parser, "fail_fast"),
            "api_limit_wait": Config._getbool(parser, "api_limit_wait"),
            "daemon": Config._getbool(parser, "daemon"),
            "daemon_loop_sleep": parse_timedelta(
                parser.get("wpwatcher", "daemon_loop_sleep")
            ),
            "resend_emails_after": parse_timedelta(
                parser.get("wpwatcher", "resend_emails_after")
            ),
            "wp_reports": parser.get("wpwatcher", "wp_reports"),
            "asynch_workers": Config._getint(parser, "asynch_workers"),
            "log_file": parser.get("wpwatcher", "log_file"),
            "follow_redirect": Config._getbool(parser, "follow_redirect"),
            "wpscan_output_folder": parser.get("wpwatcher", "wpscan_output_folder"),
            "wpscan_args": Config._getjson(parser, "wpscan_args"),
            "scan_timeout": parse_timedelta(parser.get("wpwatcher", "scan_timeout")),
            "false_positive_strings": Config._getjson(
                parser, "false_positive_strings"
            ),
            # Not configurable with cli arguments
            "send_warnings": Config._getbool(parser, "send_warnings"),
            "email_errors_to": Config._getjson(parser, "email_errors_to"),
            "wpscan_path": parser.get("wpwatcher", "wpscan_path"),
            "smtp_server": parser.get("wpwatcher", "smtp_server"),
            "smtp_auth": Config._getbool(parser, "smtp_auth"),
            "smtp_user": parser.get("wpwatcher", "smtp_user"),
            "smtp_pass": parser.get("wpwatcher", "smtp_pass"),
            "smtp_ssl": Config._getbool(parser, "smtp_ssl"),
            "from_email": parser.get("wpwatcher", "from_email"),
            "use_monospace_font": Config._getbool(
                parser, "use_monospace_font"
            ),
            "syslog_server": parser.get("wpwatcher", "syslog_server"),
            "syslog_port": Config._getint(parser, "syslog_port"),
            "syslog_stream": parser.get("wpwatcher", "syslog_stream"),
            "syslog_kwargs": Config._getjson(parser, "syslog_kwargs"),
        }
        return config_dict

    @staticmethod
    def _getjson(
        parser: configparser.ConfigParser,
        key: str,
        section: str = "wpwatcher",
    ) -> Union[List[Any], Dict[str, Any]]:
        """Return json loaded structure from a configparser object. Empty list if the loaded value is null.
        Arguments:
        - `conf`: configparser object
        - `key`: config key
        """
        try:
            loaded = json.loads(parser.get(section, key))
            return loaded if loaded else []
        except ValueError as err:
            raise ValueError(
                f"Could not read JSON value in config file for key '{key}' and string: '{parser.get(section, key)}'"
            ) from err

    @staticmethod
    def _getbool(
        parser: configparser.ConfigParser,
        key: str,
        section: str = "wpwatcher",
    ) -> bool:
        """Return bool value from a configparser object.
        Arguments:
        - `conf`: configparser object
        - `key`: config key
        """
        try:
            return parser.getboolean(section, key)
        except ValueError as err:
            raise ValueError(
                f"Could not read boolean value in config file for key '{key}' and string '{parser.get(section, key)}'. Must be Yes/No"
            ) from err

    @staticmethod
    def _getint(
        parser: configparser.ConfigParser,
        key: str,
        section: str = "wpwatcher",
    ) -> int:
        """Return int value from a configparser object.
        Arguments:
        - `conf`: configparser object
        - `key`: config key
        """
        try:
            return parser.getint(section, key)
        except ValueError as err:
            raise ValueError(
                f"Could not read int value in config file for key '{key}' and string '{parser.get(section, key)}'. Must be an integer"
            ) from err

    @staticmethod
    def find_files(
        env_location: List[str],
        potential_files: List[str],
        default_content: str = "",
        create: bool = False,
    ) -> List[str]:
        """Find existent files or folders based on folders name and file names.

        Arguments:
        - `env_location`: list of environment variable to use as a base path. Exemple: ['HOME', 'XDG_CONFIG_HOME', 'APPDATA', 'PWD']
        - `potential_files`: list of filenames. Exemple: ['.wpwatcher/wpwatcher.conf', 'wpwatcher.conf']
        - `default_content`: Write default content if the file does not exist
        - `create`: Create the file in the first existing env_location with default content if the file does not exist
        """
        potential_paths = []
        existent_files = []

        env_loc_exists = False
        # build potential_paths of config file
        for env_var in env_location:
            if env_var in os.environ:
                env_loc_exists = True
                for file_path in potential_files:
                    potential_paths.append(os.path.join(os.environ[env_var], file_path))
        if not env_loc_exists:
            raise RuntimeError(f"Cannot find any of the env locations {env_location}. ")
        # If file or folder exist, add to list
        for p in potential_paths:
            if os.path.isfile(p) or os.path.isdir(p):
                existent_files.append(p)
        # If no file foud and create=True, init new template config
        if len(existent_files) == 0 and create:
            os.makedirs(os.path.dirname(potential_paths[0]), exist_ok=True)
            with open(potential_paths[0], "w") as config_file:
                config_file.write(default_content)
            log.info(f"Init new file: {potential_paths[0]}")
            existent_files.append(potential_paths[0])
        return existent_files

    @staticmethod
    def find_config_files(create: bool = False) -> List[str]:
        """
        Returns the location of existing `wpwatcher.conf` file at `./wpwatcher.conf` and/or `~/wpwatcher.conf` or under `~/.wpwatcher/` folder
        """
        files = [".wpwatcher/wpwatcher.conf", "wpwatcher.conf"]
        env = ["HOME", "XDG_CONFIG_HOME", "APPDATA", "PWD"]

        return Config.find_files(
            env, files, Config.TEMPLATE_FILE, create=create
        )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """
        Init Config dict.

        :Note: Should not be used directly to create a Config object.
               Use class methods instead.

        :Raise KeyError: If missing config field from ``**kwargs``.

        Parameters `"files"` and `"string"` are deprecated since verion 3.0.
        """

        super().__init__(*args, **kwargs)
        # Raise if missing fields
        missing = []
        for key in self.FIELDS:
            if key not in self:
                missing.append(key)

        if missing:
            fields = ", ".join(f"'{key}'" for key in missing)
            raise KeyError(f"Missing config field(s): {fields}. ")
