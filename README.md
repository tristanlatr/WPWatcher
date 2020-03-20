# WPWatcher
Wordpress Watcher is a wrapper for [WPScan](http://wpscan.org/) that manages scans on multiple sites and reports by email

## In a Nutshell

  - Scan multiple sites with WPScan
  - Define a reporting email address for every configured site individually and also a global reporting address
  - Define false positives strings for every configured site individually and also globally
  - Define WPScan arguments for every configured site individually and also globally
  - Elements are divided in "Warnings", "Alerts", "Informations" and eventually "Errors"
  - Mail notification and verbosity can be configred in config file 
  - Local log file "wpwatcher.log" also lists all the findings (integrate in monitoring)
  - Parse the results differently whether wpscan argument `--format` is `json` or `cli`.

## Prerequisites 

  - [WPScan](http://wpscan.org/) (itself requires Ruby and some libraries).   
  - Python 3 (standard libraries)

## Usage

  1. Save script on server system
  2. Save template config file and configure script
  3. Configure cron to run WPWatcher frequently
  4. Configure email alerting to administrators if script fails.

    $ python3 ./wpwatcher.py
    # or
    $ python3 ./wpwatcher.py --conf ~/configs/wpwatcher.conf

Return non zero status code if :
- one or more WPScan command failed
- unable to send one or more email report
- other errors

#### Notes

- Will automatically delete all temp wpscan files in `/tmp/wpscan` before starting
- Set "--format","json" in  `wpscan_args` config option to have more consice email output

## Compatibility

Tested with WPScan 3.7 on :
- MacOS (WPScan install wil `HomeBrew`) and 
- Linux CentOS 7 (WPScan installed with `RubyGems`)

## Configuration
If not specified with `--conf <path>` script parameter, will try to load `./wpwatcher.conf` or `~/wpwatcher.conf` by default.  
All options can be missing from config file expect `wp_sites`

#### Basic usage (template)

```ini
[wpwatcher]
wpscan_path=wpscan
wp_sites=   [ {"url":"exemple.com"},
              {"url":"exemple2.com"}  ]
send_email_report=Yes
email_to=["me@exemple.com"]
smtp_server=mailserver.exemple.com:25
from_email=WordPressWatcher@exemple.com
```

#### Full configuration options
```ini
[wpwatcher]
# Path to wpscan executable. On linuxes could be /usr/local/rvm/gems/ruby-2.6.0/wrappers/wpscan
# Assume wpscan is in you path by default
wpscan_path=wpscan

# Monitoerd sites, custom email report recepient, false positives and specific wpscan arguments
# Must be a valid Json string
# Each dictrionnary must contain at least a 'url' key
wp_sites=   [
        {   
            "url":"exemple.com",
            "email_to":["site_owner@domain.com","site_wordpress_admins@domain.com"], 
            "false_positive_strings":["Vulnerability 123"],
            "wpscan_args":["--verbose", "--enumerate", "vp,vt,cb,dbe,m"] 
        },
        {   
            "url":"exemple.com",
            "email_to":null, 
            "false_positive_strings":null,
            "wpscan_args":null
        },
        {   
            "url":"exemple.com"
        }
    ]

# False positive strings
# Must be a valid Json string
# You can use this to ignore some warnmings or alerts. False positives will be still processed as info
# Use with care
false_positive_strings=["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]

# Log file
log_file=./wpwatcher.log

# WPScan arguments. wpscan v3.7
# Must be a valid Json string
#
# Set "--format","json" to use Json parsing feature
# The list of warnings, alerts and infos might differ when using json 
#   The outpout is more concice. 
#   But not all informations are logged. 
# Using "--format", "cli" will parse full WPScan output with [!] etc
#   Logs all informations
wpscan_args=[   "--format", "cli",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks" ]

# Whether to send emails
send_email_report=No

# Wheter to include warnings in the reports
# If set to No, no reports will be sent if WPScan find warnings
send_warnings=Yes

# Wheter to include Informations in the reports
# If set to Yes, reports will be sent every time
send_infos=No

# Will send emails even if wpscan exited with non zero status code
send_errors=No

# Default email report recepients, will always receive email reports of all sites
# Must be a valid Json string
email_to=["securityalerts@domain.com"]

# Applicable only if send_errors=Yes
# If set, will send any error output to those addresses (not to other)
email_errors_to=["admins@domain.com"]

# Email settings
smtp_server=mailserver.de:25
smtp_auth=No
smtp_user=office
smtp_pass=p@assw0rd
smtp_ssl=Yes
from_email=WordPressWatcher@domain.com

# Set yes to print only errors and WPScan warnings
quiet=No

# Verbose terminal output and logging.
# Print raw WPScan output before parsing
verbose=No
```

## Report

![WPWatcher Report](/screens/wpwatcher-report.png "WPWatcher Report")

## Questions ?
If you have any questions, please create a new issue.

## Contribute
If you like the project and think you could help with making it better, there are many ways you can do it:

- Create new issue for new feature proposal or a bug
- Implement existing issues
- Help with improving the documentation
- Spread a word about the project to your collegues, friends, blogs or any other channels
- Any other things you could imagine
- Any contribution would be of great help

## Authors
- Florian Roth
- Tristan Landès
