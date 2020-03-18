# WPWatcher
Wordpress Watcher is a wrapper for [WPScan](http://wpscan.org/) that manages scans on multiple sites and reports by email

## In a Nutshell

  - Scan multiple sites with WPScan
  - Define a reporting email address for every configured site individually
  - Elements are divided in "Warnings" and "Alerts"
  - Mail is sent if at least 1 warning or 1 alert has been found
  - Local log file "wpwatcher.log" also lists all the findings (integrate in monitoring)

## Prerequisites 

  - [WPScan](http://wpscan.org/) (itself requires Ruby and some libraries)
  - Python 3 (standard libraries)

## Usage

Best Practice:
  1. Save script on server system
  2. Configure script in the config file
  4. Configure cron to run WPWatcher frequently
  5. Configure email alerting to administrators if script fails.

    $ python3 ./wpwatcher.py
    # or
    $ python3 ./wpwatcher.py --conf ~/configs/wpwatcher.conf

Return non zero status code if :
- one or more WPScan command failed
- unable to send one or more email report
- other errors

## Compatibility

Version 0.3 is compatible with Python 3.

## Configuration
If not specified with `--conf`, will use `./wpwatcher.conf` or `~/wpwatcher.conf` by default.
```ini
[wpwatcher]

# Monitoerd sites, custom email report recepient, false positives and specific wpscan arguments
# Must be a valid Json string
# Each dictrionnary must contain at least a 'url' key
wp_sites=   [
        {   
            "url":"aeets.com",
            "email_to":["user1@mail.com"], 
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
# Can be set to null with false_positive_strings=null
false_positive_strings=[    "You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up",
                            "No plugins Found.",
                            "No themes Found.",
                            "No Config Backups Found.", 
                            "No DB Exports Found.",
                            "No Medias Found." ]
                            
# Path to wpscan. On linuxes could be /usr/local/rvm/gems/ruby-2.6.0/wrappers/wpscan
wpscan_path=wpscan

# Log file
# Can be /dev/null
log_file=./wpwatcher.log

# WPScan arguments. wpscan v3.7
# Must be a valid Json string
# Can be set to null with wpscan_args=null
wpscan_args=[   "--no-banner",
                "--random-user-agent", 
                "--format", "cli-no-colour",
                "--disable-tls-checks" ]

# Whether not sending emails
send_email_report=No

# If set to yes, will send reports even is they is alert.
# Use with verbose=yes to send complete wpscan output by email all the time
always_send_reports=No

# Default email report recepients, will always receive email reports of all sites
# Must be a valid Json string
# Can be set to null with email_to=null
email_to=["alerts@domain.com"]

# Email settings
smtp_server=mailserver.de:587
smtp_auth=Yes
smtp_user=office
smtp_pass=p@assw0rd
smtp_ssl=Yes
from_email=wpwatcher@domain.com

# Set yes to print only errors and WPScan warnings
quiet=No

# Set yes to print wpscan out put every time
# Will email full wpscan output as well
verbose=No
```
## Scan Run

![WPWatcher Screenshot](/screens/wpwatcher.png "WPWatcher Run")

## Report

![WPWatcher Report](/screens/wpwatcher-report.png "WPWatcher Report")
