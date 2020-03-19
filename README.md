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

Tested on 
- MacOS (WPScan install wil HomeBrew) and 
- Linux CentOS 7 (installed with RubyGems)

## Configuration
If not specified with `--conf`, will use `./wpwatcher.conf` or `~/wpwatcher.conf` by default.
```ini
[wpwatcher]

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
# Can be set to null with false_positive_strings=null
# You can use this to ignore some infos, warnmings or alerts
# Use with care
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
#
# Set "--format","json" to use Json parsing feature
# The list of warnings, alerts and infos might differ when using json 
#   The outpout is more concice and less false positives 
#   But not all informations are logged. 
# Using "--format", "cli" will parse full WPScan output with [!] etc
#   Generates more false positives but logs all information
wpscan_args=[   "--format", "cli",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks" ]

# Whether to send emails
send_email_report=No

# Wheter to include warnings in the reports Alerts
# If set to No, no reports will be sent if WPScan find only warnings
#     and always_send_reports=No 
send_warnings=Yes

# Wheter to include Informations in the reports
send_infos=Yes

# If set to yes, will send reports even is there is no alert.
# Will send emails even if wpscan exited with non zero status code
# Will NOT send emails if there is no alerts and both send_warnings and send_infos are False
always_send_reports=No

# Default email report recepients, will always receive email reports of all sites
# Must be a valid Json string
# Can be set to null with email_to=null
email_to=["securityalerts@domain.com"]

# Applicable only if always_send_report=Yes
# If set, will send any error output to this address, 
#   not the pre configured reports recepients in email_to fields.
email_errors_to=["admins@domain.com"]

# Email settings
smtp_server=mailserver.de:587
smtp_auth=Yes
smtp_user=office
smtp_pass=p@assw0rd
smtp_ssl=Yes
from_email=wpwatcher@domain.com

# Set yes to print only errors and WPScan warnings
quiet=No

# Verbose terminal output and logging.
# Print raw WPScan output before parsing
verbose=No
```
## Scan Run

![WPWatcher Screenshot](/screens/wpwatcher.png "WPWatcher Run")

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
- Tristan 
