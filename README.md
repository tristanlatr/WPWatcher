# WPWatcher
WordPress Watcher is a Python wrapper for [WPScan](http://wpscan.org/) that manages scans on multiple sites and reports by email

## In a Nutshell
  - Scan multiple sites with WPScan
  - Define reporting emails addresses for every configured site individually and globally
  - Mail messages are divided in "Warnings", "Alerts", "Informations" and eventually "Errors"
  - Mail notification and verbosity can be configred in config file 
  - Local log file can be configured and also lists all the findings 
  - Define false positives strings for every configured site individually and globally
  - Define WPScan arguments for every configured site individually and globally
  - Parse the results differently whether wpscan argument `--format` is `json` or `cli`

## Prerequisites 
  - [WPScan](http://wpscan.org/) (itself requires Ruby and some libraries).   
  - Python 3 (standard libraries)

## Install
```bash
git clone https://github.com/tristanlatr/WPWatcher.git
cd WPWatcher && python3 setup.py install
```

### Configure
Copy template config file on your system and configure script.  
```bash
curl https://raw.githubusercontent.com/tristanlatr/WPWatcher/master/template_config.txt > ~/wpwatcher.conf
vim ~/wpwatcher.conf
```
Loads `~/wpwatcher.conf` as the default config file

### Execute

    wpwatcher

`wpwatcher` command only takes one argument: `--conf <path>` 

The command should be in your `PATH` but you can always run the python script directly  
                
    python3 ./wpwatcher.py

### Crontab
Add the following line to crontab to run WPWatcher every day and ignore errors.  

    0 0 * * * wpwatcher 2> /dev/null

If you want to receive email alerts when script fail with cron `MAILTO` feature.

    0 0 * * * wpwatcher | grep 'ERROR'

To print only ERRORS and WPScan ALERTS, set `quiet=Yes` in your config.

#### Return non zero status code if :
- One or more WPScan command failed
- Unable to send one or more email report
- Other errors

## Compatibility
Tested with WPScan 3.7 on :
- MacOS (WPScan install wil `HomeBrew`) and 
- Linux CentOS 7 (WPScan installed with `RubyGems`)

## Configuration

The script must read a configuration file. If not specified with `--conf <path>` parameter, will try to load config from file `./wpwatcher.conf` or `~/wpwatcher.conf`.

All options can be missing from config file except `wp_sites`

#### No mail report

Minimalist configuration file
```ini
[wpwatcher]
wpscan_path=wpscan
wp_sites=   [ {"url":"exemple.com"},
              {"url":"exemple2.com"}  ]
```

#### Basic usage with mail report

Simple configuration file

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

File below lists all configuration options with explanatory comments.

```ini
[wpwatcher]
# Path to wpscan executable. On linuxes could be /usr/local/rvm/gems/ruby-2.6.0/wrappers/wpscan
# If missing , assume wpscan is in you path
wpscan_path=wpscan

# Monitored sites:
# List of dictionnary having a url, custom email report recepients, false positives and specific wpscan arguments
# Each dictrionnary must contain at least a "url" key
# Must be a valid Json string
# Cannot be missing
wp_sites=   [
        {   
            "url":"exemple.com",
            "email_to":["site_owner@domain.com"],
            "false_positive_strings":["Vulnerability 123"],
            "wpscan_args":["--stealthy"]
        },
        {   
            "url":"exemple2.com",
            "email_to":["site_owner2@domain.com"],
            "false_positive_strings":["Vulnerability 456"]
        },
        {   
            "url":"exemple3.com",
            "email_to":["site_owner3@domain.com"],
            "wpscan_args":["--enumerate", "vp,vt,cb,dbe,m"] 
        }
    ]

# Global false positive strings
# You can use this to ignore some warnmings or alerts.
# False positives will still be processed as infos: Use with care !
# Must be a valid Json string
false_positive_strings=["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]

# Global WPScan arguments.
# Must be a valid Json string
#
# Set "--format","json" to use Json parsing feature
# The list of warnings, alerts and infos might differ when using json 
#   Email outpout will be more concice. 
#   But not all informations are logged. 
# Using "--format", "cli" will parse full WPScan output with [!] etc
#   Logs all informations
wpscan_args=[   "--format", "cli",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks" ]

# Whether to send emails for alerting of the WPScan result (ALERT or other)
# If missing, default to No
send_email_report=No

# Whether to send warnings. 
# Will send WARNING notifications and will include warnings in ALERT reports
# If missing, default to Yes
send_warnings=Yes

# Wheter to include Informations in the reports
# Will send INFO notifications if no warnings or alerts are found
# If missing, default to No
send_infos=No

# Will send ERROR notifications if wpscan exited with non zero status code
# If missing, default to No
send_errors=No

# Global email report recepients, will always receive email reports for all sites
# Must be a valid Json string
email_to=["securityalerts@domain.com"]

# Applicable only if send_errors=Yes
# If set, will send any error output to those addresses (not to other)
# Must be a valid Json string
email_errors_to=["admins@domain.com"]

# Send email reports as
from_email=WordPressWatcher@domain.com

# SMTP Email server settings
smtp_server=mailserver.de:25
# SMTP Use authentication. If missing, default to No
smtp_auth=No
# SMTP Username
smtp_user=office
# SMTP Password
smtp_pass=p@assw0rd
# SMTP Use SSL
smtp_ssl=Yes

# Local log file
log_file=./wpwatcher.log
# Print only errors and WPScan ALERTs
quiet=No
# Verbose terminal output and logging.
# Print raw WPScan output before parsing
verbose=No
```

## Email reports

One report is generated per site and the reports are sent individually when finished scanning a website.

Email notification can have 4 status: 
- `ALERT`: You have a vulnerable Wordpress, theme or plugin
- `WARNING`: You have an oudated Wordpress, theme or plugin
- `INFO`: WPScan did not find any issues with your site
- `ERROR`: WPScan failed

![WPWatcher Report List](/screens/wpwatcher-report-list.png "WPWatcher Report")


Tip: set `"--format","json"` in  `wpscan_args` config option to have more consice email output


![WPWatcher Report](/screens/wpwatcher-report.png "WPWatcher Report")

## Output

Log file and stdout outputs are easily grepable with the following log levels and keywords:
  - `CRITICAL`: Only used for `WPScan ALERT`
  - `ERROR`:  WPScan failed, send report failed or other errors
  - `WARNING`: Only used for `WPScan WARNING`
  - `INFO`: Used for info output and `WPScan INFO`
  - `DEBUG`: Used for debug outup and raw WPScan output. 

```log
% python3 wpwatcher.py --conf ./test.conf
INFO - Read config file ./test.conf
INFO - Updating WPScan
INFO - Starting scans on configured sites
INFO - Scanning 'wp.exemple.com' with command: wpscan --format cli --no-banner --random-user-agent --disable-tls-checks --url wp.exemple.com
INFO - ** WPScan INFO wp.exemple.com ** [+] URL: http://wp.exemple.com/ [104.31.70.16] [+] Effective URL: https://wp.exemple.com/ [+] Started: Fri Mar 20 17:52:59 2020
INFO - ** WPScan INFO wp.exemple.com ** Interesting Finding(s):
INFO - ** WPScan INFO wp.exemple.com ** [+] Headers | Interesting Entries: |  - cf-cache-status: DYNAMIC |  - expect-ct: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct" |  - server: cloudflare |  - cf-ray: 5772a9d14da0ca63-YUL | Found By: Headers (Passive Detection) | Confidence: 100%
INFO - ** WPScan INFO wp.exemple.com ** [+] This site seems to be a multisite | Found By: Direct Access (Aggressive Detection) | Confidence: 100% | Reference: http://codex.wordpress.org/Glossary#Multisite
INFO - ** WPScan INFO wp.exemple.com ** [+] WordPress theme in use: julesr-aeets | Location: http://wp.exemple.com/wordpress/wp-content/themes/julesr-aeets/ | Style URL: http://wp.exemple.com/wordpress/wp-content/themes/julesr-aeets/style.css | | Found By: Urls In Homepage (Passive Detection) | Confirmed By: Urls In 404 Page (Passive Detection) | | The version could not be determined.
INFO - ** WPScan INFO wp.exemple.com ** [+] Enumerating All Plugins (via Passive Methods)
INFO - ** WPScan INFO wp.exemple.com ** [i] No plugins Found.
INFO - ** WPScan INFO wp.exemple.com ** [+] Enumerating Config Backups (via Passive and Aggressive Methods)
INFO - ** WPScan INFO wp.exemple.com ** Checking Config Backups -: |=======================================================================================|
INFO - ** WPScan INFO wp.exemple.com ** [i] No Config Backups Found.
INFO - ** WPScan INFO wp.exemple.com ** [+] Finished: Fri Mar 20 17:53:05 2020 [+] Requests Done: 55 [+] Cached Requests: 4 [+] Data Sent: 17.677 KB [+] Data Received: 153.06 KB [+] Memory used: 204.426 MB [+] Elapsed time: 00:00:06
INFO - ** WPScan INFO wp.exemple.com ** [False positive] [!] No WPVulnDB API Token given, as a result vulnerability data has not been output. [!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up
WARNING - ** WPScan WARNING wp.exemple.com ** [+] WordPress version 5.1.1 identified (Insecure, released on 2019-03-13). | Found By: Meta Generator (Passive Detection) |  - https://wp.exemple.com/, Match: 'WordPress 5.1.1' | Confirmed By: Most Common Wp Includes Query Parameter In Homepage (Passive Detection) |  - https://wp.exemple.com/wordpress/wp-includes/css/dist/block-library/style.min.css?ver=5.1.1
INFO - No WPWatcher email report have been sent for site wp.exemple.com. If you want to receive emails, set send_email_report=Yes in the config.
INFO - Scans finished successfully.
```

## Notes
- The script will automatically try to delete all temp wpscan files in `/tmp/wpscan` before starting scans

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
