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

#### Update
```bash
git pull && python3 setup.py install
```

### Configure
Copy template config file on your system and configure script.  
See *Configuration* bellow to learn more about options.
```bash
cp ./template_config.txt ~/wpwatcher.conf
vim ~/wpwatcher.conf
```
Loads `~/wpwatcher.conf` as the default config file

### Execute

    wpwatcher

Messages are printed to `stdout`

The command should be in your `PATH` but you can always run the python script directly  
                
    python3 ./wpwatcher.py

### Crontab
Add the following line to crontab to run WPWatcher every day and ignore errors.  

    0 0 * * * wpwatcher >/dev/null 2>&1

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

The script must read a configuration file to set mail server settings, WPScan path and arguments. If no config file is found, mail server settings, WPScan path and arguments will have default values.  
Setup mail server settings in the config file if you want to receive reports.  

`wpwatcher` command takes some arguments: `--conf <path>` is the main one, other arguments will simply overwrite config values. See *Command arguments* section below to see list of configurables values with CLI arguments. 

If not specified with `--conf <path>` parameter, will try to load config from file `./wpwatcher.conf` or `~/wpwatcher.conf`.  

All options can be missing from config file.

#### Basic usage with mail report

Simple configuration file without SMTP authentication 

```ini
[wpwatcher]
wpscan_path=wpscan
wp_sites=   [ {"url":"exemple.com"},
              {"url":"exemple2.com"}  ]
wpscan_args=[   "--format", "json",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks" ]
send_email_report=Yes
email_to=["me@exemple.com"]
smtp_server=mailserver.exemple.com:25
from_email=WordPressWatcher@exemple.com
```

#### Full configuration options

All configuration options with explanatory comments.

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

# Will attach text output file with raw WPScan output when sending a report
attach_wpscan_output=No

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
# Print WPScan raw output 
# Print parsed WPScan results
verbose=No

# Raise exceptions with stack trace or exit when WPScan failed
# Default behaviour is too log error, continue scans and return non zero status code when all scans are over
fail_fast=No
```

#### Command arguments

Some config arguments can be passed to the `wpwatcher` command.   
Warning: it will overwrite previous values from config file.
```
  -h, --help            show this help message and exit
  --conf File path [File path ...]
  --send_email_report
  --send_infos
  --send_errors
  --attach_wpscan_output
  --fail_fast
  --wp_sites URL [URL ...]
  --email_to Email [Email ...]
  --email_errors_to Email [Email ...]
  --false_positive_strings String [String ...]
  -v, --verbose
  -q, --quiet
```


## Email reports

One report is generated per site and the reports are sent individually when finished scanning a website.

Email notification can have 4 status: 
- `ALERT`: You have a vulnerable Wordpress, theme or plugin
- `WARNING`: You have an oudated Wordpress, theme or plugin
- `INFO`: WPScan did not find any issues with your site
- `ERROR`: WPScan failed

![WPWatcher Report List](/screens/wpwatcher-report-list.png "WPWatcher Report")


Tip: set `"--format","json"` in  `wpscan_args` config option to use the json parsing feature. 

`wpwatcher` will use the `wpscan_parser.py` to parse WPScan output messages. Alerts, Warnings and Infos might differ whether you're using cli or json format.

![WPWatcher Report](/screens/wpwatcher-report.png "WPWatcher Report")

## Output

Log file and stdout outputs are easily grepable with the following log levels and keywords:
  - `CRITICAL`: Only used for `WPScan ALERT`
  - `ERROR`:  WPScan failed, send report failed or other errors
  - `WARNING`: Only used for `WPScan WARNING`
  - `INFO`: Used for info output and `WPScan INFO`
  - `DEBUG`: Used for debug outup and raw WPScan output. 

```log
% python3 ./wpwatcher.py --conf ./test.conf
INFO - Updating WPScan
INFO - Deleted temp WPScan files in /tmp/wpscan/
INFO - Starting scans on configured sites
INFO - Scanning 'wp.exemple.com' with command: wpscan --format json --no-banner --random-user-agent --disable-tls-checks --enumerate cb,dbe,u,m --api-token HqarfnE6e4FpowFAGyS9rVcqGte2SL7vJtmYWcl5gIc --url wp.exemple.com
INFO - ** WPScan INFO wp.exemple.com ** Target URL: http://wp.exemple.com/ IP: 104.31.70.16 Effective URL: https://wp.exemple.com/
INFO - ** WPScan INFO wp.exemple.com ** Interesting finding: [headers] Headers URL: https://wp.exemple.com/ Interesting Entries: cf-cache-status: DYNAMIC, expect-ct: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct", server: cloudflare, cf-ray: 578db0a64b7b3f7b-YUL
INFO - ** WPScan INFO wp.exemple.com ** Interesting finding: [multisite] This site seems to be a multisite URL: http://wp.exemple.com/wordpress/wp-signup.php References: url: http://codex.wordpress.org/Glossary#Multisite
INFO - ** WPScan INFO wp.exemple.com ** Running WordPress version: 5.1.1  Interesting Entries: https://wp.exemple.com/, Match: 'WordPress 5.1.1'
INFO - ** WPScan INFO wp.exemple.com ** WordPress user found: secretariat
INFO - ** WPScan INFO wp.exemple.com ** WPScan did not find any WordPress config backups
INFO - ** WPScan INFO wp.exemple.com ** WPScan did not find any WordPress db exports
INFO - ** WPScan INFO wp.exemple.com ** WPScan did not find any medias
WARNING - ** WPScan WARNING wp.exemple.com ** The version of your WordPress site is out of date. Status insecure for version 5.1.1
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation Fixed In: 5.1.2 References: - CVE-2019-16222 url: https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/, https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68, https://hackerone.com/reports/339483 - WPVulnDB(9867): https://wpvulndb.com/vulnerabilities/9867
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress 5.0-5.2.2 - Authenticated Stored XSS in Shortcode Previews Fixed In: 5.1.2 References: - CVE-2019-16219 url: https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/, https://fortiguard.com/zeroday/FG-VD-18-165, https://www.fortinet.com/blog/threat-research/wordpress-core-stored-xss-vulnerability.html - WPVulnDB(9864): https://wpvulndb.com/vulnerabilities/9864
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.2.3 - Stored XSS in Customizer Fixed In: 5.1.3 References: - CVE-2019-17674 url: https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/, https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html - WPVulnDB(9908): https://wpvulndb.com/vulnerabilities/9908
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts Fixed In: 5.1.3 References: - CVE-2019-17671 url: https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/, https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html, https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308, https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/ - WPVulnDB(9909): https://wpvulndb.com/vulnerabilities/9909
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.2.3 - Stored XSS in Style Tags Fixed In: 5.1.3 References: - CVE-2019-17672 url: https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/, https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html - WPVulnDB(9910): https://wpvulndb.com/vulnerabilities/9910
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.2.3 - JSON Request Cache Poisoning Fixed In: 5.1.3 References: - CVE-2019-17673 url: https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/, https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de, https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html - WPVulnDB(9911): https://wpvulndb.com/vulnerabilities/9911
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation Fixed In: 5.1.3 References: - CVE-2019-17669 - CVE-2019-17670 url: https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/, https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2, https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html - WPVulnDB(9912): https://wpvulndb.com/vulnerabilities/9912
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.2.3 - Admin Referrer Validation Fixed In: 5.1.3 References: - CVE-2019-17675 url: https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/, https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0, https://blog.wpscan.org/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html - WPVulnDB(9913): https://wpvulndb.com/vulnerabilities/9913
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.3 - Improper Access Controls in REST API Fixed In: 5.1.4 References: - CVE-2019-20043 - CVE-2019-16788 url: https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/, https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw - WPVulnDB(9973): https://wpvulndb.com/vulnerabilities/9973
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.3 - Stored XSS via Crafted Links Fixed In: 5.1.4 References: - CVE-2019-20042 - CVE-2019-16773 - CVE-2019-16773 url: https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/, https://hackerone.com/reports/509930, https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d, https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7 - WPVulnDB(9975): https://wpvulndb.com/vulnerabilities/9975
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.3 - Stored XSS via Block Editor Content Fixed In: 5.1.4 References: - CVE-2019-16781 - CVE-2019-16780 url: https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/, https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v - WPVulnDB(9976): https://wpvulndb.com/vulnerabilities/9976
CRITICAL - ** WPScan ALERT wp.exemple.com ** Vulnerable wordpress: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass Fixed In: 5.1.4 References: - CVE-2019-20041 url: https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/, https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53 - WPVulnDB(10004): https://wpvulndb.com/vulnerabilities/10004
INFO - No WPWatcher ALERT email report have been sent for site wp.exemple.com. If you want to receive emails, set send_email_report=Yes in the config.
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
