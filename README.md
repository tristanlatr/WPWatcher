# WPWatcher
WordPress Watcher is a Python wrapper for [WPScan](http://wpscan.org/) that manages scans on multiple sites and reports by email

## In a Nutshell
  - Scan multiple sites with WPScan
  - Define reporting emails addresses for every configured site individually and globally
  - Mail messages are divided in "Warnings", "Alerts", "Fixed" items, "Informations" and eventually "Errors"
  - Mail notification and verbosity can be configred in config file, additionnaly WPScan output can be attached to emails. 
  - Scan sites continuously at defined interval and handled VulnDB API limit.  
  - Local log file can be configured and also lists all the findings 
  - Define false positives strings for every configured site individually and globally
  - Define WPScan arguments for every configured site individually and globally
  - Parse the results differently whether wpscan argument `--format` is `json` or `cli`

## Prerequisites 
  - [WPScan](http://wpscan.org/) (itself requires Ruby and some libraries).   
  - Python 3 (standard libraries)
  - Tested on Linux and MacOS

<!-- #### Compatibility
Tested with WPScan 3.7 on :
- MacOS (WPScan install wil `HomeBrew`)
- Linux (WPScan installed with `RubyGems`)  
- Raspbian (WPScan installed with `RubyGems`)   -->

## Install
#### With PyPi (stable)
    pip3 install wpwatcher

#####  Update
```bash
pip3 install wpwatcher --upgrade
```

#### Or manually
```bash
git clone https://github.com/tristanlatr/WPWatcher.git
cd WPWatcher && python3 setup.py install
```

#### Try it out

    wpwatcher --url exemple.com exemple1.com

The command should be in your `PATH`, as well as `wpwatcher.py` (synonym of `wpwatcher`) and `wpscan_parser.py` (standalone WPScan output parser).

You can always run the python script directly 
                
    python3 ./wpwatcher.py --url exemple3.com -v

### Configure
Create and edit a new config file from template.   (  `--template_conf` argument print a default config file  )

```bash
wpwatcher --template_conf > ./wpwatcher.conf
vim ./wpwatcher.conf
```
See *Configuration* bellow to learn more about options and how to and configure the script.    

#### Execute

    wpwatcher [--conf File path [File path ...]] [...]

`--conf` is the main argument, you can specify multiple files. Will overwrites the keys with each successive file.  
If not specified, it will try to load config from files `~/.wpwatcher/wpwatcher.conf` , `~/wpwatcher.conf` and `./wpwatcher.conf`, in this order.

Other arguments will simply overwrite config values like `--url URL [URL ...]` or  `--verbose`.

See complete list of supported arguments in the sction *Full configuration options* bellow or use `wpwatcher --help`

#### Notes
- The script will automatically try to delete all temp `wpscan` files in `/tmp/wpscan` before starting scans
- You might want to use `--ff` (fail fast) when you're setting up and configuring the script. Abort scans when WPScan fails, useful to troubleshoot.
- All messages are printed to `stdout`.
- WPWatcher store a database of reports and compare reports one scan after another to notice for fixed issues and implement `resend_emails_after` config . Default location is `~/.wpwatcher/wp_reports.json`. If the databse cannot de loaded or missing, it will be (re)created.  Set `wp_reports=null` in the config to disable the storage of the Json file, the database will still be stored in memory when using `--daemon`.

### Return non zero status code if :
- One or more WPScan command failed
- Unable to send one or more email report
- Other errors

## Configuration

The script **must read a configuration file to set mail server settings, WPScan path and arguments**. If no config file is found, mail server settings, WPScan path and arguments and other config values will have default values.  

Setup mail server settings and turn on `send_email_report` in the config file if you want to receive reports.  

All options can be missing from config file.

See *Full configuration options* section below to see list of configurables values with CLI arguments and shortcuts. 

### Notes about WPScan API token

You need a WPScan API token (`--api-token`) in order to show vulnerability data and be alerted of vulnerable WordPress or plugin. 

You can get a free API token with 50 daily requests. Scanning a site generates a undefined number of requests, it depends on the WPScan config and the number of WordPress plugins. WPScan will fail if you have reached yout API limit. 

Turn on `api_limit_wait` to wait 24h and contuinue scans when API limit si reached.

If no API token is provided to WPScan, scans will trigger WARNING emails with outdated plugin or WordPress version.

### Scanning a large number of sites
Tip: you can configure `wp_sites` from a text file (one URL per line) using `--urls File path` argument (overwrite sites from config files).

If you have large number of sites to scan, you'll probably can't scan all your sites with 50 requests.  

Please make sure you respect the [WPScan license](https://github.com/wpscanteam/wpscan/blob/master/LICENSE).

#### Setup continuous scanning service
Caution: **do not configure crontab execution and continuous scanning at the same time** .   

Configure :
- `daemon_loop_sleep`: i.e. `12h` 
- `resend_emails_after` i.e.`5d` and 
- `api_limit_wait=Yes`. 

Recommended to use `--daemon` argument and not the config file value, otherwise `wpwatcher` will start by default in daemon mode.  
Launch WPWatcher in daemon mode:

    wpwatcher --daemon [--urls ./my_sites.txt] ...

Let's say you have 20 WordPress sites to scan but your API limit is reached after 8 sites, the program will sleep 24h and continue until all sites are scanned (2 days later). Then will sleep the configured time and start again.

Tip: `wpwatcher` and `wpscan` might not be in your execution environement `PATH`. If you run into file not found error, try to configure the full paths to executables and config files.

Note: By default a different database file will be used when using daemon mode `~/.wpwatcher/wp_reports.daemon.json`

Setup WPWatcher as a service.
-  With `systemctl`
    
    <details><summary><b>See</b></summary>
    <p>

    Create and configure the service file `/lib/systemd/system/wpwatcher.service`
    ```bash
    systemctl edit --full --force wpwatcher.service
    ```
    Adjust the following template service:  
    ```
    [Unit]
    Description=WPWatcher
    After=network.target
    StartLimitIntervalSec=0

    [Service]
    Type=simple
    Restart=always
    RestartSec=1
    ExecStart=/usr/local/bin/wpwatcher --daemon 
    User=user

    [Install]
    WantedBy=multi-user.target
    ```

    Enable the service to start on boot
    ```
    systemctl daemon-reload
    systemctl enable wpwatcher.service
    ```

    The service can be started/stopped with the following commands:
    ```
    systemctl start wpwatcher.service
    systemctl stop wpwatcher.service
    ```  

    Follow logs
    ```
    journalctl -u wpwatcher -f
    ```
    [More infos on systemctl](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system_administrators_guide/sect-managing_services_with_systemd-unit_files) 

    </p>
    </details>
- [Other systems](https://blog.frd.mn/how-to-set-up-proper-startstop-services-ubuntu-debian-mac-windows/)

#### Or schedule scans with cron
<details><summary><b>See</b></summary>
<p>
Make sure daemon feature if turned off.

- Crontab usage:

```
0 0 * * * wpwatcher --quiet
```

To print only ERRORS and WPScan ALERTS, use `--quiet` or set `quiet=Yes` in your config.  
You'll receive email alerts with cron `MAILTO` feature. Add `>/dev/null` to ignore.  


- Crontab with multiple config files usage:
    - `wpwatcher.conf`: contains all configurations except `wp_wites`
    - `wp_sites_1.conf`: contains first X sites
    - `wp_sites_2.conf`: contain the rest  ...  

    In your crontab, configure script to run at your convenience. For exemple, with two lists :
```
# Will run at 00:00 on Monday:
0 0 * * 1 wpwatcher --conf wpwatcher.conf wp_sites_1.conf --quiet
# Will run at 00:00 on Tuesday:
0 0 * * 2 wpwatcher --conf wpwatcher.conf wp_sites_2.conf --quiet
```
Warning, this kind of setup can lead into having two `wpwatcher` executions at the same time. This might result into database corruption because of conccurent accesses to reports database file.
</p>
</details>

### Simple configuration with mail report

Simple configuration file without SMTP authentication 

```ini
[wpwatcher]
wpscan_path=wpscan
wp_sites=   [ {"url":"exemple.com"},
              {"url":"exemple2.com"}  ]
wpscan_args=[   "--format", "json",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks",
                "--api-token", "YOUR_API_TOKEN" ]
send_email_report=Yes
email_to=["me@exemple.com"]
smtp_server=mailserver.exemple.com:25
from_email=WordPressWatcher@exemple.com
```
You can store the API Token in the WPScan default config file at `~/.wpscan/scan.yml` and not supply it via the wpscan CLI argument in the WPWatcher config file. See [WPSacn readme](https://github.com/wpscanteam/wpscan#save-api-token-in-a-file).

### Full configuration options

All configuration options with explanatory comments.

<details><summary><b>See</b></summary>
<p>

#### WPScan path
Path to wpscan executable. 
With RVM could be `/usr/local/rvm/gems/default/wrappers/wpscan`.  
If missing, assume `wpscan` is in your `PATH`

```ini
wpscan_path=wpscan
```
#### WPScan arguments
Global WPScan arguments.  
Must be a valid Json string.  
<!-- Set `"--format","json"` to use Json parsing feature.  
The list of warnings, alerts and infos might differ when using json  
    Email outpout will be more concice.   
    But not all informations are logged.   
Using `"--format", "cli"` will parse full WPScan output with [!] etc  
    Logs all informations   -->

See `wpscan --help` for more informations about WPScan options  
```ini
wpscan_args=[   "--format", "cli",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks",
                "--detection-mode", "aggressive",
                "--enumerate", "t,p,tt,cb,dbe,u,m"]
```
#### False positive strings
You can use this to ignore some warnmings or alerts.  
False positives will still be processed as infos: Use with care.   
Must be a valid Json string
```ini
false_positive_strings=["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"]
```
#### Monitored sites
List of dictionnary having a url, custom email report recepients, false positives and specific wpscan arguments.
Each dictrionnary must contain at least a `"url"` key.
Must be a valid Json string.
Must be supplied with config file or argument.
```ini
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
            "email_to":["site_owner3@domain.com"]
        }
    ]
```
Overwrite with arguments: `--url URL [URL...]` or `--urls File path`. Custom email report recepients, false positives and specific wpscan arguments are not supported with CLI arguments

#### Notifications

- Whether to send emails for alerting of the WPScan result (ALERT or other).  
If missing, default to No
```ini
send_email_report=No
```
Overwrite with arguments: `--send`
- Whether to report warnings and track the warnings fixes.
Will send WARNING notifications and will include warnings in ALERT reports.  
If missing, default to Yes
```ini
send_warnings=Yes
```
- Wheter to include Informations in the reports. Send INFO notifications if no warnings or alerts are found.  
If missing, default to No
```ini
send_infos=No
```
Overwrite with arguments: `--infos`
- Send ERROR notifications if wpscan exited with non zero status code.  
If missing, default to No
```ini
send_errors=No
```
Overwrite with arguments: `--errors`
- Attach text output file with raw WPScan output when sending a report  
```ini
attach_wpscan_output=No
```
Overwrite with arguments: `--attach`
- Global email report recepients, will always receive email reports for all sites.  
Must be a valid Json string
```ini
email_to=["securityalerts@domain.com"]
```
Overwrite with arguments: `--email_to Email [Email...]`
- Minimum time inverval between sending two report with the same status.  Examples of valid strings: `8h`, `2d8h5m20s`, `2m4s`
If missing, default to `0s`
```ini
resend_emails_after=3d
```
Overwrite with arguments: `--resend Time string`
- Send any error email to those addresses and not to other recepients (`email_to` options).  
Applicable only if `send_errors=Yes`.  
Must be a valid Json string
```ini
email_errors_to=["admins@domain.com"]
```

#### Mail server
- Send email reports as
```ini
from_email=WordPressWatcher@domain.com
```
- SMTP Email server and port
```ini
smtp_server=mailserver.de:25
```
- SMTP Use authentication. If missing, default to No
```ini
smtp_auth=No
```
- SMTP Username
```ini
smtp_user=office
```
- SMTP Password
```ini
smtp_pass=p@assw0rd
```
- SMTP Use SSL
```ini
smtp_ssl=Yes
```
#### Sleep when API limit reached
Wait 24h when API limit has been reached.  
Default behaviour will consider the API limit as a WPScan failure and continue the scans (if not fail_fast) leading into making lot's of failed commands
```ini
api_limit_wait=No
```
Overwrite with arguments: `--wait`
#### Daemon settings
- Daemon mode: loops forever. 
If missing, default to No
```ini
daemon=No
```
Overwrite with arguments: `--daemon`
- Sleep time between two scans.  
If missing, default to `0s`
```ini
daemon_loop_sleep=12h
```
#### Output
- Quiet
Print only errors and WPScan ALERTS
```ini
quiet=No
```
Overwrite with arguments: `--quiet`
- Verbose terminal output and logging.  
Print WPScan raw output and parsed WPScan results.
```ini
verbose=No
```
Overwrite with arguments: `--verbose`
- Local log file
```ini
log_file=/home/user/.wpwatcher/wpwatcher.log
```
#### Misc
- Raise exceptions with stack trace or exit when WPScan failed.  
Default behaviour is to log error, continue scans and return non zero status code when all scans are over
```ini
fail_fast=No
```
Overwrite with arguments: `--ff`
- Reports database file.  
If missing, will figure out a place based on your environment to store the database. Use `null` keyword to disable the storage of the Json database file.
```ini
wp_reports=/home/user/.wpwatcher/wp_reports.json
```
Overwrite with arguments: `--reports File path`

</p>
</details>

## Email reports

One report is generated per site and the reports are sent individually when finished scanning a website.

Email notification can have 4 status: 
- `ALERT`: You have a vulnerable Wordpress, theme or plugin
- `WARNING`: You have an oudated Wordpress, theme or plugin
- `FIXED`: All issues are fixed or ignored (warnings included if `send_warnings=Yes`) 
- `INFO`: WPScan did not find any issues with your site
- `ERROR`: WPScan failed

![WPWatcher Report List](/screens/wpwatcher-report-list.png "WPWatcher Report")


Tip: set `"--format","json"` in  `wpscan_args` config option to use the json parsing feature and have more concise email text. 

`wpwatcher` will use the `wpscan_parser.py` to parse WPScan output messages. Alerts, Warnings and Infos might differ whether you're using cli or json format.

![WPWatcher Report](/screens/wpwatcher-report.png "WPWatcher Report")

## Output

Log file and stdout outputs are easily grepable with the following log levels and keywords:
  - `CRITICAL`: Only used for `WPScan ALERT`
  - `ERROR`:  WPScan failed, send report failed or other errors
  - `WARNING`: Only used for `WPScan WARNING`
  - `INFO`: Used for info output , `WPScan INFO` and `FIXED` issues
  - `DEBUG`: Used for debug outup and raw WPScan output. 

In addition to log messages, the readable report, and raw WPScan output can be printed with `--verbose`.
<details><summary><b>See</b></summary>
<p>

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
</p>
</details>

## Library usage

<details><summary><b>See</b></summary>
<p>

- Init config dict from file with `build_config_files()` method  
- Customize the config if you want, you can overwrite any config values  
- Create a `WPWatcher` object with your desired configuration  
- Call `run_scans_and_notify()` method  

```python
from wpwatcher import WPWatcher, build_config_files
config,files=build_config_files(['./demo.conf']) # leave None to find default config file
config.update({ 'send_infos':   True,
                'wp_sites':     [   {'url':'exemple1.com'},
                                    {'url':'exemple2.com'}  ],
                'wpscam_args': ['--stealthy']
            })
w=WPWatcher(config)
w.run_scans_and_notify()
```
</p>
</details>

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
