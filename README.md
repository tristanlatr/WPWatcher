


<h1 align="center">WPWatcher</h1>

<p align="center">
  Automating <a href="https://wpscan.org/" title="homepage" target="_blank">WPScan</a> to scan and report vulnerable Wordpress sites
  <br>
</p>

<p align="center">
  <a href="https://github.com/tristanlatr/WPWatcher/actions" target="_blank"><img src="https://github.com/tristanlatr/WPWatcher/workflows/test/badge.svg"></a>
  <a href="https://codecov.io/gh/tristanlatr/WPWatcher" target="_blank"><img src="https://codecov.io/gh/tristanlatr/WPWatcher/branch/master/graph/badge.svg"></a>
  <a href="https://pypi.org/project/WPWatcher/" target="_blank"><img src="https://badge.fury.io/py/wpwatcher.svg"></a>
  <a href="https://codeclimate.com/github/tristanlatr/WPWatcher" target="_blank"><img src="https://codeclimate.com/github/tristanlatr/WPWatcher/badges/gpa.svg"></a>

</p>

## Features
  - Scan multiple sites with WPScan
  - Define reporting emails addresses for every configured site individually and globally
  - Parse WPScan output and divide the results in "Warnings", "Alerts", "Fixed" items, "Informations" and eventually "Errors"
  - Mail notification and verbosity can be configred, additionnaly WPScan output can be attached to emails. 
  - Scan sites continuously at defined interval and handled VulnDB API limit.  
  - Local log file can be configured and also lists all the findings 
  - Define false positives strings for every configured site individually and globally
  - Define WPScan arguments for every configured site individually and globally
  - Speed up scans using several asynchronous workers
  - Optionnal follow URL redirection if WPScan fails and propose to ignore main redirect 
  - Save raw WPScan results into files
  - Parse the results differently whether wpscan argument `--format` is `json` or `cli`
  - Optionnal prescan sites without API token, then use token on site having issues (i.e. outdated Wordpress, plugin version) only to save calls ;-)

## Prerequisites 
  - [WPScan](http://wpscan.org/) (itself requires Ruby and some libraries).   
  - Python 3 (standard libraries)
  - Tested on Linux and MacOS

<!-- #### Compatibility
Tested with WPScan 3.7.11 on :
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

#### Manually (devel)
```bash
git clone https://github.com/tristanlatr/WPWatcher.git
cd WPWatcher && python3 setup.py install
```

`wpwatcher` should be in your `PATH` but you can always run the python script directly 
    
    python3 ./wpwatcher/cli.py --url exemple3.com -v

<!-- 
Before version 0.5.7 

    python3 ./wpwatcher.py --url exemple3.com -v
 -->

#### With docker

<details><summary><b>See docker installation steps</b></summary>
<p>

- Clone the repository
- Install docker image 

With the user UID, `wpwatcher` will then run as this user. The following will use the current logged user UID. Won't work if you build the image as root.
```bash
docker image build \
    --build-arg USER_ID=$(id -u ${USER}) \
    -t wpwatcher .
```
- Create and map a WPWatcher folder containing your `wpwatcher.conf` file to the docker runner.
`wpwatcher` command would look like :  
```bash
docker run -it -v '/path/to/wpwatcher.conf/folder/:/wpwatcher/.wpwatcher/' wpwatcher [...]
```

Or install without UID mapping, it will use [docker volumes](https://stackoverflow.com/questions/18496940/how-to-deal-with-persistent-storage-e-g-databases-in-docker?answertab=votes#tab-top) in order to write files and save reports
```bash
docker image build -t wpwatcher .
```

- `wpwatcher` command would look like :  
```
docker run -it -v 'wpwatcher_data:/wpwatcher/.wpwatcher/' wpwatcher
```
<!-- - Then, as root, check `docker volume inspect wpwatcher_data` to see Mountpoint, other WPWatcher files and create your config file if you want
```bash
docker run -it wpwatcher --template_conf > /var/lib/docker/volumes/wpwatcher_data/_data/wpwatcher.conf
vim /var/lib/docker/volumes/wpwatcher_data/_data/wpwatcher.conf
``` -->

Try it out (No persistent storage)
```bash
docker run -it wpwatcher --url exemple1.com
```

Create an alias with volume mapping your good to go
```
alias wpwatcher="docker run -it -v 'volume-name-or-path-to-folder:/wpwatcher/.wpwatcher/' wpwatcher"
```
</p>
</details>

#### Try it out
Simple usage, scan 2 sites with default config

    wpwatcher --url exemple.com exemple1.com

Load sites from text file , pass WPScan arguments , follow redirection if WPScan failed , use 5 asynchronous workers , email custom recepients if any alert or warning with full WPScan output attached. If you reach your API limit, it will wait and continue 24h later.

```bash
wpwatcher --urls sites.txt \
        --wpscan_args "--rua --force --stealthy --api-token <TOKEN>" \
        --follow_redirect \
        --workers 5 \
        --send --attach \
        --email_to collaborator1@office.ca collaborator2@office.ca \
        --api_limit_wait
```

#### Notes on script behaviours
- The script will automatically try to delete all temp `wpscan` files in `/tmp/wpscan` before starting scans
- You might want to use `--ff` (fail fast) when you're setting up and configuring the script. Abort scans when WPScan fails, useful to troubleshoot.
- All messages are printed to `stdout`.
- WPWatcher store a database of reports and compare reports one scan after another to notice for fixed issues and implement `resend_emails_after` config . Default location is `~/.wpwatcher/wp_reports.json`.  Set `wp_reports=null` in the config to disable the storage of the Json file, the database will still be stored in memory when using `--daemon`.

### Return non zero status code if :
- One or more WPScan command failed
- Unable to send one or more email report
- Other errors

## Configuration

The script **must read a configuration file to setup mail server settings and other otions**. Setup mail server settings and turn on `send_email_report` in the config file or use `--send` if you want to receive reports.  
See *Full configuration options* section below to see list of configurables values with CLI arguments and shortcuts. 

Select config file with `--conf File path`. You can specify multiple files. Will overwrites the keys with each successive file. If not specified, it will try to load config from files `~/.wpwatcher/wpwatcher.conf` , `~/wpwatcher.conf` and `./wpwatcher.conf`, in this order.

Create and edit a new config file from template.   (  `--template_conf` argument print a default config file  )

```bash
wpwatcher --template_conf > ./wpwatcher.conf
vim ./wpwatcher.conf
```
Other arguments will simply overwrite config values.

See complete list of options in the section *Full configuration options* bellow or use `wpwatcher --help` to see options configurable with CLI.

### Notes about WPScan API token

You need a WPScan API token in order to show vulnerability data and be alerted of vulnerable WordPress or plugin. If you have large number of sites to scan, you'll probably can't scan all your sites because of the limited amount of daily API request. Turn on `api_limit_wait` to wait 24h and contuinue scans when API limit si reached.  
If no API token is provided to WPScan, scans will still trigger WARNING emails with outdated plugin or WordPress version.
<!-- You can get a free API token with 50 daily requests. Scanning a site generates a undefined number of requests, it depends on the WPScan config and the number of WordPress plugins. WPScan will fail if you have reached yout API limit.  -->
<!-- ### Scanning a large number of sites
Tips: 
- You can configure `wp_sites` from a text file (one URL per line) using `--urls File path` argument (overwrite sites from config files).
- Speed up the scans with multiple asynchronous workers `--workers Number` option   -->
Please make sure you respect the [WPScan license](https://github.com/wpscanteam/wpscan/blob/master/LICENSE).

#### Setup continuous scanning service, daemon mode

<details><summary><b>See details and how to</b></summary>
<p>

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

    Create and configure the service file `/lib/systemd/system/wpwatcher.service`
    ```bash
    systemctl edit --full --force wpwatcher.service
    ```
    Adjust `ExecStart` and `User` in the following template service file:  
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


- For other systems, please refer to the appropriate [documentation](https://blog.frd.mn/how-to-set-up-proper-startstop-services-ubuntu-debian-mac-windows/)

</p>
</details>

#### Or schedule scans with cron
Caution: **do not configure crontab execution and continuous scanning at the same time** .   
<details><summary><b>See contab usage</b></summary>
<p>

- Crontab usage:

```
0 0 * * * wpwatcher --quiet
```

To print only ERRORS and WPScan ALERTS, use `--quiet` or set `quiet=Yes` in your config.  
You'll receive email alerts with cron `MAILTO` feature. Add `>/dev/null` to ignore.  

- Crontab with multiple config files usage:
    - `wpwatcher.conf`: contains all configurations except `wp_wites`
    - `site1.txt`: contains first X urls
    - `site2.txt`: contain the rest  ...  

    In your crontab, configure script to run at your convenience. For exemple, with two lists :
```
# Will run at 00:00 on Monday:
0 0 * * 1 wpwatcher --conf wpwatcher.conf --urls site1.txt --quiet
# Will run at 00:00 on Tuesday:
0 0 * * 2 wpwatcher --conf wpwatcher.conf --urls sites2.txt --quiet
```
Warning, this kind of setup can lead into having two `wpwatcher` executions at the same time. This might result into failure and/or database corruption because of conccurent accesses to reports database file.
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

<details><summary><b>See all configuration options with explanatory comments.</b></summary>
<p>

#### WPScan path
Path to wpscan executable. 
With RVM could be `/usr/local/rvm/gems/default/wrappers/wpscan`.  
Path is parsed with shlex.  
If missing, assume `wpscan` is in your `PATH`.  

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
Overwrite with `--wpargs "WPScan arguments"`. If you run into option parsing error, start the arguments string with a space or use equals sign `--wpargs="[...]"` to avoid [argparse bug](https://stackoverflow.com/questions/16174992/cant-get-argparse-to-read-quoted-string-with-dashes-in-it?noredirect=1&lq=1).
#### False positive strings
You can use this to ignore some warnings or alerts.  
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
- Send ERROR notifications if wpscan failed.  
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
Overwrite with argument: `--loop Time string`
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
Overwrite with argument: `--log File path`
- Save WPScan results to files as they are scanned
```ini
wpscan_output_folder=/home/user/Documents/WPScanResults/
```
Overwrite with argument: `--wpout Folder path`
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
- Number of asynchronous workers. Speed up the scans.  
If missing, default to `1`, synchronous iterating. 
```ini
asynch_workers=5
```
Overwrite with arguments: `--workers Number`
- Follow redirection when WPScan failed and propose to use `--ignore-main-redirect`.  
If missing, default to `No` 
```ini
follow_redirect=Yes
```
Overwrite with arguments: `--follow`

Prescan sites without API token, then use API token only on site with outdated pugin version or WordPress version only to save API calls

```ini
prescan_without_api_token=Yes
```
Overwrite with argument `--prescan`

Scan timeout. Default to `5m`
```ini
scan_timeout=10m
```

</p>
</details>

See options configurable with CLI, run `wpwatcher --help`

## Email reports

One report is generated per site and the reports are sent individually when finished scanning a website.

Email notification can have 5 status: 
- `ALERT`: You have a vulnerable Wordpress, theme or plugin
- `WARNING`: You have an oudated Wordpress, theme or plugin
- `FIXED`: All issues are fixed or ignored (warnings included if `send_warnings=Yes`) 
- `INFO`: WPScan did not find any issues with your site
- `ERROR`: WPScan failed

![WPWatcher Report List](/screens/wpwatcher-report-list.png "WPWatcher Report")

Tip: set `"--format","json"` in  `wpscan_args` config option to use the json parsing feature and have more concise email text. 

Alerts, Warnings and Infos might differ whether you're using cli or json format.

![WPWatcher Report](/screens/wpwatcher-report.png "WPWatcher Report")

## Output

Log file and stdout outputs are easily grepable with the following log levels and keywords:
  - `CRITICAL`: Only used for `WPScan ALERT`
  - `ERROR`:  WPScan failed, send report failed or other errors
  - `WARNING`: Only used for `WPScan WARNING`
  - `INFO`: Used for info output , `WPScan INFO` and `FIXED` issues
  - `DEBUG`: Used for debug outup and raw WPScan output. 

In addition to log messages, the readable report, and raw WPScan output can be printed with `--verbose`.
<details><summary><b>See output sample</b></summary>
<p>

```log
% wpwatcher --url www.exemple.com www.exemple2.com 
INFO - WPWatcher -  Automating WPscan to scan and report vulnerable Wordpress sites
INFO - Load config file(s) : ['/Users/user/Documents/WPWatcher/wpwatcher.conf']
INFO - Deleted temp WPScan files in /tmp/wpscan/
INFO - Load wp_reports database: /Users/user/.wpwatcher/wp_reports.json
INFO - Starting scans on 2 configured sites
INFO - Scanning site http://www.exemple.com
INFO - ** WPScan INFO http://www.exemple.com ** [+] URL: http://www.exemple.com/ [167.71.91.231] [+] Effective URL: https://www.exemple.com/ [+] Started: Tue Apr 28 19:30:39 2020
INFO - ** WPScan INFO http://www.exemple.com ** Interesting Finding(s):
INFO - ** WPScan INFO http://www.exemple.com ** [+] Headers | Interesting Entry: server: nginx | Found By: Headers (Passive Detection) | Confidence: 100%
INFO - ** WPScan INFO http://www.exemple.com ** [+] XML-RPC seems to be enabled: https://www.exemple.com/xmlrpc.php | Found By: Link Tag (Passive Detection) | Confidence: 100% | Confirmed By: Direct Access (Aggressive Detection), 100% confidence | References: |  - http://codex.wordpress.org/XML-RPC_Pingback_API |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access
INFO - ** WPScan INFO http://www.exemple.com ** [+] This site seems to be a multisite | Found By: Direct Access (Aggressive Detection) | Confidence: 100% | Reference: http://codex.wordpress.org/Glossary#Multisite
INFO - ** WPScan INFO http://www.exemple.com ** [+] This site has 'Must Use Plugins': http://www.exemple.com/wp-content/mu-plugins/ | Found By: Direct Access (Aggressive Detection) | Confidence: 80% | Reference: http://codex.wordpress.org/Must_Use_Plugins
INFO - ** WPScan INFO http://www.exemple.com ** [+] WordPress version 4.9.13 identified (Latest, released on 2019-12-12). | Found By: Rss Generator (Passive Detection) |  - https://www.exemple.com/feed/, <generator>https://wordpress.org/?v=4.9.13</generator> |  - https://www.exemple.com/comments/feed/, <generator>https://wordpress.org/?v=4.9.13</generator>
INFO - ** WPScan INFO http://www.exemple.com ** [+] WordPress theme in use: bb-theme-child | Location: http://www.exemple.com/wp-content/themes/bb-theme-child/ | Style URL: https://www.exemple.com/wp-content/themes/bb-theme-child/style.css?ver=4.9.13 | Style Name: Beaver Builder Child Theme | Style URI: http://www.wpbeaverbuilder.com | Description: An example child theme that can be used as a starting point for custom development.... | Author: The Beaver Builder Team | Author URI: http://www.fastlinemedia.com | Found By: Css Style In Homepage (Passive Detection) | Confirmed By: Css Style In 404 Page (Passive Detection) | Version: 1.0 (80% confidence) | Found By: Style (Passive Detection) |  - https://www.exemple.com/wp-content/themes/bb-theme-child/style.css?ver=4.9.13, Match: 'Version: 1.0'
INFO - ** WPScan INFO http://www.exemple.com ** [+] Enumerating All Plugins (via Passive Methods) [+] Checking Plugin Versions (via Passive and Aggressive Methods)
INFO - ** WPScan INFO http://www.exemple.com ** [i] Plugin(s) Identified:
INFO - ** WPScan INFO http://www.exemple.com ** [+] bb-plugin | Location: http://www.exemple.com/wp-content/plugins/bb-plugin/ | Found By: Urls In Homepage (Passive Detection) | Confirmed By: Urls In 404 Page (Passive Detection) | The version could not be determined.
INFO - ** WPScan INFO http://www.exemple.com ** [+] bbpowerpack | Location: http://www.exemple.com/wp-content/plugins/bbpowerpack/ | Found By: Urls In Homepage (Passive Detection) | Confirmed By: Urls In 404 Page (Passive Detection) | The version could not be determined.
INFO - ** WPScan INFO http://www.exemple.com ** [+] Enumerating Config Backups (via Passive and Aggressive Methods)
INFO - ** WPScan INFO http://www.exemple.com ** Checking Config Backups -: |================================================================================================================================================================================|
INFO - ** WPScan INFO http://www.exemple.com ** [i] No Config Backups Found.
INFO - ** WPScan INFO http://www.exemple.com ** [+] Finished: Tue Apr 28 19:30:47 2020 [+] Requests Done: 71 [+] Cached Requests: 4 [+] Data Sent: 19.451 KB [+] Data Received: 3.523 MB [+] Memory used: 247.629 MB [+] Elapsed time: 00:00:07
INFO - ** WPScan INFO http://www.exemple.com ** [False positive] [!] No WPVulnDB API Token given, as a result vulnerability data has not been output. [!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up
WARNING - ** WPScan WARNING http://www.exemple.com ** [+] stream | Location: http://www.exemple.com/wp-content/plugins/stream/ | Last Updated: 2020-03-19T21:55:00.000Z | [!] The version is out of date, the latest version is 3.4.3 | Found By: Comment (Passive Detection) | Version: 3.2.3 (100% confidence) | Found By: Comment (Passive Detection) |  - https://www.exemple.com/, Match: 'Stream WordPress user activity plugin v3.2.3' | Confirmed By: Readme - Stable Tag (Aggressive Detection) |  - http://www.exemple.com/wp-content/plugins/stream/readme.txt
INFO - Not sending WPWatcher WARNING email report for site http://www.exemple.com. To receive emails, setup mail server settings in the config and enable send_email_report or use --send.
INFO - Progress - [===============               ] 50% - 1 / 2
INFO - Scanning site http://www.exemple2.com
INFO - ** WPScan INFO http://www.exemple2.com ** [+] URL: http://www.exemple2.com/ [104.31.71.16] [+] Effective URL: https://www.exemple2.com/ [+] Started: Tue Apr 28 19:30:51 2020
INFO - ** WPScan INFO http://www.exemple2.com ** Interesting Finding(s):
INFO - ** WPScan INFO http://www.exemple2.com ** [+] Headers | Interesting Entries: |  - cf-cache-status: DYNAMIC |  - expect-ct: max-age=604800, report-uri="https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct" |  - server: cloudflare |  - cf-ray: 58b492d1ec18ca67-YUL |  - cf-request-id: 0264ba172d0000ca67e8275200000001 | Found By: Headers (Passive Detection) | Confidence: 100%
INFO - ** WPScan INFO http://www.exemple2.com ** [+] This site seems to be a multisite | Found By: Direct Access (Aggressive Detection) | Confidence: 100% | Reference: http://codex.wordpress.org/Glossary#Multisite
INFO - ** WPScan INFO http://www.exemple2.com ** [+] WordPress theme in use: julesr-aeets | Location: http://www.exemple2.com/wordpress/wp-content/themes/julesr-aeets/ | Style URL: http://www.exemple2.com/wordpress/wp-content/themes/julesr-aeets/style.css | Found By: Urls In Homepage (Passive Detection) | Confirmed By: Urls In 404 Page (Passive Detection) | The version could not be determined.
INFO - ** WPScan INFO http://www.exemple2.com ** [+] Enumerating All Plugins (via Passive Methods)
INFO - ** WPScan INFO http://www.exemple2.com ** [i] No plugins Found.
INFO - ** WPScan INFO http://www.exemple2.com ** [+] Enumerating Config Backups (via Passive and Aggressive Methods)
INFO - ** WPScan INFO http://www.exemple2.com ** Checking Config Backups -: |================================================================================================================================================================================|
INFO - ** WPScan INFO http://www.exemple2.com ** [i] No Config Backups Found.
INFO - ** WPScan INFO http://www.exemple2.com ** [+] Finished: Tue Apr 28 19:30:58 2020 [+] Requests Done: 55 [+] Cached Requests: 4 [+] Data Sent: 19.047 KB [+] Data Received: 156.492 KB [+] Memory used: 214.516 MB [+] Elapsed time: 00:00:06
INFO - ** WPScan INFO http://www.exemple2.com ** [False positive] [!] No WPVulnDB API Token given, as a result vulnerability data has not been output. [!] You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up
WARNING - ** WPScan WARNING http://www.exemple2.com ** [+] WordPress version 5.1.1 identified (Insecure, released on 2019-03-13). | Found By: Meta Generator (Passive Detection) |  - https://www.exemple2.com/, Match: 'WordPress 5.1.1' | Confirmed By: Most Common Wp Includes Query Parameter In Homepage (Passive Detection) |  - https://www.exemple2.com/wordpress/wp-includes/css/dist/block-library/style.min.css?ver=5.1.1
INFO - Not sending WPWatcher WARNING email report for site http://www.exemple2.com. To receive emails, setup mail server settings in the config and enable send_email_report or use --send.
INFO - Progress - [==============================] 100% - 2 / 2
INFO - Results summary
Site                            Status   Last scan            Last email           Issues   Problematic component(s)
http://www.exemple.com     WARNING  2020-04-28T19-30-32  None                 1        [+] stream
http://www.exemple2.com                WARNING  2020-04-28T19-30-47  None                 1        [+] WordPress version 5.1.1 identified (Insecure, released on 2019-03-13).
INFO - Updated 2 reports in database: /Users/user/.wpwatcher/wp_reports.json
INFO - Scans finished successfully.
```
</p>
</details>

## Json database summary generator

Do not use on a json file currently used by a `wpwatcher` execution.  

Load default database

    wpwatcher --wprs

Load specific file

    wpwatcher --wprs ~/.wpwatcher/wp_reports.json

<details><summary><b>See screenshot</b></summary>
<p>

![WPWatcher Report summary](/screens/reports-summary-wprs.png "WPWatcher Reports summary")

</p>
</details>

## Library usage

<details><summary><b>See guidelines and exemple</b></summary>
<p>

- Init config dict from file with `WPWatcherConfig().build_config()` method  
- Customize the config if you want, you can overwrite any config values  
- Create a `WPWatcher` object with your desired configuration  
- Call `run_scans_and_notify()` method. Return a `tuple (exit code, reports)`. 


```python
from wpwatcher.config import WPWatcherConfig
from wpwatcher.core import WPWatcher
config, files = WPWatcherConfig(files=['./demo.conf']).build_config() # leave None to find default config file
config.update({ 'send_infos':   True,
                'wp_sites':     [   {'url':'exemple1.com'},
                                    {'url':'exemple2.com'}  ],
                'wpscam_args': ['--stealthy']
            })
w=WPWatcher(config)
exit_code, reports = w.run_scans_and_notify()
for r in reports:
    print("%s\t\t%s"%( r['site'], r['status'] ))
```
</p>
</details>

## Changelog
See [Releases](https://github.com/tristanlatr/WPWatcher/releases)

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

## Running tests
```
python3 -m unittest tests.quick_test
```

## Authors
- Florian Roth (Original author of [WPWatcher v0.2](https://github.com/Neo23x0/WPWatcher))
- Tristan Landès