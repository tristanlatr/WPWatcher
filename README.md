


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

Wordpress Watcher is a wrapper for WPScan that manages scans on multiple sites and reports by email and/or syslog.  
Automate scans and get notified when vulnerabilities, outdated plugins or other risks are found. 

## Features
  - Scan **multiple sites** with WPScan
  - **Parse WPScan output** and divide the results in *"Alerts", "Warnings", "Informations" and eventually "Errors"*
  - **Handled VulnDB API limit**
  - Define **reporting emails addresses** for every configured site individually and globally ([wiki/Email-reports](https://github.com/tristanlatr/WPWatcher/wiki/Email-reports))
  - Define **false positives strings** for every configured site individually and globally ([wiki/False-positives](https://github.com/tristanlatr/WPWatcher/wiki/False-positives))
  - Define **WPScan arguments** for every configured site individually and globally ([wiki/WPScan-configuration](https://github.com/tristanlatr/WPWatcher/wiki/WPScan-configuration))
  - Send WPScan findings to **Syslog** server ([wiki/Syslog-output](https://github.com/tristanlatr/WPWatcher/wiki/Syslog-output))
  - Save raw WPScan output into files
  - Log file lists all the findings ([wiki/Output](https://github.com/tristanlatr/WPWatcher/wiki/Output))
  - Speed up scans using several asynchronous workers
  - **Follow URL redirection** if WPScan fails and propose to ignore main redirect
  - Scan sites continuously at defined interval and configure script as a linux service ([wiki/Linux-service](https://github.com/tristanlatr/WPWatcher/wiki/Linux-service))
  - Additionnal alerts depending of finding type (SQL dump, etc.)  ([match list](https://github.com/tristanlatr/wpscan_out_parse#additionnal-alerts-strings))
  - Keep track of fixed and unfixed issues
  - Simple library usage ([wiki/Library-usage](https://github.com/tristanlatr/WPWatcher/wiki/Library-usage)) (Breaking changes in v3.0)

## Prerequisites 
  - [WPScan](http://wpscan.org/) (itself requires Ruby and some libraries).   
  - Python 3.6 or later

## Install
#### With PyPi (stable)

```bash
python3 -m pip install 'wpwatcher' --upgrade
```
*Installs WPWatcher without syslog output support*  

`wpwatcher` should be in your `PATH`.

**[Review the Wiki](https://github.com/tristanlatr/WPWatcher/wiki)** for more documentation.

#### Try it out

**Simple usage**  
Scan 2 sites with default config.

    wpwatcher --url exemple.com exemple1.com
    
**More complete exemple**  
Load sites from text file , add WPScan arguments , follow redirection if WPScan fails , use 5 asynchronous workers , email custom recepients if any alerts with full WPScan output attached. If you reach your API limit, it will wait and continue 24h later.

```bash
wpwatcher --urls sites.txt \
        --wpscan_args "--force --stealthy --api-token <TOKEN>" \
        --follow_redirect \
        --workers 5 \
        --send --attach \
        --email_to collaborator1@office.ca collaborator2@office.ca \
        --api_limit_wait
```

WPWatcher must read a configuration file to send mail reports.  
*This exemple assume you have filled your config file with mail server setings*.

**Inspect a report in database**

```bash
wpwatcher --show <site>
```

## Configuration

Select config file with `--conf File path`. You can specify multiple files. Will overwrites the keys with each successive file.  

Create and edit a new config file from template.

```bash
wpwatcher --template_conf > wpwatcher.conf
vim wpwatcher.conf
```

To load the config file by default, move the file to the following location:
  - For Windows: `%APPDATA%\.wpwatcher\wpwatcher.conf` or `%APPDATA%\wpwatcher.conf`
  - For Mac/Linux : `$HOME/.wpwatcher/wpwatcher.conf` or `$HOME/wpwatcher.conf`

See:
**[All configuration options](https://github.com/tristanlatr/WPWatcher/wiki/All-configuration-options)**

### Configuration exemple

Sample configuration file with full featured `wp_sites` entry, custom WPScan path and arguments, vuln DB api limit handling, email and syslog reporting

```ini
[wpwatcher]
wp_sites=   [ {   
                "url":"exemple.com",
                "email_to":["site_owner@domain.com"],
                "false_positive_strings":[
                    "Yoast SEO 1.2.0-11.5 - Authenticated Stored XSS",
                    "Yoast SEO <= 9.1 - Authenticated Race Condition"],
                "wpscan_args":["--stealthy"]
              },
              { "url":"exemple2.com"  }  ]
wpscan_path=/usr/local/rvm/gems/default/wrappers/wpscan
wpscan_args=[   "--format", "json",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks",
                "--api-token", "YOUR_API_TOKEN" ]
api_limit_wait=Yes
send_email_report=Yes
email_to=["me@gmail.com"]
from_email=me@gmail.com
smtp_user=me@gmail.com
smtp_server=smtp.gmail.com:587
smtp_ssl=Yes
smtp_auth=Yes
smtp_pass=P@assW0rd
syslog_server=syslogserver.ca
syslog_port=514
```

### Email reports

One report is generated per site and the reports are sent individually when finished scanning a website.  

![WPWatcher Report List](https://github.com/tristanlatr/WPWatcher/raw/master/screens/wpwatcher-report-list.png "WPWatcher Report")

![WPWatcher Report](https://github.com/tristanlatr/WPWatcher/raw/master/screens/wpwatcher-report.png "WPWatcher Report")

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
pytest
```

## Authors
- Florian Roth (Original author of [WPWatcher v0.2](https://github.com/Neo23x0/WPWatcher))
- Tristan Landes
