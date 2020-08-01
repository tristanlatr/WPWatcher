


<h1 align="center">WPWatcher</h1>

<p align="center">
  Automating <a href="https://wpscan.org/" title="homepage" target="_blank">WPScan</a> to scan and report vulnerable Wordpress sites
  <br>
</p>

<p align="center">
  <a href="https://github.com/tristanlatr/WPWatcher/actions" target="_blank"><img src="https://github.com/tristanlatr/WPWatcher/workflows/test/badge.svg"></a>
  <a href="https://codecov.io/gh/tristanlatr/WPWatcher" target="_blank"><img src="https://codecov.io/gh/tristanlatr/WPWatcher/branch/master/graph/badge.svg"></a>
  <a href="https://pypi.org/project/WPWatcher/" target="_blank"><img src="https://badge.fury.io/py/wpwatcher.svg"></a>
  <!-- <a href="https://codeclimate.com/github/tristanlatr/WPWatcher" target="_blank"><img src="https://codeclimate.com/github/tristanlatr/WPWatcher/badges/gpa.svg"></a> -->

</p>

## Features
  - Scan multiple sites with WPScan
  - Parse WPScan output and divide the results in "Alerts", "Warnings", "Informations" and eventually "Errors"
  - Keep track of fixed issues
  - Handled VulnDB API limit
  - Define reporting emails addresses for every configured site individually and globally
  - Define false positives strings for every configured site individually and globally
  - Define WPScan arguments for every configured site individually and globally
  - Save raw WPScan results into files
  - Speed up scans using several asynchronous workers
  - Follow URL redirection if WPScan fails and propose to ignore main redirect 
  - Log file also lists all the findings 
  - Scan sites continuously at defined interval and configure script as a linux service
  - Parse results differently wether WPScan format is JSON or CLI

## Prerequisites 
  - [WPScan](http://wpscan.org/) (itself requires Ruby and some libraries).   
  - Python 3 (standard libraries)
  - Tested on Linux and MacOS

## Install
#### With PyPi (stable)
```bash
python3 -m pip install wpwatcher
```

#####  Update
```bash
python3 -m pip install wpwatcher --upgrade
```

#### Manually (develop)
```bash
git clone https://github.com/tristanlatr/WPWatcher.git
cd WPWatcher
python3 setup.py install
```
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

## Configuration

Select config file with `--conf File path`. You can specify multiple files. Will overwrites the keys with each successive file.  
Default config files are `~/.wpwatcher/wpwatcher.conf` , `~/wpwatcher.conf` and `./wpwatcher.conf`.

Create and edit a new config file from template.

```bash
wpwatcher --template_conf > ./wpwatcher.conf
vim ./wpwatcher.conf
```

**[All configuration options](https://github.com/tristanlatr/WPWatcher/wiki/All-configuration-options)**

### Configuration exemple

Sample configuration file with full featured `wp_sites` entry, custom WPScan path and arguments, vuln DB api limit handling and email reporting.

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
```


### Email reports

One report is generated per site and the reports are sent individually when finished scanning a website.  

![WPWatcher Report List](/screens/wpwatcher-report-list.png "WPWatcher Report")

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

## Running tests
```
python3 -m unittest tests.quick_test
```

## Authors
- Florian Roth (Original author of [WPWatcher v0.2](https://github.com/Neo23x0/WPWatcher))
- Tristan Landes
