
<h1 align="center">  
  <img src="https://wpwatcher.readthedocs.io/en/latest/_static/logo.png" width="250" />
</h1>

<p align="center">
  WPWatcher - Automating <a href="https://wpscan.org/" title="homepage" target="_blank">WPScan</a> to scan and report vulnerable Wordpress sites
  <br>
</p>

<p align="center">
  <a href="https://github.com/tristanlatr/WPWatcher/actions" target="_blank"><img src="https://github.com/tristanlatr/WPWatcher/workflows/test/badge.svg"></a>
  <a href="https://codecov.io/gh/tristanlatr/WPWatcher" target="_blank"><img src="https://codecov.io/gh/tristanlatr/WPWatcher/branch/master/graph/badge.svg"></a>
  <a href="https://pypi.org/project/WPWatcher/" target="_blank"><img src="https://badge.fury.io/py/wpwatcher.svg"></a>
  <a href="https://codeclimate.com/github/tristanlatr/WPWatcher" target="_blank"><img src="https://codeclimate.com/github/tristanlatr/WPWatcher/badges/gpa.svg"></a>
  <a href="http://mypy-lang.org/" target="_blank"><img src="http://www.mypy-lang.org/static/mypy_badge.svg"></a>
  <a href='https://wpwatcher.readthedocs.io/en/latest/'>
    <img src='https://readthedocs.org/projects/wpwatcher/badge/?version=latest' alt='Documentation Status' />
  </a>
</p>

<p align="center">
  Wordpress Watcher is a wrapper for WPScan that manages scans on multiple sites and reports by email and/or syslog. 
  Schedule scans and get notified when vulnerabilities, outdated plugins and other risks are found. 
</p>

## Features

  - Scan **multiple sites** with WPScan
  - **Parse WPScan output** and divide the results in *"Alerts"*, *"Warnings"* and *"Informations"*  
  - **Handled VulnDB API limit**
  - Define **reporting emails addresses** for every configured site individually and globally 
  - Define **false positives strings** for every configured site individually and globally 
  - Define **WPScan arguments** for every configured site individually and globally 
  - Send WPScan findings to **Syslog** server 
  - Save raw WPScan output into files
  - Log file lists all the findings 
  - Speed up scans using several asynchronous workers
  - **Follow URL redirection** if WPScan fails and propose to ignore main redirect
  - Scan sites continuously at defined interval and configure script as a linux service 
  - Additionnal alerts depending of finding type (SQL dump, etc.)  
  - Keep track of fixed and unfixed issues

## Documentation

[Read The Docs](https://wpwatcher.readthedocs.io/en/latest/).  

## Usage exemple

Scan two sites, add WPScan arguments, follow URL redirection and email report to recepients. If you reach your API limit, it will wait and continue 24h later.

```bash
wpwatcher --url exemple.com exemple1.com \
  --wpscan_args "--force --stealthy --api-token <TOKEN>" \
  --follow_redirect --api_limit_wait \
  --send --infos --email_to you@office.ca me@office.ca
```

WPWatcher must read a configuration file to send mail reports. This exemple assume you have filled your config file with mail server setings.

## Emails

Sample email report.

![WPWatcher Report](https://github.com/tristanlatr/WPWatcher/raw/master/docs/source/_static/wpwatcher-report.png "WPWatcher Report")

## Authors
- Florian Roth (Original author of [WPWatcher v0.2](https://github.com/Neo23x0/WPWatcher))
- Tristan Landes

## Disclamer

Use at your own risks.
