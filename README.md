
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
  - **Parse WPScan output** and divide the results in *"Alerts"*, *"Warnings"* and *"Informations"*.  
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
  - Additionnal alerts depending of finding type (SQL dump, etc.)  ([match list](https://github.com/tristanlatr/wpscan_out_parse#additionnal-alerts-strings))
  - Keep track of fixed and unfixed issues
  - Simple library usage 

## Documentation

[Read The Docs](https://wpwatcher.readthedocs.io/en/latest/) for more informations.  

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

## Disclamer

Use at your own risks.
