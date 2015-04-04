# WPWatcher
Wordpress Watcher is a wrapper for WPScan that manages scans on multiple sites and reports by email

## In a Nutshell

  - Scan multiple sites with WPScan
  - Define a reporting email address for every configured site individually
  - Elements are divided in "Warnings" and "Alerts"
  - Mail is sent if at least 1 warning or 1 alert has been found
  - Local log file "wpwatcher.log" also lists all the findings (integrate in monitoring)

## Usage

Best Practice:
  1. Save script on server system
  2. Adjust the sites to scan
  3. Adjust the mail server settings
  4. Configure cron to run WPWatcher frequently

## Compatibility

Version 0.2 is compatible with Python 2.6. Previous version used "check_output", which is not available in Python 2.6.

## Screenshots

### Configuration

![WPWatcher Configuration](/screens/wpwatcher-config.png "WPWacther Config")

### Scan Run

![WPWatcher Screenshot](/screens/wpwatcher.png "WPWatcher Run")

### Report

![WPWatcher Report](/screens/wpwatcher-report.png "WPWatcher Report")
