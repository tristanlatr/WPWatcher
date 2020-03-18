# WPWatcher
Wordpress Watcher is a wrapper for [WPScan](http://wpscan.org/) that manages scans on multiple sites and reports by email

## In a Nutshell

  - Scan multiple sites with WPScan
  - Define a reporting email address for every configured site individually
  - Elements are divided in "Warnings" and "Alerts"
  - Mail is sent if at least 1 warning or 1 alert has been found
  - Local log file "wpwatcher.log" also lists all the findings (integrate in monitoring)

## Prerequisites 

  - [WPScan](http://wpscan.org/) (itself requires Ruby and some libraries)
  - Python 3 (standard libraries)

## Usage

Best Practice:
  1. Save script on server system
  2. Adjust the sites to scan and other configuration in a config file
  3. Adjust the mail server settings in the config file
  4. Configure cron to run WPWatcher frequently

## Compatibility

Version 0.3 is compatible with Python 3.

## Configuration

    [wpscan]
    # Monitoerd sites and custom email report recepient
    wp_sites=   [   
        {   "url":"exemple.com"  },
        {   
            "url":"exemple2.com",
            "email_report_recepients":["person1@mail.com"], 
            "false_positive_strings":["this string"]
        }
    ]
    # Default email report recepient, will always receive email report
    email_report_recepients=["alerts@domain.com"]
    # WPScan arguments. wpscan v3.7
    wpscan_args=[   "--no-banner",
                    "--random-user-agent", 
                    "--format", "cli-no-colour",
                    "--disable-tls-checks",
                    "--enumerate", "vp,vt,cb,dbe,u,m" ]
    # False positive strings
    false_positive_strings=["You can get a free API token with 50 daily requests by registering at https://wpvulndb.com/users/sign_up"   ]
    # Path to wpscan. On linuxes could be /usr/local/rvm/gems/ruby-2.6.0/bin/wpscan
    wpscan_path= wpscan
    # Log file
    log_file=./wpwatcher.log
    # Whether not sending emails
    send_email_report=No
    # Email settings
    smtp_server=mailserver.de:587
    smtp_auth=Yes
    smtp_user=office
    smtp_pass=p@assw0rd
    smtp_ssl=Yes
    from_email=wpwatcher@domain.com



## Screenshots

### Scan Run

![WPWatcher Screenshot](/screens/wpwatcher.png "WPWatcher Run")

### Report

![WPWatcher Report](/screens/wpwatcher-report.png "WPWatcher Report")
