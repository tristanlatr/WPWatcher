# Email reports

WPWatcher **must read a configuration file to send mail reports**. 

Setup mail server settings and turn on `send_email_report` in the config file or use `--send` if you want to receive email alerts.

## Reports

One report is generated per site and the reports are sent individually when finished scanning a website.  
Email notification can have 5 status: 

- **`ALERT`**: You have a vulnerable Wordpress, theme or plugin.  
- **`WARNING`**: You have an outdated Wordpress, theme or plugin. Not necessarily vulnerable but more risky.  
- **`INFO`**: WPScan did not find any issues with your site.   
- **`ERROR`**: WPScan failed.   

Alerts, Warnings and Infos might differ whether you're using cli or json format.

## Mail server settings

Not configurable with CLI arguments

```ini
# Configuration file: mail server settings

# Send email reports as
from_email=WordPressWatcher@inc.com
# Mail server and port
smtp_server=mailserver.inc.com:587
# Use authentication, default to No
smtp_auth=Yes
# Auth username
smtp_user=office@inc.com
# Auth password
smtp_pass=p@assw0rd
# Use SSL, default to No
smtp_ssl=Yes
```

If you use Gmail, make sure you set up gmail to work with "less secure apps" [here](https://myaccount.google.com/lesssecureapps?pli=1).  

## Notification settings


```ini
# Configuration file: notification settings

# Send emails for alerting of the WPScan result (ALERT or other). Default to No. 
# Overwrite with arguments: `--send`
send_email_report=No

# Send WARNING notifications and will include warnings in ALERT reports.
# Default to Yes, cannot be overwritten by CLI arguments.
send_warnings=Yes

# Send INFO notifications if no warnings or alerts are found. Default to No
# Overwrite with arguments: `--infos`
send_infos=No

# Send ERROR notifications if wpscan failed. Default to No
# Overwrite with arguments: `--errors`
send_errors=No
```

## Reports recipients

Recipients can be configured globally and on a per site basis

### Global recipients
```ini
# Configuration file: reports recipients

# Global email report recepients, will always receive email reports for all sites.  
# Overwrite with arguments: `--email_to Email [Email...]`
email_to=["securityalerts@domain.com"]

# Send any error email to those addresses and not to other recipients (`email_to` options).  
# Applicable only if `send_errors=Yes`.
email_errors_to=["admins@domain.com"]
```

### Per site recipients
```ini
# Configuration file: sites

wp_sites=[
        {   
            "url":"exemple.com",
            "email_to":["site_owner@domain.com"]
        },
        {   
            "url":"exemple2.com",
            "email_to":["site_owner2@domain.com"]
        }
    ]
```
Global recipients will still receive reports


## Misc config

```ini
# Minimum time inverval between sending two report with the same status.  Examples of valid strings: `8h`, `2d8h5m20s`, `2m4s`
# If missing, default to `0s`
# Overwrite with arguments: `--resend Time string`
resend_emails_after=3d

# Attach text output file with raw WPScan output when sending a report. 
# Useful with when using WPScan arguments "--format cli"
# Overwrite with arguments: `--attach`
attach_wpscan_output=No
```

## Sample email report

![WPWatcher Report](https://github.com/tristanlatr/WPWatcher/raw/master/docs/source/_static/wpwatcher-report.png "WPWatcher Report")
