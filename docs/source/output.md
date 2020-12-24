# Output

Log file and stdout outputs are **easily grepable** with the following log levels and keywords:

  - `CRITICAL`: Only used for `WPScan ALERT`
  - `ERROR`:  WPScan failed, send report failed or other errors
  - `WARNING`: Only used for `WPScan WARNING`
  - `INFO`: Used for info output , `WPScan INFO` and `FIXED` issues
  - `DEBUG`: Used for debug output and raw WPScan output. 

In addition to log messages, the readable report, and raw WPScan output can be printed with `--verbose`.

## Output configuration

- Local log file
```ini
log_file=/home/user/.wpwatcher/wpwatcher.log
```
Overwrite with argument: `--log File path`

- Save WPScan output to files
```ini
wpscan_output_folder=/home/user/Documents/WPScanResults/
```
Overwrite with argument: `--wpout Folder path`

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

## Output sample

```
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




