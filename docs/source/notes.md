# Notes

## Notes on script behaviours
- The script will automatically try to delete all temp `wpscan` files in `/tmp/wpscan` before starting scans. You might run into file not found error, please consider adding `--cache-ttl 0` to WPScan arguments.
- You might want to use `--ff` (fail fast) when you're setting up and configuring the script. Abort scans when WPScan fails, useful to troubleshoot.
- All messages are printed to `stdout`.
- WPWatcher store a database of reports and compare reports one scan after another to notice for fixed issues. Default location is `~/.wpwatcher/wp_reports.json`.  Set `wp_reports=null` in the config to disable this feature.

## Return non zero status code if...
- One or more WPScan command failed
- Unable to send one or more email report
- Other errors

## Notes about WPScan API token

You need a WPScan API token in order to show vulnerability data and be alerted of vulnerable WordPress or plugin. If you have large number of sites to scan, you'll probably can't scan all your sites because of the limited amount of daily API request. Turn on `api_limit_wait` to wait 24h and contuinue scans when API limit si reached.  
**If no API token is provided to WPScan, scans will still trigger WARNING emails with outdated plugin or WordPress version**.  
Please make sure you respect the [WPScan license](https://github.com/wpscanteam/wpscan/blob/master/LICENSE).
