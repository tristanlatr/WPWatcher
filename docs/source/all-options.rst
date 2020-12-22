All configuration options
=========================

.. list-table:: List of all WPWatcher configuration options

  * - Option
    - Accepted values in config file
    - CLI argument
    - Accepted values in CLI argument
    - Default value

  * - `wpscan_path`
    - Strings
    - NA
    - NA
    - `wpscan`

  * - `wpscan_args` 
    - Json string 
    - `--wpargs "WPScan arguments"` 
    - String 
    - `--random-user-agent --format json` 
  
  * - `wp_sites` 
    - Json string (Fully configurable) 
    - `--url URL [URL...]`
    - Strings 
    - None 
    
  * - Load `wp_sites` URLs from file 
    - NA 
    - `--urls Path` 
    - String 
    - None 
    
  * - `false_positive_strings` 
    - Json string 
    - `--fpstr String [String...]` 
    - Strings 
    - None 
    
  * - `send_email_report` 
    - Boolean Yes/No 
    - `--send` 
    - No value 
    - No 
    
  * - `email_to` 
    - Json string 
    - `--email_to Email [Email ...]`
    - Strings 
    - No one 
    
  * - `email_errors_to` 
    - Json string 
    - NA 
    - NA 
    - Same as `email_to` 
    
  * - `send_infos` 
    - Boolean Yes /No 
    - `--infos` 
    - No value 
    - No 
    
  * - `send_warnings` 
    - Boolean Yes/No 
    - NA 
    - NA 
    - Yes 
    
  * - `send_errors` 
    - Boolean Yes/No 
    - `--errors` 
    - No value 
    - No 
    
  * - `attach_wpscan_output` 
    - Boolean Yes/No 
    - `--attach` 
    - No value 
    - No 
    
  * - `resend_emails_after` 
    - String 
    - `--resend String` 
    - String 
    - `0s` 
    
  * - `api_limit_wait` 
    - Boolean Yes/No 
    - `--wait` 
    - No value 
    - No
    
  * - `daemon` 
    - Boolean Yes/No 
    - `--daemon` 
    - No value 
    - No 
    
  * - `daemon_loop_sleep` 
    - String 
    - `--loop` 
    - String 
    - `0s` 
    
  * - `log_file` 
    - String 
    - `--log Path` 
    - String 
    - None 
    
  * - `quiet` 
    - Boolean Yes/No 
    - `--quiet` 
    - No value 
    - No 
    
  * - `verbose` 
    - Boolean Yes/No 
    - `--verbose` 
    - No value 
    - No 
    
  * - `wpscan_output_folder` 
    - String 
    - `--wpout Path` 
    - String 
    - None 
    
  * - `wp_reports` 
    - String 
    - `--reports Path` 
    - String 
    - `~/.wpwatcher/wp_reports.json` 
    
  * - `fail_fast` 
    - Boolean Yes/No 
    - `--ff` 
    - No value 
    - No 
    
  * - `asynch_workers` 
    - Int 
    - `--workers Number` 
    - Int 
    - 1 
    
  * - `follow_redirect` 
    - Boolean Yes/No 
    - `--follow` 
    - No value 
    - No 
    
  * - `scan_timeout` 
    - String
    - NA 
    - NA 
    - `15m` 
    
  * - `from_email` 
    - String 
    - NA 
    - NA 
    - None 
    
  * - `smtp_server` 
    - String 
    - NA 
    - NA 
    - None 
    
  * - `smtp_ssl` 
    - Boolean Yes/No 
    - NA 
    - NA 
    - No 
    
  * - `smtp_auth` 
    - String 
    - NA 
    - NA 
    - No 
    
  * - `smtp_user` 
    - String 
    - NA 
    - NA 
    - None 
    
  * - `smtp_pass` 
    - String 
    - NA 
    - NA 
    - None 
    
  * - `use_monospace_font` 
    - Boolean 
    - `--monospace` 
    - No value 
    - No 
    
  * - `syslog_server` 
    - String 
    - NA 
    - NA 
    - None 
    
  * - `syslog_port` 
    - Int 
    - NA 
    - NA 
    - 514 
    
  * - `syslog_stream` 
    - String 
    - NA 
    - NA 
    - `SOCK_STREAM` (TCP) 
    
  * - `syslog_kwargs` 
    - Json String 
    - NA 
    - NA 
    - `{"enterprise_id":42, "msg_as_utf8":true, "utc_timestamp":true}` 
    
  * - Test syslog 
    - NA 
    - `--syslog_test` 
    - No value 
    - No 
    
  * - Dump database summary 
    - NA 
    - `--wprs` 
    - File path or None 
    - None 
    
  * - Inspect a report in database 
    - NA 
    - `--show` 
    - String 
    - None
