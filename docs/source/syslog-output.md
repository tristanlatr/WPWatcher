# Syslog output

## Install syslog library  

```bash
python3 -m pip install 'wpwatcher[syslog]'
```
*Installs WPWatcher with syslog output support*.

Syslog feature uses library `rfc5424-logging-handler` and `cefevent`.  

## Configure

```ini
[wpwatcher]

# Syslog settings

# Your syslog server
syslog_server=syslogserver.ca
syslog_port=514

# TCP or UDP: 
# `SOCK_STREAM` to use TCP stream 
# `SOCK_DGRAM` to send UDP packets (not recommended)  
syslog_stream=SOCK_STREAM 

# Additionnal settings, must be valid JSON
syslog_kwargs={"enterprise_id":42, "msg_as_utf8":true, "utc_timestamp":true}
```

Additional parameters can be passed during `Rfc5424SysLogHandler` initiation with the `syslog_kwargs` configuration options.  
See [the package docs](https://rfc5424-logging-handler.readthedocs.io/en/latest/basics.html#usage) for more infos on init arguments.  

Multiple CEF syslog messages are sent per scanned website.  

Syslog message exemple: 
```
<14>1 2020-09-17T14:07:20.624590+00:00 localhost WPWatcher 29016 - - CEF:0|Github|WPWatcher|2.4.0.dev1|3|WPScan WARNING|6|msg=Plugin: woocommerce\nThe version is out of date\nVersion: 4.2.2 (latest is 4.5.2) shost=http://exemple.com
```

## Send test events

```
wpwatcher -c testing.conf --syslog_test
```
Will send 5 test events, one per possible event type (`WPScan ALERT`, `WPScan WARNING`, `WPScan INFO`, `WPScan issue FIXED` and `WPScan ERROR`).  

Syslog sender code is [here](https://github.com/tristanlatr/WPWatcher/blob/master/wpwatcher/syslogout.py)
