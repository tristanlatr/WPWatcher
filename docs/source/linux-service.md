# Linux service

## Daemon settings
- Daemon mode: loops forever. Default to No.  
It's recommended to use `--daemon` argument and not the config file value, otherwise `wpwatcher` will start by default in daemon mode.  
```ini
daemon=No
```

- Sleep time between two scans.  
If missing, default to `0s`
```ini
daemon_loop_sleep=12h
```
Overwrite with argument: `--loop Time string`

## Setup continuous scanning linux service

Configure :
- `daemon_loop_sleep`: i.e. `12h` 
- `resend_emails_after` i.e.`5d` and 
- `api_limit_wait=Yes`. 

    wpwatcher --daemon [--urls ./my_sites.txt] ...

Let's say you have 20 WordPress sites to scan but your API limit is reached after 8 sites, the program will sleep 24h and continue until all sites are scanned (2 days later). Then will sleep the configured time and start again.

Tip: `wpwatcher` and `wpscan` might not be in your execution environement `PATH`. If you run into file not found error, try to configure the full paths to executables and config files.

Note: By default a different database file will be used when using daemon mode `~/.wpwatcher/wp_reports.daemon.json`

Setup WPWatcher as a service.
-  With `systemctl`

    Create and configure the service file `/lib/systemd/system/wpwatcher.service`
    ```bash
    nano /lib/systemd/system/wpwatcher.service
    ```
    Adjust `ExecStart` and `User` in the following template service file:  
    ```
    [Unit]
    Description=WPWatcher
    After=network.target
    StartLimitIntervalSec=0

    [Service]
    Type=simple
    Restart=always
    RestartSec=1
    ExecStart=/usr/local/bin/wpwatcher --daemon --conf /path/to/wpwatcher.conf
    User=user

    [Install]
    WantedBy=multi-user.target
    ```

    Enable the service to start on boot
    ```
    systemctl daemon-reload
    systemctl enable wpwatcher.service
    ```

    The service can be started/stopped with the following commands:
    ```
    systemctl start wpwatcher
    systemctl stop wpwatcher
    ```  

    Follow logs
    ```
    journalctl -u wpwatcher -f
    ```
    [More infos on systemctl](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/system_administrators_guide/sect-managing_services_with_systemd-unit_files) 


- For other systems, please refer to the appropriate [documentation](https://blog.frd.mn/how-to-set-up-proper-startstop-services-ubuntu-debian-mac-windows/)
