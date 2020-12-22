# WPScan configurations

## WPScan path
Path to wpscan executable.   
If WPScan is installed with RVM could be: `/usr/local/rvm/gems/default/wrappers/wpscan`.  
With docker, could be: `docker run -it --rm wpscanteam/wpscan`.  
If missing, assume `wpscan` is in your `PATH`.  

```ini
wpscan_path=wpscan
```
## WPScan arguments
**Global WPScan arguments**.  
Must be a valid Json string.  
<!-- Set `"--format","json"` to use Json parsing feature.  
The list of warnings, alerts and infos might differ when using json  
    Email outpout will be more concice.   
    But not all informations are logged.   
Using `"--format", "cli"` will parse full WPScan output with [!] etc  
    Logs all informations   -->

See `wpscan --help` for more informations about WPScan options  
```ini
wpscan_args=[   "--format", "json",
                "--no-banner",
                "--random-user-agent", 
                "--disable-tls-checks",
                "--detection-mode", "aggressive",
                "--enumerate", "t,p,tt,cb,dbe,u,m",
                "--api-token", "YOUR_API_TOKEN" ]
```
Overwrite with `--wpargs "WPScan arguments"`. If you run into option parsing error, start the arguments string with a space or use equals sign `--wpargs="[...]"` to avoid [argparse bug](https://stackoverflow.com/questions/16174992/cant-get-argparse-to-read-quoted-string-with-dashes-in-it?noredirect=1&lq=1).

You can store the API Token in the WPScan default config file at `~/.wpscan/scan.yml` and not supply it via the wpscan CLI argument in the WPWatcher config file. See [WPSacn readme](https://github.com/wpscanteam/wpscan#save-api-token-in-a-file).

**Per site WPScan arguments**  
Arguments will be appended to global WPScan arguments.  
```ini
wp_sites=   [
        {   
            "url":"exemple.com",
            "wpscan_args":["--stealthy", "--http-auth", "myuser:p@assw0rD"]
        },
        {   
            "url":"exemple2.com",
            "wpscan_args":["--disable-tls-checks", "--enumerate", "ap,vt,tt,cb,dbe,u,m"]
        }
    ]
```
## Sleep when API limit reached
Wait 24h when API limit has been reached.  
Default behaviour will consider the API limit as a WPScan failure and continue the scans (if not fail_fast) leading into making lot's of failed commands
```ini
api_limit_wait=No
```
Overwrite with arguments: `--wait`

## Follow redirection
If WPScan fails and propose to use `--ignore-main-redirect`, parse output and scan redirected URL.   
Default to `No`   
```ini
follow_redirect=Yes
```
Overwrite with arguments: `--follow`

## Scan timeout  
Default to `15m`. You could have to increase scan timeout if you use enumerating features or password attack. 
```ini
scan_timeout=2h
```
