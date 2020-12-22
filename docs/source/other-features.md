# Other features

## Exit if WPScan failed.  
Default behaviour is to log error, continue scans and return non zero status code when all scans are over
```ini
fail_fast=No
```
Overwrite with arguments: `--ff`
## Reports database file.  
If missing, will figure out a place based on your environment to store the database.  
Use `null` keyword to disable the storage of the Json database file and turn off the tracking of the fixed issues.  
```ini
wp_reports=/home/user/.wpwatcher/wp_reports.json
```
Overwrite with arguments: `--reports File path`
## Number of asynchronous workers
Speed up the scans. Default to `1`, synchronous iterating. 
```ini
asynch_workers=5
```
Overwrite with arguments: `--workers Number`
