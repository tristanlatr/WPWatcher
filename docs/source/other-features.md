# Other features


## Fail fast

You might want to use this option when you're setting up and configuring the script. Abort scans if WPScan fails, useful to troubleshoot.

Default behaviour is to log error, continue scans and return non zero status code when all scans are over
```ini
fail_fast=No
```
Overwrite with arguments: `--ff`

## Asynchronous workers

You can use asynchronous workers to speed up the scans. 

Default to `1`. 

```ini
asynch_workers=5
```
Overwrite with arguments: `--workers Number`

**Warning**: Using too many asynchronous workers (let's say, more than 5) can lead to incomplete WPScan reports since the token limit might be reach much faster and affect multiple scans concurrently. Unexpected behaviour can happend. 
