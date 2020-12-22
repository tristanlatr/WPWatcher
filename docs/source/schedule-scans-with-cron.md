# Shedule scans with cron

Caution: **do not configure crontab execution and linux service at the same time** .   


- Config files:

    - `wpwatcher.conf`: your config file


In **your crontab**, configure script to run at your convenience:
```
# Will run at 00:00 on Mondays:
0 0 * * 1 wpwatcher --conf /path/to/wpwatcher.conf --wait > /dev/null
```

**Warning**: This kind of setup can lead into having two `wpwatcher` executions at the same time if you have too many URLs. This might result into failure and/or database corruption because of conccurent accesses to reports database file.
