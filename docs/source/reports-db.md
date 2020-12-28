# Reports database

WPWatcher store a database of reports and compare reports one scan after another to notice for fixed and unfixed issues. 

Default location is `~/.wpwatcher/wp_reports.json`.  

Set `wp_reports=null` in the config to disable this feature.

## Reports database file 
If missing, will figure out a place based on your environment to store the database.  

Use `null` keyword to disable the storage of the Json database file and turn off the tracking of the fixed issues.  

```ini
wp_reports=/home/user/.wpwatcher/wp_reports.json
```

Overwrite with arguments: `--reports File path`

## Dump database summary

Table-like dump of the `Status`, `Last scan`, `Last email`, `Issues` count and `Problematic component(s)` of all your scanned sites.  

Load default database

    wpwatcher --wprs

Load specific file

    wpwatcher --wprs ~/.wpwatcher/wp_reports.json

<details><summary><b>See exemple</b></summary>
<p>

![WPWatcher Report summary](https://wpwatcher.readthedocs.io/en/latest/_static/reports-summary-wprs.png "WPWatcher Reports summary")

</p>
</details>

## Inspect a specific report in database

Get the report text for a specific site. 

    wpwatcher --show <site>