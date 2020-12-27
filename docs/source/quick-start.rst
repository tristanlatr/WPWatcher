

Quick start
===========

Prerequisites 
^^^^^^^^^^^^^

  - `WPScan <http://wpscan.org/>`_ (itself requires Ruby and some libraries).   
  - Python 3.6 or later

Install
^^^^^^^

::

   pip install -U 'wpwatcher'

*Installs WPWatcher without syslog output support*  

``wpwatcher`` should be in your `PATH`.

Try it out
^^^^^^^^^^

**Simple usage**  

Scan 2 sites with default config::

    wpwatcher --url exemple.com exemple1.com
    
**More complete exemple**  

Load sites from text file , add WPScan arguments , follow redirection if WPScan fails , use 5 asynchronous workers , email custom recepients if any alerts with full WPScan output attached. If you reach your API limit, it will wait and continue 24h later.

::

   wpwatcher --urls sites.txt \
         --wpscan_args "--force --stealthy --api-token <TOKEN>" \
         --follow_redirect \
         --workers 5 \
         --send --attach \
         --email_to you@office.ca me@office.ca \
         --api_limit_wait


WPWatcher must read a configuration file to send mail reports.  
*This exemple assume you have filled your config file with mail server setings*.

Configure
^^^^^^^^^

Select config file with ``--conf Path``. You can specify multiple files. Will overwrites the keys with each successive file.  

Create and edit a new config file from template.

::

   wpwatcher --template_conf > wpwatcher.conf
   vim wpwatcher.conf


To load the config file by default, move the file to the following location:
  - For Windows: ``%APPDATA%\.wpwatcher\wpwatcher.conf`` or ``%APPDATA%\wpwatcher.conf``
  - For Mac/Linux : ``$HOME/.wpwatcher/wpwatcher.conf`` or ``$HOME/wpwatcher.conf``

**Configuration exemple**

Sample configuration file with full featured ``wp_sites`` entry, custom WPScan path and arguments, vuln DB api limit handling, email and syslog reporting

.. code:: ini

   [wpwatcher]
   wp_sites=   [ {   
                  "url":"exemple.com",
                  "email_to":["site_owner@domain.com"],
                  "false_positive_strings":[
                     "Yoast SEO 1.2.0-11.5 - Authenticated Stored XSS",
                     "Yoast SEO <= 9.1 - Authenticated Race Condition"],
                  "wpscan_args":["--stealthy"]
               },
               { "url":"exemple2.com"  }  ]
   wpscan_path=/usr/local/rvm/gems/default/wrappers/wpscan
   wpscan_args=[   "--format", "json",
                  "--no-banner",
                  "--random-user-agent", 
                  "--disable-tls-checks",
                  "--api-token", "YOUR_API_TOKEN" ]
   api_limit_wait=Yes
   send_email_report=Yes
   email_to=["me@gmail.com"]
   from_email=me@gmail.com
   smtp_user=me@gmail.com
   smtp_server=smtp.gmail.com:587
   smtp_ssl=Yes
   smtp_auth=Yes
   smtp_pass=P@assW0rd
   syslog_server=syslogserver.ca
   syslog_port=514

Return non zero status code if...
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- A WPScan command failed
- Unable to parse a WPScan output
- Unable to send a email report
- Other errors

.. note:: Returns a non-zero status code only on errors. 
          If a site is vulnerable it will still return zero. 
          Search for ``ALERT`` or ``WARNING`` keywords in stdout to check for issues or configure email or syslog reports. 

Notes about WPScan API token
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You need a WPScan API token in order to show vulnerability data and be alerted of vulnerable WordPress or plugin. 

If you have large number of sites to scan, you'll probably can't scan all your sites because of the limited amount of daily API request. 
Set ``api_limit_wait=Yes`` to wait 24h and contuinue scans when API limit si reached.  

.. note:: 
   If no API token is provided to WPScan, scans will still WARNING emails if outdated plugin or WordPress version is detected.  

.. attention::   
   Please make sure you respect the `WPScan license <https://github.com/wpscanteam/wpscan/blob/master/LICENSE>`_.


