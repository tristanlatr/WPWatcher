Library usage
=============

- Init config dict from file with ``WPWatcherConfig.fromfiles()`` method. 
- Customize the config if you want, you can overwrite any config values  
- Create a ``WPWatcher`` object with your desired configuration  
- Call ``run_scans_and_notify()`` method. Return a `tuple (exit code, reports)`. 

.. code:: python

    from wpwatcher.config import WPWatcherConfig
    from wpwatcher.core import WPWatcher
    config = WPWatcherConfig.fromfiles(['/path/to/wpwatcher.conf'])
    config.update({ 'send_infos':   True,
                    'wp_sites':     [   {'url':'exemple1.com'},
                                        {'url':'exemple2.com'}  ],
                    'wpscan_args': ['--stealthy']
                })
    watcher = WPWatcher(config)
    exit_code, reports = watcher.run_scans_and_notify()
    for r in reports:
        print("%s\t\t%s"%( r['site'], r['status'] ))

.. toctree::

    api/index
