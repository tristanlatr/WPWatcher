Library usage
=============

- Init config dict from file with :py:meth:`wpwatcher:wpwatcher.config.WPWatcherConfig.fromfiles` method (or other classmethods). 
- Customize the config if you want, you can overwrite any config values  
- Create a :py:class:`wpwatcher:wpwatcher.core.WPWatcher` object with your desired configuration  
- Call :py:meth:`wpwatcher:wpwatcher.core.WPWatcher.run_scans` method. It returns a ``tuple (exit code, reports)``. 

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
    exit_code, reports = watcher.run_scans()
    for r in reports:
        print("%s\t\t%s"%( r['site'], r['status'] ))

.. toctree::

    api/classIndex

