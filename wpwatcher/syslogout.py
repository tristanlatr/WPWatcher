""""
Wordpress Watcher
Automating WPscan to scan and report vulnerable Wordpress sites

DISCLAIMER - USE AT YOUR OWN RISK.
"""

import socket
import logging
from urllib.parse import urlparse
from wpwatcher import VERSION, log

class WPSyslogOutput(object):

    def __init__(self, conf):
        # Keep syslog dependency optionnal by importing at init time
        from rfc5424logging import Rfc5424SysLogHandler
        sh = Rfc5424SysLogHandler(
            address=(conf['syslog_server'], conf['syslog_port']),
            socktype=getattr(socket, conf['syslog_stream']), # Use TCP or UDP
            appname='WPWatcher',
            **conf['syslog_kwargs']
        )
        self.syslog=logging.getLogger('wpwatcher-syslog')
        self.syslog.setLevel(logging.DEBUG)
        self.syslog.addHandler(sh)

    DEVICE_VENDOR = "Github"
    DEVICE_PRODUCT = "WPWatcher"
    DEVICE_VERSION = VERSION

    # Dict of  # report_key: (signatureId, name, severiry)
    EVENTS =    {   'infos':    ('100', 'WPScan INFO',           4),  
                    'fixed':    ('101', 'WPScan issue FIXED',    4),  
                    'error':    ('102', 'WPScan ERROR',          6),  
                    'warnings': ('103', 'WPScan WARNING',        6),  
                    'alerts':   ('104', 'WPScan ALERT',          9),  
                }
    
    def emit_messages(self, wp_report):
        """
        Sends the CEF syslog messages for the report.  
        """ 
        log.debug("Sending Syslog messages for site {}".format(wp_report['site']))
        for m in self.get_messages(wp_report):
            self.syslog.info(m)

    def get_messages(self, wp_report):
        """
        Return a list of CEF formatted messages
        """
        from cefevent import CEFEvent 
        messages = []
        for v in self.EVENTS.keys():
            # make sure items is a list, cast error string to list
            items = wp_report[v] if isinstance(wp_report[v], list) else [wp_report[v]]
            for msg_data in items:
                if msg_data:
                    log.debug("Message data: {}".format(msg_data))
                    c = CEFEvent()
                    # WPWatcher related fields
                    c.set_prefix('deviceVendor', self.DEVICE_VENDOR)
                    c.set_prefix('deviceProduct', self.DEVICE_PRODUCT)
                    c.set_prefix('deviceVersion', VERSION)
                    # Message common fields
                    c.set_prefix('signatureId', self.EVENTS[v][0])
                    c.set_prefix('name', self.EVENTS[v][1])
                    c.set_prefix('severity', self.EVENTS[v][2])
                    # Message supp infos
                    c.set_field('message', msg_data[:1022])   
                    c.set_field("sourceHostName", wp_report['site'][:1022])
                    msg = c.build_cef()
                    log.debug("Message CEF: {}".format(msg))
                    messages.append(msg)
        return messages



       

