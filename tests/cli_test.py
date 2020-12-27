import unittest
import tempfile
import os
from datetime import timedelta
from wpwatcher.cli import get_arg_parser
from wpwatcher.config import WPWatcherConfig

class T(unittest.TestCase):

    def test_build_config_cli(self):
        parser = get_arg_parser()

        tmp=tempfile.NamedTemporaryFile('w', delete=False)
            
        tmp.write("site10.com\nsite11.org\nsite12.fr")
        
        tmp.flush()

        args = parser.parse_args(
            [   '--url', 
                'site1.ca', 
                'site2.ca', 
                '--urls',
                tmp.name,
                '--resend', 
                '2m', 
                '--loop', 
                '60s', 
                '--wpargs',
                '--format cli'
            ])

        wpwatcher_configuration = WPWatcherConfig.fromcliargs(args)

        self.assertEqual(
            wpwatcher_configuration.get('wp_sites'), [{"url":"site1.ca"}, {"url":"site2.ca"}, {"url":"site10.com"}, {"url":"site11.org"}, {"url":"site12.fr"}])
        
        self.assertIsInstance(wpwatcher_configuration.get('daemon_loop_sleep'), timedelta)
        self.assertIsInstance(wpwatcher_configuration.get('resend_emails_after'), timedelta)
        
        self.assertEqual(wpwatcher_configuration.get('wpscan_args'), ["--random-user-agent", "--format", "json", "--cache-ttl", "0", "--format", "cli"])
        
        os.remove(tmp.name)
