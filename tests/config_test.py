import unittest
import os
from . import DEFAULT_CONFIG
from wpwatcher.config import WPWatcherConfig

class T(unittest.TestCase):

    def test_init_config_from_string(self):
    
        # Test minimal config
        config_dict=WPWatcherConfig.fromstring(DEFAULT_CONFIG)
        self.assertEquals(config_dict['email_to'], ["test@mail.com"])
        self.assertEquals(config_dict['from_email'], "testing-wpwatcher@exemple.com")
        self.assertEquals(config_dict['smtp_server'], "localhost:1025")
        
        # Test config template file
        config_dict2=WPWatcherConfig.fromstring(WPWatcherConfig.TEMPLATE_FILE)
        self.assertEquals(config_dict2['smtp_server'], "mailserver.de:587")

    def test_init_config_from_file(self):

        # Test find config file, rename default file if already exist and restore after test
        paths_found=WPWatcherConfig.find_config_files()
        existent_files=[]
        if len(paths_found)==0:
            paths_found=WPWatcherConfig.find_config_files(create=True)
        else:
            existent_files=paths_found
            for p in paths_found:
                os.rename(p,'%s.temp'%p)
            paths_found=WPWatcherConfig.find_config_files(create=True)

        # Init config and compare
        config_object=WPWatcherConfig.fromenv()
        config_object2=WPWatcherConfig.fromfiles(paths_found)
        self.assertEqual(config_object.data, config_object2.data, "Config built with config path and without are different even if files are the same")
        for f in paths_found: 
            os.remove(f)
        for f in existent_files:
            os.rename('%s.temp'%f , f)

    def test_read_config_error(self):

        with self.assertRaisesRegex((ValueError), 'Make sure the file exists and you have correct access right'):
            WPWatcherConfig.fromfiles(['/tmp/this_file_is_inexistent.conf'])

        WRONG_CONFIG=DEFAULT_CONFIG+'\nverbose=I dont know'

        with self.assertRaisesRegex(ValueError, 'Could not read boolean value in config file'):
            WPWatcherConfig.fromstring(WRONG_CONFIG)

        WRONG_CONFIG=DEFAULT_CONFIG+'\nwpscan_args=["forgot", "a" "commas"]'

        with self.assertRaisesRegex(ValueError, 'Could not read JSON value in config file'):
            WPWatcherConfig.fromstring(WRONG_CONFIG)

