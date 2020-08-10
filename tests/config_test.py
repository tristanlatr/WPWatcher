import unittest
import os
from . import DEFAULT_CONFIG, NUMBER_OF_CONFIG_VALUES
from wpwatcher.config import WPWatcherConfig

class T(unittest.TestCase):

    def test_init_config_from_string(self):
    
        # Test minimal config
        config_object=WPWatcherConfig(string=DEFAULT_CONFIG)
        self.assertEqual(0, len(config_object.files), "Files seems to have been loaded even if custom string passed to config oject")
        config_dict, files=config_object.build_config()
        self.assertEqual(0, len(files), "Files seems to have been loaded even if custom string passed to config oject")
        self.assertEqual(NUMBER_OF_CONFIG_VALUES, len(config_dict), "The number of config values if not right or you forgot to change the value of NUMBER_OF_CONFIG_VALUES")
        
        # Test config template file
        config_object=WPWatcherConfig(string=WPWatcherConfig.TEMPLATE_FILE)
        self.assertEqual(0, len(config_object.files), "Files seems to have been loaded even if custom string passed to config oject")
        config_dict, files=config_object.build_config()
        self.assertEqual(0, len(files), "Files seems to have been loaded even if custom string passed to config oject")
        self.assertEqual(NUMBER_OF_CONFIG_VALUES, len(config_dict), "The number of config values if not right or you forgot to change the value of NUMBER_OF_CONFIG_VALUES")

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
        config_object=WPWatcherConfig()
        config_object2=WPWatcherConfig(files=paths_found)
        self.assertEqual(config_object.build_config(), config_object2.build_config(), "Config built with config path and without are different even if files are the same")
        for f in paths_found: 
            os.remove(f)
        for f in existent_files:
            os.rename('%s.temp'%f , f)

    def test_read_config_error(self):

        with self.assertRaisesRegex((ValueError), 'Make sure the file exists and you have correct access right'):
            WPWatcherConfig(files=['/tmp/this_file_is_inexistent.conf'])

        WRONG_CONFIG=DEFAULT_CONFIG+'\nverbose=I dont know'

        with self.assertRaisesRegex(ValueError, 'Could not read boolean value in config file'):
            WPWatcherConfig(string=WRONG_CONFIG).build_config()

        WRONG_CONFIG=DEFAULT_CONFIG+'\nwpscan_args=["forgot", "a" "commas"]'

        with self.assertRaisesRegex(ValueError, 'Could not read JSON value in config file'):
            WPWatcherConfig(string=WRONG_CONFIG).build_config()