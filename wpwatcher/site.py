from collections import UserDict

class WPWatcherSite(UserDict):

    FIELDS:list = [ "url", "email_to", 
        "false_positive_strings", "wpscan_args" ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in self.FIELDS:
            self.setdefault(key, None)
