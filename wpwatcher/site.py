from collections import UserDict
from urllib.parse import urlparse


class WPWatcherSite(UserDict):

    DEFAULT_SITE:dict = {
        "url": "",
        "email_to": [],
        "false_positive_strings": [],
        "wpscan_args": [],
    }

    FIELDS:list = DEFAULT_SITE.keys()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if "url" not in self.data:
            raise ValueError("Invalid site %s\nMust contain 'url' key" % self.data)
        else:
            # Strip URL string
            self.data["url"] = self.data["url"].strip()
            # Format sites with scheme indication
            p_url = list(urlparse(self.data["url"]))
            if p_url[0] == "":
                self.data["url"] = "http://" + self.data["url"]

        for key in self.FIELDS:
            self.setdefault(key, self.DEFAULT_SITE[key])
