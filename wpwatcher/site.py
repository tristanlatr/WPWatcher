from urllib.parse import urlparse
from typing import Iterable, Dict, Any, Tuple

class WPWatcherSite(Dict[str, Any]):

    DEFAULT_SITE:Dict[str, Any] = {
        "url": "",
        "email_to": [],
        "false_positive_strings": [],
        "wpscan_args": [],
    }

    FIELDS:Iterable[str] = list(DEFAULT_SITE.keys())

    def __init__(self, *args, **kwargs) -> None: # type: ignore [no-untyped-def]
        super().__init__(*args, **kwargs)

        if "url" not in self:
            raise ValueError("Invalid site %s\nMust contain 'url' key" % self)
        else:
            # Strip URL string
            self["url"] = self["url"].strip()
            # Format sites with scheme indication
            p_url = list(urlparse(self["url"]))
            if p_url[0] == "":
                self["url"] = "http://" + self["url"]

        for key in self.FIELDS:
            self.setdefault(key, self.DEFAULT_SITE[key])