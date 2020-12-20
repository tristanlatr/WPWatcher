
from collections import UserDict

class WPWatcherReport(UserDict):

    DEFAULT_REPORT:dict = {
        "site":"",
        "status":"",
        "datetime":None,
        "last_email":None,
        "error":"",
        "infos":[],
        "warnings":[],
        "alerts":[],
        "fixed":[],
        "summary":{},
        "wpscan_output":"",
        "wpscan_parser":None,
    }

    FIELDS:list = DEFAULT_REPORT.keys()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in self.FIELDS:
            self.setdefault(key, self.DEFAULT_REPORT[key])
