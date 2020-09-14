import json
from wpwatcher.core import WPWatcher
# Constants
NUMBER_OF_CONFIG_VALUES=33

WP_SITES=[ WPWatcher.format_site(s) for s in [ {"url":"exemple.com"},
              {"url":"exemple2.com"}  ] ]

DEFAULT_CONFIG="""
[wpwatcher]
wp_sites=%s
smtp_server=localhost:1025
from_email=testing-wpwatcher@exemple.com
email_to=["test@mail.com"]
"""%json.dumps(WP_SITES)