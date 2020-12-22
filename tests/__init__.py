import json

WP_SITES=[ {"url":"exemple.com"},
              {"url":"exemple2.com"}  ]

DEFAULT_CONFIG="""
[wpwatcher]
wp_sites=%s
smtp_server=localhost:1025
from_email=testing-wpwatcher@exemple.com
email_to=["test@mail.com"]
"""%json.dumps(WP_SITES)
