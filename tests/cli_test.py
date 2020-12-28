import unittest
import tempfile
import os
import io
from datetime import timedelta
from contextlib import redirect_stdout
from wpwatcher.cli import get_arg_parser, main
from wpwatcher.config import Config

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

        wpwatcher_configuration = Config.fromcliargs(args)

        self.assertEqual(
            wpwatcher_configuration.get('wp_sites'), [{"url":"site1.ca"}, {"url":"site2.ca"}, {"url":"site10.com"}, {"url":"site11.org"}, {"url":"site12.fr"}])
        
        self.assertIsInstance(wpwatcher_configuration.get('daemon_loop_sleep'), timedelta)
        self.assertIsInstance(wpwatcher_configuration.get('resend_emails_after'), timedelta)
        
        self.assertEqual(wpwatcher_configuration.get('wpscan_args'), ["--random-user-agent", "--format", "json", "--cache-ttl", "0", "--format", "cli"])
        
        os.remove(tmp.name)

    def test_wprs(self):

        tmp=tempfile.NamedTemporaryFile('w', delete=False)

        tmp.write(r"""[
    {
        "site": "http://exemple.fr",
        "datetime": "2020-12-27T12-22-15",
        "status": "INFO",
        "last_email": null,
        "error": "",
        "infos": [
            "_______________________________________________________________\n__          _______   _____\n\\ \\        / /  __ \\ / ____|\n\\ \\  /\\  / /| |__) | (___   ___  __ _ _ __ \u00ae\n\\ \\/  \\/ / |  ___/ \\___ \\ / __|/ _` | '_ \\\n\\  /\\  /  | |     ____) | (__| (_| | | | |\n\\/  \\/   |_|    |_____/ \\___|\\__,_|_| |_|",
            "WordPress Security Scanner by the WPScan Team\nVersion 3.8.11\nSponsored by Automattic - https://automattic.com/\n@_WPScan_, @ethicalhack3r, @erwan_lr, @firefart\n_______________________________________________________________",
            "[+] URL: http://exemple.fr/ [51.91.236.255]\n[+] Effective URL: https://cap-ad.fr/\n[+] Started: Sun Dec 27 12:22:19 2020",
            "Interesting Finding(s):",
            "[+] Headers\n| Interesting Entries:\n|  - Server: Apache\n|  - X-Powered-By: PHP/7.4\n| Found By: Headers (Passive Detection)\n| Confidence: 100%",
            "[+] This site seems to be a multisite\n| Found By: Direct Access (Aggressive Detection)\n| Confidence: 100%\n| Reference: http://codex.wordpress.org/Glossary#Multisite",
            "[+] WordPress version 5.5.3 identified (Latest, released on 2020-10-30).\n| Found By: Rss Generator (Passive Detection)\n|  - https://cap-ad.fr/feed/, <generator>https://wordpress.org/?v=5.5.3</generator>\n|  - https://cap-ad.fr/comments/feed/, <generator>https://wordpress.org/?v=5.5.3</generator>",
            "[+] WordPress theme in use: catch-responsive\n| Location: http://exemple.fr/wp-content/themes/catch-responsive/\n| Latest Version: 2.7.8 (up to date)\n| Last Updated: 2020-09-15T00:00:00.000Z\n| Style URL: https://cap-ad.fr/wp-content/themes/catch-responsive/style.css?ver=20201028-161708\n| Style Name: Catch Responsive\n| Style URI: https://catchthemes.com/themes/catch-responsive/\n| Description: Catch Responsive is an extremely flexible and customizable Responsive WordPress theme suitable for almost any kind of professional website. It is based on responsive web design where each element has been carefully configured for perfect display on all devices and platforms. It is built in HTML5, CSS3 and WordPress Theme Customizer for real time customization. It comes with a wide variety of options so you can modify layout, styling, featured content, promotion headline, featured slider, pagination, icons, menus, breadcrumb, widgets and much more, directly from theme customizer. This theme is translation ready and also currently translated in Swedish, French, Brazilian Portuguese, German, Russian, Ukrainian, Polish and Danish languages. Check out Theme Instructions at https://catchthemes.com/theme-instructions/catch-responsive/, Support at https://catchthemes.com/support/ and Demo at https://catchthemes.com/demo/catch-responsive/\n| Author: Catch Themes\n| Author URI: https://catchthemes.com/\n| License: GNU General Public License, version 3 (GPLv3)\n| License URI: http://www.gnu.org/licenses/gpl-3.0.txt\n| Tags: one-column, two-columns, left-sidebar, right-sidebar, grid-layout, custom-background, custom-colors, custom-header, custom-menu, editor-style, featured-image-header, featured-images, flexible-header, front-page-post-form, post-formats, sticky-post, theme-options, threaded-comments, translation-ready, footer-widgets, blog, education, portfolio\n| Text Domain: catch-responsive\n| Found By: Css Style In Homepage (Passive Detection)\n| Confirmed By: Css Style In 404 Page (Passive Detection)\n| Version: 2.7.8 (80% confidence)\n| Found By: Style (Aggressive Detection)\n|  - https://cap-ad.fr/wp-content/themes/catch-responsive/style.css?ver=20201028-161708, Match: 'Version: 2.7.8'",
            "[+] Enumerating All Plugins (via Passive Methods)\n[+] Checking Plugin Versions (via Passive and Aggressive Methods)",
            "[i] Plugin(s) Identified:",
            "[+] feature-a-page-widget\n| Location: http://exemple.fr/wp-content/plugins/feature-a-page-widget/\n| Latest Version: 2.2.0\n| Last Updated: 2020-08-12T18:51:00.000Z\n| Found By: Urls In Homepage (Passive Detection)\n| The version could not be determined.",
            "[+] siteorigin-panels\n| Location: http://exemple.fr/wp-content/plugins/siteorigin-panels/\n| Latest Version: 2.11.8\n| Last Updated: 2020-12-09T14:03:00.000Z\n| Found By: Urls In Homepage (Passive Detection)\n| Confirmed By: Urls In 404 Page (Passive Detection)\n| The version could not be determined.",
            "[+] so-widgets-bundle\n| Location: http://exemple.fr/wp-content/plugins/so-widgets-bundle/\n| Latest Version: 1.17.11\n| Last Updated: 2020-12-09T14:30:00.000Z\n| Found By: Urls In Homepage (Passive Detection)\n| Confirmed By: Urls In 404 Page (Passive Detection)\n| The version could not be determined.",
            "[+] tablepress\n| Location: http://exemple.fr/wp-content/plugins/tablepress/\n| Latest Version: 1.12 (up to date)\n| Last Updated: 2020-12-09T09:24:00.000Z\n| Found By: Urls In Homepage (Passive Detection)\n| Confirmed By: Urls In 404 Page (Passive Detection)\n| Version: 1.12 (10% confidence)\n| Found By: Query Parameter (Passive Detection)\n|  - https://cap-ad.fr/wp-content/plugins/tablepress/css/default.min.css?ver=1.12",
            "[+] wordpress-seo\n| Location: http://exemple.fr/wp-content/plugins/wordpress-seo/\n| Latest Version: 15.5 (up to date)\n| Last Updated: 2020-12-15T08:22:00.000Z\n| Found By: Comment (Passive Detection)\n| Version: 15.5 (60% confidence)\n| Found By: Comment (Passive Detection)\n|  - https://cap-ad.fr/, Match: 'optimized with the Yoast SEO plugin v15.5 -'",
            "[+] Enumerating Config Backups (via Passive and Aggressive Methods)",
            "Checking Config Backups -: |================================================================================================================================================================================================================|",
            "[i] No Config Backups Found.",
            "[+] Finished: Sun Dec 27 12:22:30 2020\n[+] Requests Done: 71\n[+] Cached Requests: 0\n[+] Data Sent: 16.156 KB\n[+] Data Received: 544.387 KB\n[+] Memory used: 245.668 MB\n[+] Elapsed time: 00:00:11",
            "[False positive]\n[!] No WPScan API Token given, as a result vulnerability data has not been output.\n[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register"
        ],
        "warnings": [],
        "alerts": [],
        "fixed": [],
        "summary": {
            "table": null,
            "line": "WPScan result summary: alerts=0, warnings=0, infos=20, error=0"
        },
        "wpscan_output": "",
        "wpscan_parser": null
    },
    {
        "site": "http://google.com",
        "datetime": "2020-12-28T13-31-30",
        "status": "ERROR",
        "last_email": null,
        "error": "Scan Aborted: The remote website is up, but does not seem to be running WordPress.\n\nCould not scan site http://google.com \nTraceback (most recent call last):\n  File \"/Users/landestt/Documents/isrm-git/WPWatcher/wpwatcher/scan.py\", line 244, in scan_site\n    if not self._scan_site(wp_site, wp_report):\n  File \"/Users/landestt/Documents/isrm-git/WPWatcher/wpwatcher/scan.py\", line 208, in _scan_site\n    raise RuntimeError(err_str)\nRuntimeError: WPScan failed with exit code 4. \nArguments: ['--random-user-agent', '--format', 'json', '--cache-ttl', '0', '--url', 'http://google.com']. \nOutput: \n{\n  \"banner\": {\n    \"description\": \"WordPress Security Scanner by the WPScan Team\",\n    \"version\": \"3.8.11\",\n    \"authors\": [\n      \"@_WPScan_\",\n      \"@ethicalhack3r\",\n      \"@erwan_lr\",\n      \"@firefart\"\n    ],\n    \"sponsor\": \"Sponsored by Automattic - https://automattic.com/\"\n  },\n  \"scan_aborted\": \"The remote website is up, but does not seem to be running WordPress.\"\n}\n\nError: \n\n",
        "infos": [
            "Scanned with WordPress Security Scanner by the WPScan Team\nVersion: 3.8.11"
        ],
        "warnings": [],
        "alerts": [],
        "fixed": [],
        "summary": {
            "table": [],
            "line": "WPScan result summary: alerts=0, warnings=0, infos=1, error=1"
        },
        "wpscan_output": "",
        "wpscan_parser": null
    }
]
        """)

        tmp.flush()

        f = io.StringIO()
        with redirect_stdout(f):
            try:
                main(["--wprs", tmp.name])
            except SystemExit:
                pass
        s = f.getvalue()

        self.assertIn("http://google.com    ERROR    2020-12-28T13-31-30  None                 0        Scan Aborted: The remote website is up, but does not seem to be running WordPress.", s)
        self.assertIn("http://exemple.fr    INFO     2020-12-27T12-22-15  None", s)
        self.assertIn(f"INFO - Load wp_reports database: {tmp.name}", s)
        
        os.remove(tmp.name)


    def test_show(self):

        tmp=tempfile.NamedTemporaryFile('w', delete=False)

        tmp.write(r"""[
    {
        "site": "http://exemple.fr",
        "datetime": "2020-12-27T12-22-15",
        "status": "INFO",
        "last_email": null,
        "error": "",
        "infos": [
            "_______________________________________________________________\n__          _______   _____\n\\ \\        / /  __ \\ / ____|\n\\ \\  /\\  / /| |__) | (___   ___  __ _ _ __ \u00ae\n\\ \\/  \\/ / |  ___/ \\___ \\ / __|/ _` | '_ \\\n\\  /\\  /  | |     ____) | (__| (_| | | | |\n\\/  \\/   |_|    |_____/ \\___|\\__,_|_| |_|",
            "WordPress Security Scanner by the WPScan Team\nVersion 3.8.11\nSponsored by Automattic - https://automattic.com/\n@_WPScan_, @ethicalhack3r, @erwan_lr, @firefart\n_______________________________________________________________",
            "[+] URL: http://exemple.fr/ [51.91.236.255]\n[+] Effective URL: https://cap-ad.fr/\n[+] Started: Sun Dec 27 12:22:19 2020",
            "Interesting Finding(s):",
            "[+] Headers\n| Interesting Entries:\n|  - Server: Apache\n|  - X-Powered-By: PHP/7.4\n| Found By: Headers (Passive Detection)\n| Confidence: 100%",
            "[+] This site seems to be a multisite\n| Found By: Direct Access (Aggressive Detection)\n| Confidence: 100%\n| Reference: http://codex.wordpress.org/Glossary#Multisite",
            "[+] WordPress version 5.5.3 identified (Latest, released on 2020-10-30).\n| Found By: Rss Generator (Passive Detection)\n|  - https://cap-ad.fr/feed/, <generator>https://wordpress.org/?v=5.5.3</generator>\n|  - https://cap-ad.fr/comments/feed/, <generator>https://wordpress.org/?v=5.5.3</generator>",
            "[+] WordPress theme in use: catch-responsive\n| Location: http://exemple.fr/wp-content/themes/catch-responsive/\n| Latest Version: 2.7.8 (up to date)\n| Last Updated: 2020-09-15T00:00:00.000Z\n| Style URL: https://cap-ad.fr/wp-content/themes/catch-responsive/style.css?ver=20201028-161708\n| Style Name: Catch Responsive\n| Style URI: https://catchthemes.com/themes/catch-responsive/\n| Description: Catch Responsive is an extremely flexible and customizable Responsive WordPress theme suitable for almost any kind of professional website. It is based on responsive web design where each element has been carefully configured for perfect display on all devices and platforms. It is built in HTML5, CSS3 and WordPress Theme Customizer for real time customization. It comes with a wide variety of options so you can modify layout, styling, featured content, promotion headline, featured slider, pagination, icons, menus, breadcrumb, widgets and much more, directly from theme customizer. This theme is translation ready and also currently translated in Swedish, French, Brazilian Portuguese, German, Russian, Ukrainian, Polish and Danish languages. Check out Theme Instructions at https://catchthemes.com/theme-instructions/catch-responsive/, Support at https://catchthemes.com/support/ and Demo at https://catchthemes.com/demo/catch-responsive/\n| Author: Catch Themes\n| Author URI: https://catchthemes.com/\n| License: GNU General Public License, version 3 (GPLv3)\n| License URI: http://www.gnu.org/licenses/gpl-3.0.txt\n| Tags: one-column, two-columns, left-sidebar, right-sidebar, grid-layout, custom-background, custom-colors, custom-header, custom-menu, editor-style, featured-image-header, featured-images, flexible-header, front-page-post-form, post-formats, sticky-post, theme-options, threaded-comments, translation-ready, footer-widgets, blog, education, portfolio\n| Text Domain: catch-responsive\n| Found By: Css Style In Homepage (Passive Detection)\n| Confirmed By: Css Style In 404 Page (Passive Detection)\n| Version: 2.7.8 (80% confidence)\n| Found By: Style (Aggressive Detection)\n|  - https://cap-ad.fr/wp-content/themes/catch-responsive/style.css?ver=20201028-161708, Match: 'Version: 2.7.8'",
            "[+] Enumerating All Plugins (via Passive Methods)\n[+] Checking Plugin Versions (via Passive and Aggressive Methods)",
            "[i] Plugin(s) Identified:",
            "[+] feature-a-page-widget\n| Location: http://exemple.fr/wp-content/plugins/feature-a-page-widget/\n| Latest Version: 2.2.0\n| Last Updated: 2020-08-12T18:51:00.000Z\n| Found By: Urls In Homepage (Passive Detection)\n| The version could not be determined.",
            "[+] siteorigin-panels\n| Location: http://exemple.fr/wp-content/plugins/siteorigin-panels/\n| Latest Version: 2.11.8\n| Last Updated: 2020-12-09T14:03:00.000Z\n| Found By: Urls In Homepage (Passive Detection)\n| Confirmed By: Urls In 404 Page (Passive Detection)\n| The version could not be determined.",
            "[+] so-widgets-bundle\n| Location: http://exemple.fr/wp-content/plugins/so-widgets-bundle/\n| Latest Version: 1.17.11\n| Last Updated: 2020-12-09T14:30:00.000Z\n| Found By: Urls In Homepage (Passive Detection)\n| Confirmed By: Urls In 404 Page (Passive Detection)\n| The version could not be determined.",
            "[+] tablepress\n| Location: http://exemple.fr/wp-content/plugins/tablepress/\n| Latest Version: 1.12 (up to date)\n| Last Updated: 2020-12-09T09:24:00.000Z\n| Found By: Urls In Homepage (Passive Detection)\n| Confirmed By: Urls In 404 Page (Passive Detection)\n| Version: 1.12 (10% confidence)\n| Found By: Query Parameter (Passive Detection)\n|  - https://cap-ad.fr/wp-content/plugins/tablepress/css/default.min.css?ver=1.12",
            "[+] wordpress-seo\n| Location: http://exemple.fr/wp-content/plugins/wordpress-seo/\n| Latest Version: 15.5 (up to date)\n| Last Updated: 2020-12-15T08:22:00.000Z\n| Found By: Comment (Passive Detection)\n| Version: 15.5 (60% confidence)\n| Found By: Comment (Passive Detection)\n|  - https://cap-ad.fr/, Match: 'optimized with the Yoast SEO plugin v15.5 -'",
            "[+] Enumerating Config Backups (via Passive and Aggressive Methods)",
            "Checking Config Backups -: |================================================================================================================================================================================================================|",
            "[i] No Config Backups Found.",
            "[+] Finished: Sun Dec 27 12:22:30 2020\n[+] Requests Done: 71\n[+] Cached Requests: 0\n[+] Data Sent: 16.156 KB\n[+] Data Received: 544.387 KB\n[+] Memory used: 245.668 MB\n[+] Elapsed time: 00:00:11",
            "[False positive]\n[!] No WPScan API Token given, as a result vulnerability data has not been output.\n[!] You can get a free API token with 50 daily requests by registering at https://wpscan.com/register"
        ],
        "warnings": [],
        "alerts": [],
        "fixed": [],
        "summary": {
            "table": null,
            "line": "WPScan result summary: alerts=0, warnings=0, infos=20, error=0"
        },
        "wpscan_output": "",
        "wpscan_parser": null
    },
    {
        "site": "http://google.com",
        "datetime": "2020-12-28T13-31-30",
        "status": "ERROR",
        "last_email": null,
        "error": "Scan Aborted: The remote website is up, but does not seem to be running WordPress.\n\nCould not scan site http://google.com \nTraceback (most recent call last):\n  File \"/Users/landestt/Documents/isrm-git/WPWatcher/wpwatcher/scan.py\", line 244, in scan_site\n    if not self._scan_site(wp_site, wp_report):\n  File \"/Users/landestt/Documents/isrm-git/WPWatcher/wpwatcher/scan.py\", line 208, in _scan_site\n    raise RuntimeError(err_str)\nRuntimeError: WPScan failed with exit code 4. \nArguments: ['--random-user-agent', '--format', 'json', '--cache-ttl', '0', '--url', 'http://google.com']. \nOutput: \n{\n  \"banner\": {\n    \"description\": \"WordPress Security Scanner by the WPScan Team\",\n    \"version\": \"3.8.11\",\n    \"authors\": [\n      \"@_WPScan_\",\n      \"@ethicalhack3r\",\n      \"@erwan_lr\",\n      \"@firefart\"\n    ],\n    \"sponsor\": \"Sponsored by Automattic - https://automattic.com/\"\n  },\n  \"scan_aborted\": \"The remote website is up, but does not seem to be running WordPress.\"\n}\n\nError: \n\n",
        "infos": [
            "Scanned with WordPress Security Scanner by the WPScan Team\nVersion: 3.8.11"
        ],
        "warnings": [],
        "alerts": [],
        "fixed": [],
        "summary": {
            "table": [],
            "line": "WPScan result summary: alerts=0, warnings=0, infos=1, error=1"
        },
        "wpscan_output": "",
        "wpscan_parser": null
    }
]
        """)

        tmp.flush()

        f = io.StringIO()
        with redirect_stdout(f):
            try:
                main(["--reports", tmp.name, "--show", "exemple.fr"])
            except SystemExit:
                pass
        s = f.getvalue()

        self.assertIn("WPScan result summary: alerts=0, warnings=0, infos=20, error=0", s)
        self.assertIn(f"INFO - Load wp_reports database: {tmp.name}", s)
        
        os.remove(tmp.name)