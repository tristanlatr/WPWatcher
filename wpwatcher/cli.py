"""
Command line arguments and specific options. 
"""

# Main program, parse the args, read config and launch scans
from typing import Dict, Optional, Any, List, Sequence, Text
import argparse
import shlex
import sys
from wpwatcher import log, _init_log
from wpwatcher.__version__ import __version__, __author__, __url__
from wpwatcher.utils import parse_timedelta
from wpwatcher.config import Config
from wpwatcher.core import WPWatcher
from wpwatcher.db import DataBase
from wpwatcher.daemon import Daemon
from wpwatcher.syslog import SyslogOutput
from wpwatcher.report import ReportCollection
from wpscan_out_parse import format_results


def main(_args: Optional[Sequence[Text]] = None) -> None:
    """Main program entrypoint"""
    # Parse arguments
    args: argparse.Namespace = get_arg_parser().parse_args(_args)

    # Init logger with CLi arguments
    _init_log(args.verbose, args.quiet)

    # If template conf , print and exit
    if args.template_conf:
        template_conf()

    # Print "banner"
    log.info(
        "WPWatcher - Automating WPscan to scan and report vulnerable Wordpress sites"
    )

    if args.version:
        # Print and exit
        version()

    if args.wprs != False:
        # Init WPWatcherDataBase object and dump reports
        wprs(filepath=args.wprs, daemon=args.daemon)

    # Read config
    configuration = Config.fromcliargs(args)

    if args.show:
        # Init WPWatcherDataBase object and dump cli formatted report
        show(
            urlpart=args.show,
            filepath=configuration["wp_reports"],
            daemon=args.daemon,
        )

    # Launch syslog test
    if args.syslog_test:
        syslog_test(configuration)

    # If daemon lopping
    if configuration["daemon"]:

        # Run 4 ever
        daemon = Daemon(configuration)
        daemon.loop()

    else:
        # Run scans and quit
        wpwatcher = WPWatcher(configuration)
        exit_code, reports = wpwatcher.run_scans()
        exit(exit_code)


def wprs(filepath: Optional[str] = None, daemon: bool = False) -> None:
    """Generate JSON file database summary"""
    db = DataBase(filepath, daemon=daemon)
    print(repr(db))
    exit(0)


def show(urlpart: str, filepath: Optional[str] = None, daemon: bool = False) -> None:
    """Inspect a report in database"""
    db = DataBase(filepath, daemon=daemon)
    matching_reports = [r for r in db._data if urlpart in r["site"]]
    eq_reports = [r for r in db._data if urlpart == r["site"]]
    if len(eq_reports):
        print(
            format_results(eq_reports[0], format="cli")
        )
    elif len(matching_reports) == 1:
        print(
            format_results(matching_reports[0], format="cli")
        )
    elif len(matching_reports) > 1:
        print(
            "The following sites match your search: \n"
        )
        print(
            repr(ReportCollection(matching_reports))
        )
        print("\nPlease be more specific. \n")
    else:
        print("No report found")
        exit(1)
    exit(0)


def version() -> None:
    """Print version and contributors"""
    print(f"Version:\t\t{__version__}")
    print(f"Authors:\t\t{__author__}")
    exit(0)


def template_conf() -> None:
    """Print template configuration"""
    print(Config.TEMPLATE_FILE)
    exit(0)


def syslog_test(conf: Config) -> None:
    """Launch the emit_test_messages() method"""
    syslog = SyslogOutput(conf)
    syslog.emit_test_messages()
    exit(0)


def get_arg_parser() -> argparse.ArgumentParser:
    """Parse CLI arguments, arguments can overwrite config file values"""

    parser = argparse.ArgumentParser(
        description=f"""WordPress Watcher is a Python wrapper for WPScan that manages scans on multiple sites and reports by email.
Some config arguments can be passed to the command.
It will overwrite previous values from config file(s).
Check {__url__} for more informations."""
    )
    parser.add_argument(
        "--conf",
        "-c",
        metavar="File path",
        help="""Configuration file. You can specify multiple files, it will overwrites the keys with each successive file.
If not specified, will try to load config from file `~/.wpwatcher/wpwatcher.conf`, `~/wpwatcher.conf` and `./wpwatcher.conf`.
All options can be missing from config file.""",
        nargs="+",
        default=None,
    )
    parser.add_argument(
        "--template_conf",
        "--tmpconf",
        help="""Print a template config file.""",
        action="store_true",
    )

    # Declare arguments
    parser.add_argument(
        "--wp_sites",
        "--url",
        metavar="URL",
        help="Site(s) to scan, you can pass multiple values",
        nargs="+",
        default=None,
    )
    parser.add_argument(
        "--wp_sites_list",
        "--urls",
        metavar="Path",
        help="Read URLs from a text file. File must contain one URL per line",
        default=None,
    )
    parser.add_argument(
        "--send_email_report",
        "--send",
        help="Enable email report sending",
        action="store_true",
    )
    parser.add_argument(
        "--email_to",
        "--em",
        metavar="Email",
        help="Email the specified receipent(s) you can pass multiple values",
        nargs="+",
        default=None,
    )
    parser.add_argument(
        "--send_infos", "--infos", help="Email INFO reports", action="store_true"
    )
    parser.add_argument(
        "--send_errors", "--errors", help="Email ERROR reports", action="store_true"
    )
    parser.add_argument(
        "--attach_wpscan_output",
        "--attach",
        help="Attach WPScan output to emails",
        action="store_true",
    )
    parser.add_argument(
        "--use_monospace_font",
        "--monospace",
        help="Use Courrier New monospaced font in emails",
        action="store_true",
    )
    parser.add_argument(
        "--fail_fast",
        "--ff",
        help="Interrupt scans if any WPScan or sendmail failure",
        action="store_true",
    )
    parser.add_argument(
        "--api_limit_wait",
        "--wait",
        help="Sleep 24h if API limit reached",
        action="store_true",
    )
    parser.add_argument("--daemon", help="Loop and scan for ever", action="store_true")
    parser.add_argument(
        "--daemon_loop_sleep",
        "--loop",
        metavar="Time string",
        help="Time interval to sleep in daemon loop",
        default=None,
    )
    parser.add_argument(
        "--wp_reports",
        "--reports",
        metavar="Path",
        help="Database Json file",
        default=None,
    )
    parser.add_argument(
        "--resend_emails_after",
        "--resend",
        metavar="Time string",
        help="Minimum time interval to resend email report with same status",
        default=None,
    )
    parser.add_argument(
        "--asynch_workers",
        "--workers",
        metavar="Number",
        help="Number of asynchronous workers",
        type=int,
        default=None,
    )
    parser.add_argument(
        "--log_file",
        "--log",
        metavar="Path",
        help="Logfile replicates all output with timestamps",
        default=None,
    )
    parser.add_argument(
        "--follow_redirect",
        "--follow",
        help="Follow site redirection if causes WPscan failure",
        action="store_true",
    )
    parser.add_argument(
        "--wpscan_output_folder",
        "--wpout",
        metavar="Path",
        help="Write all WPScan results in sub directories 'info', 'warning', 'alert' and 'error'",
        default=None,
    )
    parser.add_argument(
        "--wpscan_args",
        "--wpargs",
        metavar="Arguments",
        help="WPScan arguments as string. See 'wpscan --help' for more infos",
        default=None,
    )
    parser.add_argument(
        "--false_positive_strings",
        "--fpstr",
        metavar="String",
        help="False positive strings, you can pass multiple values",
        nargs="+",
        default=None,
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help="Verbose output, print WPScan raw output and parsed WPScan results.",
        action="store_true",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        help="Print only errors and WPScan ALERTS",
        action="store_true",
    )
    parser.add_argument(
        "--version", "-V", help="Print WPWatcher version", action="store_true"
    )
    parser.add_argument(
        "--syslog_test",
        help="Sends syslog testing packets of all possible sorts to the configured syslog server.",
        action="store_true",
    )
    parser.add_argument(
        "--wprs",
        metavar="Path",
        help="Print all reports summary. Leave path blank to find default file. Can be used with --daemon to print default daemon databse.",
        nargs="?",
        default=False,
    )
    parser.add_argument(
        "--show", metavar="Site", help="Inspect a report in the Database"
    )
    return parser


"""Main program if called with wpwatcher/cli.py"""
if __name__ == "__main__":
    main()
