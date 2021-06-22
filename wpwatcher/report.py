"""
Containers for scan results data stucture.  
"""

from typing import Dict, Any, List, Iterable, Tuple, Optional, overload
from wpwatcher import log
from wpscan_out_parse.parser.base import Parser
class ScanReport(Dict[str, Any]):
    """
    Dict-Like object to store and process scan results.

    Keys:

    - "site"
    - "status"
    - "datetime"
    - "last_email"
    - "error"
    - "infos"
    - "warnings"
    - "alerts"
    - "fixed"
    - "summary"
    - "wpscan_output"
    - "wpscan_parser"

    """

    DEFAULT_REPORT: Dict[str, Any] = {
        "site": "",
        "status": "",
        "datetime": None,
        "last_email": None,
        "error": "",
        "infos": [],
        "warnings": [],
        "alerts": [],
        "fixed": [],
        "summary": {},
        "wpscan_output": "",
        "wpscan_parser": None,
    }

    FIELDS: Iterable[str] = list(DEFAULT_REPORT.keys())

    def __init__(self, *args, **kwargs) -> None:  # type: ignore [no-untyped-def]
        super().__init__(*args, **kwargs)
        for key in self.FIELDS:
            self.setdefault(key, self.DEFAULT_REPORT[key])

    def fail(self, reason: str) -> None:
        """
        Mark the scan as failed. 
        """
        log.error(reason)
        if self["error"]:
            self["error"] += "\n\n"
        self["error"] += reason

    def load_parser(self, parser: Parser) -> None:
        """
        Load parser results into the report. 
        """
        # Save parser object
        self["wpscan_parser"] = parser
        
        # Save WPScan result dict
        results = parser.get_results()
        (
            self["infos"],
            self["warnings"],
            self["alerts"],
            self["summary"],
        ) = (
            results["infos"],
            results["warnings"],
            results["alerts"],
            results["summary"],
        )

        # Including error if not None
        if results["error"]:
            self.fail(results["error"])
        
        self.status()

    def __getitem__(self, key: str) -> Any:
        if key == "status":
            return self.status()
        else:
            return super().__getitem__(key)

    def status(self) -> str:
        """Get report status. """
        status = ""
        if len(self["error"]) > 0:
            status = "ERROR"
        elif len(self["warnings"]) > 0 and len(self["alerts"]) == 0:
            status = "WARNING"
        elif len(self["alerts"]) > 0:
            status = "ALERT"
        else:
            status = "INFO"
        self['status'] = status
        return status

    def update_report(self, last_wp_report: Optional['ScanReport']) -> None:
        """
        Update the report considering last report.
        """
        if last_wp_report:
            # Save already fixed issues but not reported yet
            self["fixed"] = last_wp_report["fixed"]

            # Fill out last_email datetime if any
            if last_wp_report["last_email"]:
                self["last_email"] = last_wp_report["last_email"]

            # Fill out fixed issues if the scan is not an error
            if self["status"] != "ERROR":
                fixed, unfixed = self._get_fixed_n_unfixed_issues(
                    last_wp_report, issue_type="alerts"
                )
                self["fixed"].extend(fixed)
                self._add_unfixed_warnings(
                    last_wp_report, unfixed, issue_type="alerts"
                )

                fixed, unfixed = self._get_fixed_n_unfixed_issues(
                    last_wp_report, issue_type="warnings"
                )
                self["fixed"].extend(fixed)
                self._add_unfixed_warnings(
                    last_wp_report, unfixed, issue_type="warnings"
                )

    def _add_unfixed_warnings(
        self,
        last_wp_report: 'ScanReport',
        unfixed_items: List[str],
        issue_type: str,
    ) -> None:
        """
        A line will be added at the end of the warning like:
        "This issue is unfixed since {date}"
        """

        for unfixed_item in unfixed_items:
            try:
                # Get unfixd issue
                issue_index = [
                    alert.splitlines()[0] for alert in self[issue_type]
                ].index(unfixed_item.splitlines()[0])
            except ValueError as e:
                log.error(e)
            else:
                self[issue_type][issue_index] += "\n"
                try:
                    # Try to get older issue if it exists
                    older_issue_index = [
                        alert.splitlines()[0] for alert in last_wp_report[issue_type]
                    ].index(unfixed_item.splitlines()[0])
                except ValueError as e:
                    log.error(e)
                else:
                    older_warn_last_line = last_wp_report[issue_type][
                        older_issue_index
                    ].splitlines()[-1]
                    if "This issue is unfixed" in older_warn_last_line:
                        self[issue_type][issue_index] += older_warn_last_line
                    else:
                        self[issue_type][
                            issue_index
                        ] += f"This issue is unfixed since {last_wp_report['datetime']}"

    def _get_fixed_n_unfixed_issues(
        self, last_wp_report: 'ScanReport', issue_type: str
    ) -> Tuple[List[str], List[str]]:
        """Return list of fixed issue texts to include in mails"""
        fixed_issues = []
        unfixed_issues = []
        for last_alert in last_wp_report[issue_type]:
            if (self["wpscan_parser"] and 
            not self["wpscan_parser"].is_false_positive(last_alert) ):

                if last_alert.splitlines()[0] not in [
                    alert.splitlines()[0] for alert in self[issue_type]
                ]:
                    fixed_issues.append(
                        f'Issue regarding component "{last_alert.splitlines()[0]}" has been fixed since the last scan.'
                    )
                else:
                    unfixed_issues.append(last_alert)

        return fixed_issues, unfixed_issues


class ReportCollection(List[ScanReport]):
    """
    List-Like object to store reports. 
    """

    def __repr__(self) -> str:
        """
        Get the summary string.

        :Return: Summary table of all sites contained in the collection.
                 Columns are: "Site", "Status", "Last scan", "Last email", "Issues", "Problematic component(s)"
        """
        results = [ item for item in self if item ] 
        if not results:
            return "No scan report to show"
        string = "Scan reports summary\n"
        header = (
            "Site",
            "Status",
            "Last scan",
            "Last email",
            "Issues",
            "Problematic component(s)",
        )
        sites_w = 20
        # Determine the longest width for site column
        for r in results:
            sites_w = len(r["site"]) + 4 if r and len(r["site"]) > sites_w else sites_w
        frow = "{:<%d} {:<8} {:<20} {:<20} {:<8} {}" % sites_w
        string += frow.format(*header)
        for row in results:
            pb_components = []
            for m in row["alerts"] + row["warnings"]:
                pb_components.append(m.splitlines()[0])
            # 'errors' key is deprecated.
            if row.get("error", None) or row.get("errors", []):
                err = row.get("error", "").splitlines()
                if err:
                    pb_components.append(err[0])
                # 'errors' key is deprecated, this part would be removed in the future
                for m in row.get("errors", []):
                    pb_components.append(m.splitlines()[0])
            string += "\n"
            string += frow.format(
                str(row["site"]),
                str(row["status"]),
                str(row["datetime"]),
                str(row["last_email"]),
                len(row["alerts"] + row["warnings"]),
                ", ".join(pb_components),
            )
        return string
