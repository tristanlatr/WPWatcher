"""
Containers for scan results data stucture.  
"""

from typing import Dict, Any, List, Iterable, Union, Optional
from wpscan_out_parse.parser.base import _Parser
class Report(Dict[str, Any]):
    """
    Dict-Like object to store scan results.
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
        if self["error"]:
            self["error"] += "\n\n"
        self["error"] += reason
        self["status"] = "ERROR"

    def load_parser(self, parser: _Parser) -> None:
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


class ReportCollection(List[Report]):
    """
    List-Like object to store reports. 
    """

    def __repr__(self) -> str:
        """
        Get the summary string.

        :Return: Summary table of all sites contained in the collection.
                 Columns are: "Site", "Status", "Last scan", "Last email", "Issues", "Problematic component(s)"
        """
        results = self
        string = "Results summary\n"
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
