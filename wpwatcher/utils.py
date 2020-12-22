"""
A few quick static methods. 
"""
from typing import Iterable, Optional, Tuple, Dict, Any, Callable, List
import re
import threading
import sys
import copy
import threading
import queue
from datetime import timedelta
from wpwatcher import log

# Few static helper methods -------------------


def remove_color(string: str) -> str:
    """
    Remove ansi colors from string.
    """
    return re.sub(r"(\x1b|\[[0-9][0-9]?m)", "", string)


def timeout(
    timeout: float,
    func: Callable[..., Any],
    args: Tuple[Any, ...] = (),
    kwargs: Dict[str, Any] = {},
) -> Any:
    """Run func with the given timeout.

    :raise TimeoutError: If func didn't finish running within the given timeout.
    """

    class FuncThread(threading.Thread):
        def __init__(self, bucket: queue.Queue) -> None:  # type: ignore [type-arg]
            threading.Thread.__init__(self)
            self.result: Any = None
            self.bucket: queue.Queue = bucket  # type: ignore [type-arg]
            self.err: Optional[Exception] = None

        def run(self) -> None:
            try:
                self.result = func(*args, **kwargs)
            except Exception as err:
                self.bucket.put(sys.exc_info())
                self.err = err

    bucket: queue.Queue = queue.Queue()  # type: ignore [type-arg]
    it = FuncThread(bucket)
    it.start()
    it.join(timeout)
    if it.is_alive():
        raise TimeoutError()
    else:
        try:
            _, _, exc_trace = bucket.get(block=False)
        except queue.Empty:
            return it.result
        else:
            raise it.err.with_traceback(exc_trace)  # type: ignore [union-attr]


def safe_log_wpscan_args(wpscan_args: Iterable[str]) -> List[str]:
    """Replace `--api-token` param with `"***"` for safer logging"""
    args = [val.strip() for val in copy.deepcopy(wpscan_args)]
    if "--api-token" in args:
        args[args.index("--api-token") + 1] = "***"
    return args


def oneline(string: str) -> str:
    """Helper method that transform multiline string to one line for grepable output"""
    return " ".join(line.strip() for line in string.splitlines())


def get_valid_filename(s: str) -> str:
    """Return the given string converted to a string that can be used for a clean filename.  Stolen from Django I think"""
    s = str(s).strip().replace(" ", "_")
    return re.sub(r"(?u)[^-\w.]", "", s)


def print_progress_bar(count: int, total: int) -> None:
    """Helper method to print progress bar.  Stolen on the web"""
    size = 0.3  # size of progress bar
    percent = int(float(count) / float(total) * 100)
    log.info(
        f"Progress - [{'=' * int(int(percent) * size)}{' ' * int((100 - int(percent)) * size)}] {percent}% - {count} / {total}"
    )


def parse_timedelta(time_str: str) -> timedelta:
    """
    Parse a time string e.g. (2h13m) into a timedelta object.  Stolen on the web
    """
    regex = re.compile(
        r"^((?P<days>[\.\d]+?)d)?((?P<hours>[\.\d]+?)h)?((?P<minutes>[\.\d]+?)m)?((?P<seconds>[\.\d]+?)s)?$"
    )
    time_str = replace(
        time_str,
        {
            "sec": "s",
            "second": "s",
            "seconds": "s",
            "minute": "m",
            "minutes": "m",
            "min": "m",
            "mn": "m",
            "days": "d",
            "day": "d",
            "hours": "h",
            "hour": "h",
        },
    )
    parts = regex.match(time_str)
    if parts is None:
        raise ValueError(
            f"Could not parse any time information from '{time_str}'.  Examples of valid strings: '8h', '2d8h5m20s', '2m4s'"
        )
    time_params = {
        name: float(param) for name, param in parts.groupdict().items() if param
    }
    return timedelta(**time_params)  # type: ignore [arg-type]


def replace(text: str, conditions: Dict[str, str]) -> str:
    """Multiple replacements helper method.  Stolen on the web"""
    rep = conditions
    rep = dict((re.escape(k), rep[k]) for k in rep)
    pattern = re.compile("|".join(rep.keys()))
    text = pattern.sub(lambda m: rep[re.escape(m.group(0))], text)
    return text
