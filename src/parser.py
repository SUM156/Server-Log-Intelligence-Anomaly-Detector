"""
parser.py
=========
Parses Apache/Nginx "combined" access log format lines into `LogEntry`
objects using a single regex with NAMED groups.

Why named groups instead of positional groups?
`match.group(1)`, `match.group(2)`, etc. is a well-known source of
subtle bugs -- if the log format ever gains/loses a field, every
positional index downstream silently shifts. Named groups
(`match.group("ip")`) are self-documenting and immune to that class of
bug: reordering the regex's groups doesn't break the parsing code at all.

The "combined" log format (used by both Apache and Nginx by default)
looks like this:

    127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.0" \
    200 2326 "http://referrer.com/" "Mozilla/5.0 ..."

    host  ident  authuser  [timestamp]  "request"  status  size  "referrer"  "user-agent"
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from src.exceptions import EmptyLogFileError
from src.models import LogEntry

logger = logging.getLogger(__name__)

# A single, well-anchored regex for the entire combined log line. Named
# groups map directly onto LogEntry fields, which keeps this the ONLY
# place in the whole codebase that needs to know the raw log format.
COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'                     # host ident authuser
    r'\[(?P<timestamp>[^\]]+)\]\s+'                     # [timestamp]
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'  # "request"
    r'(?P<status>\d{3})\s+'                              # status code
    r'(?P<size>\S+)'                                      # response size or '-'
    r'(?:\s+"(?P<referrer>[^"]*)")?'                        # optional "referrer"
    r'(?:\s+"(?P<user_agent>[^"]*)")?'                        # optional "user-agent"
)

# Apache/Nginx timestamp format: 10/Oct/2000:13:55:36 -0700
TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_line(raw_line: str) -> Optional[LogEntry]:
    """Parse a single raw log line into a `LogEntry`.

    Args:
        raw_line: One line of an Apache/Nginx combined-format access log.

    Returns:
        A `LogEntry` if the line matched the expected format, or None
        if it didn't (malformed/truncated lines are common in
        real-world logs -- e.g. from a crashed write mid-request -- so
        the caller decides whether to skip or escalate, rather than
        this function raising on every anomaly).
    """
    raw_line = raw_line.strip()
    if not raw_line:
        return None

    match = COMBINED_LOG_PATTERN.match(raw_line)
    if match is None:
        logger.debug("Skipping unparseable log line: %r", raw_line[:100])
        return None

    fields = match.groupdict()

    try:
        timestamp = datetime.strptime(fields["timestamp"], TIMESTAMP_FORMAT)
    except ValueError:
        logger.debug("Skipping line with unparseable timestamp: %r", raw_line[:100])
        return None

    size_str = fields["size"]
    response_size = int(size_str) if size_str.isdigit() else None

    return LogEntry(
        ip_address=fields["ip"],
        timestamp=timestamp,
        method=fields["method"],
        path=fields["path"],
        protocol=fields["protocol"],
        status_code=int(fields["status"]),
        response_size=response_size,
        referrer=fields.get("referrer") or None,
        user_agent=fields.get("user_agent") or None,
    )


def parse_lines(lines: Iterator[str]) -> Iterator[LogEntry]:
    """Parse an iterable of raw lines, silently skipping malformed ones.

    Uses a generator (rather than returning a list) so a multi-gigabyte
    log file can be streamed through analysis without ever holding the
    whole file in memory at once.
    """
    skipped = 0
    parsed = 0
    for raw_line in lines:
        entry = parse_line(raw_line)
        if entry is not None:
            parsed += 1
            yield entry
        else:
            skipped += 1

    if skipped:
        logger.info("Parsed %d line(s), skipped %d malformed line(s)", parsed, skipped)


def parse_file(file_path: str) -> list[LogEntry]:
    """Parse an entire log file from disk.

    Args:
        file_path: Path to the Apache/Nginx access log file.

    Returns:
        A list of successfully parsed `LogEntry` objects, in file order.

    Raises:
        FileNotFoundError: If `file_path` doesn't exist.
        EmptyLogFileError: If the file exists but contains zero
            parseable entries -- this is almost always a sign the file
            is empty, the wrong format, or corrupted, so we surface it
            loudly rather than silently returning an empty report.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with path.open("r", encoding="utf-8", errors="replace") as log_file:
        entries = list(parse_lines(log_file))

    if not entries:
        raise EmptyLogFileError(
            f"No parseable log entries found in '{file_path}'. Check that "
            "it uses the Apache/Nginx 'combined' log format."
        )

    return entries