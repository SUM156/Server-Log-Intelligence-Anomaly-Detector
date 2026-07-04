"""
report.py
=========
Serializes analysis results (traffic stats + detected anomalies) into
a JSON report, optionally gzip-compressed on disk.

Why gzip the report? Access log analysis reports for a busy site can
list hundreds of flagged windows/IPs; compressing them before archival
(e.g. shipping daily reports to S3/long-term storage) is standard
practice and costs almost nothing -- JSON compresses extremely well
(usually 80-90% size reduction) because of its repetitive key names.
"""

from __future__ import annotations

import gzip
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from src.analyzer import TrafficReport
from src.anomaly import SingleIPFlood, TrafficSpike
from src.exceptions import InvalidReportPathError

logger = logging.getLogger(__name__)


def _json_default(value: Any) -> str:
    """`json.dumps(default=...)` hook for non-JSON-native types.

    `datetime` objects appear throughout this report (window start
    times) and are not natively JSON-serializable -- this converts them
    to ISO-8601 strings, which round-trip cleanly and sort correctly
    even as plain text.
    """
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def build_report_dict(
    traffic_report: TrafficReport,
    traffic_spikes: List[TrafficSpike],
    ip_floods: List[SingleIPFlood],
    source_file: str,
) -> Dict[str, Any]:
    """Assemble the full analysis result into one JSON-ready dict.

    Args:
        traffic_report: Aggregate traffic statistics.
        traffic_spikes: Detected global traffic spikes.
        ip_floods: Detected single-IP flooding events.
        source_file: Path to the log file that was analyzed (recorded
            in the report for traceability -- "which log produced
            this?" should never require guessing).

    Returns:
        A plain dict, ready to pass to `json.dumps`.
    """
    return {
        "source_file": source_file,
        "generated_at": datetime.now().isoformat(),
        "traffic_summary": traffic_report.to_dict(),
        "anomalies": {
            "traffic_spikes": [
                {
                    "window_start": spike.window_start,
                    "request_count": spike.request_count,
                    "zscore": spike.zscore,
                }
                for spike in traffic_spikes
            ],
            "single_ip_floods": [
                {
                    "window_start": flood.window_start,
                    "ip_address": flood.ip_address,
                    "request_count": flood.request_count,
                    "threshold": flood.threshold,
                }
                for flood in ip_floods
            ],
        },
    }


def write_report(report_dict: Dict[str, Any], output_path: str, compress: bool = True) -> str:
    """Write a report dict to disk as JSON, optionally gzip-compressed.

    Args:
        report_dict: The report data, as built by `build_report_dict`.
        output_path: Destination file path. If `compress` is True and
            the path doesn't already end in `.gz`, `.gz` is appended
            automatically -- this avoids ever silently writing gzip
            bytes into a file that looks like plain-text JSON.
        compress: Whether to gzip-compress the output.

    Returns:
        The actual path the report was written to (may differ from
        `output_path` if a `.gz` suffix was auto-appended).

    Raises:
        InvalidReportPathError: If the destination directory doesn't
            exist and can't be created (e.g. permission denied).
    """
    path = Path(output_path)
    if compress and path.suffix != ".gz":
        path = path.with_name(path.name + ".gz")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise InvalidReportPathError(
            f"Cannot create directory for report at '{path}': {exc}"
        ) from exc

    json_bytes = json.dumps(report_dict, indent=2, default=_json_default).encode("utf-8")

    if compress:
        with gzip.open(path, "wb") as gz_file:
            gz_file.write(json_bytes)
    else:
        path.write_bytes(json_bytes)

    logger.info(
        "Wrote report to %s (%s, %d bytes)",
        path,
        "gzip-compressed" if compress else "plain JSON",
        path.stat().st_size,
    )
    return str(path)


def read_report(report_path: str) -> Dict[str, Any]:
    """Read a report back from disk, auto-detecting gzip vs. plain JSON.

    Args:
        report_path: Path to a report file previously written by
            `write_report` (either `.gz` or plain `.json`).

    Returns:
        The deserialized report dict.
    """
    path = Path(report_path)
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as gz_file:
            return json.load(gz_file)
    return json.loads(path.read_text(encoding="utf-8"))