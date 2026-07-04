"""
analyzer.py
===========
Aggregates a list of `LogEntry` objects into traffic statistics: top
IPs, top requested paths, status code distribution, and error rate.

This module is pure aggregation -- no regex, no I/O, no anomaly
"decision-making" (that's `anomaly.py`'s job). Keeping it pure means
every function here is testable with a handful of hand-built
`LogEntry` objects, no log file needed.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List

from src.models import LogEntry


@dataclass
class TrafficReport:
    """Aggregated statistics for a batch of log entries.

    Attributes:
        total_requests: Total number of parsed requests analyzed.
        top_ips: The most frequent client IPs, most-requests-first.
        top_paths: The most frequently requested URL paths.
        status_code_distribution: Count of requests per HTTP status code.
        error_rate_percent: Percentage of requests that were 4xx/5xx.
        server_error_rate_percent: Percentage that were specifically 5xx.
        total_bytes_served: Sum of all response sizes (bytes with a
            known size only -- entries logged as "-" are excluded).
    """

    total_requests: int
    top_ips: List[tuple[str, int]] = field(default_factory=list)
    top_paths: List[tuple[str, int]] = field(default_factory=list)
    status_code_distribution: Dict[int, int] = field(default_factory=dict)
    error_rate_percent: float = 0.0
    server_error_rate_percent: float = 0.0
    total_bytes_served: int = 0

    def to_dict(self) -> dict:
        """Serialize to a plain, JSON-friendly dict for reporting."""
        return {
            "total_requests": self.total_requests,
            "top_ips": self.top_ips,
            "top_paths": self.top_paths,
            "status_code_distribution": self.status_code_distribution,
            "error_rate_percent": self.error_rate_percent,
            "server_error_rate_percent": self.server_error_rate_percent,
            "total_bytes_served": self.total_bytes_served,
        }


def analyze_traffic(entries: List[LogEntry], top_n: int = 10) -> TrafficReport:
    """Compute aggregate traffic statistics for a batch of log entries.

    Args:
        entries: Parsed log entries to analyze.
        top_n: How many top IPs/paths to include in the report.

    Returns:
        A populated `TrafficReport`. For an empty `entries` list,
        returns a report with `total_requests=0` and empty/zeroed
        fields rather than raising -- an empty report is a valid,
        meaningful result (e.g. "no traffic in this window"), not an
        error condition.
    """
    total_requests = len(entries)
    if total_requests == 0:
        return TrafficReport(total_requests=0)

    ip_counts = Counter(entry.ip_address for entry in entries)
    path_counts = Counter(entry.path for entry in entries)
    status_counts = Counter(entry.status_code for entry in entries)

    error_count = sum(1 for entry in entries if entry.is_error)
    server_error_count = sum(1 for entry in entries if entry.is_server_error)

    total_bytes = sum(
        entry.response_size for entry in entries if entry.response_size is not None
    )

    return TrafficReport(
        total_requests=total_requests,
        top_ips=ip_counts.most_common(top_n),
        top_paths=path_counts.most_common(top_n),
        status_code_distribution=dict(sorted(status_counts.items())),
        error_rate_percent=round(100 * error_count / total_requests, 2),
        server_error_rate_percent=round(100 * server_error_count / total_requests, 2),
        total_bytes_served=total_bytes,
    )