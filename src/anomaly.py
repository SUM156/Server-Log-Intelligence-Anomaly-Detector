"""
anomaly.py
==========
Flags anomalous traffic patterns using simple, EXPLAINABLE statistics
rather than a black-box ML model. For a first-line log analysis tool,
explainability matters more than sophistication: an on-call engineer
needs to be able to answer "why did this get flagged?" in one sentence
("this IP made 340 requests in one minute, 17x the deck's median"), not
"a neural network decided so".

Two detectors, covering two different real-world failure modes:

1. Global traffic spikes -- overall request volume jumps well above
   its recent baseline (e.g. a viral post, or a distributed attack from
   many IPs at once). Detected via a z-score over per-window totals.

2. Single-IP flooding -- one client makes a disproportionate number of
   requests in a short window (the classic single-source DDoS/scraper
   signature). Detected via a simple, configurable absolute threshold
   per time window, since a single aggressive IP can be well within
   the "normal" range of TOTAL site traffic and still be an attacker.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List

from src.models import LogEntry

# Z-score above which a traffic window is considered a "spike". 3.0
# means "more than 3 standard deviations above the mean" -- a
# conventional statistical outlier threshold that flags roughly the
# top 0.1% of a normal distribution, which keeps false positives low
# on naturally bursty (but legitimate) traffic.
DEFAULT_SPIKE_ZSCORE_THRESHOLD = 3.0

# A single IP making more than this many requests within one time
# window is flagged, regardless of overall site traffic. 100
# requests/minute from ONE client is far beyond normal human browsing
# behavior and is a reasonable default for "likely a bot or attack".
DEFAULT_SINGLE_IP_THRESHOLD = 100

# Size of each analysis time bucket.
DEFAULT_WINDOW = timedelta(minutes=1)


@dataclass(frozen=True)
class TrafficSpike:
    """A time window where TOTAL request volume was a statistical outlier."""

    window_start: datetime
    request_count: int
    zscore: float


@dataclass(frozen=True)
class SingleIPFlood:
    """A time window where one specific IP exceeded the flood threshold."""

    window_start: datetime
    ip_address: str
    request_count: int
    threshold: int


def _bucket_by_window(
    entries: List[LogEntry], window: timedelta
) -> Dict[datetime, List[LogEntry]]:
    """Group entries into fixed-size time buckets, keyed by bucket start.

    Bucketing is the foundation both detectors are built on: it turns
    a raw request timeline into a fixed-rate time series, which is
    what makes statistics like mean/stddev meaningful in the first
    place (comparing raw per-second counts would be far too noisy).
    """
    buckets: Dict[datetime, List[LogEntry]] = defaultdict(list)
    window_seconds = window.total_seconds()

    for entry in entries:
        # Floor the timestamp to the start of its window, e.g. with a
        # 1-minute window, 13:55:47 and 13:55:02 both map to 13:55:00.
        epoch_seconds = entry.timestamp.timestamp()
        bucket_epoch = epoch_seconds - (epoch_seconds % window_seconds)
        bucket_start = datetime.fromtimestamp(
            bucket_epoch, tz=entry.timestamp.tzinfo
        )
        buckets[bucket_start].append(entry)

    return buckets


def detect_traffic_spikes(
    entries: List[LogEntry],
    window: timedelta = DEFAULT_WINDOW,
    zscore_threshold: float = DEFAULT_SPIKE_ZSCORE_THRESHOLD,
) -> List[TrafficSpike]:
    """Detect time windows where total request volume was a statistical
    outlier compared to the rest of the log's traffic.

    Args:
        entries: Parsed log entries to analyze.
        window: Size of each time bucket (default: 1 minute).
        zscore_threshold: Minimum z-score to flag a window as a spike.

    Returns:
        Detected spikes, ordered by window start time. Returns an
        empty list if there are too few time windows (< 2) to compute
        a meaningful standard deviation, or if no window exceeds the
        threshold.
    """
    buckets = _bucket_by_window(entries, window)
    if len(buckets) < 2:
        return []

    counts = [len(bucket_entries) for bucket_entries in buckets.values()]
    mean_count = statistics.mean(counts)
    stdev_count = statistics.stdev(counts)

    if stdev_count == 0:
        # Every window had identical traffic -- there is no variance
        # to compute a z-score against, so nothing can be an outlier.
        return []

    spikes = []
    for window_start, bucket_entries in sorted(buckets.items()):
        count = len(bucket_entries)
        zscore = (count - mean_count) / stdev_count
        if zscore >= zscore_threshold:
            spikes.append(
                TrafficSpike(
                    window_start=window_start,
                    request_count=count,
                    zscore=round(zscore, 2),
                )
            )

    return spikes


def detect_single_ip_floods(
    entries: List[LogEntry],
    window: timedelta = DEFAULT_WINDOW,
    threshold: int = DEFAULT_SINGLE_IP_THRESHOLD,
) -> List[SingleIPFlood]:
    """Detect time windows where one IP exceeded the flood threshold.

    Args:
        entries: Parsed log entries to analyze.
        window: Size of each time bucket (default: 1 minute).
        threshold: Requests-per-window count above which a single IP
            is flagged, regardless of overall site traffic.

    Returns:
        Detected floods, ordered by window start time then descending
        request count.
    """
    buckets = _bucket_by_window(entries, window)

    floods = []
    for window_start, bucket_entries in sorted(buckets.items()):
        ip_counts: Dict[str, int] = defaultdict(int)
        for entry in bucket_entries:
            ip_counts[entry.ip_address] += 1

        for ip_address, count in ip_counts.items():
            if count >= threshold:
                floods.append(
                    SingleIPFlood(
                        window_start=window_start,
                        ip_address=ip_address,
                        request_count=count,
                        threshold=threshold,
                    )
                )

    floods.sort(key=lambda flood: (flood.window_start, -flood.request_count))
    return floods