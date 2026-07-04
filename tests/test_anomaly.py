"""Unit tests for src/anomaly.py -- traffic spike and IP flood detection.

These tests build synthetic timelines with a KNOWN anomaly baked in,
so each assertion verifies the detector found exactly the anomaly we
planted -- not just "found something".
"""

from datetime import datetime, timedelta

from src.anomaly import detect_single_ip_floods, detect_traffic_spikes
from src.models import LogEntry


def _make_entry(ip, dt, path="/"):
    return LogEntry(
        ip_address=ip,
        timestamp=dt,
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=200,
        response_size=100,
    )


def _minute(base: datetime, minute_offset: int, second: int = 0) -> datetime:
    return base + timedelta(minutes=minute_offset, seconds=second)


def test_no_spikes_with_uniform_traffic():
    """Perfectly uniform traffic (identical count in every window) has
    zero variance, so there is nothing to flag -- the function must
    return an empty list rather than dividing by zero.
    """
    base = datetime(2023, 10, 10, 12, 0, 0)
    entries = []
    for minute in range(10):
        for i in range(5):
            entries.append(_make_entry(f"1.1.1.{i}", _minute(base, minute, i)))

    spikes = detect_traffic_spikes(entries, window=timedelta(minutes=1))
    assert spikes == []


def test_detects_planted_traffic_spike():
    """20 windows with 5 requests each, 1 window with 100 -- a massive,
    unmistakable outlier that must be flagged. (Note: z-score is
    computed INCLUDING the outlier itself, which inflates the standard
    deviation somewhat -- a large baseline sample and a very large
    spike are used here specifically so the effect clears the default
    3.0 threshold comfortably despite that self-referential inflation.)
    """
    base = datetime(2023, 10, 10, 12, 0, 0)
    entries = []
    for minute in range(20):
        for i in range(5):
            entries.append(_make_entry(f"1.1.1.{i}", _minute(base, minute, i)))
    # Spike window: minute 20, 100 requests
    for i in range(100):
        entries.append(_make_entry(f"9.9.9.{i % 100}", _minute(base, 20, i % 59)))

    spikes = detect_traffic_spikes(entries, window=timedelta(minutes=1))

    assert len(spikes) == 1
    assert spikes[0].request_count == 100
    assert spikes[0].zscore >= 3.0


def test_too_few_windows_returns_no_spikes():
    """A z-score needs at least 2 data points to compute a standard
    deviation; a single time window must return an empty list, not
    raise a statistics.StatisticsError.
    """
    base = datetime(2023, 10, 10, 12, 0, 0)
    entries = [_make_entry("1.1.1.1", base) for _ in range(100)]

    spikes = detect_traffic_spikes(entries, window=timedelta(minutes=1))
    assert spikes == []


def test_detects_planted_single_ip_flood():
    """One IP makes 150 requests in a single window (>= the default
    100 threshold) while everyone else makes a handful -- must be
    flagged as a flood specifically attributed to that IP.
    """
    base = datetime(2023, 10, 10, 12, 0, 0)
    entries = []

    # Normal traffic from many different IPs.
    for i in range(10):
        entries.append(_make_entry(f"1.1.1.{i}", base))

    # The flooding IP.
    attacker_ip = "6.6.6.6"
    for i in range(150):
        entries.append(_make_entry(attacker_ip, base + timedelta(seconds=i % 59)))

    floods = detect_single_ip_floods(entries, window=timedelta(minutes=1), threshold=100)

    assert len(floods) == 1
    assert floods[0].ip_address == attacker_ip
    assert floods[0].request_count == 150


def test_no_flood_when_all_ips_below_threshold():
    base = datetime(2023, 10, 10, 12, 0, 0)
    entries = [_make_entry(f"1.1.1.{i}", base) for i in range(20)]

    floods = detect_single_ip_floods(entries, window=timedelta(minutes=1), threshold=100)
    assert floods == []


def test_flood_threshold_is_configurable():
    """A lower threshold should catch a smaller flood that the default
    threshold would miss entirely.
    """
    base = datetime(2023, 10, 10, 12, 0, 0)
    entries = [_make_entry("2.2.2.2", base + timedelta(seconds=i)) for i in range(30)]

    assert detect_single_ip_floods(entries, threshold=100) == []
    floods = detect_single_ip_floods(entries, threshold=25)
    assert len(floods) == 1
    assert floods[0].request_count == 30