"""Unit tests for src/analyzer.py -- traffic aggregation."""

from datetime import datetime

from src.analyzer import analyze_traffic
from src.models import LogEntry


def _make_entry(ip="1.1.1.1", path="/", status=200, size=100, dt=None):
    return LogEntry(
        ip_address=ip,
        timestamp=dt or datetime(2023, 10, 10, 12, 0, 0),
        method="GET",
        path=path,
        protocol="HTTP/1.1",
        status_code=status,
        response_size=size,
    )


def test_analyze_empty_list_returns_zeroed_report():
    report = analyze_traffic([])
    assert report.total_requests == 0
    assert report.top_ips == []
    assert report.error_rate_percent == 0.0


def test_analyze_counts_total_requests():
    entries = [_make_entry(), _make_entry(), _make_entry()]
    report = analyze_traffic(entries)
    assert report.total_requests == 3


def test_analyze_ranks_top_ips_correctly():
    entries = [
        _make_entry(ip="1.1.1.1"),
        _make_entry(ip="1.1.1.1"),
        _make_entry(ip="1.1.1.1"),
        _make_entry(ip="2.2.2.2"),
    ]
    report = analyze_traffic(entries, top_n=5)
    assert report.top_ips[0] == ("1.1.1.1", 3)
    assert report.top_ips[1] == ("2.2.2.2", 1)


def test_analyze_respects_top_n_limit():
    entries = [_make_entry(ip=f"1.1.1.{i}") for i in range(20)]
    report = analyze_traffic(entries, top_n=5)
    assert len(report.top_ips) == 5


def test_analyze_ranks_top_paths():
    entries = [
        _make_entry(path="/home"),
        _make_entry(path="/home"),
        _make_entry(path="/about"),
    ]
    report = analyze_traffic(entries)
    assert report.top_paths[0] == ("/home", 2)


def test_analyze_status_code_distribution():
    entries = [
        _make_entry(status=200),
        _make_entry(status=200),
        _make_entry(status=404),
        _make_entry(status=500),
    ]
    report = analyze_traffic(entries)
    assert report.status_code_distribution == {200: 2, 404: 1, 500: 1}


def test_analyze_error_rate_percent():
    entries = [
        _make_entry(status=200),
        _make_entry(status=200),
        _make_entry(status=404),
        _make_entry(status=500),
    ]
    report = analyze_traffic(entries)
    # 2 out of 4 are >= 400 -> 50%
    assert report.error_rate_percent == 50.0


def test_analyze_server_error_rate_percent_only_counts_5xx():
    entries = [
        _make_entry(status=200),
        _make_entry(status=404),
        _make_entry(status=500),
        _make_entry(status=503),
    ]
    report = analyze_traffic(entries)
    # 2 out of 4 are >= 500 -> 50%
    assert report.server_error_rate_percent == 50.0


def test_analyze_total_bytes_served_excludes_none_sizes():
    entries = [
        _make_entry(size=1000),
        _make_entry(size=None),
        _make_entry(size=500),
    ]
    report = analyze_traffic(entries)
    assert report.total_bytes_served == 1500


def test_analyze_to_dict_is_json_ready():
    entries = [_make_entry()]
    report = analyze_traffic(entries)
    result = report.to_dict()
    assert result["total_requests"] == 1
    assert isinstance(result["top_ips"], list)