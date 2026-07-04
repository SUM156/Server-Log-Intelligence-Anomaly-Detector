"""Unit tests for src/report.py -- report building, gzip I/O, roundtrip."""

import gzip
import json
from datetime import datetime

from src.analyzer import TrafficReport
from src.anomaly import SingleIPFlood, TrafficSpike
from src.report import build_report_dict, read_report, write_report


def _sample_report():
    traffic_report = TrafficReport(
        total_requests=100,
        top_ips=[("1.1.1.1", 50)],
        top_paths=[("/home", 30)],
        status_code_distribution={200: 90, 404: 10},
        error_rate_percent=10.0,
        server_error_rate_percent=0.0,
        total_bytes_served=50000,
    )
    spikes = [
        TrafficSpike(
            window_start=datetime(2023, 10, 10, 12, 0, 0),
            request_count=200,
            zscore=4.5,
        )
    ]
    floods = [
        SingleIPFlood(
            window_start=datetime(2023, 10, 10, 12, 1, 0),
            ip_address="6.6.6.6",
            request_count=150,
            threshold=100,
        )
    ]
    return traffic_report, spikes, floods


def test_build_report_dict_structure():
    traffic_report, spikes, floods = _sample_report()
    report_dict = build_report_dict(traffic_report, spikes, floods, source_file="access.log")

    assert report_dict["source_file"] == "access.log"
    assert report_dict["traffic_summary"]["total_requests"] == 100
    assert len(report_dict["anomalies"]["traffic_spikes"]) == 1
    assert len(report_dict["anomalies"]["single_ip_floods"]) == 1


def test_write_report_gzip_appends_gz_suffix(tmp_path):
    traffic_report, spikes, floods = _sample_report()
    report_dict = build_report_dict(traffic_report, spikes, floods, source_file="access.log")

    output_path = str(tmp_path / "report.json")
    written_path = write_report(report_dict, output_path, compress=True)

    assert written_path.endswith(".gz")
    assert (tmp_path / "report.json.gz").exists()


def test_write_report_plain_json_no_gz_suffix(tmp_path):
    traffic_report, spikes, floods = _sample_report()
    report_dict = build_report_dict(traffic_report, spikes, floods, source_file="access.log")

    output_path = str(tmp_path / "report.json")
    written_path = write_report(report_dict, output_path, compress=False)

    assert written_path == output_path
    assert not written_path.endswith(".gz")


def test_gzip_report_is_actually_compressed(tmp_path):
    """Verify the output is genuinely gzip-encoded, not just renamed --
    decoding it with the gzip module must succeed and yield valid JSON.
    """
    traffic_report, spikes, floods = _sample_report()
    report_dict = build_report_dict(traffic_report, spikes, floods, source_file="access.log")

    written_path = write_report(report_dict, str(tmp_path / "report.json"), compress=True)

    with gzip.open(written_path, "rt", encoding="utf-8") as gz_file:
        decoded = json.load(gz_file)
    assert decoded["source_file"] == "access.log"


def test_write_and_read_report_roundtrip_gzip(tmp_path):
    traffic_report, spikes, floods = _sample_report()
    report_dict = build_report_dict(traffic_report, spikes, floods, source_file="access.log")

    written_path = write_report(report_dict, str(tmp_path / "report.json"), compress=True)
    restored = read_report(written_path)

    assert restored["traffic_summary"]["total_requests"] == 100
    assert restored["anomalies"]["single_ip_floods"][0]["ip_address"] == "6.6.6.6"


def test_write_and_read_report_roundtrip_plain(tmp_path):
    traffic_report, spikes, floods = _sample_report()
    report_dict = build_report_dict(traffic_report, spikes, floods, source_file="access.log")

    written_path = write_report(
        report_dict, str(tmp_path / "report.json"), compress=False
    )
    restored = read_report(written_path)

    assert restored["source_file"] == "access.log"


def test_datetime_serialized_as_iso_string(tmp_path):
    """Window-start datetimes must serialize to ISO-8601 strings, not
    crash `json.dumps` or silently become something unparseable.
    """
    traffic_report, spikes, floods = _sample_report()
    report_dict = build_report_dict(traffic_report, spikes, floods, source_file="access.log")

    written_path = write_report(
        report_dict, str(tmp_path / "report.json"), compress=False
    )
    restored = read_report(written_path)

    spike_window = restored["anomalies"]["traffic_spikes"][0]["window_start"]
    assert spike_window == "2023-10-10T12:00:00"