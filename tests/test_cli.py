"""Integration tests for src/cli.py -- exercises parser -> analyzer ->
anomaly -> report through main(), the same way a real invocation would.
"""

import gzip
import json

import pytest

from src.cli import main

VALID_LINE = (
    '127.0.0.1 - frank [10/Oct/2023:13:55:36 -0700] '
    '"GET /apache_pb.gif HTTP/1.1" 200 2326 '
    '"http://www.example.com/start.html" "Mozilla/5.0"'
)
ERROR_LINE = (
    '10.0.0.5 - - [10/Oct/2023:13:56:10 -0700] '
    '"GET /missing HTTP/1.1" 404 0 "-" "curl/7.79.1"'
)


@pytest.fixture
def sample_log_file(tmp_path):
    log_file = tmp_path / "access.log"
    log_file.write_text(f"{VALID_LINE}\n{ERROR_LINE}\n{VALID_LINE}\n")
    return str(log_file)


def test_cli_analyzes_valid_log_file(sample_log_file, capsys):
    exit_code = main([sample_log_file])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Total requests: 3" in captured.out


def test_cli_shows_top_ips(sample_log_file, capsys):
    main([sample_log_file])
    captured = capsys.readouterr()
    assert "127.0.0.1" in captured.out


def test_cli_shows_no_anomalies_message_on_small_log(sample_log_file, capsys):
    main([sample_log_file])
    captured = capsys.readouterr()
    assert "No global traffic spikes detected" in captured.out
    assert "No single-IP flooding detected" in captured.out


def test_cli_missing_file_returns_error_exit_code(tmp_path, capsys):
    exit_code = main([str(tmp_path / "nope.log")])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error" in captured.err


def test_cli_empty_log_file_returns_error(tmp_path, capsys):
    log_file = tmp_path / "empty.log"
    log_file.write_text("not a valid log line\n")

    exit_code = main([str(log_file)])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert "Error" in captured.err


def test_cli_writes_gzip_report_when_requested(sample_log_file, tmp_path, capsys):
    report_path = tmp_path / "report.json"
    exit_code = main([sample_log_file, "--report", str(report_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Report written to" in captured.out

    gz_path = tmp_path / "report.json.gz"
    assert gz_path.exists()

    with gzip.open(gz_path, "rt", encoding="utf-8") as gz_file:
        report_data = json.load(gz_file)
    assert report_data["traffic_summary"]["total_requests"] == 3


def test_cli_writes_plain_json_report_with_no_compress_flag(sample_log_file, tmp_path):
    report_path = tmp_path / "report.json"
    main([sample_log_file, "--report", str(report_path), "--no-compress"])

    assert report_path.exists()
    data = json.loads(report_path.read_text())
    assert data["traffic_summary"]["total_requests"] == 3


def test_cli_respects_custom_top_n(sample_log_file, capsys):
    exit_code = main([sample_log_file, "--top-n", "1"])
    captured = capsys.readouterr()
    assert exit_code == 0
    # Just verify it runs cleanly with a custom top-n; exact formatting
    # is covered by test_analyzer.py's top_n tests.
    assert "Top 1 IPs" in captured.out