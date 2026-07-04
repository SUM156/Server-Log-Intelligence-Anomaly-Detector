"""Unit tests for src/parser.py -- combined log format parsing."""

from datetime import datetime

import pytest

from src.exceptions import EmptyLogFileError
from src.parser import parse_file, parse_line, parse_lines

VALID_LINE = (
    '127.0.0.1 - frank [10/Oct/2023:13:55:36 -0700] '
    '"GET /apache_pb.gif HTTP/1.1" 200 2326 '
    '"http://www.example.com/start.html" "Mozilla/5.0"'
)


def test_parse_valid_line():
    entry = parse_line(VALID_LINE)
    assert entry is not None
    assert entry.ip_address == "127.0.0.1"
    assert entry.method == "GET"
    assert entry.path == "/apache_pb.gif"
    assert entry.protocol == "HTTP/1.1"
    assert entry.status_code == 200
    assert entry.response_size == 2326
    assert entry.referrer == "http://www.example.com/start.html"
    assert entry.user_agent == "Mozilla/5.0"


def test_parse_timestamp_correctly():
    entry = parse_line(VALID_LINE)
    assert entry.timestamp.year == 2023
    assert entry.timestamp.month == 10
    assert entry.timestamp.day == 10
    assert entry.timestamp.hour == 13
    assert entry.timestamp.minute == 55
    assert entry.timestamp.second == 36


def test_parse_line_without_referrer_or_user_agent():
    """Some log configurations omit referrer/user-agent entirely --
    the parser must still succeed on the core fields.
    """
    line = '10.0.0.5 - - [10/Oct/2023:14:00:00 -0700] "POST /api/login HTTP/1.1" 401 512'
    entry = parse_line(line)
    assert entry is not None
    assert entry.status_code == 401
    assert entry.referrer is None
    assert entry.user_agent is None


def test_parse_line_with_dash_size_returns_none_response_size():
    """A '-' in the size field means no content length was recorded --
    this must become `None`, not the integer 0 (which would incorrectly
    imply a real zero-byte response).
    """
    line = '10.0.0.5 - - [10/Oct/2023:14:00:00 -0700] "GET /redirect HTTP/1.1" 302 -'
    entry = parse_line(line)
    assert entry.response_size is None


def test_parse_empty_line_returns_none():
    assert parse_line("") is None
    assert parse_line("   ") is None


def test_parse_malformed_line_returns_none():
    assert parse_line("this is not a log line at all") is None


def test_parse_line_with_bad_timestamp_returns_none():
    line = '10.0.0.5 - - [not-a-real-date] "GET / HTTP/1.1" 200 100'
    assert parse_line(line) is None


def test_parse_lines_skips_malformed_and_keeps_valid():
    lines = [VALID_LINE, "garbage line", VALID_LINE]
    entries = list(parse_lines(lines))
    assert len(entries) == 2


def test_parse_file_reads_and_parses(tmp_path):
    log_file = tmp_path / "access.log"
    log_file.write_text(f"{VALID_LINE}\n{VALID_LINE}\n")

    entries = parse_file(str(log_file))
    assert len(entries) == 2


def test_parse_file_missing_raises_file_not_found_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_file(str(tmp_path / "does_not_exist.log"))


def test_parse_file_with_no_valid_lines_raises_empty_log_file_error(tmp_path):
    log_file = tmp_path / "junk.log"
    log_file.write_text("nothing here is a valid log line\nneither is this\n")

    with pytest.raises(EmptyLogFileError):
        parse_file(str(log_file))