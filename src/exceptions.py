"""
exceptions.py
=============
Custom exception hierarchy so callers can catch `LogSentinelError` for
any domain failure, or a specific subtype when they need to react
differently (e.g. a corrupt log file vs. an invalid CLI argument).
"""


class LogSentinelError(Exception):
    """Base class for every error raised by this application."""


class LogParseError(LogSentinelError):
    """Raised when a log line cannot be parsed into a LogEntry.

    Note: individual unparsable lines are normally SKIPPED with a
    warning (real-world logs always have a few malformed lines --
    truncated writes, custom error pages, etc.) rather than raising.
    This exception is reserved for cases where the caller explicitly
    asked for strict parsing.
    """


class EmptyLogFileError(LogSentinelError):
    """Raised when a log file contains no parseable entries at all."""


class InvalidReportPathError(LogSentinelError):
    """Raised when a report cannot be written to the given path."""