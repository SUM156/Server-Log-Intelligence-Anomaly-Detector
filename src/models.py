"""
models.py
=========
Domain model for a single parsed log line.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class LogEntry:
    """A single, fully-parsed access log entry.

    Frozen (immutable) because a parsed log entry represents a
    historical fact -- it should never be mutated after creation. This
    also makes `LogEntry` hashable, which is convenient if we ever want
    to de-duplicate entries in a set.

    Attributes:
        ip_address: Client IP address that made the request.
        timestamp: Parsed request timestamp (as a real `datetime`, not
            a string -- this is what lets `analyzer.py` bucket requests
            into time windows without re-parsing dates everywhere).
        method: HTTP method (GET, POST, etc.).
        path: The requested URL path.
        protocol: HTTP protocol version string (e.g. "HTTP/1.1").
        status_code: HTTP response status code.
        response_size: Response body size in bytes. None if the log
            recorded "-" (no content, e.g. for a redirect).
        referrer: The Referer header value, if present.
        user_agent: The User-Agent header value, if present.
    """

    ip_address: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status_code: int
    response_size: Optional[int]
    referrer: Optional[str] = None
    user_agent: Optional[str] = None

    @property
    def is_error(self) -> bool:
        """True for any HTTP 4xx or 5xx response."""
        return self.status_code >= 400

    @property
    def is_server_error(self) -> bool:
        """True specifically for HTTP 5xx responses (server's fault,
        not the client's) -- a much more actionable signal for an
        on-call engineer than a blanket "error rate".
        """
        return self.status_code >= 500