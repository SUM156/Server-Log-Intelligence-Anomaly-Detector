"""
cli.py
======
Command-line interface. Owns argparse, print statements, and exit
codes; delegates all real work to `parser.py`, `analyzer.py`,
`anomaly.py`, and `report.py`.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import timedelta

from src.analyzer import analyze_traffic
from src.anomaly import (
    DEFAULT_SINGLE_IP_THRESHOLD,
    DEFAULT_SPIKE_ZSCORE_THRESHOLD,
    detect_single_ip_floods,
    detect_traffic_spikes,
)
from src.exceptions import LogSentinelError
from src.parser import parse_file
from src.report import build_report_dict, write_report

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description=(
            "Parse Apache/Nginx access logs, summarize traffic, and "
            "detect anomalous request patterns."
        ),
    )
    parser.add_argument("log_file", help="Path to the access log file to analyze")
    parser.add_argument(
        "--top-n", type=int, default=10, help="Number of top IPs/paths to report (default: 10)"
    )
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=60,
        help="Time bucket size in seconds for anomaly detection (default: 60)",
    )
    parser.add_argument(
        "--zscore-threshold",
        type=float,
        default=DEFAULT_SPIKE_ZSCORE_THRESHOLD,
        help=f"Z-score threshold for global traffic spikes (default: {DEFAULT_SPIKE_ZSCORE_THRESHOLD})",
    )
    parser.add_argument(
        "--ip-flood-threshold",
        type=int,
        default=DEFAULT_SINGLE_IP_THRESHOLD,
        help=f"Requests/window from one IP to flag as flooding (default: {DEFAULT_SINGLE_IP_THRESHOLD})",
    )
    parser.add_argument(
        "--report",
        help="Write a JSON report to this path (gzip-compressed by default)",
    )
    parser.add_argument(
        "--no-compress",
        action="store_true",
        help="Write the report as plain JSON instead of gzip-compressed",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser


def _print_summary(traffic_report, traffic_spikes, ip_floods, top_n: int) -> None:
    """Print a human-readable summary of the analysis to stdout."""
    print(f"📊 Total requests: {traffic_report.total_requests}")
    print(f"⚠️  Error rate: {traffic_report.error_rate_percent}%")
    print(f"🔥 Server error rate (5xx): {traffic_report.server_error_rate_percent}%")
    print(f"📦 Total bytes served: {traffic_report.total_bytes_served:,}")

    print(f"\n🌐 Top {top_n} IPs:")
    for ip_address, count in traffic_report.top_ips:
        print(f"   {ip_address:<20} {count} requests")

    print(f"\n📄 Top {top_n} paths:")
    for path, count in traffic_report.top_paths:
        print(f"   {path:<40} {count} requests")

    print("\n📈 Status code distribution:")
    for status_code, count in traffic_report.status_code_distribution.items():
        print(f"   {status_code}: {count}")

    if traffic_spikes:
        print(f"\n🚨 {len(traffic_spikes)} traffic spike(s) detected:")
        for spike in traffic_spikes:
            print(
                f"   {spike.window_start} — {spike.request_count} requests "
                f"(z-score: {spike.zscore})"
            )
    else:
        print("\n✅ No global traffic spikes detected.")

    if ip_floods:
        print(f"\n🚨 {len(ip_floods)} single-IP flood event(s) detected:")
        for flood in ip_floods:
            print(
                f"   {flood.window_start} — {flood.ip_address} made "
                f"{flood.request_count} requests (threshold: {flood.threshold})"
            )
    else:
        print("\n✅ No single-IP flooding detected.")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    try:
        entries = parse_file(args.log_file)

        traffic_report = analyze_traffic(entries, top_n=args.top_n)

        window = timedelta(seconds=args.window_seconds)
        traffic_spikes = detect_traffic_spikes(
            entries, window=window, zscore_threshold=args.zscore_threshold
        )
        ip_floods = detect_single_ip_floods(
            entries, window=window, threshold=args.ip_flood_threshold
        )

        _print_summary(traffic_report, traffic_spikes, ip_floods, args.top_n)

        if args.report:
            report_dict = build_report_dict(
                traffic_report, traffic_spikes, ip_floods, source_file=args.log_file
            )
            written_path = write_report(
                report_dict, args.report, compress=not args.no_compress
            )
            print(f"\n💾 Report written to: {written_path}")

        return 0

    except LogSentinelError as exc:
        print(f"❌ Error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"❌ Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
    