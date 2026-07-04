<img width="908" height="561" alt="Screenshot 2026-07-04 220057" src="https://github.com/user-attachments/assets/8487249b-f870-4922-8bde-d4d2cfc58774" />
<img width="840" height="344" alt="Screenshot 2026-07-04 220131" src="https://github.com/user-attachments/assets/85cfd591-e613-42df-b366-8fea280c65c7" />
<img width="1218" height="672" alt="Screenshot 2026-07-04 220012" src="https://github.com/user-attachments/assets/c9f96a3f-dfdf-4e7d-843f-0e7ab7eca365" />


# 🛡️ LogSentinel — Server Log Intelligence & Anomaly Detector

> Parses Apache/Nginx access logs, summarizes traffic, and flags anomalous request patterns (traffic spikes, single-IP flooding) using simple, explainable statistics — the exact category of first-line tooling real SRE/DevOps teams run daily.

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Features](#-features)
- [How Anomaly Detection Works](#-how-anomaly-detection-works)
- [Technology Stack](#-technology-stack)
- [Architecture](#-architecture)
- [Folder Structure](#-folder-structure)
- [Installation](#-installation)
- [Usage](#-usage)
- [Testing](#-testing)
- [Demo](#-demo)
- [Future Roadmap](#-future-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

## 🎯 Overview

Every company running a web server generates gigabytes of access logs — and most of the useful signal in them (who's hammering your login endpoint, whether traffic just spiked 5x) never gets looked at until something's already on fire. **LogSentinel** parses standard Apache/Nginx "combined" format logs, computes real traffic statistics, and runs two independent statistical anomaly detectors so patterns like brute-force login attempts or DDoS-style floods get surfaced automatically.

## ❓ Problem Statement

Reading raw access logs by eye doesn't scale past a few hundred lines, and full observability platforms (Datadog, Splunk) are overkill for a quick "what happened in this log file" check. LogSentinel fills that gap: a zero-dependency, single-command tool that turns a raw log file into an actionable summary in under a second, with a compressed JSON report suitable for archival or feeding into a larger pipeline.

## ✨ Features

- **Regex-based combined-log parser** using named groups — self-documenting, immune to positional-index bugs if the format changes.
- **Streaming-friendly parsing** — a generator-based pipeline that never loads an entire multi-gigabyte log into memory at once.
- **Traffic aggregation** — top IPs, top requested paths, full status-code distribution, error rate, server-error rate, total bytes served.
- **Two independent anomaly detectors:**
  - **Global traffic spikes** — z-score based, flags time windows where total request volume is a statistical outlier.
  - **Single-IP flooding** — absolute-threshold based, flags any one IP making a disproportionate number of requests in a short window (the classic brute-force/scraper/DDoS signature).
- **Gzip-compressed JSON reports** — ~68% smaller than raw JSON, ready for long-term archival.
- **42 automated tests**, including hand-verified synthetic attack scenarios.

## 🔬 How Anomaly Detection Works

Both detectors are deliberately **explainable statistics**, not a black-box model — an on-call engineer needs to answer "why did this get flagged?" in one sentence.

**1. Global traffic spikes (z-score):**
Requests are bucketed into fixed time windows (default: 1 minute). If one window's total request count is more than 3 standard deviations above the mean of all windows, it's flagged as a spike.

**2. Single-IP flooding (absolute threshold):**
Within each time window, if any single IP address makes ≥100 requests (configurable), it's flagged — regardless of how "normal" the site's total traffic looks. This catches attackers whose activity is a drop in the bucket of overall traffic but wildly abnormal for one client.

```
Demo output (from a planted brute-force attack on /login):

🚨 1 traffic spike(s) detected:
   2026-07-04 09:15:00 — 166 requests (z-score: 5.28)

🚨 1 single-IP flood event(s) detected:
   2026-07-04 09:15:00 — 203.0.113.66 made 150 requests (threshold: 100)
```

## 🛠️ Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Language | Python 3.9+ | Type hints, dataclasses, generators |
| Parsing | `re` (named groups) | Self-documenting, format-change-resilient |
| Statistics | `statistics` (stdlib) | Mean/stdev for z-score anomaly detection |
| Reports | `gzip` + `json` (stdlib) | Compressed, portable, human-inspectable |
| CLI | `argparse` | Dependency-free subcommand/flag parsing |
| Testing | `pytest` | Synthetic-attack-scenario test coverage |
| Dependencies | **Zero at runtime** | No supply-chain risk, runs anywhere |

## 🏗️ Architecture

```
Raw Apache/Nginx access log
        ↓
   parser.py        ← Regex named-group parsing → LogEntry objects
        ↓
   models.py          ← LogEntry dataclass (frozen, immutable)
        ↓
 ┌──────┴──────┐
 │             │
analyzer.py  anomaly.py     ← Traffic stats  |  Spike + flood detection
 │             │
 └──────┬──────┘
        ↓
   report.py            ← Assembles + gzip-compresses JSON report
        ↓
    cli.py                  ← argparse, formatted console output
```

**Key design decision — two SEPARATE anomaly detectors, not one:** A global-only detector would miss a determined single attacker whose traffic is small relative to total site volume. A per-IP-only detector would miss a coordinated multi-IP flood where no single IP looks abnormal alone. Running both independently — and reporting them as distinct findings — mirrors how real SOC/SRE alerting is layered in production.

## 📁 Folder Structure

```
day20_logsentinel/
├── main.py
├── requirements.txt
├── README.md
├── GUIDE.txt                # Roman Urdu setup guide
├── data/                      # Mock logs + generated reports (gitignored)
├── src/
│   ├── __init__.py
│   ├── exceptions.py
│   ├── models.py               # LogEntry dataclass
│   ├── parser.py                 # Regex combined-log parser
│   ├── analyzer.py                 # Traffic aggregation
│   ├── anomaly.py                    # Spike + flood detection
│   ├── report.py                       # Gzip JSON report I/O
│   └── cli.py                            # argparse CLI
└── tests/
    ├── test_parser.py
    ├── test_analyzer.py
    ├── test_anomaly.py           # Synthetic planted-attack scenarios
    ├── test_report.py
    └── test_cli.py
```

## ⚙️ Installation

```bash
git clone https://github.com/<your-username>/log-file-analyzer.git
cd log-file-analyzer
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt   # only installs pytest for testing
```

## 🚀 Usage

```bash
# Basic analysis
python main.py data/access.log

# Custom top-N, time window, and thresholds
python main.py data/access.log --top-n 20 --window-seconds 30 --ip-flood-threshold 50

# Write a compressed report
python main.py data/access.log --report data/report.json

# Write an uncompressed report
python main.py data/access.log --report data/report.json --no-compress
```

## 🧪 Testing

```bash
python -m pytest tests/ -v
```

**Result: 42/42 tests passing**, including synthetic-attack scenarios that plant a known spike/flood and verify the detector finds exactly that anomaly.

## 🎬 Demo

Ran against a 604-line mock log with a planted brute-force login attack:

```
📊 Total requests: 604
⚠️  Error rate: 33.28%
🔥 Server error rate (5xx): 2.32%

🚨 1 traffic spike(s) detected:
   2026-07-04 09:15:00 — 166 requests (z-score: 5.28)

🚨 1 single-IP flood event(s) detected:
   2026-07-04 09:15:00 — 203.0.113.66 made 150 requests (threshold: 100)

💾 Report written to: data/report.json.gz   (67.9% smaller than raw JSON)
```

## 🗺️ Future Roadmap

- [ ] Support JSON-formatted logs (structured logging, e.g. from cloud load balancers)
- [ ] GeoIP lookup for flagged IPs
- [ ] Rolling/streaming mode (`tail -f`-style live analysis)
- [ ] Slack/webhook alerting when an anomaly is detected
- [ ] Web dashboard (FastAPI + Chart.js) for visual traffic trends

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for any new logic (especially new anomaly detectors)
4. Ensure `pytest tests/` passes before opening a PR

## 📄 License

MIT License — free to use, modify, and distribute.
