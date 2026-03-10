# Domain Checker

Domain Checker is a lightweight Python toolkit for validating whether domains and mapped IPs are actually live. It performs protocol-aware checks across common infrastructure ports, captures basic service banners, and then summarizes results into practical liveness tiers for cleanup and triage.

## What the application is

The project is made of two scripts:

- `check_services.py`: scans each `Domain,IP` row from `domains.csv` using TCP/UDP probes and writes raw findings to `results.csv`.
- `summarize_results.py`: reads scanner output and baseline input, then produces a categorized liveness report in `live_domains_summary.csv`.

This flow helps distinguish truly active services from stale DNS/IP mappings and firewall/WAF edge cases.

## Build / run instructions

No compilation step is required.

### Requirements

- Python 3.7+
- Standard library only (no external package install required)

### Input format

Create a `domains.csv` file with this header:

```csv
Domain,IP
example.com,93.184.216.34
```

`Domain` and `IP` column names are expected by default. `Hostname` is also accepted as an alias for `Domain`.

### Basic run sequence

```bash
python3 check_services.py
python3 summarize_results.py
```

## Basic controls

Controls are configured by editing variables at the top of `check_services.py`:

- `INPUT_FILE` / `OUTPUT_FILE`: file names for scanner input/output.
- `TCP_PORTS` / `UDP_PORTS`: which ports to probe.
- `CONN_TIMEOUT` / `READ_TIMEOUT`: socket and read limits.
- `MAX_WORKERS`: scan concurrency.

The summarizer then reads `results.csv` and generates `live_domains_summary.csv` with tiered statuses.

## Liveness tiers (summary)

- **Tier 1 – Verified Application:** direct service response received.
- **Tier 1b – Browser Verified:** direct IP probe failed, but hostname resolved and loaded.
- **Tier 2 – SSL/TLS Protected:** network path open but TLS handshake failed/timed out.
- **Tier 3 – Silent/Firewalled:** open port, no meaningful response body/banner.
- **Tier 4 – Inactive/Unreachable:** no scan or browser-level verification succeeded.

The summarizer normalizes hostnames (lowercase, trims trailing dots, strips wildcard markers) before tiering so duplicate variants map to a single domain entry.

## Roadmap

- Add wildcard-DNS detection heuristics to reduce false-positive Tier 1b classifications.
- Add optional JSON output alongside CSV for easier pipeline integrations.
- Add CLI flags for runtime configuration instead of source edits.
- Add unit tests for summarization logic and tier classification rules.
