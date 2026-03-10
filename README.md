Infrastructure Service Scanner & Analyzer

This toolset consists of two Python scripts designed to audit a list of domains and IP addresses to determine their true "liveness" state. It goes beyond simple ping or nmap scans by performing protocol-specific banner grabbing and fallback browser-level HTTP checks to bypass false negatives caused by Load Balancers, WAFs, and stale DNS records.

Workflow

Provide an input CSV (domains.csv) containing Domain, IP.

Run check_services_v2.py -> Outputs raw port/service data to results.csv.

Run summarize_results.py -> Outputs a categorized summary to live_domains_summary.csv.

Prerequisites

Python 3.7+

No external dependencies required. All modules used (csv, socket, ssl, threading, urllib, concurrent.futures) are part of the Python Standard Library.

Script 1: Service Scanner (check_services_v2.py)

This is a highly concurrent, multi-threaded port scanner and banner grabber.

Key Features:

Protocol-Aware Probes: Sends specific probes based on the port (e.g., HTTP GET requests for 80/443, HELO for SMTP, standard UDP payloads for DNS/NTP).

SSL/TLS Forgiveness: Uses a highly permissive SSL context to communicate with legacy VPNs, PBXs, and strict WAFs that might reject standard Python socket connections.

Failsafe Browser Check: If the IP address listed in the CSV is completely dead, the script performs a fallback check. It ignores the CSV's IP, performs a fresh system DNS lookup for the hostname, and attempts to load it using urllib (mimicking a standard web browser). This prevents false negatives caused by outdated IP lists.

Configuration Variables (at top of script):

INPUT_FILE: Default domains.csv

OUTPUT_FILE: Default results.csv

TCP_PORTS: List of TCP ports to scan (Default: 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080)

UDP_PORTS: List of UDP ports to scan (Default: 53, 123)

CONN_TIMEOUT / READ_TIMEOUT: Timeouts for socket operations.

MAX_WORKERS: Number of concurrent threads (Default: 80).

Usage:

python3 check_services_v2.py


Script 2: Results Summarizer (summarize_results.py)

This script analyzes the raw data from results.csv, compares it against the original domains.csv baseline, and categorizes every domain into a specific "Liveness Tier." It cleans the domain names (stripping *. and -) and outputs a final CSV report.

The Liveness Tiers:

Tier 1: Verified Application (Definitively Live)

Meaning: The script successfully connected to the IP provided in the CSV, requested data, and received a valid application response (e.g., an HTTP 200/302, an SSH version string, or an SMTP banner).

Tier 1b: Browser Verified (DNS/IP Mismatch or WAF)

Meaning: The IP address provided in the CSV was completely dead. However, the failsafe browser check successfully loaded a webpage by resolving the hostname via system DNS.

Actionable Insight: The CSV contains outdated IP data for this domain, or the direct IP is blocked by a WAF but the hostname routing works.

Tier 2: SSL/TLS Protected (Definitively Live)

Meaning: A TCP connection was successfully established to the IP on port 443, but the SSL handshake timed out or was rejected with an alert.

Actionable Insight: Usually indicates a Load Balancer, VPN gateway, or strict WAF. The network path is open, but the security appliance dropped the automated probe. (Note: Can also indicate a "Stale VIP" where a load balancer is holding a port open for a decommissioned backend server).

Tier 3: Silent/Firewalled (Network Live)

Meaning: The TCP network connection succeeded (port is open), but the server refused to send any data back.

Actionable Insight: Common for infrastructure ports or strictly firewalled services that drop packets unless the exact correct protocol sequence is initiated.

Tier 4: Inactive / Unreachable

Meaning: The domain was in the original domains.csv, but it completely failed the port scan AND failed the failsafe browser check.

Actionable Insight: These are excellent candidates for DNS/Infrastructure cleanup. (Note: If this tier is empty, watch out for Wildcard DNS records acting as a catch-all for dead subdomains).

Usage:

python3 summarize_results.py


Known Context / Edge Cases for Future AI Development

Wildcard DNS: If *.domain.com resolves to a parking page, the "Tier 1b Browser Sanity Check" will mark truly dead subdomains as "Live" because the parking page returns an HTTP 200/404. Future logic may need to analyze the HTML body length to identify generic holding pages.

Stale VIPs: A load balancer may accept a TCP connection for a dead backend IP, resulting in a Tier 2 (SSL Timeout) classification. Manual verification via curl or openssl s_client is required to confirm if the backend is actually gone.
