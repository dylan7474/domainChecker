import csv
import ipaddress
import socket
import ssl
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
INPUT_FILE = 'domains.csv'
INPUT_FILE_FALLBACKS = ['domains.txt']
OUTPUT_FILE = 'results.csv'

TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080] 
UDP_PORTS = [53, 123] 

CONN_TIMEOUT = 3   
READ_TIMEOUT = 3   
MAX_WORKERS = 80   


def get_ip_family(ip):
    try:
        parsed = ipaddress.ip_address(ip)
        return socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
    except ValueError:
        return None

class SafeCsvWriter:
    def __init__(self, filename):
        self.filename = filename
        self.lock = threading.Lock()
        with open(self.filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Hostname', 'CSV_IP', 'Port', 'Status', 'Banner/Info'])

    def write_row(self, row):
        with self.lock:
            with open(self.filename, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(row)

class ProgressTracker:
    def __init__(self, total):
        self.total = total
        self.count = 0
        self.lock = threading.Lock()

    def increment(self):
        with self.lock:
            self.count += 1
            percent = (self.count / self.total) * 100
            print(f"\rProgress: [{self.count}/{self.total}] {percent:.1f}% complete...", end="", flush=True)

def get_ssl_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers('DEFAULT@SECLEVEL=1') 
    except:
        pass
    return context

def browser_sanity_check(hostname):
    """
    Acts exactly like a web browser. Ignores the CSV IP and uses system DNS
    to make a standard HTTP/HTTPS request.
    """
    clean_host = hostname.rstrip('.')
    ctx = get_ssl_context()
    
    try:
        # Try HTTPS first
        req = urllib.request.Request(
            f"https://{clean_host}/", 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=5)
        return True, f"HTTP {resp.getcode()} (Browser check successful via System DNS)"
    except urllib.error.HTTPError as e:
        return True, f"HTTP {e.code} (Browser check successful via System DNS)"
    except Exception:
        pass # HTTPS failed, try HTTP
        
    try:
        # Try standard HTTP
        req = urllib.request.Request(
            f"http://{clean_host}/", 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        )
        resp = urllib.request.urlopen(req, timeout=5)
        return True, f"HTTP {resp.getcode()} (Browser check successful via System DNS)"
    except urllib.error.HTTPError as e:
        return True, f"HTTP {e.code} (Browser check successful via System DNS)"
    except Exception as e:
        return False, str(e)

def grab_banner(s, hostname, port):
    try:
        s.settimeout(READ_TIMEOUT)
        
        if port in [80, 443, 8080]:
            probe = (f"GET / HTTP/1.1\r\nHost: {hostname}\r\n"
                     f"User-Agent: Mozilla/5.0 ServiceCheck/3.0\r\nConnection: close\r\n\r\n").encode()
            
            if port == 443:
                try:
                    with get_ssl_context().wrap_socket(s, server_hostname=hostname) as ssock:
                        ssock.sendall(probe)
                        resp = ssock.recv(512).decode(errors='ignore').strip()
                        return "OPEN (Verified)", resp.splitlines()[0] if resp else "SSL Handshake Success but No Data"
                except Exception as e:
                    return "OPEN (SSL-Error)", str(e).split('] ')[-1]
            else:
                s.sendall(probe)
                resp = s.recv(512).decode(errors='ignore').strip()
                return "OPEN (Verified)", resp.splitlines()[0] if resp else "TCP Open but No HTTP Response"

        # Simplified banner grab for others
        banner = s.recv(512).decode(errors='ignore').strip()
        if not banner:
            s.sendall(b"\r\n")
            banner = s.recv(256).decode(errors='ignore').strip()
        return "OPEN (Verified)", banner if banner else "TCP Handshake Success (Silent)"

    except socket.timeout:
        return "OPEN (Silent)", "TCP Handshake Success (Timed out waiting for data)"
    except Exception as e:
        return "OPEN (Error)", f"TCP Handshake Success (Error: {str(e)[:50]})"

def check_target(hostname, ip, port, writer):
    clean_host = hostname.rstrip('.')
    family = get_ip_family(ip)
    if family is None:
        return False
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(CONN_TIMEOUT)
            if s.connect_ex((ip, port)) == 0:
                status, info = grab_banner(s, clean_host, port)
                writer.write_row([hostname, ip, f"{port}/TCP", status, info])
                return True
    except:
        pass
    return False

def check_udp_target(hostname, ip, port, writer):
    family = get_ip_family(ip)
    if family is None:
        return False
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(READ_TIMEOUT)
            if port == 53:
                probe = b'\xdb\x42\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01'
            elif port == 123:
                probe = b'\x23' + 47 * b'\x00'
            else:
                return False
            
            s.sendto(probe, (ip, port))
            data, _ = s.recvfrom(1024)
            if data:
                writer.write_row([hostname, ip, f"{port}/UDP", "OPEN (Verified)", f"UDP Response received ({len(data)} bytes)"])
                return True
    except:
        pass
    return False

def process_row(row, tracker, writer):
    if not row:
        tracker.increment()
        return

    hostname = (row.get('Domain') or row.get('Hostname') or '').strip()
    ip = (row.get('IP') or row.get('Csv_IP') or row.get('CSV_IP') or '').strip()

    if not hostname or not ip:
        tracker.increment()
        return

    found_live_service = False
    
    for port in TCP_PORTS:
        if check_target(hostname, ip, port, writer):
            found_live_service = True
            
    for port in UDP_PORTS:
        if check_udp_target(hostname, ip, port, writer):
            found_live_service = True
            
    # FAILSAFE: If the raw IP scan found NOTHING, try to load it like a web browser using DNS
    if not found_live_service:
        success, info = browser_sanity_check(hostname)
        if success:
            writer.write_row([hostname, ip, "443/80 (Browser)", "LIVE (IP Mismatch/WAF)", info])
        
    tracker.increment()


def resolve_input_path():
    candidates = [INPUT_FILE] + [name for name in INPUT_FILE_FALLBACKS if name != INPUT_FILE]
    for candidate in candidates:
        try:
            with open(candidate, 'r', encoding='utf-8'):
                return candidate
        except FileNotFoundError:
            continue
    raise FileNotFoundError(f"Could not find any input file in: {', '.join(candidates)}")


def parse_plaintext_rows(lines):
    rows = []
    for line in lines:
        clean = line.strip()
        if not clean:
            continue
        parts = [part.strip() for part in clean.split(',')]
        if len(parts) < 2:
            continue
        rows.append({'Domain': parts[0], 'IP': parts[1]})
    return rows


def load_rows(input_path):
    with open(input_path, 'r', encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        fieldnames = {name.strip().lower() for name in (reader.fieldnames or []) if name}
        has_expected_headers = bool(fieldnames & {'domain', 'hostname'}) and 'ip' in fieldnames
        if has_expected_headers:
            return list(reader)

        f.seek(0)
        return parse_plaintext_rows(f.readlines())

def main():
    try:
        input_path = resolve_input_path()
        rows = load_rows(input_path)

        print(f"--- Service Scanner (Failsafe Edition) ---")
        print(f"Input file: {input_path}")
        writer = SafeCsvWriter(OUTPUT_FILE)
        tracker = ProgressTracker(len(rows) if rows else 1)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(process_row, row, tracker, writer) for row in rows]
            for future in futures:
                future.result()
            
        print(f"\n\n--- Scan Complete! Results saved to {OUTPUT_FILE} ---")

    except Exception as e:
        print(f"\nCritical System Error: {e}")

if __name__ == "__main__":
    main()
