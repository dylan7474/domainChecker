import csv
import socket
import ssl
import threading
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
INPUT_FILE = 'domains.csv'
OUTPUT_FILE = 'results.csv'

TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080] 
UDP_PORTS = [53, 123] 

CONN_TIMEOUT = 3   
READ_TIMEOUT = 3   
MAX_WORKERS = 80   

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
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(CONN_TIMEOUT)
            if s.connect_ex((ip, port)) == 0:
                status, info = grab_banner(s, clean_host, port)
                writer.write_row([hostname, ip, f"{port}/TCP", status, info])
                return True
    except:
        pass
    return False

def check_udp_target(hostname, ip, port, writer):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
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
    if not row or len(row) < 2:
        tracker.increment()
        return
    
    hostname, ip = row[0].strip(), row[1].strip()
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

def main():
    try:
        with open(INPUT_FILE, 'r') as f:
            total_rows = sum(1 for _ in f)
        
        print(f"--- Service Scanner (Failsafe Edition) ---")
        writer = SafeCsvWriter(OUTPUT_FILE)
        tracker = ProgressTracker(total_rows)

        with open(INPUT_FILE, 'r') as f:
            reader = csv.reader(f)
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(process_row, row, tracker, writer) for row in reader]
                for future in futures:
                    future.result()
            
        print(f"\n\n--- Scan Complete! Results saved to {OUTPUT_FILE} ---")

    except Exception as e:
        print(f"\nCritical System Error: {e}")

if __name__ == "__main__":
    main()
