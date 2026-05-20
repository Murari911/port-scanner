import socket
import threading
from datetime import datetime

# ── Common ports and their services ──────────────────────────────────────────
COMMON_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}

# ── Result storage ─────────────────────────────────────────────────────────
open_ports   = []
closed_ports = []
lock         = threading.Lock()

def get_service(port):
    """Return service name for a port or try to get it from socket"""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"

def scan_port(target, port, timeout=1):
    """
    Scan a single port on the target.
    Uses TCP connect scan — tries to complete a full connection.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        start   = datetime.now()
        result  = sock.connect_ex((target, port))
        elapsed = (datetime.now() - start).microseconds // 1000  # ms

        sock.close()

        if result == 0:
            service = get_service(port)
            with lock:
                open_ports.append({
                    "port":    port,
                    "service": service,
                    "time_ms": elapsed,
                    "status":  "OPEN"
                })
        else:
            with lock:
                closed_ports.append(port)

    except socket.error:
        with lock:
            closed_ports.append(port)

def scan_target(target, port_range, timeout=1):
    """
    Scan a target using multiple threads.
    port_range is a list of ports to scan.
    """
    # Reset results for fresh scan
    open_ports.clear()
    closed_ports.clear()

    print(f"\n{'='*52}")
    print(f"  TARGET   : {target}")
    print(f"  PORTS    : {port_range[0]} - {port_range[-1]}")
    print(f"  THREADS  : 100")
    print(f"  STARTED  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*52}\n")
    print("  Scanning", end="", flush=True)

    threads = []
    for port in port_range:
        t = threading.Thread(target=scan_port, args=(target, port, timeout))
        threads.append(t)
        t.start()

        # Run max 100 threads at a time
        if len(threads) >= 100:
            for t in threads:
                t.join()
            threads = []
            print(".", end="", flush=True)

    # Wait for remaining threads
    for t in threads:
        t.join()

    print(" done!\n")
    return open_ports, closed_ports