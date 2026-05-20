import json
from datetime import datetime

def print_results(target, open_ports, closed_ports, start_time):
    """Print scan results to terminal in a clean format"""

    duration = (datetime.now() - start_time).seconds

    print(f"{'='*52}")
    print(f"  SCAN COMPLETE")
    print(f"{'='*52}")
    print(f"  Target        : {target}")
    print(f"  Open Ports    : {len(open_ports)}")
    print(f"  Closed Ports  : {len(closed_ports)}")
    print(f"  Duration      : {duration}s")
    print(f"{'='*52}\n")

    if not open_ports:
        print("  No open ports found.\n")
        return

    # Sort by port number
    sorted_ports = sorted(open_ports, key=lambda x: x["port"])

    print(f"  {'PORT':<10} {'SERVICE':<15} {'STATUS':<10} {'RESPONSE'}")
    print(f"  {'-'*46}")

    for p in sorted_ports:
        print(f"  {p['port']:<10} {p['service']:<15} {p['status']:<10} {p['time_ms']}ms")

    print()

def save_report(target, open_ports, closed_ports, start_time):
    """Save scan results to a JSON report file"""

    duration = (datetime.now() - start_time).seconds
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.json"

    report = {
        "scan_info": {
            "target":       target,
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration_sec": duration,
            "total_open":   len(open_ports),
            "total_closed": len(closed_ports),
        },
        "open_ports": sorted(open_ports, key=lambda x: x["port"]),
        "risk_assessment": assess_risk(open_ports),
    }

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"  Report saved → {filename}\n")
    return filename

def assess_risk(open_ports):
    """Basic risk assessment based on open ports"""

    risky_ports = {
        21:   "FTP — unencrypted file transfer, credentials sent in plaintext",
        23:   "Telnet — completely unencrypted, highly dangerous",
        135:  "RPC — common attack vector for Windows exploits",
        139:  "NetBIOS — can leak system information",
        445:  "SMB — vulnerable to EternalBlue/WannaCry type attacks",
        3389: "RDP — Remote Desktop, brute-force target",
        3306: "MySQL — database exposed, should not be public",
        27017:"MongoDB — often misconfigured with no authentication",
        6379: "Redis — often runs with no authentication by default",
    }

    risks = []
    for port_info in open_ports:
        port = port_info["port"]
        if port in risky_ports:
            risks.append({
                "port":  port,
                "risk":  "HIGH",
                "note":  risky_ports[port]
            })

    return risks if risks else [{"note": "No high-risk ports detected"}]