import socket
import sys
from datetime import datetime
from scanner import scan_target
from report import print_results, save_report

def resolve_target(target):
    """Resolve hostname to IP address"""
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"\n  Resolved {target} → {ip}")
        return ip
    except socket.gaierror:
        print(f"\n  [ERROR] Cannot resolve host: {target}")
        sys.exit(1)

def get_port_range(choice):
    """Return port list based on user choice"""
    if choice == "1":
        # Top 20 most common ports
        return [21, 22, 23, 25, 53, 80, 110, 135,
                139, 143, 443, 445, 3306, 3389,
                5432, 6379, 8080, 8443, 27017, 8888]
    elif choice == "2":
        return list(range(1, 1025))       # Well-known ports
    elif choice == "3":
        return list(range(1, 10001))      # Top 10,000 ports
    elif choice == "4":
        start = int(input("  Start port : "))
        end   = int(input("  End port   : "))
        return list(range(start, end + 1))
    else:
        print("  Invalid choice, using top 20 ports")
        return [21, 22, 23, 25, 53, 80, 110, 135,
                139, 143, 443, 445, 3306, 3389,
                5432, 6379, 8080, 8443, 27017, 8888]

def banner():
    print("""
  ╔══════════════════════════════════════════════╗
  ║         NETWORK PORT SCANNER v1.0            ║
  ║         Built by Murari Amara                ║
  ║         github.com/Murari911                 ║
  ╚══════════════════════════════════════════════╝
    """)

def main():
    banner()

    # ── Target input ──────────────────────────────
    print("  Enter target (IP or hostname)")
    print("  Examples: 127.0.0.1 | scanme.nmap.org")
    target_input = input("\n  Target → ").strip()

    if not target_input:
        print("  [ERROR] No target entered.")
        sys.exit(1)

    target = resolve_target(target_input)

    # ── Port range ────────────────────────────────
    print(f"""
  Select port range:
  [1] Top 20 common ports  (fast)
  [2] Well-known ports 1-1024  (medium)
  [3] Top 10,000 ports  (slow)
  [4] Custom range
    """)
    choice = input("  Choice → ").strip()
    port_range = get_port_range(choice)

    # ── Scan ──────────────────────────────────────
    start_time = datetime.now()
    open_ports, closed_ports = scan_target(target, port_range)

    # ── Results ───────────────────────────────────
    print_results(target, open_ports, closed_ports, start_time)

    # ── Risk Assessment ───────────────────────────
    if open_ports:
        from report import assess_risk
        risks = assess_risk(open_ports)
        risky = [r for r in risks if r.get("risk") == "HIGH"]
        if risky:
            print(f"  ⚠️  RISK ASSESSMENT")
            print(f"  {'-'*46}")
            for r in risky:
                print(f"  Port {r['port']} — {r['note']}")
            print()

    # ── Save report ───────────────────────────────
    save_choice = input("  Save report to JSON? (y/n) → ").strip().lower()
    if save_choice == 'y':
        save_report(target, open_ports, closed_ports, start_time)

    print("  Scan finished. Stay ethical! 🔐\n")

if __name__ == "__main__":
    main()