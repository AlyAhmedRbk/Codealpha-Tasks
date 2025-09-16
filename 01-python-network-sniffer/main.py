import socket
import sys
import time
import threading
from datetime import datetime

# ------- Configuration -------
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT",
}
PORT_TIMEOUT = 0.5

# ANSI color helpers (minimal)
CSI = "["
RESET = CSI + "0m"
BOLD = CSI + "1m"
GREEN = CSI + "32m"
YELLOW = CSI + "33m"
RED = CSI + "31m"
CYAN = CSI + "36m"
MAGENTA = CSI + "35m"

# Small "hacker" banner
BANNER = r'''
  _   _             _    ____                          
 | \ | | ___  _ __ | |_ / ___|  ___ _ ____   _____ _ __ 
 |  \| |/ _ \| '_ \| __| |  _ / _ \ '__\ \ / / _ \ '__|
 | |\  | (_) | | | | |_| |_| |  __/ |   \ V /  __/ |   
 |_| \_|\___/|_| |_|\__|\____|\___|_|    \_/ \___|_|   

       Tiny IP Scanner — ethical use only
'''

# ------- Utilities -------

def slow_print(s, delay=0.006):
    """Print text like a terminal typing effect."""
    for ch in s:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("")


class Spinner:
    def __init__(self, text="Scanning"):
        self._running = False
        self._thread = None
        self.text = text

    def _spin(self):
        chars = "'|/-\'"
        i = 0
        while self._running:
            sys.stdout.write(f"{CYAN}{self.text} {chars[i % len(chars)]}{RESET}")
            sys.stdout.flush()
            time.sleep(0.12)
            i += 1
        sys.stdout.write("" + " " * (len(self.text) + 4) + "")
        sys.stdout.flush()

    def __enter__(self):
        self._running = True
        self._thread = threading.Thread(target=self._spin)
        self._thread.daemon = True
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._running = False
        if self._thread:
            self._thread.join()


def resolve_target(tgt):
    try:
        ip = socket.gethostbyname(tgt)
        return ip
    except Exception:
        return None


def scan_port(ip, port, timeout=PORT_TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        # banner grab attempt
        banner = b""
        try:
            s.settimeout(0.8)
            banner = s.recv(1024)
        except Exception:
            pass
        s.close()
        try:
            text = banner.decode("utf-8", errors="ignore").strip()
        except Exception:
            text = ""
        return True, text
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return False, ""


# ------- Main interactive CLI -------

def print_banner():
    print(MAGENTA + BANNER + RESET)


def prompt_menu():
    slow_print(BOLD + "Choose scan type:" + RESET, 0.004)
    print(f"  1) Quick scan (common {len(COMMON_PORTS)} ports)")
    print("  2) Custom range (e.g. 20-1024)")
    print("  3) Exit")
    choice = input(BOLD + "Select option [1-3]: " + RESET).strip()
    return choice


def parse_range(rng):
    try:
        lo, hi = rng.split("-")
        lo = int(lo)
        hi = int(hi)
        if lo < 1 or hi > 65535 or lo > hi:
            return None
        # limit size for demo to avoid very long scans
        if hi - lo > 2000:
            return None
        return list(range(lo, hi + 1))
    except Exception:
        return None


def run_scan(target, ports, save=False):
    ip = resolve_target(target)
    if not ip:
        print(RED + "Failed to resolve target." + RESET)
        return

    try:
        rdns = socket.gethostbyaddr(ip)[0]
    except Exception:
        rdns = "-"

    header = []
    header.append(f"Target: {target} ({ip})")
    header.append(f"Reverse DNS: {rdns}")
    header.append(f"Started: {datetime.utcnow().isoformat()}Z")

    results = []

    with Spinner(text=f"Scanning {ip}"):
        for p in ports:
            ok, banner = scan_port(ip, p)
            if ok:
                svc = COMMON_PORTS.get(p, "")
                results.append((p, svc, banner))
            # small sleep to be polite
            time.sleep(0.02)

    # print results
    print(BOLD + "--- Scan results ---" + RESET)
    if results:
        for p, svc, banner in sorted(results):
            line = f"{GREEN}[OPEN]{RESET} {p}/tcp"
            if svc:
                line += f" ({svc})"
            if banner:
                preview = banner.replace('', ' ')[:140]
                line += f" — {YELLOW}{preview}{RESET}"
            print(line)
    else:
        print(YELLOW + "No open ports found in the scanned range." + RESET)

    # summary
    print(BOLD + "Summary:" + RESET)
    print(f"  Target: {target} ({ip})")
    print(f"  Reverse DNS: {rdns}")
    print(f"  Scanned ports: {len(ports)}")
    print(f"  Open ports: {len(results)}")

    if save:
        fname = f"scan_{target.replace(':','_')}_{int(time.time())}.txt"
        try:
            with open(fname, "w") as fh:
                fh.write("".join(header) + "")
                if results:
                    for p, svc, banner in sorted(results):
                        fh.write(f"{p}/tcp {svc} {banner}")
                else:
                    fh.write("No open ports found.")
            print(GREEN + f"Saved results to {fname}" + RESET)
        except Exception as e:
            print(RED + f"Failed to save results: {e}" + RESET)


def main():
    print_banner()
    slow_print(CYAN + "Welcome, operator. This tool is for education and authorized testing only." + RESET)

    target = input(BOLD + "Enter target IP or hostname: " + RESET).strip()
    if not target:
        print(RED + "No target entered. Exiting." + RESET)
        return

    # resolve now to give quick feedback
    ip = resolve_target(target)
    if not ip:
        print(RED + "Could not resolve target. Try a valid hostname or IP." + RESET)
        return

    while True:
        choice = prompt_menu()
        if choice == "1":
            ports = list(COMMON_PORTS.keys())
            save = input("Save results to file? [y/N]: ").strip().lower() == 'y'
            run_scan(target, ports, save=save)
        elif choice == "2":
            rng = input("Enter port range (e.g. 20-1024): ").strip()
            ports = parse_range(rng)
            if not ports:
                print(RED + "Invalid or too-large range. Try again." + RESET)
                continue
            save = input("Save results to file? [y/N]: ").strip().lower() == 'y'
            run_scan(target, ports, save=save)
        elif choice == "3":
            slow_print(MAGENTA + "Exiting. Stay ethical." + RESET)
            break
        else:
            print(YELLOW + "Invalid choice." + RESET)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted. Bye.")
