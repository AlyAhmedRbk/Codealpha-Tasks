import os
import re
import sys
import datetime
import subprocess

# ----------------------------------------------
# Simple Python Secure Code Audit Tool
# ----------------------------------------------
# Scans .py files for common security vulnerabilities
# and produces a markdown report of findings.
# ----------------------------------------------

# Security Patterns
PATTERNS = [
    ("R001", r"eval\(", "Use of eval() detected", "CRITICAL"),
    ("R002", r"debug\s*=\s*True", "Debug mode enabled", "HIGH"),
    ("R003", r"flask_cors|CORS\(", "CORS configured (check for overly permissive origins)", "MEDIUM"),
    ("R004", r"SELECT .*%s|%s' %|\bexecute\([^,]+,\s*['\"]?%|\bformat\(", "Possible SQL concatenation / injection", "HIGH"),
    ("R005", r"os\.system\(", "Command execution via os.system()", "HIGH"),
    ("R006", r"pickle\.loads\(", "Untrusted pickle deserialization", "CRITICAL"),
    ("R007", r"subprocess.*shell=True", "subprocess called with shell=True (RCE risk)", "HIGH"),
    ("R008", r"yaml\.load\(", "Unsafe yaml.load() use (use safe_load instead)", "HIGH"),
    ("R009", r"hashlib\.(md5|sha1)\(", "Use of weak hashing algorithms (md5/sha1)", "MEDIUM"),
    ("R010", r"requests\..*verify=False", "Disabling TLS verification in requests", "HIGH"),
    ("R011", r"redirect\(", "Potential open redirect - validate redirect targets", "MEDIUM"),
    ("R012", r"password\s*=\s*['\"]|api_key\s*=\s*['\"]", "Hardcoded credential-like pattern", "HIGH"),
    ("R013", r"0\.0\.0\.0", "App bound to 0.0.0.0 (exposed to network)", "MEDIUM"),
]

def scan_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for lineno, line in enumerate(lines, 1):
        for rid, pattern, desc, severity in PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    "id": rid,
                    "desc": desc,
                    "severity": severity,
                    "file": filepath,
                    "line": lineno,
                    "code": line.strip()
                })
    return findings

def run_bandit_scan(target_dir):
    """Try to run Bandit if installed"""
    try:
        print("[+] Running Bandit static analysis...")
        result = subprocess.run(["bandit", "-r", target_dir, "-f", "json"], capture_output=True, text=True)
        if result.returncode == 0 or result.returncode == 1:
            return result.stdout
    except FileNotFoundError:
        print("[!] Bandit not installed. Skipping Bandit scan.")
    return None

def generate_report(findings, target_dir, bandit_output=None):
    report_file = os.path.join(target_dir, "secure_audit_report.md")
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"# Secure Audit Report - scanned: {target_dir}\n\n")
        f.write(f"**Generated:** {datetime.datetime.utcnow()} UTC\n\n")
        f.write(f"- Python files scanned: {len(set([x['file'] for x in findings]))}\n")
        f.write(f"- Findings (heuristic): {len(findings)}\n\n")

        for item in findings:
            f.write(f"### {item['id']} - {item['desc']}\n")
            f.write(f"- **Severity:** {item['severity']}\n")
            f.write(f"- **File:** {os.path.basename(item['file'])}:{item['line']}\n")
            f.write(f"- **Code:** `{item['code']}`\n\n")

        if bandit_output:
            f.write("\n\n---\n## Bandit Output (JSON)\n\n")
            f.write("```\n" + bandit_output[:4000] + "\n```")  # truncate for readability

    print(f"\nReport written to {report_file}")
    print(f"Findings: {len(findings)}")
    return report_file

def main():
    if len(sys.argv) < 2:
        print("Usage: python secure_audit_tool.py <target_directory>")
        sys.exit(1)

    target_dir = sys.argv[1]
    all_findings = []

    print(f"Scanning directory: {target_dir}")
    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                all_findings.extend(scan_file(path))

    bandit_output = run_bandit_scan(target_dir)
    report_path = generate_report(all_findings, target_dir, bandit_output)

    print("\nScan complete. Open the Markdown report for details.")
    print(f"{report_path}")

if __name__ == "__main__":
    main()
