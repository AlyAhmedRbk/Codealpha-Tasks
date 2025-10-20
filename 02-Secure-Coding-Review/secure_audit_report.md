# Secure Audit Report - scanned: .

**Generated:** 2025-10-20 14:02:17.974712 UTC

- Python files scanned: 1
- Findings (heuristic): 7

### R001 - Use of eval() detected
- **Severity:** CRITICAL
- **File:** secure_audit_tool.py:16
- **Code:** `("R001", r"eval\(", "Use of eval() detected", "CRITICAL"),`

### R003 - CORS configured (check for overly permissive origins)
- **Severity:** MEDIUM
- **File:** secure_audit_tool.py:18
- **Code:** `("R003", r"flask_cors|CORS\(", "CORS configured (check for overly permissive origins)", "MEDIUM"),`

### R004 - Possible SQL concatenation / injection
- **Severity:** HIGH
- **File:** secure_audit_tool.py:19
- **Code:** `("R004", r"SELECT .*%s|%s' %|\bexecute\([^,]+,\s*['\"]?%|\bformat\(", "Possible SQL concatenation / injection", "HIGH"),`

### R005 - Command execution via os.system()
- **Severity:** HIGH
- **File:** secure_audit_tool.py:20
- **Code:** `("R005", r"os\.system\(", "Command execution via os.system()", "HIGH"),`

### R007 - subprocess called with shell=True (RCE risk)
- **Severity:** HIGH
- **File:** secure_audit_tool.py:22
- **Code:** `("R007", r"subprocess.*shell=True", "subprocess called with shell=True (RCE risk)", "HIGH"),`

### R008 - Unsafe yaml.load() use (use safe_load instead)
- **Severity:** HIGH
- **File:** secure_audit_tool.py:23
- **Code:** `("R008", r"yaml\.load\(", "Unsafe yaml.load() use (use safe_load instead)", "HIGH"),`

### R013 - App bound to 0.0.0.0 (exposed to network)
- **Severity:** MEDIUM
- **File:** secure_audit_tool.py:28
- **Code:** `("R013", r"0\.0\.0\.0", "App bound to 0.0.0.0 (exposed to network)", "MEDIUM"),`



---
## Bandit Output (JSON)

```
{
  "errors": [],
  "generated_at": "2025-10-20T14:02:17Z",
  "metrics": {
    "./secure_audit_tool.py": {
      "CONFIDENCE.HIGH": 3,
      "CONFIDENCE.LOW": 0,
      "CONFIDENCE.MEDIUM": 0,
      "CONFIDENCE.UNDEFINED": 0,
      "SEVERITY.HIGH": 0,
      "SEVERITY.LOW": 3,
      "SEVERITY.MEDIUM": 0,
      "SEVERITY.UNDEFINED": 0,
      "loc": 82,
      "nosec": 0,
      "skipped_tests": 0
    },
    "_totals": {
      "CONFIDENCE.HIGH": 3,
      "CONFIDENCE.LOW": 0,
      "CONFIDENCE.MEDIUM": 0,
      "CONFIDENCE.UNDEFINED": 0,
      "SEVERITY.HIGH": 0,
      "SEVERITY.LOW": 3,
      "SEVERITY.MEDIUM": 0,
      "SEVERITY.UNDEFINED": 0,
      "loc": 82,
      "nosec": 0,
      "skipped_tests": 0
    }
  },
  "results": [
    {
      "code": "4 import datetime\n5 import subprocess\n6 \n",
      "col_offset": 0,
      "end_col_offset": 17,
      "filename": "./secure_audit_tool.py",
      "issue_confidence": "HIGH",
      "issue_cwe": {
        "id": 78,
        "link": "https://cwe.mitre.org/data/definitions/78.html"
      },
      "issue_severity": "LOW",
      "issue_text": "Consider possible security implications associated with the subprocess module.",
      "line_number": 5,
      "line_range": [
        5
      ],
      "more_info": "https://bandit.readthedocs.io/en/1.8.6/blacklists/blacklist_imports.html#b404-import-subprocess",
      "test_id": "B404",
      "test_name": "blacklist"
    },
    {
      "code": "52         print(\"[+] Running Bandit static analysis...\")\n53         result = subprocess.run([\"bandit\", \"-r\", target_dir, \"-f\", \"json\"], capture_output=True, text=True)\n54         if result.returncode == 0 or result.returncode == 1:\n",
      "col_offset": 17,
      "end_col_offset": 107,
      "filename": "./secure_audit_tool.py",
      "issue_confidence": "HIGH",
      "issue_cwe": {
        "id": 78,
        "link": "https://cwe.mitre.org/data/definitions/78.html"
      },
      "issue_severity": "LOW",
      "issue_text": "Starting a process with a partial executable path",
      "line_number": 53,
      "line_range": [
        53
      ],
      "more_info": "https://bandit.readthedocs.io/en/1.8.6/plugins/b607_start_process_with_partial_path.html",
      "test_id": "B607",
      "test_name": "start_process_with_partial_path"
    },
    {
      "code": "52         print(\"[+] Running Bandit static analysis...\")\n53         result = subprocess.run([\"bandit\", \"-r\", target_dir, \"-f\", \"json\"], capture_output=True, text=True)\n54         if result.returncode == 0 or result.returncode == 1:\n",
      "col_offset": 17,
      "end_col_offset": 107,
      "filename": "./secure_audit_tool.py",
      "issue_confidence": "HIGH",
      "issue_cwe": {
        "id": 78,
        "link": "https://cwe.mitre.org/data/definitions/78.html"
      },
      "issue_severity": "LOW",
      "issue_text": "subprocess call - check for execution of untrusted input.",
      "line_number": 53,
      "line_range": [
        53
      ],
      "more_info": "https://bandit.readthedocs.io/en/1.8.6/plugins/b603_subprocess_without_shell_equals_true.html",
      "test_id": "B603",
      "test_name": "subprocess_without_shell_equals_true"
    }
  ]
}
```