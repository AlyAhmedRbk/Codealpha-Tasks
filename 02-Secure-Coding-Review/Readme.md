🔐 Secure Coding Review – Python Static Security Audit Tool
📘 Overview

This project demonstrates a Secure Coding Review process using Python.
It includes a custom-built static analysis tool that scans Python source code for common security vulnerabilities and insecure coding practices.
The goal of this task is to identify, document, and mitigate potential security risks in an application’s source code.

🎯 Objectives

Identify security vulnerabilities in Python code.

Perform static analysis using both manual inspection and automated scanning.

Generate a security audit report listing findings, severities, and remediation steps.

Provide secure coding best practices to prevent similar issues in the future.

🧩 Tools & Technologies

Language: Python

Static Analyzer: Custom regex-based scanner

Optional Tool: Bandit
 for deep static analysis

Report Format: Markdown (.md)

⚙️ How It Works

The script recursively scans all .py files in a specified directory.

It looks for insecure coding patterns using regex rules:

eval() or exec() usage

Hardcoded passwords or API keys

pickle.loads() (unsafe deserialization)

subprocess(..., shell=True) (command injection)

Debug mode enabled (debug=True)

Disabled TLS verification (verify=False)

SQL queries built with string concatenation

Weak hashing algorithms (MD5, SHA1)

Optionally, it integrates Bandit results if installed.

All findings are written to a secure_audit_report.md file with:

Vulnerability ID and description

Severity level

File name and line number

Code snippet

Recommendations for remediation

🧠 Example Usage
1. Clone or copy this repository
``` bash
git clone https://github.com/yourusername/secure-coding-review.git
cd secure-coding-review
```
2. Install Bandit (optional but recommended)
``` bash
pip install bandit
```
3. Run the scanner
``` bash
python secure_audit_tool.py .
```
4. Open the generated report
``` bash
cat secure_audit_report.md
```