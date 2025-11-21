# 🛡️ Local Bug Bounty Scanner

A beginner‑friendly, passive vulnerability and misconfiguration scanner built in Python for learning security testing and bug bounty research. This tool helps analyze web applications for common weaknesses such as missing security headers, weak cookie configurations, exposed admin paths, and publicly accessible `robots.txt`.

This project is designed to be used **safely on local or authorized systems only** and is perfect for students, interns, and beginners building hands‑on security skills.

---

## 🚀 Features

* Detects missing essential security headers:

  * `Content-Security-Policy`
  * `Strict-Transport-Security`
  * `X-Frame-Options`
  * `X-Content-Type-Options`
  * `Referrer-Policy`
  * `Permissions-Policy`
* Checks cookies for missing:

  * Secure flag
  * HttpOnly flag
* Reads publicly available `robots.txt`
* Searches for admin‑like links (e.g., `/admin`)
* Outputs results in easy‑to‑read JSON format
* Fully passive and safe – no exploitation

---

## ⚠️ Legal & Ethical Notice

This tool is for **educational and legal use only**.

You may:
✔ Scan your own local systems
✔ Scan targets you are explicitly permitted to test

You may **not**:
❌ Scan websites without legal permission
❌ Use this tool for unauthorized hacking

You are responsible for your own usage.

---

# 📁 Project Structure

```
Local-Bug-Bounty-Scanner/
|
|-- simple_scanner.py     # Main scanner script
|   # Local vulnerable environment
|   index.html
|   admin.html
|   robots.txt
|
|-- README.md
```

---

# ⚙️ Requirements

### 1️⃣ Install Python 3

Confirm installation:

```bash
python3 --version
```

### 2️⃣ Install required packages

```bash
pip install requests beautifulsoup4
```

---

# 🧪 Testing the Tool on a Local Web Server

## Step 1 – Create a Local Vulnerable Test Site

Inside a folder `test-site`, create:

`index.html`

```html
<!DOCTYPE html>
<html>
<head>
    <title>Test Site</title>
</head>
<body>
    <h1>Welcome to the local vulnerable site</h1>
    <a href="/admin">Admin Panel</a>

    <form action="/login" method="POST">
        <input type="text" name="username"/>
        <input type="password" name="password"/>
        <button>Login</button>
    </form>
</body>
</html>
```

`admin.html`

```html
<h1>This is admin panel (unprotected)</h1>
```

`robots.txt`

```txt
Disallow: /admin
```

---

## Step 2 – Start a Local Web Server

Inside `test-site`, run:

```bash
python3 -m http.server 8000
```

Your site is now available here:

```
http://localhost:8000

```

---

# ▶️ Using the Scanner

## Step 1 – Run the script

From the project folder:

```bash
python3 simple_scanner.py http://localhost:8000

```

## Step 2 – Example Output

```json
{
  "target": "http://localhost:8000",
  "status": 200,
  "security_headers": {
    "present": {},
    "missing": [
      "Strict-Transport-Security",
      "Content-Security-Policy",
      "X-Frame-Options",
      "X-Content-Type-Options",
      "Referrer-Policy",
      "Permissions-Policy"
    ]
  },
  "cookie_issues": [],
  "robots_file": "Disallow: /admin",
  "admin_links_found": [
    "/admin"
  ],
  "server": "SimpleHTTP/0.6 Python/3.10.0"
}
```

---

# 🧠 Understanding the Findings

### Missing Security Headers

Headers like CSP, HSTS, and X-Frame-Options help protect against:

* clickjacking
* man‑in‑the‑middle attacks
* unsafe content loading

### Exposed `robots.txt`

Listing sensitive endpoints can leak information to attackers.

### Admin Links Found

Unprotected admin pages may lead to unauthorized access if not secured.

---

# 📌 How It Works (Internally)

The scanner performs:

1. HTTP GET request to the target
2. Parses:

   * Response headers
   * HTML structure
   * Cookies
3. Checks for:

   * Industry‑standard security policies
   * Sensitive links
   * Potential configurations weaknesses

It does **not perform intrusion, fuzzing, brute force, or exploitation**, making it safe and compliant.

---

# 🛠️ Next Feature Ideas

You can expand this project by adding:

* HTTPS validation (certificate & TLS strength)
* Directory enumeration
* Form CSRF checks
* Built‑in HTML crawler
* Output to:

  * CSV
  * Markdown report
  * JSON logs
* Integration with tools like:

  * OWASP ZAP
  * Nmap



# 🤝 Contributions

Pull Requests, forks, and suggestions are welcome!
If you improve this tool, document your changes in the README.

---

# 📜 License

This project is free for educational and legal security auditing purposes.

Use responsibly.
