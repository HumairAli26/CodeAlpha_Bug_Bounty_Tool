# CodeAlpha_Bug_Bounty_Tool
📌 Overview
This Python script is a lightweight bug bounty and web security scanning tool, built primarily for educational and learning purposes. It helps identify common misconfigurations in web applications by checking for missing security headers and probing sensitive paths that may unintentionally expose information.

The tool emphasizes ethical use by requiring users to confirm they have explicit permission before scanning. It is not a replacement for professional vulnerability scanners but serves as a solid foundation for learning bug bounty methodologies.

✨ Features

✅ Permission safeguard → requires explicit confirmation before scanning.

✅ Automatic target normalization → adds https:// if missing and enforces trailing slash.

✅ Security headers check → detects missing headers such as:

Content-Security-Policy

Strict-Transport-Security

X-Frame-Options

X-Content-Type-Options

Referrer-Policy

Permissions-Policy

✅ Common paths discovery → scans for files and directories like:

/robots.txt

/.env

/admin

/backup.zip

/wp-login.php

✅ Error handling → clear messages when requests fail (timeouts, connection errors, etc.).

✅ Multi-target support → accepts multiple targets (comma-separated).

✅ Parallel scanning → uses multithreading (ThreadPoolExecutor) for faster execution.

✅ Structured output → saves detailed results in results.json.

🚀 Usage

Clone or download the script.

Make sure you have Python 3.x installed.

Install required dependency:

pip install requests


Run the script:

python3 scanner.py


Confirm you have permission to scan when prompted.

Enter one or more targets (comma-separated):

Targets: example.com, testsite.org

📂 Output

Results are displayed in the console with:

Number of missing security headers

Count of interesting paths discovered

All findings are saved in a structured JSON file (results.json), including:

Target URL

Timestamp

Missing headers

Found paths with status codes and response lengths

Errors (if any)

Example snippet from results.json:

[
  {
    "target": "https://example.com/",
    "timestamp": "2025-08-23T18:40:21Z",
    "checks": {
      "headers": {
        "status": 200,
        "missing_security_headers": ["Content-Security-Policy", "Permissions-Policy"],
        "server": "nginx"
      },
      "paths": [
        {
          "path": "/robots.txt",
          "url": "https://example.com/robots.txt",
          "status": 200,
          "len": 102
        }
      ]
    }
  }
]

⚠️ Disclaimer

This tool is meant only for educational purposes.
Use it only on systems you own or have explicit permission to test. Unauthorized scanning may be illegal.
