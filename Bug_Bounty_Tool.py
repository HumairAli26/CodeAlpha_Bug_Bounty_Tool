#!/usr/bin/env python3

import concurrent.futures
import json
import sys
from datetime import datetime
from urllib.parse import urljoin
import requests

COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.git", "/.env", "/backup.zip",
    "/admin", "/login", "/wp-login.php"
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

TIMEOUT = 10
MAX_WORKERS = 6


def affirm_permission():
    print("\n*** IMPORTANT: Only scan targets you own or have explicit permission to test. ***\n")
    res = input("Type YES to confirm you have permission to scan: ").strip()
    if res.upper() != "YES":
        print("Permission not confirmed. Exiting.")
        sys.exit(1)


def normalize_target(t):
    if not t.startswith("http://") and not t.startswith("https://"):
        t = "https://" + t
    if not t.endswith("/"):
        t += "/"
    return t


def check_headers(base_url):
    try:
        r = requests.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}  # normalize
        missing = [h for h in SECURITY_HEADERS if h.lower() not in headers]
        return {
            "status": r.status_code,
            "missing_security_headers": missing,
            "server": headers.get("server")
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"Header check failed: {str(e)}"}


def check_common_paths(base_url):
    found = []
    for p in COMMON_PATHS:
        url = urljoin(base_url, p.lstrip("/"))
        try:
            r = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code in (200, 301, 302, 403):
                found.append({
                    "path": p,
                    "url": url,
                    "status": r.status_code,
                    "len": len(r.content)
                })
        except requests.exceptions.RequestException as e:
            print(f"[!] Error checking {url}: {e}")
    return found


def scan_target(target):
    base = normalize_target(target)
    result = {
        "target": base,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": {}
    }
    try:
        result["checks"]["headers"] = check_headers(base)
        result["checks"]["paths"] = check_common_paths(base)
    except Exception as e:
        result["error"] = f"Unexpected error while scanning {base}: {str(e)}"
    return result


def main():
    affirm_permission()
    print("\nEnter your targets (comma-separated if multiple, e.g. site1.com,site2.com):")
    user_input = input("Targets: ").strip()
    if not user_input:
        print("No targets entered. Exiting.")
        sys.exit(1)

    targets = [t.strip() for t in user_input.split(",") if t.strip()]

    print(f"\nScanning {len(targets)} target(s) with {MAX_WORKERS} worker(s)...\n")
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(scan_target, t): t for t in targets}
        for fut in concurrent.futures.as_completed(futures):
            t = futures[fut]
            try:
                res = fut.result()
                if "error" in res:
                    print(f"[!] Scan failed for {t}: {res['error']}")
                else:
                    headers_missing = res["checks"]["headers"].get("missing_security_headers", [])
                    paths_found = res["checks"]["paths"]
                    print(f"[+] Done: {t}  (missing headers: {len(headers_missing)}, interesting paths: {len(paths_found)})")
                results.append(res)
            except Exception as e:
                print(f"[!] Fatal error scanning {t}: {e}")

    # Save to file
    out_file = "results.json"
    with open(out_file, "w") as outf:
        json.dump(results, outf, indent=2)

    print(f"\nResults saved to {out_file}")

if __name__ == "__main__":
    main()