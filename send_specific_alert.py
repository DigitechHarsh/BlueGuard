import requests
import time

WEBHOOK_URL = "http://127.0.0.1:5000/webhook"

test_alert = {
    "timestamp": "2026-04-22T12:00:00+05:30",
    "rule": {
        "level": 14,
        "description": "Nessus Vulnerability Scanner: Critical vulnerability detected. Plugin ID: 298055. Vulnerability: Nginx-Ui (CVE-2026-33032).",
        "id": "87924",
        "groups": ["vulnerability-detector", "nessus"]
    },
    "agent": {
        "id": "007",
        "name": "NGINX-PROXY-01",
        "ip": "10.0.1.15"
    },
    "full_log": "Severity: Critical\nPlugin ID: 298055\nCVE: CVE-2026-33032\nVulnerability: Nginx-Ui (CVE-2026-33032)\nDescription: Remote Code Execution vulnerability in Nginx-UI."
}

print("Sending the specific Nginx-UI CVE-2026-33032 alert requested by the organization...")

try:
    resp = requests.post(WEBHOOK_URL, json=test_alert, timeout=60)
    if resp.status_code == 200:
        print("✅ Alert received successfully by the webhook!")
    else:
        print(f"❌ Error: {resp.status_code} - {resp.text}")
except Exception as e:
    print(f"❌ Connection Error: {e}")
