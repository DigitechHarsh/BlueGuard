"""
BlueGuard Test Alert Sender
Sends realistic Wazuh-style alerts to the /webhook endpoint.
These alerts are designed to show how org security controls mitigate base risk.
"""
import requests
import json
import time

WEBHOOK_URL = "http://127.0.0.1:5000/webhook"

# Test alerts designed to show Base vs Org Risk differences
test_alerts = [
    {
        "name": "🔴 SSH Brute Force (External Attack Vector)",
        "payload": {
            "timestamp": "2026-04-22T11:30:00+05:30",
            "rule": {
                "level": 10,
                "description": "Multiple authentication failures from external IP. sshd: Authentication failure for root from 185.220.101.45 port 22",
                "id": "5763",
                "groups": ["syslog", "sshd", "authentication_failures"]
            },
            "agent": {
                "id": "003",
                "name": "PROD-WEB-01",
                "ip": "10.0.1.50"
            },
            "data": {
                "srcip": "185.220.101.45"
            },
            "full_log": "Apr 22 11:30:00 PROD-WEB-01 sshd[4521]: Failed password for root from 185.220.101.45 port 22 ssh2 - 47 failed attempts in last 5 minutes"
        }
    },
    {
        "name": "🟠 Nginx-UI RCE Vulnerability (CVE-2026-33032)",
        "payload": {
            "timestamp": "2026-04-22T11:31:00+05:30",
            "rule": {
                "level": 13,
                "description": "Nessus Vulnerability Scanner: Critical vulnerability detected - Nginx-Ui Remote Code Execution (CVE-2026-33032). CVSS 9.8. Plugin ID 298055.",
                "id": "87924",
                "groups": ["vulnerability-detector", "nessus"]
            },
            "agent": {
                "id": "007",
                "name": "NGINX-PROXY-01",
                "ip": "10.0.1.15"
            },
            "full_log": "Nessus Plugin 298055: Nginx-Ui CVE-2026-33032 - Remote Code Execution via crafted HTTP request to /api/config endpoint. CVSS Base Score: 9.8 Critical. Requires network access to the Nginx-UI management interface."
        }
    },
    {
        "name": "🟡 File Integrity Change (Suspicious Binary Modified)",
        "payload": {
            "timestamp": "2026-04-22T11:32:00+05:30",
            "rule": {
                "level": 7,
                "description": "File integrity monitoring: File '/etc/passwd' was modified. syscheck alert.",
                "id": "550",
                "groups": ["ossec", "syscheck", "file_integrity_monitoring"]
            },
            "agent": {
                "id": "005",
                "name": "DB-SERVER-02",
                "ip": "10.0.2.30"
            },
            "full_log": "syscheck: File '/etc/passwd' modified. Size changed from 2451 to 2523. MD5 hash changed. User: root. Modification time: 2026-04-22T11:31:45"
        }
    },
    {
        "name": "🔴 Privilege Escalation Attempt (Kernel Exploit)",
        "payload": {
            "timestamp": "2026-04-22T11:33:00+05:30",
            "rule": {
                "level": 14,
                "description": "Attempted privilege escalation detected. User 'jsmith' executed sudo command to gain root shell access. Special privileges assigned to new logon.",
                "id": "5401",
                "groups": ["syslog", "sudo", "authentication_success"]
            },
            "agent": {
                "id": "009",
                "name": "APP-SERVER-03",
                "ip": "10.0.3.10"
            },
            "full_log": "Apr 22 11:33:00 APP-SERVER-03 sudo: jsmith : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash - privilege escalation attempt via sudo abuse"
        }
    },
    {
        "name": "🟢 Windows Logon Failure (Internal Workstation)",
        "payload": {
            "timestamp": "2026-04-22T11:34:00+05:30",
            "rule": {
                "level": 5,
                "description": "Windows logon failure. Multiple authentication failures detected for user 'admin' on internal workstation.",
                "id": "60122",
                "groups": ["windows", "authentication_failure"]
            },
            "agent": {
                "id": "012",
                "name": "WKS-FINANCE-04",
                "ip": "10.0.5.45"
            },
            "data": {
                "win": {
                    "system": {
                        "ipAddress": "10.0.5.100"
                    }
                }
            },
            "full_log": "EventID 4625: An account failed to log on. Subject: WORKGROUP\\admin. Failure Reason: Unknown user name or bad password. Source Network Address: 10.0.5.100. Logon Type: 3"
        }
    }
]

print("=" * 60)
print("  BlueGuard - Sending Test Alerts with Org Risk Context")
print("=" * 60)

for i, test in enumerate(test_alerts):
    print(f"\n[{i+1}/{len(test_alerts)}] Sending: {test['name']}")
    print(f"  Agent: {test['payload']['agent']['name']} ({test['payload']['agent']['ip']})")
    print(f"  Rule: {test['payload']['rule']['description'][:80]}...")
    
    try:
        resp = requests.post(WEBHOOK_URL, json=test['payload'], timeout=60)
        if resp.status_code == 200:
            print(f"  ✅ Alert received successfully!")
        else:
            print(f"  ❌ Error: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"  ❌ Connection Error: {e}")
    
    # Wait between alerts to not overwhelm the AI API
    if i < len(test_alerts) - 1:
        print("  ⏳ Waiting 5 seconds before next alert...")
        time.sleep(5)

print("\n" + "=" * 60)
print("  ✅ All test alerts sent! Check http://127.0.0.1:5000")
print("  Look for Base Risk vs Org Risk differences.")
print("=" * 60)
