"""
BlueGuard FinTech Threat Simulator
Generates and sends 100+ highly diverse, FinTech-specific Wazuh alerts
to test the AI's context-aware organizational risk assessment.
"""
import requests
import time
import random
import datetime

WEBHOOK_URL = "http://127.0.0.1:5000/webhook"
DELAY_BETWEEN_ALERTS = 4 # Seconds to wait so OpenRouter API doesn't rate-limit you

AGENTS = [
    {"id": "001", "name": "CORE-BANKING-DB", "ip": "10.0.1.10"},
    {"id": "002", "name": "SWIFT-GATEWAY-01", "ip": "10.0.1.20"},
    {"id": "003", "name": "API-GATEWAY-EXT", "ip": "10.0.2.15"},
    {"id": "004", "name": "PAYMENT-PROC-01", "ip": "10.0.1.30"},
    {"id": "005", "name": "WKS-TRADING-04", "ip": "10.0.5.55"},
    {"id": "006", "name": "HR-FILE-SERVER", "ip": "10.0.4.10"},
]

SCENARIOS = [
    # 1. Insider Threat / Privilege Escalation (Should be caught despite internal controls)
    {
        "level": 12, "groups": ["syslog", "sudo"], "cve": "N/A",
        "desc": "User 't.teller' attempted to run sudo /bin/bash on core banking database.",
        "log": "sudo: t.teller : command not allowed ; PWD=/home/t.teller ; USER=root ; COMMAND=/bin/bash"
    },
    {
        "level": 14, "groups": ["syscheck", "file_integrity"], "cve": "N/A",
        "desc": "File integrity monitoring: Authorized keys modified for root user.",
        "log": "syscheck: File '/root/.ssh/authorized_keys' modified. Size changed. User: unknown."
    },
    # 2. Database & Data Exfiltration Attacks
    {
        "level": 10, "groups": ["database", "sql_injection"], "cve": "CWE-89",
        "desc": "Multiple SQL Injection attempts detected on internal payment API.",
        "log": "ERROR: syntax error at or near \"UNION SELECT\" in query: SELECT * FROM transactions WHERE id = 1 UNION SELECT password FROM users--"
    },
    {
        "level": 8, "groups": ["network", "data_leak"], "cve": "N/A",
        "desc": "Large outbound data transfer detected to unauthorized external IP (Mega.nz).",
        "log": "fw-palo-alto: traffic from 10.0.1.10 to 31.216.144.5 (Mega.nz) port 443 bytes sent: 4.2GB"
    },
    # 3. Ransomware / Malware Indicators
    {
        "level": 13, "groups": ["sysmon", "malware"], "cve": "N/A",
        "desc": "Ransomware indicator: Multiple files renamed with .encrypted extension rapidly.",
        "log": "EventID 11: FileCreate. Image: C:\\Users\\Public\\svchost.exe. TargetFilename: C:\\Finance\\Q3_Report.pdf.encrypted"
    },
    {
        "level": 15, "groups": ["sysmon", "process_creation"], "cve": "N/A",
        "desc": "Suspicious process execution: vssadmin.exe used to delete shadow copies.",
        "log": "EventID 1: Process Creation. CommandLine: vssadmin.exe Delete Shadows /All /Quiet. User: SYSTEM."
    },
    # 4. SWIFT / Payment Gateway Specific
    {
        "level": 14, "groups": ["application", "swift"], "cve": "N/A",
        "desc": "SWIFT Alliance Access: Unauthorized IP attempted to access MT103 messaging queue.",
        "log": "SWIFT-AA: Auth failed for user 'sysadmin' from unauthorized segment 10.0.5.45 on port 1414."
    },
    {
        "level": 12, "groups": ["application", "fraud"], "cve": "N/A",
        "desc": "Payment processing threshold anomaly. 500+ micro-transactions initiated in 60 seconds.",
        "log": "PaymentProc: Rate limit triggered. 542 transactions from MerchantID: 884729 in 1 minute."
    },
    # 5. Vulnerabilities (To test Base vs Org Risk mapping)
    {
        "level": 15, "groups": ["vulnerability", "nessus"], "cve": "CVE-2021-44228",
        "desc": "Nessus: Critical Log4Shell vulnerability detected in internal HR system.",
        "log": "Nessus Plugin 155998: Apache Log4j RCE (CVE-2021-44228). CVSS 10.0. Service listening on port 8080."
    },
    {
        "level": 13, "groups": ["vulnerability", "nessus"], "cve": "CVE-2024-3094",
        "desc": "Nessus: XZ Utils Backdoor vulnerability detected.",
        "log": "Nessus Plugin 192833: XZ Utils Backdoor (CVE-2024-3094). CVSS 10.0."
    },
    # 6. Routine / Low Risk (To test noise filtering)
    {
        "level": 5, "groups": ["windows", "logon_failure"], "cve": "N/A",
        "desc": "Windows logon failure. User 'j.doe' typed wrong password.",
        "log": "EventID 4625: An account failed to log on. Subject: WORKGROUP\\j.doe."
    },
    {
        "level": 3, "groups": ["syslog", "ssh"], "cve": "N/A",
        "desc": "SSH connection closed by preauth.",
        "log": "sshd: Connection closed by 10.0.2.15 port 44322 [preauth]"
    }
]

def generate_alerts(count=100):
    alerts = []
    
    # Generate timestamp starting from 2 hours ago
    base_time = datetime.datetime.now() - datetime.timedelta(hours=2)
    
    for i in range(count):
        agent = random.choice(AGENTS)
        scenario = random.choice(SCENARIOS)
        
        # Advance time by a few minutes for each alert
        alert_time = base_time + datetime.timedelta(minutes=(i * 1.5))
        
        # Add some random variance to the logs to make them unique
        unique_id = random.randint(1000, 99999)
        full_log = scenario["log"] + f" [TraceID: {unique_id}]"
        
        alert = {
            "timestamp": alert_time.strftime("%Y-%m-%dT%H:%M:%S+05:30"),
            "rule": {
                "level": scenario["level"],
                "description": scenario["desc"],
                "id": str(random.randint(100, 9999)),
                "groups": scenario["groups"]
            },
            "agent": agent,
            "full_log": full_log
        }
        alerts.append(alert)
        
    return alerts

def main():
    print("=" * 60)
    print(" 🚀 BlueGuard FinTech Threat Simulator 🚀")
    print("=" * 60)
    print(f"Generating 100 unique FinTech-specific alerts...")
    
    alerts = generate_alerts(100)
    
    print(f"Starting transmission to BlueGuard Webhook ({WEBHOOK_URL})")
    print(f"Warning: A {DELAY_BETWEEN_ALERTS}-second delay is added between alerts to prevent OpenRouter API bans.")
    print("-" * 60)
    
    success = 0
    failed = 0
    
    for i, alert in enumerate(alerts):
        print(f"[{i+1}/100] Sending -> {alert['agent']['name']} | Level: {alert['rule']['level']} | {alert['rule']['groups'][1]}")
        
        try:
            resp = requests.post(WEBHOOK_URL, json=alert, timeout=30)
            if resp.status_code == 200:
                success += 1
            else:
                failed += 1
                print(f"   ❌ Failed: HTTP {resp.status_code}")
        except requests.exceptions.RequestException as e:
            failed += 1
            print(f"   ❌ Connection Error")
            
        # Don't sleep after the very last alert
        if i < len(alerts) - 1:
            time.sleep(DELAY_BETWEEN_ALERTS)
            
    print("=" * 60)
    print(" Simulation Complete!")
    print(f" Successfully Sent: {success}")
    print(f" Failed/Errors: {failed}")
    print(" Check your dashboard at http://127.0.0.1:5000")
    print("=" * 60)

if __name__ == "__main__":
    main()
