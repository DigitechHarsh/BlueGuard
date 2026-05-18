import sys
import os
import json

# Add parent directory to path to import analyzer
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import classify_attack

def run_test():
    # Mocking a realistic Wazuh alert for a critical attack (e.g., Ransomware/WannaCry)
    mock_alert = {
        "rule": {
            "description": "Potential Ransomware activity detected. High number of file modifications (WannaCry indicator)",
            "level": 12,
            "groups": ["ransomware", "malware", "syscheck"]
        },
        "agent": {
            "name": "WIN-SRV-PROD-02"
        },
        "full_log": "File integrity checksum changed for C:\\Windows\\System32\\tasksche.exe. Extension changed to .wncry"
    }

    print("=== Testing AI Analysis Log Generation (classify_attack) ===")
    print(f"Alert Description: {mock_alert['rule']['description']}")
    print("Waiting for AI response...\n")

    result_json_str = classify_attack(mock_alert)
    
    try:
        result = json.loads(result_json_str)
        print("=== AI ANALYSIS OUTPUT ===")
        print(f"Threat Actor:         {result.get('threat_actor')}")
        print(f"Attack Vector:        {result.get('attack_vector')}")
        print(f"MITRE Technique:      {result.get('mitre_technique_id')} - {result.get('mitre_technique_name')}")
        print(f"CVE ID(s):            {result.get('cve_id')}")
        print(f"CWE ID(s):            {result.get('cwe_id')}")
        print(f"CVSS Score:           {result.get('cvss_score')}")
        print(f"Risk Severity:        {result.get('risk_severity')}")
        print(f"Forensic Summary:     {result.get('forensic_summary')}")
        print(f"Org Impact:           {result.get('org_impact')}")
        
        print("\nRemediation Steps:")
        steps = result.get('remediation_steps', '')
        if isinstance(steps, str):
            for i, step in enumerate(steps.split('\\n'), 1):
                if step.strip(): print(f"  {i}. {step.strip()}")
        elif isinstance(steps, list):
            for i, step in enumerate(steps, 1):
                print(f"  {i}. {step}")

        print("\nReasoning:")
        print(f"  {result.get('reasoning')}")
        
    except Exception as e:
        print("Failed to parse AI response as JSON.")
        print(f"Error: {e}")
        print(f"Raw Output:\n{result_json_str}")

if __name__ == '__main__':
    run_test()
