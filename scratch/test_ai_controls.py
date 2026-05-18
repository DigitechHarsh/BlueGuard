import sys
import os
import json

# Add parent directory to path to import analyzer
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import analyze_vulnerability

def run_test():
    # Mocking a highly critical vulnerability that would normally be a 10/10/10
    # But because our org controls say "No internet access, Palo Alto FW, etc",
    # the AI should drastically reduce the CIA scores and Org Risk.
    test_vuln = {
        "asset_name": "WIN-SRV-DB-01",
        "vuln_name": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "cve_id": "CVE-2021-44228",
        "nessus_severity": "Critical",
        "vpr_score": "9.9"
    }

    print("=== Sending Mock Vulnerability to AI ===")
    print(f"Target Asset: {test_vuln['asset_name']}")
    print(f"Vulnerability: {test_vuln['vuln_name']} (Nessus: Critical)")
    print("Waiting for AI response...\n")

    result_json_str = analyze_vulnerability(test_vuln)
    
    try:
        result = json.loads(result_json_str)
        print("=== AI ANALYSIS RESULT ===")
        print(f"Org Risk Level: {result.get('org_risk')}")
        print("\nCIA Matrix (Should be reduced due to Internal/FW controls):")
        cia = result.get('cia_matrix', {})
        print(f"  - Confidentiality: {cia.get('confidentiality')}/10")
        print(f"  - Integrity:       {cia.get('integrity')}/10")
        print(f"  - Availability:    {cia.get('availability')}/10")
        
        print("\nSecurity Control Validation:")
        print(f"  {result.get('control_context')}")
        
        print("\nBusiness Impact (Should be 3-4 points):")
        impacts = result.get('business_impact', [])
        if isinstance(impacts, list):
            for i, p in enumerate(impacts, 1):
                print(f"  {i}. {p}")
        else:
            print(f"  [Error: Not a list] {impacts}")

        print("\nRaw JSON Output:")
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        print("Failed to parse AI response as JSON.")
        print(f"Error: {e}")
        print(f"Raw Output:\n{result_json_str}")

if __name__ == '__main__':
    run_test()
