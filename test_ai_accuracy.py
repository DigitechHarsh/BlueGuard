import sys
sys.path.insert(0, '.')
from analyzer import analyze_vulnerability
import json

# Test cases — different vulnerability types
test_vulns = [
    {
        "asset_name": "aaa",
        "vuln_name": "RHEL 8 : kernel (RHSA-2026:2264)",
        "cve_id": "CVE-2022-50673, CVE-2025-38403",
        "nessus_severity": "Medium",
        "vpr_score": "7.3",
        "description": "",
        "synopsis": ""
    },
    {
        "asset_name": "aaa",
        "vuln_name": "RHEL 8 : openssl (RHSA-2026:0337)",
        "cve_id": "CVE-2025-1234",
        "nessus_severity": "High",
        "vpr_score": "7.9",
        "description": "",
        "synopsis": ""
    },
    {
        "asset_name": "aaa",
        "vuln_name": "RHEL 8 : python3 (RHSA-2026:6473)",
        "cve_id": "CVE-2024-11111",
        "nessus_severity": "Low",
        "vpr_score": "2.1",
        "description": "",
        "synopsis": ""
    },
    {
        "asset_name": "aaa",
        "vuln_name": "Apache Log4j 1.2 JMSAppender Remote Code Execution",
        "cve_id": "CVE-2019-17571",
        "nessus_severity": "Medium",
        "vpr_score": "9.8",
        "description": "",
        "synopsis": ""
    },
    {
        "asset_name": "aaa",
        "vuln_name": "RHEL 8 : brotli (RHSA-2026:2389)",
        "cve_id": "CVE-2020-8927",
        "nessus_severity": "High",
        "vpr_score": "3.0",
        "description": "",
        "synopsis": ""
    },
    {
        "asset_name": "aaa",
        "vuln_name": "RHEL 8 : glibc (RHSA-2026:4772)",
        "cve_id": "CVE-2024-33600",
        "nessus_severity": "High",
        "vpr_score": "5.5",
        "description": "",
        "synopsis": ""
    },
    {
        "asset_name": "aaa",
        "vuln_name": "RHEL 8 : nfs-utils (RHSA-2026:3938)",
        "cve_id": "CVE-2024-52336",
        "nessus_severity": "Medium",
        "vpr_score": "4.0",
        "description": "",
        "synopsis": ""
    },
    {
        "asset_name": "aaa",
        "vuln_name": "Oracle Linux 9 : cockpit: / Unauthenticated / remote access",
        "cve_id": "CVE-2024-2947",
        "nessus_severity": "Critical",
        "vpr_score": "9.0",
        "description": "",
        "synopsis": ""
    }
]

print(f"\n{'VULN NAME':<55} | {'NESSUS':<10} | {'ORG_RISK (AI)':<14}")
print("-" * 85)
for v in test_vulns:
    result = json.loads(analyze_vulnerability(v))
    name = v['vuln_name'][:53]
    nessus = v['nessus_severity']
    org = result.get("org_risk", "ERR")
    summary = result.get("summary", "")[:60]
    print(f"{name:<55} | {nessus:<10} | {org:<14}")
    print(f"  -> {summary}")
    print()
