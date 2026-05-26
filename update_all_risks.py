import os, certifi
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
client = MongoClient(os.getenv('MONGO_URI'), tlsCAFile=certifi.where())
db = client.blueguard_db

def calc_org_risk(v_name, desc, n_sev):
    text = (v_name + " " + desc).lower()
    b_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    base = b_map.get(n_sev, 1)
    
    # Mitigation: Network is internal-only, behind Palo Alto firewall.
    if any(x in text for x in ["remote code execution", "rce", "unauthenticated", "remote", "external"]):
        base -= 2 
    if any(x in text for x in ["xss", "cross-site scripting", "sql injection", "sqli"]):
        base -= 1
        
    # Escalation: Insider threats, bypasses, or local privilege escalation.
    if any(x in text for x in ["privilege escalation", "local", "credential", "root", "admin", "bypass", "kernel"]):
        base += 1 
        
    # Absolute Escalation: Destructive malware / ransomware
    if any(x in text for x in ["ransomware", "wannacry", "malware", "lockbit", "encrypt"]):
        base = 4  # Always critical
        
    base = max(1, min(base, 4))
    r_map = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}
    return r_map[base]

vulns = list(db.vulnerabilities.find({}))
updated_count = 0
for v in vulns:
    v_name = v.get("vuln_name", "")
    desc = v.get("description", "")
    sev = v.get("nessus_severity", "Low")
    
    new_org_risk = calc_org_risk(v_name, desc, sev)
    
    if v.get("org_risk") != new_org_risk:
        db.vulnerabilities.update_one({"_id": v["_id"]}, {"$set": {"org_risk": new_org_risk}})
        updated_count += 1

print(f"Successfully updated {updated_count} vulnerabilities with new org_risk logic.")
