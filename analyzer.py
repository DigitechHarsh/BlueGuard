import os
import json
import re
from openai import OpenAI
from dotenv import load_dotenv
import pymongo

# Load environment variables
load_dotenv()

# Configure OpenAI client for OpenRouter
client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key=os.getenv("OPENROUTER_API_KEY"),
  timeout=15.0
)

MODELS_TO_TRY = [
    "google/gemini-2.5-flash",
    "google/gemini-2.5-flash-lite",
    "google/gemma-4-31b-it:free",
    "google/gemma-4-26b-a4b-it:free",
    "nvidia/nemotron-nano-9b-v2:free",
    "openrouter/free"
]

import certifi
ca = certifi.where()

# ─── Local CVE Intelligence DB ───────────────────────────────────────────────
try:
    _mongo = pymongo.MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"), 
                                 serverSelectionTimeoutMS=10000,
                                 tlsCAFile=ca)
    _cve_col = _mongo.blueguard_db.cve_intelligence
    _cve_col.count_documents({})   # ping
    CVE_DB_AVAILABLE = True
    _db_label = "Atlas (cloud)" if "mongodb+srv" in os.getenv("MONGO_URI", "") else "Local"
    print(f"[CVE-DB] ✅ NVD intelligence DB connected ({_db_label}).")
except Exception:
    CVE_DB_AVAILABLE = False
    print("[CVE-DB] Local CVE DB not available — AI-only mode active.")


# ─── NVD Multi-CVE Intelligence Lookup ──────────────────────────────────────

# Keyword → NVD search terms mapping
KEYWORD_MAP = {
    "log4j":          ["log4j"],
    "log4shell":      ["log4j", "jndi"],
    "eternalblue":    ["eternalblue", "ms17-010"],
    "wannacry":       ["wannacry", "ms17-010"],
    "printnightmare": ["print spooler", "windows print"],
    "spring4shell":   ["spring framework", "classloader"],
    "moveit":         ["moveit transfer"],
    "citrix":         ["citrix", "netscaler"],
    "zerologon":      ["netlogon", "zerologon"],
    "proxylogon":     ["exchange server", "proxylogon"],
    "ivanti":         ["ivanti", "pulse connect"],
    "fortinet":       ["fortios", "fortigate"],
    "paloalto":       ["pan-os", "globalprotect"],
    "pan-os":         ["pan-os"],
    "struts":         ["apache struts"],
    "mimikatz":       ["lsass", "credential dump"],
    "swift":          ["swift", "financial messaging"],
    "hsm":            ["hardware security module"],
    "rtgs":           ["rtgs", "payment system"],
    "sql injection":  ["sql injection"],
    "xss":            ["cross-site scripting"],
    "traversal":      ["path traversal", "directory traversal"],
    "brute force":    ["authentication", "brute force"],
    "dns tunnel":     ["dns tunnel"],
    "ransomware":     ["ransomware"],
    "lockbit":        ["lockbit", "ransomware"],
    "ebpf":           ["ebpf", "linux kernel"],
    "syscheck":       ["file integrity"],
    "c2":             ["command and control"],
    "idor":           ["insecure direct object"],
    "otp":            ["authentication bypass"],
}


def _cvss_to_severity(score: float) -> str:
    """Convert CVSS score to severity label."""
    if score >= 9.0:   return "Critical"
    elif score >= 7.0: return "High"
    elif score >= 4.0: return "Medium"
    elif score > 0.0:  return "Low"
    return "Unknown"


def _save_ai_cve_to_db(cve_id: str, cwe_ids: list, cvss_score: float,
                        description: str, alert_desc: str):
    """
    🧠 AUTO-LEARNING: Save AI-discovered CVE back to local DB.
    Creates a feedback loop — DB grows smarter with every alert.
    Only saves if CVE not already in DB.
    """
    if not CVE_DB_AVAILABLE or not cve_id:
        return
    try:
        # Check if already exists
        if _cve_col.find_one({"cve_id": cve_id.upper()}):
            return

        severity = _cvss_to_severity(cvss_score)
        doc = {
            "cve_id":         cve_id.upper(),
            "description":    description or alert_desc[:300],
            "cvss_score":     round(float(cvss_score), 1),
            "cvss_vector":    "",
            "severity":       severity,
            "cwe_ids":        [c.strip() for c in cwe_ids if c.strip()],
            "published_date": "",
            "last_modified":  "",
            "fetched_at":     __import__("datetime").datetime.utcnow(),
            "source":         "ai_learned"   # distinguish from NVD-fetched
        }
        _cve_col.insert_one(doc)
        print(f"[AI-LEARN] 🧠 Saved new CVE to DB: {cve_id} (CVSS {cvss_score}) — DB is growing!")
    except Exception as e:
        print(f"[AI-LEARN] Could not save: {e}")


def lookup_nvd_intelligence(description: str) -> dict:
    """
    Multi-CVE NVD lookup.
    Returns aggregated intelligence dict:
      {
        'found': True/False,
        'cve_ids': 'CVE-2021-44228, CVE-2021-45046',
        'cwe_ids': 'CWE-502, CWE-917',
        'avg_cvss': 9.5,
        'max_cvss': 10.0,
        'severity': 'Critical',
        'nvd_descriptions': ['...', '...'],
        'matched_count': 2
      }
    """
    if not CVE_DB_AVAILABLE:
        return {"found": False}

    desc_lower = description.lower()
    matches = []   # list of CVE records from DB

    # ── 1. Direct CVE ID match (highest priority) ─────────────────────────────
    direct_ids = re.findall(r"CVE-\d{4}-\d{4,7}", description, re.IGNORECASE)
    if direct_ids:
        for cid in direct_ids[:5]:   # max 5 direct
            rec = _cve_col.find_one({"cve_id": cid.upper()})
            if rec and rec not in matches:
                matches.append(rec)

    # ── 2. Keyword-based multi-fetch ──────────────────────────────────────────
    search_terms = []
    for trigger, terms in KEYWORD_MAP.items():
        if trigger in desc_lower:
            search_terms.extend(terms)

    if search_terms:
        pattern = "|".join(set(search_terms))
        keyword_results = list(
            _cve_col.find(
                {"description": {"$regex": pattern, "$options": "i"}},
                sort=[("cvss_score", pymongo.DESCENDING)],
                limit=5
            )
        )
        for rec in keyword_results:
            # Avoid duplicates
            if not any(m["cve_id"] == rec["cve_id"] for m in matches):
                matches.append(rec)

    if not matches:
        return {"found": False}

    # ── 3. Aggregate all matched CVEs ─────────────────────────────────────────
    cve_ids_list  = [m["cve_id"] for m in matches]
    cwe_ids_set   = set()
    cvss_scores   = []
    nvd_descs     = []

    for m in matches:
        # CWE IDs — only add if present and non-empty
        for cw in m.get("cwe_ids", []):
            if cw and cw.strip():
                cwe_ids_set.add(cw.strip())
        # CVSS
        score = m.get("cvss_score", 0.0)
        if isinstance(score, (int, float)) and score > 0:
            cvss_scores.append(float(score))
        # Description snippet
        d = m.get("description", "")[:120]
        if d:
            nvd_descs.append(f"{m['cve_id']}: {d}")

    avg_cvss = round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else 0.0
    max_cvss = max(cvss_scores) if cvss_scores else 0.0
    severity = _cvss_to_severity(avg_cvss)

    result = {
        "found":          True,
        "cve_ids":        ", ".join(cve_ids_list),
        "cwe_ids":        ", ".join(sorted(cwe_ids_set)),   # empty string if none
        "avg_cvss":       avg_cvss,
        "max_cvss":       max_cvss,
        "severity":       severity,
        "nvd_descriptions": nvd_descs[:3],                  # max 3 snippets
        "matched_count":  len(matches)
    }

    print(f"[NVD] ✅ {len(matches)} CVE(s) matched | IDs: {result['cve_ids']} | Avg CVSS: {avg_cvss} | Severity: {severity}")
    return result

# ========================================================================
# Organization Security Controls (Hardcoded for Infrastructure Context)
# ========================================================================
ORG_SECURITY_CONTROLS = """
The following existing security controls are deployed in the organization's infrastructure.
You MUST factor these into your risk assessment to determine the ACTUAL organizational risk:

1. Servers are NOT exposed to the internet and are accessible ONLY within the internal network (no external SSH access, even with valid credentials).
2. A perimeter Palo Alto Networks firewall is in place with Threat Prevention and Anti-Spyware profiles enabled.
3. Wazuh agents are deployed on ALL servers for real-time log monitoring, including command execution tracking and alerting on suspicious activities.
4. End users do NOT have administrative/root privileges, and data exfiltration outside the internal network is restricted.
5. The organization manages 180+ assets monitored by these controls.
"""

def classify_attack(alert):
    """
    NVD-first attack classification.
    1. Fetches ALL matching CVEs from local NVD database.
    2. Aggregates CVE IDs, CWE IDs, average CVSS.
    3. AI focuses ONLY on org-risk, MITRE, threat actor, remediation.
    """
    description = alert.get('rule', {}).get('description', '')
    agent_name  = alert.get('agent', {}).get('name', 'Unknown')
    rule_level  = alert.get('rule', {}).get('level', 'Unknown')
    rule_groups = alert.get('rule', {}).get('groups', [])
    full_log    = alert.get('full_log', '')

    # ── NVD Multi-CVE Lookup ──────────────────────────────────────────────────
    nvd = lookup_nvd_intelligence(description)

    # Basic fallback if no description
    if not description:
        return json.dumps({
            "threat_actor":        "Unknown",
            "attack_vector":       "Unknown",
            "mitre_technique_id":  "N/A",
            "mitre_technique_name":"N/A",
            "cve_id":              "",
            "cwe_id":              "",
            "cvss_score":          "0.0",
            "cwss_score":          "0.0",
            "risk_severity":       "Low",
            "remediation_steps":   "No data.",
            "forensic_summary":    "No description provided.",
            "org_impact":          "Unknown",
            "reasoning":           "Empty alert."
        })

    # ── Build NVD Intelligence block for prompt ───────────────────────────────
    if nvd["found"]:
        cwe_line = f"CWE IDs:       {nvd['cwe_ids']}" if nvd["cwe_ids"] else "CWE IDs:       (none recorded in NVD for these CVEs)"
        nvd_desc_block = "\n    ".join(nvd["nvd_descriptions"])
        cve_context = f"""
    ╔══════════════════════════════════════════════════════╗
    ║  ⚡ NVD INTELLIGENCE — {nvd['matched_count']} CVE(s) MATCHED           ║
    ╚══════════════════════════════════════════════════════╝
    CVE IDs:       {nvd['cve_ids']}
    {cwe_line}
    Avg CVSS:      {nvd['avg_cvss']}  |  Max CVSS: {nvd['max_cvss']}
    NVD Severity:  {nvd['severity']}
    NVD Summaries:
    {nvd_desc_block}

    ▶ USE THESE EXACT CVE/CWE VALUES. Do NOT invent new ones.
    ▶ Base your risk_severity on the avg CVSS: {nvd['avg_cvss']}
    """
        nvd_found = True
    else:
        cve_context = ""
        nvd_found = False
        print(f"[NVD] No DB match — AI will infer CVE from description")

    # ── Build prompt ─────────────────────────────────────────────────────────
    if nvd_found:
        # NVD-FIRST prompt: AI focuses on org analysis, NOT CVE hunting
        prompt = f"""
    You are a Senior SOC Analyst performing organizational risk assessment.

    ALERT:
    Description : {description}
    Agent       : {agent_name}
    Rule Level  : {rule_level}
    Groups      : {', '.join(rule_groups) if rule_groups else 'N/A'}
    Log Snippet : {full_log[:300] if full_log else 'N/A'}

    {ORG_SECURITY_CONTROLS}

    {cve_context}

    YOUR TASK:
    The CVE/CWE/CVSS data above is from NIST NVD — treat it as GROUND TRUTH.
    Do NOT change or invent CVE/CWE values.
    Focus on:
    1. Threat actor classification for this FinTech org
    2. MITRE ATT&CK technique mapping
    3. Organizational risk level given our security controls
    4. Concise remediation steps (max 5 words each)
    5. Forensic summary (1 line)
    6. Org impact assessment

    Respond with ONLY this JSON:
    {{
      "threat_actor":         "...",
      "attack_vector":        "...",
      "mitre_technique_id":   "T1xxx",
      "mitre_technique_name": "...",
      "cve_id":               "{nvd['cve_ids']}",
      "cwe_id":               "{nvd['cwe_ids']}",
      "cvss_score":           "{nvd['avg_cvss']}",
      "cwss_score":           "...",
      "risk_severity":        "Critical|High|Medium|Low",
      "remediation_steps":    "step1\\nstep2\\nstep3",
      "forensic_summary":     "...",
      "org_impact":           "...",
      "reasoning":            "..."
    }}
    """
    else:
        # FALLBACK prompt: AI must infer everything
        prompt = f"""
    You are an elite Threat Intelligence Researcher.
    Analyze this Wazuh security alert and identify real vulnerability identifiers.

    ALERT:
    Description : {description}
    Agent       : {agent_name}
    Rule Level  : {rule_level}
    Groups      : {', '.join(rule_groups) if rule_groups else 'N/A'}
    Log Snippet : {full_log[:300] if full_log else 'N/A'}

    {ORG_SECURITY_CONTROLS}

    KNOWLEDGE BASE — match attack to these known CVEs:
    - SSH brute force / credential stuffing  → CVE-2022-36946, CWE-307
    - Log4Shell / JNDI injection            → CVE-2021-44228, CVE-2021-45046, CWE-502
    - EternalBlue / SMB exploit             → CVE-2017-0144, CVE-2017-0145, CWE-119
    - WannaCry ransomware                   → CVE-2017-0144, CWE-119
    - PrintNightmare                        → CVE-2021-34527, CWE-427
    - Spring4Shell                          → CVE-2022-22965, CWE-94
    - MOVEit Transfer                       → CVE-2023-34362, CWE-89
    - Citrix Bleed                          → CVE-2023-4966, CWE-125
    - ProxyLogon Exchange                   → CVE-2021-26855, CWE-918
    - ZeroLogon Netlogon                    → CVE-2020-1472, CWE-287
    - Ivanti / Pulse Connect                → CVE-2024-21887, CVE-2023-46805, CWE-918
    - Fortinet FortiOS bypass               → CVE-2024-55591, CWE-287
    - PAN-OS GlobalProtect RCE              → CVE-2024-3400, CWE-77
    - Apache Struts RCE                     → CVE-2023-50164, CWE-434
    - SQL Injection                         → CVE-2023-28432, CWE-89
    - Cross-site scripting XSS              → CVE-2023-29489, CWE-79
    - Directory/path traversal              → CVE-2021-41773, CWE-22
    - LSASS / Mimikatz credential dump      → CVE-2021-36934, CWE-522
    - LockBit / ransomware encryption       → CVE-2023-44487, CWE-400
    - SWIFT financial messaging fraud       → CVE-2022-26134, CWE-284
    - HSM hardware security module attack   → CVE-2019-14821, CWE-284
    - Linux kernel eBPF exploit             → CVE-2025-21756, CWE-416
    - DNS tunneling / C2 exfiltration       → CVE-2021-25220, CWE-200
    - File integrity / syscheck violation   → CVE-2023-32629, CWE-732
    - IDOR API enumeration                  → CVE-2023-29489, CWE-639
    - OTP / authentication bypass           → CVE-2022-36946, CWE-287
    - TLS downgrade attack                  → CVE-2021-3449, CWE-326
    - Port scan reconnaissance              → CVE-2021-25220, CWE-200

    MANDATORY RULES:
    1. You MUST provide real CVE IDs — use the knowledge base or your training data
    2. List ALL matching CVEs comma-separated
    3. CWE can be empty string ONLY if truly no CWE mapping exists
    4. NEVER leave cve_id as empty string — always pick the best-matching CVE
    5. Estimate CVSS based on attack severity

    Respond with ONLY valid JSON (no markdown, no extra text):
    {{
      "threat_actor":         "e.g. APT Group, Ransomware Operator",
      "attack_vector":        "technical method used",
      "mitre_technique_id":   "T1078",
      "mitre_technique_name": "Valid Accounts",
      "cve_id":               "CVE-2021-44228, CVE-2021-45046",
      "cwe_id":               "CWE-502, CWE-917",
      "cvss_score":           "9.8",
      "cwss_score":           "92.0",
      "risk_severity":        "Critical",
      "remediation_steps":    "Patch immediately\\nBlock outbound JNDI\\nUpdate WAF rules",
      "forensic_summary":     "One-line technical summary",
      "org_impact":           "Impact on FinTech org assets",
      "reasoning":            "Why this CVE was chosen"
    }}
    """

    try:
        response = client.chat.completions.create(
            model="google/gemini-2.0-flash-001",
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=600,
            response_format={ "type": "json_object" }
        )
        
        result_text = response.choices[0].message.content
        
        if result_text.startswith("```json"):
            result_text = result_text.replace("```json", "").replace("```", "").strip()
        elif result_text.startswith("```"):
            result_text = result_text.replace("```", "").strip()

        try:
            result = json.loads(result_text)
            # Ensure all required keys exist
            required_keys = ["threat_actor", "attack_vector", "mitre_technique_id",
                           "mitre_technique_name", "cve_id", "cwe_id",
                           "cvss_score", "cwss_score", "risk_severity",
                           "remediation_steps", "forensic_summary", "org_impact", "reasoning"]
            for key in required_keys:
                if key not in result:
                    result[key] = ""

            # ── 🗺️ MITRE FALLBACK MAPPING ────────────────────────────────────────
            # If AI did not provide a valid MITRE ID, derive it from description
            mitre_id   = str(result.get("mitre_technique_id", "")).strip()
            mitre_name = str(result.get("mitre_technique_name", "")).strip()

            if not mitre_id or mitre_id in ["N/A", "T1xxx", "", "null"]:
                combined = (description + " " + str(result.get("attack_vector",""))).lower()
                # Ordered from most-specific to most-generic
                MITRE_MAP = [
                    (["log4j","log4shell","jndi"],            "T1190", "Exploit Public-Facing Application"),
                    (["wannacry","eternalblue","ms17-010","smb exploit"], "T1210", "Exploitation of Remote Services"),
                    (["ransomware","encrypt","lockbit","clop","ryuk"],    "T1486", "Data Encrypted for Impact"),
                    (["mimikatz","lsass","credential dump","sam dump"],   "T1003", "OS Credential Dumping"),
                    (["zerologon","netlogon","privilege escalation","privesc"], "T1068", "Exploitation for Privilege Escalation"),
                    (["proxylogon","exchange","webshell"],    "T1505.003", "Server Software Component: Web Shell"),
                    (["sql injection","sqli"],                "T1190",   "Exploit Public-Facing Application"),
                    (["xss","cross-site scripting"],          "T1059.007","Command and Scripting: JavaScript"),
                    (["path traversal","directory traversal","lfi"],      "T1083", "File and Directory Discovery"),
                    (["brute force","password spray","credential stuff"], "T1110", "Brute Force"),
                    (["swift","rtgs","financial fraud","payment"],        "T1657", "Financial Theft"),
                    (["hsm","hardware security","vault","key theft"],     "T1552.004","Unsecured Credentials: Private Keys"),
                    (["dns tunnel","dnscat","iodine"],        "T1071.004","Application Layer Protocol: DNS"),
                    (["c2","command and control","beacon","cobalt strike"],"T1071.001","Application Layer Protocol: Web Protocols"),
                    (["moveit","file transfer","sftp exploit"],"T1190",  "Exploit Public-Facing Application"),
                    (["fortinet","fortigate","vpn bypass"],   "T1133",   "External Remote Services"),
                    (["citrix","netscaler","bleed"],          "T1190",   "Exploit Public-Facing Application"),
                    (["ivanti","pulse"],                      "T1190",   "Exploit Public-Facing Application"),
                    (["pan-os","palo alto","globalprotect"],  "T1190",   "Exploit Public-Facing Application"),
                    (["struts","rce","remote code"],          "T1059",   "Command and Scripting Interpreter"),
                    (["ebpf","kernel exploit","linux kernel"],"T1068",   "Exploitation for Privilege Escalation"),
                    (["port scan","nmap","recon","enumerat"], "T1046",   "Network Service Discovery"),
                    (["idor","insecure direct object"],       "T1078",   "Valid Accounts"),
                    (["otp bypass","auth bypass","mfa bypass"],"T1556",  "Modify Authentication Process"),
                    (["ssh","bastion","remote login"],        "T1021.004","Remote Services: SSH"),
                    (["syscheck","file integrity","fim"],     "T1565.001","Data Manipulation: Stored Data Manipulation"),
                    (["tls","ssl","downgrade","mitm"],        "T1557",   "Adversary-in-the-Middle"),
                    (["data exfil","exfiltration","upload"],  "T1041",   "Exfiltration Over C2 Channel"),
                    (["insider","malicious user","rogue"],    "T1078",   "Valid Accounts"),
                    (["phishing","spear phish"],              "T1566",   "Phishing"),
                ]
                for keywords, tid, tname in MITRE_MAP:
                    if any(k in combined for k in keywords):
                        result["mitre_technique_id"]   = tid
                        result["mitre_technique_name"] = tname
                        break
                else:
                    # Generic fallback
                    result["mitre_technique_id"]   = "T1059"
                    result["mitre_technique_name"] = "Command and Scripting Interpreter"

            # --- SEVERITY SAFETY OVERRIDE & CVSS SYNC ---
            desc_lower = description.lower()
            atk_lower = str(result.get("attack_vector", "")).lower()
            
            # 1. Check for Critical Threats
            if any(x in desc_lower or x in atk_lower for x in ["wannacry", "ransomware", "encrypt", "malware", "lockbit", "swift", "rtgs", "hsm"]):
                result["risk_severity"] = "Critical"
                result["cvss_score"] = "9.8"
            
            # 2. Check for Admin/Root activity (High Priority)
            elif any(x in desc_lower or x in atk_lower for x in ["root", "privilege escalation", "admin", "zerologon", "proxylogon"]):
                # Do NOT escalate if it's just a failed login or brute force attempt
                if not any(f in desc_lower for f in ["fail", "failed", "failure", "brute force"]):
                    if result.get("risk_severity") not in ["Critical", "High"]:
                        result["risk_severity"] = "High"
                        result["cvss_score"] = "7.5"
            
            # 3. Final Range Validation (Ensure CVSS matches the final Severity string)
            final_sev = result.get("risk_severity", "Low")
            try:
                current_cvss = float(result.get("cvss_score", 0))
            except:
                current_cvss = 0

            if final_sev == "Critical":
                if current_cvss < 9.0: result["cvss_score"] = "9.5"
                try:
                    if float(result.get("cwss_score", 0)) < 90.0: result["cwss_score"] = "95.0"
                except: result["cwss_score"] = "95.0"
            elif final_sev == "High":
                if current_cvss < 7.0 or current_cvss >= 9.0: result["cvss_score"] = "8.2"
                try:
                    val = float(result.get("cwss_score", 0))
                    if val < 70.0 or val >= 90.0: result["cwss_score"] = "82.5"
                except: result["cwss_score"] = "82.5"
            elif final_sev == "Medium":
                if current_cvss < 4.0 or current_cvss >= 7.0: result["cvss_score"] = "5.5"
                try:
                    val = float(result.get("cwss_score", 0))
                    if val < 40.0 or val >= 70.0: result["cwss_score"] = "58.0"
                except: result["cwss_score"] = "58.0"
            elif final_sev == "Low":
                if current_cvss < 0.1 or current_cvss >= 4.0: result["cvss_score"] = "3.2"
                try:
                    val = float(result.get("cwss_score", 0))
                    if val < 10.0 or val >= 40.0: result["cwss_score"] = "25.0"
                except: result["cwss_score"] = "25.0"
            elif final_sev == "None":
                result["cvss_score"] = "0.0"
                result["cwss_score"] = "5.0"

            # Ensure risk_severity is always set
            if not result.get("risk_severity") or result["risk_severity"] == "N/A":
                result["risk_severity"] = "Medium"

            # —— 🧠 AUTO-LEARNING: Save AI-provided CVEs to DB (fallback path only) ——
            if not nvd_found:
                ai_cve_str = result.get("cve_id", "")
                ai_cwe_str = result.get("cwe_id", "")
                ai_cvss    = 0.0
                try: ai_cvss = float(result.get("cvss_score", 0))
                except: pass

                if ai_cve_str and ai_cve_str.strip():
                    cwe_list = [c.strip() for c in ai_cwe_str.split(",") if c.strip()]
                    for cid in ai_cve_str.split(","):
                        cid = cid.strip()
                        if re.match(r"CVE-\d{4}-\d{4,7}", cid, re.IGNORECASE):
                            _save_ai_cve_to_db(
                                cve_id=cid,
                                cwe_ids=cwe_list,
                                cvss_score=ai_cvss,
                                description=result.get("forensic_summary", ""),
                                alert_desc=description
                            )

            return json.dumps(result)
        except json.JSONDecodeError as decode_error:
            print(f"JSON Parsing Error. Raw AI Response:\n{result_text}")
            raise decode_error

    except Exception as e:
        print(f"Error calling Gemini: {e}")
        return json.dumps({"risk_severity": "Medium", "forensic_summary": "Analysis failed."})

def analyze_vulnerability(vuln_data):
    """
    🧠 HIGH-PRECISION ANALYSIS — CVE-Aware, Context-Aware
    Analyzes a Nessus vulnerability for organizational risk.
    """
    asset_name      = vuln_data.get('asset_name', 'Unknown')
    vuln_name       = vuln_data.get('vuln_name', 'Unknown')
    cve_id          = vuln_data.get('cve_id', 'N/A')
    nessus_severity = vuln_data.get('nessus_severity', 'Low')
    vpr_score       = vuln_data.get('vpr_score', '0.0')
    plugin_id       = vuln_data.get('plugin_id', 'N/A')
    description     = vuln_data.get('description', '').strip()
    synopsis        = vuln_data.get('synopsis', '').strip()

    vuln_context = description or synopsis or "NOT PROVIDED — use your training knowledge about the CVE IDs and vulnerability name above."

    prompt = f"""
You are a cybersecurity analyst. Analyze the following Nessus vulnerability finding:

=== VULNERABILITY DETAILS ===
Asset Name: {asset_name}
Vulnerability Name: {vuln_name}
CVE ID(s): {cve_id}
Nessus Severity: {nessus_severity}
VPR Score: {vpr_score}
Plugin ID: {plugin_id}
Description: {vuln_context}

=== EXISTING SECURITY CONTROLS ===
1. Servers are not exposed to the internet and are accessible only within the internal network (no external SSH access, even with valid credentials).
2. A perimeter Palo Alto Networks firewall is in place with Threat Prevention and Anti-Spyware profiles enabled.
3. Wazuh EDR agents are deployed on all servers for real-time log monitoring, including command execution tracking and alerting on suspicious activities.
4. End users do not have administrative/root privileges, and data exfiltration outside the internal network is restricted.

=== YOUR TASK ===
Provide a detailed assessment covering:
- Real-world exploitability (beyond CVSS score; consider practical attack feasibility).
- Possible attack paths within the given environment.
- Potential business impact if exploited.
- Likelihood of false positives.
- Recommended remediation priority (with justification).

=== OUTPUT FORMAT ===
You MUST return ONLY a JSON object with this exact structure (no markdown fences, no conversational text outside the JSON):
{{
    "org_risk": "Critical|High|Medium|Low",
    "cia_matrix": {{
        "confidentiality": "0-10",
        "integrity": "0-10",
        "availability": "0-10"
    }},
    "business_impact": [
        "Business impact detailing financial or operational loss..."
    ],
    "control_context": "Real-world exploitability and attack paths considering internal network, Palo Alto firewalls, and EDR controls.",
    "remediation_steps": [
        "Remediation step...",
        "Remediation justification with priority details..."
    ],
    "summary": "Brief summary of practical attack feasibility, asset criticality, and likelihood of false positives."
}}
"""

    last_error = None
    for model in MODELS_TO_TRY:
        try:
            print(f"[AI-BIA] Analyzing: {vuln_name} | CVE: {cve_id} using model: {model}")
            
            response = None
            supports_json_mode = "gemma" not in model.lower()
            
            if supports_json_mode:
                try:
                    response = client.chat.completions.create(
                        model=model,
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.1,
                        max_tokens=1000,
                        response_format={ "type": "json_object" },
                        timeout=3.0
                    )
                except Exception as e_fmt:
                    print(f"[AI-BIA] Model {model} failed JSON format attempt: {e_fmt}. Retrying without format parameter...")
                    response = None
            
            if not response:
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    max_tokens=1000,
                    timeout=4.0
                )
                
            if not response or not getattr(response, "choices", None) or len(response.choices) == 0:
                raise ValueError(f"AI response choices is None or empty: {repr(response)}")
                
            choice = response.choices[0]
            if not choice or not getattr(choice, "message", None):
                raise ValueError(f"AI choice or message is None: {repr(choice)}")
                
            content = choice.message.content
            if not content:
                raise ValueError("AI message content is empty")
                
            cleaned_content = content.strip()
            if cleaned_content.startswith("```"):
                lines = cleaned_content.splitlines()
                if lines[0].startswith("```json") or lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                cleaned_content = "\n".join(lines).strip()
                
            start_idx = cleaned_content.find("{")
            end_idx = cleaned_content.rfind("}")
            if start_idx != -1 and end_idx != -1:
                cleaned_content = cleaned_content[start_idx:end_idx+1]
                
            parsed_data = json.loads(cleaned_content)
            
            org_risk = parsed_data.get("org_risk", "")
            if org_risk not in ["Critical", "High", "Medium", "Low"]:
                capitalized_risk = org_risk.strip().capitalize()
                if capitalized_risk in ["Critical", "High", "Medium", "Low"]:
                    parsed_data["org_risk"] = capitalized_risk
                else:
                    parsed_data["org_risk"] = nessus_severity if nessus_severity in ["Critical", "High", "Medium", "Low"] else "Medium"
            
            print(f"[AI-BIA] Analysis complete using {model}. Resulting Org Risk: {parsed_data.get('org_risk')}")
            return json.dumps(parsed_data)
            
        except Exception as e:
            print(f"[AI-BIA] Attempt with model {model} failed: {e}")
            last_error = e
            err_msg = str(e).lower()
            if "free-models-per-day" in err_msg:
                print("[AI-BIA] Daily free model rate limit reached. Exiting fallback loop early.")
                break
            continue
            
    print(f"BIA AI ERROR (All models failed): {str(last_error)}")
    return json.dumps({
        "org_risk": nessus_severity if nessus_severity in ["Critical", "High", "Medium", "Low"] else "Medium",
        "summary": "Analysis failed. Defaulted to Nessus severity.",
        "control_context": "AI analysis error.",
        "remediation_steps": ["Check NVD for CVE details."]
    })


def analyze_vulnerabilities_batch(batch_vulns):
    """
    🧠 BATCH ANALYSIS — Process multiple vulnerabilities in a single prompt.
    Keeps 100% of the security controls and analysis context.
    """
    vuln_blocks = []
    for i, v in enumerate(batch_vulns):
        desc = v.get("description", "") or v.get("synopsis", "") or "NOT PROVIDED"
        block = f"""--- VULNERABILITY #{i} ---
ID: {v['_id']}
Asset Name: {v.get('asset_name', 'Unknown')}
Vulnerability Name: {v.get('vuln_name', 'Unknown')}
CVE ID(s): {v.get('cve_id', 'N/A')}
Nessus Severity: {v.get('nessus_severity', 'Medium')}
VPR Score: {v.get('vpr_score', '0.0')}
Plugin ID: {v.get('plugin_id', 'N/A')}
Description: {desc}"""
        vuln_blocks.append(block)
        
    vulns_input = "\n\n".join(vuln_blocks)

    prompt = f"""
You are a cybersecurity analyst. Analyze the following list of Nessus vulnerability findings:

=== VULNERABILITY LIST ===
{vulns_input}

=== EXISTING SECURITY CONTROLS ===
1. Servers are not exposed to the internet and are accessible only within the internal network (no external SSH access, even with valid credentials).
2. A perimeter Palo Alto Networks firewall is in place with Threat Prevention and Anti-Spyware profiles enabled.
3. Wazuh EDR agents are deployed on all servers for real-time log monitoring, including command execution tracking and alerting on suspicious activities.
4. End users do not have administrative/root privileges, and data exfiltration outside the internal network is restricted.

=== YOUR TASK ===
For each vulnerability listed above, provide a detailed assessment covering:
- Real-world exploitability (beyond CVSS score; consider practical attack feasibility).
- Possible attack paths within the given environment.
- Potential business impact if exploited.
- Likelihood of false positives.
- Recommended remediation priority (with justification).

=== OUTPUT FORMAT ===
You MUST return ONLY a JSON object containing a 'results' key with a list of assessment results in the exact same order as the inputs. No conversational text outside of the JSON.
CRITICAL: Every string value in the JSON MUST be properly escaped. Do not use unescaped double quotes inside text fields (use single quotes instead).
{{
    "results": [
        {{
            "id": "vulnerability_unique_id_from_above",
            "org_risk": "Critical|High|Medium|Low",
            "cia_matrix": {{
                "confidentiality": "0-10",
                "integrity": "0-10",
                "availability": "0-10"
            }},
            "business_impact": [
                "Business impact string..."
            ],
            "control_context": "Real-world exploitability and attack paths considering internal network, Palo Alto firewalls, and EDR controls.",
            "remediation_steps": [
                "Remediation step...",
                "Remediation justification with priority details..."
            ],
            "summary": "Detailed summary covering attack feasibility and likelihood of false positives."
        }}
    ]
}}
"""

    last_error = None
    for model in MODELS_TO_TRY:
        try:
            print(f"[AI-BIA] Querying batch of {len(batch_vulns)} items using model: {model}")
            
            response = None
            supports_json_mode = "gemma" not in model.lower()
            
            if supports_json_mode:
                try:
                    response = client.chat.completions.create(
                        model=model,
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.1,
                        max_tokens=3000,
                        response_format={ "type": "json_object" },
                        timeout=5.0
                    )
                except Exception as e_fmt:
                    print(f"[AI-BIA] Batch model {model} failed JSON format attempt: {e_fmt}. Retrying without format parameter...")
                    response = None
            
            if not response:
                response = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.1,
                    max_tokens=3000,
                    timeout=8.0
                )
                
            if not response or not getattr(response, "choices", None) or len(response.choices) == 0:
                raise ValueError(f"Batch AI response choices is None or empty: {repr(response)}")
                
            content = response.choices[0].message.content
            if not content:
                raise ValueError("Batch AI message content is empty")
                
            cleaned_content = content.strip()
            if cleaned_content.startswith("```"):
                lines = cleaned_content.splitlines()
                if lines[0].startswith("```json") or lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                cleaned_content = "\n".join(lines).strip()
                
            start_idx = cleaned_content.find("{")
            end_idx = cleaned_content.rfind("}")
            if start_idx != -1 and end_idx != -1:
                cleaned_content = cleaned_content[start_idx:end_idx+1]
                
            parsed_data = json.loads(cleaned_content)
            results_list = parsed_data.get("results", [])
            
            results_map = {}
            for r in results_list:
                v_id = r.get("id")
                if v_id:
                    results_map[str(v_id)] = r
            
            print(f"[AI-BIA] Batch analysis complete using {model}. Resolved {len(results_map)} items.")
            return results_map
            
        except Exception as e:
            print(f"[AI-BIA] Batch attempt with model {model} failed: {e}")
            last_error = e
            err_msg = str(e).lower()
            if "free-models-per-day" in err_msg:
                print("[AI-BIA] Daily free model rate limit reached. Exiting batch loop early.")
                break
            continue
            
    print(f"[AI-BIA] Batch AI ERROR (All models failed): {str(last_error)}")
    return {}
