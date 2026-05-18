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
)

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
    🧠 HIGH-PRECISION ANALYSIS (99% Accuracy Goal)
    Specifically analyzes a Nessus vulnerability for organizational risk in a FinTech context.
    Uses Security Control Validation & Business Impact Analysis (BIA).
    """
    asset_name      = vuln_data.get('asset_name', 'Unknown')
    vuln_name       = vuln_data.get('vuln_name', 'Unknown')
    cve_id          = vuln_data.get('cve_id', 'N/A')
    nessus_severity = vuln_data.get('nessus_severity', 'Low')
    vpr_score       = vuln_data.get('vpr_score', '0.0')

    prompt = f"""
    You are a Senior Security Architect. Perform a 99% accurate Organizational Risk Assessment & Business Impact Analysis (BIA) for this vulnerability.

    DATA:
    Asset: {asset_name}
    Vulnerability: {vuln_name}
    CVE ID: {cve_id}
    Nessus Severity: {nessus_severity}
    VPR Score: {vpr_score}

    {ORG_SECURITY_CONTROLS}

    YOUR TASK:
    1. CIA SCORE CALCULATION (CRITICAL): Calculate the Confidentiality, Integrity, and Availability impact scores on a scale of 0 to 10. You MUST start with the vulnerability's baseline theoretical impact, and then STRICTLY REDUCE the score based on the 'ORG_SECURITY_CONTROLS' provided above. For example, if a vulnerability requires external network access, but the asset is isolated internally behind the Palo Alto firewall, the availability/confidentiality impact should be severely reduced (e.g., 0-2). Provide 100% accurate scores contextualized to the org.
    2. BUSINESS IMPACT ANALYSIS (BIA): Analyze impact on Confidentiality, Integrity, and Availability.
    3. SECURITY CONTROL VALIDATION: Validate how specific controls (Palo Alto, Wazuh, No Root Access) actively mitigate or fail to mitigate this exact vulnerability.
    4. ASSET CRITICALITY: Assets like 'DB', 'Core', 'Prod', 'Gateway', 'Swift' are CRITICAL. 'Dev', 'Test', 'Internal-Office' are Medium/Low.
    5. RE-CALCULATE SEVERITY: Provide a final 'Org Risk' (Critical/High/Medium/Low) which may differ from Nessus Global Severity.

    OUTPUT JSON FORMAT (STRICT):
    {{
        "org_risk": "Critical|High|Medium|Low",
        "cia_matrix": {{
            "confidentiality": "0-10",
            "integrity": "0-10",
            "availability": "0-10"
        }},
        "business_impact": ["Impact 1: ...", "Impact 2: ...", "Impact 3: ..."],
        "control_context": "Briefly explain how our Firewall/WAF/EDR impacts this risk.",
        "remediation_steps": ["Step 1", "Step 2", "..."],
        "summary": "1-sentence executive summary of the threat."
    }}

    RULES:
    - Be extremely concise. No fluff.
    - Provide exactly 3 to 4 points for business_impact, focusing on possibilities specific to the organizational infrastructure context.
    - Focus on organizational impact, not global theory.
    - Return ONLY valid JSON.
    """
    
    try:
        print(f"[AI-BIA] Analyzing high-precision risk for: {asset_name}")
        response = client.chat.completions.create(
            model="google/gemini-2.0-flash-001",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=400,
            response_format={ "type": "json_object" }
        )
        print("[AI-BIA] Analysis complete.")
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"BIA AI ERROR: {str(e)}")
        return json.dumps({
            "org_risk": "Medium", 
            "summary": "Analysis failed. Manual review required.",
            "control_context": "AI analysis error.",
            "remediation_steps": ["Check NVD for CVE details."]
        })

        is_rate_limit = "429" in str(e) or "Quota exceeded" in str(e) or "rate" in str(e).lower()
        
        desc_lower = description.lower()
        mitre_tactic = "Defense Evasion"
        mitre_technique = "Indicator Removal (T1070)"
        attack_type = "Security Event"
        cve_cwe = "N/A"
        cvss_score = "N/A"
        cwss_score = "0.0"
        base_severity = "Medium"
        org_risk_severity = "Low"
        org_risk_assessment = "AI analysis unavailable. Based on organizational security controls (internal network only, Palo Alto firewall, Wazuh monitoring, no root access), the risk is assessed as reduced. Manual investigation recommended."
        
        # FIM Check
        if "file integrity monitoring" in desc_lower or "syscheck" in desc_lower:
            attack_type = "File Integrity Change"
            mitre_tactic = "Defense Evasion"
            mitre_technique = "Indicator Removal on Host (T1070)"
            cve_cwe = "CWE-73" # External Control of File Name or Path
            base_severity = "High"
            org_risk_severity = "Medium"
            remediation = "Verify if this file change was authorized. If not, restore from backup."
            org_risk_assessment = "File integrity change detected. While Wazuh agents provide real-time monitoring and the internal network restricts external access, unauthorized file modifications could indicate insider threat activity. Remediation priority: Medium - verify change authorization within 24 hours."
        elif "logon failure" in desc_lower or "authentication failure" in desc_lower:
            attack_type = "Brute Force Attempt"
            mitre_tactic = "Credential Access"
            mitre_technique = "Brute Force (T1110)"
            cve_cwe = "CWE-307" # Improper Restriction of Excessive Authentication Attempts
            base_severity = "High"
            org_risk_severity = "Low"
            remediation = "Disable the source IP and enforce multi-factor authentication."
            org_risk_assessment = "Brute force attempt detected. Given that servers are internal-only with no external SSH access, external exploitation is not feasible. The Palo Alto firewall with Threat Prevention further mitigates this risk. However, this could indicate an insider threat or compromised internal device. Remediation priority: Low - monitor for repeated attempts from same source."
        elif "wannacry" in desc_lower or "ransomware" in desc_lower or "malware" in desc_lower:
            attack_type = "Malware Infection"
            mitre_tactic = "Impact"
            mitre_technique = "Data Encrypted for Impact (T1486)"
            cve_cwe = "CVE-2017-0144" # EternalBlue
            base_severity = "Critical"
            org_risk_severity = "Critical"
            remediation = "Isolate infected host immediately. Shutdown SMB services. Restore from offline backups."
            org_risk_assessment = "CRITICAL: Ransomware indicators detected. Although the network is internal, ransomware like WannaCry spreads laterally via SMB. Our internal isolation won't stop a worm once it's inside. Immediate isolation required to prevent total infrastructure loss."
        elif "xss" in desc_lower or "cross-site scripting" in desc_lower:
            attack_type = "Cross-Site Scripting (XSS)"
            mitre_tactic = "Initial Access"
            mitre_technique = "Exploit Public-Facing Application (T1190)"
            cve_cwe = "CWE-79" # Cross-site Scripting
            base_severity = "High"
            org_risk_severity = "Low"
            remediation = "Sanitize user input and implement Content Security Policy (CSP)."
            org_risk_assessment = "XSS attempt detected in HTTP request. Perimeter Palo Alto firewall with Threat Prevention and internal-only access significantly reduce the likelihood of a successful exploit reaching a vulnerable endpoint. Remediation priority: Low."
        elif "special privileges" in desc_lower or "root" in desc_lower:
            attack_type = "Privilege Escalation"
            mitre_tactic = "Privilege Escalation"
            mitre_technique = "Exploitation for Privilege Escalation (T1068)"
            cve_cwe = "CWE-269" # Improper Privilege Management
            base_severity = "Critical"
            org_risk_severity = "Critical"
            remediation = "Patch the target vulnerability and audit system logs. Terminate the suspicious session."
            org_risk_assessment = "CRITICAL: Privilege escalation attempt to root/admin. This bypasses our 'Restricted Privileges' control. Since the attacker is already internal, this is a direct threat to the core infrastructure. Immediate investigation required."
        else:
            attack_type = "General Security Event"
            mitre_tactic = "Execution"
            mitre_technique = "User Execution (T1204)"
            cve_cwe = "CWE-20" # Improper Input Validation
            base_severity = "Medium"
            org_risk_severity = "Medium"
            remediation = "Investigate manually for unusual system activity."
            org_risk_assessment = "Security event detected. While we have multiple layers of defense, the nature of this event requires manual review to ensure internal integrity is not compromised."

        analysis_msg = (
            "⚠️ AI Analysis temporarily unavailable (API Quota Exceeded). Fallback risk assessment active using organizational security controls."
            if is_rate_limit 
            else f"Fallback classification used because AI generation failed. Organizational controls factored into risk assessment."
        )

        return json.dumps({
            "attack_type": attack_type,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "analysis": analysis_msg,
            "severity": org_risk_severity,
            "remediation": remediation,
            "cve_cwe": cve_cwe,
            "cvss_score": cvss_score,
            "cwss_score": cwss_score,
            "base_severity": base_severity,
            "org_risk_severity": org_risk_severity,
            "org_risk_assessment": org_risk_assessment
        })
