from flask import Flask, request, jsonify, render_template, Response, redirect
import csv
import io
import os
from dotenv import load_dotenv
load_dotenv()   # ← MUST be before any os.getenv() calls

from analyzer import classify_attack
from notifier import send_critical_alert_email
from pymongo import MongoClient
import threading
import json
import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

import certifi
ca = certifi.where()

# MongoDB Setup
try:
    client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"), 
                         serverSelectionTimeoutMS=10000,
                         tlsCAFile=ca)
    db = client.blueguard_db
    # Test connection
    client.server_info()
    print("[MDB] ✅ Connected to MongoDB Atlas (cloud)!")
except Exception as e:
    print(f"[FATAL] MongoDB connection failed: {e}")


# ----- CORE HELPER & ROUTES -----

def get_filtered_alerts(agent_filter=None, start_time=None, end_time=None, page=1, limit=15):
    query = {}
    if agent_filter and agent_filter != "All":
        query["agent.name"] = agent_filter
        
    if start_time or end_time:
        query["timestamp"] = {}
        if start_time:
            query["timestamp"]["$gte"] = start_time
        if end_time:
            query["timestamp"]["$lte"] = end_time
        
    skip = (page - 1) * limit
    total_count = db.alerts.count_documents(query)
    
    cursor = db.alerts.find(query).sort("_id", -1).skip(skip).limit(limit)
    alerts_list = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        alerts_list.append(doc)
    return alerts_list, total_count

def group_alerts_data(alerts_list):
    grouped = {}
    for alert in alerts_list:
        agent_name = alert.get('agent', {}).get('name', 'Unknown')
        attack_type = alert.get('attack_type', 'Unknown')
        key = f"{agent_name}_{attack_type}"
        
        if key not in grouped:
            grouped[key] = alert.copy()
            grouped[key]['count'] = 1
        else:
            grouped[key]['count'] += 1
            
    return list(grouped.values())

@app.route("/", methods=["GET"])
def home():
    agent_filter = request.args.get("agent", "All")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")
    page = int(request.args.get("page", 1))
    limit = 10
    
    alerts_list, total_count = get_filtered_alerts(agent_filter, start_time, end_time, page=page, limit=limit)
    
    # Simple summary stats for dashboard
    stats = {
        "total": total_count,
        "critical": sum(1 for a in alerts_list if a.get("org_risk") == "Critical"),
        "high": sum(1 for a in alerts_list if a.get("org_risk") == "High")
    }
    
    # Build query for charts (consistent with filters)
    query = {}
    if agent_filter != "All":
        query["agent.name"] = agent_filter
    if start_time and end_time:
        query["timestamp"] = {"$gte": start_time, "$lte": end_time}

    # Get last 200 alerts to ensure charts are always populated
    all_recent_for_charts = list(db.alerts.find(query).sort("_id", -1).limit(200))
    from collections import Counter
    sev_counts = Counter([a.get("org_risk", "Low") for a in all_recent_for_charts])
    agent_counts = Counter([a.get("agent", {}).get("name", "Unknown") for a in all_recent_for_charts])
    
    chart_data = {
        "severities_labels": list(sev_counts.keys()),
        "severities_data": list(sev_counts.values()),
        "agent_labels": [k for k, v in agent_counts.most_common(5)],
        "agent_data": [v for k, v in agent_counts.most_common(5)],
    }

    total_pages = max(1, (total_count + limit - 1) // limit)
    available_agents = db.alerts.distinct("agent.name")
    
    return render_template("index.html", 
                           alerts=alerts_list, 
                           stats=stats, 
                           chart_data=chart_data, 
                           available_agents=available_agents, 
                           current_filter=agent_filter, 
                           current_start=start_time, 
                           current_end=end_time,
                           page=page,
                           total_pages=total_pages)

@app.route("/vulnerabilities", methods=["GET"])
def vulnerabilities():
    scan_id = request.args.get("scan_id")
    asset_filter = request.args.get("asset", "All")
    sev_filter = request.args.get("severity", "All")
    page = int(request.args.get("page", 1))
    limit = 15

    # If NO scan_id, show the GRID of SCANS
    if not scan_id:
        scans = list(db.nessus_scans.find().sort("timestamp", -1))
        # Summary stats for all scans
        total_vulns = db.vulnerabilities.count_documents({})
        critical_vulns = db.vulnerabilities.count_documents({"nessus_severity": {"$regex": "Critical", "$options": "i"}})
        total_assets = len(db.vulnerabilities.distinct("asset_name"))
        
        return render_template("vulnerabilities.html", 
                               view_mode="grid",
                               scans=scans,
                               stats={"total_vulns": total_vulns, "critical_vulns": critical_vulns, "total_assets": total_assets})

    # If scan_id is present, show the TABLE for that specific scan
    query = {"scan_id": scan_id}
    if asset_filter != "All":
        query["asset_name"] = asset_filter
    if sev_filter != "All":
        query["nessus_severity"] = {"$regex": sev_filter, "$options": "i"}
    
    total_count = db.vulnerabilities.count_documents(query)
    vulns = list(db.vulnerabilities.find(query).sort("nessus_severity", -1).skip((page - 1) * limit).limit(limit))
    
    # —— 📊 SUMMARY STATS FOR THIS SPECIFIC SCAN ——
    critical_count = db.vulnerabilities.count_documents({**query, "nessus_severity": {"$regex": "Critical", "$options": "i"}})
    max_vpr_doc = db.vulnerabilities.find_one(query, sort=[("vpr_score", -1)])
    max_vpr = max_vpr_doc.get("vpr_score", "0.0") if max_vpr_doc else "0.0"
    at_risk_assets = len(db.vulnerabilities.distinct("asset_name", {**query, "nessus_severity": {"$in": ["Critical", "High", "critical", "high"]}}))
    
    summary_stats = {
        "total_assets": len(db.vulnerabilities.distinct("asset_name", {"scan_id": scan_id})),
        "critical_vulns": critical_count,
        "max_vpr": max_vpr,
        "at_risk_count": at_risk_assets
    }
    
    total_pages = max(1, (total_count + limit - 1) // limit)
    available_assets = db.vulnerabilities.distinct("asset_name", {"scan_id": scan_id})
    scan_meta = db.nessus_scans.find_one({"scan_id": scan_id})
    
    return render_template("vulnerabilities.html", 
                           view_mode="table",
                           vulns=vulns, 
                           available_assets=available_assets,
                           current_asset=asset_filter,
                           current_severity=sev_filter,
                           current_scan_id=scan_id,
                           scan_name=scan_meta.get("name", "Unknown Scan") if scan_meta else "Unknown Scan",
                           page=page,
                           total_pages=total_pages,
                           stats=summary_stats)

@app.route("/upload_nessus", methods=["POST"])
def upload_nessus():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    scan_name = request.form.get("scan_name", f"Scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}")
    
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if file and file.filename.endswith('.csv'):
        # 1. Create a unique Scan ID
        import uuid
        scan_id = str(uuid.uuid4())[:8]
        
        # 2. Parse CSV
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        reader = csv.DictReader(stream)
        
        vulns_to_insert = []
        for row in reader:
            # --- SMART MAPPING LOGIC ---
            # Hum saari keys ko lowercase kar dete hain taaki matching asaan ho
            row_lower = {k.lower().strip(): v for k, v in row.items() if k}
            
            def get_field(options):
                for opt in options:
                    for key in row_lower:
                        if opt.lower() in key: # Partial match (e.g. 'asset.nam' contains 'asset')
                            return row_lower[key]
                return None

            asset = get_field(["asset.name", "asset.nam", "host", "ip address", "dns"]) or "Unknown"
            v_name = get_field(["definition.name", "vuln name", "name", "title"]) or "Unknown Vulnerability"
            cve = get_field(["definition.cve", "cve id", "cve"]) or "N/A"
            sev = get_field(["severity", "risk", "definition.severity"]) or "Low"
            vpr = get_field(["definition.vpr_v2.score", "vpr score", "vpr"]) or "0.0"
            
            doc = {
                "scan_id": scan_id,
                "asset_name": asset,
                "vuln_name": v_name,
                "cve_id": cve,
                "nessus_severity": sev,
                "vpr_score": vpr,
                "synopsis": row.get("Synopsis", ""),
                "description": row.get("description", row.get("Description", "")),
                "solution": row.get("solution", row.get("Solution", "")),
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            vulns_to_insert.append(doc)
        
        if vulns_to_insert:
            db.vulnerabilities.insert_many(vulns_to_insert)
            
            # 3. Create Scan Metadata
            db.nessus_scans.insert_one({
                "scan_id": scan_id,
                "name": scan_name,
                "filename": file.filename,
                "total_vulns": len(vulns_to_insert),
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            
            return redirect("/vulnerabilities")
    
    return jsonify({"error": "Invalid file format. Please upload a CSV."}), 400

@app.route("/delete_scan/<scan_id>", methods=["POST"])
def delete_scan(scan_id):
    db.vulnerabilities.delete_many({"scan_id": scan_id})
    db.nessus_scans.delete_one({"scan_id": scan_id})
    return redirect("/vulnerabilities")

@app.route("/nuke_vulnerabilities")
def nuke_vulnerabilities():
    db.vulnerabilities.delete_many({})
    db.nessus_scans.delete_many({})
    return "🧹 Database Cleaned! Go back to /vulnerabilities and refresh."

@app.route("/analyze_vulnerability/<vuln_id>", methods=["POST"])
def analyze_vuln_route(vuln_id):
    from bson import ObjectId
    vuln = db.vulnerabilities.find_one({"_id": ObjectId(vuln_id)})
    if not vuln:
        return jsonify({"error": "Vulnerability not found"}), 404
    
    from analyzer import analyze_vulnerability
    try:
        analysis_result = analyze_vulnerability(vuln)
        print(f"[DEBUG] AI Response: {analysis_result}")
        
        # Load JSON and handle if AI returns a list instead of a single object
        data = json.loads(analysis_result)
        if isinstance(data, list) and len(data) > 0:
            data = data[0]
            
        return jsonify(data), 200
    except Exception as e:
        print(f"Route Analysis Error: {e}")
        return jsonify({"error": "AI analysis failed", "org_risk": "High"}), 500

@app.route("/logs", methods=["GET"])
def logs():
    agent_filter = request.args.get("agent", "All")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")
    page = int(request.args.get("page", 1))
    limit = 10
    
    all_filtered_raw, _ = get_filtered_alerts(agent_filter, start_time, end_time, limit=1000)
    grouped_all = group_alerts_data(all_filtered_raw)
    
    total_grouped = len(grouped_all)
    total_pages = (total_grouped + limit - 1) // limit
    paginated_grouped = grouped_all[(page-1)*limit : page*limit]
    
    available_agents = db.alerts.distinct("agent.name")
    
    return render_template("logs.html", 
                           alerts=paginated_grouped, 
                           available_agents=available_agents, 
                           current_filter=agent_filter, 
                           current_start=start_time, 
                           current_end=end_time,
                           page=page,
                           total_pages=total_pages)

@app.route("/reports", methods=["GET"])
def reports():
    # Calculate key metrics for the report
    total_alerts = db.alerts.count_documents({})
    critical_alerts = db.alerts.count_documents({"$or": [{"org_risk": "Critical"}, {"severity": "Critical"}]})
    high_alerts = db.alerts.count_documents({"$or": [{"org_risk": "High"}, {"severity": "High"}]})
    
    # Get top 5 targeted agents
    top_agents = list(db.alerts.aggregate([
        {"$group": {"_id": "$agent.name", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]))
    
    # Get last 5 critical incidents for the summary table
    recent_critical = list(db.alerts.find({"$or": [{"org_risk": "Critical"}, {"severity": "Critical"}]}).sort("timestamp", -1).limit(5))
    
    return render_template("reports.html", 
                           total=total_alerts, 
                           critical=critical_alerts, 
                           high=high_alerts,
                           top_agents=top_agents,
                           recent_critical=recent_critical,
                           report_date=datetime.datetime.now().strftime("%B %d, %Y"))

@app.route("/alerts", methods=["GET"])
def alerts_page():
    agent_filter = request.args.get("agent", "All")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")
    alerts_list, _ = get_filtered_alerts(agent_filter, start_time, end_time, limit=1000)
    available_agents = db.alerts.distinct("agent.name")
    return render_template("alerts.html", alerts=alerts_list, available_agents=available_agents, current_filter=agent_filter, current_start=start_time, current_end=end_time)

@app.route("/agents", methods=["GET", "POST"])
def agents():
    if request.method == "POST":
        hostname = request.form.get("hostname")
        os_type = request.form.get("os")
        ip = request.form.get("ip_address")
        db.agents.update_one(
            {"hostname": hostname},
            {"$set": {"os": os_type, "ip_address": ip, "registered_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}},
            upsert=True
        )
        return redirect("/agents")

    # Ultra-Robust Discovery: Get all host stats in ONE aggregation query to avoid N+1 latency
    pipeline = [
        {
            "$group": {
                "_id": {"$ifNull": ["$agent.name", {"$ifNull": ["$agent_name", "$hostname"]}]},
                "total_alerts": {"$sum": 1},
                "crit": {
                    "$sum": {
                        "$cond": [{"$or": [{"$eq": ["$org_risk", "Critical"]}, {"$eq": ["$severity", "Critical"]}]}, 1, 0]
                    }
                },
                "high": {
                    "$sum": {
                        "$cond": [{"$or": [{"$eq": ["$org_risk", "High"]}, {"$eq": ["$severity", "High"]}]}, 1, 0]
                    }
                },
                "med": {
                    "$sum": {
                        "$cond": [{"$or": [{"$eq": ["$org_risk", "Medium"]}, {"$eq": ["$severity", "Medium"]}]}, 1, 0]
                    }
                },
                "latest_ip": {"$last": {"$ifNull": ["$agent.ip", "$ip"]}}
            }
        }
    ]
    
    agg_results = list(db.alerts.aggregate(pipeline))
    
    # Store aggregated stats by hostname
    host_stats = {}
    for res in agg_results:
        name = res["_id"]
        if name and name != "Unknown":
            host_stats[name] = res

    # Also include manually registered agents
    registered_info = {a["hostname"]: a for a in db.agents.find()}
    unique_names = set(host_stats.keys()).union(set(registered_info.keys()))
    
    final_inventory = []
    
    for hostname in sorted(list(unique_names)):
        reg_data = registered_info.get(hostname, {})
        stats = host_stats.get(hostname, {"total_alerts": 0, "crit": 0, "high": 0, "med": 0, "latest_ip": None})
        
        agent_data = {
            "hostname": hostname,
            "os": reg_data.get("os", "Linux/Other"),
            "ip_address": reg_data.get("ip_address", "Auto-Detected"),
            "registered_at": reg_data.get("registered_at", "N/A (Discovered)")
        }
        
        # IP Discovery for auto-detected hosts
        if agent_data["ip_address"] == "Auto-Detected" and stats["latest_ip"]:
            agent_data["ip_address"] = stats["latest_ip"]

        # Calculate Risk from pre-aggregated stats
        crit = stats["crit"]
        high = stats["high"]
        med = stats["med"]
        
        risk_score = (crit * 25) + (high * 10) + (med * 5)
        agent_data["health_score"] = max(0, 100 - risk_score)
        agent_data["critical_alerts"] = crit
        agent_data["total_alerts"] = stats["total_alerts"]
        
        # Determine Risk Level for UI
        if crit > 0: agent_data["risk"] = "Critical"
        elif high > 0: agent_data["risk"] = "High"
        elif med > 0: agent_data["risk"] = "Medium"
        else: agent_data["risk"] = "Low"
        
        if agent_data["health_score"] < 40: agent_data["status"] = "Critical"
        elif agent_data["health_score"] < 80: agent_data["status"] = "Warning"
        else: agent_data["status"] = "Healthy"
        
        final_inventory.append(agent_data)

    return render_template("agents.html", agents=final_inventory)

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json

    # Calculate Base Severity from Rule Level (Wazuh Standard)
    try:
        level = int(data.get('rule', {}).get('level', 0))
    except:
        level = 0
        
    if level >= 12: data["base_severity"] = "Critical"
    elif level >= 10: data["base_severity"] = "High"
    elif level >= 5: data["base_severity"] = "Medium"
    else: data["base_severity"] = "Low"

    try:
        # Perform AI Analysis SYNCHRONOUSLY
        ai_response_str = classify_attack(data)
        
        # ✅ ROBUST PARSING: Handle both dict AND list responses from AI
        raw = json.loads(ai_response_str)
        if isinstance(raw, list):
            # AI returned an array — take the first item
            ai_data = raw[0] if raw else {}
        elif isinstance(raw, dict):
            ai_data = raw
        else:
            ai_data = {}
        
        # --- EXHAUSTIVE HEURISTIC SAFETY NET ---
        desc = data.get("rule", {}).get("description", "").lower()
        log_text = data.get("full_log", "").lower()
        combined_text = desc + " " + log_text
        
        intel_library = {
            "wannacry": {"cve": "CVE-2017-0144, CVE-2017-0145", "cwe": "CWE-119, CWE-254", "cvss": 9.8, "cwss": 98.0, "actor": "WannaCry Ransomware Operator"},
            "ransomware": {"cve": "CVE-2017-0144", "cwe": "CWE-119, CWE-200", "cvss": 9.8, "cwss": 98.0, "actor": "Ransomware Operator"},
            "lockbit": {"cve": "CVE-2021-34527", "cwe": "CWE-269, CWE-200", "cvss": 9.8, "cwss": 98.0, "actor": "LockBit 3.0 Operator"},
            "eternalblue": {"cve": "CVE-2017-0144, CVE-2017-0145", "cwe": "CWE-119, CWE-254", "cvss": 9.8, "cwss": 98.0, "actor": "Shadow Brokers APT"},
            "log4j": {"cve": "CVE-2021-44228, CVE-2021-45046", "cwe": "CWE-502, CWE-917", "cvss": 10.0, "cwss": 100.0, "actor": "APT Log4Shell Exploiter"},
            "log4shell": {"cve": "CVE-2021-44228, CVE-2021-45046", "cwe": "CWE-502, CWE-917", "cvss": 10.0, "cwss": 100.0, "actor": "APT Log4Shell Exploiter"},
            "proxylogon": {"cve": "CVE-2021-26855, CVE-2021-26857", "cwe": "CWE-20, CWE-287", "cvss": 9.8, "cwss": 95.0, "actor": "Hafnium APT Group"},
            "zerologon": {"cve": "CVE-2020-1472", "cwe": "CWE-287, CWE-326", "cvss": 10.0, "cwss": 100.0, "actor": "Domain Privilege Escalator"},
            "printnightmare": {"cve": "CVE-2021-34527", "cwe": "CWE-427, CWE-269", "cvss": 8.8, "cwss": 90.0, "actor": "Print Spooler Exploiter"},
            "spring4shell": {"cve": "CVE-2022-22965", "cwe": "CWE-94, CWE-119", "cvss": 9.8, "cwss": 95.0, "actor": "Spring Core Exploiter"},
            "moveit": {"cve": "CVE-2023-34362", "cwe": "CWE-89, CWE-284", "cvss": 9.8, "cwss": 97.0, "actor": "Clop Ransomware Group"},
            "citrix": {"cve": "CVE-2023-4966", "cwe": "CWE-125, CWE-200", "cvss": 9.4, "cwss": 94.0, "actor": "Citrix Bleed Exploiter"},
            "ivanti": {"cve": "CVE-2024-21887, CVE-2023-46805", "cwe": "CWE-918, CWE-287", "cvss": 9.1, "cwss": 92.0, "actor": "APT UTA0178"},
            "fortinet": {"cve": "CVE-2024-55591", "cwe": "CWE-287, CWE-306", "cvss": 9.6, "cwss": 96.0, "actor": "Fortinet APT Exploiter"},
            "paloalto": {"cve": "CVE-2024-3400", "cwe": "CWE-77, CWE-78", "cvss": 10.0, "cwss": 100.0, "actor": "UTA0218 APT Group"},
            "pan-os": {"cve": "CVE-2024-3400", "cwe": "CWE-77", "cvss": 10.0, "cwss": 100.0, "actor": "UTA0218 APT Group"},
            "struts": {"cve": "CVE-2023-50164", "cwe": "CWE-434, CWE-22", "cvss": 9.8, "cwss": 95.0, "actor": "Struts RCE Exploiter"},
            "mimikatz": {"cve": "CVE-2021-36934", "cwe": "CWE-259, CWE-522", "cvss": 7.8, "cwss": 85.0, "actor": "Credential Theft Operator"},
            # FinTech Specific
            "swift": {"cve": "CVE-2022-26134", "cwe": "CWE-284, CWE-287", "cvss": 9.8, "cwss": 99.0, "actor": "Financial Fraud APT"},
            "pci": {"cve": "CVE-2023-28432", "cwe": "CWE-200, CWE-311", "cvss": 7.5, "cwss": 85.0, "actor": "Compliance Violator"},
            "pci_dss": {"cve": "CVE-2023-28432", "cwe": "CWE-200, CWE-311", "cvss": 7.5, "cwss": 85.0, "actor": "Compliance Violator"},
            "cardholder": {"cve": "CVE-2023-28432", "cwe": "CWE-200, CWE-311", "cvss": 8.0, "cwss": 90.0, "actor": "Card Data Thief"},
            "hsm": {"cve": "CVE-2019-14821", "cwe": "CWE-284, CWE-330", "cvss": 9.8, "cwss": 99.0, "actor": "Cryptographic Attack APT"},
            "rtgs": {"cve": "CVE-2022-26134", "cwe": "CWE-284, CWE-89", "cvss": 9.8, "cwss": 99.0, "actor": "Banking Fraud Operator"},
            "core banking": {"cve": "CVE-2021-4034", "cwe": "CWE-269, CWE-284", "cvss": 9.8, "cwss": 99.0, "actor": "Banking Infrastructure APT"},
            "idor": {"cve": "CVE-2023-29489", "cwe": "CWE-639, CWE-284", "cvss": 7.5, "cwss": 80.0, "actor": "Insecure API Exploiter"},
            "otp bypass": {"cve": "CVE-2022-36946", "cwe": "CWE-287, CWE-303", "cvss": 7.5, "cwss": 78.0, "actor": "Authentication Bypass Attacker"},
            # Generic
            "sql injection": {"cve": "CVE-2023-28432", "cwe": "CWE-89", "cvss": 7.5, "cwss": 82.0, "actor": "Web Application Exploiter"},
            "xss": {"cve": "CVE-2023-29489", "cwe": "CWE-79", "cvss": 6.1, "cwss": 65.0, "actor": "Cross-Site Script Injector"},
            "cross-site scripting": {"cve": "CVE-2023-29489", "cwe": "CWE-79", "cvss": 6.1, "cwss": 65.0, "actor": "Cross-Site Script Injector"},
            "brute force": {"cve": "CVE-2022-36946", "cwe": "CWE-307, CWE-521", "cvss": 5.8, "cwss": 65.0, "actor": "Brute Force Botnet"},
            "traversal": {"cve": "CVE-2021-41773", "cwe": "CWE-22", "cvss": 7.5, "cwss": 78.0, "actor": "Directory Traversal Attacker"},
            "dns tunnel": {"cve": "CVE-2021-25220", "cwe": "CWE-200", "cvss": 6.5, "cwss": 75.0, "actor": "Exfiltration Specialist"},
            "syscheck": {"cve": "CVE-2023-32629", "cwe": "CWE-732", "cvss": 5.5, "cwss": 60.0, "actor": "Insider Threat"},
            "port scan": {"cve": "CVE-2021-25220", "cwe": "CWE-200", "cvss": 4.5, "cwss": 45.0, "actor": "Reconnaissance Bot"},
            "c2": {"cve": "CVE-2021-44228", "cwe": "CWE-200, CWE-78", "cvss": 8.0, "cwss": 88.0, "actor": "C2 Operator"},
            "ebpf": {"cve": "CVE-2025-21756", "cwe": "CWE-416, CWE-269", "cvss": 7.8, "cwss": 82.0, "actor": "Linux Kernel Exploiter"},
            "tls": {"cve": "CVE-2021-3449", "cwe": "CWE-326", "cvss": 5.9, "cwss": 58.0, "actor": "Protocol Downgrade Attacker"},
            "reverse shell": {"cve": "CVE-2022-26134", "cwe": "CWE-78, CWE-427", "cvss": 8.5, "cwss": 92.0, "actor": "Reverse Shell Operator"},
        }

        # Initial assignments from AI (using new key names)
        actor = ai_data.get("threat_actor", "Unknown")
        vector = ai_data.get("attack_vector", "Unknown")
        
        # Apply safety net if AI was vague or missing IDs
        for key, intel in intel_library.items():
            if key in combined_text or key.replace(" ", "") in combined_text.replace(" ", ""):
                if actor in ["Unknown", "Unknown Actor", "Unspecified", "N/A", ""]:
                    actor = intel["actor"]
                if vector in ["Unknown", "Unknown Vector", "Unspecified", "N/A", ""]:
                    vector = key.upper()
                
                # Force update CVE/CWE if they are missing or N/A
                current_cve = ai_data.get("cve_id", "N/A")
                current_cwe = ai_data.get("cwe_id", "N/A")
                
                if not current_cve or current_cve in ["N/A", "", "None", "Unspecified"]:
                    ai_data["cve_id"] = intel["cve"]
                if not current_cwe or current_cwe in ["N/A", "", "None", "Unspecified"]:
                    ai_data["cwe_id"] = intel["cwe"]
                
                try:
                    curr_cvss = float(ai_data.get("cvss_score", 0))
                    if curr_cvss == 0: ai_data["cvss_score"] = intel["cvss"]
                except: ai_data["cvss_score"] = intel["cvss"]
                
                try:
                    curr_cwss = float(ai_data.get("cwss_score", 0))
                    if curr_cwss == 0: ai_data["cwss_score"] = intel["cwss"]
                except: ai_data["cwss_score"] = intel["cwss"]
                break

        # Final Mapping & Normalization based on User's Specified Ranges
        org_sev = ai_data.get("risk_severity", "Low")
        
        # Initialize default scores if they are missing or zero
        try:
            cvss = float(ai_data.get("cvss_score", 0))
            cwss = float(ai_data.get("cwss_score", 0))
        except:
            cvss, cwss = 0.0, 0.0

        # --- SCORE NORMALIZATION LOGIC ---
        if org_sev == "Critical":
            if cwss < 90.0: cwss = 95.0
            if cvss < 9.0: cvss = 9.8
        elif org_sev == "High":
            if cwss < 70.0 or cwss >= 90.0: cwss = 82.5
            if cvss < 7.0 or cvss >= 9.0: cvss = 7.5
        elif org_sev == "Medium":
            if cwss < 40.0 or cwss >= 70.0: cwss = 55.0
            if cvss < 4.0 or cvss >= 7.0: cvss = 5.5
        else: # Low
            if cwss >= 40.0: cwss = 25.0
            if cvss >= 4.0: cvss = 2.5

        data["attack_type"] = actor if actor not in ["Unknown", "Unspecified", ""] else vector
        data["mitre_tactic"] = vector
        data["mitre_technique"] = ai_data.get("mitre_technique_id", "N/A")
        data["mitre_technique_name"] = ai_data.get("mitre_technique_name", "N/A")
        
        # ✅ CVE PRE-SEED: If payload already has explicit CVE/CWE, use it directly
        payload_cve = data.get("data", {}).get("cve", "")
        payload_cwe = data.get("data", {}).get("cwe", "")
        
        if payload_cve and payload_cve.strip() and payload_cve != "N/A":
            data["cve_id"] = payload_cve.strip()
        else:
            data["cve_id"] = ai_data.get("cve_id", "N/A")
            
        if payload_cwe and payload_cwe.strip() and payload_cwe != "N/A":
            data["cwe_id"] = payload_cwe.strip()
        else:
            data["cwe_id"] = ai_data.get("cwe_id", "N/A")

        data["cvss_score"] = f"{cvss:.1f}"
        data["cwss_score"] = f"{cwss:.1f}"
        
        # ✅ SOURCE IP: Extract from multiple possible payload locations
        src_ip = (
            data.get("agent", {}).get("ip") or
            data.get("data", {}).get("srcip") or
            data.get("data", {}).get("src_ip") or
            data.get("srcip") or
            "N/A"
        )
        data["src_ip"] = src_ip
        
        # Use AI's risk_severity as the primary risk level (fallback to base severity)
        final_risk = ai_data.get("risk_severity", org_sev)
        if final_risk not in ["Critical", "High", "Medium", "Low"]:
            final_risk = org_sev
        data["org_risk"] = final_risk
        data["severity"] = final_risk
        
        data["remediation"] = ai_data.get("remediation_steps", "No remediation suggested.")
        data["analysis"] = ai_data.get("forensic_summary", "No forensic details available.")
        data["org_risk_assessment"] = ai_data.get("org_impact", "No organizational impact details available.")
        
        data["is_analyzed"] = True

    except Exception as e:
        print(f"Error during AI analysis: {e}")
        data["attack_type"] = "Analysis Error"
        data["is_analyzed"] = False

    # Save to MongoDB ONLY after analysis is complete
    db.alerts.insert_one(data)
    print(f"✅ ALERT PROCESSED: {data['attack_type']} | Risk: {data['org_risk']}")
    
    # Trigger email asynchronously for criticals (keep this async as it takes time)
    if data.get('severity') in ['Critical', 'High']:
        threading.Thread(target=send_critical_alert_email, args=(data,), daemon=True).start()

    return jsonify({"status": "received"}), 200

@app.route("/export_csv", methods=["GET"])
def export_csv():
    agent_filter = request.args.get("agent", "All")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")
    
    alerts_list, _ = get_filtered_alerts(agent_filter, start_time, end_time, limit=10000)
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header Row
    writer.writerow(["Timestamp", "Base Severity", "Org Risk Severity", "Agent", "Attack Type", "CVE/CWE", "CVSS Score", "MITRE Tactic", "MITRE Technique", "Rule Description", "AI Analysis", "Org Risk Assessment", "Remediation"])
    
    for alert in alerts_list:
        writer.writerow([
            alert.get("timestamp", "N/A"),
            alert.get("base_severity", alert.get("severity", "Unknown")),
            alert.get("org_risk_severity", alert.get("severity", "Unknown")),
            alert.get("agent", {}).get("name", "Unknown"),
            alert.get("attack_type", "Unknown"),
            alert.get("cve_cwe", "N/A"),
            alert.get("cvss_score", "N/A"),
            alert.get("mitre_tactic", "N/A"),
            alert.get("mitre_technique", "N/A"),
            alert.get("rule", {}).get("description", "N/A"),
            alert.get("analysis", "N/A"),
            alert.get("org_risk_assessment", "N/A"),
            alert.get("remediation", "N/A")
        ])
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=BlueGuard_Incident_Report.csv"}
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)