from flask import Flask, request, jsonify, render_template, Response
import csv
import io
from analyzer import classify_attack
from notifier import send_critical_alert_email
from pymongo import MongoClient
import threading
import json
import datetime
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# MongoDB Setup
try:
    client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    db = client.blueguard_db
    # Test connection
    client.server_info()
    print("[MDB] Connected to MongoDB locally.")
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
    limit = 15  # Increased for better visibility
    
    # Get paginated alerts directly (NO GROUPING for true live stream)
    alerts_list, total_count = get_filtered_alerts(agent_filter, start_time, end_time, page=page, limit=limit)
    
    # Stats from recent data
    all_recent, _ = get_filtered_alerts(agent_filter, start_time, end_time, limit=200)
    
    stats = {
        "total": total_count,
        "critical": sum(1 for a in all_recent if a.get("org_risk") == "Critical"),
        "high": sum(1 for a in all_recent if a.get("org_risk") == "High")
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

    # Ultra-Robust Discovery: Scan all alerts using multiple common field paths
    all_alerts = list(db.alerts.find({}, {"agent": 1, "agent_name": 1, "hostname": 1}))
    unique_names = set()
    
    for a in all_alerts:
        # Check all possible locations for a hostname
        name = a.get('agent', {}).get('name') or a.get('agent_name') or a.get('hostname')
        if name and name != "Unknown":
            unique_names.add(name)
    
    # Also include manually registered agents
    for reg in db.agents.find():
        if reg.get("hostname"):
            unique_names.add(reg.get("hostname"))

    registered_info = {a["hostname"]: a for a in db.agents.find()}
    final_inventory = []
    
    for hostname in sorted(list(unique_names)):
        reg_data = registered_info.get(hostname, {})
        agent_data = {
            "hostname": hostname,
            "os": reg_data.get("os", "Linux/Other"),
            "ip_address": reg_data.get("ip_address", "Auto-Detected"),
            "registered_at": reg_data.get("registered_at", "N/A (Discovered)")
        }
        
        # IP Discovery for auto-detected hosts
        if agent_data["ip_address"] == "Auto-Detected":
            latest = db.alerts.find_one({"$or": [{"agent.name": hostname}, {"agent_name": hostname}]}, sort=[("timestamp", -1)])
            if latest:
                agent_data["ip_address"] = latest.get("agent", {}).get("ip") or latest.get("ip") or "Unknown"

        # Risk & Health Scoring
        host_query = {"$or": [{"agent.name": hostname}, {"agent_name": hostname}, {"hostname": hostname}]}
        crit = db.alerts.count_documents({**host_query, "$or": [{"org_risk": "Critical"}, {"severity": "Critical"}]})
        high = db.alerts.count_documents({**host_query, "$or": [{"org_risk": "High"}, {"severity": "High"}]})
        med = db.alerts.count_documents({**host_query, "$or": [{"org_risk": "Medium"}, {"severity": "Medium"}]})
        
        risk = (crit * 25) + (high * 10) + (med * 5)
        agent_data["health_score"] = max(0, 100 - risk)
        agent_data["critical_alerts"] = crit
        agent_data["total_alerts"] = db.alerts.count_documents(host_query)
        
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
        ai_data = json.loads(ai_response_str)
        
        # --- EXHAUSTIVE HEURISTIC SAFETY NET ---
        desc = data.get("rule", {}).get("description", "").lower()
        log_text = data.get("full_log", "").lower()
        combined_text = desc + " " + log_text
        
        intel_library = {
            "reverse shell": {"cve": "N/A", "cwe": "CWE-78, CWE-427", "cvss": 8.5, "cwss": 92.0, "actor": "Reverse Shell Operator"},
            "brute force": {"cve": "N/A", "cwe": "CWE-307, CWE-521", "cvss": 5.8, "cwss": 65.0, "actor": "Brute Force Botnet"},
            "eternalblue": {"cve": "CVE-2017-0144, CVE-2017-0145", "cwe": "CWE-119, CWE-254", "cvss": 9.8, "cwss": 98.0, "actor": "Shadow Brokers / WannaCry"},
            "proxylogon": {"cve": "CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065", "cwe": "CWE-20, CWE-287, CWE-502", "cvss": 9.8, "cwss": 95.0, "actor": "Hafnium Group"},
            "zerologon": {"cve": "CVE-2020-1472", "cwe": "CWE-287, CWE-326", "cvss": 10.0, "cwss": 100.0, "actor": "Domain Controller Exploit"},
            "log4j": {"cve": "CVE-2021-44228, CVE-2021-45046", "cwe": "CWE-502, CWE-400, CWE-917", "cvss": 10.0, "cwss": 100.0, "actor": "APT Intruder"},
            "log4shell": {"cve": "CVE-2021-44228, CVE-2021-45046", "cwe": "CWE-502, CWE-400, CWE-917", "cvss": 10.0, "cwss": 100.0, "actor": "APT Intruder"},
            "solarwinds": {"cve": "CVE-2020-10148, CVE-2020-10189", "cwe": "CWE-494, CWE-506", "cvss": 9.8, "cwss": 98.0, "actor": "Sunburst APT"},
            "f5 big-ip": {"cve": "CVE-2020-5902, CVE-2021-22986", "cwe": "CWE-22, CWE-77", "cvss": 9.8, "cwss": 95.0, "actor": "F5 Exploiter"},
            "printnightmare": {"cve": "CVE-2021-34527", "cwe": "CWE-427, CWE-269", "cvss": 8.8, "cwss": 90.0, "actor": "Privilege Escalator"},
            "spring4shell": {"cve": "CVE-2022-22965", "cwe": "CWE-119", "cvss": 9.8, "cwss": 95.0, "actor": "Spring Core Exploiter"},
            "solarwinds": {"cve": "CVE-2020-10148", "cwe": "CWE-494", "cvss": 9.8, "cwss": 95.0, "actor": "Sunburst APT"},
            "mimikatz": {"cve": "N/A", "cwe": "CWE-259", "cvss": 7.5, "cwss": 85.0, "actor": "Credential Thief"},
            "lockbit": {"cve": "N/A", "cwe": "CWE-200", "cvss": 9.8, "cwss": 98.0, "actor": "LockBit Ransomware Group"},
            "mbr destruction": {"cve": "N/A", "cwe": "CWE-676", "cvss": 9.0, "cwss": 95.0, "actor": "Data Wiper / NotPetya"},
            "dns tunneling": {"cve": "N/A", "cwe": "CWE-200", "cvss": 6.5, "cwss": 75.0, "actor": "Exfiltration Specialist"},
            "sql injection": {"cve": "N/A", "cwe": "CWE-89", "cvss": 7.5, "cwss": 82.0, "actor": "Web Application Exploiter"},
            "port scan": {"cve": "N/A", "cwe": "CWE-200", "cvss": 4.5, "cwss": 45.0, "actor": "Reconnaissance Bot"},
            "xss": {"cve": "N/A", "cwe": "CWE-79", "cvss": 6.1, "cwss": 65.0, "actor": "Script Kiddie"},
            "cross-site scripting": {"cve": "N/A", "cwe": "CWE-79", "cvss": 6.1, "cwss": 65.0, "actor": "Script Kiddie"}
        }

        # Initial assignments from AI
        actor = ai_data.get("threat_actor", "Unknown")
        vector = ai_data.get("attack_vector", "Unknown")
        
        # Apply safety net if AI was vague or missing IDs
        for key, intel in intel_library.items():
            # Robust check in both description and full log
            if key in combined_text or key.replace(" ", "") in combined_text.replace(" ", ""):
                if actor == "Unknown" or actor == "Unknown Actor":
                    actor = intel["actor"]
                if vector == "Unknown" or vector == "Unknown Vector":
                    vector = key.upper()
                
                # Force update scores if they are missing or N/A
                current_cve = ai_data.get("cve_id", "N/A")
                current_cwe = ai_data.get("cwe_id", "N/A")
                
                if current_cve == "N/A" or not current_cve or current_cve == "":
                    ai_data["cve_id"] = intel["cve"]
                if current_cwe == "N/A" or not current_cwe or current_cwe == "":
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

        data["attack_type"] = vector if actor == "Unknown" else actor
        data["mitre_tactic"] = vector
        data["mitre_technique"] = ai_data.get("mitre_technique_id", "N/A")
        data["mitre_technique_name"] = ai_data.get("mitre_technique_name", "N/A")
        
        data["cve_id"] = ai_data.get("cve_id", "N/A")
        data["cwe_id"] = ai_data.get("cwe_id", "N/A")
        data["cvss_score"] = f"{cvss:.1f}"
        data["cwss_score"] = f"{cwss:.1f}"
        
        data["org_risk"] = org_sev
        data["severity"] = org_sev
        
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