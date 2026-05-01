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
    limit = 10
    
    # Get alerts for charts (top 200 for stats)
    all_alerts_for_stats, _ = get_filtered_alerts(agent_filter, start_time, end_time, limit=200)
    
    # Get paginated alerts for table
    alerts_list, total_count = get_filtered_alerts(agent_filter, start_time, end_time, page=page, limit=limit)
    
    stats = {
        "total": total_count,
        "critical": sum(1 for a in all_alerts_for_stats if a.get("severity") == "Critical"),
        "high": sum(1 for a in all_alerts_for_stats if a.get("severity") == "High")
    }
    
    from collections import Counter
    sev_counts = Counter([a.get("severity", "Unknown") for a in all_alerts_for_stats])
    att_counts = Counter([a.get("attack_type", "Unknown") for a in all_alerts_for_stats])
    agent_counts = Counter([a.get("agent", {}).get("name", "Unknown") for a in all_alerts_for_stats])
    
    chart_data = {
        "severities_labels": list(sev_counts.keys()),
        "severities_data": list(sev_counts.values()),
        "attack_labels": list(att_counts.keys()),
        "attack_data": list(att_counts.values()),
        "agent_labels": [k for k, v in agent_counts.most_common(5)],
        "agent_data": [v for k, v in agent_counts.most_common(5)],
    }

    # Note: We group the paginated list, or we could group everything and then paginate.
    # Grouping the paginated list might miss counts across pages.
    # Better: Group all filtered, then paginate grouped results.
    all_filtered_raw, _ = get_filtered_alerts(agent_filter, start_time, end_time, limit=1000)
    grouped_all = group_alerts_data(all_filtered_raw)
    
    # Paginate grouped data
    total_grouped = len(grouped_all)
    total_pages = (total_grouped + limit - 1) // limit
    paginated_grouped = grouped_all[(page-1)*limit : page*limit]
    
    available_agents = db.alerts.distinct("agent.name")
    
    return render_template("index.html", 
                           alerts=paginated_grouped, 
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

@app.route("/alerts", methods=["GET"])
def alerts_page():
    agent_filter = request.args.get("agent", "All")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")
    alerts_list, _ = get_filtered_alerts(agent_filter, start_time, end_time, limit=1000)
    available_agents = db.alerts.distinct("agent.name")
    return render_template("alerts.html", alerts=alerts_list, available_agents=available_agents, current_filter=agent_filter, current_start=start_time, current_end=end_time)

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json

    try:
        # Get JSON string from Gemini
        ai_response_str = classify_attack(data)
        ai_data = json.loads(ai_response_str)

        # Enrich alert with AI data
        data["attack_type"] = ai_data.get("attack_type", "Unknown")
        data["analysis"] = ai_data.get("analysis", "No analysis available.")
        data["severity"] = ai_data.get("severity", "Unknown")  # This is now the ORG-ADJUSTED severity
        data["remediation"] = ai_data.get("remediation", "No remediation suggested.")
        data["mitre_tactic"] = ai_data.get("mitre_tactic", "N/A")
        data["mitre_technique"] = ai_data.get("mitre_technique", "N/A")
        # New organizational risk assessment fields
        data["cve_cwe"] = ai_data.get("cve_cwe", "N/A")
        data["cvss_score"] = ai_data.get("cvss_score", "N/A")
        data["base_severity"] = ai_data.get("base_severity", "Unknown")
        data["org_risk_severity"] = ai_data.get("org_risk_severity", ai_data.get("severity", "Unknown"))
        data["org_risk_assessment"] = ai_data.get("org_risk_assessment", "No organizational risk assessment available.")
        
    except Exception as e:
        print(f"Error parsing AI response: {e}")
        data["attack_type"] = "Parsing Error"
        data["analysis"] = "Failed to parse AI output."
        data["severity"] = "Unknown"
        data["remediation"] = "Check logs."
        data["cve_cwe"] = "N/A"
        data["cvss_score"] = "N/A"
        data["base_severity"] = "Unknown"
        data["org_risk_severity"] = "Unknown"
        data["org_risk_assessment"] = "AI parsing failed. Manual assessment required."

    # Save to MongoDB Database instead of list
    db.alerts.insert_one(data)
    print(f"ALERT SAVED IN DB: {data['attack_type']} | Severity: {data['severity']}")
    
    # Trigger email asynchronously if severity is high or critical
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
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)