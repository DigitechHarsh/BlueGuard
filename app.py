from flask import Flask, request, jsonify, render_template, session, redirect, url_for, Response
import csv
import io
import re
from analyzer import classify_attack
from notifier import send_critical_alert_email
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
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

# ----- AUTHENTICATION ROUTES -----

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        if not username or not password:
            return render_template("login.html", error="Please enter both username and password")
            
        user = db.users.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            session['user'] = username
            session['role'] = user.get("role", "Analyst")
            return redirect(url_for("home"))
        else:
            return render_template("login.html", error="Invalid Username or Password")
            
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "").strip()
        
        # Validation
        if not username or not email or not password or not role:
            return render_template("register.html", error="All fields are required.")
            
        if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
            return render_template("register.html", error="Username must be 3-20 characters (alphanumeric/underscore).")
            
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return render_template("register.html", error="Please enter a valid email address.")
            
        if len(password) < 6:
            return render_template("register.html", error="Password must be at least 6 characters.")
            
        if role not in ["Tier 1 Analyst", "Tier 2 Responder", "SOC Manager"]:
            return render_template("register.html", error="Invalid role selection.")
            
        if db.users.find_one({"username": username}):
            return render_template("register.html", error="Analyst ID is already taken.")
            
        hashed_pw = generate_password_hash(password)
        db.users.insert_one({
            "username": username,
            "email": email,
            "role": role,
            "password": hashed_pw,
            "created_at": datetime.datetime.now()
        })
        return render_template("login.html", msg="Registration successful. Clear to login.")

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ----- AGENT MANAGEMENT -----

@app.route("/agents", methods=["GET", "POST"])
def agents():
    if not session.get("user"):
        return redirect(url_for("login"))
        
    if session.get("role") != "SOC Manager":
        return "403 Forbidden: You do not have 'SOC Manager' clearance to view or modify Agents.", 403
        
    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip()
        os_type = request.form.get("os", "").strip()
        ip_address = request.form.get("ip_address", "").strip()
        
        # Validation
        if not hostname or not os_type or not ip_address:
            return "Please fill all fields", 400
            
        if not re.match(r"^[a-zA-Z0-9\-\.]{3,30}$", hostname):
            return "Invalid Hostname format", 400
            
        if not re.match(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)$", ip_address):
            return "Invalid IPv4 address", 400
            
        if os_type not in ["Windows", "Ubuntu", "CentOS"]:
            return "Invalid OS selection", 400
            
        db.agents.insert_one({
            "hostname": hostname,
            "os": os_type,
            "ip_address": ip_address,
            "registered_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        return redirect(url_for("agents"))
        
    agents_list = list(db.agents.find().sort("_id", -1))
    return render_template("agents.html", agents=agents_list)


# ----- CORE HELPER & ROUTES -----

def get_filtered_alerts(agent_filter=None, start_time=None, end_time=None):
    query = {}
    if agent_filter and agent_filter != "All":
        query["agent.name"] = agent_filter
        
    if start_time or end_time:
        query["timestamp"] = {}
        if start_time:
            # HTML datetime-local uses 'YYYY-MM-DDTHH:MM'. The Wazuh 'timestamp' uses similar ISO format.
            query["timestamp"]["$gte"] = start_time
        if end_time:
            query["timestamp"]["$lte"] = end_time
        
    cursor = db.alerts.find(query).sort("_id", -1).limit(200) # Prevents crashing memory
    alerts_list = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        alerts_list.append(doc)
    return alerts_list

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
    if not session.get("user"):
        return redirect(url_for("login"))
        
    agent_filter = request.args.get("agent", "All")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")
    alerts_list = get_filtered_alerts(agent_filter, start_time, end_time)
    
    stats = {
        "total": len(alerts_list),
        "critical": sum(1 for a in alerts_list if a.get("severity") == "Critical"),
        "high": sum(1 for a in alerts_list if a.get("severity") == "High")
    }
    
    from collections import Counter
    sev_counts = Counter([a.get("severity", "Unknown") for a in alerts_list])
    att_counts = Counter([a.get("attack_type", "Unknown") for a in alerts_list])
    
    # Calculate Ticket Stats
    ticket_status_list = [t.get("status", "Pending") for t in list(db.tickets.find({}, {"status": 1}))]
    ticket_counts = Counter(ticket_status_list)
    
    chart_data = {
        "severities_labels": list(sev_counts.keys()),
        "severities_data": list(sev_counts.values()),
        "attack_labels": list(att_counts.keys()),
        "attack_data": list(att_counts.values()),
        "ticket_labels": list(ticket_counts.keys()) if ticket_counts else ["Pending", "Investigating", "Resolved"],
        "ticket_data": list(ticket_counts.values()) if ticket_counts else [0, 0, 0]
    }

    grouped_alerts = group_alerts_data(alerts_list)
    available_agents = db.alerts.distinct("agent.name")
    
    return render_template("index.html", alerts=grouped_alerts, stats=stats, chart_data=chart_data, available_agents=available_agents, current_filter=agent_filter, current_start=start_time, current_end=end_time)

@app.route("/logs", methods=["GET"])
def logs():
    if not session.get("user"):
        return redirect(url_for("login"))
        
    agent_filter = request.args.get("agent", "All")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")
    alerts_list = get_filtered_alerts(agent_filter, start_time, end_time)
    grouped_alerts = group_alerts_data(alerts_list)
    available_agents = db.alerts.distinct("agent.name")
    
    return render_template("logs.html", alerts=grouped_alerts, available_agents=available_agents, current_filter=agent_filter, current_start=start_time, current_end=end_time)

@app.route("/alerts", methods=["GET"])
def alerts_page():
    if not session.get("user"):
        return redirect(url_for("login"))
        
    agent_filter = request.args.get("agent", "All")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")
    alerts_list = get_filtered_alerts(agent_filter, start_time, end_time)
    available_agents = db.alerts.distinct("agent.name")
    return render_template("alerts.html", alerts=alerts_list, available_agents=available_agents, current_filter=agent_filter, current_start=start_time, current_end=end_time)

@app.route("/get_tier2_users", methods=["GET"])
def get_tier2_users():
    if not session.get("user"):
        return jsonify([]), 401
    # Find all users with role 'Tier 2 Responder'
    users = list(db.users.find({"role": "Tier 2 Responder"}, {"username": 1, "_id": 0}))
    return jsonify([u["username"] for u in users])

@app.route("/tickets", methods=["GET", "POST"])
def tickets():
    if not session.get("user"):
        return redirect(url_for("login"))
    
    username = session.get("user")
    role = session.get("role")

    if request.method == "POST":
        alert_id = request.form.get("alert_id", "").strip()
        receiver = request.form.get("receiver", "").strip()
        priority = request.form.get("priority", "Medium").strip()
        subject = request.form.get("subject", "").strip()
        observations = request.form.get("observations", "").strip()
        
        # Validation
        if not alert_id or not receiver or not subject or not observations:
            return "Missing required reporting fields", 400
            
        if len(subject) < 5 or len(subject) > 100:
            return "Subject must be 5-100 characters", 400
            
        if len(observations) < 10 or len(observations) > 1000:
            return "Observations must be 10-1000 characters", 400
            
        if priority not in ["Low", "Medium", "High", "Critical"]:
            return "Invalid priority level", 400
        
        # Verify alert exists in DB
        from bson.objectid import ObjectId
        alert = db.alerts.find_one({"_id": ObjectId(alert_id)})
        if not alert:
            return "Alert not found", 404
            
        db.tickets.insert_one({
            "alert_id": alert_id,
            "sender": username,
            "receiver": receiver,
            "status": "Pending",
            "priority": priority,
            "subject": subject,
            "observations": observations,
            "resolution_notes": "",
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "alert_details": {
                "attack_type": alert.get("attack_type"),
                "severity": alert.get("severity"),
                "agent": alert.get("agent", {}).get("name"),
                "analysis": alert.get("analysis"),
                "remediation": alert.get("remediation"),
                "mitre_tactic": alert.get("mitre_tactic", "N/A"),
                "mitre_technique": alert.get("mitre_technique", "N/A")
            }
        })
        return redirect(url_for("tickets"))

    # Fetch tickets: 
    # Tier 1 sees what they sent; Tier 2 sees what was sent to them; Manager sees all.
    query = {}
    if role == "Tier 1 Analyst":
        query = {"sender": username}
    elif role == "Tier 2 Responder":
        query = {"receiver": username}
    
    all_tickets = list(db.tickets.find(query).sort("_id", -1))
    for t in all_tickets:
        t["_id"] = str(t["_id"])
        
    return render_template("tickets.html", tickets=all_tickets)

@app.route("/update_ticket/<ticket_id>", methods=["POST"])
def update_ticket(ticket_id):
    if not session.get("user") or session.get("role") != "Tier 2 Responder":
        return "Unauthorized", 403
        
    new_status = request.form.get("status")
    resolution_notes = request.form.get("resolution_notes", "")
    
    from bson.objectid import ObjectId
    update_data = {"status": new_status}
    if resolution_notes:
        update_data["resolution_notes"] = resolution_notes
        
    db.tickets.update_one({"_id": ObjectId(ticket_id)}, {"$set": update_data})
    return redirect(url_for("tickets"))

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
        data["severity"] = ai_data.get("severity", "Unknown")
        data["remediation"] = ai_data.get("remediation", "No remediation suggested.")
        data["mitre_tactic"] = ai_data.get("mitre_tactic", "N/A")
        data["mitre_technique"] = ai_data.get("mitre_technique", "N/A")
        
    except Exception as e:
        print(f"Error parsing AI response: {e}")
        data["attack_type"] = "Parsing Error"
        data["analysis"] = "Failed to parse AI output."
        data["severity"] = "Unknown"
        data["remediation"] = "Check logs."

    # Save to MongoDB Database instead of list
    db.alerts.insert_one(data)
    print(f"ALERT SAVED IN DB: {data['attack_type']} | Severity: {data['severity']}")
    
    # Trigger email asynchronously if severity is high or critical
    if data.get('severity') in ['Critical', 'High']:
        threading.Thread(target=send_critical_alert_email, args=(data,), daemon=True).start()

    return jsonify({"status": "received"}), 200

@app.route("/export_csv", methods=["GET"])
def export_csv():
    if not session.get("user"):
        return redirect(url_for("login"))
        
    agent_filter = request.args.get("agent", "All")
    start_time = request.args.get("start_time", "")
    end_time = request.args.get("end_time", "")
    
    alerts_list = get_filtered_alerts(agent_filter, start_time, end_time)
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Header Row
    writer.writerow(["Timestamp", "Severity", "Agent", "Attack Type", "Rule Description", "AI Analysis", "Remediation"])
    
    for alert in alerts_list:
        writer.writerow([
            alert.get("timestamp", "N/A"),
            alert.get("severity", "Unknown"),
            alert.get("agent", {}).get("name", "Unknown"),
            alert.get("attack_type", "Unknown"),
            alert.get("rule", {}).get("description", "N/A"),
            alert.get("analysis", "N/A"),
            alert.get("remediation", "N/A")
        ])
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=BlueGuard_Incident_Report.csv"}
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)