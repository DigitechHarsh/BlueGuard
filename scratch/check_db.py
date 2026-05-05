from pymongo import MongoClient
import json
from bson import json_util

client = MongoClient('mongodb://localhost:27017/')
db = client['blueguard_db']
alert = db.alerts.find_one()

print("--- ALERT STRUCTURE ---")
print(json.dumps(alert, indent=4, default=json_util.default))

agents_count = db.agents.count_documents({})
print(f"\nRegistered Agents Count: {agents_count}")

unique_agents = db.alerts.distinct("agent.name")
print(f"Unique Agent Names found in Alerts: {unique_agents}")
