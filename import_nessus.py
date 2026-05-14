import csv
import os
import pymongo
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

# MongoDB Connection
client = pymongo.MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
db = client.blueguard_db
vuln_col = db.vulnerabilities

def import_nessus_csv(file_path):
    print(f"Reading Nessus CSV: {file_path}")
    count = 0
    with open(file_path, mode='r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Cleanup and normalize data
            doc = {
                "asset_name": row.get("asset.name", "Unknown"),
                "cve_id": row.get("definition.cve", "N/A"),
                "cwe_id": row.get("definition.cwe", "N/A"),
                "vuln_name": row.get("definition.name", "N/A"),
                "nessus_severity": row.get("severity", "Low"),
                "vpr_score": row.get("definition.vpr_v2.score", "0.0"),
                "age": row.get("age_in_days", "0"),
                "last_seen": row.get("last_seen", ""),
                "state": row.get("state", "ACTIVE"),
                "imported_at": datetime.utcnow().isoformat()
            }
            # Insert into MongoDB
            vuln_col.update_one({"id": row.get("id")}, {"$set": doc}, upsert=True)
            count += 1
    
    print(f"✅ Successfully imported {count} vulnerabilities into MongoDB.")

if __name__ == "__main__":
    CSV_FILE = "vulnerabilities-04_27_2026_-17_56_32-gmt_5_30.csv"
    import_nessus_csv(CSV_FILE)
