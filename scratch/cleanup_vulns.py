from pymongo import MongoClient
import os
from dotenv import load_dotenv
import certifi

load_dotenv()
ca = certifi.where()

try:
    client = MongoClient(os.getenv("MONGO_URI"), tlsCAFile=ca)
    db = client.blueguard_db
    
    # Delete all from vulnerabilities
    res1 = db.vulnerabilities.delete_many({})
    # Delete all from scans metadata
    res2 = db.nessus_scans.delete_many({})
    
    print(f"🧹 Database Cleaned Successfully!")
    print(f"🗑️ Deleted {res1.deleted_count} vulnerability records.")
    print(f"🗑️ Deleted {res2.deleted_count} scan metadata records.")
    
except Exception as e:
    print(f"❌ Error during cleanup: {e}")
