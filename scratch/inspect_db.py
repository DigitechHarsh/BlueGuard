from pymongo import MongoClient
import os
from dotenv import load_dotenv
import json

load_dotenv()
client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017/"))
db = client.blueguard_db
doc = db.vulnerabilities.find_one()

if doc:
    # Convert ObjectId to string for printing
    doc['_id'] = str(doc['_id'])
    print(json.dumps(doc, indent=4))
else:
    print("No documents found in vulnerabilities collection.")
