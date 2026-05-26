import os, certifi
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
client = MongoClient(os.getenv('MONGO_URI'), tlsCAFile=certifi.where())
db = client.blueguard_db
v = db.vulnerabilities.find_one({'vuln_name': {'$regex': 'kernel'}})
print(v)
