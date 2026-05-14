"""
BlueGuard — Local MongoDB → Atlas Migration Script
====================================================
Migrates ALL collections from local MongoDB to Atlas.
Collections: alerts, cve_intelligence, tickets, users, vulnerabilities

Usage: python migrate_to_atlas.py
"""

import os
import pymongo
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# ─── Connections ──────────────────────────────────────────────────────────────
LOCAL_URI = "mongodb://localhost:27017/"
ATLAS_URI = os.getenv("MONGO_URI")

if not ATLAS_URI or "mongodb+srv" not in ATLAS_URI:
    print("❌ MONGO_URI not set or not an Atlas URI. Check your .env file.")
    exit(1)

print("=" * 62)
print("  🚀 BlueGuard: Local MongoDB → Atlas Migration")
print("=" * 62)

# Connect to both
try:
    local_client = pymongo.MongoClient(LOCAL_URI, serverSelectionTimeoutMS=5000)
    local_client.server_info()
    print("✅ Local MongoDB connected.")
except Exception as e:
    print(f"❌ Local MongoDB connection failed: {e}")
    exit(1)

try:
    atlas_client = pymongo.MongoClient(ATLAS_URI, serverSelectionTimeoutMS=15000)
    atlas_client.server_info()
    print("✅ MongoDB Atlas connected.")
except Exception as e:
    print(f"❌ Atlas connection failed: {e}")
    exit(1)

local_db = local_client.blueguard_db
atlas_db = atlas_client.blueguard_db

# ─── Collections to migrate ───────────────────────────────────────────────────
COLLECTIONS = [
    "alerts",
    "cve_intelligence",
    "tickets",
    "users",
    "vulnerabilities",
]

print(f"\n📦 Starting migration at {datetime.now().strftime('%H:%M:%S')}\n")

total_migrated = 0

for col_name in COLLECTIONS:
    local_col = local_db[col_name]
    atlas_col = atlas_db[col_name]

    # Count local docs
    local_count = local_col.count_documents({})
    if local_count == 0:
        print(f"  ⏭️  {col_name:<20} — empty, skipping")
        continue

    # Count already in Atlas
    atlas_count = atlas_col.count_documents({})
    print(f"\n  📁 {col_name}")
    print(f"     Local : {local_count:,} documents")
    print(f"     Atlas : {atlas_count:,} documents (existing)")

    # Fetch all local docs in batches
    BATCH_SIZE = 500
    cursor     = local_col.find({})
    batch      = []
    inserted   = 0
    skipped    = 0

    for doc in cursor:
        batch.append(doc)
        if len(batch) >= BATCH_SIZE:
            # Upsert batch
            ops = [
                pymongo.UpdateOne(
                    {"_id": d["_id"]},
                    {"$set": d},
                    upsert=True
                )
                for d in batch
            ]
            try:
                result = atlas_col.bulk_write(ops, ordered=False)
                inserted += result.upserted_count + result.modified_count
            except Exception as e:
                print(f"     ⚠️  Batch error: {e}")
            batch = []

    # Remaining batch
    if batch:
        ops = [
            pymongo.UpdateOne({"_id": d["_id"]}, {"$set": d}, upsert=True)
            for d in batch
        ]
        try:
            result = atlas_col.bulk_write(ops, ordered=False)
            inserted += result.upserted_count + result.modified_count
        except Exception as e:
            print(f"     ⚠️  Final batch error: {e}")

    total_migrated += inserted
    print(f"     ✅ Migrated: {inserted:,} → Atlas now has {atlas_col.count_documents({}):,} docs")

print("\n" + "=" * 62)
print(f"  ✅ MIGRATION COMPLETE!")
print(f"  📊 Total documents migrated: {total_migrated:,}")
print(f"  ☁️  All data now on MongoDB Atlas!")
print(f"  🔗 Check: cloud.mongodb.com → Cluster0 → Browse Collections")
print("=" * 62)
