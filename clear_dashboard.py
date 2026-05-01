from pymongo import MongoClient

def clear_dashboard():
    try:
        print("Connecting to MongoDB...")
        client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
        db = client.blueguard_db
        
        # Count before deletion
        count = db.alerts.count_documents({})
        print(f"Found {count} alerts in the database.")
        
        # Delete all documents in the alerts collection
        result = db.alerts.delete_many({})
        print(f"✅ Successfully deleted {result.deleted_count} alerts.")
        print("Your dashboard is now completely clean!")
        
    except Exception as e:
        print(f"❌ Error clearing database: {e}")

if __name__ == "__main__":
    clear_dashboard()
