import requests
import urllib3
import json

urllib3.disable_warnings()

# Configuration (Matching wazuh_api.py)
WAZUH_INDEXER_URL = "https://192.168.6.129:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "admin" 

def test_connection():
    print(f"--- Testing Connection to {WAZUH_INDEXER_URL} ---")
    try:
        # 1. Test basic connectivity
        resp = requests.get(WAZUH_INDEXER_URL, auth=(INDEXER_USER, INDEXER_PASS), verify=False, timeout=5)
        print(f"Success! Indexer Response: {resp.status_code}")
        print(f"Indexer Version Info: {resp.json().get('version', {}).get('number', 'Unknown')}")
        
        # 2. Check total alert count
        print("\n--- Checking Total Alerts Count ---")
        count_url = f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_count"
        count_resp = requests.get(count_url, auth=(INDEXER_USER, INDEXER_PASS), verify=False)
        print(f"Total Alerts in Indexer: {count_resp.json().get('count', 0)}")
        
        # 3. Check for alerts in the last 24 hours (to rule out time sync issues)
        print("\n--- Searching for alerts in the last 24 hours ---")
        search_url = f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search"
        query = {
            "query": {
                "range": {
                    "timestamp": { "gte": "now-24h" }
                }
            },
            "size": 1
        }
        search_resp = requests.post(search_url, auth=(INDEXER_USER, INDEXER_PASS), json=query, verify=False)
        hits = search_resp.json().get('hits', {}).get('total', {}).get('value', 0)
        print(f"Alerts found in last 24 hours: {hits}")
        
    except Exception as e:
        print(f"FAILED: {e}")

if __name__ == "__main__":
    test_connection()
