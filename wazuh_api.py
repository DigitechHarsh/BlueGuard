import requests
import urllib3
import time
import json

urllib3.disable_warnings()

# Wazuh Indexer runs on port 9200 for searching alerts.
WAZUH_INDEXER_URL = "https://192.168.6.129:9200"

# Default OVA credentials for the Indexer are usually admin/admin or admin/SecretPassword
INDEXER_USER = "admin"
INDEXER_PASS = "admin" 

WEBHOOK_URL = "http://127.0.0.1:5000/webhook"

seen_alerts = set()

def get_alerts():
    try:
        # Query to fetch the latest alerts from the last 1 minute
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": "now-1m"
                    }
                }
            },
            "sort": [
                {"timestamp": {"order": "desc"}}
            ],
            "size": 10
        }

        response = requests.post(
            f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
            auth=(INDEXER_USER, INDEXER_PASS),
            json=query,
            verify=False
        )
        response.raise_for_status()
        
        # OpenSearch wraps the actual alert inside nested JSON, so we extract it:
        hits = response.json().get('hits', {}).get('hits', [])
        alerts = [hit['_source'] for hit in hits]
        return alerts

    except Exception as e:
        print("Indexer API Error fetching alerts. Check if Password is correct:", e)
        return []

def send_to_webhook(alert):
    try:
        response = requests.post(
            WEBHOOK_URL,
            json=alert,
            headers={"Content-Type": "application/json"}
        )
        if response.status_code == 200:
            print(f"Successfully forwarded alert {alert.get('id', 'Unknown')} to webhook.")
        else:
            print(f"Failed to forward alert. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending alert to webhook: {e}")

def main():
    print("Starting BlueGuard Wazuh Indexer Poller...")
    
    while True:
        try:
            alerts = get_alerts()
            
            # Process oldest first to maintain chronological order
            for alert in reversed(alerts):
                # Using a fallback ID if 'id' key is missing in the source
                alert_id = alert.get('id', f"{alert.get('timestamp')}-{alert.get('rule', {}).get('id')}")
                
                if alert_id not in seen_alerts:
                    print(f"Detected new alert: {alert_id} - {alert.get('rule', {}).get('description', 'Unknown')}")
                    # Assign the ID back to the alert object if it was a fallback
                    alert['id'] = alert_id
                    send_to_webhook(alert)
                    seen_alerts.add(alert_id)
            
            # To prevent memory leak, keep seen_alerts bounded
            if len(seen_alerts) > 5000:
                print("Clearing old seen alerts cache...")
                seen_alerts.clear()

            time.sleep(5)  # Poll every 5 seconds
            
        except KeyboardInterrupt:
            print("\nShutting down poller.")
            break
        except Exception as e:
            print(f"Unexpected error in polling loop: {e}")
            time.sleep(10)

if __name__ == '__main__':
    main()
