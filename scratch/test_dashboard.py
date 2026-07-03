import urllib.request
import json
import urllib.parse

def call_dashboard():
    url = "http://127.0.0.1:50001/api/dashboard"
    req = urllib.request.Request(url, headers={"X-API-Key": "kova_secret_api_key_2026"})
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode())

try:
    print("Querying /api/dashboard endpoint...")
    data = call_dashboard()
    print("Response keys:", list(data.keys()))
    
    assert data["status"] == "success", "Expected status to be success"
    assert "rows" in data, "Expected 'rows' in response"
    assert "summary" in data, "Expected 'summary' in response"
    assert "chart_data" in data, "Expected 'chart_data' in response"
    assert "combinations" in data, "Expected 'combinations' in response"
    assert "model_status" in data, "Expected 'model_status' in response"
    assert "dataset_path" in data, "Expected 'dataset_path' in response"
    
    rows = data["rows"]
    summary = data["summary"]
    metrics = summary["metrics"]
    
    print(f"Number of rows returned: {len(rows)}")
    print(f"Summary total_transactions: {metrics['total_transactions']}")
    print(f"Summary average_risk_score: {metrics['average_risk_score']}")
    print(f"Summary total_members: {metrics['total_members']}")
    print(f"Summary flagged_members: {metrics['flagged_members']}")
    print(f"Summary critical_alerts: {metrics['critical_alerts']}")
    print(f"Model status: {data['model_status']}")
    print(f"Dataset path: {data['dataset_path']}")
    
    assert len(rows) == metrics["total_transactions"], f"Mismatch! rows count is {len(rows)} but summary total_transactions is {metrics['total_transactions']}"
    assert len(rows) <= 1500, f"Expected rows count <= 1500, got {len(rows)}"
    
    # Check that transaction_id is NOT in the row, and customer_id is present
    for row in rows[:5]:
        assert "transaction_id" not in row, "Error: transaction_id must not be present in rows"
        assert "customer_id" in row, "Error: customer_id must be present in rows"
        
    print("SUCCESS: Unified /api/dashboard endpoint is fully functional and consistent!")
except Exception as e:
    print("ERROR testing dashboard endpoint:")
    import traceback
    traceback.print_exc()
