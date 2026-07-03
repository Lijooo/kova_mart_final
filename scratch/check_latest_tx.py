import urllib.request
import json
import urllib.parse

def call_api(params):
    query = urllib.parse.urlencode(params)
    url = f"http://127.0.0.1:50001/api/transactions?{query}"
    req = urllib.request.Request(url, headers={"X-API-Key": "kova_secret_api_key_2026"})
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode())

# 1. Fetch transactions with limit = -1 (all)
data = call_api({"limit": -1})

if data["status"] == "success":
    rows = data["rows"]
    print(f"Total records returned: {len(rows)}")
    print(f"Total records according to metadata: {data['total_records']}")
    
    # 2. Check for duplicate customer IDs
    customer_ids = [r["customer_id"] for r in rows]
    unique_customer_ids = set(customer_ids)
    print(f"Unique customer IDs: {len(unique_customer_ids)}")
    print(f"Duplicate customer IDs count: {len(customer_ids) - len(unique_customer_ids)}")
    
    # Assert no duplicate customer IDs
    assert len(customer_ids) == len(unique_customer_ids), "Error: found duplicate customer IDs in dashboard data!"
    print("Success: Verified that all returned customer IDs are unique!")
    
    # 3. Verify pagination
    data_paginated = call_api({"limit": 12, "page": 1})
    print(f"Page 1 records returned: {len(data_paginated['rows'])}")
    print(f"Total pages: {data_paginated['total_pages']}")
    print(f"Current page: {data_paginated['current_page']}")
    
    if len(rows) > 12:
        data_page2 = call_api({"limit": 12, "page": 2})
        print(f"Page 2 records returned: {len(data_page2['rows'])}")
        print(f"Current page: {data_page2['current_page']}")
        
        # Make sure page 1 and page 2 don't overlap
        p1_ids = [r["id"] for r in data_paginated["rows"]]
        p2_ids = [r["id"] for r in data_page2["rows"]]
        overlap = set(p1_ids).intersection(set(p2_ids))
        print(f"Overlap between page 1 and page 2: {overlap}")
        assert len(overlap) == 0, "Error: Overlapping transactions found between pages!"
        print("Success: Verified pagination paging is disjoint!")
else:
    print("Failed to get transactions:", data)
