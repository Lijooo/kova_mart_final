import unittest
import os
import sys

# Disable background generator for tests
os.environ["ENABLE_BACKGROUND_GENERATOR"] = "false"

# Import app_server test client
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import app_server

class TestTransactionsPagination(unittest.TestCase):
    def setUp(self):
        self.app = app_server.app.test_client()
        self.app.testing = True
        self.api_key = "kova_secret_api_key_2026"
        self.headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key
        }

    def test_default_pagination(self):
        # Fetch without parameters (should default to page=1, limit=12)
        res = self.app.get("/api/transactions", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        
        self.assertEqual(data["status"], "success")
        self.assertIn("total_records", data)
        self.assertIn("total_pages", data)
        self.assertEqual(data["current_page"], 1)
        self.assertIn("rows", data)
        
        # Verify limit of 12 rows
        self.assertLessEqual(len(data["rows"]), 12)
        
        # Verify transaction_id format for every row
        for row in data["rows"]:
            self.assertIn("transaction_id", row)
            self.assertTrue(row["transaction_id"].startswith("TX-"))
            self.assertEqual(len(row["transaction_id"]), 7) # TX-0001 is 7 characters

    def test_limit_all(self):
        # Fetch with limit=-1
        res = self.app.get("/api/transactions?limit=-1", headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["rows"]), data["total_records"])
        self.assertEqual(data["total_pages"], 1)

    def test_searching_by_transaction_id(self):
        # 1. Get first transaction ID from database
        res_all = self.app.get("/api/transactions?limit=1", headers=self.headers)
        self.assertEqual(res_all.status_code, 200)
        first_tx = res_all.get_json()["rows"][0]
        tx_id_str = first_tx["transaction_id"]
        
        # 2. Search for that specific transaction ID
        res_search = self.app.get(f"/api/transactions?search={tx_id_str}", headers=self.headers)
        self.assertEqual(res_search.status_code, 200)
        search_rows = res_search.get_json()["rows"]
        
        self.assertGreaterEqual(len(search_rows), 1)
        self.assertEqual(search_rows[0]["transaction_id"], tx_id_str)

    def test_filtering_and_sorting(self):
        # 1. Risk Level Filter
        res_risk = self.app.get("/api/transactions?risk_level=🔴 CRITICAL", headers=self.headers)
        self.assertEqual(res_risk.status_code, 200)
        for row in res_risk.get_json()["rows"]:
            self.assertEqual(row["level"], "CRITICAL")
            
        # 2. Status Filter
        res_status = self.app.get("/api/transactions?status=approved", headers=self.headers)
        self.assertEqual(res_status.status_code, 200)
        for row in res_status.get_json()["rows"]:
            self.assertEqual(row["status"], "approved")

        # 3. Channel Filter
        res_channel = self.app.get("/api/transactions?channel=1", headers=self.headers)
        self.assertEqual(res_channel.status_code, 200)
        for row in res_channel.get_json()["rows"]:
            self.assertEqual(row["app(0) vs kiosk(1)transaction"], 1)

        # 4. Sorting
        res_sort_asc = self.app.get("/api/transactions?sort_by=transaction_amount&sort_dir=asc&limit=5", headers=self.headers)
        res_sort_desc = self.app.get("/api/transactions?sort_by=transaction_amount&sort_dir=desc&limit=5", headers=self.headers)
        
        self.assertEqual(res_sort_asc.status_code, 200)
        self.assertEqual(res_sort_desc.status_code, 200)
        
        amt_asc = [r["transaction_amount"] for r in res_sort_asc.get_json()["rows"]]
        amt_desc = [r["transaction_amount"] for r in res_sort_desc.get_json()["rows"]]
        
        if len(amt_asc) > 1:
            self.assertTrue(all(amt_asc[i] <= amt_asc[i+1] for i in range(len(amt_asc)-1)))
        if len(amt_desc) > 1:
            self.assertTrue(all(amt_desc[i] >= amt_desc[i+1] for i in range(len(amt_desc)-1)))

if __name__ == "__main__":
    unittest.main()
