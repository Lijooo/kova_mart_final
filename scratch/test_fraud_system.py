import unittest
import json
import time
import sqlite3
import os
import csv
from datetime import datetime

# Disable the background generator thread for test execution
os.environ["ENABLE_BACKGROUND_GENERATOR"] = "false"

# Import the app to use its test client
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import app_server

class TestFraudDetectionSystem(unittest.TestCase):
    def setUp(self):
        self.app = app_server.app.test_client()
        self.app.testing = True
        self.api_key = "kova_secret_api_key_2026"
        self.headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key
        }
        
        # Helper payload templates
        self.low_risk_payload = {
            "customer_id": 1,
            "initial_subsidy": 1000000.0,
            "transaction_amount": 5000.0,
            "subsidy_balance": 995000.0,
            "hour_of_day": 12,
            "num_items": 1,
            "repeated_product_purchase": 0,
            "same_product_transaction_count_month": 1,
            "previous_transactions": 5,
            "is_first_transaction": 0,
            "national_id_verification": 1,
            "kks_card_validation": 1,
            "duplicate_account_detection": 0,
            "transaction_frequency_high": 0,
            "valid_card": 1,
            "ip_outside_indonesia": 0,
            "app_vs_kiosk": 0,
            "failed_login_attempts": 0,
            "payment_retry_count": 0,
            "same_device_multiple_accounts": 0,
            "login_location_changed": 0
        }
        
        # High-risk payload (triggers C1: Foreign IP + Duplicate Account -> BLOCK/CRITICAL)
        self.high_risk_payload = dict(self.low_risk_payload)
        self.high_risk_payload.update({
            "duplicate_account_detection": 1,
            "ip_outside_indonesia": 1,
            "customer_id": 2
        })
        
        # Medium-risk payload (triggers C12: Unverified ID + Invalid KKS + Invalid Card -> REVIEW)
        self.medium_risk_payload = dict(self.low_risk_payload)
        self.medium_risk_payload.update({
            "national_id_verification": 0,
            "kks_card_validation": 0,
            "valid_card": 0,
            "customer_id": 3
        })

    def test_api_authentication(self):
        # 1. Test score endpoint without API key
        res = self.app.post("/api/fraud/score", json=self.low_risk_payload)
        self.assertEqual(res.status_code, 401)
        self.assertIn("Unauthorized", res.get_json()["message"])
        
        # 2. Test checkout endpoint without API key
        res = self.app.post("/api/checkout", json=self.low_risk_payload)
        self.assertEqual(res.status_code, 401)
        
        # 3. Test feedback endpoint with invalid token
        res = self.app.post("/api/fraud/feedback", json={}, headers={"Authorization": "Bearer bad_token"})
        self.assertEqual(res.status_code, 401)

    def test_input_validation(self):
        # Test negative amount
        payload = dict(self.low_risk_payload)
        payload["transaction_amount"] = -100.0
        res = self.app.post("/api/fraud/score", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("must be a non-negative number", res.get_json()["message"])
        
        # Test invalid binary value
        payload = dict(self.low_risk_payload)
        payload["is_first_transaction"] = 3
        res = self.app.post("/api/fraud/score", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("must be 0 or 1", res.get_json()["message"])

    def test_fraud_scoring_categories(self):
        # 1. LOW Risk (APPROVE)
        res = self.app.post("/api/fraud/score", json=self.low_risk_payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["decision"], "APPROVE")
        self.assertEqual(data["allow_transaction"], True)
        self.assertEqual(data["risk_category"], "LOW")
        
        # 2. MEDIUM Risk (REVIEW)
        res = self.app.post("/api/fraud/score", json=self.medium_risk_payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["decision"], "REVIEW")
        self.assertEqual(data["allow_transaction"], False)
        self.assertEqual(data["risk_category"], "MEDIUM")
        
        # 3. CRITICAL Risk (BLOCK)
        res = self.app.post("/api/fraud/score", json=self.high_risk_payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["decision"], "BLOCK")
        self.assertEqual(data["allow_transaction"], False)
        self.assertEqual(data["risk_category"], "CRITICAL")

    def test_checkout_policies(self):
        # 1. Test APPROVE Checkout completes and deducts subsidy
        conn = app_server.database.get_db_connection()
        cursor = conn.cursor()
        customer_id = 1
        cursor.execute("UPDATE members SET verification_status = 'Verified' WHERE id = ?", (customer_id,))
        # Find latest balance of member 1
        cursor.execute("SELECT subsidy_balance FROM transactions WHERE customer_id = ? AND status = 'approved' ORDER BY id DESC LIMIT 1", (customer_id,))
        row = cursor.fetchone()
        current_bal = float(row["subsidy_balance"]) if row else 1000000.0
        conn.commit()
        conn.close()
        
        payload = dict(self.low_risk_payload)
        payload["customer_id"] = customer_id
        payload["initial_subsidy"] = current_bal
        payload["transaction_amount"] = 1000.0
        
        res = self.app.post("/api/checkout", json=payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["remaining_subsidy"], round(current_bal - 1000.0, 2))
        
        # Verify in DB
        conn = app_server.database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT subsidy_balance, status FROM transactions ORDER BY id DESC LIMIT 1")
        db_tx = cursor.fetchone()
        self.assertEqual(db_tx["status"], "approved")
        self.assertEqual(db_tx["subsidy_balance"], round(current_bal - 1000.0, 2))
        conn.close()

        # 2. Test BLOCK/REVIEW Checkout fails with support message and doesn't deduct
        payload_blocked = dict(self.high_risk_payload)
        payload_blocked["customer_id"] = customer_id
        payload_blocked["initial_subsidy"] = round(current_bal - 1000.0, 2)
        payload_blocked["transaction_amount"] = 5000.0
        
        res = self.app.post("/api/checkout", json=payload_blocked, headers=self.headers)
        self.assertEqual(res.status_code, 403)
        data = res.get_json()
        self.assertEqual(data["status"], "blocked")
        self.assertEqual(data["message"], "This purchase could not be completed because additional verification is required. Please contact support.")
        
        # Verify balance is not modified
        conn = app_server.database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT subsidy_balance, status FROM transactions WHERE customer_id = ? AND status = 'approved' ORDER BY id DESC LIMIT 1", (customer_id,))
        self.assertEqual(float(cursor.fetchone()["subsidy_balance"]), round(current_bal - 1000.0, 2))
        conn.close()

    def test_feedback_loop(self):
        feedback_payload = {
            "transaction_id": f"TX-TEST-{int(time.time())}",
            "model_decision": "BLOCK",
            "auditor_decision": "CONFIRMED",
            "confirmed_label": "fraud",
            "notes": "Test feedback loop notes.",
            "reviewed_by": "Test Tester",
            "reviewed_at": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        }
        
        res = self.app.post("/api/fraud/feedback", json=feedback_payload, headers=self.headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["status"], "success")
        
        # Verify in database
        conn = app_server.database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM fraud_feedback WHERE transaction_id = ?", (feedback_payload["transaction_id"],))
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["confirmed_label"], "fraud")
        conn.close()
        
        # Verify in retraining dataset CSV
        csv_path = os.path.join(os.path.dirname(os.path.abspath(app_server.__file__)), "retraining_feedback_dataset.csv")
        self.assertTrue(os.path.exists(csv_path))
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            self.assertTrue(any(r["transaction_id"] == feedback_payload["transaction_id"] for r in rows))

    def test_rate_limiting(self):
        # Trigger multiple fast requests
        payload = dict(self.low_risk_payload)
        for i in range(70):
            res = self.app.post("/api/fraud/score", json=payload, headers=self.headers)
            if res.status_code == 429:
                break
        self.assertEqual(res.status_code, 429)
        self.assertIn("Rate limit exceeded", res.get_json()["message"])

if __name__ == "__main__":
    unittest.main()
