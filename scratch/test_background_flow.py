import os
import sys
import time
import unittest

# Ensure the parent directory is in the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set test environment variables
os.environ["ENABLE_BACKGROUND_GENERATOR"] = "True"
os.environ["BACKGROUND_GENERATOR_INTERVAL"] = "1"

import app_server

class TestBackgroundGeneratorFlow(unittest.TestCase):
    def setUp(self):
        self.app = app_server.app.test_client()
        # Trigger the first request to start the background thread via before_request
        self.app.get('/')
        
    def test_background_flow(self):
        # 1. Wait a bit to ensure the generator thread starts and makes at least one transaction
        time.sleep(2.5)
        
        # 2. Query /api/status
        resp_status = self.app.get('/api/status')
        self.assertEqual(resp_status.status_code, 200)
        data_status = resp_status.get_json()
        print("\n--- /api/status Response ---")
        print(data_status)
        
        bg_status = data_status.get("background_generator")
        self.assertIsNotNone(bg_status)
        self.assertTrue(bg_status.get("enabled"))
        self.assertEqual(bg_status.get("interval_seconds"), 1.0)
        self.assertGreater(bg_status.get("generated_count"), 0)
        self.assertIsNotNone(bg_status.get("last_generated_customer_id"))
        self.assertIsNotNone(bg_status.get("last_generated_at"))
        
        # 3. Query /api/dashboard
        resp_db = self.app.get('/api/dashboard')
        self.assertEqual(resp_db.status_code, 200)
        data_db = resp_db.get_json()
        
        bg_db = data_db.get("background_generator")
        self.assertIsNotNone(bg_db)
        self.assertEqual(bg_db.get("generated_count"), bg_status.get("generated_count"))
        
        print("\nVerification successful! Background generator thread correctly creates transactions and updates stats.")

if __name__ == '__main__':
    unittest.main()
