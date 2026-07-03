import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kovamart.db")
print("Database file path:", DB_PATH)
print("File size:", os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else "Not found")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute("SELECT COUNT(*) FROM transactions")
tx_count = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM members")
member_count = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM alerts")
alert_count = cursor.fetchone()[0]

cursor.execute("SELECT severity_level, status, COUNT(*) FROM alerts GROUP BY severity_level, status")
alert_breakdown = cursor.fetchall()

print("Transactions Count:", tx_count)
print("Members Count:", member_count)
print("Alerts Count:", alert_count)
print("Alerts Breakdown:", alert_breakdown)

cursor.execute("SELECT id, status FROM transactions ORDER BY id DESC LIMIT 10")
latest_tx = cursor.fetchall()
print("Latest 10 transactions status:", latest_tx)

conn.close()
