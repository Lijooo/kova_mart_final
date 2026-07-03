import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kovamart.db")

print("Connecting to:", DB_PATH)
conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Get initial counts
cursor.execute("SELECT COUNT(*) FROM transactions")
before_tx = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM members")
before_m = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM alerts")
before_a = cursor.fetchone()[0]

# Perform cleanup (keep only first 1000 seeded items)
cursor.execute("DELETE FROM transactions WHERE id > 1000")
cursor.execute("DELETE FROM members WHERE id > 1000")

cursor.execute("DELETE FROM alerts WHERE (target_type = 'transaction' AND target_id > 1000) OR (target_type = 'member' AND target_id > 1000) OR customer_id > 1000")
cursor.execute("DELETE FROM risk_scores WHERE (target_type = 'transaction' AND target_id > 1000) OR (target_type = 'member' AND target_id > 1000)")
cursor.execute("DELETE FROM audit_logs WHERE (target_type = 'transaction' AND target_id > 1000) OR (target_type = 'member' AND target_id > 1000)")
cursor.execute("DELETE FROM fraud_scoring_logs")
cursor.execute("DELETE FROM fraud_feedback")

conn.commit()

# Get final counts
cursor.execute("SELECT COUNT(*) FROM transactions")
after_tx = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM members")
after_m = cursor.fetchone()[0]
cursor.execute("SELECT COUNT(*) FROM alerts")
after_a = cursor.fetchone()[0]

print("CLEANUP COMPLETED:")
print(f"Transactions: {before_tx} -> {after_tx}")
print(f"Members: {before_m} -> {after_m}")
print(f"Alerts: {before_a} -> {after_a}")

conn.close()
