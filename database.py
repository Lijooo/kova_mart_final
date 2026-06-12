import sqlite3
import os
import json
import threading
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kovamart.db")
CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Kova_Mart_Dataset - Sheet1.csv")
DOCS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "documentation")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def db_init():
    # Ensure docs directory exists
    if not os.path.exists(DOCS_DIR):
        os.makedirs(DOCS_DIR)

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Create Members Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        nik TEXT UNIQUE NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        kks_card TEXT UNIQUE NOT NULL,
        address TEXT NOT NULL,
        registration_date TEXT NOT NULL,
        verification_status TEXT NOT NULL, -- 'Verified', 'Unverified', 'Flagged', 'Under Review'
        device_info TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 2. Create Transactions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        initial_subsidy REAL NOT NULL,
        transaction_amount REAL NOT NULL,
        subsidy_balance REAL NOT NULL,
        hour_of_day INTEGER NOT NULL,
        num_items INTEGER NOT NULL,
        repeated_product_purchase INTEGER NOT NULL,
        same_product_transaction_count_month INTEGER NOT NULL,
        prev_transactions INTEGER NOT NULL,
        is_first_transaction INTEGER NOT NULL,
        national_id_verification INTEGER NOT NULL,
        kks_card_validation INTEGER NOT NULL,
        duplicate_account_detection INTEGER NOT NULL,
        transaction_frequency_high INTEGER NOT NULL,
        valid_card INTEGER NOT NULL,
        ip_outside_indonesia INTEGER NOT NULL,
        app_vs_kiosk INTEGER NOT NULL,
        failed_login_attempts INTEGER NOT NULL,
        payment_retry_count INTEGER NOT NULL,
        same_device_multiple_accounts INTEGER NOT NULL,
        login_location_changed INTEGER NOT NULL,
        status TEXT DEFAULT 'pending', -- 'approved', 'blocked', 'review', 'pending'
        notes TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES members (id)
    )
    """)

    # 3. Create Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT UNIQUE NOT NULL,
        target_type TEXT NOT NULL, -- 'member' or 'transaction'
        target_id INTEGER NOT NULL,
        customer_name TEXT NOT NULL,
        customer_id INTEGER NOT NULL,
        risk_score REAL NOT NULL,
        fraud_indicators_triggered TEXT NOT NULL, -- JSON array of strings
        transaction_details TEXT, -- JSON dict or NULL
        detection_timestamp TEXT NOT NULL,
        status TEXT NOT NULL, -- 'Open', 'Under Review', 'Resolved'
        severity_level TEXT NOT NULL, -- 'Low', 'Medium', 'High', 'Critical'
        recommended_action TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES members (id)
    )
    """)

    # Create Risk Scores Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_type TEXT NOT NULL, -- 'member' or 'transaction'
        target_id INTEGER NOT NULL,
        rule_based_pct REAL NOT NULL,
        ai_prob REAL NOT NULL,
        final_pct REAL NOT NULL,
        level TEXT NOT NULL,
        verdict TEXT NOT NULL,
        triggered_flags TEXT NOT NULL, -- JSON array of strings
        triggered_combos TEXT NOT NULL, -- JSON array of strings
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 4. Create Audit Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_type TEXT NOT NULL, -- 'member', 'transaction', or 'alert'
        target_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        note TEXT,
        operator TEXT DEFAULT 'System',
        timestamp TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 5. Create Fraud Feedback Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fraud_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id TEXT NOT NULL UNIQUE,
        model_decision TEXT NOT NULL,
        auditor_decision TEXT NOT NULL,
        confirmed_label TEXT NOT NULL CHECK(confirmed_label IN ('fraud', 'legitimate', 'unknown')),
        notes TEXT,
        reviewed_by TEXT NOT NULL,
        reviewed_at TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 6. Create Fraud Scoring Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS fraud_scoring_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT NOT NULL UNIQUE,
        transaction_id TEXT NOT NULL UNIQUE,
        customer_id INTEGER NOT NULL,
        initial_subsidy REAL NOT NULL,
        transaction_amount REAL NOT NULL,
        subsidy_balance REAL NOT NULL,
        hour_of_day INTEGER NOT NULL,
        num_items INTEGER NOT NULL,
        repeated_product_purchase INTEGER NOT NULL,
        same_product_transaction_count_month INTEGER NOT NULL,
        previous_transactions INTEGER NOT NULL,
        is_first_transaction INTEGER NOT NULL,
        national_id_verification INTEGER NOT NULL,
        kks_card_validation INTEGER NOT NULL,
        duplicate_account_detection INTEGER NOT NULL,
        transaction_frequency_high INTEGER NOT NULL,
        valid_card INTEGER NOT NULL,
        ip_outside_indonesia INTEGER NOT NULL,
        app_vs_kiosk INTEGER NOT NULL,
        failed_login_attempts INTEGER NOT NULL,
        payment_retry_count INTEGER NOT NULL,
        same_device_multiple_accounts INTEGER NOT NULL,
        login_location_changed INTEGER NOT NULL,
        rule_based_score REAL NOT NULL,
        ai_probability_score REAL NOT NULL,
        final_risk_score REAL NOT NULL,
        risk_category TEXT NOT NULL,
        decision TEXT NOT NULL,
        allow_transaction INTEGER NOT NULL,
        triggered_flags TEXT NOT NULL,
        triggered_combo_rules TEXT NOT NULL,
        highest_combo_rule TEXT,
        recommendation TEXT,
        timestamp TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # 7. Create Indexes for Performance
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fraud_scoring_logs_tx_id ON fraud_scoring_logs(transaction_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fraud_scoring_logs_req_id ON fraud_scoring_logs(request_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_alert_id ON alerts(alert_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_type, target_id)")

    conn.commit()

    # Check if seeding is needed
    cursor.execute("SELECT COUNT(*) FROM members")
    member_count = cursor.fetchone()[0]

    if member_count == 0:
        print("[DB] Seeding database from CSV...")
        seed_from_csv(conn)
    else:
        conn.close()

def seed_from_csv(conn):
    import pandas as pd
    import random
    
    cursor = conn.cursor()
    df = pd.read_csv(CSV_PATH)
    
    # Common Indonesian names to generate realistic member profiles
    first_names = ["Budi", "Siti", "Agus", "Rudi", "Dewi", "Joko", "Sri", "Andi", "Lani", "Hendra", "Mega", "Eko", "Ika", "Hadi", "Yanto", "Rini"]
    last_names = ["Santoso", "Susanti", "Setiawan", "Wijaya", "Kusuma", "Pratama", "Hidayat", "Astuti", "Siregar", "Nasution", "Suharto", "Gunawan"]
    
    device_models = [
        "Samsung Galaxy S22 Ultra", 
        "iPhone 13 Pro Max", 
        "Xiaomi Redmi Note 11", 
        "Oppo A96", 
        "Vivo Y21", 
        "Realme 9 Pro",
        "Xiaomi Poco X4 Pro",
        "Samsung Galaxy A53"
    ]
    
    browsers = ["Chrome/120.0.0.0", "Safari/605.1.15", "Firefox/121.0", "Edge/120.0.2210.121"]
    
    print(f"[DB] Importing {len(df)} transactions and members...")
    
    # We will seed members matching name/customer_id 1 to 1000
    for idx, row in df.iterrows():
        c_id = int(row["Name/customer_id"])
        
        # Determine verification status based on flags in CSV
        has_fraud_flags = (
            row["National_ID_verification"] == 0 or
            row["KKS_card_validation"] == 0 or
            row["Duplicate_account_detection"] == 1 or
            row["same_device_multiple_accounts"] == 1
        )
        status = "Flagged" if has_fraud_flags else "Verified"
        
        # Generate member details
        random.seed(c_id) # Consistent generation
        first = random.choice(first_names)
        last = random.choice(last_names)
        name = f"{first} {last}"
        nik = f"3273{c_id:012d}"
        phone = f"0812{c_id:08d}"
        kks_card = f"1012{c_id:012d}"
        address = f"Jl. Sukarno Hatta No. {c_id}, Bandung, West Java"
        reg_date = f"2026-05-{random.randint(1, 31):02d}T{random.randint(8, 20):02d}:{random.randint(10, 59):02d}:00Z"
        
        # Set IP Address based on Outsider flag
        is_outsider = int(row["IP address (outside Indonesia )"])
        if is_outsider == 1:
            ip = f"{random.randint(5, 120)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        else:
            # Common domestic IP block (Indihome / Telkomsel)
            ip = f"180.250.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
        device = f"Mozilla/5.0 (Linux; Android 12; {random.choice(device_models)}) AppleWebKit/537.36 Mobile {random.choice(browsers)}"
        
        # Insert member
        cursor.execute("""
        INSERT INTO members (id, name, nik, phone, kks_card, address, registration_date, verification_status, device_info, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (c_id, name, nik, phone, kks_card, address, reg_date, status, device, ip))
        
        # Insert transaction
        tx_id = c_id
        initial_subsidy = float(row["Initial_Subsidy"])
        tx_amount = float(row["transaction_amount"])
        subsidy_balance = float(row["Subsidy_balance"])
        hour = int(row["hour_of_day"])
        items = int(row["num_items"])
        repeated = int(row.get("repeated_product_purchase(>10)", row.get("repeated_product_purchase", 0)))
        same_product = int(row.get("same_product_transcation_count_month", 0))
        prev_tx = int(row["prev_transactions"])
        is_first = int(row["is_first_transaction"])
        nat_id = int(row["National_ID_verification"])
        kks_valid = int(row["KKS_card_validation"])
        dup_acc = int(row["Duplicate_account_detection"])
        freq_high = int(row["Transaction frequency (>3 per hour)"])
        valid_card = int(row["valid_card"])
        ip_out = int(row["IP address (outside Indonesia )"])
        app_kiosk = int(row["app(0) vs kiosk(1)transaction"])
        failed_login = int(row["failed_login_attempts"])
        pay_retry = int(row["payment_retry_count"])
        same_device = int(row.get("same_device_multiple_accounts", 0))
        loc_change = int(row.get("login_location_changed", 0))
        
        # Default transaction audit status
        # If it looks like fraud, it could be 'blocked' or 'review' based on threshold
        tx_status = "pending"
        
        cursor.execute("""
        INSERT INTO transactions (
            id, customer_id, initial_subsidy, transaction_amount, subsidy_balance, hour_of_day, num_items,
            repeated_product_purchase, same_product_transaction_count_month, prev_transactions,
            is_first_transaction, national_id_verification, kks_card_validation, duplicate_account_detection,
            transaction_frequency_high, valid_card, ip_outside_indonesia, app_vs_kiosk, failed_login_attempts,
            payment_retry_count, same_device_multiple_accounts, login_location_changed, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (tx_id, c_id, initial_subsidy, tx_amount, subsidy_balance, hour, items, repeated, same_product,
              prev_tx, is_first, nat_id, kks_valid, dup_acc, freq_high, valid_card, ip_out, app_kiosk,
              failed_login, pay_retry, same_device, loc_change, tx_status))

    conn.commit()
    print("[DB] Initial seeding complete! Running score predictions and generating alerts...")
    
    # Run scoring on all seeded transactions and generate actual alerts for fraud
    # We load 'final' module here to score transactions
    import final
    
    cursor.execute("SELECT * FROM transactions")
    tx_rows = cursor.fetchall()
    
    alerts_to_insert = []
    scores_to_insert = []
    
    for tx in tx_rows:
        t_dict = {
            "Initial_Subsidy": tx["initial_subsidy"],
            "transaction_amount": tx["transaction_amount"],
            "Subsidy_balance": tx["subsidy_balance"],
            "hour_of_day": tx["hour_of_day"],
            "num_items": tx["num_items"],
            "repeated_product_purchase(>10)": tx["repeated_product_purchase"],
            "same_product_transcation_count_month": tx["same_product_transaction_count_month"],
            "prev_transactions": tx["prev_transactions"],
            "is_first_transaction": tx["is_first_transaction"],
            "National_ID_verification": tx["national_id_verification"],
            "KKS_card_validation": tx["kks_card_validation"],
            "Duplicate_account_detection": tx["duplicate_account_detection"],
            "Transaction frequency (>3 per hour)": tx["transaction_frequency_high"],
            "valid_card": tx["valid_card"],
            "IP address (outside Indonesia )": tx["ip_outside_indonesia"],
            "app(0) vs kiosk(1)transaction": tx["app_vs_kiosk"],
            "failed_login_attempts": tx["failed_login_attempts"],
            "payment_retry_count": tx["payment_retry_count"],
            "same_device_multiple_accounts": tx["same_device_multiple_accounts"],
            "login_location_changed": tx["login_location_changed"]
        }
        
        res = final.score_transaction(t_dict)
        score = res["final_pct"]
        
        # Save score
        scores_to_insert.append((
            'transaction', tx["id"], res["rule_based_pct"], res["ai_prob"], score,
            res["level"].replace("🔴 ", "").replace("🟠 ", "").replace("🟡 ", "").replace("🟢 ", "").split()[0],
            res["verdict"], json.dumps([k for k, v in res["flags"].items() if v == 1]),
            json.dumps([c["combo_id"] for c in res["triggered_combos"]])
        ))
        
        # If score is high (>= 55%), generate alert
        if score >= 55:
            c_id = tx["customer_id"]
            cursor.execute("SELECT name FROM members WHERE id = ?", (c_id,))
            member_name = cursor.fetchone()["name"]
            
            # Generate recommended action
            sev = res["level"].replace("🔴 ", "").replace("🟠 ", "").replace("🟡 ", "").replace("🟢 ", "").split()[0]
            rec_act = "Flag account for immediate review. Inspect payment retry logs."
            if sev == "CRITICAL":
                rec_act = "IMMEDIATE ACTION REQUIRED: Block account and freeze remaining subsidy balance."
            elif sev == "HIGH":
                rec_act = "Verify identity document (NIK) and review login location history."
                
            alert_id = f"ALT-{datetime.now().strftime('%Y%m%d')}-{tx['id']:04d}"
            triggered_flags = [k for k, v in res["flags"].items() if v == 1]
            
            alerts_to_insert.append((
                alert_id, 'transaction', tx["id"], member_name, c_id, score,
                json.dumps(triggered_flags), json.dumps(t_dict),
                tx["created_at"], 'Open', sev, rec_act
            ))
            
            # Update transaction status to match alert severity
            cursor.execute("UPDATE transactions SET status = 'review' WHERE id = ?", (tx["id"],))

    # Insert risk scores
    cursor.executemany("""
    INSERT INTO risk_scores (target_type, target_id, rule_based_pct, ai_prob, final_pct, level, verdict, triggered_flags, triggered_combos)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, scores_to_insert)

    # Insert alerts
    cursor.executemany("""
    INSERT INTO alerts (alert_id, target_type, target_id, customer_name, customer_id, risk_score, fraud_indicators_triggered, transaction_details, detection_timestamp, status, severity_level, recommended_action)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, alerts_to_insert)

    # Create initial audit log
    cursor.execute("""
    INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
    VALUES ('alert', 0, 'initialized', 'Database successfully initialized and seeded with 1000 transactions and members.', 'System', ?)
    """, (datetime.now().isoformat(),))

    conn.commit()
    conn.close()
    
    # Sync documentation files
    sync_all_documentation()
    print("[DB] Seeding complete! Documentation generated.")

_sync_lock = threading.Lock()

def sync_all_documentation():
    """Starts the database documentation sync in a background thread to prevent blocking request handlers."""
    thread = threading.Thread(target=_sync_all_documentation_sync, daemon=True)
    thread.start()

def _sync_all_documentation_sync():
    """Reads database and generates synchronized audit documentation."""
    # Prevent concurrent sync processes from corrupting files
    if not _sync_lock.acquire(blocking=False):
        return
    conn = None
    try:
        if not os.path.exists(DOCS_DIR):
            os.makedirs(DOCS_DIR)

        conn = get_db_connection()
        cursor = conn.cursor()

        # 1. Sync registration_history.md
        cursor.execute("SELECT * FROM members ORDER BY id DESC")
        members = cursor.fetchall()
        reg_history_path = os.path.join(DOCS_DIR, "registration_history.md")
        
        with open(reg_history_path, "w", encoding="utf-8") as f:
            f.write("# Kova Mart - Member Registration History\n\n")
            f.write("This log maintains a complete history of all registered members and their validation status.\n\n")
            f.write("| ID | Name | NIK | Phone Number | KKS Card Number | Registration Date | Status | Device | IP Address |\n")
            f.write("|----|------|-----|--------------|-----------------|-------------------|--------|--------|------------|\n")
            for m in members:
                # truncate device info for markdown readability
                dev = m["device_info"]
                if len(dev) > 40:
                    dev = dev[:37] + "..."
                f.write(f"| #{m['id']} | {m['name']} | {m['nik']} | {m['phone']} | {m['kks_card']} | {m['registration_date']} | **{m['verification_status']}** | {dev} | {m['ip_address']} |\n")

        # 2. Sync audit_logs.md
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC")
        logs = cursor.fetchall()
        audit_logs_path = os.path.join(DOCS_DIR, "audit_logs.md")
        
        with open(audit_logs_path, "w", encoding="utf-8") as f:
            f.write("# Kova Mart - System Audit Trail\n\n")
            f.write("A complete log of system initializations, checks, decisions, and manual auditor reviews.\n\n")
            f.write("| Log ID | Target | Target ID | Action | Notes | Auditor | Timestamp |\n")
            f.write("|--------|--------|-----------|--------|-------|---------|-----------|\n")
            for log in logs:
                f.write(f"| #{log['id']} | {log['target_type'].upper()} | {log['target_id']} | **{log['action'].upper()}** | {log['note']} | {log['operator']} | {log['timestamp']} |\n")

        # 3. Sync fraud_investigation_history.md
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
        alerts = cursor.fetchall()
        
        # Pre-fetch all alert audit logs in a single query to eliminate N+1 queries
        cursor.execute("SELECT target_id, timestamp, operator, action, note FROM audit_logs WHERE target_type = 'alert' ORDER BY id ASC")
        logs_rows = cursor.fetchall()
        logs_by_alert = {}
        for log in logs_rows:
            a_id = log["target_id"]
            if a_id not in logs_by_alert:
                logs_by_alert[a_id] = []
            logs_by_alert[a_id].append(log)
            
        investigation_path = os.path.join(DOCS_DIR, "fraud_investigation_history.md")
        
        with open(investigation_path, "w", encoding="utf-8") as f:
            f.write("# Kova Mart - Fraud Investigation & Alerts History\n\n")
            f.write("Official record of all generated security alerts, threat analyses, and investigation outcomes.\n\n")
            for alt in alerts:
                f.write(f"## Alert {alt['alert_id']} - {alt['status'].upper()}\n")
                f.write(f"- **Target Type:** {alt['target_type'].upper()} (ID: {alt['target_id']})\n")
                f.write(f"- **Customer Name:** {alt['customer_name']} (ID: {alt['customer_id']})\n")
                f.write(f"- **Threat Score:** {alt['risk_score']}%\n")
                f.write(f"- **Severity Level:** {alt['severity_level']}\n")
                f.write(f"- **Triggered Indicators:** `{alt['fraud_indicators_triggered']}`\n")
                f.write(f"- **Recommended Actions:** *{alt['recommended_action']}*\n")
                f.write(f"- **Detection Timestamp:** {alt['detection_timestamp']}\n")
                
                # Fetch investigation notes from pre-fetched dictionary
                notes = logs_by_alert.get(alt['id'], [])
                if notes:
                    f.write("- **Investigation Timeline:**\n")
                    for note in notes:
                        f.write(f"  - **[{note['timestamp']}]** ({note['operator']}): {note['action'].upper()} - {note['note']}\n")
                else:
                    f.write("- **Investigation Timeline:** No auditor updates on record.\n")
                f.write("\n---\n\n")

    except Exception as e:
        print(f"[DB Documentation Sync] Error synchronizing documentation: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if conn:
            try:
                conn.close()
            except Exception as e_close:
                print(f"[DB Documentation Sync] Error closing connection: {e_close}")
        _sync_lock.release()

def check_member_fraud(nik, phone, kks_card, device_info, ip_address):
    """
    Checks database for fraud conditions on new member registration.
    Returns:
      is_fraud (bool)
      triggered_checks (list of dicts describing the triggered conditions)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    triggered_checks = []

    # 1. Check Duplicate NIK
    cursor.execute("SELECT id, name FROM members WHERE nik = ?", (nik,))
    dup_nik = cursor.fetchone()
    if dup_nik:
        triggered_checks.append({
            "rule": "Duplicate NIK",
            "desc": f"NIK {nik} already registered under Member ID #{dup_nik['id']} ({dup_nik['name']}).",
            "severity": "Critical",
            "score": 100
        })

    # 2. Check Duplicate Phone
    cursor.execute("SELECT id, name FROM members WHERE phone = ?", (phone,))
    dup_phone = cursor.fetchone()
    if dup_phone:
        triggered_checks.append({
            "rule": "Duplicate Phone Number",
            "desc": f"Phone number {phone} already registered under Member ID #{dup_phone['id']} ({dup_phone['name']}).",
            "severity": "High",
            "score": 80
        })

    # 3. Check Duplicate KKS Card
    cursor.execute("SELECT id, name FROM members WHERE kks_card = ?", (kks_card,))
    dup_kks = cursor.fetchone()
    if dup_kks:
        triggered_checks.append({
            "rule": "Duplicate KKS Card",
            "desc": f"KKS Card {kks_card} already registered under Member ID #{dup_kks['id']} ({dup_kks['name']}).",
            "severity": "Critical",
            "score": 90
        })

    # 4. Same Device Multiple Accounts
    cursor.execute("SELECT COUNT(*), GROUP_CONCAT(id) FROM members WHERE device_info = ?", (device_info,))
    row = cursor.fetchone()
    device_count = row[0]
    member_ids = row[1]
    if device_count >= 1:
        triggered_checks.append({
            "rule": "Same Device Multiple Accounts",
            "desc": f"Device already registered with {device_count} member(s): Member ID(s) #{member_ids}.",
            "severity": "High",
            "score": 75
        })

    # 5. Suspicious Registration Activity
    # Check registration counts for same IP/Device within the last 24 hours
    # Since our mock/csv data registration date is historical, we check last registrations from members table
    # We will query if there are multiple accounts registered on the same day/timestamp pattern
    # For a real implementation, we look at the last 24 hours. We can simulate it:
    cursor.execute("SELECT COUNT(*) FROM members WHERE ip_address = ?", (ip_address,))
    ip_count = cursor.fetchone()[0]
    if ip_count >= 3:
        triggered_checks.append({
            "rule": "Suspicious Registration Activity",
            "desc": f"High rate of registrations from same IP address: {ip_count} accounts.",
            "severity": "High",
            "score": 85
        })

    conn.close()
    is_fraud = len(triggered_checks) > 0
    return is_fraud, triggered_checks

def ensure_indexes():
    """Ensures performance indexes are created on database tables if they exist."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Check if one of the tables exists (e.g., audit_logs)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'")
        if cursor.fetchone():
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_fraud_scoring_logs_tx_id ON fraud_scoring_logs(transaction_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_fraud_scoring_logs_req_id ON fraud_scoring_logs(request_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_alert_id ON alerts(alert_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_type, target_id)")
            conn.commit()
    except Exception as e:
        print(f"[DB] Error ensuring indexes: {e}")
    finally:
        conn.close()

# Ensure performance indexes exist at startup/import
ensure_indexes()

