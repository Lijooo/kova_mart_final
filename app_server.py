import sys
import os
import json
import traceback
import numpy as np
import random
import threading
import time
import csv
import sqlite3
from datetime import datetime

# 1. Force UTF-8 stdout encoding (Windows compatibility)
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
if sys.stderr.encoding != 'utf-8':
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

print("[Server] Importing final.py (loading AI model and data)...")
try:
    import final
    print("[Server] Successfully imported final.py!")
except Exception as e:
    print("[Server] Error importing final.py:")
    traceback.print_exc()
    sys.exit(1)

import database
print("[Server] Checking database status...")
try:
    db_exists = os.path.exists(database.DB_PATH) and os.path.getsize(database.DB_PATH) > 0
    if not db_exists:
        print("[Server] Database file not found or empty. Initializing database...")
        database.db_init()
        print("[Server] Database initialized successfully!")
    else:
        print("[Server] Database already exists. Skipping initialization.")
except Exception as e:
    print("[Server] Database initialization warning (non-fatal):")
    traceback.print_exc()

from flask import Flask, jsonify, request, render_template, session
from functools import wraps

def require_auth(f):
    return f

# API Key Authentication Decorator
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = os.environ.get("KOVA_API_KEY", "kova_secret_api_key_2026")
        provided_key = request.headers.get("X-API-Key")
        if not provided_key:
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                provided_key = auth_header.split(" ", 1)[1].strip()
                
        if not provided_key or provided_key != api_key:
            return jsonify({
                "status": "error",
                "message": "Unauthorized: Invalid or missing API key."
            }), 401
        return f(*args, **kwargs)
    return decorated

# In-Memory Rate Limiter
rate_limit_store = {}
rate_limit_lock = threading.Lock()

def check_rate_limit(ip_address, limit=60, window=60):
    now = time.time()
    with rate_limit_lock:
        timestamps = rate_limit_store.get(ip_address, [])
        timestamps = [t for t in timestamps if now - t < window]
        if len(timestamps) >= limit:
            rate_limit_store[ip_address] = timestamps
            return False
        timestamps.append(now)
        rate_limit_store[ip_address] = timestamps
        return True

def rate_limit(limit=60, window=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr
            if request.headers.getlist("X-Forwarded-For"):
                ip = request.headers.getlist("X-Forwarded-For")[0]
            if not check_rate_limit(ip, limit, window):
                return jsonify({
                    "status": "error",
                    "message": "Too Many Requests: Rate limit exceeded."
                }), 429
            return f(*args, **kwargs)
        return decorated
    return decorator

def clean_numpy(val):
    if isinstance(val, (np.integer, np.int64, np.int32)):
        return int(val)
    elif isinstance(val, (np.floating, np.float64, np.float32)):
        return float(val)
    elif isinstance(val, dict):
        return {k: clean_numpy(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [clean_numpy(v) for v in val]
    return val

def mask_sensitive_data(member):
    member_copy = dict(member)
    if "nik" in member_copy and member_copy["nik"]:
        nik = str(member_copy["nik"])
        if len(nik) >= 8:
            member_copy["nik"] = f"{nik[:4]}******{nik[-4:]}"
        else:
            member_copy["nik"] = "******"
    if "kks_card" in member_copy and member_copy["kks_card"]:
        kks = str(member_copy["kks_card"])
        if len(kks) >= 8:
            member_copy["kks_card"] = f"{kks[:4]}******{kks[-4:]}"
        else:
            member_copy["kks_card"] = "******"
    if "phone" in member_copy and member_copy["phone"]:
        phone = str(member_copy["phone"])
        if len(phone) >= 6:
            member_copy["phone"] = f"{phone[:3]}******{phone[-3:]}"
        else:
            member_copy["phone"] = "******"
    return member_copy

# 2. Create Flask App
# Use templates/ and static/ in current directory
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'),
    static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
)
app.secret_key = 'kova-secure-session-secret-key-9988'

# CORS helper
@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response

# Limit request payload size to 1MB
@app.before_request
def limit_payload_size():
    if request.method in ['POST', 'PUT']:
        max_size = 1 * 1024 * 1024  # 1MB
        content_length = request.content_length
        if content_length and content_length > max_size:
            return jsonify({
                "status": "error",
                "message": "Payload Too Large: Request body exceeds 1MB limit."
            }), 413

# ─── PAGES ───────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('index.html')


# ─── API: DASHBOARD STATISTICS ───────────────────────────────────────────────
@app.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    try:
        conn = database.get_db_connection()
        cursor = conn.cursor()

        # 1. Member stats
        cursor.execute("SELECT COUNT(*) FROM members")
        total_members = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM members WHERE verification_status = 'Verified'")
        active_members = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM members WHERE verification_status IN ('Flagged', 'Under Review')")
        flagged_members = cursor.fetchone()[0]

        # 2. Alert stats
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity_level = 'Critical' AND status != 'Resolved'")
        critical_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM alerts WHERE status != 'Resolved'")
        unresolved_alerts = cursor.fetchone()[0]

        # 3. Transaction stats
        cursor.execute("SELECT COUNT(*) FROM transactions")
        total_tx = cursor.fetchone()[0]

        # Fraud transactions are transactions that triggered a high-risk score
        cursor.execute("SELECT COUNT(*) FROM transactions WHERE status IN ('blocked', 'review')")
        fraud_tx = cursor.fetchone()[0]
        legit_tx = total_tx - fraud_tx

        cursor.execute("SELECT AVG(final_pct) FROM risk_scores WHERE target_type = 'transaction'")
        avg_risk = cursor.fetchone()[0] or 0.0

        # 4. Risk distribution
        cursor.execute("SELECT COUNT(*) FROM risk_scores WHERE target_type = 'transaction' AND final_pct >= 80")
        critical_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM risk_scores WHERE target_type = 'transaction' AND final_pct >= 55 AND final_pct < 80")
        high_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM risk_scores WHERE target_type = 'transaction' AND final_pct >= 40 AND final_pct < 55")
        medium_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM risk_scores WHERE target_type = 'transaction' AND final_pct < 40")
        low_count = cursor.fetchone()[0]

        # 5. Top flags counts
        cursor.execute("SELECT triggered_flags FROM risk_scores WHERE target_type = 'transaction'")
        all_flag_lists = cursor.fetchall()
        
        flag_labels = {
            "flag_ip_outsider":       "Foreign IP Address",
            "flag_repeated_purchase": "Repeated Product Purchase >10",
            "flag_high_frequency":    "Transaction Frequency >3/hr",
            "flag_duplicate_account": "Duplicate Account Detected",
            "flag_same_device":       "Same Device Multiple Accounts",
            "flag_location_changed":  "Login Location Changed",
            "flag_same_product_high": "Same Product Count >5/month",
            "flag_payment_retry":     "Payment Retry >= 3",
            "flag_failed_login":      "Failed Login Attempts >= 3",
            "flag_id_not_verified":   "National ID Not Verified",
            "flag_kks_not_valid":     "KKS Card Invalid",
            "flag_card_invalid":      "Card Not Valid",
            "flag_subsidy_exhausted": "Subsidy Used > 900,000",
            "flag_kiosk":             "App Transaction"
        }
        
        labeled_flags = {label: 0 for label in flag_labels.values()}
        for row in all_flag_lists:
            flags = json.loads(row[0])
            for f in flags:
                label = flag_labels.get(f, f)
                if label in labeled_flags:
                    labeled_flags[label] += 1
                else:
                    labeled_flags[label] = 1

        # 6. Recent registrations
        cursor.execute("SELECT * FROM members ORDER BY id DESC LIMIT 5")
        recent_m_rows = cursor.fetchall()
        recent_members = []
        for rm in recent_m_rows:
            recent_members.append(mask_sensitive_data({
                "id": rm["id"],
                "name": rm["name"],
                "nik": rm["nik"],
                "phone": rm["phone"],
                "verification_status": rm["verification_status"],
                "registration_date": rm["registration_date"]
            }))

        # 7. Recent fraud alerts
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5")
        recent_a_rows = cursor.fetchall()
        recent_alerts = []
        for ra in recent_a_rows:
            recent_alerts.append({
                "id": ra["id"],
                "alert_id": ra["alert_id"],
                "customer_name": ra["customer_name"],
                "customer_id": ra["customer_id"],
                "risk_score": ra["risk_score"],
                "severity_level": ra["severity_level"],
                "status": ra["status"],
                "detection_timestamp": ra["detection_timestamp"],
                "fraud_indicators_triggered": json.loads(ra["fraud_indicators_triggered"])
            })

        conn.close()

        return jsonify({
            "status": "success",
            "metrics": {
                "total_transactions":  total_tx,
                "fraud_detected":      fraud_tx,
                "legit_transactions":  legit_tx,
                "average_risk_score":  round(avg_risk, 2),
                "fraud_rate_pct":      round((fraud_tx / total_tx) * 100, 2) if total_tx > 0 else 0.0,
                "total_members":       total_members,
                "active_members":      active_members,
                "flagged_members":     flagged_members,
                "total_alerts":        total_alerts,
                "critical_alerts":     critical_alerts,
                "unresolved_alerts":   unresolved_alerts
            },
            "risk_distribution": {
                "Critical": critical_count,
                "High":     high_count,
                "Medium":   medium_count,
                "Low":      low_count
            },
            "top_flags": labeled_flags,
            "recent_registrations": recent_members,
            "recent_alerts": recent_alerts
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# ─── API: RECENT SUSPICIOUS ALERTS ───────────────────────────────────────────
@app.route('/api/suspicious', methods=['GET'])
@require_auth
def get_suspicious():
    try:
        conn = database.get_db_connection()
        cursor = conn.cursor()
        # Fetch alerts that are not resolved
        cursor.execute("""
            SELECT * FROM alerts 
            WHERE status != 'Resolved' 
            ORDER BY risk_score DESC, id DESC LIMIT 15
        """)
        alert_rows = cursor.fetchall()
        
        records = []
        for row in alert_rows:
            tx_details = json.loads(row["transaction_details"]) if row["transaction_details"] else {}
            records.append({
                "alert_id":            row["alert_id"],
                "customer_id":         row["customer_id"],
                "customer_name":       row["customer_name"],
                "target_type":         row["target_type"],
                "target_id":           row["target_id"],
                "risk_score":          row["risk_score"],
                "severity_level":      row["severity_level"],
                "status":              row["status"],
                "detection_timestamp": row["detection_timestamp"],
                "indicators":          json.loads(row["fraud_indicators_triggered"]),
                "recommended_action":  row["recommended_action"],
                "transaction_amount":  tx_details.get("transaction_amount", 0.0),
                "subsidy_balance":     tx_details.get("Subsidy_balance", 0.0)
            })
        conn.close()
        return jsonify({"status": "success", "count": len(records), "transactions": records})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# ─── API: ALL TRANSACTIONS (FOR OPERATIONS CONSOLE) ───────────────────────────
@app.route('/api/transactions', methods=['GET'])
@require_auth
def get_transactions():
    try:
        conn = database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT t.*, m.name as customer_name, r.final_pct, r.rule_based_pct, r.ai_prob, r.verdict, r.level
            FROM transactions t
            LEFT JOIN members m ON t.customer_id = m.id
            LEFT JOIN risk_scores r ON r.target_type = 'transaction' AND r.target_id = t.id
            ORDER BY t.id DESC
        """)
        rows = cursor.fetchall()
        
        # Pre-fetch all transaction audit logs in a single query to prevent N+1 performance issues
        cursor.execute("SELECT target_id, action, note, timestamp FROM audit_logs WHERE target_type = 'transaction' ORDER BY id DESC")
        logs_rows = cursor.fetchall()
        logs_by_tx = {}
        for log in logs_rows:
            tx_id = log["target_id"]
            if tx_id not in logs_by_tx:
                logs_by_tx[tx_id] = []
            logs_by_tx[tx_id].append({
                "action": log["action"],
                "note": log["note"],
                "timestamp": log["timestamp"]
            })
        
        records = []
        for r in rows:
            rec = dict(r)
            rec["auditHistory"] = logs_by_tx.get(r["id"], [])
            rec["risk_pct"] = r["final_pct"] if r["final_pct"] is not None else 0.0
            rec["Initial_Subsidy"] = r["initial_subsidy"]
            rec["Subsidy_balance"] = r["subsidy_balance"]
            rec["IP address (outside Indonesia )"] = r["ip_outside_indonesia"]
            rec["app(0) vs kiosk(1)transaction"] = r["app_vs_kiosk"]
            rec["repeated_product_purchase(>10)"] = r["repeated_product_purchase"]
            rec["same_product_transcation_count_month"] = r["same_product_transaction_count_month"]
            
            records.append(clean_numpy(rec))
            
        conn.close()
        return jsonify({"status": "success", "count": len(records), "transactions": records})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# ─── API: REVEAL MEMBER SENSITIVE DATA ────────────────────────────────────────
@app.route('/api/members/<int:member_id>/reveal', methods=['POST'])
@require_auth
def reveal_member_data(member_id):
    try:
        conn = database.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM members WHERE id = ?", (member_id,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return jsonify({"status": "error", "message": "Member not found"}), 404
            
        member = dict(row)
        operator = session.get('user', 'Auditor')
        timestamp = datetime.now().isoformat()
        
        # Log reveal to audit_logs
        cursor.execute("""
            INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
            VALUES ('member', ?, 'reveal', ?, ?, ?)
        """, (member_id, f"Auditor revealed sensitive NIK/KKS card details for Member '{member['name']}'.", operator, timestamp))
        
        conn.commit()
        conn.close()
        
        # Sync to markdown documents
        database.sync_all_documentation()
        
        return jsonify({
            "status": "success",
            "nik": member["nik"],
            "kks_card": member["kks_card"],
            "phone": member["phone"]
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# ─── API: MEMBER REGISTRATION & MANAGEMENT ───────────────────────────────────
@app.route('/api/members', methods=['GET', 'POST'])
@require_auth
def handle_members():
    if request.method == 'GET':
        try:
            conn = database.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM members ORDER BY id DESC")
            rows = cursor.fetchall()
            
            # Pre-fetch all member audit logs in a single query to prevent N+1 performance issues
            cursor.execute("SELECT target_id, action, note, timestamp FROM audit_logs WHERE target_type = 'member' ORDER BY id DESC")
            logs_rows = cursor.fetchall()
            logs_by_member = {}
            for log in logs_rows:
                m_id = log["target_id"]
                if m_id not in logs_by_member:
                    logs_by_member[m_id] = []
                logs_by_member[m_id].append({
                    "action": log["action"],
                    "note": log["note"],
                    "timestamp": log["timestamp"]
                })
            
            members = []
            for r in rows:
                m = dict(r)
                m["auditHistory"] = logs_by_member.get(r["id"], [])
                members.append(mask_sensitive_data(m))
            conn.close()
            return jsonify({"status": "success", "members": members})
        except Exception as e:
            traceback.print_exc()
            return jsonify({"status": "error", "message": str(e)}), 500
            
    elif request.method == 'POST':
        try:
            data = request.json
            if not data:
                return jsonify({"status": "error", "message": "No data provided"}), 400
                
            name = data.get("name", "").strip()
            nik = data.get("nik", "").strip()
            phone = data.get("phone", "").strip()
            kks_card = data.get("kks_card", "").strip()
            address = data.get("address", "").strip()
            device_info = data.get("device_info", "").strip()
            ip_address = data.get("ip_address", "").strip()
            verification_status = data.get("verification_status", "Verified").strip()
            
            # 1. Validation
            if not (name and nik and phone and kks_card and address and device_info and ip_address):
                return jsonify({"status": "error", "message": "All fields are required"}), 400
                
            if len(nik) != 16 or not nik.isdigit():
                return jsonify({"status": "error", "message": "National ID (NIK) must be exactly 16 digits"}), 400
                
            if len(kks_card) != 16 or not kks_card.isdigit():
                return jsonify({"status": "error", "message": "KKS Card Number must be exactly 16 digits"}), 400
            
            # 2. Check for Fraud Rules
            is_fraud, triggered_rules = database.check_member_fraud(nik, phone, kks_card, device_info, ip_address)
            
            status = "Flagged" if is_fraud else verification_status
            reg_date = datetime.now().isoformat()
            
            # 3. Save Member to Database
            conn = database.get_db_connection()
            cursor = conn.cursor()
            
            # Check for UNIQUE constraint conflicts (duplicate NIK, Phone, or KKS Card)
            cursor.execute("SELECT id, name FROM members WHERE nik = ? OR phone = ? OR kks_card = ?", (nik, phone, kks_card))
            existing_members = cursor.fetchall()
            
            if existing_members:
                # Conflict detected! Do NOT insert new member. Flag the existing member(s), log audits, generate alerts.
                flagged_names = []
                for ex_member in existing_members:
                    ex_id = ex_member["id"]
                    ex_name = ex_member["name"]
                    flagged_names.append(ex_name)
                    
                    # Update status of existing member to Flagged
                    cursor.execute("UPDATE members SET verification_status = 'Flagged' WHERE id = ?", (ex_id,))
                    
                    # Log audit of flagging
                    cursor.execute("""
                        INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
                        VALUES ('member', ?, 'flagged', ?, 'System', ?)
                    """, (ex_id, f"Member flagged due to duplicate registration attempt by '{name}' (NIK: {nik}, Phone: {phone}, KKS: {kks_card}).", reg_date))
                    
                    # Generate fraud alert and risk score linked to the existing member
                    dup_indicators = [r["rule"] for r in triggered_rules if r["rule"] in ["Duplicate NIK", "Duplicate Phone Number", "Duplicate KKS Card"]]
                    if not dup_indicators:
                        dup_indicators = ["Duplicate Registration Details"]
                        
                    max_score = max([r["score"] for r in triggered_rules if r["rule"] in ["Duplicate NIK", "Duplicate Phone Number", "Duplicate KKS Card"]] or [90])
                    severity = "Critical" if max_score >= 90 else "High"
                    
                    rec_actions = {
                        "Duplicate NIK": "Freeze account immediately. Contact citizen registry to verify identity.",
                        "Duplicate Phone Number": "Require SMS verification. Review linked profiles.",
                        "Duplicate KKS Card": "Flag subsidy card. Block transactions.",
                        "Duplicate Registration Details": "Audit profile details."
                    }
                    rec_act = "; ".join([rec_actions.get(i, "Audit profile.") for i in dup_indicators])
                    
                    # Ensure alert_id is unique
                    base_alert_id = f"ALT-{datetime.now().strftime('%Y%m%d')}-M{ex_id:03d}"
                    alert_id = base_alert_id
                    suffix_attempts = 0
                    while True:
                        cursor.execute("SELECT id FROM alerts WHERE alert_id = ?", (alert_id,))
                        if not cursor.fetchone():
                            break
                        suffix_attempts += 1
                        alert_id = f"{base_alert_id}-{random.randint(10, 99) if suffix_attempts < 5 else random.randint(100, 9999)}"
                        
                    cursor.execute("""
                        INSERT INTO alerts (alert_id, target_type, target_id, customer_name, customer_id, risk_score, fraud_indicators_triggered, detection_timestamp, status, severity_level, recommended_action)
                        VALUES (?, 'member', ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
                    """, (alert_id, ex_id, ex_name, ex_id, max_score, json.dumps(dup_indicators), reg_date, severity, rec_act))
                    alert_db_id = cursor.lastrowid
                    
                    cursor.execute("""
                        INSERT INTO risk_scores (target_type, target_id, rule_based_pct, ai_prob, final_pct, level, verdict, triggered_flags, triggered_combos)
                        VALUES ('member', ?, ?, 0.0, ?, ?, ?, ?, '[]')
                    """, (ex_id, max_score, max_score, severity.upper(), f"RULE-FLAGGED ON REGISTRATION - {', '.join(dup_indicators)}", json.dumps(dup_indicators)))
                    
                    cursor.execute("""
                        INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
                        VALUES ('alert', ?, 'triggered', ?, 'System', ?)
                    """, (alert_db_id, f"Security alert generated for existing member {ex_name} (ID: {ex_id}) due to duplicate details.", reg_date))
                
                conn.commit()
                conn.close()
                database.sync_all_documentation()
                
                return jsonify({
                    "status": "error",
                    "message": f"Registration details conflict with existing account(s). Existing member(s) flagged: {', '.join(flagged_names)}."
                }), 400
            
            cursor.execute("""
                INSERT INTO members (name, nik, phone, kks_card, address, registration_date, verification_status, device_info, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (name, nik, phone, kks_card, address, reg_date, status, device_info, ip_address))
            member_id = cursor.lastrowid
            
            # Log registration in audit logs
            cursor.execute("""
                INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
                VALUES ('member', ?, 'registered', ?, 'System', ?)
            """, (member_id, f"Registered member {name}. Initial status: {status}.", reg_date))
            
            # 4. Generate Alert if Fraud Detected
            alert_generated = False
            alert_data = None
            if is_fraud:
                alert_generated = True
                max_score = max([r["score"] for r in triggered_rules])
                severity = "Critical" if max_score >= 90 else "High"
                indicators = [r["rule"] for r in triggered_rules]
                
                # Recommended action
                rec_actions = {
                    "Duplicate NIK": "Freeze account immediately. Contact citizen registry to verify identity.",
                    "Duplicate Phone Number": "Require SMS verification. Review linked profiles.",
                    "Duplicate KKS Card": "Flag subsidy card. Block transactions.",
                    "Same Device Multiple Accounts": "Review other accounts linked to device fingerprint. Verify authenticity.",
                    "Suspicious Registration Activity": "IP address flagged. Monitor transaction logins."
                }
                rec_act = "; ".join([rec_actions.get(i, "Audit profile.") for i in indicators])
                
                base_alert_id = f"ALT-{datetime.now().strftime('%Y%m%d')}-M{member_id:03d}"
                alert_id = base_alert_id
                suffix_attempts = 0
                while True:
                    cursor.execute("SELECT id FROM alerts WHERE alert_id = ?", (alert_id,))
                    if not cursor.fetchone():
                        break
                    suffix_attempts += 1
                    alert_id = f"{base_alert_id}-{random.randint(10, 99) if suffix_attempts < 5 else random.randint(100, 9999)}"
                
                cursor.execute("""
                    INSERT INTO alerts (alert_id, target_type, target_id, customer_name, customer_id, risk_score, fraud_indicators_triggered, detection_timestamp, status, severity_level, recommended_action)
                    VALUES (?, 'member', ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
                """, (alert_id, member_id, name, member_id, max_score, json.dumps(indicators), reg_date, severity, rec_act))
                alert_db_id = cursor.lastrowid
                
                # Add risk score record
                cursor.execute("""
                    INSERT INTO risk_scores (target_type, target_id, rule_based_pct, ai_prob, final_pct, level, verdict, triggered_flags, triggered_combos)
                    VALUES ('member', ?, ?, 0.0, ?, ?, ?, ?, '[]')
                """, (member_id, max_score, max_score, severity.upper(), f"RULE-FLAGGED ON REGISTRATION - {', '.join(indicators)}", json.dumps(indicators)))
                
                # Log alert generation
                cursor.execute("""
                    INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
                    VALUES ('alert', ?, 'triggered', ?, 'System', ?)
                """, (alert_db_id, f"Security alert generated for registered member {name} due to: {', '.join(indicators)}.", reg_date))
                
                alert_data = {
                    "alert_id": alert_id,
                    "customer_name": name,
                    "customer_id": member_id,
                    "risk_score": max_score,
                    "indicators": indicators,
                    "severity": severity,
                    "status": "Open",
                    "timestamp": reg_date
                }
                
            conn.commit()
            conn.close()
            
            # Sync to markdown documents
            database.sync_all_documentation()
            
            return jsonify({
                "status": "success",
                "member_id": member_id,
                "verification_status": status,
                "alert_triggered": alert_generated,
                "alert": alert_data
            })
            
        except Exception as e:
            traceback.print_exc()
            return jsonify({"status": "error", "message": str(e)}), 500

# ─── API: ALERTS LIST & RESOLUTION ───────────────────────────────────────────
@app.route('/api/alerts', methods=['GET'])
@require_auth
def get_alerts():
    try:
        conn = database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC")
        rows = cursor.fetchall()
        
        # Pre-fetch all alert audit logs in a single query to prevent N+1 performance issues
        cursor.execute("SELECT target_id, action, note, operator, timestamp FROM audit_logs WHERE target_type = 'alert' ORDER BY id DESC")
        logs_rows = cursor.fetchall()
        logs_by_alert = {}
        for log in logs_rows:
            a_id = log["target_id"]
            if a_id not in logs_by_alert:
                logs_by_alert[a_id] = []
            logs_by_alert[a_id].append({
                "action": log["action"],
                "note": log["note"],
                "operator": log["operator"],
                "timestamp": log["timestamp"]
            })
        
        alerts = []
        for r in rows:
            alt = dict(r)
            alt["indicators"] = json.loads(r["fraud_indicators_triggered"])
            alt["transaction_details"] = json.loads(r["transaction_details"]) if r["transaction_details"] else None
            alt["auditHistory"] = logs_by_alert.get(r["id"], [])
            alerts.append(alt)
            
        conn.close()
        return jsonify({"status": "success", "alerts": alerts})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/alerts/<int:alert_db_id>/status', methods=['POST'])
@require_auth
def resolve_alert(alert_db_id):
    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "No parameters supplied"}), 400
            
        new_status = data.get("status") # 'Open', 'Under Review', 'Resolved'
        note = data.get("note", "").strip()
        operator = data.get("operator", "Auditor").strip()
        
        if new_status not in ['Open', 'Under Review', 'Resolved']:
            return jsonify({"status": "error", "message": "Invalid status value"}), 400
            
        conn = database.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_db_id,))
        alert = cursor.fetchone()
        if not alert:
            conn.close()
            return jsonify({"status": "error", "message": "Alert not found"}), 404
            
        timestamp = datetime.now().isoformat()
        
        # 1. Update Alert Status
        cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_db_id))
        
        # 2. Add Audit Log
        cursor.execute("""
            INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
            VALUES ('alert', ?, ?, ?, ?, ?)
        """, (alert_db_id, new_status.lower(), note or f"Alert status updated to {new_status}.", operator, timestamp))
        
        # 3. If resolving, cascade update to the target member or transaction
        if new_status == 'Resolved':
            target_type = alert["target_type"]
            target_id = alert["target_id"]
            
            if target_type == 'member':
                # Determine action from notes: block or approve?
                decision = "Blocked" if "block" in note.lower() or "fraud" in note.lower() else "Verified"
                cursor.execute("UPDATE members SET verification_status = ? WHERE id = ?", (decision, target_id))
                cursor.execute("""
                    INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
                    VALUES ('member', ?, ?, ?, ?, ?)
                """, (target_id, decision.lower(), f"Member verification status updated to {decision} following Alert {alert['alert_id']} resolution.", operator, timestamp))
            elif target_type == 'transaction':
                decision = "blocked" if "block" in note.lower() or "fraud" in note.lower() else "approved"
                cursor.execute("UPDATE transactions SET status = ? WHERE id = ?", (decision, target_id))
                cursor.execute("""
                    INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
                    VALUES ('transaction', ?, ?, ?, ?, ?)
                """, (target_id, decision, f"Transaction status updated to {decision} following Alert {alert['alert_id']} resolution.", operator, timestamp))
                
        conn.commit()
        conn.close()
        
        # Sync to markdown documents
        database.sync_all_documentation()
        
        return jsonify({"status": "success", "message": f"Alert successfully updated to {new_status}"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# ─── API: TRANSACTION MANUAL AUDITING ─────────────────────────────────────────
@app.route('/api/transactions/audit', methods=['POST'])
@require_auth
def audit_transaction():
    try:
        data = request.json
        if not data or 'transaction_id' not in data or 'status' not in data:
            return jsonify({"status": "error", "message": "Missing transaction_id or status"}), 400
            
        tx_id = data["transaction_id"]
        status = data["status"] # 'approved', 'blocked', 'review'
        note = data.get("note", "").strip()
        operator = data.get("operator", "Auditor").strip()
        
        if status not in ['approved', 'blocked', 'review']:
            return jsonify({"status": "error", "message": "Invalid status value"}), 400
            
        conn = database.get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, customer_id FROM transactions WHERE id = ?", (tx_id,))
        tx = cursor.fetchone()
        if not tx:
            conn.close()
            return jsonify({"status": "error", "message": "Transaction not found"}), 404
            
        timestamp = datetime.now().isoformat()
        
        # 1. Update Transaction Status and Notes
        cursor.execute("UPDATE transactions SET status = ?, notes = ? WHERE id = ?", (status, note, tx_id))
        
        # 2. Write Audit Log
        cursor.execute("""
            INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
            VALUES ('transaction', ?, ?, ?, ?, ?)
        """, (tx_id, status, note or f"Transaction marked as {status}.", operator, timestamp))
        
        # 3. If there is an associated Open/Under Review alert for this transaction, update its status
        cursor.execute("SELECT id, alert_id FROM alerts WHERE target_type = 'transaction' AND target_id = ? AND status != 'Resolved'", (tx_id,))
        open_alert = cursor.fetchone()
        if open_alert:
            alert_db_id = open_alert["id"]
            alert_status = 'Resolved' if status in ['approved', 'blocked'] else 'Under Review'
            cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (alert_status, alert_db_id))
            cursor.execute("""
                INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
                VALUES ('alert', ?, ?, ?, ?, ?)
            """, (alert_db_id, alert_status.lower(), f"Alert status updated to {alert_status} due to manual transaction audit update to {status.upper()}.", operator, timestamp))
            
        conn.commit()
        conn.close()
        
        # Sync to markdown documents
        database.sync_all_documentation()
        
        return jsonify({"status": "success", "message": "Transaction audit registered successfully"})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# ─── API: BATCH TRANSACTION ANALYSIS ─────────────────────────────────────────
@app.route('/api/analyze_batch', methods=['POST'])
def analyze_batch():
    try:
        data = request.json
        if not data or 'transactions' not in data:
            return jsonify({"status": "error", "message": "No transactions provided"}), 400
        
        batch = data['transactions']
        results = []
        for item in batch:
            t = {}
            t["Initial_Subsidy"]                        = float(item.get("Initial_Subsidy", 0))
            t["transaction_amount"]                     = float(item.get("transaction_amount", 0))
            t["Subsidy_balance"]                        = round(t["Initial_Subsidy"] - t["transaction_amount"], 2)
            t["hour_of_day"]                            = int(item.get("hour_of_day", 12))
            t["num_items"]                              = int(item.get("num_items", 1))
            t["repeated_product_purchase(>10)"]         = int(item.get("repeated_product_purchase(>10)", 0))
            t["same_product_transcation_count_month"]   = int(item.get("same_product_transcation_count_month", 0))
            t["prev_transactions"]                      = int(item.get("prev_transactions", 0))
            t["is_first_transaction"]                   = int(item.get("is_first_transaction", 0))
            t["National_ID_verification"]               = int(item.get("National_ID_verification", 1))
            t["KKS_card_validation"]                    = int(item.get("KKS_card_validation", 1))
            t["Duplicate_account_detection"]            = int(item.get("Duplicate_account_detection", 0))
            t["Transaction frequency (>3 per hour)"]    = int(item.get("Transaction frequency (>3 per hour)", 0))
            t["valid_card"]                             = int(item.get("valid_card", 1))
            t["IP address (outside Indonesia )"]        = int(item.get("IP address (outside Indonesia )", 0))
            t["app(0) vs kiosk(1)transaction"]          = int(item.get("app(0) vs kiosk(1)transaction", 0))
            t["failed_login_attempts"]                  = int(item.get("failed_login_attempts", 0))
            t["payment_retry_count"]                    = int(item.get("payment_retry_count", 0))
            t["same_device_multiple_accounts"]          = int(item.get("same_device_multiple_accounts", 0))
            t["login_location_changed"]                 = int(item.get("login_location_changed", 0))
            
            result = final.score_transaction(t)
            
            clean_res = {
                "rule_based_pct":   float(result["rule_based_pct"]),
                "ai_prob":          float(result["ai_prob"]),
                "final_pct":        float(result["final_pct"]),
                "level":            str(result["level"]),
                "verdict":          str(result["verdict"]),
                "n_flags":          int(result["n_flags"]),
            }
            if "Name/customer_id" in item:
                clean_res["customer_id"] = int(item["Name/customer_id"])
            elif "customer_id" in item:
                clean_res["customer_id"] = int(item["customer_id"])
            
            for k, v in t.items():
                clean_res[k] = v
                
            results.append(clean_res)
            
        return jsonify({"status": "success", "count": len(results), "results": results})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500

# ─── API: GENERATE SYNTHETIC TRANSACTION ─────────────────────────────────────
CSV_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_transactions_log.csv")

def save_to_csv_log(tx, score, level, verdict, alert_id=None):
    file_exists = os.path.exists(CSV_LOG_PATH)
    headers = [
        "timestamp", "customer_id", "Initial_Subsidy", "transaction_amount", "Subsidy_balance", 
        "hour_of_day", "num_items", "repeated_product_purchase", "same_product_transaction_count_month",
        "prev_transactions", "is_first_transaction", "National_ID_verification", "KKS_card_validation", 
        "Duplicate_account_detection", "Transaction frequency (>3 per hour)", "valid_card", 
        "IP address (outside Indonesia )", "app(0) vs kiosk(1)transaction", "failed_login_attempts", 
        "payment_retry_count", "same_device_multiple_accounts", "login_location_changed", 
        "risk_score", "risk_level", "verdict", "alert_id"
    ]
    
    row = {
        "timestamp": datetime.now().isoformat(),
        "customer_id": int(tx.get("Name/customer_id", 999)),
        "Initial_Subsidy": float(tx.get("Initial_Subsidy", 0.0)),
        "transaction_amount": float(tx.get("transaction_amount", 0.0)),
        "Subsidy_balance": float(tx.get("Subsidy_balance", 0.0)),
        "hour_of_day": int(tx.get("hour_of_day", 12)),
        "num_items": int(tx.get("num_items", 1)),
        "repeated_product_purchase": int(tx.get("repeated_product_purchase(>10)", tx.get("repeated_product_purchase", 0))),
        "same_product_transaction_count_month": int(tx.get("same_product_transcation_count_month", tx.get("same_product_transaction_count_month", 0))),
        "prev_transactions": int(tx.get("prev_transactions", 0)),
        "is_first_transaction": int(tx.get("is_first_transaction", 0)),
        "National_ID_verification": int(tx.get("National_ID_verification", 1)),
        "KKS_card_validation": int(tx.get("KKS_card_validation", 1)),
        "Duplicate_account_detection": int(tx.get("Duplicate_account_detection", 0)),
        "Transaction frequency (>3 per hour)": int(tx.get("Transaction frequency (>3 per hour)", 0)),
        "valid_card": int(tx.get("valid_card", 1)),
        "IP address (outside Indonesia )": int(tx.get("IP address (outside Indonesia )", 0)),
        "app(0) vs kiosk(1)transaction": int(tx.get("app(0) vs kiosk(1)transaction", 0)),
        "failed_login_attempts": int(tx.get("failed_login_attempts", 0)),
        "payment_retry_count": int(tx.get("payment_retry_count", 0)),
        "same_device_multiple_accounts": int(tx.get("same_device_multiple_accounts", 0)),
        "login_location_changed": int(tx.get("login_location_changed", 0)),
        "risk_score": float(score),
        "risk_level": level,
        "verdict": verdict,
        "alert_id": alert_id or ""
    }
    
    with open(CSV_LOG_PATH, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)

def generate_and_score_transaction_internal():
    tx = final.generate_one_transaction()
    
    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, ip_address, device_info FROM members ORDER BY RANDOM() LIMIT 1")
    member = cursor.fetchone()
    
    if member:
        c_id = member["id"]
        name = member["name"]
        tx["Name/customer_id"] = c_id
        is_outside = 1 if not member["ip_address"].startswith("180.250.") else 0
        tx["IP address (outside Indonesia )"] = is_outside
    else:
        c_id = 999
        name = "Default Customer"
        tx["Name/customer_id"] = c_id
        
    res = final.score_transaction(tx)
    score = res["final_pct"]
    timestamp = datetime.now().isoformat()
    
    # 1. Save Transaction to database
    cursor.execute("""
        INSERT INTO transactions (
            customer_id, initial_subsidy, transaction_amount, subsidy_balance, hour_of_day, num_items,
            repeated_product_purchase, same_product_transaction_count_month, prev_transactions,
            is_first_transaction, national_id_verification, kks_card_validation, duplicate_account_detection,
            transaction_frequency_high, valid_card, ip_outside_indonesia, app_vs_kiosk, failed_login_attempts,
            payment_retry_count, same_device_multiple_accounts, login_location_changed, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (c_id, float(tx["Initial_Subsidy"]), float(tx["transaction_amount"]), float(tx["Subsidy_balance"]),
          int(tx["hour_of_day"]), int(tx["num_items"]), int(tx.get("repeated_product_purchase(>10)", 0)),
          int(tx.get("same_product_transcation_count_month", 0)), int(tx["prev_transactions"]),
          int(tx["is_first_transaction"]), int(tx["National_ID_verification"]), int(tx["KKS_card_validation"]),
          int(tx["Duplicate_account_detection"]), int(tx["Transaction frequency (>3 per hour)"]),
          int(tx["valid_card"]), int(tx["IP address (outside Indonesia )"]), int(tx["app(0) vs kiosk(1)transaction"]),
          int(tx["failed_login_attempts"]), int(tx["payment_retry_count"]),
          int(tx.get("same_device_multiple_accounts", 0)), int(tx.get("login_location_changed", 0)),
          "review" if score >= 55 else "approved"))
    tx_id = cursor.lastrowid
    
    # 2. Save Risk Score
    level = res["level"].replace("🔴 ", "").replace("🟠 ", "").replace("🟡 ", "").replace("🟢 ", "").split()[0]
    verdict = res["verdict"]
    cursor.execute("""
        INSERT INTO risk_scores (target_type, target_id, rule_based_pct, ai_prob, final_pct, level, verdict, triggered_flags, triggered_combos)
        VALUES ('transaction', ?, ?, ?, ?, ?, ?, ?, ?)
    """, (tx_id, res["rule_based_pct"], res["ai_prob"], score,
          level, verdict, json.dumps([k for k, v in res["flags"].items() if v == 1]),
          json.dumps([c["combo_id"] for c in res["triggered_combos"]])))
    
    # 3. Log Audit Entry
    cursor.execute("""
        INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
        VALUES ('transaction', ?, 'created', ?, 'System', ?)
    """, (tx_id, f"Generated transaction for {name}. Score: {score}%. Status: {'REVIEW' if score >= 55 else 'APPROVED'}.", timestamp))
    
    alert_id = None
    # 4. Generate Alert if Score >= 55%
    if score >= 55:
        rec_act = "Flag account for immediate review. Inspect payment retry logs."
        if level == "CRITICAL":
            rec_act = "IMMEDIATE ACTION REQUIRED: Block account and freeze remaining subsidy balance."
        elif level == "HIGH":
            rec_act = "Verify identity document (NIK) and review login location history."
            
        alert_id = f"ALT-{datetime.now().strftime('%Y%m%d')}-TX{tx_id:04d}"
        triggered_flags = [k for k, v in res["flags"].items() if v == 1]
        
        cursor.execute("""
            INSERT INTO alerts (alert_id, target_type, target_id, customer_name, customer_id, risk_score, fraud_indicators_triggered, transaction_details, detection_timestamp, status, severity_level, recommended_action)
            VALUES (?, 'transaction', ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
        """, (alert_id, tx_id, name, c_id, score, json.dumps(triggered_flags), json.dumps(tx), timestamp, level, rec_act))
        alert_db_id = cursor.lastrowid
        
        # Log Alert
        cursor.execute("""
            INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
            VALUES ('alert', ?, 'triggered', ?, 'System', ?)
        """, (alert_db_id, f"Alert {alert_id} generated for {name} transaction ID {tx_id}.", timestamp))
        
    conn.commit()
    conn.close()
    
    # Sync documentation
    database.sync_all_documentation()
    
    # Save generated/scored transactions to log CSV file
    save_to_csv_log(tx, score, level, verdict, alert_id)
    
    # Print backend logs
    print(f"Generated transaction TX{tx_id:04d} for {name}")
    print(f"Risk score: {score}%")
    if alert_id:
        print(f"Alert created: {alert_id}")
    print("Stored in generated_transactions_log.csv")
    
    return tx, score, alert_id

@app.route('/api/generate', methods=['GET'])
def generate_tx():
    try:
        tx, score, alert_id = generate_and_score_transaction_internal()
        
        # Format clean response matching CSV headers
        clean_tx = {}
        for k, v in tx.items():
            if isinstance(v, (np.integer, np.int64, np.int32)):
                clean_tx[k] = int(v)
            elif isinstance(v, (np.floating, np.float64, np.float32)):
                clean_tx[k] = float(v)
            else:
                clean_tx[k] = v
        clean_tx["Name/customer_id"] = tx.get("Name/customer_id", 999)
        clean_tx["customer_id"] = tx.get("Name/customer_id", 999)

        return jsonify({"status": "success", "transaction": clean_tx})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


# ─── API: ANALYZE ONE TRANSACTION ────────────────────────────────────────────
@app.route('/api/analyze', methods=['POST', 'OPTIONS'])
def analyze_tx():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400

        t = {}
        t["Initial_Subsidy"]                        = float(data.get("Initial_Subsidy", 0))
        t["transaction_amount"]                     = float(data.get("transaction_amount", 0))
        t["Subsidy_balance"]                        = round(t["Initial_Subsidy"] - t["transaction_amount"], 2)
        t["hour_of_day"]                            = int(data.get("hour_of_day", 12))
        t["num_items"]                              = int(data.get("num_items", 1))
        t["repeated_product_purchase(>10)"]         = int(data.get("repeated_product_purchase(>10)", 0))
        t["same_product_transcation_count_month"]   = int(data.get("same_product_transcation_count_month", 0))
        t["prev_transactions"]                      = int(data.get("prev_transactions", 0))
        t["is_first_transaction"]                   = int(data.get("is_first_transaction", 0))
        t["National_ID_verification"]               = int(data.get("National_ID_verification", 1))
        t["KKS_card_validation"]                    = int(data.get("KKS_card_validation", 1))
        t["Duplicate_account_detection"]            = int(data.get("Duplicate_account_detection", 0))
        t["Transaction frequency (>3 per hour)"]    = int(data.get("Transaction frequency (>3 per hour)", 0))
        t["valid_card"]                             = int(data.get("valid_card", 1))
        t["IP address (outside Indonesia )"]        = int(data.get("IP address (outside Indonesia )", 0))
        t["app(0) vs kiosk(1)transaction"]          = int(data.get("app(0) vs kiosk(1)transaction", 0))
        t["failed_login_attempts"]                  = int(data.get("failed_login_attempts", 0))
        t["payment_retry_count"]                    = int(data.get("payment_retry_count", 0))
        t["same_device_multiple_accounts"]          = int(data.get("same_device_multiple_accounts", 0))
        t["login_location_changed"]                 = int(data.get("login_location_changed", 0))

        result = final.score_transaction(t)

        clean_result = {
            "rule_based_pct":   float(result["rule_based_pct"]),
            "ai_prob":          float(result["ai_prob"]),
            "final_pct":        float(result["final_pct"]),
            "level":            str(result["level"]),
            "verdict":          str(result["verdict"]),
            "n_flags":          int(result["n_flags"]),
            "flags":            {k: int(v) for k, v in result["flags"].items()},
            "triggered_combos": [
                {
                    "combo_id":    str(c["combo_id"]),
                    "name":        str(c["name"]),
                    "combo_score": float(c["combo_score"]),
                    "tier":        str(c["tier"]),
                    "reason":      str(c["reason"]),
                    "flags":       c["flags"]
                }
                for c in result["triggered_combos"]
            ],
            "highest_combo": {
                "combo_id":    str(result["highest_combo"]["combo_id"]),
                "name":        str(result["highest_combo"]["name"]),
                "combo_score": float(result["highest_combo"]["combo_score"]),
                "tier":        str(result["highest_combo"]["tier"]),
                "reason":      str(result["highest_combo"]["reason"]),
                "flags":       result["highest_combo"]["flags"]
            } if result["highest_combo"] else None
        }

        return jsonify({"status": "success", "result": clean_result})
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": "An internal server error occurred."}), 500

# ─── PRODUCTION FRAUD ENGINE ENDPOINTS ───────────────────────────────────────

FLAG_MAP_TO_API = {
    "flag_ip_outsider": "ip_outside_indonesia",
    "flag_repeated_purchase": "repeated_product_purchase",
    "flag_high_frequency": "transaction_frequency_high",
    "flag_duplicate_account": "duplicate_account_detection",
    "flag_same_device": "same_device_multiple_accounts",
    "flag_location_changed": "login_location_changed",
    "flag_same_product_high": "same_product_transaction_count_month",
    "flag_payment_retry": "payment_retry_count",
    "flag_failed_login": "failed_login_attempts",
    "flag_id_not_verified": "national_id_verification",
    "flag_kks_not_valid": "kks_card_validation",
    "flag_card_invalid": "valid_card",
    "flag_subsidy_exhausted": "subsidy_exhausted",
    "flag_kiosk": "app_vs_kiosk"
}

def validate_and_score_transaction_payload(data):
    # binary fields (0 or 1)
    binary_fields = [
        "is_first_transaction", "national_id_verification", "kks_card_validation", 
        "duplicate_account_detection", "transaction_frequency_high", "valid_card", 
        "ip_outside_indonesia", "app_vs_kiosk", "same_device_multiple_accounts", 
        "login_location_changed"
    ]
    
    # non-negative integer fields
    integer_fields = [
        "customer_id", "hour_of_day", "num_items", "repeated_product_purchase", 
        "same_product_transaction_count_month", "previous_transactions", 
        "failed_login_attempts", "payment_retry_count"
    ]
    
    # float/int fields (non-negative)
    amount_fields = ["initial_subsidy", "transaction_amount"]
    
    # Verify all required fields exist (except optional subsidy_balance)
    for field in binary_fields + integer_fields + amount_fields:
        if field not in data:
            raise ValueError(f"Missing required field: {field}")
            
    # Validate binary fields
    for field in binary_fields:
        val = data[field]
        if not isinstance(val, int) or isinstance(val, bool) or val not in [0, 1]:
            raise ValueError(f"Invalid value for binary field '{field}': must be 0 or 1")
            
    # Validate integer fields
    for field in integer_fields:
        val = data[field]
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise ValueError(f"Invalid value for integer field '{field}': must be a non-negative integer")
            
    # Validate hour_of_day range
    if data["hour_of_day"] > 23:
        raise ValueError("Invalid value for 'hour_of_day': must be between 0 and 23")
        
    # Validate amount fields
    for field in amount_fields:
        val = data[field]
        if not isinstance(val, (int, float)) or isinstance(val, bool) or val < 0:
            raise ValueError(f"Invalid value for field '{field}': must be a non-negative number")
            
    # Handle subsidy_balance
    if "subsidy_balance" in data and data["subsidy_balance"] is not None:
        sub_bal = data["subsidy_balance"]
        if not isinstance(sub_bal, (int, float)) or isinstance(sub_bal, bool) or sub_bal < 0:
            raise ValueError("Invalid value for field 'subsidy_balance': must be a non-negative number")
    else:
        sub_bal = round(float(data["initial_subsidy"]) - float(data["transaction_amount"]), 2)
        
    return sub_bal

def save_scoring_log(request_id, transaction_id, data, sub_bal, res, score, risk_category, decision, allow_transaction, triggered_flags, triggered_combo_rules, highest_combo, recommendation, timestamp):
    conn = database.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO fraud_scoring_logs (
                request_id, transaction_id, customer_id, initial_subsidy, transaction_amount, subsidy_balance,
                hour_of_day, num_items, repeated_product_purchase, same_product_transaction_count_month,
                previous_transactions, is_first_transaction, national_id_verification, kks_card_validation,
                duplicate_account_detection, transaction_frequency_high, valid_card, ip_outside_indonesia,
                app_vs_kiosk, failed_login_attempts, payment_retry_count, same_device_multiple_accounts,
                login_location_changed, rule_based_score, ai_probability_score, final_risk_score,
                risk_category, decision, allow_transaction, triggered_flags, triggered_combo_rules,
                highest_combo_rule, recommendation, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request_id, transaction_id, int(data["customer_id"]), float(data["initial_subsidy"]), float(data["transaction_amount"]), float(sub_bal),
            int(data["hour_of_day"]), int(data["num_items"]), int(data["repeated_product_purchase"]), int(data["same_product_transaction_count_month"]),
            int(data["previous_transactions"]), int(data["is_first_transaction"]), int(data["national_id_verification"]), int(data["kks_card_validation"]),
            int(data["duplicate_account_detection"]), int(data["transaction_frequency_high"]), int(data["valid_card"]), int(data["ip_outside_indonesia"]),
            int(data["app_vs_kiosk"]), int(data["failed_login_attempts"]), int(data["payment_retry_count"]), int(data["same_device_multiple_accounts"]),
            int(data["login_location_changed"]), float(res["rule_based_pct"]), float(res["ai_prob"]), float(score),
            risk_category, decision, 1 if allow_transaction else 0, json.dumps(triggered_flags), json.dumps(triggered_combo_rules),
            highest_combo, recommendation, timestamp
        ))
        conn.commit()
    except Exception as e:
        print(f"[Fraud Logger] Database write failed: {e}")
        conn.rollback()
    finally:
        conn.close()

@app.route('/api/fraud/score', methods=['POST'])
@require_api_key
@rate_limit(limit=60, window=60)
def post_fraud_score():
    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "Missing request payload"}), 400
            
        try:
            sub_bal = validate_and_score_transaction_payload(data)
        except ValueError as val_err:
            return jsonify({"status": "error", "message": str(val_err)}), 400
            
        # Map fields to scoring format
        t_mapped = {
            "Initial_Subsidy": float(data["initial_subsidy"]),
            "transaction_amount": float(data["transaction_amount"]),
            "Subsidy_balance": float(sub_bal),
            "hour_of_day": int(data["hour_of_day"]),
            "num_items": int(data["num_items"]),
            "repeated_product_purchase(>10)": int(data["repeated_product_purchase"]),
            "same_product_transcation_count_month": int(data["same_product_transaction_count_month"]),
            "prev_transactions": int(data["previous_transactions"]),
            "is_first_transaction": int(data["is_first_transaction"]),
            "National_ID_verification": int(data["national_id_verification"]),
            "KKS_card_validation": int(data["kks_card_validation"]),
            "Duplicate_account_detection": int(data["duplicate_account_detection"]),
            "Transaction frequency (>3 per hour)": int(data["transaction_frequency_high"]),
            "valid_card": int(data["valid_card"]),
            "IP address (outside Indonesia )": int(data["ip_outside_indonesia"]),
            "app(0) vs kiosk(1)transaction": int(data["app_vs_kiosk"]),
            "failed_login_attempts": int(data["failed_login_attempts"]),
            "payment_retry_count": int(data["payment_retry_count"]),
            "same_device_multiple_accounts": int(data["same_device_multiple_accounts"]),
            "login_location_changed": int(data["login_location_changed"])
        }
        
        # Invoke scoring logic
        res = final.score_transaction(t_mapped)
        score = float(res["final_pct"])
        
        # Determine risk and decision
        if score < 40:
            risk_category = "LOW"
            decision = "APPROVE"
            allow_transaction = True
        elif score < 55:
            risk_category = "MEDIUM"
            decision = "REVIEW"
            allow_transaction = False
        elif score < 80:
            risk_category = "HIGH"
            decision = "BLOCK"
            allow_transaction = False
        else:
            risk_category = "CRITICAL"
            decision = "BLOCK"
            allow_transaction = False
            
        request_id = f"REQ-{datetime.utcnow().strftime('%Y%m%d')}-{random.randint(100000, 999999)}"
        transaction_id = f"TX-{datetime.utcnow().strftime('%Y%m%d')}-{random.randint(100000, 999999)}"
        
        triggered_flags = [FLAG_MAP_TO_API.get(k, k) for k, v in res["flags"].items() if v == 1]
        triggered_combo_rules = [c["combo_id"] for c in res["triggered_combos"]]
        highest_combo = res["highest_combo"]["combo_id"] if res["highest_combo"] else None
        
        # Recommendation
        recommendation = "Allow transaction."
        if decision == "BLOCK":
            if risk_category == "CRITICAL":
                recommendation = "Block the transaction and investigate the account."
            else:
                recommendation = "Verify identity document (NIK) and review login location history."
        elif decision == "REVIEW":
            recommendation = "Flag account for immediate review. Inspect payment retry logs."
            
        timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        
        # Save to logs
        save_scoring_log(
            request_id, transaction_id, data, sub_bal, res, score,
            risk_category, decision, allow_transaction, triggered_flags,
            triggered_combo_rules, highest_combo, recommendation, timestamp
        )
        
        print(f"[Fraud API] [SCORE] IP: {request.remote_addr} - Req: {request_id} - Score: {score}% - Decision: {decision}")
        
        return jsonify({
            "status": "success",
            "request_id": request_id,
            "transaction_id": transaction_id,
            "rule_based_score": float(res["rule_based_pct"]),
            "ai_probability_score": float(res["ai_prob"]),
            "final_risk_score": score,
            "risk_category": risk_category,
            "decision": decision,
            "allow_transaction": allow_transaction,
            "triggered_flags": triggered_flags,
            "triggered_combo_rules": triggered_combo_rules,
            "highest_combo_rule": highest_combo,
            "recommendation": recommendation,
            "timestamp": timestamp
        }), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": "An internal server error occurred."}), 500

@app.route('/api/checkout', methods=['POST'])
@require_api_key
@rate_limit(limit=60, window=60)
def post_checkout():
    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "Missing request payload"}), 400
            
        # 1. Run fraud check
        try:
            sub_bal = validate_and_score_transaction_payload(data)
            
            # Map fields to scoring format
            t_mapped = {
                "Initial_Subsidy": float(data["initial_subsidy"]),
                "transaction_amount": float(data["transaction_amount"]),
                "Subsidy_balance": float(sub_bal),
                "hour_of_day": int(data["hour_of_day"]),
                "num_items": int(data["num_items"]),
                "repeated_product_purchase(>10)": int(data["repeated_product_purchase"]),
                "same_product_transcation_count_month": int(data["same_product_transaction_count_month"]),
                "prev_transactions": int(data["previous_transactions"]),
                "is_first_transaction": int(data["is_first_transaction"]),
                "National_ID_verification": int(data["national_id_verification"]),
                "KKS_card_validation": int(data["kks_card_validation"]),
                "Duplicate_account_detection": int(data["duplicate_account_detection"]),
                "Transaction frequency (>3 per hour)": int(data["transaction_frequency_high"]),
                "valid_card": int(data["valid_card"]),
                "IP address (outside Indonesia )": int(data["ip_outside_indonesia"]),
                "app(0) vs kiosk(1)transaction": int(data["app_vs_kiosk"]),
                "failed_login_attempts": int(data["failed_login_attempts"]),
                "payment_retry_count": int(data["payment_retry_count"]),
                "same_device_multiple_accounts": int(data["same_device_multiple_accounts"]),
                "login_location_changed": int(data["login_location_changed"])
            }
            
            # Score
            res = final.score_transaction(t_mapped)
            score = float(res["final_pct"])
            
            # Determine risk and decision
            if score < 40:
                risk_category = "LOW"
                decision = "APPROVE"
                allow_transaction = True
            elif score < 55:
                risk_category = "MEDIUM"
                decision = "REVIEW"
                allow_transaction = False
            elif score < 80:
                risk_category = "HIGH"
                decision = "BLOCK"
                allow_transaction = False
            else:
                risk_category = "CRITICAL"
                decision = "BLOCK"
                allow_transaction = False
                
            request_id = f"REQ-{datetime.utcnow().strftime('%Y%m%d')}-{random.randint(100000, 999999)}"
            transaction_id = f"TX-{datetime.utcnow().strftime('%Y%m%d')}-{random.randint(100000, 999999)}"
            
            triggered_flags = [FLAG_MAP_TO_API.get(k, k) for k, v in res["flags"].items() if v == 1]
            triggered_combo_rules = [c["combo_id"] for c in res["triggered_combos"]]
            highest_combo = res["highest_combo"]["combo_id"] if res["highest_combo"] else None
            
            recommendation = "Allow transaction."
            if decision == "BLOCK":
                if risk_category == "CRITICAL":
                    recommendation = "Block the transaction and investigate the account."
                else:
                    recommendation = "Verify identity document (NIK) and review login location history."
            elif decision == "REVIEW":
                recommendation = "Flag account for immediate review. Inspect payment retry logs."
                
            timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            
            # Log scoring result
            save_scoring_log(
                request_id, transaction_id, data, sub_bal, res, score,
                risk_category, decision, allow_transaction, triggered_flags,
                triggered_combo_rules, highest_combo, recommendation, timestamp
            )
            
        except Exception as e_score:
            print(f"[Checkout Fraud Guard] Scoring failed: {e_score}")
            # Fail closed to REVIEW
            sub_bal = round(float(data.get("initial_subsidy", 0)) - float(data.get("transaction_amount", 0)), 2)
            score = 50.0
            risk_category = "MEDIUM"
            decision = "REVIEW"
            allow_transaction = False
            triggered_flags = []
            triggered_combo_rules = []
            highest_combo = None
            recommendation = "System error/timeout during fraud scoring. Holding for manual review."
            request_id = f"REQ-{datetime.utcnow().strftime('%Y%m%d')}-{random.randint(100000, 999999)}"
            transaction_id = f"TX-{datetime.utcnow().strftime('%Y%m%d')}-{random.randint(100000, 999999)}"
            timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            
            res = {
                "rule_based_pct": 50.0,
                "ai_prob": 0.5,
                "verdict": "TIMEOUT / SCORING ENGINE FAULT"
            }
            
        # 2. Check Decision
        if decision == "BLOCK" or decision == "REVIEW":
            # Log attempted (blocked/review) transaction
            status_val = "blocked" if decision == "BLOCK" else "review"
            conn = database.get_db_connection()
            cursor = conn.cursor()
            try:
                t_mapped_log = dict(t_mapped) if 't_mapped' in locals() else {}
                t_mapped_log["Name/customer_id"] = int(data["customer_id"])
                
                # Fetch current balance (without deducting)
                customer_id = int(data["customer_id"])
                cursor.execute("""
                    SELECT subsidy_balance FROM transactions 
                    WHERE customer_id = ? AND status = 'approved' 
                    ORDER BY id DESC LIMIT 1
                """, (customer_id,))
                last_tx = cursor.fetchone()
                current_balance = float(last_tx["subsidy_balance"]) if last_tx else float(data["initial_subsidy"])
                
                # Insert attempted transaction
                cursor.execute("""
                    INSERT INTO transactions (
                        customer_id, initial_subsidy, transaction_amount, subsidy_balance, hour_of_day, num_items,
                        repeated_product_purchase, same_product_transaction_count_month, prev_transactions,
                        is_first_transaction, national_id_verification, kks_card_validation, duplicate_account_detection,
                        transaction_frequency_high, valid_card, ip_outside_indonesia, app_vs_kiosk, failed_login_attempts,
                        payment_retry_count, same_device_multiple_accounts, login_location_changed, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    customer_id, float(data["initial_subsidy"]), float(data["transaction_amount"]), current_balance,
                    int(data["hour_of_day"]), int(data["num_items"]), int(data["repeated_product_purchase"]), int(data["same_product_transaction_count_month"]),
                    int(data["previous_transactions"]), int(data["is_first_transaction"]), int(data["national_id_verification"]), int(data["kks_card_validation"]),
                    int(data["duplicate_account_detection"]), int(data["transaction_frequency_high"]), int(data["valid_card"]), int(data["ip_outside_indonesia"]),
                    int(data["app_vs_kiosk"]), int(data["failed_login_attempts"]), int(data["payment_retry_count"]), int(data["same_device_multiple_accounts"]),
                    int(data["login_location_changed"]), status_val
                ))
                db_tx_id = cursor.lastrowid
                
                # Save Risk Score
                cursor.execute("""
                    INSERT INTO risk_scores (target_type, target_id, rule_based_pct, ai_prob, final_pct, level, verdict, triggered_flags, triggered_combos)
                    VALUES ('transaction', ?, ?, ?, ?, ?, ?, ?, ?)
                """, (db_tx_id, res["rule_based_pct"], res["ai_prob"], score,
                      risk_category, res["verdict"], json.dumps(triggered_flags),
                      json.dumps(triggered_combo_rules)))
                      
                # Log Audit Entry
                cursor.execute("""
                    INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
                    VALUES ('transaction', ?, ?, ?, 'System', ?)
                """, (db_tx_id, status_val, f"Attempted transaction {decision}ed. Status: {status_val.upper()}.", timestamp))
                
                # Generate Alerts for HIGH and CRITICAL (score >= 55)
                if score >= 55:
                    cursor.execute("SELECT name FROM members WHERE id = ?", (customer_id,))
                    member_row = cursor.fetchone()
                    member_name = member_row["name"] if member_row else f"Customer {customer_id}"
                    
                    alert_id = f"ALT-{datetime.utcnow().strftime('%Y%m%d')}-TX{db_tx_id:04d}"
                    
                    cursor.execute("""
                        INSERT INTO alerts (alert_id, target_type, target_id, customer_name, customer_id, risk_score, fraud_indicators_triggered, transaction_details, detection_timestamp, status, severity_level, recommended_action)
                        VALUES (?, 'transaction', ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
                    """, (alert_id, db_tx_id, member_name, customer_id, score, json.dumps(triggered_flags), json.dumps(data), timestamp, risk_category, recommendation))
                    alert_db_id = cursor.lastrowid
                    
                    cursor.execute("""
                        INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
                        VALUES ('alert', ?, 'triggered', ?, 'System', ?)
                    """, (alert_db_id, f"Alert {alert_id} generated for {member_name} attempted transaction ID {db_tx_id}.", timestamp))
                    
                    # Save to CSV log file
                    save_to_csv_log(t_mapped_log, score, risk_category, res["verdict"], alert_id)
                    
                conn.commit()
            except Exception as e_log:
                conn.rollback()
                print(f"[Checkout] Failed to log blocked/review transaction: {e_log}")
            finally:
                conn.close()
                database.sync_all_documentation()
                
            return jsonify({
                "status": "blocked",
                "message": "This purchase could not be completed because additional verification is required. Please contact support."
            }), 403
            
        # 3. Decision is APPROVE: Process in SQLite Transaction
        conn = database.get_db_connection()
        conn.isolation_level = None  # Manual transactions
        cursor = conn.cursor()
        try:
            cursor.execute("BEGIN TRANSACTION")
            
            customer_id = int(data["customer_id"])
            cursor.execute("SELECT name, verification_status FROM members WHERE id = ?", (customer_id,))
            member = cursor.fetchone()
            if not member:
                raise ValueError(f"Member ID {customer_id} does not exist.")
                
            if member["verification_status"] in ["Flagged", "Blocked"]:
                raise ValueError("Member account is restricted or flagged.")
                
            # Get latest balance
            cursor.execute("""
                SELECT subsidy_balance FROM transactions 
                WHERE customer_id = ? AND status = 'approved' 
                ORDER BY id DESC LIMIT 1
            """, (customer_id,))
            last_tx = cursor.fetchone()
            if last_tx:
                current_balance = float(last_tx["subsidy_balance"])
            else:
                current_balance = float(data["initial_subsidy"])
                
            tx_amount = float(data["transaction_amount"])
            if current_balance < tx_amount:
                raise ValueError(f"Insufficient subsidy balance: current is {current_balance}, required is {tx_amount}")
                
            new_balance = round(current_balance - tx_amount, 2)
            
            # Insert approved transaction
            cursor.execute("""
                INSERT INTO transactions (
                    customer_id, initial_subsidy, transaction_amount, subsidy_balance, hour_of_day, num_items,
                    repeated_product_purchase, same_product_transaction_count_month, prev_transactions,
                    is_first_transaction, national_id_verification, kks_card_validation, duplicate_account_detection,
                    transaction_frequency_high, valid_card, ip_outside_indonesia, app_vs_kiosk, failed_login_attempts,
                    payment_retry_count, same_device_multiple_accounts, login_location_changed, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved')
            """, (
                customer_id, float(data["initial_subsidy"]), tx_amount, new_balance,
                int(data["hour_of_day"]), int(data["num_items"]), int(data["repeated_product_purchase"]), int(data["same_product_transaction_count_month"]),
                int(data["previous_transactions"]), int(data["is_first_transaction"]), int(data["national_id_verification"]), int(data["kks_card_validation"]),
                int(data["duplicate_account_detection"]), int(data["transaction_frequency_high"]), int(data["valid_card"]), int(data["ip_outside_indonesia"]),
                int(data["app_vs_kiosk"]), int(data["failed_login_attempts"]), int(data["payment_retry_count"]), int(data["same_device_multiple_accounts"]),
                int(data["login_location_changed"])
            ))
            db_tx_id = cursor.lastrowid
            
            # Save Risk Score
            cursor.execute("""
                INSERT INTO risk_scores (target_type, target_id, rule_based_pct, ai_prob, final_pct, level, verdict, triggered_flags, triggered_combos)
                VALUES ('transaction', ?, ?, ?, ?, ?, ?, ?, ?)
            """, (db_tx_id, res["rule_based_pct"], res["ai_prob"], score,
                  risk_category, res["verdict"], json.dumps(triggered_flags),
                  json.dumps(triggered_combo_rules)))
                  
            # Log Audit Entry
            cursor.execute("""
                INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
                VALUES ('transaction', ?, 'completed', ?, 'System', ?)
            """, (db_tx_id, f"Approved transaction checkout. New subsidy balance: {new_balance}.", timestamp))
            
            cursor.execute("COMMIT")
            print(f"[Checkout] Approved checkout completed successfully for customer {customer_id}, transaction: {db_tx_id}")
            
        except Exception as e_commit:
            cursor.execute("ROLLBACK")
            print(f"[Checkout] Transaction rollback due to error: {e_commit}")
            return jsonify({"status": "error", "message": f"Checkout processing failed: {str(e_commit)}"}), 400
        finally:
            conn.close()
            database.sync_all_documentation()
            
        return jsonify({
            "status": "success",
            "message": "Checkout completed successfully.",
            "transaction_id": f"TX-APPROVED-{db_tx_id}",
            "remaining_subsidy": new_balance
        }), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": "An internal server error occurred."}), 500

@app.route('/api/fraud/feedback', methods=['POST'])
@require_api_key
@rate_limit(limit=60, window=60)
def post_fraud_feedback():
    try:
        data = request.json
        if not data:
            return jsonify({"status": "error", "message": "Missing request payload"}), 400
            
        required_fields = ["transaction_id", "model_decision", "auditor_decision", "confirmed_label", "notes", "reviewed_by", "reviewed_at"]
        for field in required_fields:
            if field not in data:
                return jsonify({"status": "error", "message": f"Missing required field: {field}"}), 400
                
        confirmed_label = data["confirmed_label"]
        if confirmed_label not in ['fraud', 'legitimate', 'unknown']:
            return jsonify({"status": "error", "message": "Invalid confirmed_label: must be 'fraud', 'legitimate', or 'unknown'"}), 400
            
        # Write to Database
        conn = database.get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO fraud_feedback (
                    transaction_id, model_decision, auditor_decision, confirmed_label, notes, reviewed_by, reviewed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                data["transaction_id"], data["model_decision"], data["auditor_decision"],
                confirmed_label, data["notes"], data["reviewed_by"], data["reviewed_at"]
            ))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            return jsonify({"status": "error", "message": f"Feedback for transaction_id '{data['transaction_id']}' already exists."}), 400
        except Exception as e:
            conn.rollback()
            print(f"[Feedback API] Database error: {e}")
            return jsonify({"status": "error", "message": "An internal database error occurred."}), 500
        finally:
            conn.close()
            
        # Append to Retraining CSV
        retrain_csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "retraining_feedback_dataset.csv")
        file_exists = os.path.exists(retrain_csv_path)
        headers = ["timestamp", "transaction_id", "model_decision", "auditor_decision", "confirmed_label", "notes", "reviewed_by", "reviewed_at"]
        
        row = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "transaction_id": data["transaction_id"],
            "model_decision": data["model_decision"],
            "auditor_decision": data["auditor_decision"],
            "confirmed_label": confirmed_label,
            "notes": data["notes"],
            "reviewed_by": data["reviewed_by"],
            "reviewed_at": data["reviewed_at"]
        }
        
        try:
            with open(retrain_csv_path, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                if not file_exists:
                    writer.writeheader()
                writer.writerow(row)
        except Exception as e:
            print(f"[Feedback API] CSV append error: {e}")
            
        print(f"[Fraud API] [FEEDBACK] Transaction: {data['transaction_id']} - Auditor Decision: {data['auditor_decision']} ({confirmed_label})")
        
        return jsonify({
            "status": "success",
            "message": "Feedback successfully recorded."
        }), 200
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": "An internal server error occurred."}), 500

# ─── BACKGROUND TRANSACTION GENERATOR ──────────────────────────────────────────
LOCK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generator.lock")

def generator_loop():
    my_pid = os.getpid()
    try:
        with open(LOCK_FILE, "w") as f:
            f.write(str(my_pid))
        print(f"[Background Generator] Started thread in process PID: {my_pid}")
    except Exception as e:
        print(f"[Background Generator] Error writing lock file: {e}")
        
    while True:
        # Check if background generator is enabled
        enabled = os.environ.get("ENABLE_BACKGROUND_GENERATOR", "false").lower() == "true"
        
        # Check PID lock to prevent duplicate threads in multi-worker environments
        try:
            if os.path.exists(LOCK_FILE):
                with open(LOCK_FILE, "r") as f:
                    lock_pid = f.read().strip()
                if lock_pid and int(lock_pid) != my_pid:
                    print(f"[Background Generator] PID mismatch (lock: {lock_pid}, mine: {my_pid}). Terminating thread.")
                    break
        except Exception as e:
            print(f"[Background Generator] Lock check warning: {e}")
            
        if enabled:
            try:
                generate_and_score_transaction_internal()
            except Exception as e:
                print(f"[Background Generator] Error generating transaction: {e}")
                traceback.print_exc()
                
        # Read interval dynamically
        try:
            interval = float(os.environ.get("BACKGROUND_GENERATOR_INTERVAL", "30"))
        except Exception:
            interval = 30.0
            
        time.sleep(interval)

def start_background_generator():
    t = threading.Thread(target=generator_loop, daemon=True)
    t.start()

# Start background generator only if explicitly enabled (prevents thread deadlocks on Gunicorn/Render startup)
if os.environ.get("ENABLE_BACKGROUND_GENERATOR", "false").lower() == "true":
    start_background_generator()

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 50001))
    app.run(host='0.0.0.0', port=port, debug=False)

