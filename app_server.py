import sys
import os
import json
import traceback
import numpy as np
import random
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
print("[Server] Initializing database...")
try:
    database.db_init()
    print("[Server] Database initialized successfully!")
except Exception as e:
    print("[Server] Database initialization failed:")
    traceback.print_exc()
    sys.exit(1)

from flask import Flask, jsonify, request, render_template, session
from functools import wraps

def require_auth(f):
    return f

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
        
        records = []
        for r in rows:
            rec = dict(r)
            # Fetch audit history for this transaction
            cursor.execute("SELECT * FROM audit_logs WHERE target_type = 'transaction' AND target_id = ? ORDER BY id DESC", (r["id"],))
            logs = cursor.fetchall()
            audit_history = []
            for log in logs:
                audit_history.append({
                    "action": log["action"],
                    "note": log["note"],
                    "timestamp": log["timestamp"]
                })
            
            rec["auditHistory"] = audit_history
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
            members = []
            for r in rows:
                m = dict(r)
                # Fetch audit history
                cursor.execute("SELECT * FROM audit_logs WHERE target_type = 'member' AND target_id = ? ORDER BY id DESC", (r["id"],))
                logs = cursor.fetchall()
                audit_history = []
                for log in logs:
                    audit_history.append({
                        "action": log["action"],
                        "note": log["note"],
                        "timestamp": log["timestamp"]
                    })
                m["auditHistory"] = audit_history
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
        
        alerts = []
        for r in rows:
            alt = dict(r)
            alt["indicators"] = json.loads(r["fraud_indicators_triggered"])
            alt["transaction_details"] = json.loads(r["transaction_details"]) if r["transaction_details"] else None
            
            # Fetch audit logs timeline for this alert
            cursor.execute("SELECT * FROM audit_logs WHERE target_type = 'alert' AND target_id = ? ORDER BY id DESC", (r["id"],))
            logs = cursor.fetchall()
            history = []
            for log in logs:
                history.append({
                    "action": log["action"],
                    "note": log["note"],
                    "operator": log["operator"],
                    "timestamp": log["timestamp"]
                })
            alt["auditHistory"] = history
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
@app.route('/api/generate', methods=['GET'])
def generate_tx():
    try:
        # Generate raw transaction
        tx = final.generate_one_transaction()
        
        # Link it to a random member from the database
        conn = database.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, ip_address, device_info FROM members ORDER BY RANDOM() LIMIT 1")
        member = cursor.fetchone()
        
        if member:
            c_id = member["id"]
            name = member["name"]
            # Sync transaction parameters with member's profile
            tx["Name/customer_id"] = c_id
            
            # Map outside Indonesia flag based on IP
            is_outside = 1 if not member["ip_address"].startswith("180.250.") else 0
            tx["IP address (outside Indonesia )"] = is_outside
        else:
            # Fallback
            c_id = 999
            name = "Default Customer"
            tx["Name/customer_id"] = c_id
            
        # Evaluate using hybrid engine
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
        cursor.execute("""
            INSERT INTO risk_scores (target_type, target_id, rule_based_pct, ai_prob, final_pct, level, verdict, triggered_flags, triggered_combos)
            VALUES ('transaction', ?, ?, ?, ?, ?, ?, ?, ?)
        """, (tx_id, res["rule_based_pct"], res["ai_prob"], score,
              res["level"].replace("🔴 ", "").replace("🟠 ", "").replace("🟡 ", "").replace("🟢 ", "").split()[0],
              res["verdict"], json.dumps([k for k, v in res["flags"].items() if v == 1]),
              json.dumps([c["combo_id"] for c in res["triggered_combos"]])))
        
        # 3. Log Audit Entry
        cursor.execute("""
            INSERT INTO audit_logs (target_type, target_id, action, note, operator, timestamp)
            VALUES ('transaction', ?, 'created', ?, 'System', ?)
        """, (tx_id, f"Generated transaction for {name}. Score: {score}%. Status: {'REVIEW' if score >= 55 else 'APPROVED'}.", timestamp))
        
        # 4. Generate Alert if Score >= 55%
        if score >= 55:
            sev = res["level"].replace("🔴 ", "").replace("🟠 ", "").replace("🟡 ", "").replace("🟢 ", "").split()[0]
            rec_act = "Flag account for immediate review. Inspect payment retry logs."
            if sev == "CRITICAL":
                rec_act = "IMMEDIATE ACTION REQUIRED: Block account and freeze remaining subsidy balance."
            elif sev == "HIGH":
                rec_act = "Verify identity document (NIK) and review login location history."
                
            alert_id = f"ALT-{datetime.now().strftime('%Y%m%d')}-TX{tx_id:04d}"
            triggered_flags = [k for k, v in res["flags"].items() if v == 1]
            
            cursor.execute("""
                INSERT INTO alerts (alert_id, target_type, target_id, customer_name, customer_id, risk_score, fraud_indicators_triggered, transaction_details, detection_timestamp, status, severity_level, recommended_action)
                VALUES (?, 'transaction', ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?)
            """, (alert_id, tx_id, name, c_id, score, json.dumps(triggered_flags), json.dumps(tx), timestamp, sev, rec_act))
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

        # Format clean response matching CSV headers
        clean_tx = {}
        for k, v in tx.items():
            if isinstance(v, (np.integer, np.int64, np.int32)):
                clean_tx[k] = int(v)
            elif isinstance(v, (np.floating, np.float64, np.float32)):
                clean_tx[k] = float(v)
            else:
                clean_tx[k] = v
        clean_tx["Name/customer_id"] = c_id
        clean_tx["customer_id"] = c_id

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
        return jsonify({"status": "error", "message": str(e)}), 500

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 50001))
    app.run(host='0.0.0.0', port=port, debug=False)

