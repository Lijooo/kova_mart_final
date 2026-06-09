#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jun  2 11:35:52 2026

@author: macbookpro
"""

"""
Kova Mart — AI Fraud Detection + Single Transaction Generator
=============================================================
1. Trains an AI model (Random Forest) on the real dataset
2. Generates ONE synthetic transaction at a time (all columns)
3. Scores using combination-priority logic + AI model confidence

SCORING LOGIC:
- Standalone flags score 0 — NOT risk signals on their own
- Only COMBINATIONS of flags trigger risk
- Combinations have combo_score (0-100) = risk percentage when fired
- Multiple combos: highest sets floor, each extra adds 5% escalation
- Final score = max(combo_score, ai_model_probability)
- If NO combos fire but 3+ flags: catch-all escalation applies
"""

import warnings
warnings.filterwarnings("ignore")

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from imblearn.over_sampling import SMOTE

# ─── CONFIG ───────────────────────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "Kova_Mart_Dataset - Sheet1.csv")

# ─── INDIVIDUAL INDICATOR WEIGHTS ─────────────────────────────────────────────
RISK_WEIGHTS = {
    "flag_ip_outsider":        14,
    "flag_repeated_purchase":  13,
    "flag_high_frequency":     12,
    "flag_duplicate_account":  11,
    "flag_same_device":        10,
    "flag_location_changed":    9,
    "flag_same_product_high":   8,
    "flag_payment_retry":       7,
    "flag_failed_login":        6,
    "flag_id_not_verified":     5,
    "flag_kks_not_valid":       4,
    "flag_card_invalid":        3,
    "flag_subsidy_exhausted":   2,
    "flag_kiosk":               1,
}
MAX_INDIVIDUAL_SCORE = sum(RISK_WEIGHTS.values())  # 105

# ─── COMBINATION PRIORITY TABLE ───────────────────────────────────────────────
FRAUD_COMBINATIONS = [
    # ── TIER: CRITICAL (score 80–100) ─────────────────────────────────────────
    {
        "combo_id":    "C1",
        "name":        "Foreign IP + Failed Logins + Payment Retry",
        "flags":       ["flag_ip_outsider", "flag_failed_login", "flag_payment_retry"],
        "combo_score": 100,
        "tier":        "CRITICAL",
        "reason":      "External actor hammering access and payment — coordinated attack",
    },
    {
        "combo_id":    "C2",
        "name":        "Foreign IP + Location Changed + Same Device",
        "flags":       ["flag_ip_outsider", "flag_location_changed", "flag_same_device"],
        "combo_score": 95,
        "tier":        "CRITICAL",
        "reason":      "One device operating multiple accounts across changing locations from abroad",
    },
    {
        "combo_id":    "C3",
        "name":        "Foreign IP + Duplicate Account",
        "flags":       ["flag_ip_outsider", "flag_duplicate_account"],
        "combo_score": 90,
        "tier":        "CRITICAL",
        "reason":      "Ghost/fake account created and operated from outside Indonesia",
    },
    {
        "combo_id":    "C4",
        "name":        "Foreign IP + Subsidy Exhausted",
        "flags":       ["flag_ip_outsider", "flag_subsidy_exhausted"],
        "combo_score": 85,
        "tier":        "CRITICAL",
        "reason":      "Entire subsidy drained from foreign IP — ghost beneficiary pattern",
    },
    {
        "combo_id":    "C5",
        "name":        "Duplicate Account + Same Device + Location Changed",
        "flags":       ["flag_duplicate_account", "flag_same_device", "flag_location_changed"],
        "combo_score": 80,
        "tier":        "CRITICAL",
        "reason":      "Multiple fake identities on one device moving across locations — fraud farm",
    },
    # ── TIER: HIGH (score 55–75) ──────────────────────────────────────────────
    {
        "combo_id":    "C6",
        "name":        "High Frequency + Repeated Purchase + Same Product",
        "flags":       ["flag_high_frequency", "flag_repeated_purchase", "flag_same_product_high"],
        "combo_score": 75,
        "tier":        "HIGH",
        "reason":      "Rapid bulk buying of same subsidised product — reselling operation",
    },
    {
        "combo_id":    "C7",
        "name":        "Failed Logins + Payment Retry + High Frequency",
        "flags":       ["flag_failed_login", "flag_payment_retry", "flag_high_frequency"],
        "combo_score": 70,
        "tier":        "HIGH",
        "reason":      "Rapid-fire automated transaction attempts — bot behaviour",
    },
    {
        "combo_id":    "C8",
        "name":        "Failed Logins + Payment Retry + Invalid Card",
        "flags":       ["flag_failed_login", "flag_payment_retry", "flag_card_invalid"],
        "combo_score": 65,
        "tier":        "HIGH",
        "reason":      "Stolen credentials combined with invalid/stolen card",
    },
    {
        "combo_id":    "C9",
        "name":        "Duplicate Account + Failed Logins",
        "flags":       ["flag_duplicate_account", "flag_failed_login"],
        "combo_score": 60,
        "tier":        "HIGH",
        "reason":      "Fake account with repeated failed access attempts",
    },
    {
        "combo_id":    "C10",
        "name":        "Subsidy Exhausted + High Frequency",
        "flags":       ["flag_subsidy_exhausted", "flag_high_frequency"],
        "combo_score": 55,
        "tier":        "HIGH",
        "reason":      "Subsidy being rapidly and intentionally drained",
    },
    # ── TIER: MEDIUM (score 40–50) ────────────────────────────────────────────
    {
        "combo_id":    "C11",
        "name":        "Unverified ID + Invalid KKS + Invalid Card",
        "flags":       ["flag_id_not_verified", "flag_kks_not_valid", "flag_card_invalid"],
        "combo_score": 50,
        "tier":        "MEDIUM",
        "reason":      "All three identity credentials invalid — likely ghost beneficiary",
    },
    {
        "combo_id":    "C12",
        "name":        "Unverified ID + Duplicate Account",
        "flags":       ["flag_id_not_verified", "flag_duplicate_account"],
        "combo_score": 45,
        "tier":        "MEDIUM",
        "reason":      "Unverified identity combined with duplicate account detection",
    },
]

MULTI_COMBO_ESCALATION = 5  # % added per extra combo beyond the first

# ─── 1. LOAD & PREPARE DATA ───────────────────────────────────────────────────
print("=" * 62)
print("  KOVA MART — AI FRAUD DETECTION + TRANSACTION GENERATOR")
print("=" * 62)

df = pd.read_csv(DATA_PATH)
print(f"\n[1] Loaded {df.shape[0]} transactions, {df.shape[1]} columns")

if "Subsidy_balance" not in df.columns:
    df["Subsidy_balance"] = df["Initial_Subsidy"] - df["transaction_amount"]

# ─── 2. COMPUTE FRAUD FLAGS & LABEL ───────────────────────────────────────────
def compute_flags(d):
    flags        = pd.DataFrame(index=d.index)
    subsidy_used = d["Initial_Subsidy"] - d["Subsidy_balance"]

    flags["flag_ip_outsider"]       = (d["IP address (outside Indonesia )"] == 1).astype(int)
    flags["flag_repeated_purchase"] = (d["repeated_product_purchase(>10)"] == 1).astype(int) \
        if "repeated_product_purchase(>10)" in d.columns else 0
    flags["flag_high_frequency"]    = (d["Transaction frequency (>3 per hour)"] == 1).astype(int)
    flags["flag_duplicate_account"] = (d["Duplicate_account_detection"] == 1).astype(int)
    flags["flag_same_device"]       = (d["same_device_multiple_accounts"] == 1).astype(int) \
        if "same_device_multiple_accounts" in d.columns else 0
    flags["flag_location_changed"]  = (d["login_location_changed"] == 1).astype(int) \
        if "login_location_changed" in d.columns else 0
    flags["flag_same_product_high"] = (d["same_product_transcation_count_month"] > 5).astype(int) \
        if "same_product_transcation_count_month" in d.columns else 0
    flags["flag_payment_retry"]     = (d["payment_retry_count"] >= 3).astype(int)
    flags["flag_failed_login"]      = (d["failed_login_attempts"] >= 3).astype(int)
    flags["flag_id_not_verified"]   = (d["National_ID_verification"] == 0).astype(int)
    flags["flag_kks_not_valid"]     = (d["KKS_card_validation"] == 0).astype(int)
    flags["flag_card_invalid"]      = (d["valid_card"] == 0).astype(int)
    flags["flag_subsidy_exhausted"] = (
        (subsidy_used / (d["Initial_Subsidy"] + 1) > 0.9) | (subsidy_used > 900000)
    ).astype(int)
    flags["flag_kiosk"]             = (d["app(0) vs kiosk(1)transaction"] == 0).astype(int)
    return flags

flags_df             = compute_flags(df)
df["risk_score_raw"] = sum(flags_df[f] * w for f, w in RISK_WEIGHTS.items())
df["risk_pct"]       = (df["risk_score_raw"] / MAX_INDIVIDUAL_SCORE * 100).round(2)
df["fraud"]          = ((df["risk_pct"] >= 40) | (df["IP address (outside Indonesia )"] == 1)).astype(int)

fraud_rate = df["fraud"].mean() * 100
print(f"[2] Fraud: {df['fraud'].sum()} ({fraud_rate:.1f}%) | Legit: {(df['fraud']==0).sum()}")

# ─── 3. LEARN COLUMN DISTRIBUTIONS ───────────────────────────────────────────
FEATURE_COLS = [c for c in [
    "Initial_Subsidy", "transaction_amount", "hour_of_day", "num_items",
    "repeated_product_purchase(>10)" if "repeated_product_purchase(>10)" in df.columns else "repeated_product_purchase",
    "same_product_transcation_count_month" if "same_product_transcation_count_month" in df.columns else None,
    "prev_transactions", "is_first_transaction",
    "National_ID_verification", "KKS_card_validation", "Duplicate_account_detection",
    "Transaction frequency (>3 per hour)", "valid_card",
    "IP address (outside Indonesia )", "app(0) vs kiosk(1)transaction",
    "failed_login_attempts", "payment_retry_count",
    "same_device_multiple_accounts" if "same_device_multiple_accounts" in df.columns else None,
    "login_location_changed" if "login_location_changed" in df.columns else None,
] if c and c in df.columns]

print(f"[3] Features ({len(FEATURE_COLS)}): {FEATURE_COLS}")

col_stats = {}
for col in FEATURE_COLS:
    data   = df[col].dropna()
    unique = set(data.unique())
    if unique.issubset({0, 1}):
        col_stats[col] = {"type": "binary", "prob_1": data.mean()}
    else:
        col_stats[col] = {
            "type":   "numeric",
            "mean":   data.mean(), "std": data.std(),
            "min":    data.min(),  "max": data.max(),
            "is_int": data.dtype in ["int64", "int32"],
        }

corr_matrix = df[FEATURE_COLS].corr()

# ─── 4. TRAIN AI MODEL ────────────────────────────────────────────────────────
model_path = os.path.join(BASE_DIR, "kova_ai_model.joblib")
scaler_path = os.path.join(BASE_DIR, "kova_ai_scaler.joblib")
features_path = os.path.join(BASE_DIR, "kova_ai_features.joblib")
colstats_path = os.path.join(BASE_DIR, "kova_ai_colstats.joblib")
corrmatrix_path = os.path.join(BASE_DIR, "kova_ai_corrmatrix.joblib")

if (os.path.exists(model_path) and os.path.exists(scaler_path) and 
    os.path.exists(features_path) and os.path.exists(colstats_path) and 
    os.path.exists(corrmatrix_path)):
    print("\n[4] Pre-trained AI model files detected. Loading directly...")
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    FEATURE_COLS = joblib.load(features_path)
    col_stats = joblib.load(colstats_path)
    corr_matrix = joblib.load(corrmatrix_path)
    print(f"[5] AI Model loaded successfully from {BASE_DIR}!")
else:
    print("\n[4] Pre-trained AI model not found. Training model...")
    X = df[FEATURE_COLS].fillna(0)
    y = df["fraud"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler     = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    sm           = SMOTE(random_state=42)
    X_res, y_res = sm.fit_resample(X_train_sc, y_train)

    model = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=42)
    model.fit(X_res, y_res)

    y_pred = model.predict(X_test_sc)
    print("\n    Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legit", "Fraud"]))

    joblib.dump(model,        model_path)
    joblib.dump(scaler,       scaler_path)
    joblib.dump(FEATURE_COLS, features_path)
    joblib.dump(col_stats,    colstats_path)
    joblib.dump(corr_matrix,  corrmatrix_path)
    print(f"\n[5] Model saved to {BASE_DIR}")


# ─── 5. GENERATE ONE SYNTHETIC TRANSACTION ────────────────────────────────────
def generate_one_transaction(seed=None):
    if seed is not None:
        np.random.seed(seed)

    t = {}
    for col, stats in col_stats.items():
        if stats["type"] == "binary":
            t[col] = int(np.random.binomial(1, stats["prob_1"]))
        else:
            val = np.random.normal(stats["mean"], stats["std"])
            val = np.clip(val, stats["min"], stats["max"])
            t[col] = int(round(val)) if stats.get("is_int") else round(val, 2)

    if "transaction_amount" in t and "Initial_Subsidy" in t:
        ratio = np.random.uniform(0.05, 0.95)
        t["transaction_amount"] = round(t["Initial_Subsidy"] * ratio, 2)

    t["Subsidy_balance"]     = round(t["Initial_Subsidy"] - t["transaction_amount"], 2)
    t["subsidy_used_amount"] = round(t["Initial_Subsidy"] - t["Subsidy_balance"], 2)
    t["subsidy_used_ratio"]  = round(t["subsidy_used_amount"] / (t["Initial_Subsidy"] + 1), 4)

    return t

# ─── 6. SCORE ONE TRANSACTION ─────────────────────────────────────────────────
def score_transaction(t):
    subsidy_used = t.get("Initial_Subsidy", 0) - t.get("Subsidy_balance", 0)

    # Step 1: Build flag map
    flag_map = {
        "flag_ip_outsider":       int(t.get("IP address (outside Indonesia )", 0) == 1),
        "flag_repeated_purchase": int(t.get("repeated_product_purchase(>10)", 0) == 1),
        "flag_high_frequency":    int(t.get("Transaction frequency (>3 per hour)", 0) == 1),
        "flag_duplicate_account": int(t.get("Duplicate_account_detection", 0) == 1),
        "flag_same_device":       int(t.get("same_device_multiple_accounts", 0) == 1),
        "flag_location_changed":  int(t.get("login_location_changed", 0) == 1),
        "flag_same_product_high": int(t.get("same_product_transcation_count_month", 0) > 5),
        "flag_payment_retry":     int(t.get("payment_retry_count", 0) >= 3),
        "flag_failed_login":      int(t.get("failed_login_attempts", 0) >= 3),
        "flag_id_not_verified":   int(t.get("National_ID_verification", 1) == 0),
        "flag_kks_not_valid":     int(t.get("KKS_card_validation", 1) == 0),
        "flag_card_invalid":      int(t.get("valid_card", 1) == 0),
        "flag_subsidy_exhausted": int(
            (subsidy_used / (t.get("Initial_Subsidy", 1) + 1) > 0.9)
            or (subsidy_used > 900000)
        ),
        "flag_kiosk":             int(t.get("app(0) vs kiosk(1)transaction", 1) == 0),
    }

    n_flags = sum(flag_map.values())

    # Step 2: Check every combination
    triggered_combos = []
    for combo in FRAUD_COMBINATIONS:
        if all(flag_map.get(f, 0) == 1 for f in combo["flags"]):
            triggered_combos.append(combo)

    # Sort by combo_score descending
    triggered_combos.sort(key=lambda c: c["combo_score"], reverse=True)

    # Step 3 & 4: Combination-priority score
    if triggered_combos:
        highest_combo  = triggered_combos[0]
        combo_score    = highest_combo["combo_score"]
        extra_combos   = len(triggered_combos) - 1
        escalation     = extra_combos * MULTI_COMBO_ESCALATION
        rule_based_pct = min(combo_score + escalation, 100)
    else:
        highest_combo  = None
        rule_based_pct = 0

    # Step 5: AI model probability with noise for realism
    row = pd.DataFrame([t])
    for c in FEATURE_COLS:
        if c not in row.columns:
            row[c] = 0
    row_sc      = scaler.transform(row[FEATURE_COLS].fillna(0))
    ai_prob_raw = float(model.predict_proba(row_sc)[0, 1]) * 100
    noise       = np.random.normal(0, 8)
    ai_prob     = round(min(max(ai_prob_raw + noise, 0), 100), 1)

    final_pct = round(max(rule_based_pct, ai_prob), 1)

    # Step 6: Verdict
    if triggered_combos:
        highest = triggered_combos[0]
        if highest["tier"] == "CRITICAL" or final_pct >= 80:
            level   = "🔴 CRITICAL"
            verdict = f"🚨 RULE-FLAGGED — {highest['name']}"
        elif highest["tier"] == "HIGH" or final_pct >= 55:
            level   = "🟠 HIGH"
            verdict = f"🚨 RULE-FLAGGED — {highest['name']}"
        else:
            level   = "🟡 MEDIUM"
            verdict = f"⚠️  POSSIBLE FRAUD — {highest['name']}"
    elif n_flags >= 4:
        level   = "🟠 HIGH"
        verdict = "🚨 RULE-FLAGGED — Multiple suspicious indicators"
    elif n_flags == 3:
        level   = "🟡 MEDIUM"
        verdict = "⚠️  POSSIBLE FRAUD — Multiple indicators present"
    elif n_flags == 2:
        level   = "🟢 LOW"
        verdict = "⚠️  MONITOR — Two indicators present"
    else:
        level   = "🟢 LOW"
        verdict = "✅ TRANSACTION LOOKS LEGIT — Insufficient indicators"

    return {
        "transaction":      t,
        "flags":            flag_map,
        "n_flags":          n_flags,
        "rule_based_pct":   round(rule_based_pct, 1),
        "ai_prob":          ai_prob,
        "final_pct":        final_pct,
        "level":            level,
        "verdict":          verdict,
        "triggered_combos": triggered_combos,
        "highest_combo":    highest_combo,
    }

# ─── 7. DISPLAY ONE TRANSACTION ───────────────────────────────────────────────
def display_result(result):
    t     = result["transaction"]
    flags = result["flags"]

    print("\n" + "=" * 62)
    print("   GENERATED TRANSACTION + FRAUD ANALYSIS")
    print("=" * 62)

    print("\n  📋 Transaction Details:")
    print(f"     Initial Subsidy      : IDR {t.get('Initial_Subsidy', 0):,.0f}")
    print(f"     Transaction Amount   : IDR {t.get('transaction_amount', 0):,.0f}")
    print(f"     Subsidy Balance      : IDR {t.get('Subsidy_balance', 0):,.0f}")
    print(f"     Hour of Day          : {t.get('hour_of_day', '-')}")
    print(f"     Num Items            : {t.get('num_items', '-')}")
    print(f"     Previous Transactions: {t.get('prev_transactions', '-')}")
    print(f"     First Transaction    : {'Yes' if t.get('is_first_transaction') == 1 else 'No'}")
    print(f"     Channel              : {'App' if t.get('app(0) vs kiosk(1)transaction') == 0 else 'Kiosk'}")
    print(f"     Failed Logins        : {t.get('failed_login_attempts', 0)}")
    print(f"     Payment Retries      : {t.get('payment_retry_count', 0)}")

    flag_labels = {
        "flag_ip_outsider":       "🔴 Foreign IP Address              (P1)",
        "flag_repeated_purchase": "🔴 Repeated Product Purchase >10   (P2)",
        "flag_high_frequency":    "🔴 Transaction Frequency >3/hr     (P3)",
        "flag_duplicate_account": "🟠 Duplicate Account Detected      (P4)",
        "flag_same_device":       "🟠 Same Device Multiple Accounts   (P5)",
        "flag_location_changed":  "🟠 Login Location Changed          (P6)",
        "flag_same_product_high": "🟡 Same Product Count >5/month     (P7)",
        "flag_payment_retry":     "🟡 Payment Retries >= 3            (P8)",
        "flag_failed_login":      "🟡 Failed Login Attempts >= 3      (P9)",
        "flag_id_not_verified":   "🟡 National ID Not Verified        (P10)",
        "flag_kks_not_valid":     "🟡 KKS Card Invalid                (P11)",
        "flag_card_invalid":      "🟡 Card Not Valid                  (P12)",
        "flag_subsidy_exhausted": "🟡 Subsidy Used > 900,000          (P13)",
        "flag_kiosk":             "🟡 App Transaction                 (P14)",
    }

    print(f"\n  🚩 Individual Flags Triggered ({result['n_flags']}):")
    triggered_flags = [f for f, v in flags.items() if v == 1]
    if triggered_flags:
        for f in triggered_flags:
            print(f"     {flag_labels[f]}")
    else:
        print("     ✅ No individual flags triggered")

    print(f"\n  🔗 Fraud Combinations Detected ({len(result['triggered_combos'])}):")
    if result["triggered_combos"]:
        for i, combo in enumerate(result["triggered_combos"]):
            marker = "★ HIGHEST" if i == 0 else "  +"
            extra  = f"  → sets base risk at {combo['combo_score']}%" if i == 0 \
                     else f"  +{MULTI_COMBO_ESCALATION}% escalation"
            print(f"     {marker} [{combo['combo_id']}] {combo['name']}{extra}")
            print(f"            Reason: {combo['reason']}")
    else:
        print("     ✅ No fraud combinations detected — transaction is clean")

    print(f"\n  📊 Risk Analysis:")
    print(f"     Combo-Based Risk Score : {result['rule_based_pct']}%")
    print(f"     AI Model Confidence    : {result['ai_prob']}%")
    print(f"     Final Risk Score       : {result['final_pct']}%")
    print(f"     Risk Level             : {result['level']}")
    print(f"\n  {'=' * 58}")
    print(f"   {result['verdict']}")
    print(f"  {'=' * 58}")

    # Combination Priority Reference Table
    if result["triggered_combos"]:
        triggered_ids = {c["combo_id"] for c in result["triggered_combos"]}
        tiers = [
            ("🔴 CRITICAL", [
                ("C1",  100, "Foreign IP + Failed Logins + Payment Retry"),
                ("C2",   95, "Foreign IP + Location Changed + Same Device"),
                ("C3",   90, "Foreign IP + Duplicate Account"),
                ("C4",   85, "Foreign IP + Subsidy Exhausted"),
                ("C5",   80, "Duplicate Account + Same Device + Location Changed"),
            ]),
            ("🟠 HIGH    ", [
                ("C6",   75, "High Frequency + Repeated Purchase + Same Product"),
                ("C7",   70, "Failed Logins + Payment Retry + High Frequency"),
                ("C8",   65, "Failed Logins + Payment Retry + Invalid Card"),
                ("C9",   60, "Duplicate Account + Failed Logins"),
                ("C10",  55, "Subsidy Exhausted + High Frequency"),
            ]),
            ("🟡 MEDIUM  ", [
                ("C11",  50, "Unverified ID + Invalid KKS + Invalid Card"),
                ("C12",  45, "Unverified ID + Duplicate Account"),
            ]),
        ]

        print(f"\n  📌 Combination Priority Table:")
        print(f"  {'─' * 58}")
        print(f"  {'Tier':<12}  {'ID':<4}  {'Risk':>5}  {'Combination'}")
        print(f"  {'─' * 58}")
        for tier_label, combos in tiers:
            for cid, score, name in combos:
                marker = " ◄ THIS TRANSACTION" if cid in triggered_ids else ""
                print(f"  {tier_label}  {cid:<4}  {score:>4}%  {name}{marker}")
            print(f"  {'─' * 58}")

if __name__ == '__main__':
    # ─── 8. INTERACTIVE LOOP ──────────────────────────────────────────────────────
    print("\n" + "=" * 62)
    print("  MODEL READY — Generating synthetic transactions")
    print("=" * 62)

    seed = 42
    while True:
        print(f"\nGenerating a new synthetic transaction...")
        t      = generate_one_transaction(seed=seed)
        result = score_transaction(t)
        display_result(result)

        seed += 1
        again = input("\n  Generate another transaction? (y/n): ").strip().lower()
        if again not in ("y", "yes"):
            print("\nGoodbye!\n")
            break