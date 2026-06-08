import os
import json
import numpy as np
import pandas as pd
import joblib

# Import scoring logic
import final

# Clean up numpy types
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

def generate_js():
    df = final.df
    records = []
    
    print("Scoring all transactions in the dataset...")
    for idx, row in df.iterrows():
        rec = row.to_dict()
        # Ensure customer ID is set
        customer_id = int(rec.get("Name/customer_id", idx + 1))
        
        # Format columns for score_transaction
        t = {}
        t["Initial_Subsidy"]                        = float(rec.get("Initial_Subsidy", 0))
        t["transaction_amount"]                     = float(rec.get("transaction_amount", 0))
        t["Subsidy_balance"]                        = round(t["Initial_Subsidy"] - t["transaction_amount"], 2)
        t["hour_of_day"]                            = int(rec.get("hour_of_day", 12))
        t["num_items"]                              = int(rec.get("num_items", 1))
        t["repeated_product_purchase(>10)"]         = int(rec.get("repeated_product_purchase(>10)", 0))
        t["same_product_transcation_count_month"]   = int(rec.get("same_product_transcation_count_month", 0))
        t["prev_transactions"]                      = int(rec.get("prev_transactions", 0))
        t["is_first_transaction"]                   = int(rec.get("is_first_transaction", 0))
        t["National_ID_verification"]               = int(rec.get("National_ID_verification", 1))
        t["KKS_card_validation"]                    = int(rec.get("KKS_card_validation", 1))
        t["Duplicate_account_detection"]            = int(rec.get("Duplicate_account_detection", 0))
        t["Transaction frequency (>3 per hour)"]    = int(rec.get("Transaction frequency (>3 per hour)", 0))
        t["valid_card"]                             = int(rec.get("valid_card", 1))
        t["IP address (outside Indonesia )"]        = int(rec.get("IP address (outside Indonesia )", 0))
        t["app(0) vs kiosk(1)transaction"]          = int(rec.get("app(0) vs kiosk(1)transaction", 0))
        t["failed_login_attempts"]                  = int(rec.get("failed_login_attempts", 0))
        t["payment_retry_count"]                    = int(rec.get("payment_retry_count", 0))
        t["same_device_multiple_accounts"]          = int(rec.get("same_device_multiple_accounts", 0))
        t["login_location_changed"]                 = int(rec.get("login_location_changed", 0))
        
        # Score using backend logic
        score_res = final.score_transaction(t)
        
        # Merge results into output record
        rec["customer_id"] = customer_id
        rec["rule_based_pct"] = float(score_res["rule_based_pct"])
        rec["ai_prob"] = float(score_res["ai_prob"])
        rec["final_pct"] = float(score_res["final_pct"])
        rec["level"] = str(score_res["level"])
        rec["verdict"] = str(score_res["verdict"])
        
        records.append(clean_numpy(rec))
        
    # Write to static/dataset.js
    js_content = f"// Kova Mart Offline Threat Intelligence Dataset\nconst KOVA_DATASET = {json.dumps(records, indent=2)};\n"
    
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "dataset.js")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(js_content)
    
    print(f"Successfully wrote {len(records)} records to {output_path}!")

if __name__ == "__main__":
    generate_js()
