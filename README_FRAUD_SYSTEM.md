# Kova Mart Pre-Transaction Fraud Scoring & Blocking System

This document outlines the API specification, authentication requirements, input validation, and checkout policies for the Kova Mart pre-transaction fraud scoring and automatic blocking system.

---

## 1. System Architecture

The Kova Mart fraud prevention system acts as an inline gateway guard. To ensure maximum safety and prevent subsidy leakage, **fraud checks occur on the backend BEFORE payment, subsidy deduction, order completion, or database transaction commit.**

```mermaid
sequenceDiagram
    participant Client as POS Client / Frontend
    participant Server as Flask Backend
    participant ML as AI Scoring Engine (final.py)
    participant DB as SQLite Database

    Client->>Server: POST /api/checkout (Payload + X-API-Key)
    Note over Server: Authenticate API Key
    Note over Server: Enforce Rate Limits & Payload Size (<1MB)
    Note over Server: Validate Input Types & Constraints
    Server->>ML: score_transaction(mapped_features)
    ML-->>Server: Score (final_pct) + Flags & Combo Rules
    alt Risk is HIGH or CRITICAL
        Server->>DB: Log attempted transaction (status='blocked') + Alert
        Server->>Server: Append to generated_transactions_log.csv
        Server-->>Client: HTTP 403 (Safe message: "This purchase could not be completed...")
    else Risk is MEDIUM
        Server->>DB: Log attempted transaction (status='review')
        Server-->>Client: HTTP 403 (Safe message: "This purchase could not be completed...")
    else Risk is LOW
        Server->>DB: Deduct subsidy balance (atomic transaction)
        Server->>DB: Log approved transaction (status='approved')
        Server-->>Client: HTTP 200 (Remaining balance + success message)
    end
```

---

## 2. Authentication & Rate Limiting

### Authentication
All fraud and checkout APIs require authentication. You must provide the API key in the headers of your request in one of the following formats:
- **Header:** `X-API-Key: kova_secret_api_key_2026`
- **Header:** `Authorization: Bearer kova_secret_api_key_2026`

Requests without a valid key will return `HTTP 401 Unauthorized` with a JSON response:
```json
{
  "status": "error",
  "message": "Unauthorized: Invalid or missing API key."
}
```

### Rate Limiting
A memory-based thread-safe sliding window rate limiter restricts access to **60 requests per minute per IP address**.
- Exceeding this rate returns `HTTP 429 Too Many Requests`.
- Response body:
  ```json
  {
    "status": "error",
    "message": "Rate limit exceeded. Try again in X seconds."
  }
  ```

### Payload Size Limit
To prevent Denial of Service (DoS) attacks, request payloads are limited to **1MB**. Payloads exceeding this limit receive `HTTP 413 Payload Too Large`.

---

## 3. API Endpoints

### 1. POST `/api/fraud/score`
Evaluate transaction features and return a detailed fraud risk score, triggered rule flags, and recommended actions.

*   **URL:** `/api/fraud/score`
*   **Method:** `POST`
*   **Headers:**
    ```http
    Content-Type: application/json
    X-API-Key: kova_secret_api_key_2026
    ```
*   **Request Body (JSON):**
    ```json
    {
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
    ```
    *Note: `subsidy_balance` is optional. If omitted, the system automatically calculates it as `initial_subsidy - transaction_amount`.*

*   **Validation Rules:**
    - `customer_id`, `hour_of_day`, `num_items`, `same_product_transaction_count_month`, `previous_transactions`, `failed_login_attempts`, `payment_retry_count`: **Must be non-negative integers.**
    - `initial_subsidy`, `transaction_amount`, `subsidy_balance`: **Must be non-negative floats/numbers.**
    - All other features are indicators and **must be strictly binary (0 or 1).**

*   **Response (HTTP 200 OK):**
    ```json
    {
      "status": "success",
      "request_id": "REQ-20260612-552443",
      "transaction_id": "TX-20260612-100293",
      "rule_based_score": 25.0,
      "ai_probability_score": 0.045,
      "final_risk_score": 29.5,
      "risk_category": "LOW",
      "decision": "APPROVE",
      "allow_transaction": true,
      "triggered_flags": [],
      "triggered_combo_rules": [],
      "highest_combo_rule": null,
      "recommendation": "Allow transaction.",
      "timestamp": "2026-06-12T11:57:06Z"
    }
    ```

---

### 2. POST `/api/checkout`
Submit a subsidy checkout request. Evaluates fraud risk first; only completes if risk is LOW.

*   **URL:** `/api/checkout`
*   **Method:** `POST`
*   **Headers:**
    ```http
    Content-Type: application/json
    X-API-Key: kova_secret_api_key_2026
    ```
*   **Request Body (JSON):**
    *(Same fields and validation rules as `/api/fraud/score`)*

*   **Checkout Risk Decisions:**
    *   **LOW Risk (Score < 40%)**: Allowed. Deducts transaction amount from member balance and commits.
    *   **MEDIUM Risk (Score 40% - 54%)**: Placed in `review` status. Returns safe user block message. No deduction occurs.
    *   **HIGH/CRITICAL Risk (Score >= 55%)**: Placed in `blocked` status. Triggers system alert, logs to `generated_transactions_log.csv`, and returns safe user block message. No deduction occurs.
    *   **Fail-Closed Policy**: If the scoring engine experiences a timeout or error, the request automatically falls back to a **MEDIUM/REVIEW** decision and blocks transaction processing for safety.

*   **Success Response (HTTP 200 OK - Approved):**
    ```json
    {
      "status": "success",
      "message": "Checkout completed successfully.",
      "transaction_id": "TX-APPROVED-5997",
      "remaining_subsidy": 995000.0
    }
    ```

*   **Block Response (HTTP 403 Forbidden - Blocked or Review):**
    ```json
    {
      "status": "blocked",
      "message": "This purchase could not be completed because additional verification is required. Please contact support."
    }
    ```
    *Important: Risk scores and rule flags are intentionally hidden from checkout error responses to prevent adversaries from reverse-engineering the detection logic.*

---

### 3. POST `/api/fraud/feedback`
Allows human auditors to submit confirmation feedback on scored transactions for system retraining.

*   **URL:** `/api/fraud/feedback`
*   **Method:** `POST`
*   **Headers:**
    ```http
    Content-Type: application/json
    X-API-Key: kova_secret_api_key_2026
    ```
*   **Request Body (JSON):**
    ```json
    {
      "transaction_id": "TX-APPROVED-5997",
      "model_decision": "BLOCK",
      "auditor_decision": "CONFIRMED",
      "confirmed_label": "fraud",
      "notes": "Verified duplicate identity cards used at checkout.",
      "reviewed_by": "Auditor Name",
      "reviewed_at": "2026-06-12T12:30:00Z"
    }
    ```
    *Constraints:*
    - `confirmed_label`: Must be strictly one of `'fraud'`, `'legitimate'`, or `'unknown'`.
    - All fields are mandatory.

*   **Response (HTTP 200 OK):**
    ```json
    {
      "status": "success",
      "message": "Auditor feedback logged successfully."
    }
    ```
    *Side effects:* Logs are saved in the `fraud_feedback` SQLite table, and appended to `retraining_feedback_dataset.csv` (used for periodic offline model retraining).

---

## 4. Database Schema

The scoring logs and feedback loop are tracked across two SQLite tables:

### `fraud_scoring_logs`
Stores the detailed payload, scores, indicators, and recommendation for every transaction evaluation request.
*   **Indexed Columns:** `request_id`, `transaction_id`, `customer_id`, `risk_category`

### `fraud_feedback`
Stores feedback submitted by human auditors to evaluate the model's accuracy.
*   **Unique Index:** `transaction_id` (Ensures only one audit result per transaction).

---

## 5. Verification & Testing

To run the automated integration tests verifying authentication, rate limiting, and all blocking policies:
```bash
python scratch/test_fraud_system.py
```
This runs 6 target unit tests:
1.  **test_api_authentication**: Ensures requests fail without keys/tokens.
2.  **test_input_validation**: Verifies bounds, constraints, and types of fields.
3.  **test_fraud_scoring_categories**: Ensures scores fall into correct APPROVE/REVIEW/BLOCK categories.
4.  **test_checkout_policies**: Verifies that LOW risk succeeds (funds deducted) and high/medium fails (funds intact).
5.  **test_feedback_loop**: Tests auditor logging and CSV export for model retraining.
6.  **test_rate_limiting**: Confirms HTTP 429 is raised after the sliding window limit is hit.
