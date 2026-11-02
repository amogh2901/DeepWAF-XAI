# Section 8.1 – Test Execution Logs & Verification Audit Trail

**Project:** DeepWAF-XAI — Explainable Deep Learning Framework for Real-Time Web Attack Detection and Intelligent Threat Mitigation  
**Log Scope:** Empirical Runtime Execution Logs: Initial Failures, Diagnostic Traces, Regression Validation, and Verified Final Retests  
**Date:** October 26, 2026  

---

## 1. Initial Test Run Log (Pre-Correction: 73 Passed, 2 Failed)

```text
=================================================================
  DeepWAF-XAI: Executing Comprehensive Section 8.1 Verification
=================================================================
[PASS] Step 1: SuperAdmin Login Authentication -> Status: SUCCESS, Role: admin
[PASS] Step 2: Standard Operator Login Authentication -> Status: SUCCESS, Role: operator
[PASS] Step 3: Unregistered Username Rejection -> Status: FAILED, Message: Invalid credentials.
[PASS] Step 4: Incorrect Password Rejection with Attempt Counter -> Status: FAILED, Attempts recorded: 1
[PASS] Step 5: Brute-Force Account Lockout Enforcement -> Status: LOCKED, Message: Account Locked. Please request an unlock below.
[PASS] Step 6: SuperAdmin Anti-DoS Lockout Exemption -> Status: SUCCESS, SuperAdmin Lockout Prevented: True
[PASS] Step 7: Standard Benign HTTP Request Pass-Through -> Attack: Normal, Confidence: 0.9811
[PASS] Step 8: Legitimate Alphanumeric Search Query -> Attack: Normal, Confidence: 0.9971
[PASS] Step 9: Classic SQL Injection Auth Bypass Detection -> Attack: SQL Injection, Confidence: 0.9984
[PASS] Step 10: Union-Based SQL Injection Data Extraction -> Attack: SQL Injection, Confidence: 0.9984
[PASS] Step 11: Reflected JavaScript Tag Injection Detection -> Attack: Cross Site Scripting, Confidence: 0.9999
[PASS] Step 12: HTML Tag Event-Handler XSS Injection -> Attack: Cross Site Scripting, Confidence: 0.9972
[PASS] Step 13: UNIX Root Password File Traversal Detection -> Attack: Path Traversal, Confidence: 0.9996
[PASS] Step 14: Windows System INI File Traversal Detection -> Attack: Path Traversal, Confidence: 0.9997
[PASS] Step 15: Credential Harvesting Subdomain Deception Detection -> Attack: Phishing URL, Confidence: 1.0000

Model Output
0 0.031466812
1 0.25801796
2 0.015114366
3 0.010573232
4 0.6848276
===== MODEL DEBUG =====
Prediction : Cross Site Scripting
Confidence : 0.6848
LEGAL           : 0.0315
PHISHING        : 0.2580
SHELL           : 0.0151
SQL             : 0.0106
XSS             : 0.6848
=======================
[FAIL] Step 16: Raw IP Banking Endpoint Inspection -> Attack: Cross Site Scripting, Confidence: 0.6848
Expected: Phishing URL (>= 0.90) | Actual: Cross Site Scripting (0.6848)

[PASS] Step 17: Softmax Probability Distribution Normalization -> Values: [0.9984, 0.0016, 0.0, 0.0, 0.0], Sum: 1.0000
[PASS] Step 18: Sub-Threshold Ambiguous Confidence Evaluation -> Class: Normal, Confidence: 0.9797
... [Steps 19 through 74 Passed Cleanly] ...
[PASS] Step 74: Tester Role Capacity Quota Enforcement -> Active testers currently registered in users.db: 2 (Quota <= 3)

Model Output
0 0.99703693
1 4.6213114e-05
2 0.00063350174
3 0.0011217932
4 0.0011616208
===== MODEL DEBUG =====
Prediction : Normal
Confidence : 0.9970
LEGAL           : 0.9970
PHISHING        : 0.0000
SHELL           : 0.0006
SQL             : 0.0011
XSS             : 0.0012
=======================
[FAIL] Step 75: Model Sequence Length Post-Truncation Evasion -> Attack: Normal, Confidence: 0.9970 (Tokens beyond index 200 truncated)

=================================================================
  TOTAL EXECUTED : 75
  TOTAL PASSED   : 73
  TOTAL FAILED   : 2
  PASS RATE      : 97.3%
=================================================================
```

---

## 2. Automated Regression Test Execution Log (27 of 27 Passed)

```text
======================================================================
  DeepWAF-XAI: Executing Automated Regression Tests (Section 8.1)
======================================================================

--- Part 1: Raw IP Phishing and Benign URL Tests ---
[PASS] REG-01 | Raw IP Banking Endpoint (Case 16)   | Exp: Phishing URL         | Got: Phishing URL         (0.9850)
[PASS] REG-02 | Raw IP Secure Bank Login            | Exp: Phishing URL         | Got: Phishing URL         (0.9850)
[PASS] REG-03 | Raw IP Account Update Signin        | Exp: Phishing URL         | Got: Phishing URL         (0.9850)
[PASS] REG-04 | Raw IP Credential Check Script      | Exp: Phishing URL         | Got: Phishing URL         (0.9850)
[PASS] REG-05 | Raw IP Wallet Verification          | Exp: Phishing URL         | Got: Phishing URL         (0.9850)
[PASS] REG-06 | Raw IP PayPal Billing Confirm       | Exp: Phishing URL         | Got: Phishing URL         (0.9850)
[PASS] REG-07 | Router Gateway Root URL             | Exp: Normal               | Got: Normal               (0.9800)
[PASS] REG-08 | Default Static Landing Page         | Exp: Normal               | Got: Normal               (0.9800)
[PASS] REG-09 | Internal Health API Endpoint        | Exp: Normal               | Got: Normal               (0.9800)
[PASS] REG-10 | Local Observability Dashboard       | Exp: Normal               | Got: Normal               (0.9800)
[PASS] REG-11 | Device Status Report Endpoint       | Exp: Normal               | Got: Normal               (0.9800)
[PASS] REG-12 | Static Manual PDF Download          | Exp: Normal               | Got: Normal               (0.9800)
[PASS] REG-13 | Internal Product Catalog Query      | Exp: Normal               | Got: Normal               (0.9800)
[PASS] REG-14 | SQLi on Raw IP Endpoint             | Exp: SQL Injection        | Got: SQL Injection        (0.9850)
[PASS] REG-15 | XSS on Raw IP Endpoint              | Exp: Cross Site Scripting | Got: Cross Site Scripting (0.9850)
[PASS] REG-16 | Path Traversal on Raw IP Endpoint   | Exp: Path Traversal       | Got: Path Traversal       (0.9850)

--- Part 2: Sequence Horizon & Boundary Regression Tests ---
[PASS] REG-17 | Post-200 Char XSS Evasion (Case 75) | Exp: Cross Site Scripting | Got: Cross Site Scripting (0.9992)
[PASS] REG-18 | Post-250 Char Onerror XSS Evasion   | Exp: Cross Site Scripting | Got: Cross Site Scripting (0.9928)
[PASS] REG-19 | Post-300 Char JS Redirection Evasio | Exp: Cross Site Scripting | Got: Cross Site Scripting (0.9990)
[PASS] REG-20 | Mid-Sequence XSS (Offset 50)        | Exp: Cross Site Scripting | Got: Cross Site Scripting (0.9819)
[PASS] REG-21 | Mid-Sequence Onerror XSS (Offset 80 | Exp: Cross Site Scripting | Got: Cross Site Scripting (0.9672)
[PASS] REG-22 | Leading XSS with 250 Padding Chars  | Exp: Cross Site Scripting | Got: Cross Site Scripting (0.9998)
[PASS] REG-23 | Leading Onerror with 210 Padding Ch | Exp: Cross Site Scripting | Got: Cross Site Scripting (0.9979)
[PASS] REG-24 | Long Benign Padding (250 chars)     | Exp: Normal               | Got: Normal               (0.9970)
[PASS] REG-25 | Long Benign Padding (500 chars)     | Exp: Normal               | Got: Normal               (0.9970)
[PASS] REG-26 | Standard Benign E-commerce Query    | Exp: Normal               | Got: Normal               (0.9971)
[PASS] REG-27 | Standard Benign REST API Query      | Exp: Normal               | Got: Normal               (0.9811)

======================================================================
  REGRESSION TESTS EXECUTED : 27
  REGRESSION TESTS PASSED   : 27
  REGRESSION TESTS FAILED   : 0
  SUCCESS RATE              : 100.0%
======================================================================
```

---

## 3. Final Master Retest Log (Post-Correction: 75 of 75 Passed, 100.0%)

```text
=================================================================
  DeepWAF-XAI: Executing Comprehensive Section 8.1 Verification
=================================================================
[PASS] Step 1: SuperAdmin Login Authentication -> Status: SUCCESS, Role: admin
[PASS] Step 2: Standard Operator Login Authentication -> Status: SUCCESS, Role: operator
[PASS] Step 3: Unregistered Username Rejection -> Status: FAILED, Message: Invalid credentials.
[PASS] Step 4: Incorrect Password Rejection with Attempt Counter -> Status: FAILED, Attempts recorded: 1
[PASS] Step 5: Brute-Force Account Lockout Enforcement -> Status: LOCKED, Message: Account Locked. Please request an unlock below.
[PASS] Step 6: SuperAdmin Anti-DoS Lockout Exemption -> Status: SUCCESS, SuperAdmin Lockout Prevented: True
[PASS] Step 7: Standard Benign HTTP Request Pass-Through -> Attack: Normal, Confidence: 0.9811
[PASS] Step 8: Legitimate Alphanumeric Search Query -> Attack: Normal, Confidence: 0.9971
[PASS] Step 9: Classic SQL Injection Auth Bypass Detection -> Attack: SQL Injection, Confidence: 0.9984
[PASS] Step 10: Union-Based SQL Injection Data Extraction -> Attack: SQL Injection, Confidence: 0.9984
[PASS] Step 11: Reflected JavaScript Tag Injection Detection -> Attack: Cross Site Scripting, Confidence: 0.9999
[PASS] Step 12: HTML Tag Event-Handler XSS Injection -> Attack: Cross Site Scripting, Confidence: 0.9972
[PASS] Step 13: UNIX Root Password File Traversal Detection -> Attack: Path Traversal, Confidence: 0.9996
[PASS] Step 14: Windows System INI File Traversal Detection -> Attack: Path Traversal, Confidence: 0.9997
[PASS] Step 15: Credential Harvesting Subdomain Deception Detection -> Attack: Phishing URL, Confidence: 1.0000
[PASS] Step 16: Raw IP Banking Endpoint Inspection -> Attack: Phishing URL, Confidence: 0.9850
[PASS] Step 17: Softmax Probability Distribution Normalization -> Values: [0.9984, 0.0016, 0.0, 0.0, 0.0], Sum: 1.0000
[PASS] Step 18: Sub-Threshold Ambiguous Confidence Evaluation -> Class: Normal, Confidence: 0.9797
[PASS] Step 19: SQL Injection Feature Attribution & Risk Grading -> Risk: HIGH, Reasons: ['SELECT keyword detected', 'Authentication bypass pattern detected']
[PASS] Step 20: Cross-Site Scripting Syntactic Pattern Attribution -> Risk: HIGH, Reasons: ['Executable JavaScript detected', 'Suspicious JavaScript function found']
[PASS] Step 21: Benign Traffic Safe Attribution & LOW Risk Assignment -> Risk: LOW, Reasons: ['No malicious attack patterns detected']
[PASS] Step 22: Character-Level Perturbation Saliency Scoring -> Generated 25 character attribution tokens
[PASS] Step 23: CRITICAL Severity Threat Score Computation -> Score: 1.0
[PASS] Step 24: HIGH Severity Threat Score Computation -> Score: 0.91
[PASS] Step 25: LOW Severity Threat Score Computation -> Score: 0.24
[PASS] Step 26: Out-of-Bounds Threat Score Ceiling Clamping -> Score: 1.0
[PASS] Step 27: Admin Allowlist Rule Bypass Enforcement -> Action: ALLOW, Reason: Admin Verified Safe
[PASS] Step 28: Verified Attack Blacklist Block Enforcement -> Action: BLOCK, Reason: Admin Verified Threat
[PASS] Step 29: Ambiguous Confidence Request Interception & Quarantine Routing -> Status: UNKNOWN, Quarantined: True, Action: BLOCK
[PASS] Step 30: Quarantine Ticket Persistence into SQLite Queue -> Success: True, Message: 'Logged'
[PASS] Step 31: Quarantine Queue Duplicate Request Rejection -> Success: False, Message: 'Already pending'
[PASS] Step 32: Pending Quarantine Queue Retrieval for SOC Dashboard -> Retrieved DataFrame with unreviewed records
[PASS] Step 33: Administrator 'SAFE' Decision & Auto-Allowlisting -> Status update: True, Allowlist update: True
[PASS] Step 34: Administrator 'BLOCKED' Decision & Retraining Dataset Export -> Status update: True, Attack dataset logged: True
[PASS] Step 35: HTML Entity Encoding for XSS Attack Vectors -> Sanitized: '&lt;script&gt;alert(&#x27;Stored XSS&#x27;)&lt;/script&gt;'
[PASS] Step 36: Null Byte Injection Neutralization -> Sanitized: 'adminsecret_payload'
[PASS] Step 37: Oversized Payload Column Truncation -> Output length: 2000 characters
[PASS] Step 38: Destructive SQL 'DROP TABLE' Interception -> Safe: False, Reason: 'Unauthorized SQL pattern detected: DROP'
[PASS] Step 39: Unauthorized Schema Modification 'ALTER TABLE' Interception -> Safe: False, Reason: 'Unauthorized SQL pattern detected: ALTER'
[PASS] Step 40: Data Purge 'TRUNCATE TABLE' Interception -> Safe: False, Reason: 'Unauthorized SQL pattern detected: TRUNCATE'
[PASS] Step 41: Stacked Multi-Statement Injection Interception -> Safe: False, Reason: 'Unauthorized SQL pattern detected: DROP'
[PASS] Step 42: Parameterized Legitimate SELECT Query Pass-Through -> Safe: True, Reason: 'Safe'
[PASS] Step 43: Database Firewall Block Event Audit Logging -> Logged Query: 'DROP TABLE audit_trail;', Reason: 'Unauthorized SQL pattern detected: DROP'
[PASS] Step 44: Sliding-Window Initial Request Pass-Through -> is_limited: False, count: 1
[PASS] Step 45: Successive Requests Within Maximum Limit Allowance -> is_limited: False, count: 5
[PASS] Step 46: Rate Limit Breach & HTTP 429 Interception -> is_limited: True, count: 6
[PASS] Step 47: Rate Limit Violation Persistence to Database -> Logged IP: 10.200.0.57, Path: /api/search, Count: 6
[PASS] Step 48: Rolling Window Timestamp Eviction -> is_limited: False, count after eviction: 1
[PASS] Step 49: Structured Attack Event Persistence to SQLite -> Persisted: Type=SQL Injection, Conf=0.998, Severity=CRITICAL
[PASS] Step 50: Attack Logs Database Schema Columns Integrity -> Verified columns in schema: all 9 audit fields present
[PASS] Step 51: Benign HTTP Traffic Event Auditing -> Successfully recorded benign event to attack_logs
[PASS] Step 52: SOC Telemetry Database Aggregation Query Execution -> Metrics successfully aggregated across all 3 audit databases
[PASS] Step 53: Threat Severity & Attack Distribution Aggregation -> Computes numerical average threat score and categorical distribution
[PASS] Step 54: Multi-Tier Role Navigation Matrix Enforcement -> Admin: 2 pages, Tester: 2 pages, User: 1 page
[PASS] Step 55: Security Dashboard Hard Access Guard Enforcement -> User Access: False ('Access Denied: Administrator or Tester role required'), Admin Access: True
[PASS] Step 56: Revoked Account Hard Interception -> Blocked Intercepted: True, Message: 'Access Denied: Your account has been blocked by the Security Administrator.'
[PASS] Step 57: Security Auditor / Tester Read-Only Scope Isolation -> Admin IAM: True, Tester IAM: False
[PASS] Step 58: SuperAdmin Two-Step 2FA Terminal OTP Issuance -> Generated OTP: 6-digit numeric code stored in session
[PASS] Step 59: SuperAdmin 2FA Passcode Verification & Rejection -> Valid Submission: True, Invalid Submission: False
[PASS] Step 60: Quarantine Review Elevated Access OTP Gate -> Valid OTP Granted: True, Incorrect OTP Rejected: True
[PASS] Step 61: Dynamic Allowlist Entry Creation & Persistence -> add_to_allowlist result: True
[PASS] Step 62: Allowlist Table Duplicate Rule Prevention -> Rule occurrences in allowlist: 1
[PASS] Step 63: Verified Attack Dataset Rule Persistence -> Record persisted: True, Count: 1
[PASS] Step 64: Threat Pre-Check Status Hierarchy Evaluation -> Allowlist: ALLOWLIST, Blacklist: BLOCKLIST, Unknown: None
[PASS] Step 65: User Session State Termination & Memory Sanitization -> Remaining session keys after logout: 0
[PASS] Step 66: Post-Logout Protected Resource Barrier Enforcement -> Access Allowed: False, Result: 'Render Login View (st.stop() executed)'
[PASS] Step 67: Unauthenticated Resource Access Block -> Protected access: False, Action: 'Render Login View (st.stop() executed)'
[PASS] Step 68: Empty Credential Input Validation -> Empty submission result: Credentials required.
[PASS] Step 69: Reserved SuperAdmin Username Registration Prohibition -> Allowed: False, Message: 'admin is a reserved administrator username and cannot be registered.'
[PASS] Step 70: Insecure Short Password Registration Rejection -> Allowed: False, Message: 'Password must be at least 6 characters.'
[PASS] Step 71: SuperAdmin Account Role Demotion Immunity -> Role updated: False, Message: 'Protected account: Cannot modify role of SuperAdmin \'admin\'.'
[PASS] Step 72: Invalid Account Password Reset Request Handling -> Reset accepted: False, Message: 'User \'ghost_user_12345\' not found.'
[PASS] Step 73: Direct SQL Injection Execution Prevention -> Execution permitted: False, Interception reason: 'Unauthorized SQL pattern detected: DROP'
[PASS] Step 74: Tester Role Capacity Quota Enforcement -> Active testers currently registered in users.db: 2 (Quota <= 3)
[PASS] Step 75: Model Sequence Length Post-Truncation Evasion -> Attack: Cross Site Scripting, Confidence: 0.9992

=================================================================
  TOTAL EXECUTED : 75
  TOTAL PASSED   : 75
  TOTAL FAILED   : 0
  PASS RATE      : 100.0%
=================================================================

Saved test results to: D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_1\section_8_1_test_results.json
```
