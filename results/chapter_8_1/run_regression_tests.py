"""
DeepWAF-XAI — Automated Regression Test Suite
============================================
Specifically validates:
1. Raw IP URL Inspection:
   - Confirms phishing-like raw IP URLs are identified as 'Phishing URL'.
   - Confirms benign raw IP URLs are classified as 'Normal' (zero false-positives).
   - Confirms exploit injections on IP hosts are correctly mapped to their exploit categories.
2. Sequence Length Truncation & Post-Boundary Evasion:
   - Confirms malicious content beyond the 200-character boundary is detected.
   - Confirms malicious content within the 200-character boundary is detected.
   - Confirms malicious content at the beginning of long requests is detected.
   - Confirms long benign requests across boundaries remain classified as 'Normal'.
"""

import os
import sys
import json
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

import detector

print("=" * 70)
print("  DeepWAF-XAI: Executing Automated Regression Tests (Section 8.1)")
print("=" * 70)

regression_results = []

def run_test(test_id, category, test_name, payload, expected_attack, min_conf=0.60):
    start = time.perf_counter()
    atk, conf, probs = detector.detect_attack(payload)
    elapsed = (time.perf_counter() - start) * 1000.0

    passed = (atk == expected_attack) and (conf >= min_conf)
    status = "PASS" if passed else "FAIL"

    record = {
        "id": test_id,
        "category": category,
        "test_name": test_name,
        "payload_length": len(payload),
        "payload_preview": (payload[:50] + "...") if len(payload) > 50 else payload,
        "expected_attack": expected_attack,
        "actual_attack": atk,
        "confidence": conf,
        "latency_ms": round(elapsed, 2),
        "status": status
    }
    regression_results.append(record)

    print(f"[{status}] {test_id:6} | {test_name[:35]:35} | Exp: {expected_attack:20} | Got: {atk:20} ({conf:.4f})")
    return passed

# ============================================================================
# PART 1: Raw IP URL Phishing and Benign Regression Tests
# ============================================================================
print("\n--- Part 1: Raw IP Phishing and Benign URL Tests ---")

# 1.1 Phishing raw IP endpoints
run_test("REG-01", "IP Phishing", "Raw IP Banking Endpoint (Case 16)", 
         "http://192.168.1.105/bank/account-verification.php", "Phishing URL", 0.90)

run_test("REG-02", "IP Phishing", "Raw IP Secure Bank Login", 
         "http://192.168.1.200/secure/bank/login", "Phishing URL", 0.90)

run_test("REG-03", "IP Phishing", "Raw IP Account Update Signin", 
         "http://203.0.113.15/signin/account-update", "Phishing URL", 0.90)

run_test("REG-04", "IP Phishing", "Raw IP Credential Check Script", 
         "http://10.0.0.55/auth/credential-check.php", "Phishing URL", 0.90)

run_test("REG-05", "IP Phishing", "Raw IP Wallet Verification", 
         "http://198.51.100.42/wallet/verify-identity", "Phishing URL", 0.90)

run_test("REG-06", "IP Phishing", "Raw IP PayPal Billing Confirm", 
         "http://172.16.0.4/paypal/confirm-billing", "Phishing URL", 0.90)

# 1.2 Benign raw IP endpoints (verify zero false positives)
run_test("REG-07", "IP Benign", "Router Gateway Root URL", 
         "http://192.168.1.1/", "Normal", 0.90)

run_test("REG-08", "IP Benign", "Default Static Landing Page", 
         "http://192.168.1.1/index.html", "Normal", 0.90)

run_test("REG-09", "IP Benign", "Internal Health API Endpoint", 
         "http://10.0.0.1:8080/api/v1/health", "Normal", 0.90)

run_test("REG-10", "IP Benign", "Local Observability Dashboard", 
         "http://127.0.0.1:5000/dashboard", "Normal", 0.90)

run_test("REG-11", "IP Benign", "Device Status Report Endpoint", 
         "http://192.168.1.50/status", "Normal", 0.90)

run_test("REG-12", "IP Benign", "Static Manual PDF Download", 
         "http://192.168.1.100/download/manual.pdf", "Normal", 0.90)

run_test("REG-13", "IP Benign", "Internal Product Catalog Query", 
         "http://10.200.0.1/products?category=electronics", "Normal", 0.90)

# 1.3 Exploit payloads targeting raw IP hosts (verify proper exploit mapping)
run_test("REG-14", "IP Exploit", "SQLi on Raw IP Endpoint", 
         "http://192.168.1.105/search.php?id=1' OR '1'='1", "SQL Injection", 0.90)

run_test("REG-15", "IP Exploit", "XSS on Raw IP Endpoint", 
         "http://192.168.1.105/comment?msg=<script>alert(1)</script>", "Cross Site Scripting", 0.90)

run_test("REG-16", "IP Exploit", "Path Traversal on Raw IP Endpoint", 
         "http://192.168.1.105/view?file=../../../../etc/passwd", "Path Traversal", 0.90)


# ============================================================================
# PART 2: Sequence Boundary and Post-Truncation Evasion Regression Tests
# ============================================================================
print("\n--- Part 2: Sequence Horizon & Boundary Regression Tests ---")

# 2.1 Attack content placed beyond 200-character boundary
run_test("REG-17", "Boundary Suffix", "Post-200 Char XSS Evasion (Case 75)", 
         "A" * 210 + "<script>alert('XSS-Evasion')</script>", "Cross Site Scripting", 0.90)

run_test("REG-18", "Boundary Suffix", "Post-250 Char Onerror XSS Evasion", 
         "A" * 250 + "<img src=x onerror=alert('cookie')>", "Cross Site Scripting", 0.90)

run_test("REG-19", "Boundary Suffix", "Post-300 Char JS Redirection Evasion", 
         "A" * 300 + "<script>document.location='http://attacker.com'</script>", "Cross Site Scripting", 0.90)

# 2.2 Attack content placed within the 200-character boundary
run_test("REG-20", "Boundary Mid", "Mid-Sequence XSS (Offset 50)", 
         "A" * 50 + "<script>alert('XSS-Mid')</script>" + "A" * 50, "Cross Site Scripting", 0.90)

run_test("REG-21", "Boundary Mid", "Mid-Sequence Onerror XSS (Offset 80)", 
         "A" * 80 + "<img src=x onerror=alert(1)>" + "A" * 40, "Cross Site Scripting", 0.90)

# 2.3 Attack content placed at the beginning of long request (>200 chars)
run_test("REG-22", "Boundary Prefix", "Leading XSS with 250 Padding Chars", 
         "<script>alert('XSS-Start')</script>" + "A" * 250, "Cross Site Scripting", 0.90)

run_test("REG-23", "Boundary Prefix", "Leading Onerror with 210 Padding Chars", 
         "<img src=x onerror=alert(1)>" + "A" * 210, "Cross Site Scripting", 0.90)

# 2.4 Extended benign requests across boundaries
run_test("REG-24", "Boundary Benign", "Long Benign Padding (250 chars)", 
         "A" * 250, "Normal", 0.90)

run_test("REG-25", "Boundary Benign", "Long Benign Padding (500 chars)", 
         "A" * 500, "Normal", 0.90)

run_test("REG-26", "Boundary Benign", "Standard Benign E-commerce Query", 
         "search=laptop_keyboard_wireless_bluetooth", "Normal", 0.60)

run_test("REG-27", "Boundary Benign", "Standard Benign REST API Query", 
         "GET /api/v1/products?category=electronics HTTP/1.1", "Normal", 0.60)


# ============================================================================
# Summary & Export
# ============================================================================
total_reg = len(regression_results)
passed_reg = sum(1 for r in regression_results if r["status"] == "PASS")
failed_reg = sum(1 for r in regression_results if r["status"] == "FAIL")

print("\n" + "=" * 70)
print(f"  REGRESSION TESTS EXECUTED : {total_reg}")
print(f"  REGRESSION TESTS PASSED   : {passed_reg}")
print(f"  REGRESSION TESTS FAILED   : {failed_reg}")
print(f"  SUCCESS RATE              : {(passed_reg / total_reg) * 100:.1f}%")
print("=" * 70)

out_file = Path(__file__).resolve().parent / "regression_test_results.json"
with open(out_file, "w", encoding="utf-8") as f:
    json.dump({
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_tests": total_reg,
        "total_pass": passed_reg,
        "total_fail": failed_reg,
        "results": regression_results
    }, f, indent=2)

print(f"\nSaved regression results to: {out_file}")
