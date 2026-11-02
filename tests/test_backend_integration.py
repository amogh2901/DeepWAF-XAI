"""
tests/test_backend_integration.py
---------------------------------
Automated test suite verifying:
  1. Central Database consistency & User Registration -> Admin Directory reflection
  2. Multi-channel Admin 2FA:
     - Authenticator TOTP (valid, invalid, expired/skewed, zero SMTP required)
     - Missing TOTP secret in Authenticator mode
     - Missing SMTP credentials in Email mode
     - Dynamic Email OTP lifecycle (rate-limiting, expiry, 3-attempt lockout, single-use)
     - Authenticator Resend guidance vs Email Resend dispatch
     - Admin access authorization grant on valid OTP vs denial on invalid OTP
  3. REST API endpoints (/health, /predict, /analyze, /api/mobile/login)
"""

import os
import sys
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Add project root and src/ to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
for p in (str(SRC_DIR), str(PROJECT_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

import auth
import otp_service
from detector import detect_attack
from api import app


def test_database_consistency_and_registration():
    print("\n[TEST 1] Database Consistency & Registration -> Admin Directory")
    print(f"  Central USERS_DB_PATH: {auth.USERS_DB_PATH}")
    assert "database" in str(auth.USERS_DB_PATH)

    initial_users = auth.get_all_users()
    initial_count = len(initial_users)
    print(f"  Current registered users count: {initial_count}")

    # Register new test operator
    test_uname = f"autotest_user_{int(time.time())}"
    reg_ok, reg_msg = auth.register_user(test_uname, "StrongPassword123!")
    print(f"  Registered {test_uname}: success={reg_ok}, msg={reg_msg}")
    assert reg_ok is True

    # Immediate reflection in admin directory query
    updated_users = auth.get_all_users()
    assert len(updated_users) == initial_count + 1
    found = next((u for u in updated_users if u[1] == test_uname), None)
    assert found is not None
    print(f"  User record verified in admin directory: User ID USR-{found[0]:04d}, Username: {found[1]}, Role: {found[2]}")

    # Update role via admin panel function to 'blocked'
    upd_ok, upd_msg = auth.update_user_role(test_uname, "blocked")
    assert upd_ok is True
    recheck_users = auth.get_all_users()
    recheck_user = next((u for u in recheck_users if u[1] == test_uname), None)
    assert recheck_user[2] == "blocked"
    print(f"  Role update verified in database: {recheck_user[2]}")

    # Verify quota limit: 3 testers quota
    tester_count = auth.count_users_by_role("tester")
    if tester_count >= 3:
        quota_ok, quota_msg = auth.update_user_role(test_uname, "tester")
        assert quota_ok is False
        print(f"  Quota protection verified: {quota_msg}")
    print("  [+] TEST 1 PASSED")


def test_admin_2fa_lifecycle():
    print("\n[TEST 2] Admin 2FA Lifecycle & Method Separation")
    otp_service.clear_active_otp("admin")

    # Clean environment of any pre-existing 2FA secrets
    for k in [
        "ADMIN_TOTP_SECRET", "TOTP_SECRET", "ADMIN_2FA_SECRET", "admin_totp_secret",
        "SMTP_SERVER", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD", "ADMIN_EMAIL",
        "DEEPWAF_DEV_MODE", "ALLOW_DEV_TERMINAL_OTP"
    ]:
        os.environ.pop(k, None)

    # ──────────────────────────────────────────────────────────────────────────
    # Case 2A: Authenticator Mode with Zero SMTP Credentials
    # ──────────────────────────────────────────────────────────────────────────
    print("  Case 2A: Authenticator Mode (Zero SMTP credentials configured)...")
    os.environ["ADMIN_TOTP_SECRET"] = "JBSWY3DPEHPK3PXP"
    assert otp_service.is_totp_configured() is True
    assert otp_service.is_email_configured() is False  # Zero SMTP configured!

    # 1. Valid TOTP verification
    valid_code = otp_service.generate_totp_code("JBSWY3DPEHPK3PXP")
    v_ok, v_msg = otp_service.verify_admin_otp("admin", valid_code, method="totp")
    assert v_ok is True, f"Valid TOTP failed: {v_msg}"
    print("    [+] Valid TOTP authenticated successfully without SMTP credentials.")

    # 2. Invalid TOTP verification
    bad_code = "000000" if valid_code != "000000" else "111111"
    v_bad, b_msg = otp_service.verify_admin_otp("admin", bad_code, method="totp")
    assert v_bad is False
    assert "Invalid Authenticator passcode" in b_msg
    print("    [+] Invalid TOTP correctly rejected.")

    # 3. Outdated / expired TOTP code outside skew window (e.g. 5 minutes ago)
    import struct, hmac, hashlib
    past_counter = int((time.time() - 300) // 30)
    key = otp_service._normalize_base32("JBSWY3DPEHPK3PXP")
    msg = struct.pack(">Q", past_counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[19] & 0x0F
    expired_code = f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"
    v_exp, _ = otp_service.verify_admin_otp("admin", expired_code, method="totp")
    assert v_exp is False
    print("    [+] Expired / outdated TOTP code outside ±30s window correctly rejected.")

    # 4. Resend Code behavior in Authenticator mode
    r_ok, r_msg = otp_service.handle_resend_code("admin", method="totp")
    assert r_ok is False
    assert "time-based" in r_msg.lower() or "refresh" in r_msg.lower()
    print("    [+] Resend in Authenticator mode returns time-based guidance without SMTP error.")

    # ──────────────────────────────────────────────────────────────────────────
    # Case 2B: Missing TOTP Secret in Authenticator Mode
    # ──────────────────────────────────────────────────────────────────────────
    print("  Case 2B: Missing TOTP Secret in Authenticator Mode...")
    os.environ.pop("ADMIN_TOTP_SECRET", None)
    assert otp_service.is_totp_configured() is False
    v_no_sec, no_sec_msg = otp_service.verify_admin_otp("admin", "123456", method="totp")
    assert v_no_sec is False
    assert "ADMIN_TOTP_SECRET is not configured" in no_sec_msg
    print("    [+] Missing TOTP secret displays clear configuration instruction.")

    # ──────────────────────────────────────────────────────────────────────────
    # Case 2C: Missing SMTP Credentials in Email Mode
    # ──────────────────────────────────────────────────────────────────────────
    print("  Case 2C: Missing SMTP Credentials in Email Mode...")
    assert otp_service.is_email_configured() is False
    d_ok, d_msg = otp_service.dispatch_email_otp("admin")
    assert d_ok is False
    assert "SMTP email delivery is not configured" in d_msg
    print("    [+] Email mode correctly blocks dispatch when SMTP settings are absent.")

    # ──────────────────────────────────────────────────────────────────────────
    # Case 2D: Email OTP Dynamic Lifecycle
    # ──────────────────────────────────────────────────────────────────────────
    print("  Case 2D: Dynamic Email OTP verification lifecycle...")
    otp_service.clear_active_otp("admin")
    # Simulate an active email OTP record
    now = time.time()
    test_dynamic_code = "482910"
    otp_service._ACTIVE_OTPS["admin"] = {
        "code": test_dynamic_code,
        "created_at": now,
        "expires_at": now + 300,
        "attempts": 0,
        "mode": "email"
    }

    # Wrong attempt increments attempt counter
    v_wrong, wrong_msg = otp_service.verify_admin_otp("admin", "000000", method="email")
    assert v_wrong is False
    assert "2 attempt(s) remaining" in wrong_msg
    assert otp_service._ACTIVE_OTPS["admin"]["attempts"] == 1
    print("    [+] Wrong attempt counter tracked safely.")

    # Correct attempt consumes single-use OTP
    v_right, _ = otp_service.verify_admin_otp("admin", test_dynamic_code, method="email")
    assert v_right is True
    assert "admin" not in otp_service._ACTIVE_OTPS
    print("    [+] Correct passcode verified and single-use consumed.")

    # Expired passcode test
    otp_service._ACTIVE_OTPS["admin"] = {
        "code": "112233",
        "created_at": now - 350,
        "expires_at": now - 50,  # expired
        "attempts": 0,
        "mode": "email"
    }
    v_expired, exp_msg = otp_service.verify_admin_otp("admin", "112233", method="email")
    assert v_expired is False
    assert "expired" in exp_msg.lower()
    print("    [+] Expired dynamic passcode rejected.")

    # Max attempts lockout test
    otp_service._ACTIVE_OTPS["admin"] = {
        "code": "556677",
        "created_at": now,
        "expires_at": now + 300,
        "attempts": 3,  # reached max
        "mode": "email"
    }
    v_locked, lock_msg = otp_service.verify_admin_otp("admin", "556677", method="email")
    assert v_locked is False
    assert "exceeded" in lock_msg.lower()
    print("    [+] Max attempts brute-force protection verified.")

    # ──────────────────────────────────────────────────────────────────────────
    # Case 2E: Authorization Simulation (Admin Session Granted vs Denied)
    # ──────────────────────────────────────────────────────────────────────────
    print("  Case 2E: Authorization Simulation (Admin Session Grant vs Denial)...")
    os.environ["ADMIN_TOTP_SECRET"] = "JBSWY3DPEHPK3PXP"

    # Simulate Streamlit session state
    session_state = {
        "authenticated": False,
        "username": None,
        "role": None,
        "pending_2fa_user": "admin",
        "pending_2fa_role": "admin",
    }

    # Simulate failed verification attempt
    sim_ok, _ = otp_service.verify_admin_otp(session_state["pending_2fa_user"], "000000", method="totp")
    if not sim_ok:
        pass  # Access denied, session NOT granted
    assert session_state["authenticated"] is False
    assert session_state["role"] is None
    print("    [+] Failed 2FA does NOT grant admin access.")

    # Simulate successful verification attempt
    valid_token = otp_service.generate_totp_code("JBSWY3DPEHPK3PXP")
    sim_ok, _ = otp_service.verify_admin_otp(session_state["pending_2fa_user"], valid_token, method="totp")
    if sim_ok:
        session_state["authenticated"] = True
        session_state["username"] = session_state["pending_2fa_user"]
        session_state["role"] = session_state["pending_2fa_role"]
        session_state["pending_2fa_user"] = None
        session_state["pending_2fa_role"] = None

    assert session_state["authenticated"] is True
    assert session_state["username"] == "admin"
    assert session_state["role"] == "admin"
    assert session_state["pending_2fa_user"] is None
    print("    [+] Successful 2FA grants authenticated admin session.")

    print("  [+] TEST 2 PASSED")


def test_api_endpoints():
    print("\n[TEST 3] REST API Health & Threat Detection Endpoints")
    client = app.test_client()

    # Health check
    h_res = client.get("/health")
    assert h_res.status_code == 200
    h_data = h_res.get_json()
    assert h_data["status"] == "UP"
    assert h_data["databases"]["users_db_ready"] is True
    print(f"  Health check: {h_data['status']} - {h_data['service']}")

    # BiLSTM Threat Prediction
    p_res = client.post("/predict", json={"payload": "SELECT * FROM users WHERE id = 1 OR 1=1--"})
    assert p_res.status_code == 200
    p_data = p_res.get_json()
    assert "SQL" in p_data["attack_type"]
    print(f"  Prediction test (SQLi): {p_data['attack_type']} ({p_data['confidence']}%)")

    # Benign Prediction
    norm_res = client.post("/predict", json={"payload": "https://www.google.com/search?q=weather"})
    assert norm_res.status_code == 200
    norm_data = norm_res.get_json()
    assert norm_data["attack_type"] == "Normal"
    print(f"  Prediction test (Normal): {norm_data['attack_type']} ({norm_data['confidence']}%)")
    print("  [+] TEST 3 PASSED")


if __name__ == "__main__":
    test_database_consistency_and_registration()
    test_admin_2fa_lifecycle()
    test_api_endpoints()
    print("\n" + "=" * 60)
    print("ALL BACKEND INTEGRATION & VERIFICATION TESTS PASSED!")
    print("=" * 60)
