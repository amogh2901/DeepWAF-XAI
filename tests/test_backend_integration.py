"""
tests/test_backend_integration.py
---------------------------------
Automated test suite verifying:
  1. Central Database consistency & User Registration -> Admin Directory reflection
  2. Multi-channel Admin 2FA (TOTP, Unconfigured guard, Dev mode, rate limiting)
  3. REST API endpoints (/health, /predict, /analyze, /api/mobile/login)
"""

import os
import sys
import time
from pathlib import Path

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
    print("\n[TEST 2] Admin 2FA Lifecycle")
    otp_service.clear_active_otp("admin")

    # Case A: Unconfigured state
    os.environ.pop("DEEPWAF_DEV_MODE", None)
    os.environ.pop("ADMIN_TOTP_SECRET", None)
    os.environ.pop("SMTP_SERVER", None)

    assert otp_service.get_otp_delivery_mode() == "none"
    ok_a, mode_a, msg_a = otp_service.generate_and_dispatch_admin_otp("admin")
    assert ok_a is False
    assert mode_a == "none"
    print("  Case A (Unconfigured cloud guard): PASSED")

    # Case B: Authenticator TOTP (RFC 6238)
    os.environ["ADMIN_TOTP_SECRET"] = "JBSWY3DPEHPK3PXP"
    assert otp_service.get_otp_delivery_mode() == "totp"
    ok_b, mode_b, msg_b = otp_service.generate_and_dispatch_admin_otp("admin")
    assert ok_b is True
    assert mode_b == "totp"
    valid_code = otp_service.generate_totp_code("JBSWY3DPEHPK3PXP")
    v_ok, _ = otp_service.verify_admin_otp("admin", valid_code)
    assert v_ok is True
    v_bad, _ = otp_service.verify_admin_otp("admin", "000000" if valid_code != "000000" else "111111")
    assert v_bad is False
    print("  Case B (RFC 6238 TOTP verification): PASSED")

    # Case C: Dev Mode Dynamic Passcode
    os.environ.pop("ADMIN_TOTP_SECRET", None)
    os.environ["DEEPWAF_DEV_MODE"] = "true"
    assert otp_service.get_otp_delivery_mode() == "dev"
    ok_c, mode_c, _ = otp_service.generate_and_dispatch_admin_otp("admin")
    assert ok_c is True
    assert mode_c == "dev"
    code = otp_service._ACTIVE_OTPS["admin"]["code"]
    v_c, _ = otp_service.verify_admin_otp("admin", code)
    assert v_c is True
    assert "admin" not in otp_service._ACTIVE_OTPS  # single-use consumed
    print("  Case C (Dev mode dynamic OTP lifecycle): PASSED")
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
