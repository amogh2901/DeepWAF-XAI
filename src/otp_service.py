"""
src/otp_service.py
------------------
Enterprise Two-Factor Authentication (2FA) & One-Time Passcode (OTP) Service
for DeepWAF-XAI.

Designed for cloud environments (Streamlit Community Cloud) and local development.
Supports two clearly separated production authentication channels plus local dev:
  1. RFC 6238 TOTP (Time-based One-Time Password - Google Authenticator / Authy / Microsoft Authenticator)
     - Validates against ADMIN_TOTP_SECRET (does NOT require or check SMTP)
  2. Authenticated SMTP Email Delivery (TLS/SSL)
     - Validates against SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, ADMIN_EMAIL
  3. Local Developer Console Mode (explicitly gated via DEEPWAF_DEV_MODE=true)

Security Properties:
  - 5-minute (300-second) OTP expiration for dynamic codes
  - 30-second rate-limiting cooldown per operator
  - Max 3 invalid attempts before code revocation
  - Single-use consumption (immediate revocation upon success)
  - Constant-time comparison (hmac.compare_digest) against timing side-channels
  - Strict secret hygiene (zero plaintext secrets/codes logged to stdout in production)
"""

import os
import time
import hmac
import hashlib
import struct
import base64
import random
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Dict, Any, Optional, List, Union

logger = logging.getLogger(__name__)

# In-memory store for active nonces / generated dynamic codes:
# { username: { "code": str, "created_at": float, "expires_at": float, "attempts": int, "mode": str } }
_ACTIVE_OTPS: Dict[str, Dict[str, Any]] = {}
_LAST_REQUEST_TIME: Dict[str, float] = {}

OTP_EXPIRY_SECONDS = 300       # 5 minutes validity for dynamic passcodes
OTP_COOLDOWN_SECONDS = 30      # 30 seconds rate-limit between requests
MAX_VERIFICATION_ATTEMPTS = 3  # Revoke dynamic code after 3 wrong tries

# Secret key lookup aliases
TOTP_SECRET_ALIASES = [
    "ADMIN_TOTP_SECRET",
    "TOTP_SECRET",
    "ADMIN_2FA_SECRET",
    "TWO_FACTOR_SECRET",
    "DEEPWAF_ADMIN_TOTP_SECRET",
    "ADMIN_TOTP_KEY",
]

SMTP_SERVER_ALIASES = ["SMTP_SERVER", "SMTP_HOST", "MAIL_SERVER"]
SMTP_PORT_ALIASES = ["SMTP_PORT", "MAIL_PORT"]
SMTP_USER_ALIASES = ["SMTP_USERNAME", "SMTP_EMAIL", "SMTP_USER", "MAIL_USERNAME"]
SMTP_PASS_ALIASES = ["SMTP_PASSWORD", "SMTP_APP_PASSWORD", "SMTP_PASS", "MAIL_PASSWORD"]
ADMIN_EMAIL_ALIASES = ["ADMIN_EMAIL", "ADMIN_NOTIFICATION_EMAIL", "ALERT_EMAIL", "SECURITY_ADMIN_EMAIL"]


def _clean_str(val: Any) -> Optional[str]:
    """Clean string value by stripping surrounding quotes and whitespace."""
    if val is None:
        return None
    s = str(val).strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()
    return s if s else None


def _query_streamlit_secrets(candidate_keys: List[str]) -> Optional[str]:
    """
    Safely query Streamlit Cloud Secrets supporting:
      1. Direct key match (case-sensitive)
      2. Case-insensitive top-level match
      3. Nested sections (e.g. [auth], [secrets], [general], [deepwaf])
    """
    try:
        import streamlit as st
        if not hasattr(st, "secrets"):
            return None
        sec = st.secrets

        # 1. Direct top-level match
        for k in candidate_keys:
            try:
                if k in sec:
                    cleaned = _clean_str(sec[k])
                    if cleaned:
                        return cleaned
            except Exception:
                pass

        # 2. Case-insensitive top-level match
        try:
            sec_keys = list(sec.keys())
            for ck in candidate_keys:
                ck_lower = ck.lower()
                for sk in sec_keys:
                    if str(sk).lower() == ck_lower:
                        cleaned = _clean_str(sec[sk])
                        if cleaned:
                            return cleaned
        except Exception:
            pass

        # 3. Check nested sections in secrets (e.g., [auth] or [secrets])
        try:
            for sk in list(sec.keys()):
                section_val = sec.get(sk)
                if isinstance(section_val, dict) or hasattr(section_val, "get"):
                    for ck in candidate_keys:
                        # Direct key in section
                        try:
                            v = section_val.get(ck)
                            cleaned = _clean_str(v)
                            if cleaned:
                                return cleaned
                        except Exception:
                            pass
                        # Case-insensitive in section
                        try:
                            for sub_k in section_val.keys():
                                if str(sub_k).lower() == ck.lower():
                                    cleaned = _clean_str(section_val.get(sub_k))
                                    if cleaned:
                                        return cleaned
                        except Exception:
                            pass
        except Exception:
            pass

    except Exception:
        pass

    return None


def _query_local_secrets_toml(candidate_keys: List[str]) -> Optional[str]:
    """Fallback reader for local .streamlit/secrets.toml if st.secrets is unavailable."""
    paths = [
        os.path.join(os.getcwd(), ".streamlit", "secrets.toml"),
        os.path.join(os.path.expanduser("~"), ".streamlit", "secrets.toml")
    ]
    for p in paths:
        if not os.path.isfile(p):
            continue
        try:
            import toml
            with open(p, "r", encoding="utf-8") as f:
                data = toml.load(f)
            # Check top level
            for ck in candidate_keys:
                if ck in data:
                    cleaned = _clean_str(data[ck])
                    if cleaned:
                        return cleaned
                for k, v in data.items():
                    if k.lower() == ck.lower():
                        cleaned = _clean_str(v)
                        if cleaned:
                            return cleaned
                    if isinstance(v, dict):
                        if ck in v:
                            cleaned = _clean_str(v[ck])
                            if cleaned:
                                return cleaned
                        for sub_k, sub_v in v.items():
                            if sub_k.lower() == ck.lower():
                                cleaned = _clean_str(sub_v)
                                if cleaned:
                                    return cleaned
        except Exception:
            pass
    return None


def get_config_secret(candidate_keys: Union[str, List[str]], default: Optional[str] = None) -> Optional[str]:
    """
    Safely retrieve secret configuration from:
      1. Streamlit Cloud Secrets (top-level or nested, case-insensitive)
      2. Environment variables (os.environ)
      3. Local .streamlit/secrets.toml
    """
    if isinstance(candidate_keys, str):
        keys = [candidate_keys]
    else:
        keys = list(candidate_keys)

    # 1. Streamlit secrets
    st_val = _query_streamlit_secrets(keys)
    if st_val is not None:
        return st_val

    # 2. Environment variables
    for k in keys:
        env_val = os.getenv(k)
        cleaned = _clean_str(env_val)
        if cleaned:
            return cleaned
        # Case-insensitive env search
        k_lower = k.lower()
        for ek, ev in os.environ.items():
            if ek.lower() == k_lower:
                cleaned = _clean_str(ev)
                if cleaned:
                    return cleaned

    # 3. Local secrets.toml fallback
    file_val = _query_local_secrets_toml(keys)
    if file_val is not None:
        return file_val

    return default


# ── Channel Inspection & Configuration Helpers ────────────────────────────────

def get_totp_secret() -> Optional[str]:
    """Retrieve configured TOTP secret string (Base32), or None if unconfigured."""
    return get_config_secret(TOTP_SECRET_ALIASES)


def is_totp_configured() -> bool:
    """Return True if ADMIN_TOTP_SECRET is configured."""
    return get_totp_secret() is not None


def get_smtp_config() -> Dict[str, Optional[str]]:
    """Retrieve SMTP delivery settings."""
    return {
        "server": get_config_secret(SMTP_SERVER_ALIASES),
        "port": get_config_secret(SMTP_PORT_ALIASES, default="587"),
        "username": get_config_secret(SMTP_USER_ALIASES),
        "password": get_config_secret(SMTP_PASS_ALIASES),
        "admin_email": get_config_secret(ADMIN_EMAIL_ALIASES),
        "use_tls": get_config_secret(["SMTP_USE_TLS"], default="true"),
    }


def is_email_configured() -> bool:
    """Return True if all required SMTP settings and admin recipient email are present."""
    cfg = get_smtp_config()
    return bool(cfg["server"] and cfg["username"] and cfg["password"] and cfg["admin_email"])


def is_dev_mode_enabled() -> bool:
    """Return True if local developer console mode is enabled."""
    val = get_config_secret(["DEEPWAF_DEV_MODE", "ALLOW_DEV_TERMINAL_OTP"], default="false")
    return str(val).lower() in ("true", "1", "yes")


def get_available_methods() -> List[str]:
    """List all currently configured/available 2FA methods ('totp', 'email', 'dev')."""
    methods = []
    if is_totp_configured():
        methods.append("totp")
    if is_email_configured():
        methods.append("email")
    if is_dev_mode_enabled():
        methods.append("dev")
    return methods


def get_default_method() -> str:
    """
    Get recommended active 2FA method:
      - 'totp': if TOTP is configured (preferred production standard)
      - 'email': if SMTP is configured
      - 'dev': if local dev mode
      - 'totp': default fallback view to guide administrator to set TOTP
    """
    if is_totp_configured():
        return "totp"
    if is_email_configured():
        return "email"
    if is_dev_mode_enabled():
        return "dev"
    return "totp"


def get_otp_delivery_mode() -> str:
    """Backward-compatible mode identifier for legacy callers."""
    if is_totp_configured():
        return "totp"
    if is_email_configured():
        return "email"
    if is_dev_mode_enabled():
        return "dev"
    return "none"


def is_delivery_configured() -> bool:
    """Backward-compatible check for legacy callers: True if TOTP, Email, or Dev is ready."""
    return is_totp_configured() or is_email_configured() or is_dev_mode_enabled()


# ── RFC 6238 TOTP Engine ──────────────────────────────────────────────────────

def _normalize_base32(secret: str) -> bytes:
    """
    Robust Base32 key normalizer.
    Strips whitespace/hyphens and converts to uppercase.
    Handles common user typos (0->O, 1->I, 8->B) and falls back to SHA-256
    digest if an arbitrary non-base32 passphrase was provided.
    """
    cleaned = secret.strip().replace(" ", "").replace("-", "").upper()
    padding = (8 - len(cleaned) % 8) % 8
    try:
        return base64.b32decode(cleaned + "=" * padding, casefold=True)
    except Exception:
        # Common substitution fallback
        mapped = cleaned.replace("0", "O").replace("1", "I").replace("8", "B")
        padding_m = (8 - len(mapped) % 8) % 8
        try:
            return base64.b32decode(mapped + "=" * padding_m, casefold=True)
        except Exception:
            return hashlib.sha256(secret.strip().encode("utf-8")).digest()


def generate_totp_code(secret_base32: str, interval: int = 30) -> str:
    """Generate the current 6-digit TOTP code for a base32 secret."""
    key = _normalize_base32(secret_base32)
    counter = int(time.time() // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[19] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def verify_totp_code(secret_base32: str, entered_code: str, interval: int = 30, window: int = 1) -> bool:
    """
    Verify entered code against TOTP algorithm with a ±window (default ±1 = ±30s)
    to handle mobile clock drift.
    """
    clean_code = str(entered_code).strip()
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False

    try:
        key = _normalize_base32(secret_base32)
    except Exception:
        return False

    current_counter = int(time.time() // interval)
    for w in range(-window, window + 1):
        msg = struct.pack(">Q", current_counter + w)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[19] & 0x0F
        expected = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
        if hmac.compare_digest(f"{expected:06d}", clean_code):
            return True
    return False


# ── SMTP Email Delivery ───────────────────────────────────────────────────────

def _send_smtp_email(to_email: str, otp_code: str, username: str, purpose: str) -> Tuple[bool, str]:
    """Send OTP securely via authenticated SMTP with clean HTML/text formatting."""
    cfg = get_smtp_config()
    smtp_server = cfg["server"]
    smtp_port = int(cfg["port"] or "587")
    smtp_user = cfg["username"]
    smtp_pwd = cfg["password"]
    use_tls = str(cfg["use_tls"]).lower() in ("true", "1", "yes")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[DeepWAF-XAI] 🔐 Security Passcode: {otp_code} (Valid for 5 mins)"
    msg["From"] = f"DeepWAF-XAI Security <{smtp_user}>"
    msg["To"] = to_email

    text_body = (
        f"DeepWAF-XAI Security Notification\n"
        f"==================================\n\n"
        f"Action: {purpose}\n"
        f"Operator: {username}\n"
        f"Verification Passcode: {otp_code}\n\n"
        f"This code will expire in 5 minutes. If you did not initiate this request, "
        f"please investigate your SOC console immediately.\n"
    )

    html_body = f"""
    <html>
      <body style="font-family: Arial, sans-serif; background-color: #0A0F1C; color: #FFFFFF; padding: 24px;">
        <div style="max-width: 500px; margin: auto; background: #111827; border: 1px solid #1E293B; border-radius: 12px; padding: 24px;">
          <h2 style="color: #00E5FF; margin-top: 0;">🛡️ DeepWAF-XAI Security Alert</h2>
          <p style="color: #94A3B8; font-size: 14px;">A privileged access authorization request was initiated for operator <b>{username}</b>.</p>
          <div style="background: #1E293B; border: 1px dashed #00E5FF; border-radius: 8px; padding: 16px; text-align: center; margin: 20px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #00E5FF;">{otp_code}</span>
          </div>
          <p style="color: #F87171; font-size: 13px;">⏱️ This single-use code expires in <b>5 minutes</b>.</p>
          <hr style="border: 0; border-top: 1px solid #1E293B; margin: 20px 0;">
          <p style="color: #64748B; font-size: 12px;">Purpose: {purpose} | Security Framework: DeepWAF-XAI</p>
        </div>
      </body>
    </html>
    """

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        if smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10) as server:
                server.login(smtp_user, smtp_pwd)
                server.sendmail(smtp_user, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                if use_tls:
                    server.starttls()
                server.login(smtp_user, smtp_pwd)
                server.sendmail(smtp_user, [to_email], msg.as_string())
        logger.info(f"[2FA] OTP email dispatched successfully to {to_email}")
        return True, f"Verification passcode dispatched to {to_email}."
    except Exception as exc:
        logger.error(f"[2FA] SMTP dispatch failed: {exc}")
        return False, f"Failed to dispatch email via SMTP: {str(exc)}"


def dispatch_email_otp(username: str, purpose: str = "Admin Two-Step Verification") -> Tuple[bool, str]:
    """
    Generate and dispatch a 6-digit dynamic passcode via authenticated SMTP.
    Requires SMTP settings to be configured. Does not affect TOTP mode.
    """
    username = username.strip()
    if not is_email_configured():
        return False, (
            "SMTP email delivery is not configured.\n"
            "Please configure SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD, and ADMIN_EMAIL "
            "in Streamlit Cloud Secrets."
        )

    # Rate limiting check
    now = time.time()
    last_req = _LAST_REQUEST_TIME.get(username, 0.0)
    if now - last_req < OTP_COOLDOWN_SECONDS:
        remaining = int(OTP_COOLDOWN_SECONDS - (now - last_req))
        return False, f"⏳ Rate limit: Please wait {remaining} seconds before requesting a new passcode."

    code = f"{random.SystemRandom().randint(100000, 999999):06d}"
    _ACTIVE_OTPS[username] = {
        "code": code,
        "created_at": now,
        "expires_at": now + OTP_EXPIRY_SECONDS,
        "attempts": 0,
        "mode": "email"
    }
    _LAST_REQUEST_TIME[username] = now

    cfg = get_smtp_config()
    admin_email = cfg["admin_email"]
    ok, msg = _send_smtp_email(admin_email, code, username, purpose)
    if ok:
        return True, f"✉️ A 6-digit passcode has been sent to {admin_email}. Valid for 5 minutes."
    else:
        return False, f"❌ Failed to deliver passcode: {msg}"


# ── Public Service Methods ───────────────────────────────────────────────────

def generate_and_dispatch_admin_otp(
    username: str,
    purpose: str = "Admin Two-Step Verification",
    method: Optional[str] = None
) -> Tuple[bool, str, str]:
    """
    Prepare or deliver 2FA credentials based on requested method:
      - 'totp': No email or external network call required; validates device code.
      - 'email': Generates dynamic code and dispatches via SMTP.
      - 'dev': Outputs code to local terminal (only if dev mode enabled).
      - None: Uses get_default_method().
    Returns: (success: bool, mode: str, user_facing_message: str)
    """
    username = username.strip()
    selected_method = method or get_default_method()

    # 1. Authenticator (TOTP) Mode
    if selected_method == "totp":
        if is_totp_configured():
            return True, "totp", (
                "🔐 Authenticator Active: Enter the current 6-digit code "
                "from your Authenticator app (Google Authenticator / Authy / Microsoft Authenticator)."
            )
        else:
            return False, "totp", (
                "⚠️ ADMIN_TOTP_SECRET is not configured in Streamlit Cloud Secrets.\n"
                "Please configure ADMIN_TOTP_SECRET in Streamlit App Settings → Secrets."
            )

    # 2. Email OTP Mode
    elif selected_method == "email":
        ok, msg = dispatch_email_otp(username, purpose)
        return ok, "email", msg

    # 3. Local Developer Mode
    elif selected_method == "dev":
        if not is_dev_mode_enabled():
            return False, "dev", "Dev mode is disabled. Set DEEPWAF_DEV_MODE=true for local console OTPs."

        now = time.time()
        code = f"{random.SystemRandom().randint(100000, 999999):06d}"
        _ACTIVE_OTPS[username] = {
            "code": code,
            "created_at": now,
            "expires_at": now + OTP_EXPIRY_SECONDS,
            "attempts": 0,
            "mode": "dev"
        }
        _LAST_REQUEST_TIME[username] = now
        try:
            print(f"\n{'='*60}\n[LOCAL DEV MODE] DeepWAF-XAI Admin OTP: {code}\nTarget Operator: {username} | Purpose: {purpose}\n{'='*60}\n", flush=True)
        except Exception:
            pass
        return True, "dev", "🔧 [Local Dev Mode Active] Dynamic passcode output to your local terminal."

    return False, "unknown", "Unknown 2FA mode configuration."


def handle_resend_code(username: str, method: str = "totp") -> Tuple[bool, str]:
    """
    Handle 'Resend Code' button action:
      - For 'totp': Explains that TOTP codes are time-based and auto-refresh on the user's mobile app.
      - For 'email': Dispatches a new dynamic email OTP via SMTP.
      - For 'dev': Generates a new code and outputs to terminal.
    """
    username = username.strip()
    clean_method = method.lower()

    if clean_method == "totp":
        return False, (
            "ℹ️ Authenticator codes are time-based and refresh automatically every 30 seconds "
            "on your mobile device (Google Authenticator / Authy). Use the active 6-digit code "
            "currently displayed in your app."
        )
    elif clean_method == "email":
        return dispatch_email_otp(username, purpose="Admin Login Resend")
    elif clean_method == "dev":
        ok, _, msg = generate_and_dispatch_admin_otp(username, purpose="Admin Login Resend", method="dev")
        return ok, msg
    else:
        return False, "Unsupported 2FA method for resend."


def verify_admin_otp(
    username: str,
    entered_code: str,
    method: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Verify the entered OTP against the specified or detected 2FA method:
      - 'totp': Verifies against ADMIN_TOTP_SECRET (RFC 6238). Does NOT require SMTP credentials.
      - 'email': Verifies against the dispatched dynamic OTP in _ACTIVE_OTPS.
      - 'dev': Verifies against dynamic code in _ACTIVE_OTPS.
      - None: Auto-detects (prioritizes active dispatched OTP if pending, else TOTP).
    Enforces format, expiration, max failed attempts, single-use invalidation, and timing safety.
    """
    username = username.strip()
    clean_code = str(entered_code).strip()

    if not clean_code or len(clean_code) != 6 or not clean_code.isdigit():
        return False, "Please enter a valid 6-digit passcode."

    # Determine verification method
    target_method = method
    if not target_method:
        if username in _ACTIVE_OTPS:
            target_method = _ACTIVE_OTPS[username].get("mode", "email")
        elif is_totp_configured():
            target_method = "totp"
        elif is_email_configured():
            target_method = "email"
        elif is_dev_mode_enabled():
            target_method = "dev"
        else:
            target_method = "totp"

    # ── Authenticator (TOTP) Verification ─────────────────────────────────────
    if target_method == "totp":
        totp_secret = get_totp_secret()
        if not totp_secret:
            return False, "ADMIN_TOTP_SECRET is not configured in Streamlit Cloud Secrets or environment variables."

        if verify_totp_code(totp_secret, clean_code, window=1):
            logger.info(f"[2FA] Successful TOTP authentication for operator '{username}'")
            return True, "Verification successful."
        return False, "Invalid Authenticator passcode. Check your device clock and try again."

    # ── Dynamic Code Verification (Email / Dev) ───────────────────────────────
    record = _ACTIVE_OTPS.get(username)
    if not record:
        if target_method == "email":
            return False, "No active email passcode found. Click 'Resend Code' to dispatch a new passcode."
        return False, "No active passcode found. Please request a new passcode."

    # Check expiration
    if time.time() > record["expires_at"]:
        _ACTIVE_OTPS.pop(username, None)
        return False, "Passcode has expired. Please request a new one."

    # Check attempt threshold
    record["attempts"] += 1
    if record["attempts"] > MAX_VERIFICATION_ATTEMPTS:
        _ACTIVE_OTPS.pop(username, None)
        return False, "Maximum verification attempts exceeded. Passcode revoked for security. Request a new one."

    # Constant-time comparison
    if hmac.compare_digest(record["code"], clean_code):
        _ACTIVE_OTPS.pop(username, None)
        logger.info(f"[2FA] Dynamic passcode verified for operator '{username}' ({target_method})")
        return True, "Verification successful."
    else:
        remaining = MAX_VERIFICATION_ATTEMPTS - record["attempts"]
        return False, f"Incorrect passcode ({remaining} attempt(s) remaining)."


def clear_active_otp(username: str) -> None:
    """Clear any pending active dynamic OTP for the operator."""
    _ACTIVE_OTPS.pop(username.strip(), None)
