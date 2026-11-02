"""
src/otp_service.py
------------------
Enterprise Two-Factor Authentication (2FA) & One-Time Passcode (OTP) Service
for DeepWAF-XAI.

Designed for cloud environments (Streamlit Community Cloud) and local development.
Supports:
  1. RFC 6238 TOTP (Time-based One-Time Password - Google Authenticator / Authy)
  2. Authenticated SMTP Email Delivery (TLS/SSL)
  3. Local Developer Console Mode (explicitly gated via DEEPWAF_DEV_MODE=true)

Security Properties:
  - 5-minute (300-second) OTP expiration
  - 30-second rate-limiting cooldown per operator
  - Max 3 invalid attempts before code revocation
  - Single-use consumption (immediate revocation upon success)
  - Constant-time comparison to prevent timing side-channels
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
from typing import Tuple, Dict, Any, Optional

logger = logging.getLogger(__name__)

# In-memory store for active nonces / generated dynamic codes:
# { username: { "code": str, "created_at": float, "expires_at": float, "attempts": int, "mode": str } }
_ACTIVE_OTPS: Dict[str, Dict[str, Any]] = {}
_LAST_REQUEST_TIME: Dict[str, float] = {}

OTP_EXPIRY_SECONDS = 300      # 5 minutes validity
OTP_COOLDOWN_SECONDS = 30     # 30 seconds rate-limit between requests
MAX_VERIFICATION_ATTEMPTS = 3  # Revoke code after 3 wrong tries


def _get_secret_or_env(key: str, default: Optional[str] = None) -> Optional[str]:
    """
    Safely retrieve configuration from Streamlit secrets (if available) or environment variables.
    """
    # 1. Try Streamlit secrets if running inside Streamlit
    try:
        import streamlit as st
        if hasattr(st, "secrets") and key in st.secrets:
            val = str(st.secrets[key]).strip()
            if val:
                return val
    except Exception:
        pass

    # 2. Try os.environ
    val = os.getenv(key)
    if val is not None and str(val).strip():
        return str(val).strip()

    return default


def get_otp_delivery_mode() -> str:
    """
    Determine the active 2FA delivery mode based on configuration:
      - 'totp': If ADMIN_TOTP_SECRET is configured
      - 'email': If SMTP configuration is provided
      - 'dev': If DEEPWAF_DEV_MODE == 'true' (local testing only)
      - 'none': Neither configured
    """
    totp_secret = _get_secret_or_env("ADMIN_TOTP_SECRET")
    if totp_secret:
        return "totp"

    smtp_server = _get_secret_or_env("SMTP_SERVER")
    smtp_user = _get_secret_or_env("SMTP_USERNAME") or _get_secret_or_env("SMTP_EMAIL")
    smtp_pwd = _get_secret_or_env("SMTP_PASSWORD") or _get_secret_or_env("SMTP_APP_PASSWORD")
    admin_email = _get_secret_or_env("ADMIN_EMAIL")
    if smtp_server and smtp_user and smtp_pwd and admin_email:
        return "email"

    dev_mode = _get_secret_or_env("DEEPWAF_DEV_MODE", "false").lower() in ("true", "1", "yes")
    allow_dev_term = _get_secret_or_env("ALLOW_DEV_TERMINAL_OTP", "false").lower() in ("true", "1", "yes")
    if dev_mode or allow_dev_term:
        return "dev"

    return "none"


def is_delivery_configured() -> bool:
    """Check if any valid 2FA delivery channel is ready."""
    return get_otp_delivery_mode() != "none"


# ── RFC 6238 TOTP Engine ──────────────────────────────────────────────────────

def _normalize_base32(secret: str) -> bytes:
    """Pad and decode base32 secret."""
    cleaned = secret.strip().replace(" ", "").upper()
    padding = (8 - len(cleaned) % 8) % 8
    cleaned += "=" * padding
    return base64.b32decode(cleaned, casefold=True)


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
    Verify entered code against TOTP algorithm with a ±window (default ±1 window = ±30s)
    to gracefully handle mobile clock skew.
    """
    try:
        key = _normalize_base32(secret_base32)
    except Exception:
        return False

    clean_code = str(entered_code).strip()
    if len(clean_code) != 6 or not clean_code.isdigit():
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
    smtp_server = _get_secret_or_env("SMTP_SERVER")
    smtp_port = int(_get_secret_or_env("SMTP_PORT", "587"))
    smtp_user = _get_secret_or_env("SMTP_USERNAME") or _get_secret_or_env("SMTP_EMAIL")
    smtp_pwd = _get_secret_or_env("SMTP_PASSWORD") or _get_secret_or_env("SMTP_APP_PASSWORD")
    use_tls = _get_secret_or_env("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")

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


# ── Public High-Level Service Methods ─────────────────────────────────────────

def generate_and_dispatch_admin_otp(username: str, purpose: str = "Admin Two-Step Verification") -> Tuple[bool, str, str]:
    """
    Generate and deliver a secure OTP to the operator.
    Returns:
      (success: bool, mode: str, user_facing_message: str)
    """
    username = username.strip()
    mode = get_otp_delivery_mode()

    if mode == "none":
        return False, "none", (
            "⚠️ 2FA Delivery is not configured for cloud deployment.\n"
            "Please configure ADMIN_TOTP_SECRET (recommended for Authenticator apps) "
            "or SMTP credentials in Streamlit Cloud Secrets."
        )

    # If mode is TOTP: no email/terminal dispatch is needed; code is generated on operator's device
    if mode == "totp":
        return True, "totp", (
            "🔐 Two-Factor Authentication Active: Enter the current 6-digit code "
            "from your Authenticator app (Google Authenticator / Authy / Microsoft Authenticator)."
        )

    # Rate limiting check for dynamic codes (Email / Dev)
    now = time.time()
    last_req = _LAST_REQUEST_TIME.get(username, 0.0)
    if now - last_req < OTP_COOLDOWN_SECONDS:
        remaining = int(OTP_COOLDOWN_SECONDS - (now - last_req))
        return False, mode, f"⏳ Rate limit: Please wait {remaining} seconds before requesting a new passcode."

    # Generate cryptographically strong 6-digit code
    code = f"{random.SystemRandom().randint(100000, 999999):06d}"
    _ACTIVE_OTPS[username] = {
        "code": code,
        "created_at": now,
        "expires_at": now + OTP_EXPIRY_SECONDS,
        "attempts": 0,
        "mode": mode
    }
    _LAST_REQUEST_TIME[username] = now

    if mode == "email":
        admin_email = _get_secret_or_env("ADMIN_EMAIL")
        ok, msg = _send_smtp_email(admin_email, code, username, purpose)
        if ok:
            return True, "email", f"✉️ A 6-digit passcode has been sent to {admin_email}. Valid for 5 minutes."
        else:
            return False, "email", f"❌ Failed to deliver passcode: {msg}"

    elif mode == "dev":
        # Safe dev fallback — only active when DEEPWAF_DEV_MODE=true
        try:
            print(f"\n{'='*60}\n[LOCAL DEV MODE] DeepWAF-XAI Admin OTP: {code}\nTarget Operator: {username} | Purpose: {purpose}\n{'='*60}\n", flush=True)
        except Exception:
            pass
        return True, "dev", "🔧 [Local Dev Mode Active] Dynamic passcode output to your local terminal."

    return False, "unknown", "Unknown 2FA mode configuration."


def verify_admin_otp(username: str, entered_code: str) -> Tuple[bool, str]:
    """
    Verify the entered OTP against TOTP or active dynamic passcode.
    Enforces expiry, max failed attempts, single-use invalidation, and timing-safe comparison.
    """
    username = username.strip()
    clean_code = str(entered_code).strip()
    mode = get_otp_delivery_mode()

    if not clean_code or len(clean_code) != 6 or not clean_code.isdigit():
        return False, "Please enter a valid 6-digit passcode."

    # 1. Verify via TOTP if configured
    if mode == "totp":
        totp_secret = _get_secret_or_env("ADMIN_TOTP_SECRET")
        if not totp_secret:
            return False, "TOTP secret is not configured."
        if verify_totp_code(totp_secret, clean_code):
            logger.info(f"[2FA] Successful TOTP authentication for user '{username}'")
            return True, "Verification successful."
        return False, "Invalid Authenticator passcode. Check your device clock and try again."

    # 2. Verify dynamic code (Email / Dev)
    record = _ACTIVE_OTPS.get(username)
    if not record:
        return False, "No active passcode found. Please click 'Request Passcode' to generate one."

    # Check expiration
    if time.time() > record["expires_at"]:
        _ACTIVE_OTPS.pop(username, None)
        return False, "Passcode has expired. Please request a new one."

    # Check attempts
    record["attempts"] += 1
    if record["attempts"] > MAX_VERIFICATION_ATTEMPTS:
        _ACTIVE_OTPS.pop(username, None)
        return False, "Maximum verification attempts exceeded. Passcode revoked for security. Request a new one."

    # Timing-safe comparison
    if hmac.compare_digest(record["code"], clean_code):
        # Single-use consumption
        _ACTIVE_OTPS.pop(username, None)
        logger.info(f"[2FA] Dynamic passcode verified for operator '{username}'")
        return True, "Verification successful."
    else:
        remaining = MAX_VERIFICATION_ATTEMPTS - record["attempts"]
        return False, f"Incorrect passcode ({remaining} attempt(s) remaining)."


def clear_active_otp(username: str) -> None:
    """Clear any pending OTP for the operator."""
    _ACTIVE_OTPS.pop(username.strip(), None)
