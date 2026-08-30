"""
ThreatShield Adaptive Response Engine
--------------------------------------
Generates recommended security actions based on threat severity.
This module does not block requests automatically.
It only recommends appropriate security responses.

Quarantine layer (added in v2)
-------------------------------
If the model's top-class confidence is in the grey zone
(QUARANTINE_THRESHOLD_LOW ≤ confidence < QUARANTINE_THRESHOLD), the request is
flagged as UNKNOWN and sent to the pending_requests quarantine queue.
The existing 5-class pipeline and the FP-mitigation block are untouched.

DEMO MODE (v3)
--------------
QUARANTINE_THRESHOLD has been raised to 0.90 for demo / presentation purposes.
Any attack-class prediction with confidence below 90 % will be quarantined,
making it much easier to trigger the Quarantine Review panel during a live demo.
Lower this back to 0.65 for production deployment.
"""

import sqlite3
import logging
import os
from pathlib import Path

try:
    from src.sanitizer import sanitize_payload
except ModuleNotFoundError:
    from sanitizer import sanitize_payload

logger = logging.getLogger(__name__)

# ── Database path (mirrors the convention used in logger.py / db_firewall.py) ──
_BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = _BASE_DIR / "database" / "logs.db"


def _get_db_conn() -> sqlite3.Connection:
    """Return a raw sqlite3 connection to logs.db."""
    os.makedirs(DB_PATH.parent, exist_ok=True)
    return sqlite3.connect(str(DB_PATH))


# ── Quarantine thresholds (DEMO MODE) ────────────────────────────────────────
# Predictions with confidence in [QUARANTINE_THRESHOLD_LOW, QUARANTINE_THRESHOLD)
# are intercepted and treated as UNKNOWN / Quarantined.
#
# DEMO MODE: threshold raised to 0.99 so ALL low-confidence predictions are quarantined.
# The model rarely hits 99 % on ambiguous payloads, so quarantine fires on virtually
# everything below full certainty during a live demo.
# For production, lower QUARANTINE_THRESHOLD back to 0.65.
QUARANTINE_THRESHOLD: float = 0.99        # upper bound (exclusive) — DEMO MODE
QUARANTINE_THRESHOLD_LOW: float = 0.00   # lower bound (inclusive) — catch everything

# Labels the model considers non-threatening (used only AFTER the quarantine check)
_NORMAL_LABELS = {"normal", "normal traffic", "legal"}


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic Threat Intel Feed Check (Admin Verified Rules)
# ─────────────────────────────────────────────────────────────────────────────

def query_threat_intel_feed(payload: str) -> dict | None:
    """
    Check if the incoming payload matches any admin-verified rules in logs.db.

    1. Allowlist Check:
       If payload is in allowlist, immediately return:
       {"quarantined": False, "action": "ALLOW", "reason": "Admin Verified Safe"}

    2. Blacklist Check:
       If payload is in verified_attack_dataset OR is BLOCKED in pending_requests,
       immediately return:
       {"quarantined": False, "action": "BLOCK", "reason": "Admin Verified Threat"}

    Returns None if no matching admin decision is found.
    """
    if not payload or not str(payload).strip():
        return None

    try:
        raw_p = str(payload).strip()
        safe_p = sanitize_payload(raw_p)

        with _get_db_conn() as conn:
            cursor = conn.cursor()

            # 1. Allowlist Check
            cursor.execute(
                "SELECT id FROM allowlist WHERE payload = ? OR payload = ? LIMIT 1",
                (raw_p, safe_p)
            )
            if cursor.fetchone():
                return {
                    "quarantined": False,
                    "action": "ALLOW",
                    "reason": "Admin Verified Safe",
                    "status": "SAFE",
                    "message": "Admin verified safe payload — request allowed directly by WAF Threat Intel Feed.",
                    "firewall": "No Action (Allowlisted)",
                    "admin_alert": "Not Required",
                    "log_status": "Recorded",
                    "recommended_action": "Allow request based on verified admin allowlist.",
                    "fp_mitigation": False,
                }

            # 2. Blacklist Check (verified_attack_dataset)
            cursor.execute(
                "SELECT id FROM verified_attack_dataset WHERE payload = ? OR payload = ? LIMIT 1",
                (raw_p, safe_p)
            )
            if cursor.fetchone():
                return {
                    "quarantined": False,
                    "action": "BLOCK",
                    "reason": "Admin Verified Threat",
                    "status": "BLOCKED",
                    "message": "Admin verified malicious payload — request blocked directly by WAF Threat Intel Feed.",
                    "firewall": "Enabled (Verified Attack)",
                    "admin_alert": "Threat Feed Triggered",
                    "log_status": "Recorded",
                    "recommended_action": "Block request immediately (matched verified attack dataset).",
                    "fp_mitigation": False,
                }

            # 2b. Blacklist Check (pending_requests status = BLOCKED / EXPIRED_BLOCKED / AUTO_BLOCKED)
            cursor.execute(
                """
                SELECT id FROM pending_requests
                WHERE (payload = ? OR payload = ?)
                  AND status IN ('BLOCKED', 'EXPIRED_BLOCKED', 'AUTO_BLOCKED')
                LIMIT 1
                """,
                (raw_p, safe_p)
            )
            if cursor.fetchone():
                return {
                    "quarantined": False,
                    "action": "BLOCK",
                    "reason": "Admin Verified Threat",
                    "status": "BLOCKED",
                    "message": "Admin verified blocked payload — request blocked directly by WAF Threat Intel Feed.",
                    "firewall": "Enabled (Admin Blocked)",
                    "admin_alert": "Threat Feed Triggered",
                    "log_status": "Recorded",
                    "recommended_action": "Block request immediately (matched admin blocked quarantine rule).",
                    "fp_mitigation": False,
                }

    except Exception as exc:
        logger.error(f"[ThreatIntelFeed] Error querying threat intel: {exc}")

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Quarantine gate
# ─────────────────────────────────────────────────────────────────────────────

def check_quarantine(confidence: float) -> bool:
    """
    Return True if this prediction should be quarantined.

    The check is PURELY confidence-based — the predicted class label does NOT
    matter. Any prediction below QUARANTINE_THRESHOLD will be quarantined.

    Parameters
    ----------
    confidence : Model softmax probability for the predicted class (0–1).
    """
    return confidence < QUARANTINE_THRESHOLD


# ─────────────────────────────────────────────────────────────────────────────
# Core response engine
# ─────────────────────────────────────────────────────────────────────────────

def response_action(severity, confidence=1.0, attack_type="", payload: str = ""):
    """
    Return a response dict for the given threat severity.

    Strict execution order (v4)
    --------------------------
    1. Threat Intel Check FIRST: Query the DB to bypass AI if payload is known allowlist/blacklist item.
    2. Quarantine Check SECOND: Check confidence < QUARANTINE_THRESHOLD. If true, quarantine immediately.
    3. Normal Class Check THIRD: If attack_type == "Normal", only allow if it survived quarantine.
    4. Existing Attack Logic LAST: Critical/High/Medium severity logic.
    """
    severity = severity.upper()

    # ── STEP 1: Threat Intel Check FIRST ─────────────────────────────────────
    intel_response = query_threat_intel_feed(payload)
    if intel_response is not None:
        return intel_response

    # ── STEP 2: Quarantine Check SECOND ──────────────────────────────────────
    if confidence < QUARANTINE_THRESHOLD:
        return {
            "status":   "UNKNOWN",
            "message": (
                f"Confidence ({confidence:.2%}) is below the quarantine threshold "
                f"({QUARANTINE_THRESHOLD:.0%}). Request quarantined pending admin review. "
                "A temporary block has been applied."
            ),
            "firewall":           "Temporary Block / Quarantine",
            "admin_alert":        "Review Required",
            "log_status":         "Quarantined (PENDING)",
            "recommended_action": (
                "Admin review required. Use the Quarantine Review dashboard to "
                "Mark Safe, Block, or flag as a New Attack Pattern."
            ),
            "fp_mitigation": False,
            "quarantined":   True,
            "action":        "BLOCK",
            "reason":        "Low Confidence - Pending Review",
        }

    # ── STEP 3: Normal Class Check THIRD ──────────────────────────────────────
    if attack_type.strip().lower() in _NORMAL_LABELS or attack_type == "Normal":
        # ONLY allow it if it survived the quarantine check above!
        return {
            "status":             "SAFE",
            "message":            "High-confidence normal request. No threat detected.",
            "firewall":           "No Action",
            "admin_alert":        "Not Required",
            "log_status":         "Recorded",
            "recommended_action": "Allow request and continue normal monitoring.",
            "fp_mitigation":      False,
            "quarantined":        False,
            "action":             "ALLOW",
            "reason":             "Safe Request",
        }

    # ── STEP 4: Severity-based attack mapping ─────────────────────────────────
    # High-confidence attack predictions (confidence >= QUARANTINE_THRESHOLD).
    # The existing CRITICAL / HIGH / MEDIUM / LOW logic is untouched.
    responses = {
        "CRITICAL": {
            "status":             "BLOCKED",
            "message":            "Critical threat detected. Immediately block the request and isolate the source.",
            "firewall":           "Enabled",
            "admin_alert":        "Sent",
            "log_status":         "Recorded",
            "recommended_action": "Block request, isolate source IP, investigate immediately.",
            "fp_mitigation":      False,
            "quarantined":        False,
        },
        "HIGH": {
            "status":             "WARNING",
            "message":            "High-risk attack detected. Block the request and investigate.",
            "firewall":           "Enabled",
            "admin_alert":        "Sent",
            "log_status":         "Recorded",
            "recommended_action": "Block request and review server logs.",
            "fp_mitigation":      False,
            "quarantined":        False,
        },
        "MEDIUM": {
            "status":             "MONITOR",
            "message":            "Suspicious activity detected. Continue monitoring.",
            "firewall":           "Monitoring Only",
            "admin_alert":        "Not Required",
            "log_status":         "Recorded",
            "recommended_action": "Monitor future requests from this source.",
            "fp_mitigation":      False,
            "quarantined":        False,
        },
        "LOW": {
            "status":             "SAFE",
            "message":            "No immediate threat detected.",
            "firewall":           "No Action",
            "admin_alert":        "Not Required",
            "log_status":         "Recorded",
            "recommended_action": "Allow request and continue normal monitoring.",
            "fp_mitigation":      False,
            "quarantined":        False,
        },
    }

    base_response = responses.get(
        severity,
        {
            "status":             "UNKNOWN",
            "message":            "Unknown threat level detected.",
            "firewall":           "Monitoring Only",
            "admin_alert":        "Review Required",
            "log_status":         "Recorded",
            "recommended_action": "Review the request manually.",
            "fp_mitigation":      False,
            "quarantined":        False,
        }
    )

    # ── FP-mitigation boundary (0.75) ─────────────────────────────────────────
    # In production (threshold lowered to 0.65) this fires for predictions in
    # [0.65, 0.75). In demo mode (threshold=0.99) this is dead code, but kept
    # for production correctness.
    is_attack = attack_type.strip().lower() not in _NORMAL_LABELS
    if is_attack and confidence < 0.75:
        return {
            "status": "MONITOR",
            "message": (
                "Low-confidence AI prediction detected. Action downgraded to "
                "MONITOR to prevent false positives. Manual review required."
            ),
            "firewall":           "Monitoring Only",
            "admin_alert":        "Review Recommended",
            "log_status":         "Recorded",
            "recommended_action": (
                "Low-confidence AI prediction detected. Action downgraded to "
                "MONITOR to prevent false positives. Manual review required."
            ),
            "fp_mitigation": True,
            "quarantined":   False,
        }

    return base_response

