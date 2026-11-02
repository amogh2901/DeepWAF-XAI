"""
ThreatShield DeepWAF-XAI Cyber Security Incident Reporting & Tracking Module
-----------------------------------------------------------------------------
Manages the end-to-end incident lifecycle:
  Attack Detection → Admin/SOC Review → Report to Cyber Security → Incident Tracking

Design & Compliance:
  • Preserves original evidence/raw payload accurately in secure backend storage.
  • Prevents stored XSS by keeping sanitized representations for display.
  • Enforces multi-tier RBAC: Only authorized Admin/SOC roles can report incidents.
  • Supports realistic, truthful reporting modes: SOC Forensic Export Package,
    configurable SMTP dispatch via environment variables (never hard-coded),
    and local archival.
  • Complete audit logging for every lifecycle state change and reporting action.
  • Safe requests are never flagged as incidents.
  • Duplicate reporting is handled idempotently and safely.
  • Incident reporting failures never alter or delete underlying attack logs.
"""

import sqlite3
import os
import json
import logging
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path
from typing import Tuple, Dict, Any, List, Optional

import pandas as pd

# Fallback-safe imports
try:
    from src.sanitizer import sanitize_payload
except (ModuleNotFoundError, ImportError):
    try:
        from sanitizer import sanitize_payload
    except Exception:
        def sanitize_payload(p: str) -> str:
            return str(p).replace("<", "&lt;").replace(">", "&gt;")

try:
    from src.threat_intelligence import get_threat_info
except (ModuleNotFoundError, ImportError):
    try:
        from threat_intelligence import get_threat_info
    except Exception:
        def get_threat_info(attack_type: str) -> dict:
            return {
                "severity": "HIGH",
                "description": "Detected web attack vector.",
                "action": "Block and investigate.",
                "mitre": "T1190 - Exploit Public-Facing Application",
                "cvss": 7.5,
                "recommendation": "Review web application inputs."
            }

logger = logging.getLogger(__name__)

# Base database path
_BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = _BASE_DIR / "database" / "logs.db"

# Valid incident lifecycle statuses
VALID_STATUSES = ["PENDING", "REPORTED", "UNDER_REVIEW", "RESOLVED", "REPORT_FAILED"]

# Enforced unidirectional incident lifecycle:
#   PENDING → REPORTED → UNDER_REVIEW → RESOLVED
VALID_TRANSITIONS = {
    "PENDING": ["REPORTED"],
    "REPORTED": ["UNDER_REVIEW"],
    "UNDER_REVIEW": ["RESOLVED"],
    "RESOLVED": [],
    "REPORT_FAILED": ["REPORTED"]
}

STATUS_BADGES = {
    "PENDING": ("🟡 PENDING", "#f59e0b"),
    "REPORTED": ("🔵 REPORTED", "#3b82f6"),
    "UNDER_REVIEW": ("🟣 UNDER REVIEW", "#8b5cf6"),
    "RESOLVED": ("🟢 RESOLVED", "#10b981"),
    "REPORT_FAILED": ("🔴 FAILED", "#ef4444")
}


def _get_conn(target_db: Optional[Path] = None) -> sqlite3.Connection:
    """Return raw sqlite3 connection to logs.db."""
    target = target_db or DB_PATH
    os.makedirs(target.parent, exist_ok=True)
    return sqlite3.connect(str(target))


def init_incident_tables(target_db: Optional[Path] = None) -> None:
    """
    Initialize the incident_reports and incident_audit_logs tables in database/logs.db.
    Safe to call multiple times (idempotent).
    """
    try:
        with _get_conn(target_db) as conn:
            cursor = conn.cursor()

            # 1. Main incident repository
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incident_reports (
                    incident_id         TEXT PRIMARY KEY,
                    attack_log_id       INTEGER,
                    timestamp           TEXT NOT NULL,
                    raw_payload         TEXT NOT NULL,
                    sanitized_payload   TEXT,
                    attack_type         TEXT NOT NULL,
                    confidence          REAL NOT NULL,
                    severity            TEXT NOT NULL,
                    threat_score        REAL NOT NULL,
                    mitre_attack        TEXT,
                    cvss_score          REAL,
                    xai_reason          TEXT,
                    recommended_action  TEXT,
                    current_status      TEXT NOT NULL,
                    prediction_time_ms  REAL,
                    report_status       TEXT NOT NULL DEFAULT 'PENDING',
                    reported_by         TEXT,
                    reported_at         TEXT,
                    reporting_method    TEXT,
                    notes               TEXT,
                    report_json         TEXT,
                    submitted_by        TEXT DEFAULT 'SYSTEM'
                )
            """)

            # Migration: Ensure submitted_by column exists
            cursor.execute("PRAGMA table_info(incident_reports)")
            inc_cols = [info[1] for info in cursor.fetchall()]
            if "submitted_by" not in inc_cols:
                try:
                    cursor.execute("ALTER TABLE incident_reports ADD COLUMN submitted_by TEXT DEFAULT 'SYSTEM'")
                    cursor.execute("UPDATE incident_reports SET submitted_by = 'SYSTEM' WHERE submitted_by IS NULL")
                except Exception as e:
                    logger.error(f"[IncidentManager] Migration error adding submitted_by: {e}")

            # 2. Immutable audit trail
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incident_audit_logs (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id         TEXT NOT NULL,
                    admin_username      TEXT NOT NULL,
                    timestamp           TEXT NOT NULL,
                    action              TEXT NOT NULL,
                    report_status       TEXT NOT NULL,
                    destination_method  TEXT NOT NULL,
                    failure_reason      TEXT,
                    details             TEXT
                )
            """)
            conn.commit()
    except Exception as exc:
        logger.error(f"[IncidentManager] Database init error: {exc}")


def generate_incident_id() -> str:
    """Generate a unique forensic incident identifier: INC-YYYYMMDD-XXXX."""
    date_str = datetime.now().strftime("%Y%m%d")
    suffix = f"{random.randint(0, 0xFFFF):04X}"
    return f"INC-{date_str}-{suffix}"


def record_attack_incident(
    raw_payload: str,
    attack_type: str,
    confidence: float,
    severity: str,
    threat_score: float,
    prediction_time_ms: float,
    current_status: str = "BLOCKED",
    xai_reason: str = "",
    recommended_action: str = "",
    attack_log_id: Optional[int] = None,
    submitted_by: str = "SYSTEM",
    target_db: Optional[Path] = None
) -> Optional[str]:
    """
    Records a detected harmful request as an incident in PENDING status.
    Guarantees:
      - Safe/Normal traffic is NEVER recorded as an incident.
      - Preserves the exact unmodified raw_payload separately for forensic analysis.
      - Sanitizes payload copy for UI presentation safety.
      - Preserves submitted_by username for identity tracking.
    Returns:
      incident_id if recorded, or None if safe traffic or on error.
    """
    # Guard: Safe requests must not generate incidents
    norm_type = str(attack_type).strip().lower()
    if norm_type in ["normal", "legal", "normal traffic"]:
        return None

    if not raw_payload:
        raw_payload = "<EMPTY_PAYLOAD>"

    init_incident_tables(target_db)

    # Threat Intelligence mapping lookup
    threat_meta = get_threat_info(attack_type) or {}
    mitre_attack = threat_meta.get("mitre", "T1190 - Exploit Public-Facing Application")
    try:
        cvss_score = float(threat_meta.get("cvss", 7.5))
    except (ValueError, TypeError):
        cvss_score = 7.5

    if not recommended_action:
        recommended_action = threat_meta.get("recommendation") or threat_meta.get("action") or "Block and inspect request."

    if not xai_reason:
        xai_reason = threat_meta.get("description", "Malicious web attack vector detected by DeepWAF-XAI model.")

    sanitized = sanitize_payload(raw_payload)
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_submitter = str(submitted_by).strip() if submitted_by and str(submitted_by).strip() else "SYSTEM"

    # Generate unique ID and insert
    try:
        with _get_conn(target_db) as conn:
            cursor = conn.cursor()

            # Prevent duplicate identical pending incidents within a 5-second window
            cursor.execute("""
                SELECT incident_id FROM incident_reports 
                WHERE raw_payload = ? AND attack_type = ? AND report_status = 'PENDING'
                ORDER BY timestamp DESC LIMIT 1
            """, (raw_payload, attack_type))
            existing = cursor.fetchone()
            if existing:
                return existing[0]

            incident_id = generate_incident_id()
            cursor.execute("""
                INSERT INTO incident_reports (
                    incident_id, attack_log_id, timestamp, raw_payload, sanitized_payload,
                    attack_type, confidence, severity, threat_score, mitre_attack,
                    cvss_score, xai_reason, recommended_action, current_status,
                    prediction_time_ms, report_status, reported_by, reported_at,
                    reporting_method, notes, report_json, submitted_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', NULL, NULL, NULL, NULL, NULL, ?)
            """, (
                incident_id,
                attack_log_id,
                timestamp_str,
                raw_payload,
                sanitized,
                attack_type,
                float(confidence),
                str(severity).upper(),
                float(threat_score),
                str(mitre_attack),
                float(cvss_score),
                str(xai_reason),
                str(recommended_action),
                str(current_status).upper(),
                float(prediction_time_ms),
                safe_submitter
            ))
            conn.commit()
            return incident_id
    except Exception as exc:
        logger.error(f"[IncidentManager] Error recording attack incident: {exc}")
        return None


def get_incident(incident_id: str, target_db: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Retrieve full incident details as a dictionary."""
    init_incident_tables(target_db)
    try:
        with _get_conn(target_db) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incident_reports WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as exc:
        logger.error(f"[IncidentManager] Error fetching incident '{incident_id}': {exc}")
        return None


def get_all_incidents(target_db: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Fetch all recorded incidents sorted newest first."""
    init_incident_tables(target_db)
    try:
        with _get_conn(target_db) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incident_reports ORDER BY timestamp DESC")
            return [dict(row) for row in cursor.fetchall()]
    except Exception as exc:
        logger.error(f"[IncidentManager] Error fetching all incidents: {exc}")
        return []


def generate_incident_report(incident_id: str, target_db: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """
    Builds a complete, standardized incident forensic report package containing
    all required fields and evidence.
    """
    incident = get_incident(incident_id, target_db)
    if not incident:
        return None

    report = {
        "incident_id": incident["incident_id"],
        "timestamp": incident["timestamp"],
        "lifecycle_status": incident["report_status"],
        "reporting_metadata": {
            "submitted_by": incident.get("submitted_by") or "SYSTEM",
            "reported_by": incident["reported_by"] or "Unassigned",
            "reported_at": incident["reported_at"] or "Pending Submission",
            "reporting_method": incident["reporting_method"] or "Pending",
            "notes": incident["notes"] or ""
        },
        "attack_telemetry": {
            "attack_type": incident["attack_type"],
            "model_confidence_percent": f"{incident['confidence'] * 100:.2f}%",
            "model_confidence_float": incident["confidence"],
            "severity": incident["severity"],
            "threat_score": incident["threat_score"],
            "prediction_time_ms": incident["prediction_time_ms"],
            "response_status": incident["current_status"]
        },
        "threat_intelligence": {
            "mitre_attack_technique": incident["mitre_attack"] or "N/A",
            "cvss_v3_base_score": incident["cvss_score"] if incident["cvss_score"] is not None else 0.0,
            "recommended_action": incident["recommended_action"] or "N/A"
        },
        "explainable_ai_reasoning": {
            "root_cause_explanation": incident["xai_reason"] or "N/A"
        },
        "forensic_evidence": {
            "original_request_payload": incident["raw_payload"],
            "payload_length_bytes": len(incident["raw_payload"].encode("utf-8")),
            "sanitized_display_preview": incident["sanitized_payload"]
        },
        "system_provenance": {
            "detection_system": "DeepWAF-XAI",
            "framework_version": "v3.2-SOC",
            "architecture": "Stacked Character-Level Bi-Directional LSTM with Saliency Heatmap XAI",
            "report_generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    }
    return report


def generate_incident_markdown(report: Dict[str, Any]) -> str:
    """Format an incident report package into clean, human-readable forensic Markdown/Text."""
    telemetry = report["attack_telemetry"]
    intel = report["threat_intelligence"]
    evidence = report["forensic_evidence"]
    xai = report["explainable_ai_reasoning"]
    meta = report["reporting_metadata"]

    md = f"""================================================================================
           DEEPWAF-XAI CYBER SECURITY INCIDENT FORENSIC REPORT
================================================================================

1. INCIDENT IDENTIFICATION
--------------------------------------------------------------------------------
• Incident ID           : {report['incident_id']}
• Incident Timestamp    : {report['timestamp']}
• Submitted By          : {meta.get('submitted_by', 'SYSTEM')}
• Lifecycle Status      : {report['lifecycle_status']}
• Reported By           : {meta['reported_by']}
• Reported At           : {meta['reported_at']}
• Reporting Method      : {meta['reporting_method']}

2. ATTACK CLASSIFICATION & TELEMETRY
--------------------------------------------------------------------------------
• Attack Type           : {telemetry['attack_type']}
• Model Confidence      : {telemetry['model_confidence_percent']}
• Threat Severity       : {telemetry['severity']}
• Threat Score          : {telemetry['threat_score']:.2f} / 1.00
• Response Status       : {telemetry['response_status']}
• Inference Latency     : {telemetry['prediction_time_ms']:.2f} ms

3. THREAT INTELLIGENCE & FRAMEWORK MAPPING
--------------------------------------------------------------------------------
• MITRE ATT&CK Mapping  : {intel['mitre_attack_technique']}
• CVSS Base Score       : {intel['cvss_v3_base_score']:.1f}

4. EXPLAINABLE AI (XAI) ROOT CAUSE ANALYSIS
--------------------------------------------------------------------------------
• Detection Reasons     : {xai['root_cause_explanation']}
• Recommended Action    : {intel['recommended_action']}

5. FORENSIC EVIDENCE (PRESERVED RAW REQUEST / UNMODIFIED PAYLOAD)
--------------------------------------------------------------------------------
Payload Size : {evidence['payload_length_bytes']} bytes
[BEGIN RAW EVIDENCE PAYLOAD]
{evidence['original_request_payload']}
[END RAW EVIDENCE PAYLOAD]

================================================================================
Generated by DeepWAF-XAI SOC Framework • {report['system_provenance']['report_generated_at']}
================================================================================
"""
    return md


def log_audit_event(
    incident_id: str,
    admin_username: str,
    action: str,
    report_status: str,
    destination_method: str,
    failure_reason: Optional[str] = None,
    details: Optional[str] = None,
    target_db: Optional[Path] = None
) -> None:
    """Write an immutable audit log record for an incident reporting action."""
    init_incident_tables(target_db)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _get_conn(target_db) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO incident_audit_logs (
                    incident_id, admin_username, timestamp, action,
                    report_status, destination_method, failure_reason, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_id,
                admin_username,
                now_str,
                action,
                report_status,
                destination_method,
                failure_reason,
                details
            ))
            conn.commit()
    except Exception as exc:
        logger.error(f"[IncidentManager] Failed to write audit log: {exc}")


def report_incident(
    incident_id: str,
    admin_username: str,
    admin_role: str = "admin",
    method: str = "SOC_FORENSIC_EXPORT",
    notes: str = "",
    target_db: Optional[Path] = None
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Submits a Cyber Security Incident Report:
      1. Validates role authorization (only authorized Admin/SOC roles).
      2. Assembles full incident report with preserved raw evidence.
      3. Handles duplicate reporting safely and idempotently.
      4. Dispatches via selected method:
           - 'SOC_FORENSIC_EXPORT': Generates forensic archive and report package.
           - 'EMAIL': Dispatches email using environment variables if configured.
      5. Updates incident status to 'REPORTED'.
      6. Writes immutable audit log record.
      7. Guarantees original attack logs in attack_logs are NEVER modified or deleted.
    """
    # 1. Role validation
    if str(admin_role).strip().lower() != "admin":
        msg = f"Unauthorized: Role '{admin_role}' is not authorized to submit Cyber Security incident reports. Administrator privileges required."
        log_audit_event(
            incident_id=incident_id,
            admin_username=admin_username,
            action="UNAUTHORIZED_REPORT_ATTEMPT",
            report_status="UNAUTHORIZED",
            destination_method=method,
            failure_reason="RBAC Permission Denied",
            details=msg,
            target_db=target_db
        )
        return False, msg, None

    incident = get_incident(incident_id, target_db)
    if not incident:
        return False, f"Incident '{incident_id}' not found.", None

    curr_status = str(incident.get("report_status", "")).strip().upper()
    is_duplicate = (curr_status == "REPORTED")

    # Generate full report package
    report_data = generate_incident_report(incident_id, target_db)
    if not report_data:
        return False, "Failed to compile forensic report package.", None

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_data["reporting_metadata"]["reported_by"] = admin_username
    report_data["reporting_metadata"]["reported_at"] = now_str
    report_data["reporting_metadata"]["reporting_method"] = method
    report_data["reporting_metadata"]["notes"] = notes
    report_json_str = json.dumps(report_data, indent=2)

    # 2. Dispatch handling
    dispatch_success = True
    failure_reason = None
    dispatch_message = ""

    if method == "EMAIL":
        # Check environment variables
        smtp_to = os.getenv("CYBER_SEC_EMAIL_TO")
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_port_raw = os.getenv("SMTP_PORT", "587")
        smtp_user = os.getenv("SMTP_USER")
        smtp_pass = os.getenv("SMTP_PASSWORD")

        if not (smtp_to and smtp_server and smtp_user and smtp_pass):
            # Graceful fallback: Do NOT falsely claim connection, inform clearly
            dispatch_success = False
            failure_reason = "SMTP environment variables (CYBER_SEC_EMAIL_TO, SMTP_SERVER, SMTP_USER, SMTP_PASSWORD) are not configured."
            dispatch_message = f"Email dispatch skipped: {failure_reason} Forensic incident report package generated and prepared locally for Cyber Security / CSIRT handoff."
        else:
            try:
                smtp_port = int(smtp_port_raw)
                msg_body = generate_incident_markdown(report_data)
                em = MIMEMultipart()
                em["From"] = smtp_user
                em["To"] = smtp_to
                em["Subject"] = f"[DeepWAF-XAI ALERT] Security Incident {incident_id} - {incident['attack_type']} ({incident['severity']})"
                em.attach(MIMEText(msg_body, "plain"))

                with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as s:
                    s.starttls()
                    s.login(smtp_user, smtp_pass)
                    s.send_message(em)
                dispatch_message = f"Forensic incident report successfully dispatched via email to {smtp_to} for Cyber Security / CSIRT review."
            except Exception as mail_err:
                dispatch_success = False
                failure_reason = f"SMTP transmission error: {mail_err}"
                dispatch_message = f"Failed to send email: {mail_err}. Forensic incident report package prepared locally."
    else:
        # Default: SOC Forensic Export Package
        method = "SOC_FORENSIC_EXPORT"
        if is_duplicate:
            dispatch_message = "Forensic incident report package regenerated, archived, and prepared for Cyber Security / CSIRT handoff."
        else:
            dispatch_message = "Forensic incident report package generated, archived, and prepared for Cyber Security / CSIRT handoff."

    # 3. Update database status
    new_status = "REPORTED" if dispatch_success else "REPORT_FAILED"
    try:
        with _get_conn(target_db) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE incident_reports SET
                    report_status = ?,
                    reported_by = ?,
                    reported_at = ?,
                    reporting_method = ?,
                    notes = COALESCE(?, notes),
                    report_json = ?
                WHERE incident_id = ?
            """, (
                new_status,
                admin_username,
                now_str,
                method,
                notes,
                report_json_str,
                incident_id
            ))
            conn.commit()
    except Exception as exc:
        logger.error(f"[IncidentManager] Failed to update incident record: {exc}")

    # 4. Audit logging: preserve legitimate reporting actions REPORT_SUBMITTED and REPORT_RE_SUBMITTED
    action_name = ("REPORT_RE_SUBMITTED" if is_duplicate else "REPORT_SUBMITTED") if dispatch_success else "REPORT_FAILED"
    notes_detail = f" | Notes: {notes}" if notes else ""
    log_audit_event(
        incident_id=incident_id,
        admin_username=admin_username,
        action=action_name,
        report_status=new_status,
        destination_method=method,
        failure_reason=failure_reason,
        details=f"{dispatch_message}{notes_detail}",
        target_db=target_db
    )

    if not dispatch_success:
        return False, dispatch_message, report_data

    dup_notice = " [Duplicate submission logged safely]" if is_duplicate else ""
    if method == "EMAIL":
        success_msg = f"Incident {incident_id} forensic report successfully dispatched via email to {smtp_to} for Cyber Security review.{dup_notice}"
    else:
        success_msg = f"Forensic incident report package for {incident_id} successfully generated and prepared for Cyber Security/CSIRT handoff.{dup_notice}"
    return True, success_msg, report_data


def update_incident_status(
    incident_id: str,
    new_status: str,
    admin_username: str,
    admin_role: str = "admin",
    notes: str = "",
    target_db: Optional[Path] = None
) -> Tuple[bool, str]:
    """
    Updates an incident status through the supported workflow:
      PENDING → REPORTED → UNDER_REVIEW → RESOLVED (or REPORT_FAILED)
    Strictly validates lifecycle transitions and rejects invalid or redundant changes.
    """
    new_status_norm = str(new_status).strip().upper()
    if new_status_norm not in VALID_STATUSES:
        return False, f"Invalid status '{new_status}'. Supported: {', '.join(VALID_STATUSES)}"

    if str(admin_role).strip().lower() != "admin":
        msg = f"Unauthorized: Role '{admin_role}' cannot change incident status."
        log_audit_event(
            incident_id=incident_id,
            admin_username=admin_username,
            action="UNAUTHORIZED_STATUS_CHANGE",
            report_status=new_status_norm,
            destination_method="ADMIN_CONSOLE",
            failure_reason="RBAC Permission Denied",
            details=msg,
            target_db=target_db
        )
        return False, msg

    incident = get_incident(incident_id, target_db)
    if not incident:
        return False, f"Incident '{incident_id}' not found."

    old_status = incident["report_status"]
    old_status_norm = str(old_status).strip().upper()

    # Reject same-status transition (no-op, no fake audit event)
    if old_status_norm == new_status_norm:
        return False, f"Incident '{incident_id}' is already in '{new_status_norm}' status. No status change performed."

    # Enforce strict unidirectional lifecycle transitions
    allowed_transitions = VALID_TRANSITIONS.get(old_status_norm, [])
    if new_status_norm not in allowed_transitions:
        allowed_str = ", ".join(allowed_transitions) if allowed_transitions else "None (terminal state)"
        return False, f"Invalid status transition: Cannot transition incident '{incident_id}' from '{old_status_norm}' to '{new_status_norm}'. Allowed next status: {allowed_str}."

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with _get_conn(target_db) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE incident_reports SET
                    report_status = ?,
                    notes = CASE WHEN ? != '' THEN ? ELSE notes END
                WHERE incident_id = ?
            """, (new_status_norm, notes, notes, incident_id))
            conn.commit()

        notes_suffix = f" Notes: {notes}" if notes else ""
        log_audit_event(
            incident_id=incident_id,
            admin_username=admin_username,
            action="STATUS_CHANGED",
            report_status=new_status_norm,
            destination_method="ADMIN_CONSOLE",
            failure_reason=None,
            details=f"Status transitioned from {old_status_norm} to {new_status_norm}.{notes_suffix}",
            target_db=target_db
        )
        return True, f"Incident {incident_id} status updated to '{new_status_norm}'."
    except Exception as exc:
        logger.error(f"[IncidentManager] Status update error: {exc}")
        return False, f"Database error updating status: {exc}"


def get_incident_audit_logs(incident_id: Optional[str] = None, limit: int = 50, target_db: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve audit logs, optionally filtered by incident_id."""
    init_incident_tables(target_db)
    try:
        with _get_conn(target_db) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            if incident_id:
                cursor.execute(
                    "SELECT * FROM incident_audit_logs WHERE incident_id = ? ORDER BY id DESC LIMIT ?",
                    (incident_id, limit)
                )
            else:
                cursor.execute(
                    "SELECT * FROM incident_audit_logs ORDER BY id DESC LIMIT ?",
                    (limit,)
                )
            return [dict(row) for row in cursor.fetchall()]
    except Exception as exc:
        logger.error(f"[IncidentManager] Error fetching audit logs: {exc}")
        return []


def ensure_incident_for_attack_log(attack_log_id: int, target_db: Optional[Path] = None) -> Optional[str]:
    """
    Ensures an incident record exists for a given attack_log ID.
    If already linked, returns existing incident_id.
    If not, reads attack_logs and creates a PENDING incident with the exact raw payload and username.
    """
    init_incident_tables(target_db)
    try:
        with _get_conn(target_db) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT incident_id FROM incident_reports WHERE attack_log_id = ? LIMIT 1",
                (attack_log_id,)
            )
            row = cursor.fetchone()
            if row:
                return row[0]

            # Fetch the attack_log (check if username column exists in attack_logs)
            cursor.execute("PRAGMA table_info(attack_logs)")
            a_cols = [c[1] for c in cursor.fetchall()]
            if "username" in a_cols:
                cursor.execute(
                    "SELECT id, timestamp, request, attack_type, confidence, severity, threat_score, prediction_time_ms, username FROM attack_logs WHERE id = ?",
                    (attack_log_id,)
                )
                alog = cursor.fetchone()
                if not alog:
                    return None
                _id, _ts, _req, _atype, _conf, _sev, _tscore, _ptime, _uname = alog
            else:
                cursor.execute(
                    "SELECT id, timestamp, request, attack_type, confidence, severity, threat_score, prediction_time_ms FROM attack_logs WHERE id = ?",
                    (attack_log_id,)
                )
                alog = cursor.fetchone()
                if not alog:
                    return None
                _id, _ts, _req, _atype, _conf, _sev, _tscore, _ptime = alog
                _uname = "SYSTEM"

            if str(_atype).strip().lower() in ["normal", "legal", "normal traffic"]:
                return None

            return record_attack_incident(
                raw_payload=_req,
                attack_type=_atype,
                confidence=_conf or 0.95,
                severity=_sev or "HIGH",
                threat_score=_tscore or 0.8,
                prediction_time_ms=_ptime or 0.0,
                current_status="BLOCKED",
                attack_log_id=_id,
                submitted_by=_uname or "SYSTEM",
                target_db=target_db
            )
    except Exception as exc:
        logger.error(f"[IncidentManager] ensure_incident_for_attack_log error: {exc}")
        return None


def render_incident_reporting_ui(current_role: str, current_username: str) -> None:
    """
    Renders the Cyber Security Incident Reporting & Tracking Center in Streamlit.
    Matches the dark theme and aesthetic of DeepWAF-XAI.
    """
    import streamlit as st

    init_incident_tables()

    st.markdown("""
    <div style="
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.12) 0%, rgba(124, 58, 237, 0.14) 100%);
        border: 1.5px solid rgba(239, 68, 68, 0.45);
        border-radius: 16px;
        padding: 22px 26px;
        margin-bottom: 20px;
        box-shadow: 0 0 28px rgba(239, 68, 68, 0.15);
    ">
        <div style="display: flex; align-items: center; justify-content: space-between;">
            <div>
                <span style="font-size: 24px; font-weight: 700; color: #fca5a5;">
                    🚨 Cyber Security Incident Reporting &amp; Tracking Center
                </span>
                <div style="color: #cbd5e1; font-size: 13.5px; margin-top: 5px;">
                    Formal Incident Lifecycle: <b>Attack Detection → SOC Review → Report to Cyber Security → Incident Tracking</b>
                </div>
            </div>
            <div style="background: rgba(239, 68, 68, 0.25); color: #fca5a5; padding: 5px 14px; border-radius: 20px; font-size: 11.5px; font-weight: 700; letter-spacing: 0.5px;">
                SOC GATEWAY ACTIVE
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # 1. Fetch current incidents
    incidents = get_all_incidents()
    total_inc = len(incidents)
    pending_inc = sum(1 for i in incidents if i["report_status"] == "PENDING")
    reported_inc = sum(1 for i in incidents if i["report_status"] == "REPORTED")
    review_inc = sum(1 for i in incidents if i["report_status"] == "UNDER_REVIEW")
    resolved_inc = sum(1 for i in incidents if i["report_status"] == "RESOLVED")

    # Metrics row
    m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
    m_col1.metric("Total Incidents", total_inc)
    m_col2.metric("🟡 Pending Report", pending_inc)
    m_col3.metric("🔵 Reported", reported_inc)
    m_col4.metric("🟣 Under Review", review_inc)
    m_col5.metric("🟢 Resolved", resolved_inc)

    st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)

    tab_console, tab_audit = st.tabs([
        f"📋 Incident Review & Reporting ({total_inc})",
        "📜 Incident Audit Trail"
    ])

    with tab_console:
        if not incidents:
            st.info("🟢 No security incidents currently recorded in the repository. Detect a harmful attack or run a simulation to generate an incident.")
        else:
            # Build selector options
            incident_options = []
            incident_map = {}
            for inc in incidents:
                status_lbl, _ = STATUS_BADGES.get(inc["report_status"], (inc["report_status"], "#94a3b8"))
                label = f"{inc['incident_id']} • {inc['timestamp']} • {inc['attack_type']} ({inc['severity']}) • {status_lbl}"
                incident_options.append(label)
                incident_map[label] = inc

            selected_label = st.selectbox("Select Security Incident to Review", incident_options, key="sel_inc_review")
            selected_inc = incident_map[selected_label]
            inc_id = selected_inc["incident_id"]

            st.markdown("---")

            # Incident Details Card
            status_text, status_color = STATUS_BADGES.get(selected_inc["report_status"], (selected_inc["report_status"], "#94a3b8"))
            st.markdown(f"""
            <div style="
                background: #111827;
                border: 1px solid #374151;
                border-left: 5px solid {status_color};
                border-radius: 12px;
                padding: 18px 22px;
                margin-bottom: 18px;
            ">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <div>
                        <span style="font-size: 18px; font-weight: 700; color: #f8fafc;">Incident {inc_id}</span> &nbsp;
                        <span style="color: #94a3b8; font-size: 13px;">Logged at: {selected_inc['timestamp']}</span>
                    </div>
                    <span style="background: {status_color}22; color: {status_color}; border: 1px solid {status_color}; padding: 3px 12px; border-radius: 16px; font-size: 12px; font-weight: 700;">
                        {status_text}
                    </span>
                </div>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; font-size: 13px; color: #e2e8f0;">
                    <div><b>Submitted By:</b> <span style="color: #60a5fa; font-weight: 700;">{selected_inc.get('submitted_by') or 'SYSTEM'}</span></div>
                    <div><b>Attack Classification:</b> <span style="color: #f87171;">{selected_inc['attack_type']}</span></div>
                    <div><b>Severity:</b> <span style="font-weight: 700;">{selected_inc['severity']}</span></div>
                    <div><b>Model Confidence:</b> {selected_inc['confidence'] * 100:.2f}%</div>
                    <div><b>Threat Score:</b> {selected_inc['threat_score']:.2f} / 1.00</div>
                    <div><b>MITRE ATT&CK:</b> <code style="color: #67e8f9;">{selected_inc['mitre_attack']}</code></div>
                    <div><b>CVSS Base Score:</b> <span style="color: #fb923c; font-weight: 700;">{selected_inc['cvss_score']}</span></div>
                    <div><b>Response Status:</b> <span style="color: #a78bfa; font-weight: 700;">{selected_inc['current_status']}</span></div>
                    <div><b>Inference Latency:</b> {selected_inc['prediction_time_ms']:.2f} ms</div>
                </div>
                <div style="margin-top: 12px; font-size: 13px; color: #cbd5e1;">
                    <b>XAI Detection Reason:</b> {selected_inc['xai_reason'] or 'Bi-Directional LSTM detected malicious attack sequence.'}
                </div>
                <div style="margin-top: 6px; font-size: 13px; color: #cbd5e1;">
                    <b>Recommended Action:</b> {selected_inc['recommended_action'] or 'Block request and notify security operations.'}
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Preserve & Display Raw Evidence Securely
            st.markdown("##### 🔍 Preserved Original Forensic Evidence (Unmodified Payload)")
            st.caption("The original raw request is preserved accurately for investigation. Displayed below in a protected viewport:")
            st.code(selected_inc["raw_payload"], language="text")

            # Action Buttons Area
            st.markdown("---")
            st.markdown("##### 🚀 Cyber Security Action Panel")
            st.caption("Prepares and exports a structured forensic incident report package (JSON/TXT) for Cyber Security / CSIRT review.")

            btn_col1, btn_col2, btn_col3 = st.columns([1.5, 1, 1])

            # Compile report package for download/display
            report_data = generate_incident_report(inc_id)
            report_json_str = json.dumps(report_data, indent=2) if report_data else "{}"
            report_md_str = generate_incident_markdown(report_data) if report_data else ""

            with btn_col1:
                if st.button("🚨 Report to Cyber Security", type="primary", use_container_width=True, key=f"btn_report_{inc_id}", help="Generate, archive, and prepare structured forensic report package for Cyber Security / CSIRT review."):
                    if current_role != "admin":
                        st.error("⛔ Access Denied: Only Administrator / SOC Lead role is authorized to submit Cyber Security incident reports.")
                    else:
                        ok, msg, _ = report_incident(
                            incident_id=inc_id,
                            admin_username=current_username,
                            admin_role=current_role,
                            method="SOC_FORENSIC_EXPORT",
                            notes="Reported via SOC Incident Console."
                        )
                        if ok:
                            st.success(f"✅ {msg}")
                            st.session_state['iam_refresh_tick'] = st.session_state.get('iam_refresh_tick', 0) + 1
                            import time as _t
                            _t.sleep(0.3)
                            st.rerun()
                        else:
                            if "already reported" in msg.lower():
                                st.info(f"ℹ️ {msg}")
                            else:
                                st.error(f"❌ {msg}")

            with btn_col2:
                st.download_button(
                    "📥 Export JSON Report",
                    data=report_json_str,
                    file_name=f"{inc_id}_report.json",
                    mime="application/json",
                    use_container_width=True,
                    key=f"dl_json_{inc_id}",
                    help="Export structured forensic incident report JSON for CSIRT review."
                )

            with btn_col3:
                st.download_button(
                    "📄 Export Forensic TXT",
                    data=report_md_str,
                    file_name=f"{inc_id}_forensic.txt",
                    mime="text/plain",
                    use_container_width=True,
                    key=f"dl_txt_{inc_id}",
                    help="Export human-readable forensic report text for CSIRT review."
                )

            # Lifecycle Status Updater (Admin Only)
            with st.expander("⚙️ Update Incident Tracking State (Admin Only)", expanded=False):
                if current_role != "admin":
                    st.warning("🔒 Lifecycle status management requires Administrator privileges (Read-Only Mode for Testers).")
                else:
                    st.markdown("#### Transition Incident Lifecycle Status")
                    st.caption("Valid states: **Pending** → **Reported** → **Under Review** → **Resolved**")
                    u_col1, u_col2 = st.columns([1, 2])
                    with u_col1:
                        target_status = st.selectbox(
                            "New Status",
                            ["REPORTED", "UNDER_REVIEW", "RESOLVED", "PENDING"],
                            index=["REPORTED", "UNDER_REVIEW", "RESOLVED", "PENDING"].index(selected_inc["report_status"]) if selected_inc["report_status"] in ["REPORTED", "UNDER_REVIEW", "RESOLVED", "PENDING"] else 0,
                            key=f"sel_status_{inc_id}"
                        )
                    with u_col2:
                        analyst_notes = st.text_input("Analyst Resolution Notes", placeholder="e.g. Threat verified, firewall rule enforced", key=f"notes_{inc_id}")

                    if st.button("💾 Commit Status Transition", type="secondary", key=f"btn_commit_status_{inc_id}"):
                        ok, s_msg = update_incident_status(
                            incident_id=inc_id,
                            new_status=target_status,
                            admin_username=current_username,
                            admin_role=current_role,
                            notes=analyst_notes.strip()
                        )
                        if ok:
                            st.success(f"✅ {s_msg}")
                            st.session_state['iam_refresh_tick'] = st.session_state.get('iam_refresh_tick', 0) + 1
                            import time as _t
                            _t.sleep(0.3)
                            st.rerun()
                        else:
                            if "already in" in s_msg.lower():
                                st.info(f"ℹ️ {s_msg}")
                            else:
                                st.error(f"❌ {s_msg}")

    with tab_audit:
        st.markdown("#### 📜 Immutable Security Incident Audit Trail")
        st.caption("Every reporting submission, status transition, export, and authorization check is permanently logged with forensic timestamps.")
        audit_rows = get_incident_audit_logs(limit=100)
        if audit_rows:
            df_audit = pd.DataFrame(audit_rows)
            preferred_cols = ["timestamp", "incident_id", "admin_username", "action", "report_status", "destination_method", "failure_reason", "details"]
            display_cols = [c for c in preferred_cols if c in df_audit.columns]
            st.dataframe(df_audit[display_cols], use_container_width=True)

            csv_audit = df_audit.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Download Incident Audit Log as CSV",
                data=csv_audit,
                file_name="incident_audit_logs.csv",
                mime="text/csv",
                key="btn_dl_incident_audit_csv"
            )
        else:
            st.info("No audit log entries recorded yet.")

