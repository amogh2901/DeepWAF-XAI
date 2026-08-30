"""
src/quarantine.py
-----------------
Unknown / Suspicious Request Handling Layer  (Quarantine System)
================================================================

This module manages all database operations AND the Streamlit UI for the
quarantine pipeline:

  • init_pending_table()         — Creates the three quarantine tables on startup.
  • log_pending_request(...)     — Inserts a low-confidence prediction as PENDING.
  • load_pending_requests()      — Returns a DataFrame for the admin dashboard.
  • update_pending_status(...)   — Admin action: SAFE / BLOCKED / PENDING.
  • log_verified_attack(...)     — Stores payload in verified_attack_dataset for retraining.
  • add_to_allowlist(...)        — Records a confirmed-safe payload.
  • render_quarantine_ui()       — Renders the full Streamlit admin panel (embed anywhere).

Tables created (all inside database/logs.db):

  pending_requests
    id, timestamp, payload, predicted_class, confidence, status

  verified_attack_dataset
    id, timestamp, payload, predicted_class

  allowlist
    id, timestamp, payload, source

Design contract
---------------
• This module is the ONLY place that touches the three quarantine tables.
• It never modifies attack_logs, db_firewall_logs, or any other existing table.
• render_quarantine_ui() is purely a rendering function — it has no auth gate of
  its own. Callers in app.py are responsible for gating access behind the
  Level-2 elevated passkey before calling this function.
"""

import sqlite3
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

try:
    from src.sanitizer import sanitize_payload
except ModuleNotFoundError:
    from sanitizer import sanitize_payload

logger = logging.getLogger(__name__)

# ── Database path (mirrors the convention used in logger.py / db_firewall.py) ──
_BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = _BASE_DIR / "database" / "logs.db"

# ── Confidence threshold: predictions below this are quarantined ───────────────
QUARANTINE_THRESHOLD: float = 0.65


# ─────────────────────────────────────────────────────────────────────────────
# Internal helper
# ─────────────────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    """Return a raw sqlite3 connection to logs.db."""
    os.makedirs(DB_PATH.parent, exist_ok=True)
    return sqlite3.connect(str(DB_PATH))


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def init_pending_table() -> None:
    """
    Create the three quarantine tables if they do not already exist.
    Safe to call multiple times (idempotent).
    Also performs a one-time purge of any duplicate allowlist rows and pending tickets.
    """
    try:
        with _get_conn() as conn:
            cursor = conn.cursor()

            # 1. Quarantine queue — incoming low-confidence predictions
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pending_requests (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT    NOT NULL,
                    payload         TEXT    NOT NULL,
                    predicted_class TEXT    NOT NULL,
                    confidence      REAL    NOT NULL,
                    status          TEXT    NOT NULL DEFAULT 'PENDING'
                )
            """)

            # 2. Verified attack dataset — for future model retraining
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS verified_attack_dataset (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT    NOT NULL,
                    payload         TEXT    NOT NULL,
                    predicted_class TEXT    NOT NULL
                )
            """)

            # 3. Allowlist — confirmed-safe payloads
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS allowlist (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT    NOT NULL,
                    payload   TEXT    NOT NULL,
                    source    TEXT    NOT NULL DEFAULT 'admin'
                )
            """)

            # ── Database Cleanup (One-Time Execution): Purge duplicate allowlist rows ──
            cursor.execute("""
                DELETE FROM allowlist 
                WHERE id NOT IN (SELECT MIN(id) FROM allowlist GROUP BY payload)
            """)

            # ── Purge duplicate pending quarantine tickets for the same payload ──
            cursor.execute("""
                DELETE FROM pending_requests 
                WHERE status = 'PENDING' AND id NOT IN (
                    SELECT MIN(id) FROM pending_requests WHERE status = 'PENDING' GROUP BY payload
                )
            """)

            # Also check if an explicit quarantine table exists and deduplicate it
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='quarantine'")
            if cursor.fetchone():
                cursor.execute("""
                    DELETE FROM quarantine 
                    WHERE status = 'PENDING' AND id NOT IN (
                        SELECT MIN(id) FROM quarantine WHERE status = 'PENDING' GROUP BY payload
                    )
                """)

            conn.commit()
            logger.info("[Quarantine] All quarantine tables initialised and deduplicated.")
    except Exception as exc:
        logger.error(f"[Quarantine] init_pending_table error: {exc}")


def check_payload_status(payload: str) -> str | None:
    """
    Strict database pre-check pipeline:
    1. Check Allowlist: Query the allowlist table for the exact payload.
    2. Check Blocklist: Query verified_attack_dataset or pending_requests (BLOCKED/EXPIRED_BLOCKED/AUTO_BLOCKED) or blocklist.
    3. Check Quarantine Queue: Query pending_requests where status is 'PENDING'.

    Returns:
        'ALLOWLIST' | 'BLOCKLIST' | 'PENDING' | None
    """
    if not payload or not str(payload).strip():
        return None

    raw_p = str(payload).strip()
    safe_p = sanitize_payload(raw_p)

    try:
        with _get_conn() as conn:
            cursor = conn.cursor()

            # 1. Check Allowlist
            cursor.execute(
                "SELECT id FROM allowlist WHERE payload = ? OR payload = ? LIMIT 1",
                (raw_p, safe_p),
            )
            if cursor.fetchone():
                return "ALLOWLIST"

            # 2. Check Blocklist
            cursor.execute(
                "SELECT id FROM verified_attack_dataset WHERE payload = ? OR payload = ? LIMIT 1",
                (raw_p, safe_p),
            )
            if cursor.fetchone():
                return "BLOCKLIST"

            cursor.execute(
                """
                SELECT id FROM pending_requests
                WHERE (payload = ? OR payload = ?)
                  AND status IN ('BLOCKED', 'EXPIRED_BLOCKED', 'AUTO_BLOCKED')
                LIMIT 1
                """,
                (raw_p, safe_p),
            )
            if cursor.fetchone():
                return "BLOCKLIST"

            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='blocklist'"
            )
            if cursor.fetchone():
                cursor.execute(
                    "SELECT id FROM blocklist WHERE payload = ? OR payload = ? LIMIT 1",
                    (raw_p, safe_p),
                )
                if cursor.fetchone():
                    return "BLOCKLIST"

            # 3. Check Quarantine Queue (PENDING)
            cursor.execute(
                """
                SELECT id FROM pending_requests
                WHERE (payload = ? OR payload = ?) AND status = 'PENDING'
                LIMIT 1
                """,
                (raw_p, safe_p),
            )
            if cursor.fetchone():
                return "PENDING"

    except Exception as exc:
        logger.error(f"[Quarantine] check_payload_status error: {exc}")

    return None


def log_pending_request(
    payload: str,
    predicted_class: str,
    confidence: float,
) -> tuple[bool, str]:
    """
    Insert a quarantined request into pending_requests with status 'PENDING'.

    Strict Python SELECT check before insertion.
    Returns:
        (True, "Logged") on insertion,
        (False, "Already pending") if already in queue,
        (False, "Allowlisted") if already in allowlist.
    """
    try:
        raw_payload = str(payload).strip()
        safe_payload = sanitize_payload(raw_payload)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with _get_conn() as conn:
            cursor = conn.cursor()

            # Check allowlist first
            cursor.execute(
                "SELECT id FROM allowlist WHERE payload = ? OR payload = ? LIMIT 1",
                (raw_payload, safe_payload),
            )
            if cursor.fetchone():
                logger.info("[Quarantine] Payload is in allowlist — skipping pending insert.")
                return False, "Allowlisted"

            # ── Strict Deduplication for Quarantine Queue ──
            cursor.execute(
                """
                SELECT id FROM pending_requests
                WHERE (payload = ? OR payload = ?) AND status = 'PENDING'
                LIMIT 1
                """,
                (raw_payload, safe_payload),
            )
            if cursor.fetchone():
                logger.info("[Quarantine] Payload is already pending — skipping insert.")
                return False, "Already pending"

            # Check if alternate quarantine table exists
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='quarantine'")
            if cursor.fetchone():
                cursor.execute(
                    "SELECT id FROM quarantine WHERE (payload = ? OR payload = ?) AND status = 'PENDING' LIMIT 1",
                    (raw_payload, safe_payload),
                )
                if cursor.fetchone():
                    return False, "Already pending"

            # Proceed with INSERT if no pending duplicate is found
            cursor.execute(
                """
                INSERT INTO pending_requests
                    (timestamp, payload, predicted_class, confidence, status)
                VALUES (?, ?, ?, ?, 'PENDING')
                """,
                (current_time, safe_payload, predicted_class, round(confidence, 4)),
            )
            conn.commit()
            logger.info(
                f"[Quarantine] Logged pending request — class={predicted_class} "
                f"conf={confidence:.4f}"
            )
            return True, "Logged"

    except Exception as exc:
        logger.error(f"[Quarantine] log_pending_request error: {exc}")
        return False, str(exc)


def load_pending_requests() -> pd.DataFrame:
    """
    Return only PENDING rows from pending_requests as a DataFrame.

    Actioned rows (SAFE, RESOLVED, BLOCKED, EXPIRED_BLOCKED, AUTO_BLOCKED) are excluded
    so the quarantine queue only shows items awaiting admin review.

    Columns: id, timestamp, payload, predicted_class, confidence, status
    Returns an empty DataFrame on error.
    """
    try:
        with _get_conn() as conn:
            df = pd.read_sql_query(
                """
                SELECT id, timestamp, payload, predicted_class, confidence, status
                FROM pending_requests
                WHERE status = 'PENDING'
                ORDER BY timestamp DESC
                """,
                conn,
            )
        return df
    except Exception as exc:
        logger.error(f"[Quarantine] load_pending_requests error: {exc}")
        return pd.DataFrame()


def update_pending_status(row_id: int, new_status: str, payload: str = None) -> bool:
    """
    Update the status column for a single pending_requests row.

    Parameters
    ----------
    row_id     : Primary key of the row.
    new_status : One of 'SAFE', 'RESOLVED', 'BLOCKED', 'PENDING', 'EXPIRED_BLOCKED', 'AUTO_BLOCKED'.
    payload    : Optional payload string to update any duplicate pending rows.

    Returns
    -------
    True on success, False on failure.
    """
    allowed = {"SAFE", "RESOLVED", "BLOCKED", "PENDING", "EXPIRED_BLOCKED", "AUTO_BLOCKED"}
    if new_status not in allowed:
        logger.warning(
            f"[Quarantine] Rejected invalid status '{new_status}'. "
            f"Must be one of {allowed}."
        )
        return False

    try:
        with _get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE pending_requests SET status = ? WHERE id = ?",
                (new_status, row_id),
            )
            if payload:
                raw_p = str(payload).strip()
                safe_p = sanitize_payload(raw_p)
                cursor.execute(
                    """
                    UPDATE pending_requests SET status = ?
                    WHERE (payload = ? OR payload = ?) AND status = 'PENDING'
                    """,
                    (new_status, raw_p, safe_p),
                )
            conn.commit()

        logger.info(
            f"[Quarantine] Row {row_id} status updated to {new_status}."
        )
        return True

    except Exception as exc:
        logger.error(f"[Quarantine] update_pending_status error: {exc}")
        return False


def log_verified_attack(payload: str, predicted_class: str) -> bool:
    """
    Store a payload into verified_attack_dataset for future retraining.

    Parameters
    ----------
    payload         : Raw payload (will be sanitised before storage).
    predicted_class : Human-readable attack class label.

    Returns
    -------
    True on success, False on failure.
    """
    try:
        raw_payload = str(payload).strip()
        safe_payload = sanitize_payload(raw_payload)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with _get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM verified_attack_dataset WHERE payload = ? OR payload = ? LIMIT 1",
                (raw_payload, safe_payload),
            )
            if cursor.fetchone():
                logger.info("[Quarantine] Attack already logged in verified dataset.")
                return True

            cursor.execute(
                """
                INSERT INTO verified_attack_dataset (timestamp, payload, predicted_class)
                VALUES (?, ?, ?)
                """,
                (ts, safe_payload, predicted_class),
            )
            conn.commit()

        logger.info(
            f"[Quarantine] Verified attack logged for retraining — "
            f"class={predicted_class}."
        )
        return True

    except Exception as exc:
        logger.error(f"[Quarantine] log_verified_attack error: {exc}")
        return False


def add_to_allowlist(payload: str, source: str = "admin") -> bool:
    """
    Add a confirmed-safe payload to the allowlist table.
    Uses explicit SELECT deduplication check before INSERT.

    Parameters
    ----------
    payload : Raw payload (will be sanitised before storage).
    source  : Origin label, e.g. 'admin'.

    Returns
    -------
    True on success, False on failure.
    """
    try:
        raw_payload = str(payload).strip()
        safe_payload = sanitize_payload(raw_payload)
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with _get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM allowlist WHERE payload = ? OR payload = ? LIMIT 1",
                (raw_payload, safe_payload),
            )
            if not cursor.fetchone():
                cursor.execute(
                    "INSERT INTO allowlist (payload, source, timestamp) VALUES (?, ?, ?)",
                    (safe_payload, source, current_time),
                )
                conn.commit()
                logger.info("[Quarantine] Payload added to allowlist.")
            else:
                logger.info("[Quarantine] Payload already in allowlist. Skipped insertion.")

        return True

    except Exception as exc:
        logger.error(f"[Quarantine] add_to_allowlist error: {exc}")
        return False


def auto_expire_pending_requests() -> int:
    """
    Auto-Expiry SLA System:
    Find all rows in pending_requests where status = 'PENDING' AND the timestamp
    is older than 24 hours. Change their status to 'EXPIRED_BLOCKED'.

    Returns the number of rows updated.
    """
    try:
        cutoff = (datetime.now() - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        with _get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE pending_requests
                SET status = 'EXPIRED_BLOCKED'
                WHERE status = 'PENDING' AND timestamp <= ?
                """,
                (cutoff,)
            )
            count = cursor.rowcount
            conn.commit()

        if count > 0:
            logger.info(
                f"[Quarantine] Auto-expired {count} pending request(s) older than 24h to EXPIRED_BLOCKED."
            )
        return count
    except Exception as exc:
        logger.error(f"[Quarantine] auto_expire_pending_requests error: {exc}")
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# Streamlit UI renderer  (no auth gate — caller is responsible for RBAC)
# ─────────────────────────────────────────────────────────────────────────────

def render_quarantine_ui() -> None:
    """
    Render the full quarantine management panel inside the calling Streamlit page.

    This function has NO authentication gate of its own.
    The caller (Security Dashboard in app.py) must verify elevated credentials
    before invoking this function.

    Renders:
      • Summary metrics (total / pending / safe / blocked)
      • Class distribution bar chart
      • Status + class filters
      • Per-row cards with colour-coded status badges and action buttons
      • Verified attack dataset viewer with CSV export
      • Allowlist viewer
    """
    import streamlit as st
    import plotly.express as px

    # ── Auto-expire pending requests older than 24h (SLA timeout) ───────────
    expired_count = auto_expire_pending_requests()
    if expired_count > 0:
        st.info(f"⏳ **SLA Auto-Expiry:** {expired_count} request(s) older than 24h were auto-expired to `EXPIRED_BLOCKED`.")

    df_pending = load_pending_requests()

    if df_pending.empty:
        st.markdown(
            """
            <div style="
                background:#0d1f2d;
                border:1px solid #1a3a50;
                border-radius:14px;
                padding:32px;
                text-align:center;
                margin-top:20px;
            ">
                <div style="font-size:40px;">&#x1F7E2;</div>
                <div style="color:#4ade80; font-size:20px; font-weight:600; margin-top:10px;">
                    No Pending Quarantine Requests
                </div>
                <div style="color:#64748b; margin-top:8px;">
                    All requests are being classified with sufficient confidence.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        # ── NO early return: fall through so the bottom tables always render ──

    else:
        # ── Summary strip (query full table for all-time counts) ───────────────
        # df_pending only contains PENDING rows, so we query the DB directly for
        # the all-time SAFE / BLOCKED / total counts to keep the metrics accurate.
        try:
            with _get_conn() as _cs:
                _cursor = _cs.cursor()
                _cursor.execute("SELECT COUNT(*) FROM pending_requests")
                total_q = _cursor.fetchone()[0]
                _cursor.execute("SELECT COUNT(*) FROM pending_requests WHERE status = 'PENDING'")
                pending_q = _cursor.fetchone()[0]
                _cursor.execute("SELECT COUNT(*) FROM pending_requests WHERE status = 'SAFE'")
                safe_q = _cursor.fetchone()[0]
                _cursor.execute("SELECT COUNT(*) FROM pending_requests WHERE status IN ('BLOCKED','EXPIRED_BLOCKED','AUTO_BLOCKED')")
                blocked_q = _cursor.fetchone()[0]
        except Exception:
            total_q   = len(df_pending)
            pending_q = len(df_pending)
            safe_q    = 0
            blocked_q = 0

        sq1, sq2, sq3, sq4 = st.columns(4)
        sq1.metric("Total Quarantined", total_q)
        sq2.metric("\U0001f7e1 Awaiting Review", pending_q)
        sq3.metric("\u2705 Marked Safe", safe_q)
        sq4.metric("\U0001f6ab Blocked", blocked_q)

        st.markdown("---")

        # ── Class distribution mini-chart ────────────────────────────────────
        if "predicted_class" in df_pending.columns:
            try:
                fig_q = px.bar(
                    df_pending["predicted_class"].value_counts().reset_index(),
                    x="predicted_class",
                    y="count",
                    title="Quarantined Requests by Predicted Class",
                    color="predicted_class",
                    labels={"predicted_class": "Predicted Class", "count": "Count"},
                )
                fig_q.update_layout(
                    paper_bgcolor="#0B1220",
                    plot_bgcolor="#0B1220",
                    font_color="white",
                    showlegend=False,
                )
                st.plotly_chart(fig_q, use_container_width=True)
            except Exception:
                pass

        # ── Filter controls ──────────────────────────────────────────────────
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            status_filter = st.selectbox(
                "Filter by Status",
                ["All", "PENDING", "SAFE", "BLOCKED", "EXPIRED_BLOCKED"],
                key="qr_status_filter",
            )
        with col_f2:
            class_filter_opts = ["All"] + sorted(
                df_pending["predicted_class"].dropna().unique().tolist()
            )
            class_filter = st.selectbox(
                "Filter by Predicted Class",
                class_filter_opts,
                key="qr_class_filter",
            )

        view_df = df_pending.copy()
        if status_filter != "All":
            view_df = view_df[view_df["status"] == status_filter]
        if class_filter != "All":
            view_df = view_df[view_df["predicted_class"] == class_filter]

        st.markdown("---")
        st.markdown(f"### \U0001f4cb Quarantine Queue \u2014 {len(view_df)} record(s)")

        if view_df.empty:
            st.info("No records match the current filter.")
        else:
            now_dt = datetime.now()
            trigger_refresh = False
            for _, row in view_df.iterrows():
                row_id      = int(row["id"])
                row_payload = str(row.get("payload", ""))
                row_class   = str(row.get("predicted_class", ""))
                row_conf    = float(row.get("confidence", 0.0))
                row_status  = str(row.get("status", "PENDING"))
                row_ts      = str(row.get("timestamp", ""))

                # ── Calculate SLA Time Remaining (24h window) ────────────────
                try:
                    created_at = datetime.strptime(row_ts, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    try:
                        created_at = pd.to_datetime(row_ts).to_pydatetime()
                    except Exception:
                        created_at = now_dt

                expires_at = created_at + timedelta(hours=24)
                time_left = expires_at - now_dt
                total_seconds = int(time_left.total_seconds())

                if total_seconds <= 0:
                    sla_badge = "🔴 `EXPIRED (Pending Auto-Block)`"
                else:
                    hours_left = total_seconds // 3600
                    mins_left = (total_seconds % 3600) // 60
                    if total_seconds < 2 * 3600:
                        # < 2 hours remaining: Critical warning
                        sla_badge = f"🔴 **URGENT: Expires in {hours_left}h {mins_left:02d}m**"
                    elif total_seconds < 12 * 3600:
                        # < 12 hours remaining: Amber warning
                        sla_badge = f"🟡 **Expires in: {hours_left}h {mins_left:02d}m**"
                    else:
                        # > 12 hours remaining: Standard text
                        sla_badge = f"⏳ **Expires in: {hours_left}h {mins_left:02d}m**"

                status_icon = {
                    "PENDING":         "🟡",
                    "SAFE":            "✅",
                    "RESOLVED":        "✅",
                    "BLOCKED":         "🚫",
                    "EXPIRED_BLOCKED": "🔴",
                    "AUTO_BLOCKED":    "🔴",
                }.get(row_status, "⚪")

                with st.container(border=True):
                    # ── Header row ─────────────────────────────────────────
                    st.markdown(
                        f"**#{row_id}** &nbsp;·&nbsp; "
                        f"`{row_ts}` &nbsp;·&nbsp; "
                        f"**Class:** `{row_class}` &nbsp;·&nbsp; "
                        f"**Confidence:** `{row_conf:.2%}` &nbsp;·&nbsp; "
                        f"{sla_badge} &nbsp;·&nbsp; "
                        f"{status_icon} **{row_status}**"
                    )

                    # ── Payload block ──────────────────────────────────────
                    st.code(row_payload[:800] + ("…" if len(row_payload) > 800 else ""), language="http")

                    # ── Compact action buttons ─────────────────────────────
                    col1, col2, col3, col_spacer = st.columns([1.5, 1.5, 1.5, 5])

                    with col1:
                        if st.button(
                            "✅ Mark Safe",
                            key=f"safe_{row_id}",
                            use_container_width=True,
                            help="Mark this payload as safe and add it to the allowlist",
                        ):
                            update_pending_status(row_id, "SAFE", payload=row_payload)
                            add_to_allowlist(row_payload, source="admin")
                            st.success(f"Row #{row_id} marked as SAFE and added to allowlist.")
                            trigger_refresh = True

                    with col2:
                        if st.button(
                            "🚫 Block",
                            key=f"block_{row_id}",
                            use_container_width=True,
                            help="Permanently block this payload",
                        ):
                            update_pending_status(row_id, "BLOCKED", payload=row_payload)
                            st.error(f"Row #{row_id} permanently BLOCKED.")
                            trigger_refresh = True

                    with col3:
                        if st.button(
                            "☠️ New Attack",
                            key=f"attack_{row_id}",
                            use_container_width=True,
                            help="Store in verified attack dataset for future retraining",
                        ):
                            log_verified_attack(row_payload, row_class)
                            update_pending_status(row_id, "BLOCKED", payload=row_payload)
                            st.warning(
                                f"Row #{row_id} stored in verified attack dataset "
                                "and marked BLOCKED."
                            )
                            trigger_refresh = True

            if trigger_refresh:
                import time
                time.sleep(0.2)
                st.session_state['iam_refresh_tick'] = st.session_state.get('iam_refresh_tick', 0) + 1
                try:
                    st.rerun(scope="app")
                except TypeError:
                    st.rerun()

    # ── Expired (Auto-Blocked) Requests Audit Trail ───────────────────────────
    st.markdown("---")
    with st.expander("📂 View Expired (Auto-Blocked) Requests", expanded=False):
        st.caption(
            "Audit trail of quarantine requests that automatically expired after the 24-hour "
            "SLA timeout and were transitioned to EXPIRED_BLOCKED."
        )
        try:
            with _get_conn() as _cx:
                _df_exp = pd.read_sql_query(
                    """
                    SELECT id, timestamp, predicted_class, confidence, payload, status
                    FROM pending_requests
                    WHERE status IN ('EXPIRED_BLOCKED', 'AUTO_BLOCKED')
                    ORDER BY id DESC
                    """,
                    _cx,
                )
            if _df_exp.empty:
                st.info("No expired requests in the audit log.")
            else:
                st.dataframe(_df_exp, use_container_width=True)
                st.download_button(
                    "⬇️ Download Expired Audit Log (CSV)",
                    data=_df_exp.to_csv(index=False).encode("utf-8"),
                    file_name="expired_blocked_audit_log.csv",
                    mime="text/csv",
                    key="dl_expired_audit_csv",
                )
        except Exception as _ex_err:
            st.error(f"Could not load expired requests audit log: {_ex_err}")

    # ── Verified attack dataset viewer ─────────────────────────────────────────
    st.markdown("---")
    st.markdown("### \U0001f9ec Verified Attack Dataset (for Retraining)")
    st.caption(
        "Payloads confirmed by an admin as real attacks. "
        "Use this table to augment your training dataset before the next model retraining cycle."
    )
    try:
        with _get_conn() as _cv:
            _df_v = __import__("pandas").read_sql_query(
                "SELECT id, timestamp, predicted_class, payload "
                "FROM verified_attack_dataset ORDER BY id DESC",
                _cv,
            )
        if _df_v.empty:
            st.info("No verified attacks logged yet.")
        else:
            st.dataframe(_df_v, use_container_width=True)
            st.download_button(
                "\u2b07\ufe0f Download Verified Dataset (CSV)",
                data=_df_v.to_csv(index=False).encode("utf-8"),
                file_name="verified_attack_dataset.csv",
                mime="text/csv",
            )
    except Exception as _ev:
        st.error(f"Could not load verified attack dataset: {_ev}")

    # ── Allowlist viewer ───────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("### \u2705 Allowlist \u2014 Admin-Confirmed Safe Payloads")
    try:
        with _get_conn() as _ca:
            _df_a = __import__("pandas").read_sql_query(
                "SELECT id, timestamp, source, payload FROM allowlist ORDER BY id DESC",
                _ca,
            )
        if _df_a.empty:
            st.info("Allowlist is empty.")
        else:
            st.dataframe(_df_a, use_container_width=True)
    except Exception as _ea:
        st.error(f"Could not load allowlist: {_ea}")
