"""
src/auth.py
-----------
Enterprise Authentication & User Management Module for DeepWAF-XAI.
Handles secure bcrypt password hashing, database persistence,
SuperAdmin seeding, brute-force protection, progressive delays,
account lockouts, and role-based access control (RBAC).
"""

import sqlite3
import os
import logging
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
from datetime import datetime
import bcrypt

logger = logging.getLogger(__name__)

# Database path (database/users.db)
_BASE_DIR = Path(__file__).resolve().parent.parent
USERS_DB_PATH = Path(os.getenv("DEEPWAF_USERS_DB_PATH", str(_BASE_DIR / "database" / "users.db")))
DB_PATH = USERS_DB_PATH

# Master SuperAdmin configuration
SUPERADMIN_USERNAME = "admin"
SUPERADMIN_DEFAULT_PASSWORD = "deepwaf"


def _get_conn(target_db: Optional[Path] = None) -> sqlite3.Connection:
    """Return a raw sqlite3 connection to users.db (or target_db) with WAL mode enabled."""
    target = target_db or USERS_DB_PATH
    os.makedirs(target.parent, exist_ok=True)
    conn = sqlite3.connect(str(target), timeout=20.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    except Exception:
        pass
    return conn


def init_users_table(target_db: Optional[Path] = None) -> None:
    """
    Initialize the users and system_config tables and ensure all required columns exist.
    Inspects existing columns via PRAGMA table_info(users) and adds missing columns dynamically.
    Automatically seeds or updates the master SuperAdmin ('admin') with password 'deepwaf'.
    """
    try:
        with _get_conn(target_db) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TEXT DEFAULT NULL,
                    failed_attempts INTEGER DEFAULT 0,
                    is_locked INTEGER DEFAULT 0,
                    reset_requested INTEGER DEFAULT 0,
                    soc_passkey TEXT DEFAULT NULL
                )
            """)

            # ── Dynamic System Configuration Table ───────────────────────────
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Seed default SOC access keys if not present
            cursor.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES ('soc_admin_key', 'admin')")
            cursor.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES ('soc_tester_key', 'tester123')")

            # ── Robust PRAGMA Column Inspection & Dynamic Migration ──
            cursor.execute("PRAGMA table_info(users)")
            existing_cols = {row[1] for row in cursor.fetchall()}

            col_defs = {
                "created_at": "TEXT DEFAULT NULL",
                "failed_attempts": "INTEGER DEFAULT 0",
                "is_locked": "INTEGER DEFAULT 0",
                "reset_requested": "INTEGER DEFAULT 0",
                "soc_passkey": "TEXT DEFAULT NULL",
            }
            for col_name, col_type in col_defs.items():
                if col_name not in existing_cols:
                    try:
                        cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
                    except sqlite3.OperationalError as op_err:
                        logger.warning(f"[Auth] Column {col_name} migration note: {op_err}")

            # ── Database Cleanup Query (Clear dummy keys from non-testers) ───
            cursor.execute("UPDATE users SET soc_passkey = NULL WHERE UPPER(role) NOT IN ('TESTER') AND LOWER(username) != LOWER(?)", (SUPERADMIN_USERNAME,))

            # ── Backfill NULL timestamps with current local timestamp ────────
            local_now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("UPDATE users SET created_at = ? WHERE created_at IS NULL", (local_now_str,))

            # ── Auto-Migrate Legacy 'amogh' Administrator to 'admin' ──────────
            cursor.execute(
                "SELECT id, password, soc_passkey FROM users WHERE LOWER(username) = 'amogh' AND LOWER(role) = 'admin' LIMIT 1"
            )
            old_admin_row = cursor.fetchone()
            if old_admin_row:
                cursor.execute(
                    "SELECT id FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1",
                    (SUPERADMIN_USERNAME,)
                )
                existing_new_admin = cursor.fetchone()
                if not existing_new_admin:
                    cursor.execute(
                        "UPDATE users SET username = ?, role = 'admin', is_locked = 0 WHERE id = ?",
                        (SUPERADMIN_USERNAME, old_admin_row[0])
                    )
                    logger.info(f"[Auth] Migrated legacy administrator 'amogh' to '{SUPERADMIN_USERNAME}'.")
                else:
                    cursor.execute("DELETE FROM users WHERE id = ?", (old_admin_row[0],))

            # ── Auto-Seed & Force-Update SuperAdmin 'admin' ───────────────────
            cursor.execute(
                "SELECT id, password FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1",
                (SUPERADMIN_USERNAME,)
            )
            admin_row = cursor.fetchone()
            admin_hash = hash_password(SUPERADMIN_DEFAULT_PASSWORD)

            if not admin_row:
                cursor.execute(
                    "INSERT INTO users (username, password, role, created_at, failed_attempts, is_locked, reset_requested, soc_passkey) VALUES (?, ?, 'admin', ?, 0, 0, 0, 'admin')",
                    (SUPERADMIN_USERNAME, admin_hash, local_now_str)
                )
                logger.info(f"[Auth] Master SuperAdmin '{SUPERADMIN_USERNAME}' seeded successfully.")
            else:
                cursor.execute(
                    "UPDATE users SET role = 'admin', is_locked = 0 WHERE id = ?",
                    (admin_row[0],)
                )
                logger.info(f"[Auth] Master SuperAdmin '{SUPERADMIN_USERNAME}' credentials verified.")

            conn.commit()
    except Exception as exc:
        logger.error(f"[Auth] Error initializing users table: {exc}")


def get_soc_key(key_name: str, default: str = "") -> str:
    """
    Retrieve a persistent system configuration key from users.db.
    """
    init_users_table()
    try:
        with _get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM system_config WHERE key = ? LIMIT 1",
                (key_name,)
            )
            row = cursor.fetchone()
            if row and row[0]:
                return str(row[0])
    except Exception as exc:
        logger.error(f"[Auth] Error reading config key '{key_name}': {exc}")

    defaults = {
        "soc_admin_key": "admin",
        "soc_tester_key": "tester123"
    }
    return defaults.get(key_name, default)


def update_soc_key(key_name: str, new_value: str) -> bool:
    """
    Update or insert a persistent system configuration key in users.db.
    """
    new_value = new_value.strip()
    if not new_value:
        return False
    init_users_table()
    try:
        conn = _get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO system_config (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
            """, (key_name, new_value))
            conn.commit()
            return True
        finally:
            conn.close()
    except Exception as exc:
        logger.error(f"[Auth] Error updating config key '{key_name}': {exc}")
        return False


def get_user_passkey(username: str) -> str:
    """
    Retrieve an individual user's personal soc_passkey from users.db.
    """
    username = username.strip()
    if not username:
        return ""
    init_users_table()
    try:
        conn = _get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT soc_passkey FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1",
                (username,)
            )
            row = cursor.fetchone()
            if row and row[0]:
                return str(row[0])
        finally:
            conn.close()
    except Exception as exc:
        logger.error(f"[Auth] Error retrieving personal passkey for '{username}': {exc}")
    return ""


def update_user_passkey(username: str, new_passkey: str) -> bool:
    """
    Update an individual user's personal soc_passkey in users.db.
    """
    username = username.strip()
    new_passkey = new_passkey.strip()
    if not username or not new_passkey:
        return False
    init_users_table()
    try:
        conn = _get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET soc_passkey = ? WHERE LOWER(username) = LOWER(?)",
                (new_passkey, username)
            )
            if cursor.rowcount > 0:
                conn.commit()
                return True
            return False
        finally:
            conn.close()
    except Exception as exc:
        logger.error(f"[Auth] Error updating personal passkey for '{username}': {exc}")
        return False


def count_users_by_role(role: str) -> int:
    """
    Query users.db to return the active count of a given role.
    Treats 'user' and 'operator' as equivalent standard operator roles.
    """
    init_users_table()
    role_clean = role.strip().lower()
    try:
        with _get_conn() as conn:
            cursor = conn.cursor()
            if role_clean in ("user", "operator"):
                cursor.execute("SELECT COUNT(*) FROM users WHERE LOWER(role) IN ('user', 'operator')")
            else:
                cursor.execute(
                    "SELECT COUNT(*) FROM users WHERE LOWER(role) = LOWER(?)",
                    (role_clean,)
                )
            row = cursor.fetchone()
            return row[0] if row else 0
    except Exception as exc:
        logger.error(f"[Auth] Error counting users by role '{role}': {exc}")
        return 0


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against the stored bcrypt hash."""
    try:
        return bcrypt.checkpw(
            plain_password.encode("utf-8"),
            hashed_password.encode("utf-8")
        )
    except Exception:
        return False


def register_user(username: str, password: str) -> Tuple[bool, str]:
    """Register a new operator in the database with role capacity limits enforced."""
    username = username.strip()
    if not username or not password:
        return False, "Username and password required."

    if username.lower() == SUPERADMIN_USERNAME.lower():
        return False, f"{username} is a reserved administrator username and cannot be registered."

    init_users_table()

    hashed = hash_password(password)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO users (username, password, role, created_at, failed_attempts, is_locked, reset_requested, soc_passkey) "
            "VALUES (?, ?, 'operator', ?, 0, 0, 0, NULL)",
            (username, hashed, created_at)
        )
        conn.commit()
        return True, "Registered successfully"
    except sqlite3.IntegrityError:
        return False, "User already exists"
    except Exception as exc:
        return False, f"System error: {exc}"
    finally:
        conn.close()


def authenticate_user(username: str, password: str) -> Dict[str, Any]:
    """
    Authenticate a user by verifying credentials against the database.
    Implements enterprise brute-force tracking and automatic lockout (except SuperAdmin 'admin').
    Returns a dictionary response:
      - SUCCESS: {"status": "SUCCESS", "role": role, "message": "Credentials verified"}
      - LOCKED:  {"status": "LOCKED", "message": "Account Locked. Please request an unlock below."}
      - FAILED:  {"status": "FAILED", "attempts": failed_attempts, "message": "..."}
    """
    username = username.strip()
    if not username or not password:
        return {"status": "FAILED", "attempts": 0, "message": "Credentials required."}

    init_users_table()

    try:
        conn = _get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT password, role, failed_attempts, is_locked, reset_requested FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1",
                (username,)
            )
            row = cursor.fetchone()

            if not row:
                return {"status": "FAILED", "attempts": 1, "message": "Invalid credentials."}

            stored_hash, role, failed_attempts, is_locked, reset_requested = row
            failed_attempts = failed_attempts or 0
            is_locked = is_locked or 0

            # If account is already locked, immediately deny access
            if is_locked == 1:
                return {
                    "status": "LOCKED",
                    "role": role,
                    "attempts": failed_attempts,
                    "message": "Account Locked. Please request an unlock below."
                }

            if verify_password(password, stored_hash):
                # Successful login: reset failed attempts and reset request flag
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, reset_requested = 0 WHERE LOWER(username) = LOWER(?)",
                    (username,)
                )
                conn.commit()
                return {"status": "SUCCESS", "role": role, "message": "Credentials verified"}
            else:
                # Failed login: increment failed attempts
                new_attempts = failed_attempts + 1
                new_locked = 0

                # SuperAdmin 'admin' is shielded from account lockout (Anti-DoS)
                is_superadmin = (username.lower() == SUPERADMIN_USERNAME.lower())
                if new_attempts >= 5 and not is_superadmin:
                    new_locked = 1

                cursor.execute(
                    "UPDATE users SET failed_attempts = ?, is_locked = ? WHERE LOWER(username) = LOWER(?)",
                    (new_attempts, new_locked, username)
                )
                conn.commit()

                if new_locked == 1:
                    return {
                        "status": "FAILED",
                        "attempts": new_attempts,
                        "is_locked": True,
                        "message": "Attempt 5 of 5. Security delay: 20 seconds. Account Locked."
                    }

                return {
                    "status": "FAILED",
                    "attempts": new_attempts,
                    "is_locked": False,
                    "message": f"Invalid credentials. Attempt {new_attempts} of 5."
                }
        finally:
            conn.close()

    except Exception as exc:
        logger.error(f"[Auth] Authentication error: {exc}")
        return {"status": "FAILED", "attempts": 0, "message": f"Authentication error: {exc}"}


def request_account_reset(username: str) -> Tuple[bool, str]:
    """
    Set reset_requested = 1 for the specified user in users.db.
    """
    username = username.strip()
    if not username:
        return False, "Username required."

    if username.lower() == SUPERADMIN_USERNAME.lower():
        return False, "The SuperAdmin account cannot be unlocked or reset through the standard operator request system."

    init_users_table()
    try:
        conn = _get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET reset_requested = 1 WHERE LOWER(username) = LOWER(?)",
                (username,)
            )
            if cursor.rowcount > 0:
                conn.commit()
                return True, f"Reset request submitted for '{username}'."
            return False, f"User '{username}' not found."
        finally:
            conn.close()
    except Exception as exc:
        logger.error(f"[Auth] Error requesting reset: {exc}")
        return False, f"Database error requesting reset: {exc}"


def get_pending_iam_requests() -> List[Tuple]:
    """
    Return all users who are currently locked out (is_locked == 1)
    or have requested an IT password reset / unlock (reset_requested == 1).
    Returns: List of (id, username, role, failed_attempts, is_locked, reset_requested, created_at)
    """
    init_users_table()
    try:
        conn = _get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, role, failed_attempts, is_locked, reset_requested, created_at "
                "FROM users WHERE is_locked = 1 OR reset_requested = 1 ORDER BY id DESC"
            )
            return cursor.fetchall()
        finally:
            conn.close()
    except Exception as exc:
        logger.error(f"[Auth] Error fetching pending IAM requests: {exc}")
        return []


def admin_resolve_request(username: str, new_password: Optional[str] = None) -> Tuple[bool, str]:
    """
    Admin action to approve and unlock a user account, reset failed attempts and reset requests,
    and optionally set a new bcrypt-hashed temporary password.
    """
    username = username.strip()
    if not username:
        return False, "Username required."

    if username.lower() == SUPERADMIN_USERNAME.lower():
        return False, "The SuperAdmin account cannot be unlocked or reset through the standard operator request system."

    init_users_table()
    try:
        conn = _get_conn()
        try:
            cursor = conn.cursor()
            if new_password and len(new_password.strip()) > 0:
                hashed = hash_password(new_password.strip())
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, is_locked = 0, reset_requested = 0, password = ? WHERE LOWER(username) = LOWER(?)",
                    (hashed, username)
                )
            else:
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, is_locked = 0, reset_requested = 0 WHERE LOWER(username) = LOWER(?)",
                    (username,)
                )

            if cursor.rowcount > 0:
                conn.commit()
                pwd_msg = " Temporary password updated." if new_password and len(new_password.strip()) > 0 else ""
                return True, f"Account '{username}' unlocked and reset successfully.{pwd_msg}"
            return False, f"User '{username}' not found."
        finally:
            conn.close()
    except Exception as exc:
        logger.error(f"[Auth] Error resolving IAM request: {exc}")
        return False, f"Database error resolving request: {exc}"


def update_user_role(username: str, new_role: str) -> Tuple[bool, str]:
    """
    Update the assigned role of a user in users.db with strict role capacity limits.
    """
    username = username.strip()
    new_role = new_role.strip().lower()
    if not username:
        return False, "Username required."

    if username.lower() == SUPERADMIN_USERNAME.lower():
        return False, f"Protected account: Cannot modify role of SuperAdmin '{SUPERADMIN_USERNAME}'."

    init_users_table()

    # Check current role
    try:
        conn = _get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT role FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1", (username,))
            curr_row = cursor.fetchone()
            if not curr_row:
                return False, f"User '{username}' not found."
            curr_role = curr_row[0].lower() if curr_row[0] else "user"

            # Enforce Role Capacity Limits if switching into a restricted role
            if new_role == "tester" and curr_role != "tester":
                if count_users_by_role("tester") >= 3:
                    return False, "Maximum of 3 TESTER accounts reached. Demote an existing tester first."

            if new_role == "tester":
                cursor.execute(
                    "UPDATE users SET role = ?, soc_passkey = COALESCE(soc_passkey, 'tester123') WHERE LOWER(username) = LOWER(?)",
                    (new_role, username)
                )
            else:
                cursor.execute(
                    "UPDATE users SET role = ?, soc_passkey = NULL WHERE LOWER(username) = LOWER(?)",
                    (new_role, username)
                )

            if cursor.rowcount > 0:
                conn.commit()
                return True, f"Role for '{username}' updated to '{new_role.upper()}'."
            return False, f"User '{username}' not found."
        finally:
            conn.close()
    except Exception as exc:
        return False, f"Database error updating role: {exc}"


def provision_manual_user(username: str, password: str, role: str = "user") -> Tuple[bool, str]:
    """
    Provision a new user account directly with specified role, hashed password,
    and individual passkey, enforcing strict role capacity limits.
    """
    username = username.strip()
    role = role.strip().lower()
    if not username or not password:
        return False, "Username and password required."

    if username.lower() == SUPERADMIN_USERNAME.lower():
        return False, f"{username} is a reserved administrator username and cannot be registered."

    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    init_users_table()

    # Enforce Role Capacity Limits
    if role == "tester" and count_users_by_role("tester") >= 3:
        return False, "Maximum of 3 TESTER accounts reached. Demote an existing tester first."

    hashed = hash_password(password)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    soc_key = "tester123" if role == "tester" else None

    conn = _get_conn()
    try:
        conn.execute(
            "INSERT INTO users (username, password, role, created_at, failed_attempts, is_locked, reset_requested, soc_passkey) "
            "VALUES (?, ?, ?, ?, 0, 0, 0, ?)",
            (username, hashed, role, created_at, soc_key)
        )
        conn.commit()
        return True, f"Account '{username}' provisioned successfully as '{role.upper()}'."
    except sqlite3.IntegrityError:
        return False, f"User '{username}' already exists."
    except Exception as exc:
        return False, f"Error provisioning user: {exc}"
    finally:
        conn.close()


def get_all_users() -> List[Tuple]:
    """
    Query users.db and return a list of all registered users (excluding passwords)
    for the Streamlit IAM dashboard directory.
    Returns: List of (id, username, role, created_at, failed_attempts, is_locked, reset_requested, soc_passkey)
    """
    init_users_table()
    try:
        conn = _get_conn()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, role, created_at, "
                "COALESCE(failed_attempts, 0), COALESCE(is_locked, 0), COALESCE(reset_requested, 0), "
                "soc_passkey "
                "FROM users ORDER BY id DESC"
            )
            return cursor.fetchall()
        finally:
            conn.close()
    except Exception as exc:
        logger.error(f"[Auth] Error fetching user directory: {exc}")
        return []


# ── Automatic Migration on Module Import ──────────────────────────────────────
init_users_table()



