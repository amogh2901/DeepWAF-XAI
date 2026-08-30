import sqlite3
import os
import logging
from datetime import datetime
from src.db_firewall import DBFirewall
from src.sanitizer import sanitize_payload


# Set up a logger for the module
logger = logging.getLogger(__name__)

# Module-level DB Firewall instance – intercepts INSERT queries before execution
db_fw = DBFirewall()

def log_attack(
    request,
    attack_type,
    confidence=0.0,
    severity="LOW",
    threat_score=0.0,
    prediction_time_ms=0.0
):
    """
    Logs attack details into the SQLite database 'database/logs.db'.
    Creates the database directory and table if they do not exist.
    Adds missing optional columns without affecting existing data.
    """
    db_path = "database/logs.db"
    try:
        # Ensure the directory for the database exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        # Connect to the database using a context manager
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # Create table if it doesn't exist, with the initial schema
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    request TEXT,
                    attack_type TEXT
                )
            """)

            # Retrieve existing columns
            cursor.execute("PRAGMA table_info(attack_logs)")
            existing_columns = [info[1] for info in cursor.fetchall()]

            # Optional columns that may need to be added
            optional_columns = {
                "confidence": "REAL",
                "severity": "TEXT",
                "threat_score": "REAL",
                "prediction_time_ms": "REAL"
            }

            # Add missing optional columns
            for column_name, column_type in optional_columns.items():
                if column_name not in existing_columns:
                    try:
                        cursor.execute(f"ALTER TABLE attack_logs ADD COLUMN {column_name} {column_type}")
                        logger.info(f"Added missing column: {column_name}")
                    except sqlite3.Error as e:
                        logger.error(f"Error adding column {column_name}: {e}")

            # Route the INSERT through the DB Firewall
            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            insert_query = """
                INSERT INTO attack_logs (
                    timestamp,
                    request,
                    attack_type,
                    confidence,
                    severity,
                    threat_score,
                    prediction_time_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            # Sanitize the raw request string before persisting to the DB.
            # IMPORTANT: The BiLSTM model already received the raw payload
            # upstream (in app.py) before log_attack() was called, so
            # sanitization here does NOT affect detection accuracy.
            safe_request = sanitize_payload(request)

            insert_params = (
                timestamp_str,
                safe_request,   # sanitized copy stored in DB
                attack_type,
                confidence,
                severity,
                threat_score,
                prediction_time_ms
            )
            success, message = db_fw.execute_safe_query(insert_query, insert_params)
            if not success:
                logger.warning(f"DB Firewall blocked query: {message}")
            else:
                logger.info("Attack logged successfully.")

        return success

    except sqlite3.Error as e:
        # Log SQLite errors
        logger.error(f"SQLite error: {e}")
        return False
    except Exception as e:
        # Log any other unexpected errors
        logger.error(f"Unexpected error: {e}")
        return False