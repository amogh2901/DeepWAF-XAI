import sqlite3
import re
import datetime
import os

class DBFirewall:
    def __init__(self, db_path=None):
        if db_path is None:
            # Default to the existing database folder
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.db_path = os.path.join(base_dir, 'database', 'logs.db')
        else:
            self.db_path = db_path
            
        # Forbidden SQL keywords that the application should never execute dynamically
        self.forbidden_patterns = [
            r'\bDROP\b',
            r'\bALTER\b',
            r'\bTRUNCATE\b',
            r'\bDELETE\b',
            r'\bGRANT\b',
            r';\s*DROP',
            r';\s*DELETE'
        ]
        self._init_firewall_table()

    def _init_firewall_table(self):
        """Creates a table to log blocked DB requests if it doesn't exist."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS db_firewall_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    query TEXT,
                    block_reason TEXT
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error initializing DB Firewall table: {e}")

    def inspect_query(self, query):
        """Checks the query against forbidden patterns."""
        query_upper = query.upper()
        for pattern in self.forbidden_patterns:
            if re.search(pattern, query_upper):
                clean_pattern = pattern.replace(r'\b', '').replace(r'\s*', ' ')
                return False, f"Unauthorized SQL pattern detected: {clean_pattern}"
        return True, "Safe"

    def execute_safe_query(self, query, parameters=()):
        """Intercepts the query, validates it, and executes if safe."""
        is_safe, reason = self.inspect_query(query)
        
        if not is_safe:
            self._log_blocked_query(query, reason)
            print(f"[DB FIREWALL BLOCKED] Reason: {reason}")
            return False, reason

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(query, parameters)
            conn.commit()
            
            if query.strip().upper().startswith("SELECT"):
                result = cursor.fetchall()
                conn.close()
                return True, result
            
            conn.close()
            return True, "Executed Successfully"
        except Exception as e:
            return False, str(e)

    def _log_blocked_query(self, query, reason):
        """Records the blocked query into the firewall logs."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO db_firewall_logs (timestamp, query, block_reason) VALUES (?, ?, ?)",
                (timestamp, query, reason)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error logging blocked query: {e}")
