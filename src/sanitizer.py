"""
src/sanitizer.py
----------------
Input Sanitization Utility for DeepWAF-XAI.

sanitize_payload() is applied ONLY when writing to the database (attack_logs).
The raw, un-sanitized payload is always passed to the BiLSTM model first so
that detection accuracy is not affected.

Protects the Streamlit dashboard from Stored XSS when rendering log entries.
"""

import html
import re


def sanitize_payload(payload: str) -> str:
    """
    Sanitize a raw HTTP request / payload string before persisting it to the DB.

    Operations performed (in order):
      1. HTML-escape  <  >  &  "  '  to their safe entity equivalents.
         This neutralizes reflected / stored XSS attack strings.
      2. Collapse null bytes (\\x00) that could truncate string handling.
      3. Truncate to 2 000 characters to guard against oversized log entries.

    Returns the sanitized string.  The original payload is never mutated.
    """
    if not isinstance(payload, str):
        payload = str(payload)

    # 1. HTML-escape – converts < > & " ' to safe entities
    #    quote=True ensures both single and double quotes are escaped.
    sanitized = html.escape(payload, quote=True)

    # 2. Remove null bytes
    sanitized = sanitized.replace("\x00", "")

    # 3. Truncate to a safe maximum length for the database column
    sanitized = sanitized[:2000]

    return sanitized
