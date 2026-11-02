import sys
import time
import logging
import sqlite3
import os
from pathlib import Path
from collections import defaultdict, deque

sys.path.append(str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from detector import detect_attack
from logger import log_attack
from response_engine import query_threat_intel_feed

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WAF] %(levelname)s %(message)s"
)
waf_logger = logging.getLogger("waf_rate_limiter")

# ---------------------------------------------------------------------------
# Rate Limiter configuration
# ---------------------------------------------------------------------------
RATE_LIMIT_MAX_REQUESTS = 5    # max requests allowed per window (demo: 5 req / 10 s)
RATE_LIMIT_WINDOW_SEC   = 10   # rolling window in seconds

# In-memory store: { client_ip: deque([timestamp, ...]) }
_rate_limit_store: dict = defaultdict(deque)

# ---------------------------------------------------------------------------
# DB path (shared logs.db used by the rest of the project)
# ---------------------------------------------------------------------------
_BASE_DIR = Path(__file__).resolve().parent.parent
_DB_PATH  = str(_BASE_DIR / "database" / "logs.db")


def _init_rate_limit_table() -> None:
    """Create the WAF rate-limit log table if it doesn't exist."""
    try:
        os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
        with sqlite3.connect(_DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS waf_rate_limit_logs (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT,
                    client_ip   TEXT,
                    path        TEXT,
                    req_count   INTEGER
                )
            """)
            conn.commit()
    except Exception as exc:
        waf_logger.error("Could not initialise waf_rate_limit_logs table: %s", exc)


def _log_rate_limit_event(client_ip: str, path: str, req_count: int) -> None:
    """Persist a rate-limit block event to the shared SQLite database."""
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with sqlite3.connect(_DB_PATH) as conn:
            conn.execute(
                "INSERT INTO waf_rate_limit_logs "
                "(timestamp, client_ip, path, req_count) VALUES (?, ?, ?, ?)",
                (ts, client_ip, path, req_count)
            )
            conn.commit()
    except Exception as exc:
        waf_logger.error("Could not log rate-limit event: %s", exc)


def _is_rate_limited(client_ip: str) -> tuple[bool, int]:
    """
    Sliding-window rate limiter.

    Returns (is_limited: bool, current_count: int).
    Timestamps older than RATE_LIMIT_WINDOW_SEC are evicted before checking.
    """
    now    = time.time()
    window = _rate_limit_store[client_ip]

    # Evict timestamps that have fallen outside the rolling window
    while window and now - window[0] > RATE_LIMIT_WINDOW_SEC:
        window.popleft()

    window.append(now)
    count = len(window)

    if count > RATE_LIMIT_MAX_REQUESTS:
        return True, count
    return False, count


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI()

templates = Jinja2Templates(directory=str(_BASE_DIR / "templates"))

# Initialise the rate-limit log table at startup
_init_rate_limit_table()


@app.middleware("http")
async def threatshield_firewall(request: Request, call_next):

    path = request.url.path

    # ── Rate Limiter ────────────────────────────────────────────────────────
    # Determine client identity. Behind a proxy use X-Forwarded-For; fall back
    # to the raw connecting host. Use "local" for requests with no host info.
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "local")
    )

    limited, req_count = _is_rate_limited(client_ip)

    if limited:
        waf_logger.warning(
            "RATE LIMIT EXCEEDED | client=%s | path=%s | count=%d/%d in %ds",
            client_ip, path, req_count, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SEC
        )
        _log_rate_limit_event(client_ip, path, req_count)
        return JSONResponse(
            status_code=429,
            content={
                "error":  "WAF Rate Limit Exceeded. Suspected DoS/Brute-Force attack blocked.",
                "client": client_ip,
                "limit":  f"{RATE_LIMIT_MAX_REQUESTS} requests / {RATE_LIMIT_WINDOW_SEC}s"
            }
        )
    # ────────────────────────────────────────────────────────────────────────

    # Allow homepage through without deep-learning inspection
    if path == "/":
        return await call_next(request)

    # get user input safely
    query = request.query_params.get("query")

    if query:
        # ── Step 1: Dynamic Threat Intel Feed Check (Admin Verified Rules) ──
        intel = query_threat_intel_feed(query)
        if intel:
            if intel.get("action") == "ALLOW":
                waf_logger.info("THREAT INTEL ALLOWLIST MATCH | query=%s | reason=%s", query, intel.get("reason"))
                # Allowed by admin — bypass ML and proceed to handler
                return await call_next(request)
            elif intel.get("action") == "BLOCK":
                waf_logger.warning("THREAT INTEL BLOCKLIST MATCH | query=%s | reason=%s", query, intel.get("reason"))
                log_attack(query, "Verified Threat (Threat Intel)", confidence=1.0, severity="CRITICAL")
                return templates.TemplateResponse(
                    "blocked.html",
                    {"request": request}
                )

        # ── Step 2: BiLSTM Deep Learning Model Inference ────────────────────
        result = detect_attack(query)
        if isinstance(result, tuple):
            attack     = result[0]
            confidence = result[1] if len(result) > 1 else 1.0
        else:
            attack     = result
            confidence = 1.0

        if attack.lower() != "normal":

            log_attack(query, attack, confidence=confidence, severity="HIGH")

            return templates.TemplateResponse(
                "blocked.html",
                {"request": request}
            )

    response = await call_next(request)

    # ── HTTP Security Headers ────────────────────────────────────────────────
    # Injected on every legitimate (non-rate-limited) response to harden the
    # browser connection and mitigate common client-side attack vectors.
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"]   = "default-src 'self' 'unsafe-inline'"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    # ────────────────────────────────────────────────────────────────────────

    return response


@app.get("/", response_class=HTMLResponse)
def home(request: Request):

    template_name = "home.html" if (_BASE_DIR / "templates" / "home.html").exists() else "index.html"
    return templates.TemplateResponse(
        template_name,
        {"request": request}
    )


@app.get("/search")
def search(query: str):

    return {
        "result": f"You searched for: {query}"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)