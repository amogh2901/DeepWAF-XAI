"""
main.py
-------
Embarko cloud entrypoint for DeepWAF-XAI.
Reads the dynamic PORT environment variable assigned by Embarko,
binds to 0.0.0.0, and launches the Streamlit SOC application.
"""

import os
import sys
from pathlib import Path

# Safeguard container runtime permissions: ensure writable HOME and disable metrics write
if os.environ.get("HOME") in (None, "", "/"):
    os.environ["HOME"] = "/tmp"

os.environ["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"
os.environ["STREAMLIT_SERVER_HEADLESS"] = "true"
os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib"

# Low memory thread constraints for Linux containers (256MB limit)
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["TF_NUM_INTRAOP_THREADS"] = "1"
os.environ["TF_NUM_INTEROP_THREADS"] = "1"
os.environ["MALLOC_TRIM_THRESHOLD_"] = "100000"

try:
    Path("/tmp/.streamlit").mkdir(parents=True, exist_ok=True)
    Path("/tmp/matplotlib").mkdir(parents=True, exist_ok=True)
except Exception:
    pass

# Configure persistent data directory (Embarko DATA_DIR or /tmp fallback)
data_dir = os.environ.get("DATA_DIR")
if not data_dir:
    data_dir = os.path.join(str(Path(__file__).resolve().parent), "database")
    try:
        os.makedirs(data_dir, exist_ok=True)
    except Exception:
        data_dir = "/tmp/deepwaf_data"

try:
    os.makedirs(data_dir, exist_ok=True)
except Exception:
    data_dir = "/tmp/deepwaf_data"
    os.makedirs(data_dir, exist_ok=True)

os.environ["DATA_DIR"] = data_dir
os.environ["DEEPWAF_DATABASE_DIR"] = data_dir
os.environ["DEEPWAF_LOGS_DB_PATH"] = os.path.join(data_dir, "logs.db")
os.environ["DEEPWAF_USERS_DB_PATH"] = os.path.join(data_dir, "users.db")

if __name__ == "__main__":
    port = os.environ.get("PORT", "8501")
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        "src/app.py",
        "--server.port",
        str(port),
        "--server.address",
        "0.0.0.0",
        "--server.headless",
        "true",
        "--browser.gatherUsageStats",
        "false",
    ]
    os.execv(sys.executable, cmd)
