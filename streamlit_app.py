"""
DeepWAF-XAI — Streamlit Community Cloud Entry Point
===================================================
This entry point configures module resolution paths so both local runs and
Streamlit Community Cloud deployment seamlessly locate src/ modules and assets.
"""
import os
import sys
from pathlib import Path
import runpy

# Safeguard container runtime permissions: ensure writable HOME and disable metrics write
if os.environ.get("HOME") in (None, "", "/"):
    os.environ["HOME"] = "/tmp"
os.environ["STREAMLIT_BROWSER_GATHER_USAGE_STATS"] = "false"
os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["TF_NUM_INTRAOP_THREADS"] = "1"
os.environ["TF_NUM_INTEROP_THREADS"] = "1"
try:
    Path("/tmp/.streamlit").mkdir(parents=True, exist_ok=True)
    Path("/tmp/matplotlib").mkdir(parents=True, exist_ok=True)
except Exception:
    pass

# Resolve repository paths
PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"

# Prepend src and project root to sys.path
for path in (SRC_DIR, PROJECT_ROOT):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

if __name__ == "__main__":
    # Execute primary Streamlit application
    app_entry = SRC_DIR / "app.py"
    runpy.run_path(str(app_entry), run_name="__main__")
