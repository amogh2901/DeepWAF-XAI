"""
DeepWAF-XAI — Streamlit Community Cloud Entry Point
===================================================
This entry point configures module resolution paths so both local runs and
Streamlit Community Cloud deployment seamlessly locate src/ modules and assets.
"""
import sys
from pathlib import Path
import runpy

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
