"""
ThreatShield DL — Central Configuration
========================================
All project-wide constants, paths, and hyper-parameters live here.
Import this module instead of scattering magic values across files.
"""

import os

# ─────────────────────────────────────────────
# Project Root (resolved from this file's location)
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─────────────────────────────────────────────
# Directory Paths
# ─────────────────────────────────────────────
DATASET_DIR  = os.path.join(BASE_DIR, "dataset")
MODEL_DIR    = os.path.join(BASE_DIR, "model")
DATABASE_DIR = os.path.join(BASE_DIR, "database")

# ─────────────────────────────────────────────
# Dataset Files
# ─────────────────────────────────────────────
PAYLOADS_CSV = os.path.join(DATASET_DIR, "payloads.csv")

# ─────────────────────────────────────────────
# Model Artifacts
# ─────────────────────────────────────────────
MODEL_PATH         = os.path.join(MODEL_DIR, "threat_model.keras")   # native Keras format
MODEL_H5_PATH      = os.path.join(MODEL_DIR, "threat_model.h5")      # legacy fallback
TOKENIZER_PATH     = os.path.join(MODEL_DIR, "tokenizer.pkl")
MODEL_CONFIG_PATH  = os.path.join(MODEL_DIR, "model_config.json")

# Evaluation artifacts
HISTORY_PLOT_PATH      = os.path.join(MODEL_DIR, "training_history.png")
CONFUSION_MATRIX_PATH  = os.path.join(MODEL_DIR, "confusion_matrix.png")
REPORT_PATH            = os.path.join(MODEL_DIR, "classification_report.txt")

# ─────────────────────────────────────────────
# Database Paths (Persistent & Environment-Configurable)
# ─────────────────────────────────────────────
DATABASE_DIR = os.getenv("DEEPWAF_DATABASE_DIR", os.path.join(BASE_DIR, "database"))
os.makedirs(DATABASE_DIR, exist_ok=True)
LOGS_DB_PATH  = os.getenv("DEEPWAF_LOGS_DB_PATH", os.path.join(DATABASE_DIR, "logs.db"))
USERS_DB_PATH = os.getenv("DEEPWAF_USERS_DB_PATH", os.path.join(DATABASE_DIR, "users.db"))

# ─────────────────────────────────────────────
# Backend & Reverse Proxy Services (Configurable for Cloud Deployments)
# ─────────────────────────────────────────────
BACKEND_API_URL = os.getenv("DEEPWAF_API_URL", "http://localhost:5000")
WAF_SERVER_URL  = os.getenv("DEEPWAF_WAF_URL", "http://localhost:8000")

# ─────────────────────────────────────────────
# Tokenizer / Sequence Settings
# ─────────────────────────────────────────────
MAX_SEQUENCE_LEN  = 150   # Maximum character sequence length
OOV_TOKEN         = "<OOV>"

# ─────────────────────────────────────────────
# Model Architecture Hyper-parameters
# ─────────────────────────────────────────────
EMBEDDING_DIM     = 64    # Embedding output dimensions
CONV1D_FILTERS_1  = 64    # First Conv1D filter count
CONV1D_FILTERS_2  = 128   # Second Conv1D filter count
CONV1D_KERNEL_1   = 3     # First Conv1D kernel size
CONV1D_KERNEL_2   = 5     # Second Conv1D kernel size
BILSTM_UNITS      = 64    # BiLSTM units (output = 128 due to bidirectionality)
DENSE_UNITS       = 64    # Intermediate Dense layer units
DROPOUT_RATE      = 0.4   # Dropout rate
SPATIAL_DROPOUT   = 0.2   # SpatialDropout1D rate

# ─────────────────────────────────────────────
# Training Hyper-parameters
# ─────────────────────────────────────────────
EPOCHS            = 15
BATCH_SIZE        = 128
VALIDATION_SPLIT  = 0.1
TEST_SIZE         = 0.2
RANDOM_SEED       = 42
EARLY_STOP_PATIENCE    = 3     # EarlyStopping patience
LR_REDUCE_PATIENCE     = 2     # ReduceLROnPlateau patience
LR_REDUCE_FACTOR       = 0.5   # ReduceLROnPlateau factor
MIN_LR                 = 1e-6  # Minimum learning rate

# ─────────────────────────────────────────────
# Label Mapping
# ─────────────────────────────────────────────
LABEL_MAPPING = {
    "LEGAL":    0,   # normal / safe traffic
    "XSS":      1,   # Cross-Site Scripting
    "SQL":      2,   # SQL Injection
    "SHELL":    3,   # Path Traversal / Shell injection
    "PHISHING": 4,   # Phishing URLs
}

CLASS_NAMES = ["normal", "xss", "sql_injection", "path_traversal", "phishing_link"]

# ─────────────────────────────────────────────
# Inference Settings
# ─────────────────────────────────────────────
CONFIDENCE_TEMPERATURE = 1.2   # Temperature scaling for confidence calibration

# ─────────────────────────────────────────────
# Security Settings
# ─────────────────────────────────────────────
BLOCK_DURATION_SECONDS = 300   # How long to block an IP (seconds)
RATE_LIMIT_REQUESTS    = 10    # Max requests per minute before rate-limiting

# ─────────────────────────────────────────────
# Synthetic Data Generation
# ─────────────────────────────────────────────
SYNTHETIC_PHISHING_SAMPLES = 5000
