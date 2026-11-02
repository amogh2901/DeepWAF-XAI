# 🛡️ DeepWAF-XAI — Explainable Deep Learning Web Application Firewall

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/TensorFlow-2.13%2B-orange?logo=tensorflow&logoColor=white" />
  <img src="https://img.shields.io/badge/Streamlit-UI-red?logo=streamlit&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-WAF%20Server-green?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Flask-REST%20API-black?logo=flask&logoColor=white" />
  <img src="https://img.shields.io/badge/XAI-Explainability-purple" />
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" />
</p>

> **DeepWAF-XAI** (also branded as **ThreatShield DL**) is an Explainable Deep Learning Framework for real-time web attack detection and intelligent threat mitigation. It fuses a Character-Level Stacked Bidirectional LSTM model with Explainable AI (XAI), Threat Intelligence, and an adaptive Web Application Firewall to detect, explain, and respond to web-based cyber threats.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Detected Attack Classes](#-detected-attack-classes)
- [Model Architecture](#-model-architecture)
- [Model Performance](#-model-performance)
- [Project Structure](#-project-structure)
- [Installation](#-installation)
- [Running the Application](#-running-the-application)
- [Browser Extension](#-browser-extension-threatshield)
- [Tech Stack](#-tech-stack)
- [Configuration](#-configuration)
- [Dataset](#-dataset)
- [Security Modules](#-security-modules)
- [Contributing](#-contributing)

---

## 🔍 Overview

DeepWAF-XAI addresses a critical gap in modern web security: **traditional rule-based WAFs are blind to novel attack patterns**, and black-box ML models offer no insight into *why* a request was flagged. This framework combines:

- A **Character-Level Stacked Bidirectional LSTM** that operates directly on raw HTTP payloads — no hand-crafted features needed.
- **Explainable AI (XAI)** that provides saliency heatmaps and human-readable reasoning for every prediction.
- A **Threat Intelligence** layer integrating real-world threat feeds.
- An **Adaptive Response Engine** with quarantine, IP blocking, and rate-limiting capabilities.
- A **Streamlit-based SOC Dashboard** for real-time monitoring, incident management, and analyst workflows.
- A **Chrome/Edge Browser Extension** (ThreatShield) for client-side URL scanning.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🤖 **Deep Learning Detection** | Character-level Stacked BiLSTM model trained on 100k+ payloads |
| 🔎 **XAI Explanations** | Saliency heatmaps + human-readable reasons for each prediction |
| 🚨 **Adaptive Response Engine** | Block, quarantine, rate-limit, or sanitize based on threat confidence |
| 🌐 **Threat Intelligence** | External threat feed integration for enriched context |
| 🍯 **Honeypot Detection** | Detects and flags known honeypot trigger paths |
| 🧪 **Adversarial Sandbox** | Generates adversarial mutations to stress-test the model |
| 📊 **SOC Dashboard** | Real-time attack analytics with Plotly charts and geo-maps |
| 🔐 **Role-Based Auth (RBAC)** | SuperAdmin / Admin / SOC Analyst / Viewer tiers |
| 🗂️ **Incident Management** | Full incident lifecycle: create, escalate, resolve, export |
| 🔒 **IP Block Manager** | Manual and automated IP blacklisting with TTL |
| 🧱 **FastAPI WAF Middleware** | Reverse-proxy WAF server that intercepts and scores requests |
| 🌍 **Browser Extension** | Chrome/Edge extension that scans URLs via the Flask REST API |
| 🔑 **Quarantine Queue** | Low-confidence predictions held for human analyst review |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER / BROWSER                           │
│              ThreatShield Extension (Chrome/Edge)               │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP Request / URL
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Flask REST API  (port 5000)                   │
│              api.py  — /predict, /health endpoints              │
└────────────────────────────┬────────────────────────────────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
          ▼                  ▼                  ▼
   ┌─────────────┐  ┌──────────────────┐  ┌──────────────┐
   │  Detector   │  │  Threat Intel    │  │   Honeypot   │
   │ (BiLSTM)    │  │  (threat_intel)  │  │   Checker    │
   └──────┬──────┘  └────────┬─────────┘  └──────┬───────┘
          │                  │                    │
          ▼                  ▼                    │
   ┌─────────────────────────────────┐           │
   │     Explanation Engine (XAI)    │           │
   │  Saliency Heatmap + Reasons     │           │
   └─────────────┬───────────────────┘           │
                 │                               │
                 ▼                               ▼
   ┌─────────────────────────────────────────────────────────┐
   │               Adaptive Response Engine                  │
   │  Block │ Quarantine │ Rate-limit │ Allow │ Sanitize     │
   └────────────────────────┬────────────────────────────────┘
                            │
                            ▼
   ┌─────────────────────────────────────────────────────────┐
   │         SQLite Logs DB  (database/logs.db)              │
   │  attack_logs │ quarantine │ blocked_ips │ waf_logs      │
   └────────────────────────┬────────────────────────────────┘
                            │
                            ▼
   ┌─────────────────────────────────────────────────────────┐
   │          Streamlit SOC Dashboard  (app.py)              │
   │  Real-time charts │ Incidents │ IAM │ Reports │ Config  │
   └─────────────────────────────────────────────────────────┘
```

---

## 🎯 Detected Attack Classes

| Label | Attack Type | Description |
|---|---|---|
| `LEGAL` | **Normal** | Benign / safe HTTP traffic |
| `SQL` | **SQL Injection** | UNION-based, blind, time-based SQLi |
| `XSS` | **Cross-Site Scripting** | Reflected, stored, DOM-based XSS |
| `SHELL` | **Path Traversal** | `../../etc/passwd` style shell injection |
| `PHISHING` | **Phishing URL** | Deceptive URLs mimicking trusted brands |

---

## 🧠 Model Architecture

The core detection engine is a **Character-Level Stacked Bidirectional LSTM**:

```
Input Payload (raw text)
        │
        ▼
[ Embedding Layer ]  dim=64, vocab learned from payloads
        │
        ▼
[ SpatialDropout1D ]  rate=0.2
        │
        ▼
[ Conv1D (64 filters, kernel=3) ]  + ReLU  — local pattern extraction
        │
        ▼
[ Conv1D (128 filters, kernel=5) ]  + ReLU  — wider context
        │
        ▼
[ Bidirectional LSTM (64 units) ]  return_sequences=True
        │
        ▼
[ Bidirectional LSTM (64 units) ]  — deeper sequential context
        │
        ▼
[ Dropout (0.4) ]
        │
        ▼
[ Dense (64) ]  + ReLU
        │
        ▼
[ Dropout (0.4) ]
        │
        ▼
[ Dense (5) ]  Softmax — 5-class output
```

**Key hyper-parameters:**

| Parameter | Value |
|---|---|
| Max Sequence Length | 150 characters |
| Embedding Dimensions | 64 |
| BiLSTM Units | 64 (→128 bidirectional) |
| Dropout Rate | 0.4 |
| Batch Size | 128 |
| Epochs | 15 (early stopping patience=3) |
| Optimizer | Adam (lr=0.001, min=1e-6) |
| Confidence Threshold | 0.60 (below → predicted Normal) |

---

## 📊 Model Performance

Evaluated on a held-out test set of **21,050 samples**:

```
              precision    recall  f1-score   support

       LEGAL       1.00      0.99      1.00     19564
    PHISHING       0.99      1.00      1.00       500
       SHELL       0.52      0.94      0.67        32
         SQL       0.60      0.95      0.74       165
         XSS       0.97      0.98      0.98       789

    accuracy                           0.99     21050
   macro avg       0.82      0.97      0.87     21050
weighted avg       0.99      0.99      0.99     21050
```

> ✅ **Overall Accuracy: 99%** on weighted average — exceptionally high recall across all attack classes.

---

## 📁 Project Structure

```
DeepWAF-XAI/
│
├── src/                          # Core application source
│   ├── app.py                    # Main Streamlit SOC dashboard
│   ├── detector.py               # Payload inference using BiLSTM model
│   ├── train_model.py            # Model training pipeline
│   ├── waf_server.py             # FastAPI WAF middleware server
│   ├── api.py                    # Flask REST API (/predict, /health)
│   ├── auth.py                   # RBAC authentication & user management
│   ├── response_engine.py        # Adaptive response: block/quarantine/allow
│   ├── threat_intelligence.py    # Threat feed integration
│   ├── incident_manager.py       # Incident lifecycle management
│   ├── quarantine.py             # Quarantine queue management
│   ├── logger.py                 # Structured attack logging to SQLite
│   ├── sanitizer.py              # Payload sanitization utilities
│   ├── adversarial_sandbox.py    # Adversarial mutation generator
│   ├── honeypot.py               # Honeypot trigger detection
│   ├── threat_score.py           # Composite threat score calculator
│   ├── block_manager.py          # IP block/unblock management
│   ├── db_firewall.py            # Firewall rule database helpers
│   ├── config.py                 # Central configuration & hyper-params
│   └── admin_config.py           # Admin passkey configuration
│
├── explainability/               # XAI module
│   ├── __init__.py
│   └── explanation_engine.py     # Saliency heatmaps + reason generation
│
├── model/                        # Trained model artifacts
│   ├── threat_model.keras        # Primary model (native Keras format)
│   ├── threat_model.h5           # Legacy fallback model
│   ├── tokenizer.pkl             # Character-level tokenizer
│   ├── label_encoder.pkl         # Class label encoder
│   ├── classes.pkl               # Class names list
│   ├── model_info.pkl            # Model metadata (max_seq_len, etc.)
│   ├── confusion_matrix.png      # Evaluation confusion matrix
│   ├── training_accuracy.png     # Training accuracy curve
│   ├── training_loss.png         # Training loss curve
│   ├── classification_report.txt # Per-class precision/recall/F1
│   └── model_summary.txt         # Keras model layer summary
│
├── dataset/
│   └── payloads.csv              # Training dataset (100k+ labeled payloads)
│
├── database/
│   └── logs.db                   # SQLite database (attack logs, quarantine, IAM)
│
├── ThreatShield_Extension/       # Chrome/Edge browser extension
│   ├── manifest.json             # Manifest V3 extension config
│   ├── background.js             # Service worker — URL scanning logic
│   ├── popup.html / popup.js     # Extension popup UI
│   ├── blocked.html              # Blocked page redirect
│   └── style.css                 # Extension styles
│
├── templates/                    # Jinja2 HTML templates (WAF server)
├── requirements.txt              # Python dependencies
├── demo_firewall.py              # Standalone firewall demo script
├── check_model_info.py           # Utility: print model metadata
├── check_predictions.py          # Utility: quick prediction sanity check
└── check_classes.py              # Utility: print loaded class labels
```

---

## ⚙️ Installation

### Prerequisites

- Python **3.10+**
- pip or [uv](https://github.com/astral-sh/uv) package manager
- Google Chrome or Microsoft Edge (for browser extension)

### 1. Clone the Repository

```bash
git clone https://github.com/amogh2901/DeepWAF-XAI.git
cd DeepWAF-XAI
```

### 2. Create a Virtual Environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

> **With uv (faster):**
> ```bash
> uv pip install -r requirements.txt
> ```

### 4. Verify Model Files

Ensure the following model artifacts exist under `model/`:

```
model/
├── threat_model.keras  ✅
├── tokenizer.pkl       ✅
├── label_encoder.pkl   ✅
├── classes.pkl         ✅
└── model_info.pkl      ✅
```

If not, train the model first (see [Training the Model](#training-the-model)).

---

## 🚀 Running the Application

### Option A — Streamlit SOC Dashboard (Primary UI)

```bash
streamlit run src/app.py
```

Opens at: **http://localhost:8501**

> The dashboard provides full SOC functionality: live payload scanner, attack analytics, incident management, quarantine review, IP block manager, and IAM (role-based user management).

---

### Option B — Flask REST API (for Browser Extension / External Clients)

```bash
python src/api.py
```

Runs at: **http://localhost:5000**

**Endpoints:**

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/predict` | Analyze a payload or URL for threats |
| `GET` | `/health` | API health check |

**Example request:**

```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"payload": "SELECT * FROM users WHERE id=1 OR 1=1--"}'
```

**Example response:**

```json
{
  "attack_type": "SQL Injection",
  "confidence": 0.9812,
  "probabilities": {
    "SQL Injection": 0.9812,
    "Normal": 0.0101,
    "Cross Site Scripting": 0.0047,
    "Path Traversal": 0.0023,
    "Phishing URL": 0.0017
  },
  "explanation": {
    "risk_level": "HIGH",
    "reasons": ["SELECT keyword detected", "Authentication bypass pattern detected"],
    "explanation_text": "..."
  }
}
```

---

### Option C — FastAPI WAF Middleware Server

```bash
uvicorn src.waf_server:app --host 0.0.0.0 --port 8000
```

Runs at: **http://localhost:8000**

> Acts as a reverse-proxy WAF — intercepts incoming HTTP requests, scores them with the BiLSTM model, and either allows, blocks, or rate-limits based on the response engine decision.

---

### Training the Model

To retrain the model from scratch on `dataset/payloads.csv`:

```bash
python src/train_model.py
```

This will:
1. Load and preprocess the dataset
2. Generate 5,000 synthetic phishing URLs
3. Train the Stacked BiLSTM model (15 epochs, early stopping)
4. Save model artifacts to `model/`
5. Generate confusion matrix, training curves, and classification report

---

## 🌐 Browser Extension (ThreatShield)

The **ThreatShield Chrome/Edge Extension** scans URLs in real time using the Flask REST API.

### Installation

1. Open Chrome/Edge and navigate to `chrome://extensions/`
2. Enable **Developer Mode** (top right toggle)
3. Click **"Load unpacked"**
4. Select the `ThreatShield_Extension/` folder

### Usage

- The extension automatically scans every URL you visit via the background service worker
- If a **threat is detected**, it redirects you to `blocked.html` showing the threat details
- Click the extension icon in the toolbar to view the current page's threat status

> ⚠️ The Flask API server (`python src/api.py`) must be running locally on port **5000** for the extension to function.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Deep Learning** | TensorFlow 2.13+, Keras (BiLSTM, Conv1D, Embedding) |
| **Data Processing** | NumPy, Pandas, scikit-learn, SciPy |
| **Visualization** | Matplotlib, Seaborn, Plotly |
| **SOC Dashboard** | Streamlit, streamlit-autorefresh |
| **REST API** | Flask 3.0+, Flask-CORS |
| **WAF Middleware** | FastAPI, Uvicorn |
| **Templating** | Jinja2 |
| **Database** | SQLite3 (standard library) |
| **Authentication** | bcrypt (password hashing) |
| **Browser Extension** | JavaScript (Manifest V3), HTML/CSS |
| **Environment** | python-dotenv |

---

## ⚙️ Configuration

All project-wide constants are centralized in [`src/config.py`](src/config.py):

```python
# Tokenizer / Sequence Settings
MAX_SEQUENCE_LEN  = 150     # Maximum character sequence length

# Model Architecture
EMBEDDING_DIM     = 64      # Embedding output dimensions
BILSTM_UNITS      = 64      # BiLSTM units (→ 128 bidirectional)
DROPOUT_RATE      = 0.4

# Training
EPOCHS            = 15
BATCH_SIZE        = 128
EARLY_STOP_PATIENCE = 3

# Security Settings
BLOCK_DURATION_SECONDS = 300   # IP block TTL (seconds)
RATE_LIMIT_REQUESTS    = 10    # Max requests per minute

# Inference
CONFIDENCE_TEMPERATURE = 1.2   # Temperature scaling for calibration
```

**Attack Labels:**

```python
LABEL_MAPPING = {
    "LEGAL":    0,   # Normal traffic
    "XSS":      1,   # Cross-Site Scripting
    "SQL":      2,   # SQL Injection
    "SHELL":    3,   # Path Traversal
    "PHISHING": 4,   # Phishing URLs
}
```

---

## 📦 Dataset

The model is trained on `dataset/payloads.csv` — a labeled dataset of web payloads:

| Column | Description |
|---|---|
| `payload` | Raw HTTP request string / URL |
| `label` | Attack class (`LEGAL`, `SQL`, `XSS`, `SHELL`, `PHISHING`) |

**Data Composition:**
- Real-world SQL injection, XSS, and path traversal payloads
- Benign HTTP request samples
- **5,000 synthetically generated phishing URLs** (via `train_model.py`)

> The dataset file is approximately **3.4 MB** and contains **~100,000+** labeled samples.

---

## 🔐 Security Modules

### Explanation Engine (`explainability/explanation_engine.py`)
- Pattern-matching + token saliency to highlight **which characters/keywords** triggered the prediction
- Generates **color-coded saliency heatmaps** for SOC analyst review
- Produces human-readable risk summaries: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`

### Adaptive Response Engine (`src/response_engine.py`)
- `confidence ≥ threshold` → **Block** the request
- `QUARANTINE_THRESHOLD_LOW ≤ confidence < threshold` → **Quarantine** (hold for human review)
- `confidence < 0.60` → **Allow** (classified as Normal)
- Integrates payload **sanitization** before passing to downstream

### Quarantine Manager (`src/quarantine.py`)
- Pending requests queue stored in SQLite
- SOC analysts can **approve** (allow) or **reject** (block) quarantined requests from the dashboard

### Incident Manager (`src/incident_manager.py`)
- Full **SIEM-style incident lifecycle**: open → investigate → escalate → resolve → close
- Severity tiers: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- Export incidents as reports

### IP Block Manager (`src/block_manager.py`)
- Manual IP blacklisting from the SOC Dashboard
- Automatic blocking after repeated high-confidence detections
- Configurable TTL (default: 300 seconds)

### Rate Limiter (`src/waf_server.py`)
- Rolling window rate limiting: **5 requests / 10 seconds** per IP (WAF server)
- Separate limit of **10 requests / minute** (application level)

---

## 🤝 Contributing

1. Fork this repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License**.

---

## 👤 Author

**Amogh** — MCA Project  
Repository: [amogh2901/DeepWAF-XAI](https://github.com/amogh2901/DeepWAF-XAI)

---

<p align="center">
  Made with ❤️ for safer web applications · <strong>DeepWAF-XAI / ThreatShield DL</strong>
</p>