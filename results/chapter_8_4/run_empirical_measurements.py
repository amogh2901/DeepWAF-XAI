"""
DeepWAF-XAI: Empirical Measurement Script for Section 8.4
==========================================================
1. Evaluates held-out test split (19,776 samples) across payload length groups
   (20, 50, 80, 120, 160, 200 chars) to measure exact empirical accuracy.
2. Runs concurrent load latency benchmark (50, 100, 200, 300, 400, 500 concurrent requests)
   using ThreadPoolExecutor to record exact latency in milliseconds.
3. Saves empirical results to results/chapter_8_4/empirical_metrics.json.
"""

import os, sys, time, pickle, json, random
from concurrent.futures import ThreadPoolExecutor
import numpy as np
import pandas as pd
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))

MODEL_DIR = os.path.join(PROJECT_ROOT, "model")
DATASET_PATH = os.path.join(PROJECT_ROOT, "dataset", "payloads.csv")
OUTPUT_PATH = os.path.join(PROJECT_ROOT, "results", "chapter_8_4", "empirical_metrics.json")
os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

SEED = 42
MAX_SEQ = 200

print("[1/4] Loading model and tokenizer...")
model = tf.keras.models.load_model(os.path.join(MODEL_DIR, "threat_model.h5"))
with open(os.path.join(MODEL_DIR, "tokenizer.pkl"), "rb") as f:
    tokenizer = pickle.load(f)
with open(os.path.join(MODEL_DIR, "classes.pkl"), "rb") as f:
    classes = pickle.load(f)

print("[2/4] Rebuilding exact held-out test dataset split (19,776 samples)...")
np.random.seed(SEED)
random.seed(SEED)

df = pd.read_csv(DATASET_PATH)
df = df.dropna(subset=["payload"])
df["payload"] = df["payload"].astype(str)

# Synthetic Phishing identical to evaluate.py
brands = ["paypal","secure-bank","verify-paypal","chase-login","secure-login","wells-fargo","amazon-login","google-security","facebook-verify","apple-id-verify","netflix-update"]
tlds = [".com",".net",".org",".info",".xyz",".cc",".biz",".security-update.com",".login-verify.net"]
paths = ["/login","/signin","/verify","/update","/secure/login.php","/account/update.html","/auth/login"]
queries = ["?cmd=_login-run","?ref=login","?verify=1","?sec=secure","?id=123"]

def gen_phishing(n=5000):
    out = []
    for _ in range(n):
        parts = []
        if np.random.rand() > 0.5:
            parts.append(np.random.choice(brands)); parts.append(".")
        parts.append(np.random.choice(brands)); parts.append(np.random.choice(tlds))
        if np.random.rand() > 0.3: parts.append(np.random.choice(paths))
        if np.random.rand() > 0.5: parts.append(np.random.choice(queries))
        url = "http://" + "".join(parts)
        if np.random.rand() > 0.5: url = url.replace("http://","https://")
        out.append(url)
    return out

phishing_df = pd.DataFrame({"payload": gen_phishing(5000),"is_malicious":[1]*5000,"injection_type":["PHISHING"]*5000})

pages = ["home","dashboard","profile","settings","about us","contact us","products","services","faq","support","privacy policy","terms of service"]
users_list = ["admin","john","alice","michael","rahul","amogh","guest","testuser"]
domains = ["google.com","github.com","amazon.com","flipkart.com","openai.com","microsoft.com","apple.com"]
api_paths = ["/api/users","/api/products","/api/orders","/api/profile","/api/login","/api/logout","/api/search"]

normal_payloads = []
for _ in range(4000):
    u = random.choice(users_list)
    normal_payloads.extend([
        f"GET /{random.choice(pages).replace(' ','_')} HTTP/1.1",
        f"POST /login HTTP/1.1 username={u}",
        f"POST /register HTTP/1.1 username={u}",
        f"GET {random.choice(api_paths)}",
        f"POST {random.choice(api_paths)}",
        f"username={u}",
        f"email={u}@gmail.com",
        f"user={u}",
        f"page={random.choice(pages)}",
        f"category={random.choice(['books','mobiles','electronics','fashion'])}",
        f"product={random.choice(['laptop','phone','tv','mouse'])}",
        f"https://{random.choice(domains)}",
        f"https://www.{random.choice(domains)}",
        f"Welcome {u}",
        "Welcome to ThreatShield",
        f"Search {random.choice(['products','books','mobiles'])}",
        f"View {random.choice(['profile','dashboard','orders'])}",
        f"Order #{random.randint(1000,9999)}",
        f"Invoice {random.randint(1000,9999)}",
        f"Customer ID {random.randint(10000,99999)}"
    ])
for p in ["Welcome to ThreatShield","ThreatShield Dashboard","ThreatShield Home"]:
    normal_payloads.extend([p]*300)
for p in ["login?user=admin","search?q=laptop","Login","Dashboard","Home"]:
    normal_payloads.extend([p]*300)
random.shuffle(normal_payloads)
normal_df = pd.DataFrame({"payload": normal_payloads, "is_malicious": [0]*len(normal_payloads), "injection_type": ["LEGAL"]*len(normal_payloads)})

full_df = pd.concat([df, phishing_df, normal_df], ignore_index=True)

encoder = LabelEncoder()
encoder.classes_ = np.array(classes)
full_df["label"] = encoder.transform(full_df["injection_type"])

sequences = tokenizer.texts_to_sequences(full_df["payload"].values)
X_padded = tf.keras.preprocessing.sequence.pad_sequences(sequences, maxlen=MAX_SEQ, padding="post", truncating="post")
y = full_df["label"].values

# Train / Val / Test Split
X_tr, X_tmp, y_tr, y_tmp, df_tr, df_tmp = train_test_split(X_padded, y, full_df, test_size=0.20, random_state=SEED, stratify=y)
X_val, X_test, y_val, y_test, df_val, df_test = train_test_split(X_tmp, y_tmp, df_tmp, test_size=0.50, random_state=SEED, stratify=y_tmp)

print(f"      Held-out test set size: {len(X_test)} samples")

# Predict on full test set
print("[3/4] Evaluating predictions across payload length groups...")
y_probs = model.predict(X_test, verbose=0, batch_size=256)
y_pred = np.argmax(y_probs, axis=1)

df_test = df_test.copy().reset_index(drop=True)
df_test["y_true"] = y_test
df_test["y_pred"] = y_pred
df_test["correct"] = (y_test == y_pred)
df_test["char_length"] = df_test["payload"].apply(len)

# Define Payload Length Groups
length_bins = [
    {"label": "20 chars", "min_len": 1, "max_len": 35, "desc": "Short queries & tokens"},
    {"label": "50 chars", "min_len": 36, "max_len": 65, "desc": "Standard request paths & URLs"},
    {"label": "80 chars", "min_len": 66, "max_len": 99, "desc": "Moderate parameter strings"},
    {"label": "120 chars", "min_len": 100, "max_len": 140, "desc": "Obfuscated / encoded payloads"},
    {"label": "160 chars", "min_len": 141, "max_len": 180, "desc": "Multi-statement attack strings"},
    {"label": "200 chars", "min_len": 181, "max_len": 10000, "desc": "Extended / max-token vectors"}
]

payload_length_results = []
for b in length_bins:
    subset = df_test[(df_test["char_length"] >= b["min_len"]) & (df_test["char_length"] <= b["max_len"])]
    n_samples = len(subset)
    if n_samples > 0:
        acc = float(np.mean(subset["correct"]) * 100)
        mean_len = float(subset["char_length"].mean())
    else:
        acc = 0.0
        mean_len = 0.0
    payload_length_results.append({
        "group_label": b["label"],
        "min_len": b["min_len"],
        "max_len": b["max_len"],
        "sample_count": n_samples,
        "mean_length": round(mean_len, 1),
        "accuracy_pct": round(acc, 2),
        "description": b["desc"]
    })
    print(f"      Group {b['label']} (n={n_samples}): Accuracy = {acc:.2f}% (mean len={mean_len:.1f})")

print("[4/4] Running concurrent request latency benchmark on DeepWAF-XAI...")
# Concurrency levels
concurrency_levels = [50, 100, 200, 300, 400, 500]
test_payload_pool = df_test["payload"].values[:1000]

def single_request_inference(payload_str):
    t0 = time.perf_counter()
    seq = tokenizer.texts_to_sequences([payload_str])
    pad = tf.keras.preprocessing.sequence.pad_sequences(seq, maxlen=MAX_SEQ, padding="post", truncating="post")
    _ = model.predict(pad, verbose=0)
    t1 = time.perf_counter()
    return (t1 - t0) * 1000.0  # in milliseconds

# Warm-up run
for _ in range(5):
    _ = single_request_inference("GET /index.html HTTP/1.1")

concurrent_latency_results = []
for conc in concurrency_levels:
    # Select random batch of payload strings of size conc
    batch_payloads = [random.choice(test_payload_pool) for _ in range(conc)]
    
    # Execute concurrently using ThreadPoolExecutor
    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=conc) as executor:
        latencies = list(executor.map(single_request_inference, batch_payloads))
    total_batch_time = (time.perf_counter() - t_start) * 1000.0
    
    mean_lat_ms = float(np.mean(latencies))
    median_lat_ms = float(np.median(latencies))
    p95_lat_ms = float(np.percentile(latencies, 95))
    throughput_rps = float(conc / (total_batch_time / 1000.0))
    
    concurrent_latency_results.append({
        "concurrent_requests": conc,
        "mean_latency_ms": round(mean_lat_ms, 2),
        "median_latency_ms": round(median_lat_ms, 2),
        "p95_latency_ms": round(p95_lat_ms, 2),
        "total_batch_time_ms": round(total_batch_time, 2),
        "throughput_rps": round(throughput_rps, 1)
    })
    print(f"      Concurrency {conc}: Mean Latency = {mean_lat_ms:.2f} ms | P95 = {p95_lat_ms:.2f} ms | Throughput = {throughput_rps:.1f} req/s")

# Combine all results
empirical_data = {
    "test_samples_total": len(X_test),
    "overall_accuracy_pct": round(float(accuracy_score(y_test, y_pred) * 100), 2),
    "payload_length_analysis": payload_length_results,
    "concurrency_latency_analysis": concurrent_latency_results
}

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    json.dump(empirical_data, f, indent=2)

print(f"\nSaved empirical metrics to: {OUTPUT_PATH}")
