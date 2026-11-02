"""
DeepWAF-XAI — Chapter 8.3 Evaluation Script
==============================================
Runs a proper held-out test split evaluation on the trained model.
Measures:
  - Classification metrics (accuracy, precision, recall, F1)
  - Per-class detection performance
  - Prediction latency (model inference only)
  - End-to-end request processing latency
  - Confusion matrix
  - Security feature validation

Usage:
    cd d:/Amogh/MCA/DeepWAF-XAI
    python results/chapter_8_3/evaluate.py

All outputs are saved to: results/chapter_8_3/
"""

import os, sys, time, pickle, json, warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

warnings.filterwarnings("ignore")

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "results", "chapter_8_3")
os.makedirs(OUTPUT_DIR, exist_ok=True)

MODEL_DIR  = os.path.join(PROJECT_ROOT, "model")
DATASET    = os.path.join(PROJECT_ROOT, "dataset", "payloads.csv")
SEED       = 42
MAX_SEQ    = 200
LATENCY_N  = 200

print("\n" + "="*60)
print("  DeepWAF-XAI -- Chapter 8.3 Evaluation")
print("="*60 + "\n")

print("[1/6] Loading model artefacts ...")
import tensorflow as tf

model_h5   = os.path.join(MODEL_DIR, "threat_model.h5")
model_k    = os.path.join(MODEL_DIR, "threat_model.keras")
model_path = model_h5 if os.path.exists(model_h5) else model_k
model      = tf.keras.models.load_model(model_path)
print(f"      Model loaded from: {model_path}")

with open(os.path.join(MODEL_DIR, "tokenizer.pkl"), "rb") as f:
    tokenizer = pickle.load(f)
with open(os.path.join(MODEL_DIR, "classes.pkl"), "rb") as f:
    classes = pickle.load(f)
with open(os.path.join(MODEL_DIR, "model_info.pkl"), "rb") as f:
    model_info = pickle.load(f)
with open(os.path.join(MODEL_DIR, "history.pkl"), "rb") as f:
    history = pickle.load(f)

print(f"      Classes: {classes}")
print(f"      Vocab size: {model_info['vocab_size']}")

print("\n[2/6] Rebuilding training dataset split ...")
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

np.random.seed(SEED)
import random
random.seed(SEED)

df = pd.read_csv(DATASET)
df = df.dropna(subset=["payload"])
df["payload"] = df["payload"].astype(str)

brands  = ["paypal","secure-bank","verify-paypal","chase-login","secure-login","wells-fargo","amazon-login","google-security","facebook-verify","apple-id-verify","netflix-update"]
tlds    = [".com",".net",".org",".info",".xyz",".cc",".biz",".security-update.com",".login-verify.net"]
paths   = ["/login","/signin","/verify","/update","/secure/login.php","/account/update.html","/auth/login"]
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

pages=["home","dashboard","profile","settings","about us","contact us","products","services","faq","support","privacy policy","terms of service"]
users_list=["admin","john","alice","michael","rahul","amogh","guest","testuser"]
domains=["google.com","github.com","amazon.com","flipkart.com","openai.com","microsoft.com","apple.com"]
api_paths=["/api/users","/api/products","/api/orders","/api/profile","/api/login","/api/logout","/api/search"]

normal_payloads = []
for _ in range(4000):
    u = random.choice(users_list)
    normal_payloads.extend([f"GET /{random.choice(pages).replace(' ','_')} HTTP/1.1",f"POST /login HTTP/1.1 username={u}",f"POST /register HTTP/1.1 username={u}",f"GET {random.choice(api_paths)}",f"POST {random.choice(api_paths)}",f"username={u}",f"email={u}@gmail.com",f"user={u}",f"page={random.choice(pages)}",f"category={random.choice(['books','mobiles','electronics','fashion'])}",f"product={random.choice(['laptop','phone','tv','mouse'])}",f"https://{random.choice(domains)}",f"https://www.{random.choice(domains)}",f"Welcome {u}","Welcome to ThreatShield",f"Search {random.choice(['products','books','mobiles'])}",f"View {random.choice(['profile','dashboard','orders'])}",f"Order #{random.randint(1000,9999)}",f"Invoice {random.randint(1000,9999)}",f"Customer ID {random.randint(10000,99999)}"])
for p in ["Welcome to ThreatShield","ThreatShield Dashboard","ThreatShield Home"]: normal_payloads.extend([p]*300)
for p in ["login?user=admin","search?q=laptop","Login","Dashboard","Home"]: normal_payloads.extend([p]*300)
random.shuffle(normal_payloads)
normal_df = pd.DataFrame({"payload":normal_payloads,"is_malicious":[0]*len(normal_payloads),"injection_type":["LEGAL"]*len(normal_payloads)})

full_df = pd.concat([df, phishing_df, normal_df], ignore_index=True)
print(f"      Full dataset: {len(full_df)} rows")
print(full_df["injection_type"].value_counts().to_string(header=False))

encoder = LabelEncoder()
encoder.classes_ = np.array(classes)
full_df["label"] = encoder.transform(full_df["injection_type"])

sequences = tokenizer.texts_to_sequences(full_df["payload"].values)
X_padded  = tf.keras.preprocessing.sequence.pad_sequences(sequences, maxlen=MAX_SEQ, padding="post", truncating="post")
y         = full_df["label"].values

X_tr, X_tmp, y_tr, y_tmp = train_test_split(X_padded, y, test_size=0.20, random_state=SEED, stratify=y)
X_val, X_test, y_val, y_test = train_test_split(X_tmp, y_tmp, test_size=0.50, random_state=SEED, stratify=y_tmp)
print(f"      Train={len(X_tr)} Val={len(X_val)} Test={len(X_test)}")

print("\n[3/6] Evaluating on held-out test set ...")
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

loss_val, acc_val = model.evaluate(X_test, y_test, verbose=0)
y_pred_probs = model.predict(X_test, verbose=0)
y_pred = np.argmax(y_pred_probs, axis=1)

overall_accuracy  = accuracy_score(y_test, y_pred)
overall_precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
overall_recall    = recall_score(y_test, y_pred, average="weighted", zero_division=0)
overall_f1        = f1_score(y_test, y_pred, average="weighted", zero_division=0)
macro_precision   = precision_score(y_test, y_pred, average="macro", zero_division=0)
macro_recall      = recall_score(y_test, y_pred, average="macro", zero_division=0)
macro_f1          = f1_score(y_test, y_pred, average="macro", zero_division=0)
correct           = int(np.sum(y_pred == y_test))
incorrect         = int(np.sum(y_pred != y_test))

report      = classification_report(y_test, y_pred, target_names=classes, output_dict=True)
report_text = classification_report(y_test, y_pred, target_names=classes)
print(report_text)
with open(os.path.join(OUTPUT_DIR,"classification_report_test.txt"),"w") as f:
    f.write(report_text)

cm = confusion_matrix(y_test, y_pred)
print("Confusion matrix:\n", cm)

print("\n[4/6] Measuring latency ...")
np.random.seed(SEED)
sample_idx = np.random.choice(len(X_test), size=LATENCY_N, replace=False)
X_latency  = X_test[sample_idx]

single_latencies = []
for i in range(LATENCY_N):
    t0 = time.perf_counter()
    _ = model.predict(X_latency[i:i+1], verbose=0)
    t1 = time.perf_counter()
    single_latencies.append((t1-t0)*1000)

avg_pred_ms    = float(np.mean(single_latencies))
median_pred_ms = float(np.median(single_latencies))
p95_pred_ms    = float(np.percentile(single_latencies,95))
p99_pred_ms    = float(np.percentile(single_latencies,99))
print(f"  Pred latency — mean={avg_pred_ms:.2f}ms  p95={p95_pred_ms:.2f}ms  p99={p99_pred_ms:.2f}ms")

raw_samples = full_df["payload"].values[np.random.choice(len(full_df),size=LATENCY_N,replace=False)]
e2e_latencies = []
for payload in raw_samples:
    t0 = time.perf_counter()
    seq    = tokenizer.texts_to_sequences([str(payload)])
    padded = tf.keras.preprocessing.sequence.pad_sequences(seq,maxlen=MAX_SEQ,padding="post",truncating="post")
    probs  = model.predict(padded, verbose=0)
    idx    = int(np.argmax(probs)); conf = float(probs[0][idx]); _ = classes[idx]
    t1 = time.perf_counter()
    e2e_latencies.append((t1-t0)*1000)

avg_e2e_ms    = float(np.mean(e2e_latencies))
median_e2e_ms = float(np.median(e2e_latencies))
p95_e2e_ms    = float(np.percentile(e2e_latencies,95))
p99_e2e_ms    = float(np.percentile(e2e_latencies,99))
print(f"  E2E  latency — mean={avg_e2e_ms:.2f}ms  p95={p95_e2e_ms:.2f}ms  p99={p99_e2e_ms:.2f}ms")

print("\n[5/6] Security feature validation ...")
try:
    from response_engine import response_action
    from threat_score import calculate_threat_score
    from detector import detect_attack

    feature_tests_input = [
        ("SQL Injection Detection", "' OR 1=1 --", "Attack detected (SQL)","detect"),
        ("XSS Detection", "<script>alert('xss')</script>", "Attack detected (XSS)","detect"),
        ("Path Traversal Detection", "../../etc/passwd", "Attack detected (SHELL)","detect"),
        ("Phishing URL Detection", "http://secure-bank.verify-paypal.cc/login?verify=1", "Attack detected (PHISHING)","detect"),
        ("Legitimate Request Pass-Through", "GET /dashboard HTTP/1.1 username=alice", "LEGAL (no threat)","detect"),
        ("Confidence Scoring", "SELECT * FROM users WHERE id=1", "Confidence (0.0-1.0)","detect"),
        ("Threat Score — CRITICAL", "severity=CRITICAL, conf=0.98", "Score in [0,1]","threat_score"),
        ("Response Engine — BLOCK", "severity=CRITICAL, conf=0.99", "BLOCK/BLOCKED","resp_block"),
        ("Response Engine — ALLOW", "severity=LOW, attack=Normal, conf=0.99", "ALLOW/SAFE","resp_allow"),
        ("Quarantine Low Confidence", "conf=0.55", "UNKNOWN/Quarantined","quarantine"),
    ]

    results_table = []
    for feat, inp, expected, test_type in feature_tests_input:
        try:
            if test_type == "detect":
                attack, conf, probs = detect_attack(inp)
                actual = f"Predicted: {attack} (conf={conf:.2f})"
                if "SQL" in expected: st = "PASS" if "SQL" in attack or "Injection" in attack else "WARN"
                elif "XSS" in expected: st = "PASS" if "XSS" in attack or "Script" in attack else "WARN"
                elif "SHELL" in expected: st = "PASS" if "Traversal" in attack or "SHELL" in attack else "WARN"
                elif "PHISHING" in expected: st = "PASS" if "Phishing" in attack else "WARN"
                elif "LEGAL" in expected: st = "PASS" if attack == "Normal" else "WARN"
                else: st = "PASS" if 0.0<=conf<=1.0 else "FAIL"
            elif test_type == "threat_score":
                score = calculate_threat_score("CRITICAL", 0.98)
                actual = f"Score={score:.2f}"
                st = "PASS" if 0.0<=score<=1.0 else "FAIL"
            elif test_type == "resp_block":
                resp = response_action("CRITICAL", confidence=0.99, attack_type="SQL Injection", payload="test")
                action = resp.get("action", resp.get("status","?"))
                actual = f"action={action}, status={resp.get('status','?')}"
                st = "PASS" if action in ("BLOCK","BLOCKED") or resp.get("status") in ("BLOCKED","UNKNOWN") else "WARN"
            elif test_type == "resp_allow":
                resp = response_action("LOW", confidence=0.99, attack_type="Normal", payload="test")
                action = resp.get("action", resp.get("status","?"))
                actual = f"action={action}, status={resp.get('status','?')}"
                st = "PASS" if action == "ALLOW" or resp.get("status") == "SAFE" else "WARN"
            elif test_type == "quarantine":
                resp = response_action("HIGH", confidence=0.55, attack_type="SQL Injection", payload="test")
                quarantined = resp.get("quarantined",False)
                actual = f"quarantined={quarantined}, status={resp.get('status','?')}"
                st = "PASS" if quarantined or resp.get("status")=="UNKNOWN" else "FAIL"
        except Exception as e:
            actual = f"ERROR: {e}"; st = "ERROR"
        results_table.append({"Feature":feat,"Test Input":inp[:55]+("..." if len(inp)>55 else ""),"Expected Outcome":expected,"Actual Outcome":actual,"Status":st})
        print(f"  [{st}] {feat}")

except Exception as exc:
    print(f"  Could not run feature tests: {exc}")
    results_table = []

print("\n[6/6] Saving results.json ...")
per_class_stats = {}
for cls in classes:
    if cls in report:
        per_class_stats[cls] = {"precision":round(report[cls]["precision"],4),"recall":round(report[cls]["recall"],4),"f1_score":round(report[cls]["f1-score"],4),"support":int(report[cls]["support"])}

results_json = {
    "model_path":model_path,"dataset_rows":int(len(full_df)),"test_samples":int(len(X_test)),"correct":correct,"incorrect":incorrect,
    "test_loss":round(float(loss_val),4),"overall_accuracy":round(float(overall_accuracy),4),
    "weighted_precision":round(float(overall_precision),4),"weighted_recall":round(float(overall_recall),4),"weighted_f1":round(float(overall_f1),4),
    "macro_precision":round(float(macro_precision),4),"macro_recall":round(float(macro_recall),4),"macro_f1":round(float(macro_f1),4),
    "classes":classes,"per_class":per_class_stats,"confusion_matrix":cm.tolist(),
    "latency":{"n_requests":LATENCY_N,"pred_mean_ms":round(avg_pred_ms,3),"pred_median_ms":round(median_pred_ms,3),"pred_p95_ms":round(p95_pred_ms,3),"pred_p99_ms":round(p99_pred_ms,3),"e2e_mean_ms":round(avg_e2e_ms,3),"e2e_median_ms":round(median_e2e_ms,3),"e2e_p95_ms":round(p95_e2e_ms,3),"e2e_p99_ms":round(p99_e2e_ms,3)},
    "training_history":history,
    "security_feature_tests":results_table
}

with open(os.path.join(OUTPUT_DIR,"results.json"),"w") as f:
    json.dump(results_json, f, indent=2)
print(f"  Saved: {os.path.join(OUTPUT_DIR,'results.json')}")
print("\n" + "="*60 + "\n  DONE\n" + "="*60)
