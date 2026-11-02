"""
DeepWAF-XAI: Generate Section 8.4 Line Graphs
==============================================
Generates the exact 4 line graphs required for Section 8.4:
- Figure 8.4.1: Training and Validation Accuracy Across Epochs
- Figure 8.4.2: Detection Performance Comparison of Existing Systems and DeepWAF-XAI
- Figure 8.4.3: Detection Latency Under Concurrent Requests
- Figure 8.4.4: Detection Accuracy Across Different Payload Lengths

Outputs saved to: results/chapter_8_4/graphs/
"""

import os, json, pickle
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
GRAPHS_DIR = os.path.join(PROJECT_ROOT, "results", "chapter_8_4", "graphs")
os.makedirs(GRAPHS_DIR, exist_ok=True)

# Load empirical data
with open(os.path.join(PROJECT_ROOT, "model", "history.pkl"), "rb") as f:
    history = pickle.load(f)

with open(os.path.join(PROJECT_ROOT, "results", "chapter_8_3", "results.json"), "r", encoding="utf-8") as f:
    results_8_3 = json.load(f)

with open(os.path.join(PROJECT_ROOT, "results", "chapter_8_4", "empirical_metrics.json"), "r", encoding="utf-8") as f:
    empirical_data = json.load(f)

# Global styling for Word / Black Book presentation
plt.rcParams.update({
    "figure.dpi": 300,
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.titlesize": 11.5,
    "axes.labelsize": 10.5,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": "#334155",
    "axes.linewidth": 1.0,
    "grid.color": "#CBD5E1",
    "grid.linestyle": "--",
    "grid.alpha": 0.6,
    "xtick.labelsize": 9.5,
    "ytick.labelsize": 9.5
})

# ==============================================================================
# Graph 1: Figure 8.4.1: Training and Validation Accuracy Across Epochs
# ==============================================================================
fig, ax = plt.subplots(figsize=(8.5, 5.0))
epochs = list(range(1, len(history["accuracy"]) + 1))
train_acc = [v * 100.0 for v in history["accuracy"]]
val_acc = [v * 100.0 for v in history["val_accuracy"]]

ax.plot(epochs, train_acc, color="#2563EB", linestyle="-", marker="o", linewidth=2.2, markersize=6.5, label="Training Accuracy (%)")
ax.plot(epochs, val_acc, color="#DC2626", linestyle="--", marker="s", linewidth=2.2, markersize=6.5, label="Validation Accuracy (%)")

# Test accuracy reference line
test_acc = results_8_3["overall_accuracy"] * 100.0
ax.axhline(test_acc, color="#059669", linestyle=":", linewidth=1.8, label=f"Held-Out Test Accuracy ({test_acc:.2f}%)")

for ep, ta, va in zip(epochs, train_acc, val_acc):
    ax.annotate(f"{ta:.1f}%", (ep, ta), textcoords="offset points", xytext=(0, 6), ha="center", fontsize=8, fontweight="bold", color="#1D4ED8")
    ax.annotate(f"{va:.1f}%", (ep, va), textcoords="offset points", xytext=(0, -12), ha="center", fontsize=8, fontweight="bold", color="#B91C1C")

ax.set_xticks(epochs)
ax.set_xlim(0.6, 10.4)
ax.set_ylim(82, 102)
ax.yaxis.set_major_formatter(mtick.PercentFormatter())
ax.set_xlabel("Epoch Number", fontweight="bold", labelpad=8)
ax.set_ylabel("Accuracy (%)", fontweight="bold", labelpad=8)
ax.set_title("Figure 8.4.1: Training and Validation Accuracy Across Epochs", fontweight="bold", pad=14)
ax.grid(True)
ax.legend(loc="lower right", framealpha=0.95, edgecolor="#CBD5E1")

plt.tight_layout()
fig_1_path = os.path.join(GRAPHS_DIR, "fig_8_4_1_training_validation_accuracy.png")
plt.savefig(fig_1_path, dpi=300, bbox_inches="tight")
plt.close()
print("Saved:", fig_1_path)


# ==============================================================================
# Graph 2: Figure 8.4.2: Detection Performance Comparison of Existing Systems and DeepWAF-XAI
# ==============================================================================
fig, ax = plt.subplots(figsize=(9.2, 5.2))
metrics = ["Accuracy", "Precision", "Recall", "F1-Score"]

# Systems
trad_waf = [82.40, 84.10, 79.60, 81.80]     # Literature baseline (ModSecurity CRS)
ml_svm_rf = [88.70, 89.20, 86.50, 87.80]    # Literature baseline (Classical ML SVM/RF)
balnet = [91.30, 92.00, 90.80, 91.40]       # Base Paper baseline (BALNet 2026)
deepwaf = [
    results_8_3["overall_accuracy"] * 100.0,
    results_8_3["weighted_precision"] * 100.0,
    results_8_3["weighted_recall"] * 100.0,
    results_8_3["weighted_f1"] * 100.0
]

ax.plot(metrics, trad_waf, color="#64748B", linestyle="--", marker="o", linewidth=2.0, markersize=7, label="Traditional WAF (ModSecurity CRS) [Reported]")
ax.plot(metrics, ml_svm_rf, color="#2563EB", linestyle="-.", marker="^", linewidth=2.0, markersize=7, label="Classical ML Baseline (SVM/RF) [Reported]")
ax.plot(metrics, balnet, color="#7C3AED", linestyle=":", marker="s", linewidth=2.2, markersize=8, label="BALNet (Deep Learning Base Paper) [Reported]")
ax.plot(metrics, deepwaf, color="#059669", linestyle="-", marker="D", linewidth=3.0, markersize=8.5, label="DeepWAF-XAI (Proposed Framework) [Measured]")

# Annotate DeepWAF-XAI
for m, val in zip(metrics, deepwaf):
    ax.annotate(f"{val:.2f}%", (m, val), textcoords="offset points", xytext=(0, 9), ha="center", fontsize=8.5, fontweight="bold", color="#047857")

# Annotate Traditional WAF
for m, val in zip(metrics, trad_waf):
    ax.annotate(f"{val:.1f}%", (m, val), textcoords="offset points", xytext=(0, -13), ha="center", fontsize=8, color="#475569")

ax.set_ylim(74, 102)
ax.yaxis.set_major_formatter(mtick.PercentFormatter())
ax.set_xlabel("Evaluation Metric", fontweight="bold", labelpad=8)
ax.set_ylabel("Performance (%)", fontweight="bold", labelpad=8)
ax.set_title("Figure 8.4.2: Detection Performance Comparison of Existing Systems and DeepWAF-XAI", fontweight="bold", pad=14)
ax.grid(True)
ax.legend(loc="lower right", framealpha=0.96, edgecolor="#CBD5E1", fontsize=9)

plt.tight_layout()
fig_2_path = os.path.join(GRAPHS_DIR, "fig_8_4_2_detection_performance_comparison.png")
plt.savefig(fig_2_path, dpi=300, bbox_inches="tight")
plt.close()
print("Saved:", fig_2_path)


# ==============================================================================
# Graph 3: Figure 8.4.3: Detection Latency Under Concurrent Requests
# ==============================================================================
fig, ax = plt.subplots(figsize=(8.8, 5.0))
conc_data = empirical_data["concurrency_latency_analysis"]
concurrency_x = [d["concurrent_requests"] for d in conc_data]
mean_lat_y = [d["mean_latency_ms"] for d in conc_data]
median_lat_y = [d["median_latency_ms"] for d in conc_data]
p95_lat_y = [d["p95_latency_ms"] for d in conc_data]

ax.plot(concurrency_x, mean_lat_y, color="#0284C7", linestyle="-", marker="o", linewidth=2.4, markersize=7.5, label="DeepWAF-XAI: Mean Latency (ms)")
ax.plot(concurrency_x, median_lat_y, color="#059669", linestyle="-.", marker="^", linewidth=2.0, markersize=7, label="DeepWAF-XAI: Median (P50) Latency (ms)")
ax.plot(concurrency_x, p95_lat_y, color="#DC2626", linestyle="--", marker="s", linewidth=2.0, markersize=7, label="DeepWAF-XAI: 95th Percentile (P95) Latency (ms)")

# Annotate Mean data points
for x, y in zip(concurrency_x, mean_lat_y):
    ax.annotate(f"{y:.0f} ms", (x, y), textcoords="offset points", xytext=(0, 8), ha="center", fontsize=8.5, fontweight="bold", color="#0369A1")

# Annotate P95 data points
for x, y in zip(concurrency_x, p95_lat_y):
    ax.annotate(f"{y:.0f} ms", (x, y), textcoords="offset points", xytext=(0, 8), ha="center", fontsize=8, color="#B91C1C")

ax.set_xticks(concurrency_x)
ax.set_xlim(30, 520)
ax.set_ylim(500, 7200)
ax.set_xlabel("Concurrent Requests (Client Concurrency Level)", fontweight="bold", labelpad=8)
ax.set_ylabel("Detection Latency (milliseconds)", fontweight="bold", labelpad=8)
ax.set_title("Figure 8.4.3: Detection Latency Under Concurrent Requests", fontweight="bold", pad=14)
ax.grid(True)
ax.legend(loc="upper left", framealpha=0.96, edgecolor="#CBD5E1", fontsize=9.5)

plt.tight_layout()
fig_3_path = os.path.join(GRAPHS_DIR, "fig_8_4_3_concurrent_latency.png")
plt.savefig(fig_3_path, dpi=300, bbox_inches="tight")
plt.close()
print("Saved:", fig_3_path)


# ==============================================================================
# Graph 4: Figure 8.4.4: Detection Accuracy Across Different Payload Lengths
# ==============================================================================
fig, ax = plt.subplots(figsize=(8.8, 5.0))
length_data = empirical_data["payload_length_analysis"]
group_labels = [d["group_label"] for d in length_data]
accuracy_vals = [d["accuracy_pct"] for d in length_data]
sample_counts = [d["sample_count"] for d in length_data]

ax.plot(group_labels, accuracy_vals, color="#059669", linestyle="-", marker="D", linewidth=2.8, markersize=8.5, label="DeepWAF-XAI (Empirical Test Accuracy)")

# Data labels with sample counts
for i, (grp, acc, cnt) in enumerate(zip(group_labels, accuracy_vals, sample_counts)):
    ax.annotate(f"{acc:.2f}%\n(n={cnt})", (grp, acc), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=8, fontweight="bold", color="#047857")

# Overall accuracy baseline reference line
ax.axhline(empirical_data["overall_accuracy_pct"], color="#2563EB", linestyle=":", linewidth=1.6, label=f"Overall Held-Out Test Accuracy ({empirical_data['overall_accuracy_pct']}%)")

ax.set_ylim(50, 105)
ax.yaxis.set_major_formatter(mtick.PercentFormatter())
ax.set_xlabel("Payload Length Group (Characters)", fontweight="bold", labelpad=8)
ax.set_ylabel("Detection Accuracy (%)", fontweight="bold", labelpad=8)
ax.set_title("Figure 8.4.4: Detection Accuracy Across Different Payload Lengths", fontweight="bold", pad=14)
ax.grid(True)
ax.legend(loc="lower left", framealpha=0.96, edgecolor="#CBD5E1", fontsize=9.5)

plt.tight_layout()
fig_4_path = os.path.join(GRAPHS_DIR, "fig_8_4_4_accuracy_by_payload_length.png")
plt.savefig(fig_4_path, dpi=300, bbox_inches="tight")
plt.close()
print("Saved:", fig_4_path)

print("\nAll 4 line graphs generated and saved successfully!")
