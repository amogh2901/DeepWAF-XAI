"""
DeepWAF-XAI — Chapter 8.4 Black Book Graph Generator
=====================================================
Generates the 5 required figures matching the user's specific Black Book structure:
8.4.1 Bar Chart — Comparison of Test Cases by Module
8.4.2 Pie Chart — Distribution of Passed and Failed Test Cases
8.4.3 Line Graph — Training and Validation Performance (Accuracy & Loss)
8.4.4 Bar Chart — Performance of Attack Classification (5 Classes)
8.4.5 Bar Chart — Comparison of Detection Metrics (Measured vs Reported Baselines)
"""

import json
import os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick

OUTPUT_DIR = "results/chapter_8_4"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Load actual measured results
res_json_path = "results/chapter_8_3/results.json"
with open(res_json_path, "r", encoding="utf-8") as f:
    res = json.load(f)

# Load actual executed test case results
mod_json_path = "results/chapter_8_4/module_test_results.json"
with open(mod_json_path, "r", encoding="utf-8") as f:
    mod_res = json.load(f)

# Matplotlib global styling
plt.rcParams.update({
    "figure.dpi": 200,
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.titlesize": 12,
    "axes.labelsize": 10,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.alpha": 0.25,
    "grid.linestyle": "--",
    "xtick.labelsize": 9,
    "ytick.labelsize": 9
})

# ==============================================================================
# 8.4.1 Bar Chart — Comparison of Test Cases by Module
# ==============================================================================
modules_data = mod_res["modules"]
module_names = [
    "User Authentication",
    "Attack Detection",
    "XAI & Threat Analysis",
    "Threat Scoring",
    "Response & Quarantine",
    "WAF & Rate Limiting",
    "Database Firewall",
    "Security Logging"
]

# Map names to keys in module_test_results.json
key_map = {
    "User Authentication": "User Authentication",
    "Attack Detection": "Attack Detection",
    "XAI & Threat Analysis": "XAI and Threat Analysis",
    "Threat Scoring": "Threat Scoring",
    "Response & Quarantine": "Intelligent Response and Quarantine",
    "WAF & Rate Limiting": "WAF and Rate Limiting",
    "Database Firewall": "Database Firewall",
    "Security Logging": "Security Logging"
}

passed_counts = [modules_data[key_map[m]]["passed"] for m in module_names]
failed_counts = [modules_data[key_map[m]]["failed"] for m in module_names]

fig, ax = plt.subplots(figsize=(11, 5.5))
x = np.arange(len(module_names))
width = 0.38

bars_pass = ax.bar(x - width/2, passed_counts, width, label="Passed Test Cases", color="#16A34A", edgecolor="#15803D", linewidth=1.2, zorder=3)
bars_fail = ax.bar(x + width/2, failed_counts, width, label="Failed Test Cases", color="#DC2626", edgecolor="#B91C1C", linewidth=1.2, zorder=3)

# Data labels
for b in bars_pass:
    h = b.get_height()
    ax.text(b.get_x() + b.get_width()/2, h + 0.15, f"{int(h)}", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#15803D")

for b in bars_fail:
    h = b.get_height()
    ax.text(b.get_x() + b.get_width()/2, h + 0.15, f"{int(h)}", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#B91C1C")

ax.set_xticks(x)
ax.set_xticklabels(module_names, rotation=20, ha="right", fontsize=9.5)
ax.set_ylabel("Number of Test Cases", fontsize=11)
ax.set_ylim(0, 8.2)
ax.set_yticks(range(0, 9))
ax.set_title("Figure 8.4.1 — Comparison of Executed Test Cases by Module (Pass vs Fail)", pad=14, fontsize=12, fontweight="bold")
ax.legend(loc="upper right", framealpha=0.95, fontsize=9.5)

plt.tight_layout()
fig_8_4_1_path = os.path.join(OUTPUT_DIR, "fig_8_4_1_test_cases_by_module.png")
plt.savefig(fig_8_4_1_path, dpi=200, bbox_inches="tight")
plt.close()
print("Saved:", fig_8_4_1_path)


# ==============================================================================
# 8.4.2 Pie Chart — Distribution of Passed and Failed Test Cases
# ==============================================================================
total_exec = mod_res["total_executed"]
total_pass = mod_res["total_passed"]
total_fail = mod_res["total_failed"]

fig, ax = plt.subplots(figsize=(7.5, 6))

if total_fail == 0:
    # 100% Passed
    colors = ["#16A34A"]
    wedges, texts, autotexts = ax.pie(
        [total_pass],
        labels=["Passed Test Cases"],
        autopct="%1.1f%%",
        colors=colors,
        startangle=90,
        wedgeprops=dict(width=0.52, edgecolor="white", linewidth=2.5),
        pctdistance=0.74,
        textprops=dict(fontsize=11, fontweight="bold")
    )
    plt.setp(autotexts, size=15, weight="bold", color="white")
    ax.text(0, 0, f"Total\n{total_exec}\nTests\n100% Pass", ha="center", va="center", fontsize=12, fontweight="bold", color="#15803D")
else:
    colors = ["#16A34A", "#DC2626"]
    wedges, texts, autotexts = ax.pie(
        [total_pass, total_fail],
        labels=["Passed Test Cases", "Failed Test Cases"],
        autopct="%1.1f%%",
        colors=colors,
        startangle=90,
        wedgeprops=dict(width=0.52, edgecolor="white", linewidth=2.5),
        pctdistance=0.74,
        textprops=dict(fontsize=11, fontweight="bold")
    )
    plt.setp(autotexts, size=13, weight="bold", color="white")
    ax.text(0, 0, f"Total\n{total_exec}\nTests", ha="center", va="center", fontsize=12, fontweight="bold", color="#1F2937")

ax.set_title(f"Figure 8.4.2 — System Testing Pass vs Fail Distribution\n(Total Executed Test Cases = {total_exec})", pad=16, fontsize=12, fontweight="bold")
ax.legend(
    [f"Passed: {total_pass} ({total_pass/total_exec*100:.1f}%)", f"Failed: {total_fail} ({total_fail/total_exec*100:.1f}%)"],
    loc="lower center",
    bbox_to_anchor=(0.5, -0.1),
    ncol=2,
    fontsize=9.5
)

plt.tight_layout()
fig_8_4_2_path = os.path.join(OUTPUT_DIR, "fig_8_4_2_passed_failed_distribution.png")
plt.savefig(fig_8_4_2_path, dpi=200, bbox_inches="tight")
plt.close()
print("Saved:", fig_8_4_2_path)


# ==============================================================================
# 8.4.3 Line Graph — Training and Validation Performance (Dual Panels)
# ==============================================================================
H = res["training_history"]
epochs = list(range(1, len(H["accuracy"]) + 1))
train_acc = [v * 100 for v in H["accuracy"]]
val_acc = [v * 100 for v in H["val_accuracy"]]
train_loss = H["loss"]
val_loss = H["val_loss"]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

# (a) Accuracy Curve
ax1.plot(epochs, train_acc, "b-o", linewidth=2.2, markersize=6, label="Training Accuracy", color="#2563EB")
ax1.plot(epochs, val_acc, "r--s", linewidth=2.2, markersize=6, label="Validation Accuracy", color="#DC2626")
test_acc_val = round(res["overall_accuracy"] * 100, 2)
ax1.axhline(test_acc_val, color="#059669", linestyle=":", linewidth=1.8, label=f"Held-Out Test ({test_acc_val}%)")

# Annotate points
for ep, ta, va in zip(epochs, train_acc, val_acc):
    ax1.annotate(f"{ta:.1f}%", (ep, ta), textcoords="offset points", xytext=(0, 7), ha="center", fontsize=7.5, color="#2563EB")
    ax1.annotate(f"{va:.1f}%", (ep, va), textcoords="offset points", xytext=(0, -13), ha="center", fontsize=7.5, color="#DC2626")

ax1.set_xlim(0.5, 10.5)
ax1.set_ylim(82, 102)
ax1.set_xticks(epochs)
ax1.yaxis.set_major_formatter(mtick.PercentFormatter())
ax1.set_xlabel("Epoch", fontsize=10.5)
ax1.set_ylabel("Accuracy (%)", fontsize=10.5)
ax1.set_title("(a) Training vs Validation Accuracy", fontsize=11, fontweight="bold")
ax1.legend(loc="lower right", fontsize=8.5)
ax1.fill_between(epochs, train_acc, val_acc, alpha=0.08, color="#2563EB")

# (b) Loss Curve
ax2.plot(epochs, train_loss, "b-o", linewidth=2.2, markersize=6, label="Training Loss", color="#2563EB")
ax2.plot(epochs, val_loss, "r--s", linewidth=2.2, markersize=6, label="Validation Loss", color="#DC2626")
test_loss_val = round(res["test_loss"], 3)
ax2.axhline(test_loss_val, color="#059669", linestyle=":", linewidth=1.8, label=f"Test Loss ({test_loss_val})")

for ep, tl, vl in zip(epochs, train_loss, val_loss):
    ax2.annotate(f"{tl:.2f}", (ep, tl), textcoords="offset points", xytext=(0, 7), ha="center", fontsize=7.5, color="#2563EB")
    ax2.annotate(f"{vl:.2f}", (ep, vl), textcoords="offset points", xytext=(0, -13), ha="center", fontsize=7.5, color="#DC2626")

ax2.set_xlim(0.5, 10.5)
ax2.set_ylim(-0.02, 0.65)
ax2.set_xticks(epochs)
ax2.set_xlabel("Epoch", fontsize=10.5)
ax2.set_ylabel("Sparse Categorical Cross-Entropy Loss", fontsize=10.5)
ax2.set_title("(b) Training vs Validation Loss", fontsize=11, fontweight="bold")
ax2.legend(loc="upper right", fontsize=8.5)
ax2.fill_between(epochs, train_loss, val_loss, alpha=0.08, color="#DC2626")

fig.suptitle("Figure 8.4.3 — Training and Validation Performance Across 10 Epochs", fontsize=13, fontweight="bold", y=1.02)
plt.tight_layout()
fig_8_4_3_path = os.path.join(OUTPUT_DIR, "fig_8_4_3_training_validation_performance.png")
plt.savefig(fig_8_4_3_path, dpi=200, bbox_inches="tight")
plt.close()
print("Saved:", fig_8_4_3_path)


# ==============================================================================
# 8.4.4 Bar Chart — Performance of Attack Classification
# ==============================================================================
# 5 Classes: Normal Traffic, SQL Injection, Cross-Site Scripting (XSS), Path Traversal, Phishing URL
PC = res["per_class"]
class_display_names = [
    "Normal Traffic\n(LEGAL)",
    "SQL Injection\n(SQL)",
    "Cross-Site Scripting\n(XSS)",
    "Path Traversal\n(SHELL)",
    "Phishing URL\n(PHISHING)"
]
class_keys = ["LEGAL", "SQL", "XSS", "SHELL", "PHISHING"]

precisions = [PC[k]["precision"] * 100 for k in class_keys]
recalls = [PC[k]["recall"] * 100 for k in class_keys]
f1_scores = [PC[k]["f1_score"] * 100 for k in class_keys]

fig, ax = plt.subplots(figsize=(11, 5.5))
x = np.arange(len(class_keys))
w = 0.25

b_p = ax.bar(x - w, precisions, w, label="Precision", color="#2563EB", edgecolor="#1D4ED8", linewidth=1.1, zorder=3)
b_r = ax.bar(x, recalls, w, label="Recall", color="#16A34A", edgecolor="#15803D", linewidth=1.1, zorder=3)
b_f = ax.bar(x + w, f1_scores, w, label="F1-Score", color="#D97706", edgecolor="#B45309", linewidth=1.1, zorder=3)

# Add exact value annotations
for b in b_p:
    h = b.get_height()
    ax.text(b.get_x() + b.get_width()/2, h + 1.2, f"{h:.1f}%", ha="center", fontsize=8, fontweight="bold", color="#1D4ED8")

for b in b_r:
    h = b.get_height()
    ax.text(b.get_x() + b.get_width()/2, h + 1.2, f"{h:.1f}%", ha="center", fontsize=8, fontweight="bold", color="#15803D")

for b in b_f:
    h = b.get_height()
    ax.text(b.get_x() + b.get_width()/2, h + 1.2, f"{h:.1f}%", ha="center", fontsize=8, fontweight="bold", color="#B45309")

ax.set_xticks(x)
ax.set_xticklabels(class_display_names, fontsize=9.5)
ax.set_ylabel("Metric Score (%)", fontsize=11)
ax.set_ylim(0, 115)
ax.yaxis.set_major_formatter(mtick.PercentFormatter())
ax.set_title("Figure 8.4.4 — Performance of Attack Classification Across Five Classes\n(Measured on Held-out Test Set, n=19,776)", pad=14, fontsize=12, fontweight="bold")
ax.legend(loc="upper right", framealpha=0.95, fontsize=9.5)

plt.tight_layout()
fig_8_4_4_path = os.path.join(OUTPUT_DIR, "fig_8_4_4_attack_classification_performance.png")
plt.savefig(fig_8_4_4_path, dpi=200, bbox_inches="tight")
plt.close()
print("Saved:", fig_8_4_4_path)


# ==============================================================================
# 8.4.5 Line Graph & Bar Chart — Comparison of Detection Metrics
# ==============================================================================
# Compare Accuracy, Precision, Recall, F1-Score
# Measured results for DeepWAF-XAI vs Reported literature baselines
metric_labels = ["Accuracy", "Precision", "Recall", "F1-Score"]

# DeepWAF-XAI (Measured on held-out test split)
deepwaf_metrics = [
    res["overall_accuracy"] * 100,
    res["weighted_precision"] * 100,
    res["weighted_recall"] * 100,
    res["weighted_f1"] * 100
]

# Published / Reported Baselines from Literature (CSIC-2010 / WAF benchmarks)
traditional_waf = [82.4, 84.1, 79.6, 81.8]   # Signature / Regex-based WAF
ml_baseline = [88.7, 89.2, 86.5, 87.8]       # Feature Engineered ML (SVM / Random Forest)
balnet_baseline = [91.3, 92.0, 90.8, 91.4]   # BALNet / Deep Learning Literature

# 1. Four-Line Graph for Section 8.4.5 (Identical to Figure 8.3.7)
fig_line, ax_line = plt.subplots(figsize=(10, 5.5))
ax_line.plot(metric_labels, traditional_waf, "o--", color="#64748B", linewidth=2.0, markersize=7, label="Traditional Signature-Based WAF (Reported Benchmark)")
ax_line.plot(metric_labels, ml_baseline, "^-.", color="#2563EB", linewidth=2.0, markersize=7, label="Machine Learning Baseline (SVM/RF) (Reported Benchmark)")
ax_line.plot(metric_labels, balnet_baseline, "s:", color="#7C3AED", linewidth=2.2, markersize=8, label="BALNet (Existing Research Paper) (Reported Benchmark)")
ax_line.plot(metric_labels, deepwaf_metrics, "D-", color="#059669", linewidth=3.0, markersize=9, label="DeepWAF-XAI (Our Proposed Project) (Measured Actual)")

# Annotate DeepWAF-XAI data points clearly
for m, val in zip(metric_labels, deepwaf_metrics):
    ax_line.annotate(f"{val:.2f}%", (m, val), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=9, fontweight="bold", color="#047857")

# Annotate other lines for clarity
for m, val in zip(metric_labels, traditional_waf):
    ax_line.annotate(f"{val:.1f}%", (m, val), textcoords="offset points", xytext=(0, -14), ha="center", fontsize=8, color="#475569")

ax_line.set_xlabel("Evaluation Metric", fontsize=11, fontweight="bold", labelpad=8)
ax_line.set_ylabel("Performance (%)", fontsize=11, fontweight="bold", labelpad=8)
ax_line.set_ylim(74, 103)
ax_line.yaxis.set_major_formatter(mtick.PercentFormatter())
ax_line.grid(True, linestyle="--", linewidth=0.7, alpha=0.55, color="#CBD5E1")
ax_line.set_title("Figure 8.4.5 — Four-Line Comparison of Detection Performance Across Systems", pad=14, fontsize=12, fontweight="bold")
ax_line.legend(loc="lower right", framealpha=0.96, fontsize=9, edgecolor="#CBD5E1")

fig_line.text(
    0.5, -0.04,
    "*Disclaimer: DeepWAF-XAI results are measured project evaluation values (n=19,776). Baseline values for Traditional WAF, ML Baseline, and BALNet\nare reported literature benchmarks evaluated on their respective research datasets. Direct cross-system comparison is contextual and indicative.",
    ha="center", fontsize=7.5, style="italic", color="#4B5563"
)

plt.tight_layout()
fig_8_4_5_line_path = os.path.join(OUTPUT_DIR, "fig_8_4_5_system_comparison_line.png")
plt.savefig(fig_8_4_5_line_path, dpi=300, bbox_inches="tight")
plt.close(fig_line)
print("Saved:", fig_8_4_5_line_path)

# 2. Bar Chart comparison (retained for comprehensive analysis)
fig, ax = plt.subplots(figsize=(11, 5.8))
x = np.arange(len(metric_labels))
w = 0.20

b1 = ax.bar(x - 1.5*w, traditional_waf, w, label="Traditional Signature WAF [Reported]", color="#94A3B8", edgecolor="#64748B", linewidth=1.1, zorder=3)
b2 = ax.bar(x - 0.5*w, ml_baseline, w, label="ML Baseline (SVM/RF) [Reported]", color="#60A5FA", edgecolor="#3B82F6", linewidth=1.1, zorder=3)
b3 = ax.bar(x + 0.5*w, balnet_baseline, w, label="BALNet (Literature) [Reported]", color="#A78BFA", edgecolor="#8B5CF6", linewidth=1.1, zorder=3)
b4 = ax.bar(x + 1.5*w, deepwaf_metrics, w, label="DeepWAF-XAI [Measured Actual]", color="#059669", edgecolor="#047857", linewidth=1.3, zorder=3)

# Data labels on DeepWAF-XAI and BALNet
for b in b4:
    h = b.get_height()
    ax.text(b.get_x() + b.get_width()/2, h + 1.2, f"{h:.1f}%", ha="center", fontsize=8.5, fontweight="bold", color="#047857")

for b in b3:
    h = b.get_height()
    ax.text(b.get_x() + b.get_width()/2, h + 1.2, f"{h:.1f}%", ha="center", fontsize=7.5, color="#7C3AED")

for b in b2:
    h = b.get_height()
    ax.text(b.get_x() + b.get_width()/2, h + 1.2, f"{h:.1f}%", ha="center", fontsize=7.5, color="#2563EB")

for b in b1:
    h = b.get_height()
    ax.text(b.get_x() + b.get_width()/2, h + 1.2, f"{h:.1f}%", ha="center", fontsize=7.5, color="#475569")

ax.set_xticks(x)
ax.set_xticklabels(metric_labels, fontsize=11, fontweight="bold")
ax.set_ylabel("Metric Score (%)", fontsize=11)
ax.set_ylim(65, 105)
ax.yaxis.set_major_formatter(mtick.PercentFormatter())
ax.set_title("Figure 8.4.5B — Bar Chart Comparison of Overall Detection Metrics\n(DeepWAF-XAI Measured vs Reported Literature Baselines)", pad=14, fontsize=12, fontweight="bold")
ax.legend(loc="lower right", framealpha=0.95, fontsize=9)

# Research disclaimer annotation
fig.text(
    0.5, -0.04,
    "*Disclaimer: Baseline figures for Traditional WAF, ML Baseline, and BALNet are reported literature results evaluated on their respective research datasets.\nDirect cross-comparison is indicative; testing conditions and sample distributions differ.",
    ha="center", fontsize=7.5, style="italic", color="#4B5563"
)

plt.tight_layout()
fig_8_4_5_path = os.path.join(OUTPUT_DIR, "fig_8_4_5_detection_metrics_comparison.png")
plt.savefig(fig_8_4_5_path, dpi=200, bbox_inches="tight")
plt.close(fig)
print("Saved:", fig_8_4_5_path)

print("\nAll Black Book Chapter 8.4 graphs successfully generated!")
