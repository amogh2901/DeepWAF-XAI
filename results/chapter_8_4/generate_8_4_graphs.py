import json, os, warnings
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as mtick
import seaborn as sns
warnings.filterwarnings("ignore")

OUTPUT_DIR = "results/chapter_8_3"
r  = json.load(open("results/chapter_8_3/results.json"))
PC = r["per_class"]
H  = r["training_history"]
CM = np.array(r["confusion_matrix"])
L  = r["latency"]
CLASSES = r["classes"]

BASE = {"figure.dpi":200,"font.family":"DejaVu Sans","font.size":10,"axes.titlesize":12,
        "axes.labelsize":10,"figure.facecolor":"white","axes.facecolor":"white",
        "axes.spines.top":False,"axes.spines.right":False,"axes.grid":True,
        "grid.alpha":0.3,"grid.linestyle":"--","xtick.labelsize":9,"ytick.labelsize":9}
plt.rcParams.update(BASE)

PALETTE = ["#2563EB","#16A34A","#D97706","#DC2626","#7C3AED"]
CLS_LABEL = {"LEGAL":"LEGAL\n(Normal)","PHISHING":"PHISHING\n(Phishing URL)",
             "SHELL":"SHELL\n(Path Traversal)","SQL":"SQL\n(SQL Injection)","XSS":"XSS\n(Cross-Site Scripting)"}
EPOCHS = list(range(1, len(H["accuracy"])+1))

# ── Fig 8.4.1  Training Accuracy Curve ───────────────────────────────────────
fig, ax = plt.subplots(figsize=(9,5))
ax.plot(EPOCHS, [v*100 for v in H["accuracy"]],     "b-o",  ms=6, lw=2, label="Training Accuracy")
ax.plot(EPOCHS, [v*100 for v in H["val_accuracy"]], "r--s", ms=6, lw=2, label="Validation Accuracy")
ta = round(r["overall_accuracy"]*100, 2)
ax.axhline(ta, color="gray", ls=":", lw=1.4, label=f"Test Accuracy ({ta}%)")
for ep,tv,vv in zip(EPOCHS,[v*100 for v in H["accuracy"]],[v*100 for v in H["val_accuracy"]]):
    ax.annotate(f"{tv:.1f}", (ep,tv), textcoords="offset points", xytext=(0,6),  ha="center", fontsize=7, color="#2563EB")
    ax.annotate(f"{vv:.1f}", (ep,vv), textcoords="offset points", xytext=(0,-13),ha="center", fontsize=7, color="#DC2626")
ax.set_xlim(0.5,10.5); ax.set_ylim(82,102); ax.set_xticks(EPOCHS)
ax.yaxis.set_major_formatter(mtick.PercentFormatter())
ax.set_xlabel("Epoch"); ax.set_ylabel("Accuracy (%)")
ax.set_title("Figure 8.4.1 — Training vs Validation Accuracy Over 10 Epochs")
ax.legend(loc="lower right", fontsize=9)
ax.fill_between(EPOCHS,[v*100 for v in H["accuracy"]],[v*100 for v in H["val_accuracy"]],alpha=0.08,color="gray")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_8_4_1_accuracy_curve.png", dpi=200, bbox_inches="tight")
plt.close(); print("Fig 8.4.1 saved")

# ── Fig 8.4.2  Training Loss Curve ───────────────────────────────────────────
fig, ax = plt.subplots(figsize=(9,5))
ax.plot(EPOCHS, H["loss"],     "b-o",  ms=6, lw=2, label="Training Loss")
ax.plot(EPOCHS, H["val_loss"], "r--s", ms=6, lw=2, label="Validation Loss")
for ep,tl,vl in zip(EPOCHS, H["loss"], H["val_loss"]):
    ax.annotate(f"{tl:.3f}", (ep,tl), textcoords="offset points", xytext=(0,7),  ha="center", fontsize=7, color="#2563EB")
    ax.annotate(f"{vl:.3f}", (ep,vl), textcoords="offset points", xytext=(0,-13),ha="center", fontsize=7, color="#DC2626")
ax.set_xlim(0.5,10.5); ax.set_ylim(-0.02,0.65); ax.set_xticks(EPOCHS)
ax.set_xlabel("Epoch"); ax.set_ylabel("Loss (Categorical Cross-Entropy)")
ax.set_title("Figure 8.4.2 — Training vs Validation Loss Over 10 Epochs")
ax.legend(loc="upper right", fontsize=9)
ax.fill_between(EPOCHS, H["loss"], H["val_loss"], alpha=0.07, color="#7C3AED")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_8_4_2_loss_curve.png", dpi=200, bbox_inches="tight")
plt.close(); print("Fig 8.4.2 saved")

# ── Fig 8.4.3  Dataset Class Distribution ────────────────────────────────────
cls_support = {c: PC[c]["support"] for c in CLASSES}
full_dist   = {"LEGAL":182896,"XSS":7891,"PHISHING":5000,"SQL":1650,"SHELL":319}
cls_order   = ["LEGAL","XSS","PHISHING","SQL","SHELL"]
full_vals   = [full_dist[c] for c in cls_order]
test_vals   = [cls_support[c] for c in cls_order]
cols5 = ["#2563EB","#7C3AED","#16A34A","#D97706","#DC2626"]

fig, (ax1,ax2) = plt.subplots(1,2,figsize=(12,5))
wedges,_,atext = ax1.pie(full_vals, labels=None, autopct="%1.1f%%", colors=cols5, startangle=90,
                          pctdistance=0.82, wedgeprops=dict(width=0.55))
ax1.legend(wedges, [f"{c} ({v:,})" for c,v in zip(cls_order,full_vals)],
           loc="lower center", bbox_to_anchor=(0.5,-0.18), ncol=2, fontsize=8)
ax1.set_title("Training Dataset Distribution\n(197,756 total samples)", fontsize=11)

bars2 = ax2.bar([CLS_LABEL[c] for c in cls_order], test_vals, color=cols5, zorder=3, width=0.6)
for b in bars2:
    ax2.text(b.get_x()+b.get_width()/2, b.get_height()+80, f"{int(b.get_height()):,}",
             ha="center", fontsize=9, fontweight="bold")
ax2.set_ylim(0, max(test_vals)*1.2); ax2.set_ylabel("Number of Test Samples")
ax2.set_title("Test Set Class Distribution\n(19,776 total samples)", fontsize=11)
ax2.set_xticklabels([CLS_LABEL[c] for c in cls_order], fontsize=8)
fig.suptitle("Figure 8.4.3 — Dataset Class Distribution: Full Dataset vs Test Split", fontsize=12, y=1.01)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_8_4_3_class_distribution.png", dpi=200, bbox_inches="tight")
plt.close(); print("Fig 8.4.3 saved")

# ── Fig 8.4.4  Correct vs Incorrect per class ────────────────────────────────
correct_per_class   = [CM[i,i] for i in range(len(CLASSES))]
incorrect_per_class = [PC[c]["support"] - CM[i,i] for i,c in enumerate(CLASSES)]
x = np.arange(len(CLASSES)); w = 0.38
fig, ax = plt.subplots(figsize=(10,5))
b1 = ax.bar(x-w/2, correct_per_class,   w, label="Correctly Classified",   color="#16A34A", zorder=3)
b2 = ax.bar(x+w/2, incorrect_per_class, w, label="Incorrectly Classified", color="#DC2626", zorder=3)
for b in b1:
    ax.text(b.get_x()+b.get_width()/2, b.get_height()+20, f"{int(b.get_height()):,}", ha="center", fontsize=8, color="#16A34A", fontweight="bold")
for b in b2:
    ax.text(b.get_x()+b.get_width()/2, b.get_height()+20, f"{int(b.get_height()):,}", ha="center", fontsize=8, color="#DC2626", fontweight="bold")
for i,c in enumerate(CLASSES):
    acc_c = CM[i,i] / PC[c]["support"] * 100
    ax.text(i-w/2, CM[i,i]/2, f"{acc_c:.1f}%", ha="center", va="center", fontsize=8, color="white", fontweight="bold")
ax.set_xticks(x); ax.set_xticklabels([CLS_LABEL[c] for c in CLASSES], fontsize=9)
ax.set_ylabel("Number of Samples")
ax.set_title("Figure 8.4.4 — Correct vs Incorrect Predictions per Attack Class\n(Held-out Test Set, n=19,776)")
ax.legend(fontsize=9); ax.set_ylim(0, max(correct_per_class)*1.18)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_8_4_4_correct_incorrect.png", dpi=200, bbox_inches="tight")
plt.close(); print("Fig 8.4.4 saved")

# ── Fig 8.4.5  Precision vs Recall Scatter with F1 iso-lines ─────────────────
fig, ax = plt.subplots(figsize=(7,6))
for i,(c,col) in enumerate(zip(CLASSES, PALETTE)):
    p = PC[c]["precision"]; re = PC[c]["recall"]; f1 = PC[c]["f1_score"]
    ax.scatter(re, p, s=320, color=col, zorder=5, edgecolors="black", linewidth=0.9, label=f"{c} (F1={f1:.2f})")
    ax.annotate(c, (re,p), textcoords="offset points", xytext=(10,5), fontsize=9, color=col, fontweight="bold")
for f1_t in [0.3, 0.5, 0.7, 0.9]:
    rv = np.linspace(0.01, 1.0, 300)
    pv = f1_t*rv / (2*rv - f1_t); pv = np.clip(pv,0,1)
    mask = (pv >= 0) & (pv <= 1) & (2*rv - f1_t > 0)
    ax.plot(rv[mask], pv[mask], "k:", linewidth=0.8, alpha=0.35)
    idx = np.argmin(np.abs(rv - 0.65))
    if 0 <= pv[idx] <= 1: ax.text(rv[idx], pv[idx]+0.015, f"F1={f1_t}", fontsize=7.5, color="gray")
ax.set_xlim(-0.02,1.12); ax.set_ylim(-0.02,1.12)
ax.set_xlabel("Recall", fontsize=11); ax.set_ylabel("Precision", fontsize=11)
ax.set_title("Figure 8.4.5 — Precision vs Recall Scatter Plot\n(with F1 Iso-lines; each point = one attack class)")
ax.legend(loc="lower left", fontsize=9)
ax.axhline(0.5, color="#e5e7eb", lw=0.8); ax.axvline(0.5, color="#e5e7eb", lw=0.8)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_8_4_5_precision_recall_scatter.png", dpi=200, bbox_inches="tight")
plt.close(); print("Fig 8.4.5 saved")

# ── Fig 8.4.6  Radar Chart ────────────────────────────────────────────────────
labels_r = [CLS_LABEL[c].replace("\n"," ") for c in CLASSES]
data_r   = np.array([[PC[c]["precision"], PC[c]["recall"], PC[c]["f1_score"]] for c in CLASSES])
angles   = np.linspace(0, 2*np.pi, len(CLASSES), endpoint=False).tolist()
angles  += angles[:1]

fig, axes = plt.subplots(1,3, figsize=(13,5), subplot_kw=dict(polar=True))
for ax_idx,(mn,col) in enumerate(zip(["Precision","Recall","F1-Score"],["#2563EB","#16A34A","#D97706"])):
    ax = axes[ax_idx]
    vals = data_r[:,ax_idx].tolist(); vals += vals[:1]
    ax.fill(angles, vals, alpha=0.25, color=col)
    ax.plot(angles, vals, "o-", color=col, lw=2, markersize=5)
    ax.set_thetagrids(np.degrees(angles[:-1]), labels_r, fontsize=7.5)
    ax.set_ylim(0,1.05); ax.set_yticks([0.25,0.5,0.75,1.0])
    ax.set_yticklabels(["0.25","0.50","0.75","1.00"], fontsize=7, color="gray")
    ax.set_title(mn, pad=15, fontsize=11, color=col, fontweight="bold"); ax.grid(True, alpha=0.3)
    for angle,val in zip(angles[:-1], vals[:-1]):
        ax.annotate(f"{val:.2f}", xy=(angle,val), xytext=(angle, min(val+0.1, 1.05)),
                    ha="center", fontsize=7.5, color=col, fontweight="bold")
fig.suptitle("Figure 8.4.6 — Radar Chart: Per-Class Precision, Recall, F1-Score", fontsize=12, y=1.02)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_8_4_6_radar_chart.png", dpi=200, bbox_inches="tight")
plt.close(); print("Fig 8.4.6 saved")

# ── Fig 8.4.7  Latency Analysis ───────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(10,5))
cats = ["Mean","Median","P95","P99"]
pred = [L["pred_mean_ms"], L["pred_median_ms"], L["pred_p95_ms"], L["pred_p99_ms"]]
e2e  = [L["e2e_mean_ms"],  L["e2e_median_ms"],  L["e2e_p95_ms"],  L["e2e_p99_ms"]]
x = np.arange(len(cats)); w = 0.3
b1 = ax.bar(x-w/2, pred, w, color="#2563EB", label="Model Inference Latency", zorder=3)
b2 = ax.bar(x+w/2, e2e,  w, color="#DC2626", label="End-to-End Request Latency", zorder=3)
for b in b1: ax.text(b.get_x()+b.get_width()/2, b.get_height()+1.5, f"{b.get_height():.1f}ms", ha="center", fontsize=9, color="#2563EB", fontweight="bold")
for b in b2: ax.text(b.get_x()+b.get_width()/2, b.get_height()+1.5, f"{b.get_height():.1f}ms", ha="center", fontsize=9, color="#DC2626", fontweight="bold")
ax.set_xticks(x); ax.set_xticklabels(cats)
ax.set_ylabel("Latency (ms)"); ax.set_ylim(0, 145)
ax.axhline(100, color="orange", ls="--", lw=1.2, alpha=0.7, label="100 ms reference")
ax.set_title("Figure 8.4.7 — Request Processing Latency Analysis\n(n=200 requests, CPU-only, Windows 11, TF 2.21.0)")
ax.legend(fontsize=9)
ax.axhspan(0,   50,  alpha=0.04, color="green")
ax.axhspan(50,  100, alpha=0.04, color="orange")
ax.axhspan(100, 145, alpha=0.04, color="red")
ax.text(3.52,20,  "Fast (<50ms)",          fontsize=7.5, color="green",  alpha=0.8, ha="center")
ax.text(3.52,70,  "Acceptable\n(50-100ms)",fontsize=7.5, color="darkorange",alpha=0.8, ha="center")
ax.text(3.52,118, "High (>100ms)",         fontsize=7.5, color="red",    alpha=0.8, ha="center")
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_8_4_7_latency_analysis.png", dpi=200, bbox_inches="tight")
plt.close(); print("Fig 8.4.7 saved")

# ── Fig 8.4.8  Metric Summary Heatmap ────────────────────────────────────────
mn   = ["Accuracy","Precision","Recall","F1-Score"]
wv   = [r["overall_accuracy"], r["weighted_precision"], r["weighted_recall"], r["weighted_f1"]]
mv   = [r["overall_accuracy"], r["macro_precision"],    r["macro_recall"],    r["macro_f1"]]
heat = np.array([wv, mv])
fig, ax = plt.subplots(figsize=(9,3.2))
im = ax.imshow(heat, cmap="RdYlGn", vmin=0.0, vmax=1.0, aspect="auto")
ax.set_xticks(range(4)); ax.set_xticklabels(mn, fontsize=11)
ax.set_yticks([0,1]);    ax.set_yticklabels(["Weighted Average","Macro Average"], fontsize=11)
for i in range(2):
    for j in range(4):
        val = heat[i,j]; tc = "white" if val < 0.45 else "black"
        ax.text(j, i, f"{val*100:.2f}%", ha="center", va="center", fontsize=14, color=tc, fontweight="bold")
cbar = plt.colorbar(im, ax=ax, orientation="vertical", fraction=0.03, pad=0.04)
cbar.set_label("Score", fontsize=9)
ax.set_title("Figure 8.4.8 — Weighted vs Macro Metrics Summary Heatmap\n(Green = Strong | Red = Weak due to class imbalance)", pad=10)
plt.tight_layout()
plt.savefig(f"{OUTPUT_DIR}/fig_8_4_8_metric_heatmap.png", dpi=200, bbox_inches="tight")
plt.close(); print("Fig 8.4.8 saved")

print("\nAll 8 Chapter 8.4 figures saved.")
