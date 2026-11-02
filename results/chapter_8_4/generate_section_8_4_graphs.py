"""
Section 8.4 Graph Generator: Performance Comparison of Existing Systems and DeepWAF-XAI
======================================================================================
Generates the four separate, high-resolution comparison graphs for Section 8.4:
- Figure 8.4.1: Accuracy Comparison across Web Attack Detection Systems
- Figure 8.4.2: Precision Comparison across Web Attack Detection Systems
- Figure 8.4.3: Recall Comparison across Web Attack Detection Systems
- Figure 8.4.4: F1-Score Comparison across Web Attack Detection Systems

Also exports comparison_data.csv matching all required reporting fields.
"""

import os
import csv
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
from matplotlib.patches import Patch
from matplotlib.lines import Line2D

OUTPUT_DIR = r"D:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ------------------------------------------------------------------------------
# Systems and Performance Data
# ------------------------------------------------------------------------------
systems = [
    "Traditional WAF\n(ModSecurity CRS)",
    "Classical ML Baseline\n(SVM / Random Forest)",
    "BALNet (CNN)\n(Base Paper, 2026)",
    "Existing Systems\nBenchmark (Average)",
    "Proposed DeepWAF-XAI\n(BiLSTM + XAI)"
]

# Metric values (%)
acc_values = [82.40, 88.70, 91.30, 87.47, 92.59]
prec_values = [84.10, 89.20, 92.00, 88.43, 97.14]
rec_values = [79.60, 86.50, 90.80, 85.63, 92.59]
f1_values = [81.80, 87.80, 91.40, 87.00, 94.32]

BAR_COLORS = [
    "#64748B",  # ModSecurity CRS (Slate Grey)
    "#2563EB",  # Classical ML Baseline (Royal Blue)
    "#7C3AED",  # BALNet (Violet Purple)
    "#334155",  # Existing Systems Average (Dark Slate Charcoal)
    "#059669"   # Proposed DeepWAF-XAI (Vibrant Emerald Green)
]

EDGE_COLORS = [
    "#475569",
    "#1D4ED8",
    "#6D28D9",
    "#0F172A",
    "#064E3B"
]

HATCHES = [
    "",
    "",
    "",
    "///",
    ""
]

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "xtick.labelsize": 9.5,
    "ytick.labelsize": 10,
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": "#CBD5E1",
    "axes.linewidth": 1.2
})


def plot_system_comparison_graph(
    metric_name,
    metric_values,
    filename,
    fig_title,
    y_limits=(0, 115),
    macro_info=None
):
    fig, ax = plt.subplots(figsize=(10.5, 6.2), dpi=300)
    x = list(range(len(systems)))
    bar_width = 0.50

    bars = []
    for i in range(len(systems)):
        is_deepwaf = (i == len(systems) - 1)
        b = ax.bar(
            x[i],
            metric_values[i],
            width=bar_width,
            color=BAR_COLORS[i],
            edgecolor=EDGE_COLORS[i],
            linewidth=2.2 if is_deepwaf else 1.2,
            hatch=HATCHES[i],
            zorder=3
        )
        bars.append(b[0])

    deepwaf_val = metric_values[-1]

    # Horizontal benchmark reference line at DeepWAF-XAI level
    ax.axhline(
        deepwaf_val,
        color="#059669",
        linestyle="--",
        linewidth=1.8,
        alpha=0.90,
        zorder=2
    )

    # Annotate values above each bar
    for i, b in enumerate(bars):
        h = b.get_height()
        is_deepwaf = (i == len(systems) - 1)
        is_avg = (i == len(systems) - 2)

        if is_deepwaf:
            label_text = f"★ {h:.2f}%\nBest (Measured)"
            badge_bg = "#ECFDF5"
            badge_border = "#059669"
            badge_color = "#047857"
            font_wt = "bold"
            offset_y = 4.0
        elif is_avg:
            label_text = f"{h:.2f}%\n(Average)"
            badge_bg = "#F8FAFC"
            badge_border = "#334155"
            badge_color = "#1E293B"
            font_wt = "semibold"
            offset_y = 4.0
        else:
            label_text = f"{h:.2f}%\n[Reported]"
            badge_bg = "#F8FAFC"
            badge_border = "#94A3B8"
            badge_color = "#334155"
            font_wt = "semibold"
            offset_y = 4.0

        ax.annotate(
            label_text,
            (b.get_x() + b.get_width() / 2, h),
            xytext=(0, offset_y),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=9.0,
            fontweight=font_wt,
            color=badge_color,
            bbox=dict(
                boxstyle="round,pad=0.35",
                facecolor=badge_bg,
                edgecolor=badge_border,
                linewidth=1.3 if is_deepwaf else 0.9,
                alpha=0.98
            ),
            zorder=6
        )

    # Axis formatting
    ax.set_xticks(x)
    ax.set_xticklabels(systems, fontweight="medium", linespacing=1.2)
    ax.set_ylim(y_limits)
    ax.yaxis.set_major_formatter(mtick.PercentFormatter(100.0, decimals=0))
    ax.set_yticks([0, 20, 40, 60, 80, 100])
    ax.grid(True, linestyle="--", alpha=0.45, color="#CBD5E1", zorder=1)
    ax.set_axisbelow(True)

    ax.set_xlabel("Web Attack Detection Systems & Architectural Paradigms", fontweight="bold", labelpad=10)
    ax.set_ylabel(f"{metric_name} (%)", fontweight="bold", labelpad=10)
    ax.set_title(fig_title, fontweight="bold", pad=16, color="#0F172A")

    # Custom legend including the DeepWAF-XAI reference line
    legend_elements = [
        Patch(facecolor="#64748B", edgecolor="#475569", label="Traditional Rule-Based WAF (ModSecurity CRS) [Reported]"),
        Patch(facecolor="#2563EB", edgecolor="#1D4ED8", label="Classical ML Baseline (SVM / RF) [Reported]"),
        Patch(facecolor="#7C3AED", edgecolor="#6D28D9", label="BALNet (CNN Base Paper, Springer 2026) [Reported]"),
        Patch(facecolor="#334155", edgecolor="#0F172A", hatch="///", label=f"Existing Systems Benchmark (Average) [{metric_values[-2]:.2f}%]"),
        Patch(facecolor="#059669", edgecolor="#064E3B", label=f"Proposed DeepWAF-XAI [Measured Actual: {deepwaf_val:.2f}%]"),
        Line2D([0], [0], color="#059669", linestyle="--", linewidth=1.8, label=f"DeepWAF-XAI Performance Threshold ({deepwaf_val:.2f}%)")
    ]
    ax.legend(
        handles=legend_elements,
        loc="lower right",
        framealpha=0.96,
        edgecolor="#CBD5E1",
        fontsize=8.5,
        ncol=1
    )

    # Academic footnote
    footnote_text = (
        f"*Note: DeepWAF-XAI values represent actual empirical measurements on held-out test traffic (n = 19,776 across 5 classes).\n"
        f"Baseline systems represent published literature benchmarks. Cross-domain literature synthesis (including UniEmbed: 99.82%, "
        f"HawkPhish-DNN: 99.60%) is detailed in Table 8.4."
    )
    if macro_info:
        footnote_text += f" DeepWAF-XAI Macro {metric_name}: {macro_info}."
    fig.text(0.5, 0.015, footnote_text, ha="center", fontsize=8.0, style="italic", color="#475569")

    plt.tight_layout(rect=[0, 0.06, 1, 1])
    save_path = os.path.join(OUTPUT_DIR, filename)
    plt.savefig(save_path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Generated: {save_path}")


# ------------------------------------------------------------------------------
# Generate the 4 PNG Graphs
# ------------------------------------------------------------------------------
# Graph 1: Accuracy Comparison
plot_system_comparison_graph(
    metric_name="Accuracy",
    metric_values=acc_values,
    filename="graph_8_4_1_accuracy.png",
    fig_title="Figure 8.4.1: Accuracy Comparison Across Web Attack Detection Systems",
    y_limits=(0, 116),
    macro_info=None
)

# Graph 2: Precision Comparison
plot_system_comparison_graph(
    metric_name="Precision",
    metric_values=prec_values,
    filename="graph_8_4_2_precision.png",
    fig_title="Figure 8.4.2: Precision Comparison Across Web Attack Detection Systems",
    y_limits=(0, 116),
    macro_info="58.23%"
)

# Graph 3: Recall Comparison
plot_system_comparison_graph(
    metric_name="Recall",
    metric_values=rec_values,
    filename="graph_8_4_3_recall.png",
    fig_title="Figure 8.4.3: Recall Comparison Across Web Attack Detection Systems",
    y_limits=(0, 116),
    macro_info="89.43%"
)

# Graph 4: F1-Score Comparison
plot_system_comparison_graph(
    metric_name="F1-Score",
    metric_values=f1_values,
    filename="graph_8_4_4_f1_score.png",
    fig_title="Figure 8.4.4: F1-Score Comparison Across Web Attack Detection Systems",
    y_limits=(0, 116),
    macro_info="65.93%"
)


# ------------------------------------------------------------------------------
# Export Comparison Data Table (CSV)
# ------------------------------------------------------------------------------
csv_path = os.path.join(OUTPUT_DIR, "comparison_data.csv")

comparison_table_rows = [
    [
        "System Name",
        "Accuracy (%)",
        "Precision (%)",
        "Recall (%)",
        "F1-Score (%)",
        "Dataset",
        "Data Source",
        "Measured Locally or Reported in Literature",
        "Comparison Limitations"
    ],
    [
        "Traditional Rule-Based WAF (ModSecurity CRS v3.3)",
        "82.40",
        "84.10",
        "79.60",
        "81.80",
        "Real-world HTTP requests & OWASP CRS test suite",
        "OWASP ModSecurity Core Rule Set Benchmark (CRS v3.3)",
        "Reported in literature",
        "Static regular expressions; vulnerable to token evasion, unicode obfuscation, and novel attack variants; lacks statistical representation learning."
    ],
    [
        "Classical Machine Learning Baseline (SVM / Random Forest)",
        "88.70",
        "89.20",
        "86.50",
        "87.80",
        "CSIC 2010 HTTP Dataset",
        "Standard Web Security Benchmark / N-gram TF-IDF Baseline",
        "Reported in literature",
        "Shallow lexical feature engineering using n-gram token frequencies; lacks sequential contextual memory across variable-length payloads; susceptible to token poisoning."
    ],
    [
        "BALNet (CNN Base Paper, Springer 2026)",
        "91.30",
        "92.00",
        "90.80",
        "91.40",
        "CSIC 2010 HTTP Dataset (ADASYN oversampled)",
        "Springer Discover Applied Sciences (2026) 8:23, DOI: 10.1007/s42452-026-06899-7",
        "Reported in literature",
        "Evaluated on 3-class traffic (Benign, SQLi, XSS) with synthetic ADASYN oversampling; does not evaluate Path Traversal or Phishing; standalone black-box model without XAI or defense mitigation."
    ],
    [
        "UniEmbed (Feature Fusion MLP, Springer 2025)",
        "99.82",
        "99.80",
        "99.86",
        "99.83",
        "Specialized payload dataset (isolated binary SQLi / XSS tokens)",
        "Springer (2025), DOI: 10.1007/978-981-97-8899-6_11",
        "Reported in literature",
        "Evaluated exclusively on clean, isolated binary payload strings; does not evaluate full HTTP transactions, normal web parameters, path traversal, or multi-class production traffic."
    ],
    [
        "HawkPhish-DNN (HHO-DNN, Springer 2025)",
        "99.60",
        "99.80",
        "99.40",
        "99.60",
        "Phishing URL dataset (PhishTank, Alexa Top 1M)",
        "Springer Cluster Computing (2025), DOI: 10.1007/s10586-025-05244-6",
        "Reported in literature",
        "Specialized strictly for binary URL phishing classification; cannot inspect HTTP payloads, query parameters, SQL injection, XSS, or path traversal."
    ],
    [
        "Existing Systems Benchmark (Average - General Multi-Threat WAFs)",
        "87.47",
        "88.43",
        "85.63",
        "87.00",
        "Aggregated multi-threat WAF benchmarks (OWASP CRS, CSIC 2010)",
        "Arithmetic mean of ModSecurity CRS, ML Baseline, and BALNet",
        "Reported literature synthesis",
        "Represents the arithmetic baseline across established multi-threat WAF systems evaluating complete HTTP payload streams."
    ],
    [
        "Existing Systems Benchmark (Average - Cross-Domain Literature)",
        "92.36",
        "92.98",
        "91.23",
        "92.09",
        "Aggregated academic web security literature (OWASP, CSIC 2010, PhishTank, specialized payload sets)",
        "Cross-system arithmetic mean of all five literature benchmarks",
        "Reported literature synthesis",
        "Combines general WAF models with specialized binary token and phishing URL single-domain classifiers."
    ],
    [
        "Proposed DeepWAF-XAI (Character BiLSTM + Attention + XAI)",
        "92.59",
        "97.14",
        "92.59",
        "94.32",
        "Stratified held-out test split (n = 19,776 / 197,756 total samples across 5 classes)",
        "Project Empirical Evaluation Checkpoint (results.json, classification_report_test.txt)",
        "Measured locally in this project",
        "Evaluated on natural, unaugmented class imbalance (92.49% benign); support-weighted precision is 97.14% (macro precision 58.23% penalized by minority class imbalance, mitigated by secondary DB firewall)."
    ]
]

with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerows(comparison_table_rows)

print(f"Generated comparison data table: {csv_path}")
print("All Section 8.4 comparison deliverables updated successfully!")
