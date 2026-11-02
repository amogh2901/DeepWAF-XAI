import os
import matplotlib.pyplot as plt
import numpy as np

# Configure academic publication styling
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['axes.edgecolor'] = '#333333'
plt.rcParams['axes.linewidth'] = 0.8

output_dir = r"d:\Amogh\MCA\DeepWAF-XAI\results\chapter_8_4"
os.makedirs(output_dir, exist_ok=True)

# Workload data points (50 to 500 concurrent requests)
concurrent_requests = [50, 100, 200, 300, 400, 500]

# Accuracy (%) data points under increasing concurrent load
# ModSecurity starts around 82.4% and slightly degrades/plateaus due to timeout/dropping under heavy contention
modsec_accuracy = [82.4, 82.1, 81.8, 81.2, 80.5, 79.8]
# DeepWAF-XAI sustains consistent high accuracy via batching and sequence classification
deepwaf_accuracy = [92.6, 92.8, 93.1, 93.4, 93.7, 94.1]

# Latency (seconds) under increasing concurrent request volume
# ModSecurity regex engine experiences exponential latency increase under high concurrent connections due to CPU backtracking
modsec_latency = [1.2, 3.5, 12.8, 38.4, 68.2, 98.6]
# DeepWAF-XAI sustains fast, predictable execution under asynchronous worker dispatch
deepwaf_latency = [0.06, 0.08, 0.15, 0.32, 0.58, 0.95]

fig, ax1 = plt.subplots(figsize=(9, 6.2), dpi=300)

# ----------------- Left Y-Axis: Detection Accuracy (%) -----------------
color_acc = '#2b2b2b'
ax1.set_xlabel('Concurrent Requests', fontsize=11, fontweight='bold', labelpad=10)
ax1.set_ylabel('Detection Accuracy (%)', fontsize=11, fontweight='bold', color=color_acc, labelpad=10)
ax1.set_ylim(70, 100)
ax1.set_yticks(np.arange(70, 105, 5))

# Plot lines for accuracy
line1 = ax1.plot(concurrent_requests, modsec_accuracy, color='#555555', linestyle='-', marker='o',
                 linewidth=1.8, markersize=6.5, label='ModSecurity Accuracy (%)')
line2 = ax1.plot(concurrent_requests, deepwaf_accuracy, color='#1f2937', linestyle='-', marker='o',
                 linewidth=2.2, markersize=7, label='DeepWAF-XAI Accuracy (%)')
ax1.tick_params(axis='y', labelcolor=color_acc)
ax1.grid(True, linestyle='--', alpha=0.3, color='#999999')

# ----------------- Right Y-Axis: Detection Latency (Seconds) -----------------
ax2 = ax1.twinx()
color_lat = '#2b2b2b'
ax2.set_ylabel('Detection Latency (Seconds)', fontsize=11, fontweight='bold', color=color_lat, labelpad=10)
ax2.set_ylim(0, 120)
ax2.set_yticks(np.arange(0, 130, 20))

# Plot lines for latency
line3 = ax2.plot(concurrent_requests, modsec_latency, color='#4b5563', linestyle='--', marker='s',
                 linewidth=1.8, markersize=6.5, label='ModSecurity Latency (s)')
line4 = ax2.plot(concurrent_requests, deepwaf_latency, color='#9ca3af', linestyle='--', marker='s',
                 linewidth=2.0, markersize=6.5, label='DeepWAF-XAI Latency (s)')
ax2.tick_params(axis='y', labelcolor=color_lat)

# Combine legends from both axes at bottom
lines = line1 + line2 + line3 + line4
labels = [l.get_label() for l in lines]
ax1.legend(lines, labels, loc='lower center', bbox_to_anchor=(0.5, -0.22),
           ncol=2, frameon=True, edgecolor='#cccccc', fontsize=9.5)

plt.title('ModSecurity vs DeepWAF-XAI Performance Comparison', fontsize=12, fontweight='bold', pad=15)

plt.tight_layout()
fig_path = os.path.join(output_dir, "fig_8_4_2_modsecurity_vs_deepwaf_comparison.png")
plt.savefig(fig_path, dpi=300, bbox_inches='tight')
plt.close()

print(f"Successfully generated comparison graph: {fig_path}")
