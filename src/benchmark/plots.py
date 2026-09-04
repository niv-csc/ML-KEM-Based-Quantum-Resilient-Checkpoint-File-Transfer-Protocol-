"""
Regenerates Fig. 3 (completion time, redundant data, checkpoint-interval
trade-off) and Fig. 4 (goodput, transfer efficiency, completion-time
reduction) from the paper, using the closed-form model in
`src.protocol.model`.

Run as: python -m src.benchmark.plots
Output: results/fig3_completion_redundant_interval.png
        results/fig4_goodput_efficiency_reduction.png
"""

from __future__ import annotations

import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from src.protocol.model import compute_metrics, checkpoint_overhead_seconds, optimal_interval
from src.channel.emulator import PROFILES, CHUNK_BYTES, FILE_BYTES, CHECKPOINT_FSYNC_S

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))
DISRUPTIONS = list(range(0, 11))


def figure3():
    fig, axes = plt.subplots(1, 3, figsize=(15, 4))

    # (a) completion time, 6G and 5G, baseline vs proposed
    ax = axes[0]
    for gen, style in (("6G", "-"), ("5G", "--")):
        for arm, marker in (("baseline", "o"), ("proposed", "s")):
            ys = [compute_metrics(gen, arm, nd).completion_time_s for nd in DISRUPTIONS]
            ax.plot(DISRUPTIONS, ys, style, marker=marker, markersize=4,
                    label=f"{'Baseline' if arm=='baseline' else 'Proposed'} restart ({PROFILES[gen].name})")
    ax.set_xlabel("(a) Number of link disruptions")
    ax.set_ylabel("Completion time (s)")
    ax.legend(fontsize=7)
    ax.grid(alpha=0.3)

    # (b) redundant data re-sent, log scale
    ax = axes[1]
    width = 0.35
    x = [nd for nd in DISRUPTIONS]
    baseline_vals = [max(compute_metrics("6G", "baseline", nd).redundant_data_MB, 1e-3) for nd in DISRUPTIONS]
    proposed_vals = [max(compute_metrics("6G", "proposed", nd).redundant_data_MB, 1e-3) for nd in DISRUPTIONS]
    ax.bar([xi - width / 2 for xi in x], baseline_vals, width, label="Baseline", color="black")
    ax.bar([xi + width / 2 for xi in x], proposed_vals, width, label="Proposed", color="gray")
    ax.set_yscale("log")
    ax.set_xlabel("(b) Number of link disruptions")
    ax.set_ylabel("Redundant data re-sent (MB)")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3, which="both")

    # (c) checkpoint overhead vs N
    ax = axes[2]
    Ns = [2 ** k for k in range(1, 11)]  # 2..1024
    overhead_ms = [checkpoint_overhead_seconds(FILE_BYTES, CHUNK_BYTES, N, CHECKPOINT_FSYNC_S) * 1000
                   for N in Ns]
    ax.plot(Ns, overhead_ms, "-o", markersize=3, color="tab:blue")
    n_star = optimal_interval(FILE_BYTES, CHUNK_BYTES, PROFILES["6G"].link_rate_bps, CHECKPOINT_FSYNC_S, 5)
    ax.axvline(n_star, color="red", linestyle="--", label=f"N* ≈ {n_star:.0f}")
    ax.set_xscale("log")
    ax.set_xlabel("(c) Checkpoint interval N")
    ax.set_ylabel("Checkpoint overhead (ms)")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3, which="both")

    fig.tight_layout()
    path = os.path.join(RESULTS_DIR, "fig3_completion_redundant_interval.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def figure4():
    fig, axes = plt.subplots(1, 3, figsize=(15, 4))

    # (a) effective goodput at 5 disruptions, grouped bar per generation
    ax = axes[0]
    gens = list(PROFILES.keys())
    baseline_gp = [compute_metrics(g, "baseline", 5).goodput_MBps for g in gens]
    proposed_gp = [compute_metrics(g, "proposed", 5).goodput_MBps for g in gens]
    x = range(len(gens))
    width = 0.35
    ax.bar([xi - width / 2 for xi in x], baseline_gp, width, label="Baseline restart", color="black")
    ax.bar([xi + width / 2 for xi in x], proposed_gp, width, label="Proposed checkpoint", color="gray")
    ax.set_xticks(list(x))
    ax.set_xticklabels([PROFILES[g].name for g in gens])
    ax.set_ylabel("Goodput (MB/s)")
    ax.set_xlabel("(a) Effective goodput at 5 disruptions")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3, axis="y")

    # (b) transfer efficiency, rate-invariant
    ax = axes[1]
    baseline_eff = [compute_metrics("6G", "baseline", nd).transfer_efficiency * 100 for nd in DISRUPTIONS]
    proposed_eff = [compute_metrics("6G", "proposed", nd).transfer_efficiency * 100 for nd in DISRUPTIONS]
    ax.plot(DISRUPTIONS, baseline_eff, "-o", markersize=4, color="black", label="Baseline restart")
    ax.plot(DISRUPTIONS, proposed_eff, "-o", markersize=4, color="gray", label="Proposed checkpoint")
    ax.set_xlabel("(b) Number of link disruptions")
    ax.set_ylabel("Transfer efficiency (%)")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)

    # (c) completion-time reduction across generations
    ax = axes[2]
    for gen, marker in zip(gens, ("^", "D", "o")):
        ys = []
        for nd in DISRUPTIONS:
            b = compute_metrics(gen, "baseline", nd).completion_time_s
            p = compute_metrics(gen, "proposed", nd).completion_time_s
            ys.append((b - p) / b * 100 if b else 0.0)
        ax.plot(DISRUPTIONS, ys, "-", marker=marker, markersize=4, label=PROFILES[gen].name)
    ax.axhline(0, color="k", linewidth=0.7)
    ax.set_xlabel("(c) Number of link disruptions")
    ax.set_ylabel("Completion-time reduction (%)")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)

    fig.tight_layout()
    path = os.path.join(RESULTS_DIR, "fig4_goodput_efficiency_reduction.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


if __name__ == "__main__":
    os.makedirs(RESULTS_DIR, exist_ok=True)
    p3 = figure3()
    p4 = figure4()
    print(f"Saved {p3}")
    print(f"Saved {p4}")
