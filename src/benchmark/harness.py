"""
Three-arm benchmark harness (Section IV: "classic-restart, ML-KEM-restart,
ML-KEM-checkpoint"). This module drives:

  1. The analytical model (src.protocol.model) across every (generation,
     n_disruptions) pair to reproduce Table 2 and Fig. 3 / Fig. 4.
  2. The live crypto simulator (src.protocol.simulator) on a real, smaller
     in-memory file, to prove the protocol logic (handshake, chunking,
     AEAD, checkpoint, resume, final digest check) actually works, not
     just that the formulas add up.

Run as: python -m src.benchmark.harness
"""

from __future__ import annotations

import csv
import os
import random

from src.protocol.model import compute_metrics
from src.protocol.simulator import run_checkpointed_transfer, run_baseline_transfer
from src.channel.emulator import PROFILES, CHUNK_BYTES, FILE_BYTES, DEFAULT_INTERVAL_N

RESULTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "results"))


def analytical_table(disruption_counts=range(0, 11)) -> list[dict]:
    """Every row needed to draw Fig. 3(a)/(b) and Fig. 4(a)/(b)/(c), and to
    print Table 2 at nd=5 and nd=10."""
    rows = []
    for gen in PROFILES:
        for nd in disruption_counts:
            for arm in ("baseline", "proposed"):
                m = compute_metrics(gen, arm, nd)
                rows.append({
                    "generation": gen, "arm": arm, "n_disruptions": nd,
                    "completion_time_s": round(m.completion_time_s, 3),
                    "goodput_MBps": round(m.goodput_MBps, 2),
                    "redundant_data_MB": round(m.redundant_data_MB, 2),
                    "transfer_efficiency_pct": round(m.transfer_efficiency * 100, 1),
                    "recovery_per_outage_s": round(m.recovery_per_outage_s, 3),
                    "handshake_material_B": m.handshake_material_B,
                    "checkpoint_overhead_ratio_pct": round(m.checkpoint_overhead_ratio * 100, 2),
                })
    return rows


def print_table2(disruption_count: int = 5) -> None:
    print(f"\n=== Table 2 equivalent, {disruption_count} disruptions ===")
    header = f"{'Metric':<28}" + "".join(f"{p.name:>14}(B)" f"{p.name:>10}(P)" for p in PROFILES.values())
    print(header)
    metrics_by_gen = {
        gen: (compute_metrics(gen, "baseline", disruption_count),
              compute_metrics(gen, "proposed", disruption_count))
        for gen in PROFILES
    }

    def row(label, fmt, getter):
        line = f"{label:<28}"
        for gen in PROFILES:
            b, p = metrics_by_gen[gen]
            line += f"{fmt(getter(b)):>17}{fmt(getter(p)):>13}"
        print(line)

    fmt2 = lambda v: f"{v:.2f}"
    fmtpct = lambda v: f"{v * 100:.1f}%"
    row("Completion time (s)", fmt2, lambda m: m.completion_time_s)
    row("Goodput (MB/s)", fmt2, lambda m: m.goodput_MBps)
    row("Redundant data (MB)", fmt2, lambda m: m.redundant_data_MB)
    row("Transfer efficiency", fmtpct, lambda m: m.transfer_efficiency)
    row("Recovery / outage (s)", fmt2, lambda m: m.recovery_per_outage_s)
    row("Handshake material (B)", lambda v: str(int(v)), lambda m: m.handshake_material_B)


def run_live_crypto_demo(file_size_bytes: int = 500_000,
                          chunk_size: int = CHUNK_BYTES,
                          interval: int = DEFAULT_INTERVAL_N,
                          n_disruptions: int = 5,
                          seed: int = 42) -> None:
    """Runs the REAL crypto simulator (small file, for speed) for both arms
    and prints/verifies the result. This is the part of the repo that
    actually performs ML-KEM-768 + AES-256-GCM + HMAC checkpoint operations,
    as opposed to reporting the closed-form projection."""
    print(f"\n=== Live crypto-correctness demo ({file_size_bytes/1e6:.1f} MB payload) ===")
    rng = random.Random(seed)
    payload = os.urandom(file_size_bytes)
    n_chunks = (file_size_bytes + chunk_size - 1) // chunk_size
    disrupt_positions = set(rng.sample(range(1, n_chunks), min(n_disruptions, n_chunks - 1)))

    checkpoint_dir = os.path.join(RESULTS_DIR, "checkpoints")
    proposed = run_checkpointed_transfer(
        payload, chunk_size, interval, checkpoint_dir, disrupt_positions,
    )
    baseline = run_baseline_transfer(payload, chunk_size, disrupt_positions)

    print(f"Disruption points (chunk indices): {sorted(disrupt_positions)}")
    print(f"Proposed  -> resumes={proposed.resumes_performed:2d}  "
          f"handshakes={proposed.handshakes_performed}  "
          f"digest_ok={proposed.final_digest_ok}")
    print(f"Baseline  -> resumes={baseline.resumes_performed:2d}  "
          f"handshakes={baseline.handshakes_performed}  "
          f"digest_ok={baseline.final_digest_ok}  "
          f"bytes_resent={baseline.bytes_resent/1e6:.2f} MB")

    assert proposed.final_digest_ok and baseline.final_digest_ok, \
        "live crypto demo failed integrity check"


def save_csv(rows: list[dict], filename: str = "analytical_metrics.csv") -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, filename)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return path


if __name__ == "__main__":
    print_table2(5)
    print_table2(10)
    rows = analytical_table()
    path = save_csv(rows)
    print(f"\nSaved {len(rows)} rows to {path}")
    run_live_crypto_demo()
