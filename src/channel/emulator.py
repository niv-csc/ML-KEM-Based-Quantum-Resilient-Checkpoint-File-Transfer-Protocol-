"""
Emulated air interface. Statistical stand-in for the ns-3 / tc-netem model
the paper names as future work (Section V); here it is a Poisson blockage
process plus fixed per-generation RTT / rate, parameterised exactly per
Table 1 so results are directly comparable to the paper's closed-form model.

Both the baseline arm and the proposed arm draw disruptions from the same
seeded generator (see benchmark.harness), matching the paper's claim that
"baseline arm and proposed arm share the same channel emulator and seeds,
so all measured differences come from the protocol."
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class GenerationProfile:
    """One row of Table 1."""
    name: str
    link_rate_bps: float     # R
    rtt_s: float             # tau
    detect_s: float          # T_d
    reconnect_s: float       # T_r
    blockage_rate_hz: float  # lambda (expected disruptions per second)


PROFILES: dict[str, GenerationProfile] = {
    "5G": GenerationProfile("5G mmWave", 800e6, 2e-3, 0.3, 0.3, 0.8),
    "B5G": GenerationProfile("Beyond-5G", 900e6, 1.5e-3, 0.4, 0.4, 1.0),
    "6G": GenerationProfile("6G THz", 1e9, 1e-3, 0.5, 0.5, 1.2),
}

CHECKPOINT_FSYNC_S = 5e-3   # t_ck, Table 1
CHUNK_BYTES = 64 * 1024     # c, Table 1 ("64 KB" = 65,536 B, binary convention)
FILE_BYTES = 100_000_000    # S, Table 1 ("100 MB" = decimal, matches Mbps units
                            # and reproduces the paper's Table 2 figures exactly)
DEFAULT_INTERVAL_N = 64


class ChannelEmulator:
    """Deterministic-given-seed disruption schedule for one simulated transfer.

    disruption_positions(n_chunks, n_disruptions) places `n_disruptions`
    outages uniformly at random across the chunk stream -- a simple stand-in
    for a Poisson blockage process with the right *count* (nd), which is all
    the paper's closed-form model (Eq. 5-6) and metrics (i)-(vi) need.
    """

    def __init__(self, profile: GenerationProfile, seed: int):
        self.profile = profile
        self.rng = random.Random(seed)

    def disruption_positions(self, n_chunks: int, n_disruptions: int) -> set[int]:
        if n_disruptions <= 0 or n_chunks <= 1:
            return set()
        n_disruptions = min(n_disruptions, n_chunks - 1)
        return set(self.rng.sample(range(1, n_chunks), n_disruptions))

    def chunk_tx_time(self, n_bytes: int) -> float:
        """T_tx = size / bandwidth."""
        return n_bytes / self.profile.link_rate_bps

    def ack_rtt(self) -> float:
        return self.profile.rtt_s

    def outage_cost(self) -> float:
        """Td + Tr, the fixed cost of one disruption before reconnection."""
        return self.profile.detect_s + self.profile.reconnect_s

    def resume_rtt(self) -> float:
        """One-RTT RESUME exchange (proposed arm's post-outage cost)."""
        return self.profile.rtt_s
