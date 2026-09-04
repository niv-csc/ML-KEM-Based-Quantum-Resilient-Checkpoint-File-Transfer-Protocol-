"""
Closed-form delay/overhead model from the paper (Section II-B Eq. 1,
Section III-C Eq. 5-6, Section IV-A metrics (i)-(vi)).

This module reproduces Table 2 / Fig. 3 / Fig. 4 analytically -- exactly
the way the paper itself describes its own numbers: "The results below are
analytical projections ... not measured trials." `protocol.simulator`
complements this with a real, running crypto implementation; this module
is what regenerates the paper's plots and headline percentages quickly for
any (generation, N, nd) combination.

Every constant below is taken directly from Table 1 of the paper. The one
free parameter not pinned down by the paper's text is `EPSILON_BASELINE`,
a small fixed per-outage overhead in the baseline's recovery-cost formula
(Section IV-A metric (iv): "Td + Tr + Th + eps + p-bar*S/R for the
baseline"). The paper does not publish a numeric value for eps; solving
Table 2's own completion-time figures backwards pins it at ~0.024 s,
generation-invariant, and using that value reproduces every entry in
Table 2 to within 0.01 s. It is exposed as a constant so you can change it
and see how sensitive the headline percentages are to it.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.channel.emulator import (
    PROFILES, GenerationProfile, CHECKPOINT_FSYNC_S, CHUNK_BYTES, FILE_BYTES,
    DEFAULT_INTERVAL_N,
)
from src.crypto.kem import MLKEM768

# Reverse-engineered from Table 2 (see module docstring). Generation-invariant.
EPSILON_BASELINE_S = 0.024

# ML-KEM-768 handshake material per exchange (pk + ct), Table 2's 2272 B figure.
HANDSHAKE_BYTES = MLKEM768.handshake_material_bytes()  # 2272
# Microsecond-scale keygen/enc/dec cost folded into Th; measured once so the
# model uses a real (not guessed) constant instead of "negligible".
_KG, _DK, _T_KG = MLKEM768.keygen()
_, _, _T_ENC = MLKEM768.encaps(_KG)
_, _T_DEC = MLKEM768.decaps(_DK, _)
CRYPTO_OP_SECONDS = _T_KG + _T_ENC + _T_DEC


def handshake_time_s(profile: GenerationProfile) -> float:
    """Eq. (1): T_h = t_kg + t_enc + t_dec + (|pk|+|ct|)/R + tau."""
    return CRYPTO_OP_SECONDS + (HANDSHAKE_BYTES * 8) / profile.link_rate_bps + profile.rtt_s


def optimal_interval(S: int = FILE_BYTES, c: int = CHUNK_BYTES,
                      R_bits_per_s: float = 1e9, t_ck: float = CHECKPOINT_FSYNC_S,
                      n_d: int = 5) -> float:
    """Eq. (6): N* = sqrt(2 R S t_ck / (n_d c^2)).

    S and c are in bytes here, so R must be converted to bytes/s (the
    paper's R is quoted in bits/s, e.g. "1 Gbps") for the formula to be
    dimensionally consistent -- this is what reproduces the paper's
    N* ~ 76 at the 6G operating point (R=1 Gbps, nd=5); passing R in
    bits/s directly gives a value ~8x too large.
    """
    R_bytes_per_s = R_bits_per_s / 8
    return (2 * R_bytes_per_s * S * t_ck / (n_d * c ** 2)) ** 0.5


def checkpoint_overhead_seconds(S: int, c: int, N: int, t_ck: float) -> float:
    """Persistence term of Eq. (5): (S / (N c)) * t_ck."""
    return (S / (N * c)) * t_ck


@dataclass
class Metrics:
    """The paper's six comparable metrics, Section IV-A, one instance per
    (generation, arm)."""
    generation: str
    arm: str                    # "baseline" | "proposed"
    n_disruptions: int
    completion_time_s: float
    goodput_MBps: float
    redundant_data_MB: float
    transfer_efficiency: float   # eta = S / (S + S_red), 0..1
    recovery_per_outage_s: float
    handshake_material_B: int
    checkpoint_overhead_ratio: float  # rho, proposed only (None-like 0 for baseline)


def _redundant_data_bytes(arm: str, S: int, c: int, N: int, nd: int) -> float:
    """Expected bytes that must be re-sent given `nd` disruptions spread
    uniformly across the transfer.

    Baseline has no checkpoint: a disruption loses *all* progress, so the
    k-th of nd evenly-spaced disruptions forces re-sending k/(nd+1) of the
    whole file; summed over k=1..nd this is S * nd/2 (matches the paper's
    published 250 MB at S=100 MB, nd=5).

    Proposed: only data since the last checkpoint is at risk, at most N*c
    bytes, on average N*c/2 per disruption (matches the paper's published
    10.5 MB at N=64, c=64 KiB, nd=5).
    """
    if nd <= 0:
        return 0.0
    if arm == "baseline":
        return S * nd / 2
    return nd * (N * c) / 2


def compute_metrics(gen_key: str, arm: str, n_disruptions: int,
                     S: int = FILE_BYTES, c: int = CHUNK_BYTES,
                     N: int = DEFAULT_INTERVAL_N,
                     t_ck: float = CHECKPOINT_FSYNC_S) -> Metrics:
    profile = PROFILES[gen_key]
    R = profile.link_rate_bps
    nd = n_disruptions
    base_transfer_s = S * 8 / R  # ideal, undisrupted transfer time

    redundant_bytes = _redundant_data_bytes(arm, S, c, N, nd)
    retransmit_s = redundant_bytes * 8 / R
    Th = handshake_time_s(profile)
    fsync_overhead_s = checkpoint_overhead_seconds(S, c, N, t_ck)

    if arm == "baseline":
        completion = (
            base_transfer_s
            + nd * (profile.detect_s + profile.reconnect_s)
            + (nd + 1) * Th             # initial handshake + nd restarts
            + nd * EPSILON_BASELINE_S
            + retransmit_s
        )
        recovery_per_outage = (profile.detect_s + profile.reconnect_s + Th
                                + EPSILON_BASELINE_S
                                + (nd / 2 if nd else 0) * S * 8 / R / max(nd, 1))
        handshake_material = (nd + 1) * HANDSHAKE_BYTES
        rho = 0.0
    else:
        completion = (
            base_transfer_s
            + nd * (profile.detect_s + profile.reconnect_s)
            + Th                        # one handshake, ever
            + nd * profile.rtt_s        # one-RTT RESUME per outage
            + retransmit_s
            + fsync_overhead_s
        )
        recovery_per_outage = profile.detect_s + profile.reconnect_s + profile.rtt_s \
            + (N * c) / (2 * R) * 8
        handshake_material = HANDSHAKE_BYTES
        rho = fsync_overhead_s / base_transfer_s

    goodput_MBps = (S / 1e6) / completion
    redundant_MB = redundant_bytes / 1e6
    efficiency = S / (S + redundant_bytes) if (S + redundant_bytes) else 1.0

    return Metrics(
        generation=profile.name, arm=arm, n_disruptions=nd,
        completion_time_s=completion, goodput_MBps=goodput_MBps,
        redundant_data_MB=redundant_MB, transfer_efficiency=efficiency,
        recovery_per_outage_s=recovery_per_outage,
        handshake_material_B=handshake_material,
        checkpoint_overhead_ratio=rho,
    )
