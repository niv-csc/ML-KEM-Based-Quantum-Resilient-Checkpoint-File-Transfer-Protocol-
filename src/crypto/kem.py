"""
ML-KEM-768 key establishment (NIST FIPS 203).

Implements the handshake described in Section II-B / Eq. (1) of the paper:
    T_h = t_kg + t_enc + t_dec + (|pk| + |ct|) / R + tau

Backed by `kyber-py`, a pure-Python, spec-conformant ML-KEM implementation
(this is the same "kyber-py" entry listed in Table 1 of the paper).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from kyber_py.ml_kem import ML_KEM_768

# Fixed sizes for ML-KEM-768, quoted in the paper (Section II-B):
PK_BYTES = 1184
CT_BYTES = 1088
SS_BYTES = 32


@dataclass
class HandshakeTiming:
    t_kg: float   # key generation time (receiver / responder side), seconds
    t_enc: float  # encapsulation time (sender / initiator side), seconds
    t_dec: float  # decapsulation time (receiver side), seconds


class MLKEM768:
    """Thin, timed wrapper around kyber-py's ML-KEM-768."""

    @staticmethod
    def keygen() -> tuple[bytes, bytes, float]:
        """Generate (encapsulation key, decapsulation key, elapsed seconds)."""
        t0 = time.perf_counter()
        ek, dk = ML_KEM_768.keygen()
        elapsed = time.perf_counter() - t0
        assert len(ek) == PK_BYTES, f"unexpected pk size {len(ek)}"
        return ek, dk, elapsed

    @staticmethod
    def encaps(ek: bytes) -> tuple[bytes, bytes, float]:
        """Encapsulate against `ek`. Returns (shared_secret, ciphertext, elapsed)."""
        t0 = time.perf_counter()
        shared_secret, ct = ML_KEM_768.encaps(ek)
        elapsed = time.perf_counter() - t0
        assert len(ct) == CT_BYTES, f"unexpected ct size {len(ct)}"
        return shared_secret, ct, elapsed

    @staticmethod
    def decaps(dk: bytes, ct: bytes) -> tuple[bytes, float]:
        """Decapsulate `ct` under `dk`. Returns (shared_secret, elapsed)."""
        t0 = time.perf_counter()
        shared_secret = ML_KEM_768.decaps(dk, ct)
        elapsed = time.perf_counter() - t0
        return shared_secret, elapsed

    @staticmethod
    def handshake_material_bytes() -> int:
        """Bytes of key material sent over the wire in one ML-KEM-768 exchange
        (pk sent receiver->sender, ct sent sender->receiver). Matches the
        13,632 B figure in the paper only when multiplied by six exchanges
        (see benchmark.harness for the baseline's repeated-handshake cost)."""
        return PK_BYTES + CT_BYTES  # 2272 B, matches Table 2 "Handshake material"
