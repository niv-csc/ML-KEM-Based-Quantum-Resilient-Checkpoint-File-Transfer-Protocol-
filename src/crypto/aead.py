"""
Key schedule and bulk AEAD, matching Section II-B, Eqs. (2)-(3) of the paper.

    K || K_ck = HKDF-SHA256(ss, sid, "pq6g/v1")          (2)
    C_i = AES-256-GCM_K(nu_i, M_i, A_i),  nu_i = sid || i  (3)

`nu_i` (the AEAD nonce) is a pure function of the session id and the chunk
index, so re-sealing chunk i after a resume is idempotent: same nonce, same
plaintext, same ciphertext. That determinism is what makes GCM safe to use
across a resume (see paper, end of Section II-B).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.hashes import SHA256

HKDF_INFO = b"pq6g/v1"
NONCE_SID_BYTES = 4   # sid folded to 4 B  \
NONCE_IDX_BYTES = 8   # chunk index, 8 B   } together = 12 B GCM nonce
TAG_BYTES = 16        # AES-GCM tag length ("16 B tag per 64 KB chunk" in paper)


@dataclass
class SessionKeys:
    aead_key: bytes       # K,    32 B (AES-256)
    checkpoint_key: bytes  # K_ck, 32 B (checkpoint HMAC key)


def derive_session_keys(shared_secret: bytes, sid: bytes) -> SessionKeys:
    """Eq. (2): K || K_ck = HKDF-SHA256(ss, sid, "pq6g/v1").

    We use HKDF in "expand-only" form with `sid` folded into the info string,
    which is the standard way to bind a per-session salt when the extract
    step's randomness already comes from a fresh KEM shared secret.
    """
    hkdf = HKDFExpand(algorithm=SHA256(), length=64, info=sid + HKDF_INFO)
    okm = hkdf.derive(shared_secret)
    return SessionKeys(aead_key=okm[:32], checkpoint_key=okm[32:64])


def make_nonce(sid: bytes, chunk_index: int) -> bytes:
    """nu_i = sid_32 || i_64 -> truncate/pack into the 12 B GCM needs."""
    sid4 = sid[:NONCE_SID_BYTES].ljust(NONCE_SID_BYTES, b"\x00")
    idx8 = struct.pack(">Q", chunk_index)
    return sid4 + idx8


def seal_chunk(key: bytes, sid: bytes, chunk_index: int, plaintext: bytes) -> bytes:
    """C_i = AES-256-GCM_K(nu_i, M_i, A_i), A_i = (sid, i, |M_i|)."""
    aesgcm = AESGCM(key)
    nonce = make_nonce(sid, chunk_index)
    aad = sid + struct.pack(">Q", chunk_index) + struct.pack(">I", len(plaintext))
    return aesgcm.encrypt(nonce, plaintext, aad)


def open_chunk(key: bytes, sid: bytes, chunk_index: int, plaintext_len: int,
               ciphertext: bytes) -> bytes:
    """Inverse of seal_chunk; raises cryptography.exceptions.InvalidTag on
    tamper/mismatch, which the receiver treats as a verification failure."""
    aesgcm = AESGCM(key)
    nonce = make_nonce(sid, chunk_index)
    aad = sid + struct.pack(">Q", chunk_index) + struct.pack(">I", plaintext_len)
    return aesgcm.decrypt(nonce, ciphertext, aad)
