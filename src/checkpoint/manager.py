"""
Receiver-authoritative checkpoint, matching Section II-B Eq. (4):

    chi = (sid, i*, o*, H_i*, HMAC_Kck(sid || i* || o* || H_i*))

written durably by the receiver after verifying each chunk's tag. The sender
never dictates the resume point, and the MAC binds the offset to the session
key, so an off-path attacker cannot force a rewind or a silent skip.

Persistence is modelled as a JSON file write + os.fsync, so PERSIST(chi) in
Algorithm 1 costs a real (if tiny, on local disk) syscall -- the t_ck term
in the paper's overhead model (Eq. 5) is dominated by an assumed fsync
latency (5 ms in Table 1), which we allow the caller to simulate on top of
the real, near-zero local fsync via `channel.emulator`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, asdict
from typing import Optional


def rolling_hash(prev_hash: Optional[bytes], ciphertext: bytes) -> bytes:
    """H_i = SHA-256(H_{i-1} || SHA-256(C_i)), H_{-1} = empty."""
    inner = hashlib.sha256(ciphertext).digest()
    prev = prev_hash if prev_hash is not None else b""
    return hashlib.sha256(prev + inner).digest()


@dataclass
class Checkpoint:
    sid: str          # hex session id
    index: int         # i*  : last verified chunk index
    offset: int        # o*  : byte offset of end of chunk i*
    rolling_hash: str  # H_i* : hex
    mac: str           # HMAC_Kck(sid || i* || o* || H_i*) : hex

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(s: str) -> "Checkpoint":
        return Checkpoint(**json.loads(s))


def _mac_input(sid: bytes, index: int, offset: int, h: bytes) -> bytes:
    return sid + index.to_bytes(8, "big") + offset.to_bytes(8, "big") + h


def make_checkpoint(sid: bytes, index: int, offset: int, h: bytes,
                     checkpoint_key: bytes) -> Checkpoint:
    tag = hmac.new(checkpoint_key, _mac_input(sid, index, offset, h),
                   hashlib.sha256).digest()
    return Checkpoint(
        sid=sid.hex(), index=index, offset=offset,
        rolling_hash=h.hex(), mac=tag.hex(),
    )


def verify_checkpoint(chi: Checkpoint, checkpoint_key: bytes) -> bool:
    """Constant-time HMAC verification. Returns False on forged offset/index
    or wrong key -- this is the "abort if HMAC invalid" branch of Algorithm 1."""
    sid = bytes.fromhex(chi.sid)
    h = bytes.fromhex(chi.rolling_hash)
    expected = hmac.new(checkpoint_key, _mac_input(sid, chi.index, chi.offset, h),
                         hashlib.sha256).digest()
    return hmac.compare_digest(expected, bytes.fromhex(chi.mac))


class CheckpointStore:
    """Durable checkpoint persistence: one JSON file per session, fsync'd on
    every PERSIST call (receiver side is authoritative per the paper)."""

    def __init__(self, directory: str):
        self.directory = directory
        os.makedirs(directory, exist_ok=True)

    def _path(self, sid: bytes) -> str:
        return os.path.join(self.directory, f"{sid.hex()}.checkpoint.json")

    def persist(self, chi: Checkpoint) -> None:
        path = self._path(bytes.fromhex(chi.sid))
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(chi.to_json())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def load(self, sid: bytes) -> Optional[Checkpoint]:
        path = self._path(sid)
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return Checkpoint.from_json(f.read())

    def clear(self, sid: bytes) -> None:
        path = self._path(sid)
        if os.path.exists(path):
            os.remove(path)
