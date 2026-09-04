"""
Run with: python -m pytest tests/ -v
(or just: python tests/test_protocol.py)
"""
import os
import sys
import shutil
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.crypto.kem import MLKEM768
from src.crypto.aead import derive_session_keys, seal_chunk, open_chunk
from src.checkpoint.manager import (
    rolling_hash, make_checkpoint, verify_checkpoint, CheckpointStore,
)
from src.protocol.simulator import run_checkpointed_transfer, run_baseline_transfer
from cryptography.exceptions import InvalidTag


def test_mlkem_roundtrip():
    ek, dk, _ = MLKEM768.keygen()
    assert len(ek) == 1184
    ss, ct, _ = MLKEM768.encaps(ek)
    assert len(ct) == 1088
    assert len(ss) == 32
    ss2, _ = MLKEM768.decaps(dk, ct)
    assert ss == ss2


def test_aead_seal_open_roundtrip():
    ss = os.urandom(32)
    sid = os.urandom(4)
    keys = derive_session_keys(ss, sid)
    pt = b"hello checkpoint world" * 100
    ct = seal_chunk(keys.aead_key, sid, 7, pt)
    recovered = open_chunk(keys.aead_key, sid, 7, len(pt), ct)
    assert recovered == pt


def test_aead_rejects_wrong_index():
    ss = os.urandom(32)
    sid = os.urandom(4)
    keys = derive_session_keys(ss, sid)
    pt = b"x" * 64
    ct = seal_chunk(keys.aead_key, sid, 1, pt)
    try:
        open_chunk(keys.aead_key, sid, 2, len(pt), ct)  # wrong chunk index -> wrong nonce/AAD
        assert False, "expected InvalidTag"
    except InvalidTag:
        pass


def test_checkpoint_hmac_accepts_valid_rejects_forged():
    sid = os.urandom(4)
    ck_key = os.urandom(32)
    h = rolling_hash(None, b"some ciphertext")
    chi = make_checkpoint(sid, 10, 640, h, ck_key)
    assert verify_checkpoint(chi, ck_key)

    # Forge: attacker bumps the index without knowing the MAC key.
    chi.index = 999
    assert not verify_checkpoint(chi, ck_key)


def test_checkpoint_store_persist_and_load():
    tmpdir = tempfile.mkdtemp()
    try:
        store = CheckpointStore(tmpdir)
        sid = os.urandom(4)
        ck_key = os.urandom(32)
        h = rolling_hash(None, b"c0")
        chi = make_checkpoint(sid, 3, 192, h, ck_key)
        store.persist(chi)
        loaded = store.load(sid)
        assert loaded is not None
        assert loaded.index == 3
        assert verify_checkpoint(loaded, ck_key)
    finally:
        shutil.rmtree(tmpdir)


def test_end_to_end_transfer_survives_disruptions():
    tmpdir = tempfile.mkdtemp()
    try:
        payload = os.urandom(200_000)
        disrupt = {3, 7, 12}
        result = run_checkpointed_transfer(
            payload, chunk_size=8192, checkpoint_interval=4,
            checkpoint_dir=tmpdir, disrupt_at_chunks=disrupt,
        )
        assert result.completed
        assert result.final_digest_ok
        assert result.resumes_performed == len(disrupt)
        assert result.handshakes_performed == 1  # never re-keys on resume
    finally:
        shutil.rmtree(tmpdir)


def test_baseline_transfer_also_completes_but_pays_more():
    payload = os.urandom(200_000)
    disrupt = {3, 7, 12}
    result = run_baseline_transfer(payload, chunk_size=8192, disrupt_at_chunks=disrupt)
    assert result.completed
    assert result.final_digest_ok
    assert result.handshakes_performed == len(disrupt) + 1  # re-keys every time
    assert result.bytes_resent > 0


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for t in tests:
        print(f"Running {t.__name__} ... ", end="")
        t()
        print("OK")
    print(f"\nAll {len(tests)} tests passed.")
