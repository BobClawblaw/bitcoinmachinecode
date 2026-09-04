#!/usr/bin/env python3
"""Oracle for tests/test_scr5_spkrun.c (SCR-5, audit 2026-09-03).

Independent BIP341 sha_scriptpubkeys digest: the aggregate hash Core puts in
the sighash preimage is SHA256(ser_compactsize(len)||spk for every input).
Computed here from scratch (stdlib hashlib only) for the exact byte vectors
the C test builds, so the expected digest does not come from any code under
review. Run: python3 validation/scr5_spkrun_oracle.py
"""
import hashlib
spk0 = bytes(((i*7+3) % 256) for i in range(531))     # audit's 531-byte multisig shape
spk1 = bytes([0x51, 0x20]) + bytes(range(32))         # P2TR-shaped co-input

def cs(n):
    return bytes([n]) if n < 0xfd else bytes([0xfd, n % 256, (n >> 8) % 256])

run = cs(len(spk0)) + spk0 + cs(len(spk1)) + spk1
print("h_spk =", hashlib.sha256(run).hexdigest())
