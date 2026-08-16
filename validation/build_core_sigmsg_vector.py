#!/usr/bin/env python3
"""Produce the INDEPENDENT Bitcoin Core-format `signmessage` vector pinned in
asm/tests/test_msg_sign.c (FINDING P2-2 interop fixture).

The vector is generated here so the test fixture is reproducible and auditable.
It uses the external `ecdsa` library (RFC6979 deterministic) -- NOT any code
from this repo -- to sign the exact BIP137 digest for the fixed test key
0x01..0x20, and emits the Core compact recoverable signature the way Bitcoin
Core's signmessage does:

  1. z = SHA256d( "\\x18Bitcoin Signed Message:\\n" || varint(len) || msg )
  2. (r, s) = RFC6979 deterministic ECDSA over the RAW digest z (low-S)
  3. recid = recovery id that recovers the compressed signing pubkey
     (determined with ecdsa.VerifyingKey.from_public_key_recovery_with_digest)
  4. Core compact = [27 + 4 + recid] || r_be || s_be  -> base64(core_format)

msg_verify_core must ACCEPT this base64 for the message + address below, which
proves we verify a genuine, non-self-produced Core-format signature (not just
our own round-trip).

Output is printed to stdout as key = value lines. Requirements: `pip install
ecdsa` (system python3). Run: python3 validation/build_core_sigmsg_vector.py
"""
import base64
import hashlib
import sys

try:
    import ecdsa
except ImportError:
    sys.exit("error: 'ecdsa' python package required: pip install ecdsa")

from ecdsa.util import sigdecode_string, sigencode_string

PRIV = bytes(range(1, 33))                 # fixed test key 0x01..0x20
MSG = b"Core-interop hello from libsecp256k1"


def varint(n):
    if n < 253:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    raise ValueError("message too long for this vector builder")


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def main():
    z = sha256d(b"\x18Bitcoin Signed Message:\n" + varint(len(MSG)) + MSG)
    sk = ecdsa.SigningKey.from_string(PRIV, curve=ecdsa.SECP256k1)
    # RFC6979 deterministic over the RAW digest z (no re-hash), like Core signs
    sig = sk.sign_digest_deterministic(z, hashfunc=hashlib.sha256,
                                       sigencode=sigencode_string)
    r = sig[:32]
    s = sig[32:64]
    # low-S normalize (Core always emits low-S)
    n = ecdsa.SECP256k1.order
    sint = int.from_bytes(s, "big")
    if sint > n - sint:
        s = (n - sint).to_bytes(32, "big")

    pub_comp = sk.get_verifying_key().to_string("compressed")

    # recid such that (r,s,z,recid) recovers our compressed pubkey
    recid = None
    try:
        vks = ecdsa.VerifyingKey.from_public_key_recovery_with_digest(
            r + s, z, curve=ecdsa.SECP256k1, sigdecode=sigdecode_string)
        for i, vk in enumerate(vks):
            if vk.to_string("compressed") == pub_comp:
                recid = i
                break
    except Exception as e:  # pragma: no cover
        sys.exit("recovery error: %s" % e)
    if recid is None:
        sys.exit("error: could not determine recovery id")

    # Core compact header: 27 + (4 if compressed) + recid  (always compressed)
    header = 27 + 4 + recid
    comp = bytes([header]) + r + s
    b64 = base64.b64encode(comp).decode()

    # mainnet P2PKH address for the compressed pubkey
    h160 = hashlib.new("ripemd160", hashlib.sha256(pub_comp).digest()).digest()
    alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def b58(b):
        num = int.from_bytes(b, "big")
        s = ""
        while num:
            num, rr = divmod(num, 58)
            s = alpha[rr] + s
        pad = 0
        for c in b:
            if c == 0:
                pad += 1
            else:
                break
        return "1" * pad + s

    payload = b"\x00" + h160
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    addr = b58(payload + chk)

    print("PRIV =", PRIV.hex())
    print("MSG =", MSG.decode())
    print("PUB_COMP =", pub_comp.hex())
    print("ADDR =", addr)
    print("RECID =", recid)
    print("SIG_CORE_B64 =", b64)


if __name__ == "__main__":
    main()
