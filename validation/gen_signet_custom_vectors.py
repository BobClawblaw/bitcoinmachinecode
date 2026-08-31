#!/usr/bin/env python3
"""A SIGNED custom-signet challenge, for the witness path real signet never uses.

The default signet challenge is a bare CHECKMULTISIG, so every real block
decides on the LEGACY verification path with an empty witness stack. The
witness branch of signet_check_solution is therefore unreachable from the real
network, and the trivial OP_TRUE fixtures that cover its wiring cannot tell
whether the verification FLAGS are applied at all -- OP_TRUE succeeds under
any flags.

So this builds a custom signet the way a real one would be built: a P2WSH
challenge over a 1-of-1 CHECKMULTISIG witnessScript, with a real secp256k1
signature over the real BIP143 sighash of the synthetic to_sign transaction.
It emits two solutions differing only in the CHECKMULTISIG dummy element
(empty vs. one byte), so the pair isolates SCRIPT_VERIFY_NULLDUMMY:

    empty dummy      -> valid   (and invalid if the signature is not checked)
    one-byte dummy   -> INVALID under NULLDUMMY, valid without it

A verifier that forgets to pass the flags accepts both, and the pair catches
it. A verifier that ignores signatures accepts a corrupted one, and the third
vector catches that.

Usage: gen_signet_custom_vectors.py
"""
import hashlib, os
from coincurve import PrivateKey

def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))
def cs(n):
    if n < 253: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')

# A fixed test key. Not a secret: it signs a synthetic block on a network that
# does not exist, and the whole point is that the vector is reproducible.
KEY = PrivateKey(bytes.fromhex(
    "5ca1ab1e00000000000000000000000000000000000000000000000000000001"))
PUB = KEY.public_key.format(compressed=True)

NVERSION = 0x20000000
PREV = bytes.fromhex("00000000e1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c")
MERKLE = bytes.fromhex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
NTIME = 1700000000

# witnessScript: OP_1 <pub> OP_1 OP_CHECKMULTISIG -- 1-of-1, so the dummy
# element NULLDUMMY governs is present and is the only thing that varies.
WSCRIPT = bytes([0x51, 0x21]) + PUB + bytes([0x51, 0xae])
CHALLENGE = bytes([0x00, 0x20]) + sha256(WSCRIPT)      # P2WSH

def build_to_spend():
    block_data = (NVERSION.to_bytes(4, 'little') + PREV + MERKLE
                  + NTIME.to_bytes(4, 'little'))
    ss = b'\x00' + bytes([len(block_data)]) + block_data
    o  = (0).to_bytes(4, 'little') + b'\x01'
    o += b'\x00'*32 + b'\xff\xff\xff\xff'
    o += cs(len(ss)) + ss + (0).to_bytes(4, 'little')
    o += b'\x01' + (0).to_bytes(8, 'little') + cs(len(CHALLENGE)) + CHALLENGE
    o += (0).to_bytes(4, 'little')
    return o

def bip143_sighash(ts_txid):
    """to_sign has one input and one 0-value OP_RETURN output."""
    outpoint = ts_txid + (0).to_bytes(4, 'little')
    hash_prevouts = sha256d(outpoint)
    hash_sequence = sha256d((0).to_bytes(4, 'little'))
    out = (0).to_bytes(8, 'little') + b'\x01\x6a'
    hash_outputs = sha256d(out)
    pre = ((0).to_bytes(4, 'little')            # nVersion
           + hash_prevouts + hash_sequence
           + outpoint
           + cs(len(WSCRIPT)) + WSCRIPT         # scriptCode
           + (0).to_bytes(8, 'little')          # amount
           + (0).to_bytes(4, 'little')          # nSequence
           + hash_outputs
           + (0).to_bytes(4, 'little')          # nLockTime
           + (1).to_bytes(4, 'little'))         # SIGHASH_ALL
    return sha256d(pre)

def solution(dummy, sig):
    """scriptSig is empty; witness is [dummy, sig, witnessScript]."""
    items = [dummy, sig, WSCRIPT]
    o = cs(0)                                   # empty scriptSig
    o += cs(len(items))
    for it in items:
        o += cs(len(it)) + it
    return o

# ---- the LEGACY arm: a bare CHECKMULTISIG challenge, the SHAPE the default
# signet actually uses. Real signet blocks all have a null dummy and canonical
# DER, so they cannot tell whether the flags are applied on this path either --
# the same blind spot the P2WSH pair closes for the witness path.
LCHALLENGE = bytes([0x51, 0x21]) + PUB + bytes([0x51, 0xae])   # 1-of-1 bare

def build_to_spend_for(challenge):
    block_data = (NVERSION.to_bytes(4, 'little') + PREV + MERKLE
                  + NTIME.to_bytes(4, 'little'))
    ss = b'\x00' + bytes([len(block_data)]) + block_data
    o  = (0).to_bytes(4, 'little') + b'\x01'
    o += b'\x00'*32 + b'\xff\xff\xff\xff'
    o += cs(len(ss)) + ss + (0).to_bytes(4, 'little')
    o += b'\x01' + (0).to_bytes(8, 'little') + cs(len(challenge)) + challenge
    o += (0).to_bytes(4, 'little')
    return o

def legacy_sighash(ts_txid, script_code):
    """SIGHASH_ALL over the 1-in/1-out to_sign, scriptSig replaced by
    scriptCode. No witness serialisation: this is SigVersion::BASE."""
    o  = (0).to_bytes(4, 'little') + b'\x01'
    o += ts_txid + (0).to_bytes(4, 'little')
    o += cs(len(script_code)) + script_code + (0).to_bytes(4, 'little')
    o += b'\x01' + (0).to_bytes(8, 'little') + b'\x01\x6a'
    o += (0).to_bytes(4, 'little')
    return sha256d(o + (1).to_bytes(4, 'little'))

def legacy_solution(dummy_push, sig):
    """scriptSig = <dummy> <sig>; empty witness stack."""
    ss = dummy_push + bytes([len(sig)]) + sig
    return cs(len(ss)) + ss + cs(0)

def main():
    ts = build_to_spend()
    ts_txid = sha256d(ts)
    z = bip143_sighash(ts_txid)
    sig = KEY.sign(z, hasher=None) + b'\x01'    # DER + SIGHASH_ALL

    good    = solution(b'', sig)
    dummy1  = solution(b'\x01', sig)
    badsig  = solution(b'', sig[:-9] + bytes([sig[-9] ^ 0x08]) + sig[-8:])

    # legacy arm
    lts = build_to_spend_for(LCHALLENGE)
    lz = legacy_sighash(sha256d(lts), LCHALLENGE)
    lsig = KEY.sign(lz, hasher=None) + b'\x01'
    lgood   = legacy_solution(b'\x00', lsig)          # OP_0 dummy: null
    ldummy1 = legacy_solution(b'\x01\x01', lsig)      # push 0x01: NOT null
    lbadsig = legacy_solution(b'\x00', lsig[:-9] + bytes([lsig[-9] ^ 0x08]) + lsig[-8:])

    here = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    o = ['/* GENERATED by validation/gen_signet_custom_vectors.py -- do not edit.',
         ' *',
         ' * A CUSTOM signet: a P2WSH challenge over a 1-of-1 CHECKMULTISIG,',
         ' * signed for real. The default signet challenge is a bare',
         ' * CHECKMULTISIG, so no real block ever reaches the witness branch, and',
         ' * the OP_TRUE fixtures that cover its wiring cannot tell whether the',
         ' * verification flags are applied -- OP_TRUE succeeds under any flags.',
         ' *',
         ' * SC_SOL_GOOD and SC_SOL_DUMMY1 differ only in the CHECKMULTISIG',
         ' * dummy element -- empty, versus one byte -- and the signature is',
         ' * identical and correct in both. So NULLDUMMY is the only rule that',
         ' * can separate them: a verifier that drops the flags accepts both.',
         ' * SC_SOL_BADSIG has one bit flipped inside the DER signature. */',
         '#ifndef SIGNET_CUSTOM_VECTORS_H', '#define SIGNET_CUSTOM_VECTORS_H', '',
         '#define SC_NVERSION %d' % NVERSION,
         '#define SC_NTIME    %uu' % NTIME,
         'static const char* SC_PREV       = "%s";' % PREV.hex(),
         'static const char* SC_MERKLE     = "%s";' % MERKLE.hex(),
         'static const char* SC_CHALLENGE  = "%s";' % CHALLENGE.hex(),
         'static const char* SC_WSCRIPT    = "%s";' % WSCRIPT.hex(),
         'static const char* SC_SOL_GOOD   = "%s";' % good.hex(),
         'static const char* SC_SOL_DUMMY1 = "%s";' % dummy1.hex(),
         'static const char* SC_SOL_BADSIG = "%s";' % badsig.hex(),
         '',
         '/* The LEGACY arm: a bare CHECKMULTISIG challenge, the shape the',
         ' * default signet uses. SC_LSOL_GOOD and SC_LSOL_DUMMY1 carry the',
         ' * SAME correct signature and differ only in the scriptSig dummy',
         ' * (OP_0 versus a one-byte push), so NULLDUMMY alone separates them',
         ' * -- which is what proves the flags reach the legacy verifier. */',
         'static const char* SC_LCHALLENGE  = "%s";' % LCHALLENGE.hex(),
         'static const char* SC_LSOL_GOOD   = "%s";' % lgood.hex(),
         'static const char* SC_LSOL_DUMMY1 = "%s";' % ldummy1.hex(),
         'static const char* SC_LSOL_BADSIG = "%s";' % lbadsig.hex(),
         '', '#endif', '']
    open(os.path.join(here, "asm/tests/signet_custom_vectors.h"), 'w').write('\n'.join(o))
    print("wrote a signed P2WSH custom-signet vector (challenge %s)"
          % CHALLENGE.hex()[:20])
    print("  witnessScript: 1-of-1 CHECKMULTISIG, %d bytes" % len(WSCRIPT))
    print("  witness arm: P2WSH, dummy empty vs 1 byte, same signature")
    print("  legacy  arm: bare CHECKMULTISIG, dummy OP_0 vs push, same signature")

main()
