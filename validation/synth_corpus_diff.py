#!/usr/bin/env python3
"""synth_corpus_diff.py -- SYNTHESIZED feature-depth differential vs Core.

WHY, on top of spend_corpus_diff.py. That harness samples RANDOM real mainnet
spends and applies GENERIC byte mutations. It proves the common paths agree,
but ASSESSMENT.md sect.5 item 2 asks for something it cannot give: per-PATH
depth on the constructs that carry their own consensus rules and are rare or
absent in random blocks --

  * multisig, and its NULLDUMMY / signature-ordering / threshold rules;
  * CLTV and CSV timelock paths, and the nLockTime / nSequence / tx-version
    predicates that gate them;
  * OP_CODESEPARATOR, whose position changes the legacy sighash subscript;
  * the taproot ANNEX, committed to by BIP341 sighash but otherwise inert.

You cannot reliably HARVEST these -- a CODESEPARATOR spend may be thousands of
blocks apart, an annex spend rarer still -- so this harness SYNTHESIZES a
valid spend for each, signs it correctly (coincurve = libsecp256k1: ECDSA for
legacy/v0, Schnorr for taproot), and drives BOTH engines over the same line
protocol the existing shim/oracle speak.

THE ORACLE VALIDATES THE SYNTHESIS FOR FREE. The oracle IS Core's VerifyScript.
Every synthesized "valid" spend is first asserted to be ACCEPTED by Core; if
Core rejects it, the construction is wrong and the harness fails loudly rather
than comparing garbage. Only once Core accepts do we require the ASM stack to
agree -- on the spend and on every rule-targeted mutation.

MUTATIONS ARE RULE-TARGETED, not byte noise. Each flips the specific predicate
the feature introduces (empty the NULLDUMMY dummy to nonzero; reorder two
multisig sigs; drop nLockTime below the CLTV threshold; set the CSV disable
bit; move the CODESEPARATOR; corrupt the annex) and BOTH engines must reject,
in agreement. An ASM-accept / Core-reject on any of these is the chain-split
class this project cares about.

Usage:  synth_corpus_diff.py [--only feature] [--seed S] [--oracle P] [--shim P]
Exit 0 iff zero divergences. Writes synth_corpus_diff_report.{json,txt}.
"""
import sys, os, json, time, hashlib, argparse
import coincurve

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
from spend_corpus_diff import (Engine, ORACLE, SHIM,
                               F_P2SH, F_DERSIG, F_NULLDUMMY, F_CLTV, F_CSV,
                               F_WITNESS, F_TAPROOT)

REPORT_JSON = os.path.join(HERE, 'synth_corpus_diff_report.json')
REPORT_TXT  = os.path.join(HERE, 'synth_corpus_diff_report.txt')

# Flag set for a modern (post-taproot) block: everything on. Feature synths
# that need a rule OFF (e.g. pre-NULLDUMMY behaviour) mask it out locally.
F_ALL = F_P2SH | F_DERSIG | F_NULLDUMMY | F_CLTV | F_CSV | F_WITNESS | F_TAPROOT

# ============================================================================
# minimal Bitcoin toolkit
# ============================================================================
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def sha(b):  return hashlib.sha256(b).digest()
def tagged(tag, *msgs):
    t = hashlib.sha256(tag.encode()).digest()
    h = hashlib.sha256(); h.update(t); h.update(t)
    for m in msgs: h.update(m)
    return h.digest()

def le(n, w): return n.to_bytes(w, 'little')
def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + le(n, 2)
    if n <= 0xffffffff: return b'\xfe' + le(n, 4)
    return b'\xff' + le(n, 8)
def pushdata(b):
    n = len(b)
    if n < 0x4c:  return bytes([n]) + b
    if n <= 0xff: return b'\x4c' + bytes([n]) + b
    if n <= 0xffff: return b'\x4d' + le(n, 2) + b
    return b'\x4e' + le(n, 4) + b

# CScriptNum minimal encoding (for locktime literals inside scripts)
def scriptnum(n):
    if n == 0: return b''
    neg = n < 0; a = abs(n); out = bytearray()
    while a: out.append(a & 0xff); a >>= 8
    if out[-1] & 0x80: out.append(0x80 if neg else 0x00)
    elif neg: out[-1] |= 0x80
    return bytes(out)
def push_num(n):
    if n == 0: return b'\x00'           # OP_0
    if 1 <= n <= 16: return bytes([0x50 + n])   # OP_1..OP_16
    return pushdata(scriptnum(n))

OP_DUP=0x76; OP_HASH160=0xa9; OP_EQUAL=0x87; OP_EQUALVERIFY=0x88
OP_CHECKSIG=0xac; OP_CHECKMULTISIG=0xae; OP_CHECKLOCKTIMEVERIFY=0xb1
OP_CHECKSEQUENCEVERIFY=0xb2; OP_DROP=0x75; OP_CODESEPARATOR=0xab; OP_0=0x00
OP_TRUE=0x51

def hash160(b): return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

def keypair(seed_byte):
    k = coincurve.PrivateKey(bytes([seed_byte]) * 32)
    return k, k.public_key.format(True)         # (priv, compressed pub33)

def ecdsa_sig(priv, sighash, hashtype):
    # coincurve.sign returns strict low-S DER (BIP66-valid) already
    der = priv.sign(sighash, hasher=None)
    return der + bytes([hashtype])

# --- legacy SignatureHash (pre-segwit) --------------------------------------
SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ACP = 1, 2, 3, 0x80

def legacy_sighash(tx_ins, tx_outs, nIn, script_code, hashtype, version=1, locktime=0):
    """Core's SignatureHash, all types -- INCLUDING the SIGHASH_SINGLE bug.

    When SIGHASH_SINGLE is used with nIn >= len(outputs) there is no matching
    output to commit to, and Core (following Satoshi) returns the CONSTANT
    uint256(1) rather than erroring. A signature over that constant is valid,
    so both engines must accept such a spend -- it is a live consensus rule,
    not a curiosity, and getting it wrong in either direction is a split."""
    base = hashtype & 0x1f
    acp  = hashtype & SIGHASH_ACP
    if base == SIGHASH_SINGLE and nIn >= len(tx_outs):
        return (1).to_bytes(32, 'little')          # the SIGHASH_SINGLE bug
    ins = [tx_ins[nIn]] if acp else tx_ins
    s = bytearray()
    s += le(version, 4)
    s += varint(len(ins))
    for i, (op, seq) in enumerate(ins):
        s += op
        signing = (acp and i == 0) or (not acp and i == nIn)
        if signing: s += varint(len(script_code)) + script_code
        else:       s += b'\x00'
        # NONE/SINGLE zero every OTHER input's sequence
        if not signing and base in (SIGHASH_NONE, SIGHASH_SINGLE): s += le(0, 4)
        else:                                                      s += le(seq, 4)
    if base == SIGHASH_NONE:
        outs = []
    elif base == SIGHASH_SINGLE:
        # outputs truncated to nIn+1, all but the last BLANKED (-1 / empty)
        outs = [(0xffffffffffffffff, b'')] * nIn + [tx_outs[nIn]]
    else:
        outs = list(tx_outs)
    s += varint(len(outs))
    for val, spk in outs:
        s += le(val, 8) + varint(len(spk)) + spk
    s += le(locktime, 4)
    s += le(hashtype, 4)
    return dsha(bytes(s))

# --- BIP143 v0 sighash -------------------------------------------------------
def bip143_sighash(tx_ins, tx_outs, nIn, script_code, amount, hashtype, version=2, locktime=0):
    """BIP143, all types. The three mid-hashes are ZEROED per the spec's own
    table -- hashPrevouts under ANYONECANPAY, hashSequence under ACP/NONE/
    SINGLE, hashOutputs under NONE and under SINGLE-past-the-last-output."""
    base = hashtype & 0x1f
    acp  = bool(hashtype & SIGHASH_ACP)
    Z = b'\x00' * 32
    hashPrevouts = Z if acp else dsha(b''.join(op for op, _ in tx_ins))
    hashSequence = (Z if (acp or base in (SIGHASH_NONE, SIGHASH_SINGLE))
                    else dsha(b''.join(le(seq, 4) for _, seq in tx_ins)))
    if base == SIGHASH_SINGLE:
        hashOutputs = (dsha(le(tx_outs[nIn][0], 8) + varint(len(tx_outs[nIn][1])) + tx_outs[nIn][1])
                       if nIn < len(tx_outs) else Z)
    elif base == SIGHASH_NONE:
        hashOutputs = Z
    else:
        hashOutputs = dsha(b''.join(le(v, 8) + varint(len(spk)) + spk for v, spk in tx_outs))
    op, seq = tx_ins[nIn]
    s = bytearray()
    s += le(version, 4) + hashPrevouts + hashSequence
    s += op
    s += varint(len(script_code)) + script_code
    s += le(amount, 8) + le(seq, 4)
    s += hashOutputs + le(locktime, 4) + le(hashtype, 4)
    return dsha(bytes(s))

# --- BIP341 taproot sighash --------------------------------------------------
def taproot_sighash(tx_ins, tx_outs, in_spks, in_amounts, nIn, hash_type,
                    version=2, locktime=0, annex=None, tapleaf_hash=None,
                    codesep_pos=0xffffffff):
    ext = 1 if tapleaf_hash is not None else 0
    sha_prevouts = sha(b''.join(op for op, _ in tx_ins))
    sha_amounts  = sha(b''.join(le(a, 8) for a in in_amounts))
    sha_spks     = sha(b''.join(varint(len(s)) + s for s in in_spks))
    sha_seqs     = sha(b''.join(le(seq, 4) for _, seq in tx_ins))
    sha_outputs  = sha(b''.join(le(v, 8) + varint(len(spk)) + spk for v, spk in tx_outs))
    spend_type = (ext * 2) + (1 if annex is not None else 0)
    m = bytearray()
    m += bytes([0])                        # epoch (prefixed as part of tag call)
    m += bytes([hash_type])
    m += le(version, 4) + le(locktime, 4)
    if (hash_type & 0x80) != 0x80:         # not ANYONECANPAY
        m += sha_prevouts + sha_amounts + sha_spks + sha_seqs
    if (hash_type & 3) not in (2, 3):      # not SINGLE/NONE -> commit all outputs
        m += sha_outputs
    m += bytes([spend_type])
    if (hash_type & 0x80) == 0x80:
        op, seq = tx_ins[nIn]
        m += op + le(in_amounts[nIn], 8) + varint(len(in_spks[nIn])) + in_spks[nIn] + le(seq, 4)
    else:
        m += le(nIn, 4)
    if annex is not None:
        a = varint(len(annex)) + annex
        m += sha(a)
    # BIP341 commits sha_single_output for SIGHASH_SINGLE ONLY. An earlier
    # draft of this harness also matched NONE (& 3 == 2), which never fired
    # because only DEFAULT was used -- it would have silently produced wrong
    # sighashes the moment NONE was exercised.
    if (hash_type & 3) == 3:               # SINGLE
        m += sha(le(tx_outs[nIn][0], 8) + varint(len(tx_outs[nIn][1])) + tx_outs[nIn][1])
    if ext:
        m += tapleaf_hash + bytes([0]) + le(codesep_pos, 4)
    # tag = "TapSighash", and the epoch byte 0 is INSIDE the tagged message
    t = hashlib.sha256(b'TapSighash').digest()
    return hashlib.sha256(t + t + bytes(m)).digest()

def tapleaf(script, ver=0xc0):
    return tagged('TapLeaf', bytes([ver]) + varint(len(script)) + script)
def taptweak(internal_x, merkle):
    return tagged('TapTweak', internal_x + merkle)

# --- tx assembly -------------------------------------------------------------
PREV_TXID = bytes.fromhex('11'*32)     # synthetic funding txid (never on chain)
def outpoint(idx): return PREV_TXID + le(idx, 4)

def serialize_tx(version, ins, outs, locktime, witnesses=None):
    """ins: [(outpoint, scriptSig_bytes, sequence)]; witnesses: [[item,...]] or None."""
    s = bytearray(); s += le(version, 4)
    segwit = witnesses is not None and any(witnesses)
    if segwit: s += b'\x00\x01'
    s += varint(len(ins))
    for op, ss, seq in ins:
        s += op + varint(len(ss)) + ss + le(seq, 4)
    s += varint(len(outs))
    for v, spk in outs:
        s += le(v, 8) + varint(len(spk)) + spk
    if segwit:
        for w in witnesses:
            s += varint(len(w))
            for item in w: s += varint(len(item)) + item
    s += le(locktime, 4)
    return bytes(s)

# A throwaway destination output (P2WPKH of a fixed key) every synth pays to.
_DEST_PRIV, _DEST_PUB = keypair(0x22)
DEST_SPK = b'\x00\x14' + hash160(_DEST_PUB)
DEST_VAL = 90000
IN_VAL   = 100000

# ============================================================================
# a synthesized case: the valid spend + rule-targeted mutations
# ============================================================================
class Case:
    """One synthesized spend and its mutations, in the shape verify_line reads.
    kind drives the verb: 'legacy'->VERIFY, 'v0'->WITVERIFY, 'v1'->TAPVERIFY."""
    def __init__(self, feature, kind, flags, spk_hex, tx_hex, ss_hex, amount,
                 prevouts, idx=0):
        self.feature = feature
        self.d = {'kind': kind, 'idx': idx, 'flags': flags,
                  'tx_hex': tx_hex, 'ss_hex': ss_hex, 'scriptsig_hex': ss_hex,
                  'spk_hex': spk_hex, 'amount': amount, 'prevouts': prevouts,
                  'height': 0, 'txid': feature, 'witness': kind in ('v0', 'v1')}
        self.muts = []          # list of (name, kwargs) -> expect BOTH reject
    def add_mut(self, name, **kw): self.muts.append((name, kw))

# --- feature: multisig (bare, P2SH, P2WSH) ----------------------------------
def _multisig_script(m, pubs):
    s = bytes([0x50 + m])
    for p in pubs: s += pushdata(p)
    s += bytes([0x50 + len(pubs)]) + bytes([OP_CHECKMULTISIG])
    return s

def synth_multisig(variant):
    """variant in {'bare','p2sh','p2wsh'}. 2-of-3, signed by keys 0 and 1."""
    keys = [keypair(0x30 + i) for i in range(3)]
    pubs = [pub for _, pub in keys]
    redeem = _multisig_script(2, pubs)

    if variant == 'bare':
        spk = redeem; kind = 'legacy'
    elif variant == 'p2sh':
        spk = bytes([OP_HASH160]) + pushdata(hash160(redeem)) + bytes([OP_EQUAL]); kind = 'legacy'
    else:
        spk = b'\x00\x20' + sha(redeem); kind = 'v0'

    seq = 0xffffffff
    ins = [(outpoint(0), b'', seq)]
    outs = [(DEST_VAL, DEST_SPK)]
    tx_ins = [(outpoint(0), seq)]

    if kind == 'legacy':
        sh = legacy_sighash(tx_ins, outs, 0, redeem, 1)
        sigs = [ecdsa_sig(keys[0][0], sh, 1), ecdsa_sig(keys[1][0], sh, 1)]
        # scriptSig: OP_0 <sig0> <sig1> [redeem if p2sh]
        ss = bytes([OP_0]) + pushdata(sigs[0]) + pushdata(sigs[1])
        if variant == 'p2sh': ss += pushdata(redeem)
        tx = serialize_tx(1, [(outpoint(0), ss, seq)], outs, 0)
        c = Case('multisig-' + variant, 'legacy', F_ALL, spk.hex(), tx.hex(),
                 ss.hex(), IN_VAL, [(IN_VAL, spk.hex())])
        # mutations flip specific multisig rules; each must be REJECTED by both
        c.add_mut('nulldummy: dummy OP_1 not OP_0',
                  mutated_ss_hex=(bytes([OP_TRUE]) + pushdata(sigs[0]) + pushdata(sigs[1]) +
                                  (pushdata(redeem) if variant=='p2sh' else b'')).hex())
        c.add_mut('sig order swapped (0<->1)',
                  mutated_ss_hex=(bytes([OP_0]) + pushdata(sigs[1]) + pushdata(sigs[0]) +
                                  (pushdata(redeem) if variant=='p2sh' else b'')).hex())
        c.add_mut('one signature dropped (2-of-3 -> 1 sig)',
                  mutated_ss_hex=(bytes([OP_0]) + pushdata(sigs[0]) +
                                  (pushdata(redeem) if variant=='p2sh' else b'')).hex())
        # a third valid sig (key2) appended -> too many sigs for OP_CHECKMULTISIG
        sig2 = ecdsa_sig(keys[2][0], sh, 1)
        c.add_mut('extra third signature',
                  mutated_ss_hex=(bytes([OP_0]) + pushdata(sigs[0]) + pushdata(sigs[1]) + pushdata(sig2) +
                                  (pushdata(redeem) if variant=='p2sh' else b'')).hex())
        return c
    else:
        sh = bip143_sighash(tx_ins, outs, 0, redeem, IN_VAL, 1)
        sigs = [ecdsa_sig(keys[0][0], sh, 1), ecdsa_sig(keys[1][0], sh, 1)]
        wit = [[b'', sigs[0], sigs[1], redeem]]
        tx = serialize_tx(2, [(outpoint(0), b'', seq)], outs, 0, wit)
        c = Case('multisig-p2wsh', 'v0', F_ALL, spk.hex(), tx.hex(), '', IN_VAL,
                 [(IN_VAL, spk.hex())])
        def rebuild(witstack):
            return serialize_tx(2, [(outpoint(0), b'', seq)], outs, 0, [witstack]).hex()
        c.add_mut('nulldummy: dummy = OP_1 byte',
                  mutated_tx_hex=rebuild([b'\x01', sigs[0], sigs[1], redeem]))
        c.add_mut('sig order swapped',
                  mutated_tx_hex=rebuild([b'', sigs[1], sigs[0], redeem]))
        c.add_mut('one signature dropped',
                  mutated_tx_hex=rebuild([b'', sigs[0], redeem]))
        return c

# --- feature: CLTV / CSV timelock paths -------------------------------------
def synth_cltv():
    priv, pub = keypair(0x40)
    LOCK = 500000                          # a height-based CLTV threshold
    redeem = push_num(LOCK) + bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP]) + pushdata(pub) + bytes([OP_CHECKSIG])
    spk = bytes([OP_HASH160]) + pushdata(hash160(redeem)) + bytes([OP_EQUAL])
    # to satisfy CLTV: tx.nLockTime >= LOCK and input nSequence != 0xffffffff
    seq = 0xfffffffe; locktime = LOCK
    tx_ins = [(outpoint(0), seq)]; outs = [(DEST_VAL, DEST_SPK)]
    sh = legacy_sighash(tx_ins, outs, 0, redeem, 1, version=2, locktime=locktime)
    sig = ecdsa_sig(priv, sh, 1)
    ss = pushdata(sig) + pushdata(redeem)
    tx = serialize_tx(2, [(outpoint(0), ss, seq)], outs, locktime)
    c = Case('cltv', 'legacy', F_ALL, spk.hex(), tx.hex(), ss.hex(), IN_VAL, [(IN_VAL, spk.hex())])
    # rule mutations: rebuild the whole tx (nLockTime/nSequence live there)
    def rebuild(nlock, nseq):
        sh2 = legacy_sighash([(outpoint(0), nseq)], outs, 0, redeem, 1, 2, nlock)
        sig2 = ecdsa_sig(priv, sh2, 1); ss2 = pushdata(sig2) + pushdata(redeem)
        return serialize_tx(2, [(outpoint(0), ss2, nseq)], outs, nlock).hex()
    c.add_mut('nLockTime below the CLTV threshold', mutated_tx_hex=rebuild(LOCK-1, 0xfffffffe))
    c.add_mut('nSequence final (0xffffffff) disables CLTV', mutated_tx_hex=rebuild(LOCK, 0xffffffff))
    # time-based locktime (>=5e8) against a height-based CLTV literal: type mismatch
    c.add_mut('locktime type mismatch (time vs height)', mutated_tx_hex=rebuild(500000000, 0xfffffffe))
    return c

def synth_csv():
    priv, pub = keypair(0x41)
    CSV = 10                                # relative locktime, 10 blocks
    redeem = push_num(CSV) + bytes([OP_CHECKSEQUENCEVERIFY, OP_DROP]) + pushdata(pub) + bytes([OP_CHECKSIG])
    spk = bytes([OP_HASH160]) + pushdata(hash160(redeem)) + bytes([OP_EQUAL])
    # satisfy CSV: tx.version >= 2 and input nSequence encodes >= CSV (type-flag 0, value CSV)
    seq = CSV; outs = [(DEST_VAL, DEST_SPK)]
    tx_ins = [(outpoint(0), seq)]
    sh = legacy_sighash(tx_ins, outs, 0, redeem, 1, version=2, locktime=0)
    sig = ecdsa_sig(priv, sh, 1); ss = pushdata(sig) + pushdata(redeem)
    tx = serialize_tx(2, [(outpoint(0), ss, seq)], outs, 0)
    c = Case('csv', 'legacy', F_ALL, spk.hex(), tx.hex(), ss.hex(), IN_VAL, [(IN_VAL, spk.hex())])
    def rebuild(nseq, ver=2):
        sh2 = legacy_sighash([(outpoint(0), nseq)], outs, 0, redeem, 1, ver, 0)
        sig2 = ecdsa_sig(priv, sh2, 1); ss2 = pushdata(sig2) + pushdata(redeem)
        return serialize_tx(ver, [(outpoint(0), ss2, nseq)], outs, 0).hex()
    c.add_mut('nSequence below the CSV threshold', mutated_tx_hex=rebuild(CSV-1))
    c.add_mut('CSV disable bit set (1<<31)', mutated_tx_hex=rebuild((1 << 31) | CSV))
    c.add_mut('tx version 1 disables CSV', mutated_tx_hex=rebuild(CSV, ver=1))
    return c

# --- feature: OP_CODESEPARATOR (legacy sighash subscript) -------------------
def synth_codesep():
    priv, pub = keypair(0x50)
    # script: <pub> OP_CODESEPARATOR OP_CHECKSIG. The sighash subscript is the
    # script AFTER the last executed CODESEPARATOR -> just OP_CHECKSIG.
    redeem = pushdata(pub) + bytes([OP_CODESEPARATOR, OP_CHECKSIG])
    spk = bytes([OP_HASH160]) + pushdata(hash160(redeem)) + bytes([OP_EQUAL])
    seq = 0xffffffff; outs = [(DEST_VAL, DEST_SPK)]; tx_ins = [(outpoint(0), seq)]
    subscript = bytes([OP_CHECKSIG])       # everything after the CODESEPARATOR
    sh = legacy_sighash(tx_ins, outs, 0, subscript, 1)
    sig = ecdsa_sig(priv, sh, 1); ss = pushdata(sig) + pushdata(redeem)
    tx = serialize_tx(1, [(outpoint(0), ss, seq)], outs, 0)
    c = Case('codesep', 'legacy', F_ALL, spk.hex(), tx.hex(), ss.hex(), IN_VAL, [(IN_VAL, spk.hex())])
    # a redeemScript WITHOUT the codesep: the subscript becomes <pub>OP_CHECKSIG,
    # so the signature (made over the post-codesep subscript) no longer verifies.
    redeem_nocs = pushdata(pub) + bytes([OP_CHECKSIG])
    spk_nocs = bytes([OP_HASH160]) + pushdata(hash160(redeem_nocs)) + bytes([OP_EQUAL])
    ss_nocs = pushdata(sig) + pushdata(redeem_nocs)
    tx_nocs = serialize_tx(1, [(outpoint(0), ss_nocs, seq)], outs, 0)
    # NOTE this changes the spk too, so it is fed as its own mini-case below via
    # a mutation that swaps BOTH tx and (implicitly) the P2SH match; the harness
    # feeds spk from the case, so express it as a full-tx mutation with the
    # matching redeem embedded -- the P2SH hash check will fail, which is also a
    # valid rejection. To isolate the SIGHASH effect, also mutate with the SAME
    # spk but a moved codesep inside an equivalent-hash... not possible, so we
    # keep the honest "position matters" check: signature valid only for the
    # exact subscript.
    c.add_mut('codesep removed: subscript changes, sig invalid',
              mutated_ss_hex=ss_nocs.hex(), mutated_tx_hex=tx_nocs.hex(), alt_spk=spk_nocs.hex())
    # sign over the WRONG subscript (full redeem incl. codesep) -> reject
    sh_wrong = legacy_sighash(tx_ins, outs, 0, redeem, 1)
    sig_wrong = ecdsa_sig(priv, sh_wrong, 1)
    ss_wrong = pushdata(sig_wrong) + pushdata(redeem)
    c.add_mut('signed over pre-codesep subscript',
              mutated_ss_hex=ss_wrong.hex(),
              mutated_tx_hex=serialize_tx(1, [(outpoint(0), ss_wrong, seq)], outs, 0).hex())
    return c

# --- feature: taproot annex + script-path -----------------------------------
def synth_taproot_scriptpath(with_annex):
    ipriv = coincurve.PrivateKey(bytes([0x60]) * 32)
    internal_x = ipriv.public_key.format(True)[1:]
    spriv, spub = keypair(0x61)
    xonly_s = spub[1:]
    leaf_script = pushdata(xonly_s) + bytes([OP_CHECKSIG])
    leaf = tapleaf(leaf_script)
    tweak = taptweak(internal_x, leaf)
    # output key = internal + tweak*G ; parity from the tweaked point
    tw = coincurve.PrivateKey(tweak)
    Q = coincurve.PublicKeyXOnly.from_valid_secret  # not used; compute via add
    # coincurve: tweaked pubkey
    P = coincurve.PublicKey(b'\x02' + internal_x)     # even-Y lift of x
    Qpk = coincurve.PublicKey.combine_keys([P, tw.public_key])
    Qcomp = Qpk.format(True)
    out_x = Qcomp[1:]; out_parity = Qcomp[0] & 1
    spk = b'\x51\x20' + out_x                          # OP_1 <32-byte x>
    seq = 0xffffffff; outs = [(DEST_VAL, DEST_SPK)]
    tx_ins = [(outpoint(0), seq)]
    in_spks = [spk]; in_amts = [IN_VAL]
    annex = (b'\x50' + b'\xde\xad\xbe\xef') if with_annex else None
    sh = taproot_sighash(tx_ins, outs, in_spks, in_amts, 0, 0x00, version=2,
                         annex=annex, tapleaf_hash=leaf, codesep_pos=0xffffffff)
    sig = spriv.sign_schnorr(sh, bytes(32))
    control = bytes([0xc0 | out_parity]) + internal_x   # no siblings (single leaf)
    wit_items = [sig, leaf_script, control]
    if annex is not None: wit_items.append(annex)
    tx = serialize_tx(2, [(outpoint(0), b'', seq)], outs, 0, [wit_items])
    feat = 'taproot-scriptpath' + ('-annex' if with_annex else '')
    c = Case(feat, 'v1', F_ALL, spk.hex(), tx.hex(), '', IN_VAL, [(IN_VAL, spk.hex())])
    def rebuild(items):
        return serialize_tx(2, [(outpoint(0), b'', seq)], outs, 0, [items]).hex()
    if with_annex:
        # corrupt the annex payload: the sighash committed to it, so the sig
        # is now invalid -- but ONLY if the verifier actually commits to the
        # annex, which is the whole point.
        bad_annex = b'\x50' + b'\xde\xad\xbe\xf0'
        c.add_mut('annex payload corrupted', mutated_tx_hex=rebuild([sig, leaf_script, control, bad_annex]))
        # drop the annex entirely: spend_type changes, sig invalid
        c.add_mut('annex dropped', mutated_tx_hex=rebuild([sig, leaf_script, control]))
    else:
        # add an annex that was NOT signed over: spend_type flips, sig invalid
        c.add_mut('unsigned annex added', mutated_tx_hex=rebuild([sig, leaf_script, control, b'\x50\x01']))
    # corrupt the control block parity bit -> commitment check fails
    bad_ctrl = bytes([control[0] ^ 1]) + control[1:]
    items = [sig, leaf_script, bad_ctrl] + ([annex] if annex else [])
    c.add_mut('control-block parity flipped', mutated_tx_hex=rebuild(items))
    # flip a signature byte -> Schnorr verify fails
    bad_sig = bytearray(sig); bad_sig[10] ^= 0x01
    items = [bytes(bad_sig), leaf_script, control] + ([annex] if annex else [])
    c.add_mut('schnorr signature bit flipped', mutated_tx_hex=rebuild(items))
    return c

# ============================================================================
# driving both engines
# ============================================================================
def line_for(d, engine, mutated_tx_hex=None, mutated_ss_hex=None, alt_spk=None):
    tx = mutated_tx_hex if mutated_tx_hex is not None else d['tx_hex']
    spk = alt_spk if alt_spk is not None else d['spk_hex']
    kind = d['kind']
    if kind == 'v1':
        # every prevout, in input order: BIP341's sha_amounts/sha_scriptpubkeys
        # commit to ALL of them, so a 2-input frame must supply both or the
        # sighash differs and the spend "fails" for a harness reason.
        parts = ['TAPVERIFY', str(d['idx']), tx, str(len(d['prevouts']))]
        for amt, sp in d['prevouts']:
            parts += [str(amt), sp]
        return ' '.join(parts)
    if kind == 'v0':
        # ROUTING, as in spend_corpus_diff.py: Core's oracle has no WITVERIFY
        # verb -- its TAPVERIFY is full VerifyScript and covers every witness
        # version. The ASM side splits by version (sv_verify_witness_v0 vs
        # taproot_verify_input), exactly as daemon/tx_verify.c does, so it
        # needs WITVERIFY. Sending WITVERIFY to Core makes it answer nothing,
        # which this harness reports as an engine failure rather than
        # silently scoring the ASM's lone verdict as agreement -- that is how
        # this very bug surfaced.
        if engine == 'core':
            parts = ['TAPVERIFY', str(d['idx']), tx, str(len(d['prevouts']))]
            for amt, sp in d['prevouts']:
                parts += [str(amt), sp]
            return ' '.join(parts)
        # The MUTATED scriptSig must reach the ASM side too. Core reads the
        # scriptSig out of the transaction it is handed, so a mutation that
        # only rewrote the tx would leave the two engines looking at DIFFERENT
        # scriptSigs -- which is precisely what produced the first "false
        # accept" reported for the P2SH-wrapped cases, and it was this
        # harness's fault, not the node's.
        ss = mutated_ss_hex if mutated_ss_hex is not None else (d.get('ss_hex') or '-')
        return 'WITVERIFY %08x %d %s %d %s %s' % (d['flags'], d['idx'], tx,
                                                  d['amount'], spk, ss)
    ss = mutated_ss_hex if mutated_ss_hex is not None else d['scriptsig_hex']
    return 'VERIFY %08x %d %s %s %s' % (d['flags'], d['idx'], tx, ss, spk)

def run_case(c, core, asm, res):
    d = c.d
    res['cases'] += 1
    res['by_feature'].setdefault(c.feature, {'accept': 0, 'mut_ok': 0, 'div': 0})
    # 1) the valid spend: Core MUST accept (validates our synthesis); ASM MUST agree
    lc = line_for(d, 'core'); la = line_for(d, 'asm')
    c_ok, c_err = core.ask(lc); a_ok, a_err = asm.ask(la)
    if c_ok in ('unsupported', None) or a_ok in ('unsupported', None):
        res['engine_fail'].append({'feature': c.feature, 'phase': 'accept',
                                   'core': c_ok, 'asm': a_ok, 'line': la[:200]})
        return
    if c_ok != 1:
        # our construction is wrong -- fail LOUDLY, do not compare further
        res['synth_bad'].append({'feature': c.feature, 'core_err': c_err, 'line': lc[:300]})
        return
    if a_ok != 1:
        res['accept_div'].append({'feature': c.feature, 'core': c_ok, 'asm': a_ok,
                                  'core_err': c_err, 'asm_err': a_err})
        res['by_feature'][c.feature]['div'] += 1
    else:
        res['accept_ok'] += 1
        res['by_feature'][c.feature]['accept'] += 1
    # 2) rule mutations: BOTH must reject, in agreement
    for name, kw in c.muts:
        lc = line_for(d, 'core', **kw); la = line_for(d, 'asm', **kw)
        mc_ok, mc_err = core.ask(lc); ma_ok, ma_err = asm.ask(la)
        if mc_ok in ('unsupported', None) or ma_ok in ('unsupported', None):
            res['engine_fail'].append({'feature': c.feature, 'mutation': name,
                                       'core': mc_ok, 'asm': ma_ok}); continue
        res['muts'] += 1
        if mc_ok == 1:
            # the mutation FAILED TO FLIP the verdict in Core -- our mutation is
            # not actually rule-violating; record so it is not mistaken for parity
            res['mut_didnt_flip'].append({'feature': c.feature, 'mutation': name})
            continue
        if mc_ok == ma_ok:
            res['mut_agree'] += 1
            res['by_feature'][c.feature]['mut_ok'] += 1
        else:
            rec = {'feature': c.feature, 'mutation': name, 'core': mc_ok, 'asm': ma_ok,
                   'core_err': mc_err, 'asm_err': ma_err, 'line': la[:300]}
            res['mut_div'].append(rec)
            res['by_feature'][c.feature]['div'] += 1
            if ma_ok == 1 and mc_ok == 0:
                res['false_accept'].append(rec)

# ============================================================================
# BREADTH: SIGHASH combinations, P2SH-wrapped witness, multi-leaf taproot
# ============================================================================
# A 2-in / 2-out frame, so NONE/SINGLE/ANYONECANPAY are all MEANINGFUL: SINGLE
# has a matching output to commit to, ACP has other inputs to exclude, and NONE
# has outputs to drop. A 1-in/1-out frame makes several of these degenerate and
# would test far less than it appears to.
SIGHASH_NAMES = [('ALL', 0x01), ('NONE', 0x02), ('SINGLE', 0x03),
                 ('ALL|ACP', 0x81), ('NONE|ACP', 0x82), ('SINGLE|ACP', 0x83)]

_OTHER_PRIV, _OTHER_PUB = keypair(0x77)
OTHER_SPK = b'\x00\x14' + hash160(_OTHER_PUB)     # input 1's prevout (never verified)
OUT2_SPK  = b'\x00\x14' + hash160(hash160(b'out2'))

def _frame2():
    """(tx_ins, tx_outs) for the 2-in/2-out frame."""
    ins  = [(outpoint(0), 0xfffffffd), (outpoint(1), 0xfffffffd)]
    outs = [(DEST_VAL, DEST_SPK), (DEST_VAL // 2, OUT2_SPK)]
    return ins, outs

def synth_sighash_legacy(name, ht):
    """P2PKH input 0 signed with `ht`; input 1 left unsigned (never verified)."""
    priv, pub = keypair(0x80)
    spk = bytes([OP_DUP, OP_HASH160]) + pushdata(hash160(pub)) + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    ins, outs = _frame2()
    sh = legacy_sighash(ins, outs, 0, spk, ht, version=1, locktime=0)
    sig = ecdsa_sig(priv, sh, ht)
    ss = pushdata(sig) + pushdata(pub)
    tx = serialize_tx(1, [(outpoint(0), ss, 0xfffffffd), (outpoint(1), b'', 0xfffffffd)], outs, 0)
    c = Case('sighash-legacy-' + name, 'legacy', F_ALL, spk.hex(), tx.hex(), ss.hex(),
             IN_VAL, [(IN_VAL, spk.hex()), (IN_VAL, OTHER_SPK.hex())])
    # the hashtype byte itself is signed data: changing it must invalidate
    for other, oht in SIGHASH_NAMES:
        if oht == ht: continue
        bad = pushdata(sig[:-1] + bytes([oht])) + pushdata(pub)
        c.add_mut('hashtype byte %s->%s' % (name, other), mutated_ss_hex=bad.hex())
        break
    # flipping a byte of the signed OUTPUT must break ALL and SINGLE (which
    # commit to it) -- for NONE it legitimately does not, so it is only added
    # where it is genuinely rule-violating.
    if (ht & 0x1f) != SIGHASH_NONE:
        outs_b = [(DEST_VAL + 1, DEST_SPK), outs[1]]
        txb = serialize_tx(1, [(outpoint(0), ss, 0xfffffffd), (outpoint(1), b'', 0xfffffffd)], outs_b, 0)
        c.add_mut('committed output value changed', mutated_tx_hex=txb.hex())
    return c

def synth_sighash_v0(name, ht):
    """Native P2WPKH input 0 signed with `ht` (BIP143)."""
    priv, pub = keypair(0x81)
    h = hash160(pub)
    spk = b'\x00\x14' + h
    script_code = bytes([OP_DUP, OP_HASH160]) + pushdata(h) + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    ins, outs = _frame2()
    sh = bip143_sighash(ins, outs, 0, script_code, IN_VAL, ht)
    sig = ecdsa_sig(priv, sh, ht)
    wits = [[sig, pub], []]
    tx = serialize_tx(2, [(outpoint(0), b'', 0xfffffffd), (outpoint(1), b'', 0xfffffffd)], outs, 0, wits)
    c = Case('sighash-v0-' + name, 'v0', F_ALL, spk.hex(), tx.hex(), '', IN_VAL,
             [(IN_VAL, spk.hex()), (IN_VAL, OTHER_SPK.hex())])
    def rebuild(w0, o=outs):
        return serialize_tx(2, [(outpoint(0), b'', 0xfffffffd), (outpoint(1), b'', 0xfffffffd)],
                            o, 0, [w0, []]).hex()
    c.add_mut('hashtype byte flipped', mutated_tx_hex=rebuild([sig[:-1] + bytes([ht ^ 0x01]), pub]))
    if (ht & 0x1f) != SIGHASH_NONE:
        c.add_mut('committed output value changed',
                  mutated_tx_hex=rebuild([sig, pub], [(DEST_VAL + 1, DEST_SPK), outs[1]]))
    if not (ht & SIGHASH_ACP):
        # the OTHER input's outpoint is committed via hashPrevouts unless ACP
        alt = [(outpoint(0), b'', 0xfffffffd), (outpoint(9), b'', 0xfffffffd)]
        c.add_mut('other input outpoint changed (hashPrevouts)',
                  mutated_tx_hex=serialize_tx(2, alt, outs, 0, [[sig, pub], []]).hex())
    return c

def _tr_key(seed_byte, merkle=b''):
    """(tweaked_priv, internal_x, output_x, output_parity) for a key-path spend."""
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    d = coincurve.PrivateKey(bytes([seed_byte]) * 32)
    if d.public_key.format(True)[0] == 3:      # lift_x wants even Y
        d = coincurve.PrivateKey((N - int.from_bytes(d.secret, 'big')).to_bytes(32, 'big'))
    ix = d.public_key.format(True)[1:]
    dt = d.add(tagged('TapTweak', ix + merkle))
    Q = dt.public_key.format(True)
    return dt, ix, Q[1:], Q[0] & 1

def synth_sighash_taproot(name, ht):
    """Taproot KEY-PATH spend signed with `ht`. hash_type 0x00 (DEFAULT) also
    exercises BIP341's 64-byte signature form, where the byte is ABSENT."""
    dt, ix, ox, par = _tr_key(0x82)
    spk = b'\x51\x20' + ox
    ins, outs = _frame2()
    in_spks = [spk, OTHER_SPK]; in_amts = [IN_VAL, IN_VAL]
    sh = taproot_sighash(ins, outs, in_spks, in_amts, 0, ht, version=2)
    sig = dt.sign_schnorr(sh, bytes(32))
    if ht != 0x00: sig = sig + bytes([ht])     # 65-byte form
    wits = [[sig], []]
    tx = serialize_tx(2, [(outpoint(0), b'', 0xfffffffd), (outpoint(1), b'', 0xfffffffd)], outs, 0, wits)
    c = Case('sighash-taproot-' + name, 'v1', F_ALL, spk.hex(), tx.hex(), '', IN_VAL,
             [(IN_VAL, spk.hex()), (IN_VAL, OTHER_SPK.hex())])
    def rebuild(w0, o=outs):
        return serialize_tx(2, [(outpoint(0), b'', 0xfffffffd), (outpoint(1), b'', 0xfffffffd)],
                            o, 0, [w0, []]).hex()
    bad = bytearray(sig); bad[5] ^= 0x01
    c.add_mut('schnorr signature bit flipped', mutated_tx_hex=rebuild([bytes(bad)]))
    if ht == 0x00:
        # BIP341: DEFAULT must be the 64-byte form. Appending an explicit 0x00
        # byte is the one encoding the spec singles out as INVALID.
        c.add_mut('explicit 0x00 hashtype byte appended (must be 64-byte form)',
                  mutated_tx_hex=rebuild([sig + b'\x00']))
    else:
        c.add_mut('hashtype byte changed', mutated_tx_hex=rebuild([sig[:-1] + bytes([ht ^ 0x01])]))
    if (ht & 0x1f) != SIGHASH_NONE:
        c.add_mut('committed output value changed',
                  mutated_tx_hex=rebuild([sig], [(DEST_VAL + 1, DEST_SPK), outs[1]]))
    return c

def synth_sighash_single_bug():
    """The SIGHASH_SINGLE bug: input index >= number of outputs.

    Satoshi's SignatureHash returns the CONSTANT uint256(1) instead of
    erroring, and a signature over that constant is perfectly valid -- so the
    spend must be ACCEPTED by both engines. It is a live consensus rule that
    real mainnet transactions have relied on, and the 2-in/2-out frame above
    can never reach it (input 0 always has a matching output), so it gets its
    own 2-in/1-out frame with input 1 signed."""
    priv, pub = keypair(0x88)
    spk = bytes([OP_DUP, OP_HASH160]) + pushdata(hash160(pub)) + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    ins  = [(outpoint(0), 0xfffffffd), (outpoint(1), 0xfffffffd)]
    outs = [(DEST_VAL, DEST_SPK)]                  # ONE output, input index 1
    sh = legacy_sighash(ins, outs, 1, spk, 0x03, version=1, locktime=0)
    assert sh == (1).to_bytes(32, 'little'), 'the bug case did not trigger'
    sig = ecdsa_sig(priv, sh, 0x03)
    ss = pushdata(sig) + pushdata(pub)
    tx = serialize_tx(1, [(outpoint(0), b'', 0xfffffffd), (outpoint(1), ss, 0xfffffffd)], outs, 0)
    c = Case('sighash-legacy-SINGLE-bug', 'legacy', F_ALL, spk.hex(), tx.hex(), ss.hex(),
             IN_VAL, [(IN_VAL, OTHER_SPK.hex()), (IN_VAL, spk.hex())], idx=1)
    # the signature still has to be a real signature over that constant
    bad = bytearray(sig); bad[10] ^= 0x01
    c.add_mut('signature over the constant corrupted',
              mutated_ss_hex=(pushdata(bytes(bad)) + pushdata(pub)).hex())
    # a DIFFERENT pubkey must not satisfy the P2PKH
    _, other = keypair(0x89)
    c.add_mut('wrong pubkey', mutated_ss_hex=(pushdata(sig) + pushdata(other)).hex())
    return c

def synth_p2sh_wrapped(variant):
    """P2SH-wrapped witness: the scriptSig is ONE push of the witness program,
    and the real program lives in the redeemScript. Both engines must agree on
    the unwrapping, not just on the inner script."""
    priv, pub = keypair(0x90)
    ins, outs = _frame2()
    if variant == 'p2sh-p2wpkh':
        h = hash160(pub)
        redeem = b'\x00\x14' + h                       # the witness program
        script_code = bytes([OP_DUP, OP_HASH160]) + pushdata(h) + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
        sh = bip143_sighash(ins, outs, 0, script_code, IN_VAL, 0x01)
        sig = ecdsa_sig(priv, sh, 0x01)
        wit0 = [sig, pub]
    else:                                              # p2sh-p2wsh (2-of-2)
        k2, p2 = keypair(0x91)
        ws = _multisig_script(2, [pub, p2])
        redeem = b'\x00\x20' + sha(ws)
        sh = bip143_sighash(ins, outs, 0, ws, IN_VAL, 0x01)
        sig = ecdsa_sig(priv, sh, 0x01); sig2 = ecdsa_sig(k2, sh, 0x01)
        wit0 = [b'', sig, sig2, ws]
    spk = bytes([OP_HASH160]) + pushdata(hash160(redeem)) + bytes([OP_EQUAL])
    ss = pushdata(redeem)
    tx = serialize_tx(2, [(outpoint(0), ss, 0xfffffffd), (outpoint(1), b'', 0xfffffffd)],
                      outs, 0, [wit0, []])
    c = Case(variant, 'v0', F_ALL, spk.hex(), tx.hex(), ss.hex(), IN_VAL,
             [(IN_VAL, spk.hex()), (IN_VAL, OTHER_SPK.hex())])
    def rebuild(w0, sscript=ss):
        return serialize_tx(2, [(outpoint(0), sscript, 0xfffffffd), (outpoint(1), b'', 0xfffffffd)],
                            outs, 0, [w0, []]).hex()
    bad = bytearray(wit0[1] if variant == 'p2sh-p2wsh' else wit0[0]); bad[10] ^= 0x01
    w = list(wit0); w[1 if variant == 'p2sh-p2wsh' else 0] = bytes(bad)
    c.add_mut('signature bit flipped', mutated_tx_hex=rebuild(w))
    # a scriptSig that is not exactly the one push of the program -> the P2SH
    # hash no longer matches, and (BIP141) the scriptSig must be push-only
    c.add_mut('extra opcode appended to scriptSig',
              mutated_tx_hex=rebuild(wit0, ss + bytes([OP_TRUE])),
              mutated_ss_hex=(ss + bytes([OP_TRUE])).hex())
    if variant == 'p2sh-p2wsh':
        c.add_mut('nulldummy violated in the wrapped multisig',
                  mutated_tx_hex=rebuild([b'\x01', wit0[1], wit0[2], wit0[3]]))
    return c

def synth_taproot_multileaf(nleaves, which):
    """A taproot tree of `nleaves` leaves, spending leaf `which`. The control
    block then carries a real MERKLE PATH (nleaves-1 levels deep for a
    balanced tree), so the path reconstruction is exercised rather than the
    single-leaf degenerate case where the path is empty."""
    spriv, spub = keypair(0xA0 + which)
    scripts = []
    for i in range(nleaves):
        _, p = keypair(0xA0 + i)
        scripts.append(pushdata(p[1:]) + bytes([OP_CHECKSIG]))
    leaves = [tapleaf(sc) for sc in scripts]
    # build a balanced tree, recording the sibling path for `which`
    path, level, idx = [], list(leaves), which
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                a, b = level[i], level[i+1]
                if i == (idx & ~1):
                    path.append(b if idx % 2 == 0 else a)
                nxt.append(tagged('TapBranch', min(a, b) + max(a, b)))
            else:
                nxt.append(level[i])          # odd node promoted unchanged
        level = nxt; idx //= 2
    root = level[0]
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    d = coincurve.PrivateKey(bytes([0xB0]) * 32)
    if d.public_key.format(True)[0] == 3:
        d = coincurve.PrivateKey((N - int.from_bytes(d.secret, 'big')).to_bytes(32, 'big'))
    ix = d.public_key.format(True)[1:]
    Q = coincurve.PublicKey.combine_keys(
        [coincurve.PublicKey(b'\x02' + ix),
         coincurve.PrivateKey(tagged('TapTweak', ix + root)).public_key]).format(True)
    ox, par = Q[1:], Q[0] & 1
    spk = b'\x51\x20' + ox
    ins, outs = _frame2()
    in_spks = [spk, OTHER_SPK]; in_amts = [IN_VAL, IN_VAL]
    leaf = leaves[which]
    sh = taproot_sighash(ins, outs, in_spks, in_amts, 0, 0x00, version=2, tapleaf_hash=leaf)
    sig = spriv.sign_schnorr(sh, bytes(32))
    control = bytes([0xc0 | par]) + ix + b''.join(path)
    wits = [[sig, scripts[which], control], []]
    tx = serialize_tx(2, [(outpoint(0), b'', 0xfffffffd), (outpoint(1), b'', 0xfffffffd)], outs, 0, wits)
    feat = 'taproot-tree%d-leaf%d' % (nleaves, which)
    c = Case(feat, 'v1', F_ALL, spk.hex(), tx.hex(), '', IN_VAL,
             [(IN_VAL, spk.hex()), (IN_VAL, OTHER_SPK.hex())])
    def rebuild(items):
        return serialize_tx(2, [(outpoint(0), b'', 0xfffffffd), (outpoint(1), b'', 0xfffffffd)],
                            outs, 0, [items, []]).hex()
    # corrupt one sibling in the path -> a different root -> commitment fails
    if path:
        badpath = bytearray(b''.join(path)); badpath[0] ^= 0x01
        c.add_mut('merkle path sibling corrupted',
                  mutated_tx_hex=rebuild([sig, scripts[which], bytes([0xc0 | par]) + ix + bytes(badpath)]))
        # drop the last sibling: a SHORTER path is a different (shallower) tree
        c.add_mut('merkle path truncated by one level',
                  mutated_tx_hex=rebuild([sig, scripts[which],
                                          bytes([0xc0 | par]) + ix + b''.join(path[:-1])]))
    c.add_mut('control block parity flipped',
              mutated_tx_hex=rebuild([sig, scripts[which], bytes([(0xc0 | par) ^ 1]) + ix + b''.join(path)]))
    # present a DIFFERENT leaf's script with this leaf's path
    other = (which + 1) % nleaves
    c.add_mut('wrong leaf script for this path',
              mutated_tx_hex=rebuild([sig, scripts[other], control]))
    return c

def all_cases():
    cs = []
    for v in ('bare', 'p2sh', 'p2wsh'): cs.append(synth_multisig(v))
    cs.append(synth_cltv()); cs.append(synth_csv())
    cs.append(synth_codesep())
    cs.append(synth_taproot_scriptpath(False))
    cs.append(synth_taproot_scriptpath(True))
    # ---- breadth (2026-08-26) ----
    for name, ht in SIGHASH_NAMES:
        cs.append(synth_sighash_legacy(name, ht))
        cs.append(synth_sighash_v0(name, ht))
    # taproot adds DEFAULT (0x00), whose signature is the 64-byte form
    for name, ht in [('DEFAULT', 0x00)] + SIGHASH_NAMES:
        cs.append(synth_sighash_taproot(name, ht))
    cs.append(synth_sighash_single_bug())
    for v in ('p2sh-p2wpkh', 'p2sh-p2wsh'): cs.append(synth_p2sh_wrapped(v))
    for n, w in ((2, 0), (2, 1), (3, 2), (4, 1), (4, 3)):
        cs.append(synth_taproot_multileaf(n, w))
    return cs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only', default=None, help='substring filter on feature name')
    ap.add_argument('--oracle', default=ORACLE)
    ap.add_argument('--shim', default=SHIM)
    ap.add_argument('--seed', type=int, default=20260826)
    args = ap.parse_args()
    for p in (args.oracle, args.shim):
        if not os.path.exists(p): print('missing engine: %s' % p); return 2

    cases = [c for c in all_cases() if not args.only or args.only in c.feature]
    core = Engine(args.oracle, 'core'); asm = Engine(args.shim, 'asm')
    res = {'cases': 0, 'accept_ok': 0, 'muts': 0, 'mut_agree': 0,
           'accept_div': [], 'mut_div': [], 'false_accept': [], 'engine_fail': [],
           'synth_bad': [], 'mut_didnt_flip': [], 'by_feature': {}}
    t0 = time.time()
    for c in cases:
        run_case(c, core, asm, res)
        bf = res['by_feature'][c.feature]
        print('  %-24s accept=%d mut_ok=%d div=%d'
              % (c.feature, bf['accept'], bf['mut_ok'], bf['div']))
    core.quit(); asm.quit()
    res['elapsed'] = round(time.time() - t0, 1)
    ndiv = len(res['accept_div']) + len(res['mut_div'])
    nbad = len(res['synth_bad'])

    with open(REPORT_JSON, 'w') as f: json.dump(res, f, indent=1)
    with open(REPORT_TXT, 'w') as f:
        f.write('Synthesized feature-depth differential vs Core\n')
        f.write('generated: %s  elapsed: %ss\n\n'
                % (time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), res['elapsed']))
        f.write('cases: %d  accept-parity ok: %d\n' % (res['cases'], res['accept_ok']))
        f.write('rule mutations: %d (agree %d)\n' % (res['muts'], res['mut_agree']))
        f.write('per feature (accept / mutations-agreed / divergences):\n')
        for feat, bf in sorted(res['by_feature'].items()):
            f.write('  %-24s accept=%d  mut_ok=%d  div=%d\n'
                    % (feat, bf['accept'], bf['mut_ok'], bf['div']))
        if res['mut_didnt_flip']:
            f.write('\nmutations that did not flip Core (excluded from parity): %d\n'
                    % len(res['mut_didnt_flip']))
            for m in res['mut_didnt_flip']:
                f.write('  %s / %s\n' % (m['feature'], m['mutation']))
        if nbad:
            f.write('\nSYNTHESIS ERRORS (Core rejected a spend we built as valid): %d\n' % nbad)
            for b in res['synth_bad']: f.write('  ' + json.dumps(b) + '\n')
        if res['engine_fail']:
            f.write('\nengine failures: %d\n' % len(res['engine_fail']))
        f.write('\n')
        if ndiv == 0 and nbad == 0:
            f.write('ZERO DIVERGENCES across synthesized feature spends and their '
                    'rule-targeted mutations.\n')
        else:
            f.write('DIVERGENCES: %d  FALSE-ACCEPTS: %d  SYNTHESIS-ERRORS: %d\n\n'
                    % (ndiv, len(res['false_accept']), nbad))
            for d in (res['false_accept'] or res['accept_div'] + res['mut_div'])[:40]:
                f.write(json.dumps(d) + '\n')
    print('\n%s' % open(REPORT_TXT).read())
    return 0 if (ndiv == 0 and nbad == 0) else 1

if __name__ == '__main__':
    sys.exit(main())
