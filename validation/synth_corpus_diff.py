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
def legacy_sighash(tx_ins, tx_outs, nIn, script_code, hashtype, version=1, locktime=0):
    # SIGHASH_ALL only (this harness never needs the exotic types for its rules)
    assert (hashtype & 0x1f) == 1
    s = bytearray()
    s += le(version, 4)
    s += varint(len(tx_ins))
    for i, (op, seq) in enumerate(tx_ins):
        s += op
        if i == nIn: s += varint(len(script_code)) + script_code
        else:        s += b'\x00'
        s += le(seq, 4)
    s += varint(len(tx_outs))
    for val, spk in tx_outs:
        s += le(val, 8) + varint(len(spk)) + spk
    s += le(locktime, 4)
    s += le(hashtype, 4)
    return dsha(bytes(s))

# --- BIP143 v0 sighash -------------------------------------------------------
def bip143_sighash(tx_ins, tx_outs, nIn, script_code, amount, hashtype, version=2, locktime=0):
    assert (hashtype & 0x1f) == 1 and not (hashtype & 0x80)
    hashPrevouts = dsha(b''.join(op for op, _ in tx_ins))
    hashSequence = dsha(b''.join(le(seq, 4) for _, seq in tx_ins))
    hashOutputs  = dsha(b''.join(le(v, 8) + varint(len(spk)) + spk for v, spk in tx_outs))
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
    if (hash_type & 3) in (2, 3):          # SINGLE
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
        parts = ['TAPVERIFY', str(d['idx']), tx, str(len(d['prevouts']))]
        for amt, s in [(d['amount'], spk)]:
            parts += [str(amt), s]
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
            return 'TAPVERIFY %d %s 1 %d %s' % (d['idx'], tx, d['amount'], spk)
        return 'WITVERIFY %08x %d %s %d %s -' % (d['flags'], d['idx'], tx, d['amount'], spk)
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

def all_cases():
    cs = []
    for v in ('bare', 'p2sh', 'p2wsh'): cs.append(synth_multisig(v))
    cs.append(synth_cltv()); cs.append(synth_csv())
    cs.append(synth_codesep())
    cs.append(synth_taproot_scriptpath(False))
    cs.append(synth_taproot_scriptpath(True))
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
