#!/usr/bin/env python3
"""gen_hashtype_vectors.py -- prove Stage B's non-ALL legacy hashtypes are
wired correctly end-to-end, not just that the raw hash matches a fixture.

Covers P2PK, P2PKH, P2SH(P2PK redeem), and P2SH(2-of-2 multisig redeem) --
the four legacy script shapes PLAN_SCRIPT_VERIFY.md's Stage B named as
needing dispatch verification. sv_verify_script itself doesn't switch on
script "type" at all (it just runs whatever opcodes it's given), so these
cases exist to prove that generic path is actually exercised correctly for
each shape under non-ALL hashtypes -- not to add new dispatch code.

Uses this repo's own legacy_sighash Python reference (proven 500/500
against Bitcoin Core's official sighash.json -- see gen_sighash_vectors.py).
For most groups, each hashtype gets:
  - the genuine spend (must ACCEPT), and
  - a tampered variant that changes exactly the field that hashtype is
    supposed to ignore (must ALSO ACCEPT -- proving the field really is
    unbound), and
  - a tampered variant that changes a field the hashtype DOES bind (must
    REJECT -- proving it isn't just accepting everything).
Also: the SIGHASH_SINGLE-out-of-range (nIn>=nOut) quirk (a genuinely-signed
degenerate uint256(1) hash verifies -- Core's known behaviour), and for the
P2SH-multisig group specifically, two co-signers using DIFFERENT hashtypes
on the SAME input (CHECKMULTISIG builds its own scriptCode slice at a
different site in bitcoin_interp.asm than single CHECKSIG, so this is
genuinely separate coverage, not a restatement of the CHECKSIG cases).

Output: asm/tests/hashtype_vec.h consumed by tests/test_hashtype_e2e.c via
sv_verify_script directly (real ECDSA, real interpreter, no shortcuts).
"""
import sys, os, struct, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_p2sh_vectors import der_sign, pubkey, push, cs, Tx, sha256d, p2sh_spk

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

SV_P2SH = 1 << 0

def hash160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

def strip_codesep(s):
    out = b''; i = 0; n = len(s)
    while i < n:
        op = s[i]
        if op < 0x4c: ln, hdr = op, 1
        elif op == 0x4c: ln, hdr = s[i+1], 2
        elif op == 0x4d: ln, hdr = s[i+1]|(s[i+2]<<8), 3
        elif op == 0x4e: ln, hdr = s[i+1]|(s[i+2]<<8)|(s[i+3]<<16)|(s[i+4]<<24), 5
        else: ln, hdr = 0, 1
        unit = hdr+ln
        if i+unit > n: out += s[i:]; return out
        if op != 0xab: out += s[i:i+unit]
        i += unit
    return out

def legacy_sighash(tx_bytes, script_hex_or_bytes, nIn, hashtype):
    sc = script_hex_or_bytes if isinstance(script_hex_or_bytes, bytes) else bytes.fromhex(script_hex_or_bytes)
    b = tx_bytes; p = 0
    version = struct.unpack_from('<i', b, p)[0]; p += 4
    def rd_cs():
        nonlocal p
        v = b[p]
        if v < 0xfd: p += 1; return v
        if v == 0xfd: r = struct.unpack_from('<H', b, p+1)[0]; p += 3; return r
        if v == 0xfe: r = struct.unpack_from('<I', b, p+1)[0]; p += 5; return r
        r = struct.unpack_from('<Q', b, p+1)[0]; p += 9; return r
    nin = rd_cs(); ins = []
    for _ in range(nin):
        prevout = b[p:p+36]; p += 36
        slen = rd_cs(); p += slen
        seq = struct.unpack_from('<I', b, p)[0]; p += 4
        ins.append((prevout, seq))
    nout = rd_cs(); outs = []
    for _ in range(nout):
        val = b[p:p+8]; p += 8
        slen = rd_cs(); spk = b[p:p+slen]; p += slen
        outs.append((val, spk))
    locktime = struct.unpack_from('<I', b, p)[0]; p += 4

    hb = hashtype & 0x1f
    fSingle = hb == 3; fNone = hb == 2; fACP = (hashtype & 0x80) != 0
    if fSingle and nIn >= len(outs):
        return b'\x01' + b'\x00'*31
    scF = strip_codesep(sc)
    pre = struct.pack('<i', version)
    nInputs = 1 if fACP else len(ins)
    pre += cs(nInputs)
    for i in range(nInputs):
        real_i = nIn if fACP else i
        prevout, seq = ins[real_i]
        pre += prevout
        pre += (cs(len(scF)) + scF) if real_i == nIn else b'\x00'
        pre += struct.pack('<i', 0) if (real_i != nIn and (fSingle or fNone)) else struct.pack('<I', seq)
    if fNone: nOutputs = 0
    elif fSingle: nOutputs = nIn+1
    else: nOutputs = len(outs)
    pre += cs(nOutputs)
    for i in range(nOutputs):
        if fSingle and i != nIn: pre += b'\xff'*8 + b'\x00'
        else:
            val, spk = outs[i]; pre += val + cs(len(spk)) + spk
    pre += struct.pack('<I', locktime)
    pre += struct.pack('<i', hashtype)
    return sha256d(pre)

def p2pk_spk(pub): return push(pub) + b'\xac'
def p2pkh_spk(pub): return b'\x76\xa9\x14' + hash160(pub) + b'\x88\xac'
def multisig_redeem(pubs, m, n): return bytes([0x50+m]) + b''.join(push(p) for p in pubs) + bytes([0x50+n, 0xae])

def locate_fields(tx_bytes):
    """Parse a serialized tx and return (input_offsets, output_offsets) where
    each input_offsets[i] = offset of that input's 36-byte prevout, and each
    output_offsets[j] = offset of that output's 8-byte value. Avoids
    hand-computed byte arithmetic for the tamper cases below."""
    b = tx_bytes; p = 4
    def rd_cs():
        nonlocal p
        v = b[p]
        if v < 0xfd: p += 1; return v
        if v == 0xfd: r = struct.unpack_from('<H', b, p+1)[0]; p += 3; return r
        if v == 0xfe: r = struct.unpack_from('<I', b, p+1)[0]; p += 5; return r
        r = struct.unpack_from('<Q', b, p+1)[0]; p += 9; return r
    nin = rd_cs(); in_offs = []
    for _ in range(nin):
        in_offs.append(p)
        p += 36
        slen = rd_cs(); p += slen
        p += 4
    nout = rd_cs(); out_offs = []
    for _ in range(nout):
        out_offs.append(p)
        p += 8
        slen = rd_cs(); p += slen
    return in_offs, out_offs

def build_spend(fund_outs, spend_outs, nIn, make_ss):
    """Build a funding tx (single anyone-can-spend input) with the given
    outputs, then a spend of those outputs with an empty scriptSig at nIn;
    make_ss(spend_tx_bytes_with_empty_sig_at_nIn, nIn) -> final scriptSig
    bytes, free to call legacy_sighash however many times it needs (single-
    sig or multisig, mixed hashtypes). Returns (fund_bytes, spend_bytes, ss).
    """
    fund = Tx(); fund.ins = [('00'*32, 0xffffffff, b'\x51', 0xffffffff)]
    fund.outs = fund_outs
    fund_bytes = fund.ser()
    previd = sha256d(fund_bytes)
    spend = Tx(); spend.locktime = 0
    spend.ins = [(previd.hex(), i, b'', 0xffffffff) for i in range(len(fund_outs))]
    spend.outs = spend_outs
    raw = spend.ser()
    ss = make_ss(raw, nIn)
    spend.ins[nIn] = (spend.ins[nIn][0], spend.ins[nIn][1], ss, 0xffffffff)
    return fund_bytes, spend.ser(), ss

CASES = []
def add(name, tx, ss, spk, nIn, flags, expect_accept):
    CASES.append((name, tx, ss, spk, nIn, flags, 1 if expect_accept else 0))

def group_checksig(label, spk, script_code, ss_of, key):
    """Runs the standard genuine/tamper-unbound/tamper-bound/ACP/SINGLE/quirk
    battery for any single-signature legacy shape (P2PK, P2PKH, P2SH-P2PK),
    where ss_of(sig_with_hashtype_byte) builds the actual scriptSig bytes
    (push(sig) for P2PK/P2SH-P2PK-redeem-signing convention differs -- caller
    supplies it). flags: SV_P2SH for P2SH shapes, 0 otherwise."""
    flags = SV_P2SH if label.startswith('p2sh') else 0

    def sign_and_ss(raw, nIn, hashtype):
        d = legacy_sighash(raw, script_code, nIn, hashtype)
        sig = der_sign(key, d) + bytes([hashtype & 0xff])
        return ss_of(sig)

    # ---- SIGHASH_NONE: outputs unbound ----
    fund, spend, ss = build_spend([(100000, spk)], [(90000, b'\x51')], 0,
        lambda raw, nIn: sign_and_ss(raw, nIn, SIGHASH_NONE))
    add(f'{label}-none-genuine', spend, ss, spk, 0, flags, True)
    _, out_offs = locate_fields(spend)
    t = bytearray(spend); t[out_offs[0]:out_offs[0]+8] = struct.pack('<Q', 12345)
    add(f'{label}-none-tampered-output-still-accepts', bytes(t), ss, spk, 0, flags, True)

    # control: SIGHASH_ALL -- tampering the output MUST now reject
    fundA, spendA, ssA = build_spend([(100000, spk)], [(90000, b'\x51')], 0,
        lambda raw, nIn: sign_and_ss(raw, nIn, SIGHASH_ALL))
    add(f'{label}-all-genuine', spendA, ssA, spk, 0, flags, True)
    _, out_offsA = locate_fields(spendA)
    tA = bytearray(spendA); tA[out_offsA[0]:out_offsA[0]+8] = struct.pack('<Q', 12345)
    add(f'{label}-all-tampered-output-rejects', bytes(tA), ssA, spk, 0, flags, False)

    # ---- SIGHASH_SINGLE: only the same-index output is bound ----
    fundS, spendS, ssS = build_spend([(100000, spk)], [(50000, b'\x51'), (40000, b'\x52')], 0,
        lambda raw, nIn: sign_and_ss(raw, nIn, SIGHASH_SINGLE))
    add(f'{label}-single-genuine', spendS, ssS, spk, 0, flags, True)
    _, out_offsS = locate_fields(spendS)
    tS1 = bytearray(spendS); tS1[out_offsS[1]:out_offsS[1]+8] = struct.pack('<Q', 999)
    add(f'{label}-single-tampered-other-output-still-accepts', bytes(tS1), ssS, spk, 0, flags, True)
    tS2 = bytearray(spendS); tS2[out_offsS[0]:out_offsS[0]+8] = struct.pack('<Q', 999)
    add(f'{label}-single-tampered-same-output-rejects', bytes(tS2), ssS, spk, 0, flags, False)

    # ---- ANYONECANPAY: other inputs' prevouts unbound ----
    fundP, spendP, ssP = build_spend([(100000, spk), (50000, spk)], [(140000, b'\x51')], 0,
        lambda raw, nIn: sign_and_ss(raw, nIn, SIGHASH_ALL | SIGHASH_ANYONECANPAY))
    add(f'{label}-acp-genuine', spendP, ssP, spk, 0, flags, True)
    in_offsP, _ = locate_fields(spendP)
    tP1 = bytearray(spendP); tP1[in_offsP[1]:in_offsP[1]+4] = b'\xde\xad\xbe\xef'
    add(f'{label}-acp-tampered-other-input-still-accepts', bytes(tP1), ssP, spk, 0, flags, True)
    tP2 = bytearray(spendP); tP2[in_offsP[0]:in_offsP[0]+4] = b'\xde\xad\xbe\xef'
    add(f'{label}-acp-tampered-signed-input-rejects', bytes(tP2), ssP, spk, 0, flags, False)

    # ---- SIGHASH_SINGLE out-of-range quirk ----
    fundQ, spendQ, ssQ = build_spend([(100000, spk)], [], 0,
        lambda raw, nIn: sign_and_ss(raw, nIn, SIGHASH_SINGLE))
    add(f'{label}-single-out-of-range-quirk-still-accepts', spendQ, ssQ, spk, 0, flags, True)

def main():
    k1 = 0xA11CE
    pub1 = pubkey(k1)

    # ---- P2PK (baseline, already covered previously; kept for continuity) ----
    spk_pk = p2pk_spk(pub1)
    group_checksig('p2pk', spk_pk, spk_pk, lambda sig: push(sig), k1)

    # ---- P2PKH: scriptSig = push(sig) + push(pubkey); scriptCode == spk ----
    spk_pkh = p2pkh_spk(pub1)
    group_checksig('p2pkh', spk_pkh, spk_pkh, lambda sig: push(sig) + push(pub1), k1)

    # ---- P2SH(P2PK redeem): scriptCode is the REDEEM script, not the outer
    # HASH160..EQUAL scriptPubKey; scriptSig = push(sig) + push(redeem) ----
    redeem_pk = p2pk_spk(pub1)
    spk_p2sh_pk = p2sh_spk(redeem_pk)
    group_checksig('p2sh-p2pk', spk_p2sh_pk, redeem_pk, lambda sig: push(sig) + push(redeem_pk), k1)

    # ---- P2SH(2-of-2 multisig redeem): two co-signers, exercising
    # CHECKMULTISIG's own (separate) scriptCode/FindAndDelete site, INCLUDING
    # two signers using DIFFERENT hashtypes on the same input. ----
    k2 = 0xB0B
    pub2 = pubkey(k2)
    redeem_ms = multisig_redeem([pub1, pub2], 2, 2)
    spk_p2sh_ms = p2sh_spk(redeem_ms)

    def ms_ss(sig1, sig2):
        return b'\x00' + push(sig1) + push(sig2) + push(redeem_ms)

    # genuine, both ALL
    def make_ss_all(raw, nIn):
        d = legacy_sighash(raw, redeem_ms, nIn, SIGHASH_ALL)
        s1 = der_sign(k1, d) + bytes([SIGHASH_ALL])
        s2 = der_sign(k2, d) + bytes([SIGHASH_ALL])
        return ms_ss(s1, s2)
    fundM, spendM, ssM = build_spend([(100000, spk_p2sh_ms)], [(50000, b'\x51'), (40000, b'\x52')], 0, make_ss_all)
    add('p2sh-ms-all-genuine', spendM, ssM, spk_p2sh_ms, 0, SV_P2SH, True)

    # mixed hashtypes: sig1=NONE (ignores all outputs), sig2=SINGLE (binds
    # only output[0]) -- tamper output[1]: neither sig cares -> ACCEPT;
    # tamper output[0]: sig2 (SINGLE) breaks -> REJECT (2-of-2 needs both).
    def make_ss_mixed(raw, nIn):
        d1 = legacy_sighash(raw, redeem_ms, nIn, SIGHASH_NONE)
        d2 = legacy_sighash(raw, redeem_ms, nIn, SIGHASH_SINGLE)
        s1 = der_sign(k1, d1) + bytes([SIGHASH_NONE])
        s2 = der_sign(k2, d2) + bytes([SIGHASH_SINGLE])
        return ms_ss(s1, s2)
    fundMx, spendMx, ssMx = build_spend([(100000, spk_p2sh_ms)], [(50000, b'\x51'), (40000, b'\x52')], 0, make_ss_mixed)
    add('p2sh-ms-mixed-none-single-genuine', spendMx, ssMx, spk_p2sh_ms, 0, SV_P2SH, True)
    _, out_offsMx = locate_fields(spendMx)
    tMx1 = bytearray(spendMx); tMx1[out_offsMx[1]:out_offsMx[1]+8] = struct.pack('<Q', 777)
    add('p2sh-ms-mixed-tampered-unbound-output-still-accepts', bytes(tMx1), ssMx, spk_p2sh_ms, 0, SV_P2SH, True)
    tMx2 = bytearray(spendMx); tMx2[out_offsMx[0]:out_offsMx[0]+8] = struct.pack('<Q', 777)
    add('p2sh-ms-mixed-tampered-single-bound-output-rejects', bytes(tMx2), ssMx, spk_p2sh_ms, 0, SV_P2SH, False)

    # negative control: one signature from a key NOT in the redeem -- must
    # reject (proves 2-of-2 count enforcement survives non-ALL hashtypes,
    # not just that mismatched fields reject).
    kbad = 0xBAD
    def make_ss_badkey(raw, nIn):
        d = legacy_sighash(raw, redeem_ms, nIn, SIGHASH_ALL)
        s1 = der_sign(kbad, d) + bytes([SIGHASH_ALL])
        s2 = der_sign(k2, d) + bytes([SIGHASH_ALL])
        return ms_ss(s1, s2)
    fundB, spendB, ssB = build_spend([(100000, spk_p2sh_ms)], [(50000, b'\x51'), (40000, b'\x52')], 0, make_ss_badkey)
    add('p2sh-ms-wrong-key-rejects', spendB, ssB, spk_p2sh_ms, 0, SV_P2SH, False)

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'asm', 'tests', 'hashtype_vec.h')
    with open(out_path, 'w') as f:
        f.write('/* AUTO-GENERATED by validation/gen_hashtype_vectors.py -- DO NOT EDIT. */\n')
        f.write('#ifndef HASHTYPE_VEC_H\n#define HASHTYPE_VEC_H\n\n')
        f.write('static const char* HT_NAME[] = {\n')
        for c in CASES: f.write('  "%s",\n' % c[0])
        f.write('};\n\nstatic const char* HT_TX[] = {\n')
        for c in CASES: f.write('  "%s",\n' % c[1].hex())
        f.write('};\n\nstatic const char* HT_SS[] = {\n')
        for c in CASES: f.write('  "%s",\n' % c[2].hex())
        f.write('};\n\nstatic const char* HT_SPK[] = {\n')
        for c in CASES: f.write('  "%s",\n' % c[3].hex())
        f.write('};\n\nstatic const unsigned HT_NIN[] = {\n  ')
        f.write(', '.join(str(c[4]) for c in CASES))
        f.write('\n};\n\nstatic const unsigned long long HT_FLAGS[] = {\n  ')
        f.write(', '.join(str(c[5]) for c in CASES))
        f.write('\n};\n\nstatic const unsigned HT_EXPECT[] = {\n  ')
        f.write(', '.join(str(c[6]) for c in CASES))
        f.write('\n};\n\nstatic const unsigned HT_COUNT = %d;\n\n#endif\n' % len(CASES))
    print('wrote %d cases to %s' % (len(CASES), out_path))
    for c in CASES:
        print('  %-52s nIn=%d flags=%d expect=%s' % (c[0], c[4], c[5], 'ACCEPT' if c[6] else 'REJECT'))

if __name__ == '__main__':
    main()
