#!/usr/bin/env python3
"""gen_p2sh_vectors.py -- build genuine/negative P2SH spend vector triples.

Shared by the differential harness (validation/p2sh_diff.py) and the standalone
C test (asm/tests/test_verify_p2sh.c, via a small C-side driver or hardcoded
conversion). Hosts the ECDSA signer, the legacy SIGHASH_ALL builder and the
7-case differential corpus.

gen_cases() -> list of (name, flags, idx, tx_bytes, ss_bytes, spk_bytes)
"""
import struct, hashlib
import ecdsa
import ecdsa.util
from ecdsa import SECP256k1

N = SECP256k1.order

F_P2SH = 1<<0; F_DERSIG = 1<<2; F_NULLDUMMY = 1<<4
F_CLTV = 1<<9; F_CSV = 1<<10; F_WITNESS = 1<<11; F_TAPROOT = 1<<17

def cons_flags(height):
    # Core GetBlockScriptFlags: P2SH|WITNESS|TAPROOT (with exceptions) + DERSIG/CLTV/CSV/NULLDUMMY
    # when their deployments are active. Pre-BIP16 (height<173805) P2SH is off and,
    # since WITNESS/TAPROOT require P2SH (Core asserts WITNESS=>P2SH in VerifyScript),
    # we also drop WITNESS/TAPROOT (they were not active pre-2012 anyway).
    if height < 173805:
        return F_DERSIG | F_CLTV | F_CSV | F_NULLDUMMY
    return F_P2SH | F_WITNESS | F_TAPROOT | F_DERSIG | F_CLTV | F_CSV | F_NULLDUMMY

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

def push(x):
    if len(x) == 0: return b'\x00'
    if len(x) < 0x4c: return bytes([len(x)]) + x
    if len(x) <= 0xff: return b'\x4c' + bytes([len(x)]) + x
    if len(x) <= 0xffff: return b'\x4d' + struct.pack('<H', len(x)) + x
    return b'\x4e' + struct.pack('<I', len(x)) + x

def p2sh_spk(script):
    h = hashlib.new('ripemd160', hashlib.sha256(script).digest()).digest()
    return b'\xa9\x14' + h + b'\x87'

class Tx:
    def __init__(self, version=2, locktime=0):
        self.version=version; self.locktime=locktime; self.ins=[]; self.outs=[]
    def ser(self):
        b = struct.pack('<I', self.version) + cs(len(self.ins))
        for (txid,idx,ss,seq) in self.ins:
            b += bytes.fromhex(txid) + struct.pack('<I', idx) + cs(len(ss)) + ss + struct.pack('<I', seq)
        b += cs(len(self.outs))
        for (val,spk) in self.outs:
            b += struct.pack('<Q', val) + cs(len(spk)) + spk
        b += struct.pack('<I', self.locktime)
        return b

def leg_sighash(tx, nIn, scriptCode, htype=1):
    pre = struct.pack('<I', tx.version) + cs(len(tx.ins))
    for i,(txid,idx,ss,seq) in enumerate(tx.ins):
        pre += bytes.fromhex(txid) + struct.pack('<I', idx)
        pre += (cs(len(scriptCode)) + scriptCode) if i==nIn else b'\x00'
        pre += struct.pack('<I', seq)
    pre += cs(len(tx.outs))
    for (val,spk) in tx.outs:
        pre += struct.pack('<Q', val) + cs(len(spk)) + spk
    pre += struct.pack('<I', tx.locktime)
    pre += struct.pack('<I', htype)
    return sha256d(pre)

def der_sign(seckey, digest):
    sk = ecdsa.SigningKey.from_secret_exponent(seckey, curve=SECP256k1)
    sig = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)
    r, s = ecdsa.util.sigdecode_der(sig, N)
    if s > N//2: s = N - s
    return ecdsa.util.sigencode_der(r, s, N)

def pubkey(seckey):
    vk = ecdsa.SigningKey.from_secret_exponent(seckey, curve=SECP256k1).get_verifying_key()
    xy = vk.to_string()          # x(32) || y(32); y LSB is the last byte
    prefix = 0x02 if (xy[63] & 1) == 0 else 0x03
    return bytes([prefix]) + xy[:32]

def multisig_redeem(keys, m, n):
    return bytes([0x50+m]) + b''.join(push(k) for k in keys) + bytes([0x50+n, 0xae])

def build():
    """Genuine 2-of-3 + 1-of-1 corpus. Returns a dict for gen_cases() and the
    standalone C test's hardcoded vectors."""
    k1,k2,k3 = 0x1234, 0x9abc, 0xdef0
    keys = [pubkey(k) for k in (k1,k2,k3)]
    redeem = multisig_redeem(keys, 2, 3)
    spk2 = p2sh_spk(redeem)
    fund = Tx(); fund.ins=[('00'*32,0xffffffff,b'\x51',0xffffffff)]; fund.outs=[(100000,spk2)]
    fund_tx = fund.ser()
    previd = sha256d(fund_tx)
    spend = Tx(); spend.ins=[(previd.hex(),0,b'',0xffffffff)]; spend.outs=[(90000,b'\x51')]
    d1 = leg_sighash(spend, 0, redeem)
    sig1 = der_sign(k1, d1)+b'\x01'
    sig3 = der_sign(k3, d1)+b'\x01'
    ss_order = b'\x00'+push(sig1)+push(sig3)+push(redeem)

    def with_ss(ss):
        t = Tx(); t.version=2; t.locktime=0
        t.ins=[(previd.hex(),0,ss,0xffffffff)]
        t.outs=[(90000,b'\x51')]
        return t.ser()

    return dict(redeem=redeem, spk2=spk2, fund_tx=fund_tx, spend_tx=spend.ser(),
                ss_order=ss_order, sig1=sig1, sig3=sig3, d1=d1, keys=keys,
                k1=k1, k2=k2, k3=k3, with_ss=with_ss, previd=previd)

def gen_cases():
    d = build()
    redeem, spk2, sig1, sig3, d1 = d['redeem'], d['spk2'], d['sig1'], d['sig3'], d['d1']
    with_ss = d['with_ss']
    cases = []
    def add(name, flags, tx, ss, spk):
        cases.append((name, flags, 0, tx, ss, spk))

    # genuine 2-of-3, post-BIP16 -> accept
    add('2of3-genuine-accept', cons_flags(200000), d['spend_tx'], d['ss_order'], spk2)
    # pre-BIP16 (P2SH off): sigs unverified; redeem still pushonly-acceptable
    add('2of3-prebip16', cons_flags(100000), d['spend_tx'], d['ss_order'], spk2)

    kw = 0x55555
    sig_bad = der_sign(kw, d1) + b'\x01'
    neg = [
        ('2of3-wrong-sig',  b'\x00'+push(sig1)+push(sig_bad)+push(redeem)),
        ('2of3-insufficient', b'\x00'+push(sig1)+push(redeem)),
        ('2of3-bad-redeem',   b'\x00'+push(sig1)+push(sig3)+b'\x5c'),  # OP_ADD -> non-pushonly
        ('2of3-null-dummy',   b'\x51'+push(sig1)+push(sig3)+push(redeem)),
        ('2of3-empty-ss',     b''),
    ]
    for nm, ss in neg:
        add(nm, cons_flags(200000), with_ss(ss), ss, spk2)

    # 1-of-1 P2PKH-shaped redeem, genuine + wrong
    rk = 0x777
    rpub = pubkey(rk)
    h = hashlib.new('ripemd160', hashlib.sha256(rpub).digest()).digest()
    r_red = b'\x76\xa9\x14' + h + b'\x88\xac'
    spk1 = p2sh_spk(r_red)
    fund1 = Tx(); fund1.ins=[('00'*32,0xffffffff,b'\x51',0xffffffff)]; fund1.outs=[(100000,spk1)]
    prev1 = sha256d(fund1.ser())
    tx1 = Tx(); tx1.ins=[(prev1.hex(),0,b'',0xffffffff)]; tx1.outs=[(90000,b'\x51')]
    dd = leg_sighash(tx1,0,r_red)
    dsig = der_sign(rk, dd)+b'\x01'
    ss1 = push(dsig)+push(rpub)+push(r_red)   # <sig> <pubkey> <redeem>
    tx1.ins[0]=(tx1.ins[0][0],0,ss1,0xffffffff)
    add('1of1-accept', cons_flags(200000), tx1.ser(), ss1, spk1)
    # wrong sig: sign with a non-member key
    ss1b = push(der_sign(0x8888, dd)+b'\x01') + push(rpub) + push(r_red)
    tx1b = Tx(); tx1b.ins=[(prev1.hex(),0,ss1b,0xffffffff)]; tx1b.outs=tx1.outs
    add('1of1-wrong-sig', cons_flags(200000), tx1b.ser(), ss1b, spk1)
    return cases

if __name__ == '__main__':
    c = gen_cases()
    for (name, flags, idx, tx, ss, spk) in c:
        print('%-22s flags=%08x txlen=%d sslen=%d splen=%d' % (name, flags, len(tx), len(ss), len(spk)))
    # also write the 2of3 genuine vector for the C test
    d = build()
    open('/tmp/p2sh_redeem.hex','w').write(d['redeem'].hex())
    open('/tmp/p2sh_spk2.hex','w').write(d['spk2'].hex())
    open('/tmp/p2sh_spend_tx.hex','w').write(d['spend_tx'].hex())
    open('/tmp/p2sh_ss_order.hex','w').write(d['ss_order'].hex())
    open('/tmp/p2sh_sig1.hex','w').write(d['sig1'].hex())
    open('/tmp/p2sh_sig3.hex','w').write(d['sig3'].hex())
    open('/tmp/p2sh_d1.hex','w').write(d['d1'].hex())
