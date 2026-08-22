"""Independent BIP143 (segwit v0) sighash reference, used on 2026-08-22 to root-cause
the rejection of mainnet block 481824 tx 562 (the first real P2WPKH spend).

Self-checks against the worked example in BIP143 (expected sighash
c37af311...8cb670) before trusting itself, then verifies the real signature with
tests/ecdsa_pure.py. Run from asm/: python3 validation/bip143_ref.py

Note BIP143 lists "scriptCode" WITH its compactsize prefix (1976a914...88ac);
for P2WPKH it is the implied P2PKH script, NOT the 22-byte witness program.
"""
import hashlib, json, sys
sys.path.insert(0, 'tests')
import ecdsa_pure as E
def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def rd_cs(b,p):
    f=b[p]; 
    if f<0xfd: return f,p+1
    if f==0xfd: return int.from_bytes(b[p+1:p+3],'little'),p+3
    if f==0xfe: return int.from_bytes(b[p+1:p+5],'little'),p+5
    return int.from_bytes(b[p+1:p+9],'little'),p+9
def cs(n): return bytes([n]) if n<0xfd else (b'\xfd'+n.to_bytes(2,'little') if n<=0xffff else b'\xfe'+n.to_bytes(4,'little'))
def parse(tx):
    p=0; ver=tx[0:4]; p=4; segwit = tx[4:6]==b'\x00\x01'
    if segwit: p=6
    nin,p=rd_cs(tx,p); ins=[]
    for i in range(nin):
        op=tx[p:p+36]; p+=36; sl,p=rd_cs(tx,p); ss=tx[p:p+sl]; p+=sl; seq=tx[p:p+4]; p+=4; ins.append((op,ss,seq))
    nout,p=rd_cs(tx,p); outs=[]
    for i in range(nout):
        v=tx[p:p+8]; p+=8; sl,p=rd_cs(tx,p); spk=tx[p:p+sl]; p+=sl; outs.append(v+cs(sl)+spk)
    wit=[]
    if segwit:
        for i in range(nin):
            n,p=rd_cs(tx,p); st=[]
            for j in range(n):
                l,p=rd_cs(tx,p); st.append(tx[p:p+l]); p+=l
            wit.append(st)
    lock=tx[p:p+4]
    return ver,ins,outs,wit,lock
def bip143(tx, n_in, script_code, amount, hashtype=1):
    # Guard against the classic misuse (2026-08-22): callers passing the BARE
    # script (e.g. 25-byte 76a914...88ac) without the compactsize prefix.
    # BIP143's scriptCode is serialized WITH its length prefix; require that
    # the leading compactsize covers exactly the rest of the bytes.
    l, q = rd_cs(script_code, 0)
    assert q + l == len(script_code), (
        "script_code must include its compactsize prefix (e.g. 1976a914...88ac); "
        "got a leading compactsize of %d over %d remaining bytes" % (l, len(script_code)-q))
    ver,ins,outs,wit,lock=parse(tx)
    hp=sha256d(b''.join(i[0] for i in ins)); hs=sha256d(b''.join(i[2] for i in ins)); ho=sha256d(b''.join(outs))
    pre = ver+hp+hs+ins[n_in][0]+script_code+amount.to_bytes(8,'little')+ins[n_in][2]+ho+lock+hashtype.to_bytes(4,'little')
    return sha256d(pre), pre, (hp,hs,ho)
def der_parse(sig):
    assert sig[0]==0x30; p=2; assert sig[p]==2; l=sig[p+1]; r=int.from_bytes(sig[p+2:p+2+l],'big'); p+=2+l
    assert sig[p]==2; l=sig[p+1]; s=int.from_bytes(sig[p+2:p+2+l],'big'); p+=2+l
    return r,s,sig[p]
def pub_parse(pk):
    x=int.from_bytes(pk[1:33],'big'); p=E.P if hasattr(E,'P') else (2**256-2**32-977)
    y2=(x**3+7)%p; y=pow(y2,(p+1)//4,p)
    if (y&1)!=(pk[0]&1): y=p-y
    return (x,y)
# ---- self-check on BIP143's own P2WPKH example ----
ex_tx=bytes.fromhex("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000")
ex_sc=bytes.fromhex("1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
h,_,_=bip143(ex_tx,1,ex_sc,600000000,1)
print("BIP143 example sighash:",h.hex()); print("  expected            : c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670", "OK" if h.hex()=="c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670" else "MISMATCH")
# ---- the real tx ----
t=json.load(open('validation/fixtures/p2wpkh_481824_562.json'))
tx=bytes.fromhex(t['hex']); ver,ins,outs,wit,lock=parse(tx)
sig,pk=wit[0]; r,s,ht=der_parse(sig); Q=pub_parse(pk)
print("hash160(pk) == program:", hashlib.new('ripemd160',hashlib.sha256(pk).digest()).hexdigest()=="8d7a0a3461e3891723e5fdf8129caa0075060cff", "| sig hashtype", ht)
amount=194300
prog=bytes.fromhex("1600148d7a0a3461e3891723e5fdf8129caa0075060cff")
sc_bip143=bytes.fromhex("1976a9148d7a0a3461e3891723e5fdf8129caa0075060cff88ac")
for name,scode in (("BIP143 scriptCode 1976a914..88ac",sc_bip143),("22-byte witness program (ours)",prog)):
    h,pre,(hp,hs,ho)=bip143(tx,0,scode,amount,1)
    ok=E.verify(int.from_bytes(h,'big'),r,s,Q)
    print("%-36s sighash=%s  verify=%s"%(name,h.hex(),ok))
print("hashPrevouts",hp.hex()); print("hashSequence",hs.hex()); print("hashOutputs ",ho.hex())
print("r=%064x\ns=%064x\nQx=%064x"%(r,s,Q[0]))
