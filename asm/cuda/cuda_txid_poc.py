import sys, ctypes, time, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "validation"))
from corpus_diff import rpc, Shim

lib = ctypes.CDLL(os.path.join(os.path.dirname(os.path.abspath(__file__)), "libbmc_cuda.so"))
lib.cuda_sha256_batch_init.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint8),ctypes.POINTER(ctypes.c_uint64),ctypes.c_uint64,ctypes.c_int]
lib.cuda_sha256_batch_launch.argtypes=[ctypes.c_void_p]
lib.cuda_sha256_batch_sync.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint8)]
lib.cuda_sha256_batch_free.argtypes=[ctypes.c_void_p]

def cuda_sha256d(msgs):
    n=len(msgs); blob=b''.join(msgs)
    bb=(ctypes.c_uint8*len(blob)).from_buffer_copy(blob)
    ix=(ctypes.c_uint64*(n*2))(); off=0
    for i,m in enumerate(msgs): ix[2*i]=off; ix[2*i+1]=len(m); off+=len(m)
    out=(ctypes.c_uint8*(n*32))()
    h=ctypes.cast((ctypes.c_uint8*256).from_buffer_copy(bytes(256)),ctypes.c_void_p)
    lib.cuda_sha256_batch_init(h,bb,ix,n,1); lib.cuda_sha256_batch_launch(h); lib.cuda_sha256_batch_sync(h,out); lib.cuda_sha256_batch_free(h)
    return [bytes(out[i*32:(i+1)*32]) for i in range(n)]

def rv(b,p):
    c=b[p]
    if c<0xfd: return c,p+1
    if c==0xfd: return b[p+1]|(b[p+2]<<8), p+3
    if c==0xfe: return b[p+1]|(b[p+2]<<8)|(b[p+3]<<16)|(b[p+4]<<24), p+5
    return int.from_bytes(b[p+1:p+9],'little'), p+9

def walk_txs(raw):
    b=bytes.fromhex(raw)
    cnt,idx=rv(b,80)
    txs=[]
    for _ in range(min(cnt,20000)):
        if idx+4>len(b): break
        p=idx+4
        segwit = (idx+6<=len(b)) and b[p]==0 and b[p+1]==1
        if segwit: p+=2
        nin,p=rv(b,p)
        for _i in range(nin):
            p+=36
            s,p=rv(b,p); p+=s+4
        if p>len(b): break
        nout,p=rv(b,p)
        for _o in range(nout):
            p+=8
            s,p=rv(b,p); p+=s
        p+=4  # locktime
        base_end=p
        if segwit and p<len(b):
            nw,p2=rv(b,p)
            for _w in range(nw):
                wl,p2=rv(b,p2); p2+=wl
            p=p2
        txs.append(b[idx:base_end])  # UNWITNESSED form
        idx=p
    return txs

H=200000
raw=rpc('getblock',[rpc('getblockhash',[H]),0])
txs=walk_txs(raw)
print(f"blk {H}: walked {len(txs)} txs (unwitnessed form, segwit accepted)")

# oracle via shim TXID (trusted asm tx_txid)
s=Shim(); t1=time.time()
oracle=[]
okparse=0
for tx in txs:
    r=s.ask('TXID',tx.hex()).split()
    if len(r)>2 and r[1]=='1': okparse+=1
    oracle.append(r[2] if len(r)>2 else '')
ta=time.time()-t1; s.close()
print(f"  shim parsed {okparse}/{len(txs)}")

# CUDA batch timing
if txs:
    t0=time.time(); cd=cuda_sha256d(txs); tc=time.time()-t0
    bad=sum(1 for c,o in zip(cd,oracle) if c.hex()!=o)
    print(f"  mismatches={bad}/{len(txs)}")
    print(f"  CUDA batch (incl H2D+launch+D2H): {tc*1000:.1f} ms ({len(txs)/tc:.0f}/s)")
    print(f"  ASM oracle serial (shim per-tx)  : {ta*1000:.1f} ms ({len(txs)/ta:.0f}/s)")
    if tc>0: print(f"  speedup: {ta/tc:.1f}x")
