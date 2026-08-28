#!/usr/bin/env python3
"""fuzz_bip32.py -- independent pure-Python BIP32 differential fuzz vs the
AArch64 port (bitcoin_bip32.S: bip32_master / bip32_ckd_priv /
bip32_derive_path / bip32_fingerprint / bip32_extkey_serialize).

Builds a small C driver in a temp dir (links the ported bitcoin_bip32.o deps
from THIS dir) and compares every k/c fingerprint serialized-extkey byte-exactly
against an independent Python BIP32 reference driven by HMAC-SHA512 +
pure-Python secp256k1, over random seeds + paths (hardened+normal, boundary
indices 0/0x7fffffff/0x80000000/0xffffffff). The oracle replicates the .S
return-code semantics bug-for-bug (scalar_small_nonzero: 0<k<=n with k==n->1;
master rc: 1 iff any nonzero byte).

Requires: host aarch64 gcc + bitcoin_bip32.S (+ hmac, keys, addr, sha256,
sha512, ripemd160, hash, point, fe, scalar objects) in THIS dir.

Usage: python3 fuzz_bip32.py [seeds] [iters]
"""
import subprocess, sys, tempfile, os, hashlib, hmac as _hmac, random

# ---------------- secp256k1 ----------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

def ec_add(a, b):
    if a is None: return b
    if b is None: return a
    x1, y1 = a; x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if x1 == x2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def ec_mul(k, pt=G):
    k %= N
    r = None; add = pt
    while k:
        if k & 1: r = ec_add(r, add)
        add = ec_add(add, add); k >>= 1
    return r

def compress_pub(kint):
    pt = ec_mul(kint)
    return bytes([2 if pt[1] % 2 == 0 else 3]) + pt[0].to_bytes(32, 'big')

def hmac_sha512(k, m):
    return _hmac.new(k, m, hashlib.sha512).digest()

def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def ssn(kb):  # scalar_small_nonzero bug-for-bug: 1 iff 0<k<=n (k==n -> 1)
    x = int.from_bytes(kb, 'big')
    return 1 if (x != 0 and x <= N) else 0

def master(seed):
    I = hmac_sha512(b'Bitcoin seed', seed)
    k, c = I[:32], I[32:]
    return k, c, 1 if any(k) else 0

def ckd(kp, cp, idx):
    if idx & 0x80000000:
        inp = b'\x00' + kp + idx.to_bytes(4, 'big')
    else:
        inp = compress_pub(int.from_bytes(kp, 'big')) + idx.to_bytes(4, 'big')
    I = hmac_sha512(cp, inp)
    IL, IR = I[:32], I[32:]
    kchild = ((int.from_bytes(IL, 'big') + int.from_bytes(kp, 'big')) % N).to_bytes(32, 'big')
    rc = ssn(IL) and ssn(kchild)
    return kchild, IR, rc

def fingerprint(pub33): return hash160(pub33)[:4]

def serialize(is_priv, depth, fp4, child, c32, key, keylen):
    ver = 0x0488ADE4 if is_priv else 0x0488B21E
    ser = ver.to_bytes(4, 'big') + bytes([depth]) + fp4 + child.to_bytes(4, 'big') + c32
    return ser + (b'\x00' + key[:keylen] if is_priv else key[:keylen])

def hx(b): return b.hex()

# ---------------- embedded C driver ----------------
DRIVER = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
extern int  bip32_master(uint8_t k[32], uint8_t c[32], const void* seed, uint64_t seedlen);
extern int  bip32_ckd_priv(uint8_t k[32], uint8_t c[32], const uint8_t kp[32], const uint8_t cp[32], uint32_t idx);
extern int  bip32_derive_path(uint8_t k[32], uint8_t c[32], const void* seed, uint64_t seedlen, const uint32_t* indexes, uint64_t n);
extern void bip32_fingerprint(uint8_t fp[4], const uint8_t pub[33]);
extern int  bip32_extkey_serialize(uint8_t ser[78], int is_priv, int depth, const uint8_t fp[4], uint32_t child, const uint8_t c[32], const uint8_t* key, int keylen);
extern void scalar_to_pubkey(uint8_t pub[33], const uint8_t k[32]);
static int hexval(int c){return (c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:(c>='A'&&c<='F')?c-'A'+10:-1;}
static int hex2(const char*s, uint8_t* out, int max){int n=(int)strlen(s);if(n%2||n/2>max)return -1;for(int i=0;i<n/2;i++){int h=hexval(s[2*i]),l=hexval(s[2*i+1]);if(h<0||l<0)return -1;out[i]=(uint8_t)((h<<4)|l);}return n/2;}
static void phex(uint8_t*b,int n){for(int i=0;i<n;i++)printf("%02x",b[i]);}
int main(void){
    char line[8192]; uint8_t a[128],b[128],c[128],d[128],e[128];
    while(fgets(line,sizeof line,stdin)){
        char cmd[16]; int nf=sscanf(line," %15s",cmd); if(nf<1)continue;
        if(strcmp(cmd,"M")==0){
            char s[2048]; if(sscanf(line,"%*s %2047s",s)!=1){printf("M ERR\n");fflush(stdout);continue;}
            int sl=hex2(s,a,sizeof a); if(sl<0){printf("M ERR\n");fflush(stdout);continue;}
            int rc=bip32_master(b,c,a,sl);
            printf("K ");phex(b,32);printf(" ");phex(c,32);printf(" %d\n",rc);
        } else if(strcmp(cmd,"C")==0){
            char s0[2048],s1[2048],s2[2048],s3[2048],s4[2048];
            if(sscanf(line,"%*s %2047s %2047s %2047s %2047s %2047s",s0,s1,s2,s3,s4)!=5)continue;
            uint32_t idx=(uint32_t)strtoul(s2,0,10);
            hex2(s0,a,32); hex2(s1,b,32); hex2(s3,d,32); hex2(s4,e,32);
            int rc=bip32_ckd_priv(a,b,d,e,idx);
            printf("N ");phex(a,32);printf(" ");phex(b,32);printf(" %d\n",rc);
        } else if(strcmp(cmd,"D")==0){
            char s[2048]; if(sscanf(line,"%*s %2047s",s)!=1)continue;
            int sl=hex2(s,a,sizeof a); if(sl<0)continue;
            uint32_t idxs[128]; int got=0; char *t=strtok(line," \t\n");
            t=strtok(NULL," \t\n"); t=strtok(NULL," \t\n");
            while((t=strtok(NULL," \t\n"))&&got<128) idxs[got++]=(uint32_t)strtoul(t,0,10);
            int rc=bip32_derive_path(b,c,a,sl,idxs,got);
            printf("K ");phex(b,32);printf(" ");phex(c,32);printf(" %d\n",rc);
        } else if(strcmp(cmd,"F")==0){
            char s[2048]; if(sscanf(line,"%*s %2047s",s)!=1)continue; hex2(s,a,32);
            uint8_t pub[33],fp[4]; scalar_to_pubkey(pub,a); bip32_fingerprint(fp,pub);
            printf("R ");phex(fp,4);printf("\n");
        } else if(strcmp(cmd,"S")==0){
            int ispriv=0,depth=0,keylen=0; uint32_t child=0; char *t=strtok(line," \t\n");
            t=strtok(NULL," \t\n"); if(t)ispriv=atoi(t);
            t=strtok(NULL," \t\n"); if(t)depth=atoi(t);
            t=strtok(NULL," \t\n"); if(t)hex2(t,a,4);
            t=strtok(NULL," \t\n"); if(t)child=(uint32_t)strtoul(t,0,10);
            t=strtok(NULL," \t\n"); if(t)hex2(t,b,32);
            t=strtok(NULL," \t\n"); if(t)hex2(t,c,64);
            t=strtok(NULL," \t\n"); if(t)keylen=atoi(t);
            uint8_t ser[80];
            int rc=bip32_extkey_serialize(ser,ispriv,depth,a,child,b,c,keylen);
            if(rc!=78){printf("E ERR\n");fflush(stdout);continue;}
            printf("E ");phex(ser,78);printf("\n");
        }
        fflush(stdout);
    }
    return 0;
}
"""

def build_driver(d):
    drv = os.path.join(d, 'b32_driver.c')
    with open(drv, 'w') as f: f.write(DRIVER)
    srclist = ['bitcoin_bip32.S','bitcoin_hmac.S','bitcoin_keys.S','bitcoin_addr.S',
               'sha256.S','sha512.S','ripemd160.S','bitcoin_hash.S',
               'secp256k1_point.S','secp256k1_fe.S','secp256k1_scalar.S']
    here = os.path.dirname(os.path.abspath(__file__))
    cmd = ['gcc', '-O2', '-march=armv8.2-a+sha2', '-o', os.path.join(d, 'b32_driver'), drv] + \
          [os.path.join(here, s) for s in srclist]
    if subprocess.run(cmd).returncode != 0:
        sys.exit('driver build failed: ' + ' '.join(cmd))

def main():
    nseeds = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    iters  = int(sys.argv[2]) if len(sys.argv) > 2 else 800
    d = tempfile.mkdtemp(prefix='bip32fz_')
    build_driver(d)
    binp = os.path.join(d, 'b32_driver')
    total = 0
    for seed in range(1, nseeds + 1):
        rng = random.Random(seed)
        inputs = []
        for _ in range(iters // 4 + 50):
            sd = rng.randbytes(rng.randint(16, 64)); k, c, rc = master(sd)
            inputs.append(("M", f"M {sd.hex()}", (k, c, rc)))
        for _ in range(iters // 2):
            sd = rng.randbytes(rng.randint(16, 64)); k, c, rc = master(sd)
            cur = (k, c); path = []
            for _ in range(rng.randint(1, 12)):
                idx = rng.choice([0, 0x7fffffff, 0x80000000, 0xffffffff,
                                  rng.getrandbits(31),
                                  rng.getrandbits(31) | 0x80000000])
                kp, cp = cur; nk, nc, nrc = ckd(kp, cp, idx)
                if not nrc: break
                inputs.append(("C", f"C {hx(kp)} {hx(cp)} {idx} {hx(kp)} {hx(cp)}", (nk, nc, nrc)))
                path.append(idx); cur = (nk, nc)
            if not path: continue
            inputs.append(("M", f"M {sd.hex()}", (k, c, rc)))
            inputs.append(("D", f"D {sd.hex()} {len(path)} " + " ".join(map(str, path)),
                           (cur[0], cur[1], 1)))
        for _ in range(iters // 4 + 50):
            sd = rng.randbytes(rng.randint(16, 40)); k, c, rc = master(sd)
            if rc and rng.random() < 0.5:
                nk, nc, nrc = ckd(k, c, rng.choice([rng.getrandbits(31), rng.getrandbits(31)|0x80000000]))
                if nrc: k = nk
            pub = compress_pub(int.from_bytes(k, 'big'))
            inputs.append(("F", f"F {k.hex()}", hash160(pub)[:4]))
        for _ in range(iters // 4 + 50):
            sd = rng.randbytes(rng.randint(16, 40)); k, c, rc = master(sd)
            if not rc: continue
            for _ in range(rng.randint(0, 3)):
                nk, nc, nrc = ckd(k, c, rng.choice([rng.getrandbits(31), rng.getrandbits(31)|0x80000000]))
                if nrc: k, c = nk, nc
            depth = rng.randint(0, 254)
            child = rng.choice([0, 1, 0x7fffffff, 0x80000000, 0xffffffff, rng.getrandbits(32)])
            fp = fingerprint(compress_pub(int.from_bytes(k, 'big')))
            inputs.append(("S", f"S 1 {depth} {fp.hex()} {child} {c.hex()} {k.hex()} 32", serialize(1, depth, fp, child, c, k, 32)))
            pub = compress_pub(int.from_bytes(k, 'big'))
            inputs.append(("S", f"S 0 {depth} {fp.hex()} {child} {c.hex()} {pub.hex()} 33", serialize(0, depth, fp, child, c, pub, 33)))
        r = subprocess.run([binp], input=("\n".join(c for _, c, _ in inputs) + "\n"),
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            print(f"BINARY CRASH rc={r.returncode}: {r.stderr[-1500:]}"); sys.exit(1)
        out = [ln for ln in r.stdout.splitlines() if ln.strip()]
        if len(out) != len(inputs):
            print(f"count mismatch {len(out)} vs {len(inputs)}"); sys.exit(1)
        fails = 0
        for (kind, _c, exp), got in zip(inputs, out):
            p = got.split()
            if kind in ("M", "D"):
                ok = p[0] == "K" and p[1] == hx(exp[0]) and p[2] == hx(exp[1]) and int(p[3]) == exp[2]
            elif kind == "C":
                ok = p[0] == "N" and p[1] == hx(exp[0]) and p[2] == hx(exp[1]) and int(p[3]) == exp[2]
            elif kind == "F":
                ok = p[0] == "R" and p[1] == hx(exp)
            else:
                ok = p[0] == "E" and p[1] == hx(exp)
            if not ok:
                fails += 1
                if fails <= 5: print("FAIL", kind, "got", got)
        total += len(inputs)
        print(f"seed={seed} cases={len(inputs)} fails={fails}")
        if fails:
            sys.exit(1)
    print(f"TOTAL cases={total} across {nseeds} seeds: 0 fail")
    sys.exit(0)

if __name__ == "__main__":
    main()
