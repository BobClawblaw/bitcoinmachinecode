#!/usr/bin/env python3
"""fuzz_taproot.py -- independent differential fuzz for the AArch64 taproot
modules port/arm64/secp256k1_taproot.S + port/arm64/bitcoin_bip341.S.

Oracle: an INDEPENDENT pure-Python BIP341/342 implementation (hashlib sha256
only; affine secp256k1 group law for the tweak). Covers, case-exact against
the x86 tree's documented semantics:

  secp256k1_taproot.S:
    * tagged_hash256            sha256(sha256(t)||sha256(t)||msg)
    * tap_leaf_hash             rc: slen > TAP_PREIMG_CAP-70 -> 0 (else 1);
                                msg = ver || canonical-compactsize(slen) || script
    * tap_branch_hash           TapBranch(min(a,b) || max(a,b)) lexicographic
    * tap_merkle_root           depth = (clen-33)>>5 when control nonnull and
                                clen>=33 else 0; node=leaf[0]; per sibling i
                                (control+33+i*32): node=TapBranch(min||max);
                                count parameter IGNORED; returns 1
    * taproot_tweak_pubkey      t=TapTweak(internal||[mr]); Q=P+t*G;
                                rc 0=invalid internal key, 1=even Q.y, 2=odd Q.y

  bitcoin_bip341.S (taproot_sighash_asm):
    the full BIP341 SigMsg builder, byte-for-byte on the preimage and rc,
    vs BOTH the pure-Python oracle AND the C twin (bitcoin_taproot_sighash.c,
    linked into the same driver) -- a three-way comparison. Rules mirrored
    bug-for-bug: tx_parse bounds/canonical-compactsize/table caps;
    n<=0 / n!=tx.nin / n_in>=nin / n_in>=num_inputs -> 0; spk-run walk with
    TS_SPK_RUN_CAP ceiling; hash_type gate (<=0x03 or 0x81..0x83 else 0);
    SIGHASH_SINGLE past the output count -> 0 (BIP341, NOT BIP143's zero);
    spend_type = ext_flag*2 | annex; sha_outputs / sha_single_output hashed
    IN PLACE over the wire slices; annex sha256(cs||annex) with the
    TS_ANNEX_CAP bound; BIP342 ext tail (tapleaf||keyver0||codesep);
    every mid-field cap check in the C's exact order (cap sweep incl. the
    special spk-write check and cap<0); tagged_hash256("TapSighash") finish.

Usage: python3 fuzz_taproot.py [seeks] [iters] [drv]
  seeks: random seeds to run; iters: sighash iterations per seed;
  drv: reuse an existing built driver binary instead of rebuilding.
"""
import sys, os, subprocess, random, tempfile, hashlib

REPO = os.path.dirname(os.path.abspath(__file__)) + "/../.."
PORT = os.path.join(REPO, "port", "arm64")

# ---------------- pure-Python secp256k1 (tweak oracle) ----------------
P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def fe_inv(a): return pow(a, P-2, P)
def ec_add(Pt, Q):
    if Pt is None: return Q
    if Q  is None: return Pt
    (x1,y1),(x2,y2) = Pt,Q
    if x1==x2:
        if (y1+y2)%P==0: return None
        l = (3*x1*x1)*fe_inv(2*y1) % P
    else:
        l = (y2-y1)*fe_inv((x2-x1)%P) % P
    x3 = (l*l - x1 - x2) % P
    return (x3, (l*(x1-x3) - y1) % P)
def ec_mul(k, Pt):
    R = None
    while k:
        if k & 1: R = ec_add(R, Pt)
        Pt = ec_add(Pt, Pt); k >>= 1
    return R
def lift_even_y(x):
    """BIP340 lift_x: x<p and sqrt exists; return even-y point or None."""
    if x >= P: return None
    y2 = (pow(x,3,P) + 7) % P
    y  = pow(y2, (P+1)//4, P)
    if pow(y,2,P) != y2: return None
    if y % 2: y = P - y
    return (x, y)

def sha(b): return hashlib.sha256(b).digest()
def tagged_hash(tag, msg):
    t = sha(tag)
    return sha(t + t + msg)

def put_cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2,'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4,'little')
    return b'\xff' + n.to_bytes(8,'little')
CS = put_cs

# ---------------- oracle: tx_parse + taproot_sighash (C-twin rules) --------
TS_OFF_ENTRIES = 600000
TS_SPK_RUN_CAP = 4 << 20
TS_ANNEX_CAP   = (4 << 20) + 9
TAP_PREIMG_CAP = 4 << 20

def read_cs(buf, pos, end, st):
    """C read_cs: canonical compactsize; st=[ok]; returns (val,newpos)."""
    if pos >= end: st[0]=0; return 0, end
    f = buf[pos]; pos += 1
    if f < 0xfd: return f, pos
    extra = 2 if f==0xfd else (4 if f==0xfe else 8)
    if end - pos < extra: st[0]=0; return 0, end
    if f==0xfd:
        v = int.from_bytes(buf[pos:pos+2],'little'); mn = 0xfd; pos += 2
    elif f==0xfe:
        v = int.from_bytes(buf[pos:pos+4],'little'); mn = 0x10000; pos += 4
    else:
        v = int.from_bytes(buf[pos:pos+8],'little'); mn = 0x100000000; pos += 8
    if v < mn: st[0]=0; return 0, end
    return v, pos

def tx_parse_oracle(tx):
    """Returns view dict or None, mirroring the C's order and bounds."""
    txlen = len(tx)
    if txlen < 10 or txlen > 0xffffffff: return None
    version = int.from_bytes(tx[0:4],'little'); pos = 4
    st = [1]; end = txlen
    nin, pos = read_cs(tx, pos, end, st)
    if not st[0] or nin <= 0: return None
    if nin + 1 > TS_OFF_ENTRIES: return None
    in_off = []
    q = pos
    for i in range(nin):
        in_off.append(q)
        if end - q < 36: return None
        q += 36
        sl, q = read_cs(tx, q, end, st)
        if not st[0] or (end-q) < sl or (end-q) - sl < 4: return None
        q += sl + 4
    in_off.append(q)
    nout, pos = read_cs(tx, q, end, st)
    if not st[0] or nout < 0: return None
    if nin + 1 + nout + 1 > TS_OFF_ENTRIES: return None
    out_off = []
    q = pos
    for i in range(nout):
        out_off.append(q)
        if end - q < 8: return None
        q += 8
        sl, q = read_cs(tx, q, end, st)
        if not st[0] or (end-q) < sl: return None
        q += sl
    out_off.append(q)
    if end - q < 4: return None
    locktime = int.from_bytes(tx[q:q+4],'little')
    return dict(version=version, locktime=locktime, nin=nin, nout=nout,
                in_off=in_off, out_off=out_off, tx=tx)

def tx_seq_oracle(t, i):
    q = t['in_off'][i+1] - 4
    return int.from_bytes(t['tx'][q:q+4],'little')

_SPKBUF = bytearray(TS_SPK_RUN_CAP)   # persistent zero-filled 4MiB, like the driver
_SPK_HW = 0                           # high-water mark of previously-written bytes

def spk_walk_oracle(run, n, n_in):
    """Walk the spk run within [0, TS_SPK_RUN_CAP) over the shared zero-filled
    buffer (mirrors the C reading c->spks, which the driver zero-fills to
    4 MiB past the written data). Returns (ok, wlen, spk_at_nin_or_None)."""
    global _SPK_HW
    nrun = len(run)
    _SPKBUF[:nrun] = run
    if _SPK_HW > nrun:
        _SPKBUF[nrun:_SPK_HW] = bytes(_SPK_HW - nrun)   # clear stale residue
    _SPK_HW = nrun
    end = TS_SPK_RUN_CAP
    st = [1]; pos = 0
    spk_at = None
    for i in range(n):
        sl, pos = read_cs(_SPKBUF, pos, end, st)
        if not st[0] or (end-pos) < sl: return 0, pos, spk_at
        if i == n_in:
            spk_at = bytes(_SPKBUF[pos:pos+sl])
        pos += sl
    return 1, pos, spk_at

def ts_agg_oracle(c, t):
    n = c['num_inputs']
    if n <= 0 or n != t['nin']: return None
    h_prev = sha(c['prevouts'][:n*36])
    h_amt  = sha(c['amounts'][:n*8])
    ok, wlen, spk_nin = spk_walk_oracle(c['spks'], n, c['n_in'])
    if not ok: return None
    h_spk = sha(bytes(_SPKBUF[:wlen]))
    if n*4 > 4*TS_OFF_ENTRIES: return None
    seqbuf = b''.join(tx_seq_oracle(t,i).to_bytes(4,'little') for i in range(n))
    h_seq = sha(seqbuf)
    return (h_prev, h_amt, h_spk, h_seq, spk_nin)

def taproot_sighash_oracle(c, cap):
    """Returns (rc, preimage bytes or None) per the C's exact order."""
    t = tx_parse_oracle(c['tx'])
    if t is None: return 0, None
    if c['n_in'] < 0 or c['n_in'] >= t['nin']: return 0, None
    if c['n_in'] >= c['num_inputs']: return 0, None
    agg = ts_agg_oracle(c, t)
    if agg is None: return 0, None
    h_prev, h_amt, h_spk, h_seq, spk_nin = agg
    if spk_nin is None: return 0, None
    ht = c['hash_type']
    if not (ht <= 0x03 or (0x81 <= ht <= 0x83)): return 0, None
    eff = 1 if ht == 0 else ht
    acp = (eff & 0x80) != 0
    is_single = (eff & 0x03) == 3
    is_none   = (eff & 0x03) == 2
    pre = bytearray()
    pend = cap
    def need(k):
        return len(pre) + k <= pend if pend >= 0 else False
    if not need(1): return 0, None
    pre.append(0x00)                       # epoch
    if not need(1): return 0, None
    pre.append(ht)                         # hash_type
    if not need(4): return 0, None
    pre += (t['version'] & 0xffffffff).to_bytes(4,'little')
    if not need(4): return 0, None
    pre += t['locktime'].to_bytes(4,'little')
    if not acp:
        if not need(128): return 0, None
        pre += h_prev + h_amt + h_spk + h_seq
    if not is_none and not is_single:
        ob = t['tx'][t['out_off'][0]:t['out_off'][t['nout']]]
        if not need(32): return 0, None
        pre += sha(ob)
    annex_present = c['annex'] is not None
    if not need(1): return 0, None
    pre.append((c['ext_flag']*2 + (1 if annex_present else 0)) & 0xff)
    if acp:
        op = t['tx'][t['in_off'][c['n_in']]:t['in_off'][c['n_in']]+36]
        if not need(36): return 0, None
        pre += op
        amt = int.from_bytes(c['amounts'][c['n_in']*8:c['n_in']*8+8],'little')
        if not need(8): return 0, None
        pre += amt.to_bytes(8,'little')
        sl = len(spk_nin)
        if cap < 0 or (cap - len(pre)) < len(put_cs(sl)) + sl: return 0, None
        pre += put_cs(sl) + spk_nin
        if not need(4): return 0, None
        pre += tx_seq_oracle(t, c['n_in']).to_bytes(4,'little')
    else:
        if not need(4): return 0, None
        pre += (c['n_in'] & 0xffffffff).to_bytes(4,'little')
    if annex_present:
        if c['annexlen'] > TS_ANNEX_CAP - 9: return 0, None
        if not need(32): return 0, None
        pre += sha(put_cs(c['annexlen']) + c['annex'])
    if is_single:
        if c['n_in'] < t['nout']:
            sb = t['tx'][t['out_off'][c['n_in']]:t['out_off'][c['n_in']+1]]
            if not need(32): return 0, None
            pre += sha(sb)
        else:
            return 0, None
    if c['ext_flag'] == 1:
        if c['tapleaf'] is None: return 0, None
        if not need(32): return 0, None
        pre += c['tapleaf']
        if not need(1): return 0, None
        pre.append(0x00)                   # key_version
        if not need(4): return 0, None
        pre += (c['codesep_pos'] & 0xffffffff).to_bytes(4,'little')
    if cap < 0 or len(pre) > cap: return 0, None
    return len(pre), bytes(pre)        # (rc, PREIMAGE); digest derived in chk

def tap_leaf_oracle(ver, script):
    if len(script) > TAP_PREIMG_CAP - 70: return 0, None
    msg = bytes([ver]) + CS(len(script)) + script
    return 1, tagged_hash(b"TapLeaf", msg)

def tap_branch_oracle(a, b):
    m = a + b if a <= b else b + a
    return tagged_hash(b"TapBranch", m)

def merkle_root_oracle(leaf0, siblings):
    node = leaf0
    for sib in siblings:
        node = tap_branch_oracle(node, sib)
    return node

def tweak_oracle(internal_x, mr):
    Pt = lift_even_y(int.from_bytes(internal_x,'big'))
    if Pt is None: return 0, None
    t = int.from_bytes(tagged_hash(b"TapTweak", internal_x + (mr or b'')),'big')
    Q = ec_add(Pt, ec_mul(t % N, (Gx,Gy)))
    if Q is None: return 0, None     # t*G == -P: unreachable in practice
    x, y = Q
    return (2 if y & 1 else 1), x.to_bytes(32,'big')

# ---------------- driver ----------------------------------------------------
DRIVER_C = r'''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;
typedef long long i64;
typedef struct { const u8* tx; i64 txlen; i64 n_in; u8 hash_type;
  const u8* prevouts; const u8* amounts; const u8* spks; i64 num_inputs;
  int ext_flag; const u8* tapleaf; u32 codesep_pos; const u8* annex; u64 annexlen;
} tapctx_t;
extern long taproot_sighash(u8*, const tapctx_t*, u8*, long);
extern long taproot_sighash_asm(u8*, const tapctx_t*, u8*, long);
extern void tagged_hash256(u8*, const char*, u64, const u8*, u64);
extern long tap_leaf_hash(u8*, u8, const u8*, u64);
extern void tap_branch_hash(u8*, const u8*, const u8*);
extern long tap_merkle_root(u8*, const u8*, u64, const u8*, u64);
extern long taproot_tweak_pubkey(u8*, const u8*, const u8*);
long mempool_resolve_confirmed_utxo(void* u, const u8 t[32], unsigned long i,
    unsigned long long* v, const u8** s, unsigned long* l){
  (void)u;(void)t;(void)i;(void)v;(void)s;(void)l; abort(); }
static u8 *pre_a, *pre_c, *spk_run, *bigbuf;
#define PRECAP 8192
static void hexout(const u8* b, long n){ for(long i=0;i<n;i++) printf("%02x", b[i]); }
static u8* unhex(const char* s, long* n){ *n = strlen(s)/2;
  u8* b = malloc(*n?*n:1);
  for(long i=0;i<*n;i++){ unsigned x; sscanf(s+2*i,"%2x",&x); b[i]=x; } return b; }
static char* nextarg(char* p){ while(*p && *p!=' ') p++; while(*p==' ') p++; return p; }
int main(void){
  pre_a = malloc(PRECAP); pre_c = malloc(PRECAP);
  spk_run = malloc((4u<<20) + 4096);
  bigbuf = malloc(5u<<20);
  static char line[1<<20];
  while (fgets(line, sizeof line, stdin)){
    char op[16]; if (sscanf(line, "%15s", op) != 1) continue;
    if (!strcmp(op, "taghash")){
      char tag[512], msg[4096]; long tn, mn; u8 out[32];
      if (sscanf(line+8, "%511s %4095s", tag, msg) != 2) { puts("E"); continue; }
      long tempty = !strcmp(tag,"-"), mempty = !strcmp(msg,"-");
      if (tempty && mempty) { puts("E"); continue; }
      u8* tb = tempty?(u8*)"":unhex(tag,&tn);
      u8* mb = mempty?(u8*)"":unhex(msg,&mn);
      if (tempty) tn = 0; if (mempty) mn = 0;
      tagged_hash256(out, (char*)tb, tn, mb, mn);
      printf("R "); hexout(out,32); putchar('\n');
      if (!tempty) free(tb); if (!mempty) free(mb);
    } else if (!strcmp(op, "leaf")){
      unsigned ver; char s[4000]; u8 out[32]; long sn = 0;
      int nf = sscanf(line+5, "%u %3999s", &ver, s);
      if (nf < 1){ puts("E"); continue; }
      u8* sb = (u8*)"";
      if (nf >= 2 && strcmp(s,"-")) sb = unhex(s,&sn);
      long rc = tap_leaf_hash(out, (u8)ver, sb, (u64)sn);
      printf("R %ld ", rc); if (rc>0) hexout(out,32); else printf("-");
      putchar('\n');
      if (sn) free(sb);
    } else if (!strcmp(op, "leafbig") || !strcmp(op, "leafrc")){
      u8 out[32]; long rc;
      unsigned long n = strtoul(nextarg(line+4), NULL, 10);
      if (!strcmp(op, "leafbig")){
        for (unsigned long i=0;i<n;i++) bigbuf[i] = (u8)(i & 0xff);
        rc = tap_leaf_hash(out, 0xc0, bigbuf, n);
      } else {
        u8 tiny[16];
        rc = tap_leaf_hash(out, 0xc0, tiny, n);   /* bound must fire BEFORE copy */
      }
      printf("R %ld ", rc); if (rc>0) hexout(out,32); else printf("-");
      putchar('\n');
    } else if (!strcmp(op, "branch")){
      char a[80], b[80]; long an, bn; u8 out[32];
      if (sscanf(line+7, "%79s %79s", a, b) != 2){ puts("E"); continue; }
      u8* ab = unhex(a,&an); u8* bb = unhex(b,&bn);
      tap_branch_hash(out, ab, bb);
      printf("R "); hexout(out,32); putchar('\n'); free(ab); free(bb);
    } else if (!strcmp(op, "merkle")){
      char l[80], ctl[1200]; unsigned long cnt; long ln, cn; u8 out[32];
      if (sscanf(line+7, "%79s %lu %1199s", l, &cnt, ctl) != 3){ puts("E"); continue; }
      u8* lb = unhex(l,&ln); u8* cb = unhex(ctl,&cn);
      long rc = tap_merkle_root(out, lb, cnt, cn?cb:NULL, (u64)cn);
      printf("R %ld ", rc); if (rc>0) hexout(out,32); else printf("-");
      putchar('\n'); free(lb); free(cb);
    } else if (!strcmp(op, "tweak")){
      char k[80], mr[80]; long kn, mn; u8 out[32];
      if (sscanf(line+6, "%79s %79s", k, mr) != 2){ puts("E"); continue; }
      u8* kb = unhex(k,&kn); u8* mb = strcmp(mr,"-")?unhex(mr,&mn):NULL;
      long rc = taproot_tweak_pubkey(out, kb, mb);
      printf("R %ld ", rc); if (rc) hexout(out,32); else printf("-");
      putchar('\n'); free(kb); if (mb) free(mb);
    } else if (!strcmp(op, "sh")){
      /* sh tx n_in ht num_inputs prevouts amounts spkrun annex|NULL extflag
         tapleaf|- codesep cap */
      static char txh[280000], prh[40000], amh[12000], spkh[40000], anx[9000], tl[80];
      long txn, pn, amn, sn, ann, tln; long nin_; unsigned long ht, numin, ext, cs;
      long cap;
      if (sscanf(line+3, "%279999s %ld %lu %lu %39999s %11999s %39999s %8999s %lu %79s %lu %ld",
                 txh, &nin_, &ht, &numin, prh, amh, spkh, anx, &ext, tl, &cs, &cap) != 12){
        puts("E"); continue; }
      u8* tb2 = unhex(txh,&txn);
      if (txn == 0){                       /* "-" sentinel: empty tx */
        free(tb2);
        puts("R A 0 - - | C 0 - -");
        continue;
      }
      u8* txb = malloc((size_t)txn + 4096);
      memcpy(txb, tb2, txn); memset(txb+txn, 0, 4096); free(tb2);
      u8* prb = strcmp(prh,"-")?unhex(prh,&pn):NULL;
      u8* amb = strcmp(amh,"-")?unhex(amh,&amn):NULL;
      u8* runb = unhex(spkh,&sn);
      memset(spk_run, 0, (4u<<20));
      memcpy(spk_run, runb, sn); free(runb);
      u8* anb = strcmp(anx,"-")?unhex(anx,&ann):NULL;
      if (anb && ann == 0){}                /* "z" sentinel: 0-byte present annex */
      u8* tlb = strcmp(tl,"-")?unhex(tl,&tln):NULL;
      tapctx_t c; memset(&c,0,sizeof c);
      c.tx = txb; c.txlen = txn; c.n_in = (i64)nin_; c.hash_type = (u8)ht;
      c.prevouts = prb; c.amounts = amb; c.spks = spk_run;
      c.num_inputs = (i64)numin; c.ext_flag = (int)ext; c.tapleaf = tlb;
      c.codesep_pos = (u32)cs; c.annex = anb; c.annexlen = anb?(u64)ann:0;
      memset(pre_a, 0xE7, PRECAP); memset(pre_c, 0xE7, PRECAP);
      u8 ha[32], hc[32];
      long ra = taproot_sighash_asm(ha, &c, pre_a, cap);
      long rc2 = taproot_sighash(hc, &c, pre_c, cap);
      printf("R A %ld ", ra); if (ra>0){ hexout(ha,32); putchar(' '); hexout(pre_a, ra);} else printf("- -");
      printf(" | C %ld ", rc2); if (rc2>0){ hexout(hc,32); putchar(' '); hexout(pre_c, rc2);} else printf("- -");
      putchar('\n');
      free(txb); if (prb) free(prb); if (amb) free(amb);
      if (anb) free(anb); if (tlb) free(tlb);
    } else puts("E");
  }
  return 0;
}
'''

def build_driver(drv):
    if drv and os.path.exists(drv): return drv
    tmp = tempfile.mkdtemp(prefix="fz_tap_")
    cs = os.path.join(tmp, "fz_taproot.c")
    with open(cs, "w") as f: f.write(DRIVER_C)
    mods = ["bitcoin_bip341", "secp256k1_taproot", "sha256", "bitcoin_pubkey",
            "secp256k1_point", "secp256k1_point_ct",
            "secp256k1_fe", "secp256k1_scalar",
            "secp256k1_schnorr", "bitcoin_interp", "bitcoin_scriptcodec",
            "bitcoin_sighash", "ripemd160", "sha1", "bitcoin_hash"]
    cmods = ["secp256k1_glv_c", "secp256k1_scalar_c"]  # C upstream, not asm
    objs = []
    for m in mods + cmods:
        o = os.path.join(tmp, m + ".o")
        src = os.path.join(PORT, m + ".S")
        if not os.path.exists(src):
            src = os.path.join(REPO, "asm", m + ".c")
        r = subprocess.run(["gcc","-c","-O2","-I",os.path.join(REPO,"asm"),
                            "-o",o,src])
        if r.returncode: raise SystemExit("compile failed: " + m)
        objs.append(o)
    twin_c = os.path.join(REPO, "asm", "bitcoin_taproot_sighash.c")
    o = os.path.join(tmp, "twin.o")
    r = subprocess.run(["gcc","-c","-O2","-I",os.path.join(REPO,"asm"),"-o",o,twin_c])
    if r.returncode: raise SystemExit("compile failed: twin")
    objs.append(o)
    exe = drv or os.path.join(tmp, "fz_taproot")
    r = subprocess.run(["gcc","-O2","-no-pie","-o",exe,cs] + objs)
    if r.returncode: raise SystemExit("link failed")
    return exe

# ---------------- case generation ------------------------------------------
def gen_helpers(rnd):
    """tagged_hash / leaf / branch / merkle / tweak cases -> (line, check)."""
    tlen = rnd.choice([1,2,8,9,10,16,64,0])
    mlen = rnd.choice([0,1,5,32,64,100,1000])
    tag = bytes(rnd.randrange(256) for _ in range(tlen))
    msg = bytes(rnd.randrange(256) for _ in range(mlen))
    yield ("taghash %s %s" % (tag.hex() if tag else "-",
                              msg.hex() if msg else "-"),
           lambda out, t=tag, m=msg: out == "R " + tagged_hash(t,m).hex())

    ver = rnd.choice([0xc0, 0xc0, 0xc0, 0xbe, 0x00, 0xff])
    sl = rnd.choice([0,1,2,10,32,100,252,253,254,300])
    script = bytes(rnd.randrange(256) for _ in range(min(sl,4096)))
    script = script + bytes(sl - len(script))
    rc_o, h_o = tap_leaf_oracle(ver, script)
    yield ("leaf %d %s" % (ver, script.hex() if script else "-"),
           lambda out, rc=rc_o, h=h_o:
           out == ("R %d %s" % (rc, h.hex() if h else "-")))
    # BOUNDARY + oversize, driver-side scripts (no giant hex lines)
    for n in (TAP_PREIMG_CAP-71, TAP_PREIMG_CAP-70):
        pat = (bytes(range(256)) * (n // 256)) + bytes(range(n % 256))
        rc_o, h_o = tap_leaf_oracle(0xc0, pat)
        yield ("leafbig %d" % n,
               lambda out, rc=rc_o, h=h_o:
               out == ("R %d %s" % (rc, h.hex() if h else "-")))
    for n in (TAP_PREIMG_CAP-69, 10**9, 2**32, 2**40):
        yield ("leafrc %d" % n, lambda out: out == "R 0 -")

    a = bytes(rnd.randrange(256) for _ in range(32))
    b = bytes(rnd.randrange(256) for _ in range(32))
    if rnd.random() < 0.2: b = a
    yield ("branch %s %s" % (a.hex(), b.hex()),
           lambda out, a=a, b=b: out == "R " + tap_branch_oracle(a,b).hex())

    depth = rnd.choice([0,1,1,2,2,3,4,5,6,7])
    leaf0 = bytes(rnd.randrange(256) for _ in range(32))
    sibs = [bytes(rnd.randrange(256) for _ in range(32)) for _ in range(depth)]
    ctl = bytes([0xc0 | rnd.randrange(2)]) + bytes(32)   # control[1..32] ignored
    ctl += b"".join(sibs)
    root_o = merkle_root_oracle(leaf0, sibs)
    cnt = rnd.choice([0,1,2,depth,depth+3])              # count is IGNORED by x86
    ctlhex = ctl.hex() if depth else ctl[:33].hex()
    yield ("merkle %s %d %s" % (leaf0.hex(), cnt, ctlhex),
           lambda out, r=root_o: out == "R 1 " + r.hex())
    # short/empty control (<33) => single-leaf root == leaf0
    yield ("merkle %s %d %s" % (leaf0.hex(), 0, ctl[:rnd.choice([0,32])].hex() or "-"),
           lambda out, l=leaf0: out == "R 1 " + l.hex())

    # tweak: valid keys (random lifts), mr present/absent; parity must match
    for _ in range(2):
        x = rnd.randrange(1, P)
        pt = lift_even_y(x)
        if pt is None: continue
        ix = pt[0].to_bytes(32,'big')
        mr = bytes(rnd.randrange(256) for _ in range(32)) if rnd.random()<0.7 else None
        rc_o, outx = tweak_oracle(ix, mr)
        yield ("tweak %s %s" % (ix.hex(), mr.hex() if mr else "-"),
               lambda out, rc=rc_o, ox=outx:
               out == ("R %d %s" % (rc, ox.hex() if ox else "-")))
    # invalid internal keys: x>=p, or off-curve x
    bad = rnd.choice([P, P + rnd.randrange(1000)])
    yield ("tweak %s -" % bad.to_bytes(32,'big').hex(),
           lambda out: out == "R 0 -")
    bx = rnd.randrange(1, 1 << 200)                      # almost surely off-curve
    if lift_even_y(bx) is None:
        yield ("tweak %s -" % bx.to_bytes(32,'big').hex(),
               lambda out: out == "R 0 -")

def gen_sighash(rnd):
    """One random taproot_sighash context -> (line, check fn)."""
    nin = rnd.randrange(1, 40)
    nout = rnd.randrange(0, 40)
    tx = bytearray()
    tx += rnd.choice([1,2,3]).to_bytes(4,'little')
    tx += CS(nin)
    for i in range(nin):
        tx += bytes(rnd.randrange(256) for _ in range(32))
        tx += rnd.randrange(0, 100).to_bytes(4,'little')
        slen = rnd.choice([0,0,1,5,17,71,100,252])
        tx += CS(slen) + bytes(rnd.randrange(256) for _ in range(slen))
        tx += rnd.choice([0xffffffff, 0xfffffffe, 0, 1, 66000000]).to_bytes(4,'little')
    tx += CS(nout)
    for i in range(nout):
        tx += rnd.randrange(0, 21 * 10**10).to_bytes(8,'little')
        slen = rnd.choice([0,1,3,4,25,34,76,300])
        tx += CS(slen) + bytes(rnd.randrange(256) for _ in range(slen))
    tx += rnd.randrange(0, 2**32).to_bytes(4,'little')
    tx = bytes(tx)

    num_inputs = nin if rnd.random() < 0.9 else rnd.choice([0, nin-1 if nin>1 else 5, nin+1])
    n_in = rnd.randrange(0, nin) if rnd.random() < 0.9 else rnd.choice([-1, nin, nin+7])
    ht = rnd.choice([0x00,0x01,0x02,0x03,0x81,0x82,0x83,   # valid
                     0x04,0x05,0x80,0x84,0xff,             # invalid
                     0x01,0x02,0x03,0x81,0x82])
    ext_flag = rnd.choice([0,0,0,1,1])
    tapleaf = bytes(rnd.randrange(256) for _ in range(32)) if rnd.random() < 0.85 else None
    codesep = rnd.choice([0xffffffff, 0, rnd.randrange(0, 5000)])
    # spk run: num_inputs entries, each len<=252 (single-byte cs), then corruption
    run = bytearray()
    for i in range(max(num_inputs, 0)):
        sl = rnd.choice([0,1,4,22,34,76,252])
        run += bytes([sl]) + bytes(rnd.randrange(256) for _ in range(sl))
    run = bytes(run)
    prevouts = bytes(rnd.randrange(256) for _ in range(max(num_inputs,0)*36))
    amounts  = bytes(rnd.randrange(256) for _ in range(max(num_inputs,0)*8))
    annex = None
    if rnd.random() < 0.4:
        al = rnd.choice([0,1,5,32,100,253,300,4090])
        annex = bytes(rnd.randrange(256) for _ in range(al))
    # malformed variants
    mode = rnd.random()
    if mode < 0.06:
        if rnd.random() < 0.5:
            tx = tx[:rnd.randrange(1, len(tx))]           # truncate (nonempty)
        else:
            tx = b""                                       # empty tx (sentinel)
    elif mode < 0.10 and len(tx) > 8:
        tx = tx[:4] + b'\xfd' + b'\x00\x00' + tx[7:]      # non-canonical nin
    elif mode < 0.13:
        run = run[:max(len(run)-rnd.randrange(1,20),0)]   # truncated run
    elif mode < 0.16:
        run = bytes([0xfe]) + run[:200]                   # non-canonical run cs
    if num_inputs <= 0:
        prevouts = b''; amounts = b''

    cap = rnd.choice([8192, 8192, 8192,
                      0, -1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 40, 128,
                      160, 176, 192, 200, 208, 216, 244])
    c = dict(tx=tx, n_in=n_in, hash_type=ht, num_inputs=num_inputs,
             prevouts=prevouts, amounts=amounts, spks=run,
             ext_flag=ext_flag, tapleaf=tapleaf, codesep_pos=codesep,
             annex=annex, annexlen=(len(annex) if annex is not None else 0))
    rc_o, pre_o = taproot_sighash_oracle(dict(c), cap)
    line = ("sh %s %d %d %d %s %s %s %s %d %s %d %d" %
            (tx.hex() if tx else "-",
             n_in, ht, num_inputs,
             prevouts.hex() if prevouts else "-",
             amounts.hex() if amounts else "-",
             run.hex() if run else "00",
             annex.hex() if annex else ("z" if annex is not None else "-"),
             ext_flag, tapleaf.hex() if tapleaf else "-", codesep, cap))
    def chk(out, rc=rc_o, pre=pre_o):
        toks = [t for t in out.split() if t != "|"]
        if len(toks) < 3 or toks[0] != "R": return False
        i = 1
        for side in ("A", "C"):
            if i+1 >= len(toks) or toks[i] != side: return False
            r = int(toks[i+1]); i += 2
            if r != rc: return False
            if r > 0:
                if toks[i] != tagged_hash(b"TapSighash", pre).hex(): return False
                if toks[i+1] != pre.hex(): return False
                i += 2
            else:
                if toks[i] != "-" or toks[i+1] != "-": return False
                i += 2
        return True
    yield line, chk

def run_seed(drv, seed, iters, fails):
    rnd = random.Random(seed)
    sys.stderr.write("seed %d: " % seed); sys.stderr.flush()
    # Build the full input up front and use subprocess.run so both pipes are
    # pumped concurrently (a stdin-write + stdout-read sequence on pipes
    # deadlocks once output exceeds the pipe buffer, ~64KB).
    lines = []
    for line, chk in gen_helpers(rnd):
        lines.append(line)
    n_h = len(lines)
    for i in range(iters):
        for line, chk in gen_sighash(rnd):
            lines.append(line)
    n_s = len(lines) - n_h
    inp = "".join(ln + "\n" for ln in lines)
    r = subprocess.run([drv], input=inp, capture_output=True, text=True,
                       timeout=600)
    if r.returncode: raise SystemExit("driver exited %d" % r.returncode)
    outs = r.stdout.splitlines()
    sys.stderr.write("%d helper + %d sighash cases\n" % (n_h, n_s))
    if len(outs) != n_h + n_s:
        raise SystemExit("driver line count %d != cases %d" % (len(outs), n_h+n_s))
    # deterministic replay to pair outputs with cases
    rnd2 = random.Random(seed)
    cases = list(gen_helpers(rnd2))
    for i in range(iters):
        cases.extend(gen_sighash(rnd2))
    for out, (line, chk) in zip(outs, cases):
        if not chk(out):
            fails.append((line, out))
            if len(fails) <= 12:
                print("FAIL case: %s" % line[:220])
                print("  got: %s" % out[:420])

def main():
    seeks = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    iters = int(sys.argv[2]) if len(sys.argv) > 2 else 1200
    drv = sys.argv[3] if len(sys.argv) > 3 else None
    exe = build_driver(drv)
    fails = []
    for seed in range(1, seeks+1):
        run_seed(exe, seed, iters, fails)
    if fails:
        print("RESULT: %d FAILURES" % len(fails))
        sys.exit(1)
    print("RESULT: ALL PASS (%d seeds x (%d sighash + ~14 helper cases), "
          "0 fail -- asm vs C twin vs Python oracle, byte-exact)" % (seeks, iters))

if __name__ == "__main__":
    main()
