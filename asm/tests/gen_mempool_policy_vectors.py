#!/usr/bin/env python3
"""gen_mempool_policy_vectors.py -- independent Python oracle for the mempool
POLICY layer. Emits mempool_policy_vec.h consumed by test_mempool_policy.c.

The oracle re-implements the policy rules independently of the C module under
test (bitcoin_mempool_policy.c):
  1. structural parse,
  2. fee = sum(inputs) - sum(outputs); reject negative fee,
  3. min relay feerate floor: fee >= vsize * relay_fee_rate,
  4. duplicate reject,
  5. double-spend reject, and BIP125 RBF when enabled:
       * the new tx must signal replaceable (some input seq & 0x80000000 == 0),
       * new absolute fee >= sum(replaced fees) + incremental (incremental =
         relay_fee_rate * 1000),
       * on accept, the replaced txs are evicted,
  6. ancestor / descendant count and byte-budget limits,
  7. fee estimator (EMA of accepted feerates, k=4).

We then emit scenario tables. Each scenario is an isolated policy world
(policy config + confirmed-UTXO preload) with an ordered list of steps; each
step either preloads a UTXO, adds a tx (expecting accept/reject), or asserts
the current estimated feerate / mempool contents.
"""
import hashlib

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2,'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4,'little')
    return b'\xff' + n.to_bytes(8,'little')

def mk_tx(prevouts, outputs, seqs=None, version=2, locktime=0):
    if seqs is None: seqs = [0xffffffff]*len(prevouts)
    b = version.to_bytes(4,'little')
    b += varint(len(prevouts))
    for (t,i),s in zip(prevouts,seqs):
        b += t + i.to_bytes(4,'little') + varint(0) + s.to_bytes(4,'little')
    b += varint(len(outputs))
    for v,sc in outputs:
        b += v.to_bytes(8,'little') + varint(len(sc)) + sc
    b += locktime.to_bytes(4,'little')
    return b

class RefPolicy:
    """Independent reference mempool-policy engine."""
    def __init__(self, relay=1, max_anc=1000, max_anc_bytes=1<<30,
                 max_desc=1000, max_desc_bytes=1<<30, rbf=True):
        self.relay=relay; self.incr=relay*1000
        self.max_anc=max_anc; self.max_anc_bytes=max_anc_bytes
        self.max_desc=max_desc; self.max_desc_bytes=max_desc_bytes
        self.rbf=rbf
        self.utxo={}      # (txid,index)->value  (confirmed)
        self.out={}       # (txid,index)->value  (mempool outputs; owner==txid)
        self.claims={}; self.node_ins={}    # (prev_txid,index)->claimer_txid
        self.nodes={}     # txid -> dict
        self.est=0; self.est_n=0

    def ancestors_of(self, txid):
        seen=set(); st=list(self.nodes[txid]['parents'])
        while st:
            p=st.pop()
            if p in seen: continue
            seen.add(p); st.extend(self.nodes[p]['parents'])
        return seen

    def parse_inputs(self, tx):
        p=4
        if tx[p:p+2]==b'\x00\x01': p+=2
        n_in=tx[p]; p+=1
        ins=[]
        for _ in range(n_in):
            t=tx[p:p+32]; i=int.from_bytes(tx[p+32:p+36],'little'); p+=36
            sl=tx[p]; p+=1
            seq=int.from_bytes(tx[p+sl:p+sl+4],'little'); p+=sl+4
            ins.append((t,i,seq))
        return ins

    def add(self, tx, txid, label):
        ins=self.parse_inputs(tx)
        # outputs sum
        # re-walk to outputs for sum (policy doesn't need indices)
        # (we recompute via a second pass helper)
        sum_in=0; sum_out=0
        # inputs first pass already have (t,i,seq); resolve values
        # We need sum_out: re-derive by scanning; do a small parse
        # (same walk, capture outputs)
        # simplest: call parse_io
        ins2, outs2 = self.parse_io(tx)
        sum_in=0
        for (t,i,seq) in ins2:
            if (t,i) in self.out: sum_in+=self.out[(t,i)]
            elif (t,i) in self.utxo: sum_in+=self.utxo[(t,i)]
            else: return 0,"input-missing"
        sum_out=sum(v for (v,sc) in outs2)
        fee=sum_in-sum_out
        if fee<0: return 0,"negative-fee"
        if fee< len(tx)*self.relay: return 0,"low-fee"
        if txid in self.nodes: return 0,"duplicate"
        # conflicts
        conf=set()
        for (t,i,seq) in ins2:
            if (t,i) in self.claims: conf.add(self.claims[(t,i)])
        # RBF, Core semantics (2026-08-27 mempool-policy parity): with
        # rbf(==fullrbf) ON, no signaling requirement at all; with it OFF the
        # REPLACED txs must signal (classic BIP125 rule 1 -- checked on the
        # conflicts, never on the replacement). Rules 3+4: pay all replaced
        # fees AND the increment covers the replacement's own vsize at the
        # incremental rate (fixtures are non-witness: vsize == len).
        if conf:
            if not self.rbf:
                for c in conf:
                    c_ins = self.node_ins.get(c, [])
                    if not any(s < 0xfffffffe for (_,_,s) in c_ins):
                        return 0,"conflict-not-signaling"
            repl_fee=sum(self.nodes[c]['fee'] for c in conf)
            if fee < repl_fee: return 0,"rbf-low"
            need = self.incr * len(tx) // 1000
            if need == 0: need = 1
            if fee - repl_fee < need: return 0,"rbf-low"
        # ancestors
        parents={t for (t,i,seq) in ins2 if (t,i) in self.out}
        anc=set()
        for p in parents: anc|=self.ancestors_of(p); anc.add(p)
        anc_cnt=1+len(anc)
        anc_bytes=len(tx)+sum(self.nodes[a]['size'] for a in anc)
        if anc_cnt>self.max_anc or anc_bytes>self.max_anc_bytes: return 0,"anc"
        for a in anc:
            if self.nodes[a]['des']+1>self.max_desc: return 0,"desc"
            if self.nodes[a]['des_bytes']+len(tx)>self.max_desc_bytes: return 0,"desc"
        # commit
        for c in conf:
            del self.nodes[c]
            for k in list(self.claims):
                if self.claims[k]==c: del self.claims[k]
            for k in list(self.out):
                if k[0]==c: del self.out[k]
        for idx,(v,sc) in enumerate(outs2): self.out[(txid,idx)]=v
        for (t,i,seq) in ins2: self.claims[(t,i)]=txid
        self.nodes[txid]={'size':len(tx),'fee':fee,'parents':parents,
                          'des':1,'des_bytes':len(tx)}
        self.node_ins[txid]=list(ins2)
        for a in anc:
            self.nodes[a]['des']+=1; self.nodes[a]['des_bytes']+=len(tx)
        for p in parents: self.nodes[p]['children'].add(txid)
        self.nodes[txid]['children']=set()
        parent_nodes=self.nodes[txid]['parents']
        for p in parent_nodes:
            if p not in self.ancestors_of(txid): pass
        # estimator EMA k=4
        x=fee*1000//len(tx)
        self.est += (x-self.est)//4
        self.est_n+=1
        return 1,"accepted"

    def parse_io(self, tx):
        p=4
        if tx[p:p+2]==b'\x00\x01': p+=2
        n_in=tx[p]; p+=1
        ins=[]
        for _ in range(n_in):
            t=tx[p:p+32]; i=int.from_bytes(tx[p+32:p+36],'little'); p+=36
            sl=tx[p]; p+=1
            seq=int.from_bytes(tx[p+sl:p+sl+4],'little'); p+=sl+4
            ins.append((t,i,seq))
        n_out=tx[p]; p+=1
        outs=[]
        for _ in range(n_out):
            v=int.from_bytes(tx[p:p+8],'little'); p+=8
            sl=tx[p]; p+=1
            outs.append((v,tx[p:p+sl])); p+=sl
        return ins,outs

# hashlib-based "coins" as distinct 32-byte funding outpoints
COIN_A=sha256d(b'coinAAAAAAAAAAAAAAAAAAAAAAAA'); COIN_B=sha256d(b'coinBBBBBBBBBBBBBBBBBBBBBBBB')
COIN_C=sha256d(b'coinCCCCCCCCCCCCCCCCCCCCCCCC'); COIN_D=sha256d(b'coinDDDDDDDDDDDDDDDDDDDDDDDD')
COIN_E=sha256d(b'coinEEEEEEEEEEEEEEEEEEEEEEEE'); COIN_F=sha256d(b'coinFFFFFFFFFFFFFFFFFFFFFFFF')

# =============================================================================
# scenarios: list of dicts:
#   name, relay, max_anc, max_anc_bytes, max_desc, max_desc_bytes, rbf,
#   utxo: list of (txid_hex,index,value) to preload,
#   steps: list of tuples:
#      ("utxo", txid_hex,index,value)                     preload confirmed output
#      ("add", tx_hex, txid_hex, expect(1/0))
#      ("est", expected_est)                              assert feerate equals
#      ("present", txid_hex, expect(1/0))                 assert in mempool
# =============================================================================
scenarios=[]

# ---- S1: basic accept + low fee + double-spend + RBF ------------------------
s=dict(name="core", relay=1, max_anc=1000, max_anc_bytes=1<<30,
       max_desc=1000, max_desc_bytes=1<<30, rbf=1, utxo=[], steps=[])
for c,v in [(COIN_A,100000),(COIN_B,100000),(COIN_C,100000),(COIN_D,100000),(COIN_E,100000)]:
    s["utxo"].append((c.hex(),0,v))
mp=RefPolicy(relay=1, rbf=True)
for (h,ix,v) in s["utxo"]:
    mp.utxo[(bytes.fromhex(h), ix)] = v

tx=[]; tid=[]
def step_add(t, expect):
    tid_=sha256d(t)
    r,_=mp.add(t,tid_,"x")
    # override: some expected (like not-replaceable) need manual seq handling;
    # oracle models seq, so r should equal expectation unless we special-case.
    s["steps"].append(("add", t.hex(), tid_.hex(), expect))
    assert r==expect, ("oracle mismatch", tid_.hex(), r, expect)

# accept valid
t=mk_tx([(COIN_A,0)],[(90000,b'\x51')])
step_add(t,1)
# low fee (fee 5 sat, relay floor: len~66 *1 = 66)
t=mk_tx([(COIN_B,0)],[(99995,b'\x51')])
step_add(t,0)
# double-spend: spend COIN_C with non-replaceable seq
t=mk_tx([(COIN_C,0)],[(90000,b'\x51')],seqs=[0xffffffff]); tid1=sha256d(t)
r,_=mp.add(t,tid1,"x"); assert r==1; s["steps"].append(("add",t.hex(),tid1.hex(),1))
# a SECOND tx, same prevout: under fullrbf (Core default) this is a
# replacement ATTEMPT regardless of signaling -- and it fails rule 3, paying
# less than the tx it would replace ('insufficient fee').
t=mk_tx([(COIN_C,0)],[(95000,b'\x51')],seqs=[0xffffffff]); 
r,_=mp.add(t,sha256d(t),"x"); assert r==0 and _=="rbf-low",(r,_)
s["steps"].append(("add",t.hex(),sha256d(t).hex(),0))
# RBF: spend COIN_D replaceable
t=mk_tx([(COIN_D,0)],[(92000,b'\x51')],seqs=[0xfffffffe]); tidD1=sha256d(t)
r,_=mp.add(t,tidD1,"x"); assert r==1; s["steps"].append(("add",t.hex(),tidD1.hex(),1))
# RBF replacement higher fee (10000 >= 8000+1000)
t=mk_tx([(COIN_D,0)],[(90000,b'\x51')],seqs=[0xfffffffe]); tidD2=sha256d(t)
r,_=mp.add(t,tidD2,"x"); assert r==1
s["steps"].append(("add",t.hex(),tidD2.hex(),1))
s["steps"].append(("present",tidD1.hex(),0))   # D1 evicted
s["steps"].append(("present",tidD2.hex(),1))   # D2 present
# RBF rule 4 (Core): the increment must cover the REPLACEMENT'S OWN VSIZE at
# the incremental rate -- ~66 sat for these fixtures, NOT a flat 1 kvB. A
# +500 sat bump therefore succeeds (the flat-1000 gate was this node's old
# divergence); a +0 bump fails rule 3/4.
t=mk_tx([(COIN_E,0)],[(95000,b'\x51')],seqs=[0xfffffffe]); tidE1=sha256d(t)
r,_=mp.add(t,tidE1,"x"); assert r==1; s["steps"].append(("add",t.hex(),tidE1.hex(),1))
t=mk_tx([(COIN_E,0)],[(94500,b'\x51')],seqs=[0xfffffffe]); tidE2=sha256d(t)
r,_=mp.add(t,tidE2,"x"); assert r==1,(r,_)
s["steps"].append(("add",t.hex(),tidE2.hex(),1))
s["steps"].append(("present",tidE1.hex(),0))
s["steps"].append(("present",tidE2.hex(),1))
# and an EQUAL-fee replacement fails rule 3/4 ('insufficient fee')
t=mk_tx([(COIN_E,0)],[(94500,b'\x52')],seqs=[0xfffffffe])
r,_=mp.add(t,sha256d(t),"x"); assert r==0 and _=="rbf-low",(r,_)
s["steps"].append(("add",t.hex(),sha256d(t).hex(),0))
s["steps"].append(("present",tidE2.hex(),1))
scenarios.append(s)

# ---- S2: ancestor limit (max_anc=3) -----------------------------------------
s=dict(name="ancestor", relay=1, max_anc=3, max_anc_bytes=1<<30,
       max_desc=1000, max_desc_bytes=1<<30, rbf=1, utxo=[(COIN_A.hex(),0,100000)], steps=[])
mp=RefPolicy(relay=1,max_anc=3)
for (h,ix,v) in s["utxo"]: mp.utxo[(bytes.fromhex(h), ix)] = v
t=mk_tx([(COIN_A,0)],[(90000,b'\x51')]); idP=sha256d(t); r,_=mp.add(t,idP,"x"); assert r==1
s["steps"].append(("add",t.hex(),idP.hex(),1))
t=mk_tx([(idP,0)],[(80000,b'\x51')]); idC1=sha256d(t); r,_=mp.add(t,idC1,"x"); assert r==1
s["steps"].append(("add",t.hex(),idC1.hex(),1))
t=mk_tx([(idC1,0)],[(70000,b'\x51')]); idC2=sha256d(t); r,_=mp.add(t,idC2,"x"); assert r==1
s["steps"].append(("add",t.hex(),idC2.hex(),1))   # depth 3 == max_anc -> ok
t=mk_tx([(idC2,0)],[(60000,b'\x51')]); idC3=sha256d(t)
r,_=mp.add(t,idC3,"x"); assert r==0 and _=="anc",(r,_)
s["steps"].append(("add",t.hex(),idC3.hex(),0))   # depth 4 > 3 -> reject
scenarios.append(s)

# ---- S3: descendant limit (max_desc=2) ---------------------------------------
s=dict(name="descendant", relay=1, max_anc=1000, max_anc_bytes=1<<30,
       max_desc=2, max_desc_bytes=1<<30, rbf=1, utxo=[(COIN_C.hex(),0,100000)], steps=[])
mp=RefPolicy(relay=1,max_desc=2)
for (h,ix,v) in s["utxo"]: mp.utxo[(bytes.fromhex(h), ix)] = v
t=mk_tx([(COIN_C,0)],[(40000,b'\x51'),(40000,b'\x51')]); idR=sha256d(t)
r,_=mp.add(t,idR,"x"); assert r==1; s["steps"].append(("add",t.hex(),idR.hex(),1))
t=mk_tx([(idR,0)],[(30000,b'\x51')]); idDa=sha256d(t)
r,_=mp.add(t,idDa,"x"); assert r==1; s["steps"].append(("add",t.hex(),idDa.hex(),1))  # R desc=2
t=mk_tx([(idR,1)],[(30000,b'\x51')])
r,_=mp.add(t,sha256d(t),"x"); assert r==0 and _=="desc",(r,_)
s["steps"].append(("add",t.hex(),sha256d(t).hex(),0))   # R desc would be 3
scenarios.append(s)

# ---- S4: fee estimator ------------------------------------------------------
s=dict(name="estimator", relay=1, max_anc=1000, max_anc_bytes=1<<30,
       max_desc=1000, max_desc_bytes=1<<30, rbf=1, utxo=[], steps=[])
tot_utxo=[(COIN_A,100000),(COIN_B,100000),(COIN_C,100000),(COIN_D,100000)]
for (c,v) in tot_utxo: s["utxo"].append((c.hex(),0,v))
mp=RefPolicy(relay=1)
for (h,ix,v) in s["utxo"]: mp.utxo[(bytes.fromhex(h), ix)] = v
# fee rates: 10000/66 ~151/satB ; 8000/66 ~121 ; 12000/66 ~181
t=mk_tx([(COIN_A,0)],[(90000,b'\x51')]); r,_=mp.add(t,sha256d(t),"x"); assert r==1
s["steps"].append(("add",t.hex(),sha256d(t).hex(),1))
t=mk_tx([(COIN_B,0)],[(92000,b'\x51')]); r,_=mp.add(t,sha256d(t),"x"); assert r==1
s["steps"].append(("add",t.hex(),sha256d(t).hex(),1))
s["steps"].append(("est",mp.est))
scenarios.append(s)

# =============================================================================
# emit header
# =============================================================================
def cs(hexstr): return '"'+hexstr+'"'

lines=[]
lines.append("/* AUTO-GENERATED by gen_mempool_policy_vectors.py -- DO NOT EDIT */")
lines.append("#ifndef MEMPOOL_POLICY_VEC_H")
lines.append("#define MEMPOOL_POLICY_VEC_H")

for idx,sc in enumerate(scenarios):
    lines.append(f"/* ---- scenario {idx}: {sc['name']} ---- */")
    lines.append(f"static const unsigned SCEN{idx}_MAXANC={sc['max_anc']};")
    lines.append(f"static const unsigned SCEN{idx}_MAXANC_B={sc['max_anc_bytes']};")
    lines.append(f"static const unsigned SCEN{idx}_MAXDESC={sc['max_desc']};")
    lines.append(f"static const unsigned SCEN{idx}_MAXDESC_B={sc['max_desc_bytes']};")
    lines.append(f"static const unsigned SCEN{idx}_RBF={sc['rbf']};")
    # utxo preloads
    lines.append(f"static const char* SCEN{idx}_UTXO_TXID[]={{{','.join(cs(u[0]) for u in sc['utxo'])}}};")
    lines.append(f"static const unsigned SCEN{idx}_UTXO_IDX[]={{{','.join(str(u[1]) for u in sc['utxo'])}}};")
    lines.append(f"static const unsigned long long SCEN{idx}_UTXO_VAL[]={{{','.join(str(u[2]) for u in sc['utxo'])}}};")
    lines.append(f"static const unsigned SCEN{idx}_NUTXO={len(sc['utxo'])};")
    # steps
    nsteps=len(sc['steps'])
    lines.append(f"static const unsigned SCEN{idx}_NSTEPS={nsteps};")
    # arrays of tx hex / txid hex / expect; kind stored as expect sign: use a kind array
    step_tx=','.join(cs(sk[1]) if sk[0]=='add' else cs('') for sk in sc['steps'])
    step_txid=','.join((cs(sk[2]) if sk[0]=='add' else (cs(sk[1]) if sk[0]=='present' else cs(''))) for sk in sc['steps'])
    lines.append(f"static const char* SCEN{idx}_STEP_TX[]={{{step_tx}}};")
    lines.append(f"static const char* SCEN{idx}_STEP_TXID[]={{{step_txid}}};")
    # kind: 0=add, 1=present, 2=est
    kind=[{'add':0,'present':1,'est':2}[sk[0]] for sk in sc['steps']]
    lines.append(f"static const unsigned SCEN{idx}_STEP_KIND[]={{{','.join(str(k) for k in kind)}}};")
    expect=[(sk[-1] if sk[0] in ('add','present') else 0) for sk in sc['steps']]
    lines.append(f"static const unsigned SCEN{idx}_STEP_EXPECT[]={{{','.join(str(e) for e in expect)}}};")
    lines.append(f"static const unsigned long long SCEN{idx}_STEP_ARG[]={{{','.join((str(sk[1]) if sk[0]=='est' else '0') for sk in sc['steps'])}}};")
    lines.append("")

lines.append("#endif")
open('mempool_policy_vec.h','w').write("\n".join(lines)+"\n")
print(f"wrote mempool_policy_vec.h: {len(scenarios)} scenarios, "
      f"{sum(len(sc['steps']) for sc in scenarios)} steps")
