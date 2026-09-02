#!/usr/bin/env python3
"""validation/miniscript_core_diff.py -- Miniscript descriptors judged by
Bitcoin Core.

Part 1 (every descriptor of the corpus, private and public forms):
  getdescriptorinfo and deriveaddresses from THIS node (rpc_dispatch through
  the in-process shell) are compared byte-for-byte with a scratch regtest
  Core's answers.
Part 2 (the spend corpus): Core's wallet funds each descriptor's address, a
  PSBT is built with Core's createpsbt + utxoupdatepsbt (so the PSBT carries
  Core's own witness_utxo / witness_script / tap_leaf_script fields), hash
  preimages are added as PSBT_IN_*_PREIMAGES fields, THIS node signs it with
  descriptorprocesspsbt given only the keys the case grants, and Core's
  testmempoolaccept + sendrawtransaction + a mined block judge the witness.
  Timelocked paths use nSequence/nLockTime and mined blocks; negative cases
  must come back incomplete.

Needs the scratch Core build (never the production install). Prints one
line per check and a final RESULT line; exit 0 only if every check passed.
"""
import base64, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE = os.environ.get("CORE_BIN", "/storage/bitcoin-core-source/build-zmq/bin")
PORT, RPCPORT = 18580, 18581
checks = 0; fails = 0
def ck(label, cond, detail=""):
    global checks, fails
    checks += 1
    if cond: print(f"OK   {label}")
    else: fails += 1; print(f"FAIL {label}" + (f" -- {detail}" if detail else ""))

# ---- our RPC shell (validation/musig_shell.c over rpc_dispatch) ----
def build_shell(tmp):
    asm = os.path.join(ROOT, "asm")
    out = subprocess.run(["make", "-n", "-B", "tests/test_rpc_psbtfinal"], cwd=asm, capture_output=True, text=True).stdout
    line = [l for l in out.splitlines() if re.match(r"^(cc|gcc).*-o tests/test_rpc_psbtfinal ", l)][-1]
    line = line.replace("tests/test_rpc_psbtfinal.c", "../validation/rpc_shell_regtest.c").replace("-o tests/test_rpc_psbtfinal ", f"-o {tmp}/shell ")
    r = subprocess.run(line, shell=True, cwd=asm, capture_output=True, text=True)
    if r.returncode: print(r.stderr); sys.exit(1)
    return os.path.join(tmp, "shell")
class Ours:
    def __init__(self, path):
        self.p = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    def call(self, method, params):
        self.p.stdin.write(method + "\t" + json.dumps(params) + "\n"); self.p.stdin.flush()
        line = self.p.stdout.readline().rstrip("\n")
        if line.startswith("OK\t"): return json.loads(line[3:])
        raise RuntimeError(f"ours {method}: {line}")
    def try_call(self, method, params):
        try: return self.call(method, params), None
        except RuntimeError as e: return None, str(e)
    def close(self):
        self.p.stdin.close(); self.p.wait(timeout=10)
class Core:
    def __init__(self, tmp):
        self.tmp = tmp
        self.proc = subprocess.Popen([f"{CORE}/bitcoind", "-regtest", f"-datadir={tmp}", f"-port={PORT}", f"-rpcport={RPCPORT}",
                                      "-listen=0", "-connect=0", "-dnsseed=0", "-daemon=0", "-printtoconsole=0", "-rpcuser=u", "-rpcpassword=p", "-fallbackfee=0.0001", "-txindex=1"])
        for _ in range(60):
            try: self.call(None, "getblockcount"); break
            except Exception: time.sleep(1)
    def call(self, wallet, method, *args, named=False):
        cmd = [f"{CORE}/bitcoin-cli", "-regtest", f"-datadir={self.tmp}", f"-rpcport={RPCPORT}", "-rpcuser=u", "-rpcpassword=p"]
        if wallet: cmd.append(f"-rpcwallet={wallet}")
        if named: cmd.append("-named")
        cmd.append(method)
        for a in args: cmd.append(a if isinstance(a, str) else json.dumps(a))
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode: raise RuntimeError(f"core {method}: {r.stderr.strip()}")
        out = r.stdout.strip()
        try: return json.loads(out)
        except Exception: return out
    def try_call(self, wallet, method, *args):
        try: return self.call(wallet, method, *args), None
        except RuntimeError as e: return None, str(e)
    def stop(self):
        try: self.call(None, "stop")
        except Exception: pass
        try: self.proc.wait(timeout=60)
        except Exception: self.proc.kill()

# ---- keys and hashes ----
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58check(payload):
    d = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(d, "big"); s = ""
    while n: n, r = divmod(n, 58); s = B58[r] + s
    for b in d:
        if b == 0: s = "1" + s
        else: break
    return s
def wif(priv):  return b58check(b"\xef" + priv + b"\x01")        # regtest, compressed
PRIV = [bytes([i]) * 32 for i in (0x11, 0x22, 0x33, 0x44)]
W = [wif(p) for p in PRIV]                                         # A B C D
NUMS = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
PRE = bytes([0x42]) * 32
H_SHA = hashlib.sha256(PRE).hexdigest()
H_H256 = hashlib.sha256(hashlib.sha256(PRE).digest()).hexdigest()
def ripemd160(b): return hashlib.new("ripemd160", b).digest()
H_H160 = ripemd160(hashlib.sha256(PRE).digest()).hex()
H_RMD = ripemd160(PRE).hex()
TPRV = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK"   # a well-known testnet xprv (Core docs)
AFTER_H = 160

# ---- the corpus: (name, private descriptor, plan) ----
# plan: keys granted to the signer ("A".."D" subset), seq, locktime, preimages (list of hashes), expect_complete
def D(name, prv, keys="ABCD", seq=None, locktime=0, pre=(), complete=True, spend=True):
    return dict(name=name, prv=prv, keys=keys, seq=seq, locktime=locktime, pre=list(pre), complete=complete, spend=spend)
A, B, C, Dk = W
CORPUS = [
    D("wsh pk", f"wsh(pk({A}))", "A"),
    D("wsh pkh", f"wsh(pkh({A}))", "A"),
    D("and_v", f"wsh(and_v(v:pk({A}),pk({B})))", "AB"),
    D("and_b", f"wsh(and_b(pk({A}),s:pk({B})))", "AB"),
    D("or_b A", f"wsh(or_b(pk({A}),s:pk({B})))", "A"),
    D("or_d B (dissatisfy A)", f"wsh(or_d(pk({A}),pkh({B})))", "B"),
    D("INVALID top-level V (or_c)", f"wsh(or_c(pk({A}),v:pk({B})))", "B", spend=False),   # both must refuse: V at top level
    D("or_i A", f"wsh(or_i(pk({A}),pk({B})))", "A"),
    D("or_i B", f"wsh(or_i(pk({A}),pk({B})))", "B"),
    D("andor A+B", f"wsh(andor(pk({A}),pk({B}),pk({C})))", "AB"),
    D("andor C", f"wsh(andor(pk({A}),pk({B}),pk({C})))", "C"),
    D("older(3)", f"wsh(and_v(v:pk({A}),older(3)))", "A", seq=3),
    D("after(H)", f"wsh(and_v(v:pk({A}),after({AFTER_H})))", "A", seq=0xfffffffe, locktime=AFTER_H),
    D("or_d timelocked B", f"wsh(or_d(pk({A}),and_v(v:pk({B}),older(2))))", "B", seq=2),
    D("thresh 2/3 A,C", f"wsh(thresh(2,pk({A}),s:pk({B}),s:pk({C})))", "AC"),
    D("thresh 1/2 B", f"wsh(thresh(1,pk({A}),s:pk({B})))", "B"),
    D("multi in and_v", f"wsh(and_v(v:multi(2,{A},{B},{C}),older(1)))", "AC", seq=1),
    D("sha256 preimage", f"wsh(and_v(v:sha256({H_SHA}),pk({A})))", "A", pre=[H_SHA]),
    D("hash256 preimage", f"wsh(and_v(v:hash256({H_H256}),pk({A})))", "A", pre=[H_H256]),
    D("hash160 preimage", f"wsh(and_v(v:hash160({H_H160}),pk({A})))", "A", pre=[H_H160]),
    D("ripemd160 preimage", f"wsh(and_v(v:ripemd160({H_RMD}),pk({A})))", "A", pre=[H_RMD]),
    D("andor older", f"wsh(andor(pk({A}),older(2),pk({B})))", "A", seq=2),
    D("and_n after", f"wsh(and_n(pk({A}),after({AFTER_H})))", "A", seq=0xfffffffe, locktime=AFTER_H),
    D("t:or_c", f"wsh(t:or_c(pk({A}),v:pk({B})))", "A"),
    D("c:andor K", f"wsh(c:andor(pk({A}),pk_k({B}),pk_k({C})))", "AB"),
    D("or_i timelocked A", f"wsh(or_i(and_v(v:pk({A}),older(2)),pk({B})))", "A", seq=2),
    D("thresh mixed A+C", f"wsh(thresh(2,pk({A}),s:pk({B}),a:and_v(v:pk({C}),older(2))))", "AC", seq=2),
    D("or_d after fallback", f"wsh(and_v(v:pk({A}),or_d(pk({B}),after({AFTER_H}))))", "A", seq=0xfffffffe, locktime=AFTER_H),
    D("sh(wsh) and_v", f"sh(wsh(and_v(v:pk({A}),pk({B}))))", "AB"),
    D("sh(wsh) or_d B", f"sh(wsh(or_d(pk({A}),pkh({B}))))", "B"),
    D("ranged tprv", f"wsh(and_v(v:pk({TPRV}/0/*),pk({B})))", "TB"),
    D("j:and_v", f"wsh(j:and_v(v:pkh({A}),pk({B})))", "AB"),
    D("thresh with a timelock sub", f"wsh(thresh(2,pk({A}),s:pk({B}),sndv:older(2)))", "AB", seq=2),
    D("INVALID d: is not u under P2WSH", f"wsh(thresh(2,pk({A}),s:pk({B}),sdv:older(2)))", "AB", spend=False),
    D("l:pk", f"wsh(and_v(v:pk({A}),l:pk({B})))", "AB", complete=True),
    D("hash + timelock + key", f"wsh(and_v(and_v(v:sha256({H_SHA}),v:pk({A})),older(2)))", "A", seq=2, pre=[H_SHA]),
    D("uc:and_v", f"wsh(and_n(sha256({H_SHA}),uc:and_v(v:older(2),pk_k({A}))))", "A", seq=2, pre=[H_SHA]),
    # negatives: not enough to satisfy
    D("NEG or_d nothing", f"wsh(or_d(pk({A}),and_v(v:pk({B}),older(2))))", "B", seq=None, complete=False),
    D("NEG thresh 1 of 2", f"wsh(thresh(2,pk({A}),s:pk({B}),s:pk({C})))", "A", complete=False),
    D("NEG preimage missing", f"wsh(and_v(v:sha256({H_SHA}),pk({A})))", "A", pre=[], complete=False),
    D("NEG after unmet", f"wsh(and_v(v:pk({A}),after({AFTER_H})))", "A", seq=0xfffffffe, locktime=0, complete=False),
    # taproot leaves
    D("tr leaf and_v", f"tr({NUMS},and_v(v:pk({A}),pk({B})))", "AB"),
    D("tr leaf or_d B", f"tr({NUMS},or_d(pk({A}),pkh({B})))", "B"),
    D("tr leaf older", f"tr({NUMS},and_v(v:pk({A}),older(2)))", "A", seq=2),
    D("tr leaf sha256", f"tr({NUMS},and_v(v:sha256({H_SHA}),pk({A})))", "A", pre=[H_SHA]),
    D("tr leaf thresh", f"tr({NUMS},thresh(2,pk({A}),s:pk({B}),s:pk({C})))", "BC"),
    D("tr tree two leaves", f"tr({NUMS},{{and_v(v:pk({A}),older(2)),pk({B})}})", "B"),
    D("tr tree ms leaf spend", f"tr({NUMS},{{and_v(v:pk({A}),older(2)),multi_a(2,{B},{C})}})", "A", seq=2),
    D("tr NEG leaf older unmet", f"tr({NUMS},and_v(v:pk({A}),older(2)))", "A", seq=None, complete=False),
    # musig() (BIP390): descriptor parity only here; the signing session is part 3
    D("musig rawtr", f"rawtr(musig({A},{B},{C}))", spend=False),
    D("musig tr", f"tr(musig({A},{B},{C}))", spend=False),
    D("musig tr + leaf", f"tr(musig({A},{B}),pk({C}))", spend=False),
    D("musig in a leaf", f"tr({NUMS},pk(musig({A},{B})))", spend=False),
    D("musig ranged participants", f"rawtr(musig({TPRV}/0/*,{TPRV}/1/*))", spend=False),
    D("musig derived aggregate", f"tr(musig({TPRV}/0,{TPRV}/1)/2/*)", spend=False),
    D("musig fixed derivation", f"rawtr(musig({TPRV},{TPRV}/1)/5)", spend=False),
    D("musig in multi_a leaf", f"tr({NUMS},multi_a(1,musig({A},{B}),{C}))", spend=False),
    D("INVALID musig outside tr", f"wsh(pk(musig({A},{B})))", spend=False),
    D("INVALID musig ranged + derivation", f"tr(musig({TPRV}/0/*,{TPRV})/1)", spend=False),
]

# ---- helpers ----
def restrict(prv, keys):
    """the descriptor with only the granted keys private: others become their public form (via Core's key parse)"""
    d = prv
    for tag, w, p in zip("ABCD", W, PRIV):
        if tag not in keys:
            pub = pubkey_hex(p)
            d = d.replace(w, pub)
    if "T" not in keys and TPRV in d:
        d = d.replace(TPRV, TPUB)
    return d
_pubcache = {}
def pubkey_hex(priv):
    # compressed pubkey via Core: getdescriptorinfo(pk(WIF)) gives pk(<hex>)
    if priv not in _pubcache:
        info = core.call(None, "getdescriptorinfo", f"pk({wif(priv)})")
        _pubcache[priv] = re.match(r"pk\(([0-9a-f]+)\)", info["descriptor"]).group(1)
    return _pubcache[priv]
def cs(desc): return core.call(None, "getdescriptorinfo", desc)["checksum"]
def pubform(desc): return core.call(None, "getdescriptorinfo", desc)["descriptor"]

def read_cs(b, p):
    v = b[p]
    if v < 253: return v, p + 1
    if v == 253: return int.from_bytes(b[p+1:p+3], "little"), p + 3
    if v == 254: return int.from_bytes(b[p+1:p+5], "little"), p + 5
    return int.from_bytes(b[p+1:p+9], "little"), p + 9
def write_cs(n):
    if n < 253: return bytes([n])
    if n <= 0xffff: return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")
def psbt_maps(b):
    assert b[:5] == b"psbt\xff"; p = 5; maps = []
    while p < len(b):
        m = []
        while True:
            kl, p = read_cs(b, p)
            if kl == 0: break
            k = b[p:p+kl]; p += kl
            vl, p = read_cs(b, p); v = b[p:p+vl]; p += vl
            m.append((k, v))
        maps.append(m)
    return maps
def psbt_ser(maps):
    out = b"psbt\xff"
    for m in maps:
        for k, v in m: out += write_cs(len(k)) + k + write_cs(len(v)) + v
        out += b"\x00"
    return out
def add_preimages(psbt_b64, hashes):
    b = base64.b64decode(psbt_b64); maps = psbt_maps(b)
    inp = maps[1]
    for h in hashes:
        hb = bytes.fromhex(h)
        t = {H_RMD: 0x0a, H_SHA: 0x0b, H_H160: 0x0c, H_H256: 0x0d}[h]
        inp.append((bytes([t]) + hb, PRE))
    return base64.b64encode(psbt_ser(maps)).decode()

PRIVKEY_RE = re.compile(r"^tr\((.+?)/.+\)#.{8}$")
PUBKEY_RE = re.compile(r"^tr\((\[.+?\].+?)/.+\)#.{8}$")
ORIGIN_PATH_RE = re.compile(r"^\[\w{8}(/.*)\].*$")
def strip_musig_fields(psbt_b64):
    b = base64.b64decode(psbt_b64); maps = psbt_maps(b)
    maps[1] = [(k, v) for (k, v) in maps[1] if k[0] not in (0x1a, 0x16, 0x17, 0x18)]
    return base64.b64encode(psbt_ser(maps)).decode()
def musig_fields(dec, idx=0):
    i = dec["inputs"][idx]; out = {}
    for f in ("musig2_participant_pubkeys", "musig2_pubnonces", "musig2_partial_sigs"):
        if f in i: out[f] = sorted(json.dumps(x, sort_keys=True) for x in i[f])
    for f in ("taproot_internal_key", "taproot_merkle_root"):
        if f in i: out[f] = i[f]
    return out
_wnum = [0]
def musig_session(core, ours, mine_addr, pattern):
    label = f"musig {pattern}"
    wallets, keys = [], []
    for _ in range(3):
        name = f"ms_musig_{_wnum[0]}"; _wnum[0] += 1
        core.call(None, "createwallet", name); wallets.append(name)
        priv = pub = None
        for d in core.call(name, "listdescriptors", True)["descriptors"]:
            if d["desc"].startswith("tr("): priv = PRIVKEY_RE.search(d["desc"]).group(1); break
        for d in core.call(name, "listdescriptors")["descriptors"]:
            if d["desc"].startswith("tr("): pub = PUBKEY_RE.search(d["desc"]).group(1); priv += ORIGIN_PATH_RE.search(pub).group(1); break
        keys.append((priv, pub))
    for i in (0, 1):
        desc = pattern
        for j, (priv, pub) in enumerate(keys): desc = desc.replace(f"${j}", priv if j == i else pub)
        res = core.call(wallets[i], "importdescriptors", [{"desc": desc + "#" + cs(desc), "active": True, "timestamp": "now"}])
        ck(f"{label}: Core wallet {i} imports the descriptor", res[0]["success"], json.dumps(res)[:200])
    ours_desc = pattern; norm_desc = pattern
    for j, (priv, pub) in enumerate(keys): ours_desc = ours_desc.replace(f"${j}", priv if j == 2 else pub); norm_desc = norm_desc.replace(f"${j}", pub)
    # descriptor parity: the descriptor our node signs with, and the all-public (origin) form the address comes from
    for what, dd in (("our participant descriptor", ours_desc), ("the public descriptor", norm_desc)):
        ci, ce = core.try_call(None, "getdescriptorinfo", dd); oi, oe = ours.try_call("getdescriptorinfo", [dd])
        ck(f"{label}: getdescriptorinfo of {what} matches Core", ci is not None and oi is not None and all(ci.get(k) == oi.get(k) for k in ("descriptor", "checksum", "isrange", "issolvable", "hasprivatekeys")), f"core={json.dumps(ci)[:200] if ci else ce} ours={json.dumps(oi)[:200] if oi else oe}")
    addr = core.call(wallets[0], "getnewaddress", "", "bech32m")
    ck(f"{label}: both Core wallets derive the same aggregate address", addr == core.call(wallets[1], "getnewaddress", "", "bech32m"))
    ci = core.call(None, "getdescriptorinfo", norm_desc)
    ca = core.call(None, "deriveaddresses", ci["descriptor"], [0, 0]); oa = ours.call("deriveaddresses", [ci["descriptor"], [0, 0]])
    ck(f"{label}: deriveaddresses of the public descriptor: Core == ours == the wallets' address", ca == oa and oa[0] == addr, f"core={ca} ours={oa} wallet={addr}")
    core.call("w", "sendtoaddress", addr, 2); core.call("w", "generatetoaddress", 1, mine_addr)
    utxo = core.call(wallets[0], "listunspent")[0]
    dest = core.call("w", "getnewaddress")
    psbt = core.call(wallets[0], "walletcreatefundedpsbt", f"inputs={json.dumps([{'txid': utxo['txid'], 'vout': utxo['vout']}])}", f"outputs={json.dumps([{dest: 1}])}",
                     'options={"changePosition":1,"change_type":"bech32m"}', "psbt_version=0", named=True)["psbt"]
    core_dec = core.call(None, "decodepsbt", psbt)
    stripped = strip_musig_fields(psbt)
    ck(f"{label}: the stripped PSBT has no musig fields", "musig2_participant_pubkeys" not in core.call(None, "decodepsbt", stripped)["inputs"][0])
    ours_descs = [{"desc": ours_desc, "range": [0, 5]}]
    def ours_process(p): return ours.call("descriptorprocesspsbt", [p, ours_descs])
    def core_process(w, p): return core.call(w, "walletprocesspsbt", p)
    r1o = ours_process(stripped)
    d1 = core.call(None, "decodepsbt", r1o["psbt"])
    want = musig_fields(core_dec); want.pop("musig2_pubnonces", None)
    got = musig_fields(d1); got_nonces = got.pop("musig2_pubnonces", None)
    ck(f"{label}: our Updater recreated Core's musig2 participants + taproot internal key exactly", want == got, f"core={json.dumps(want)[:300]} ours={json.dumps(got)[:300]}")
    ck(f"{label}: Core's decodepsbt of our PSBT shows our one pubnonce", got_nonces is not None and len(got_nonces) == 1)
    if "taproot_bip32_derivs" in core_dec["inputs"][0]:
        ours_bd = d1["inputs"][0].get("taproot_bip32_derivs", []); core_bd = core_dec["inputs"][0]["taproot_bip32_derivs"]
        agg_fp = [x for x in core_bd if x.get("master_fingerprint") and x not in ours_bd]
        ck(f"{label}: our taproot_bip32_derivs carry the aggregate's derivation (Core's entry present)", any(x in ours_bd for x in core_bd), f"core={json.dumps(core_bd)[:300]} ours={json.dumps(ours_bd)[:300]}")
    r1 = [core_process(wallets[0], psbt), core_process(wallets[1], psbt), r1o]
    comb1 = core.call(None, "combinepsbt", [r["psbt"] for r in r1])
    dc1 = core.call(None, "decodepsbt", comb1)
    ck(f"{label}: round 1 -- 3 pubnonces after Core's combine", len(dc1["inputs"][0].get("musig2_pubnonces", [])) == 3)
    r2 = [core_process(wallets[0], comb1), core_process(wallets[1], comb1), ours_process(comb1)]
    comb2 = core.call(None, "combinepsbt", [r["psbt"] for r in r2])
    dc2 = core.call(None, "decodepsbt", comb2)
    ck(f"{label}: round 2 -- 3 partial signatures after Core's combine", len(dc2["inputs"][0].get("musig2_partial_sigs", [])) == 3)
    r3 = ours_process(comb2)
    ck(f"{label}: round 3 -- our node aggregates: complete", r3.get("complete") and "hex" in r3, json.dumps(r3)[:200])
    if r3.get("complete"):
        fin = core.call(None, "finalizepsbt", r3["psbt"])
        ck(f"{label}: Core finalizes our PSBT to the same transaction", fin.get("complete") and fin.get("hex") == r3["hex"])
        tma = core.call(None, "testmempoolaccept", [r3["hex"]], 0)[0]
        ck(f"{label}: Core testmempoolaccept", tma.get("allowed") is True, json.dumps(tma))
        if tma.get("allowed"):
            txid = core.call(None, "sendrawtransaction", r3["hex"], 0); core.call("w", "generatetoaddress", 1, mine_addr)
            ck(f"{label}: mined", core.call(None, "getrawtransaction", txid, True).get("confirmations", 0) >= 1)

def main():
    global core, TPUB
    tmp = tempfile.mkdtemp(prefix="msdiff.", dir=os.environ.get("CLAUDE_JOB_DIR", "/tmp"))
    shell = build_shell(tmp); ours = Ours(shell); core = Core(tmp)
    try:
        core.call(None, "createwallet", "w")
        mine_addr = core.call("w", "getnewaddress")
        core.call("w", "generatetoaddress", 130, mine_addr)      # 30 mature coinbases fund the corpus
        TPUB = pubform(f"pk({TPRV})")[3:-1]

        print("== part 1: getdescriptorinfo / deriveaddresses, private and public forms ==")
        for c in CORPUS:
            cprv, cerr = core.try_call(None, "getdescriptorinfo", c["prv"])
            if cprv is None:
                oi, oe = ours.try_call("getdescriptorinfo", [c["prv"]])
                ck(f"getdescriptorinfo {c['name']}: both refuse", oi is None, f"core={cerr} ours={json.dumps(oi)[:200] if oi else oe}")
                c["spend"] = False
                continue
            for form in ("prv", "pub"):
                desc = c["prv"] if form == "prv" else cprv["descriptor"]
                ci, ce = core.try_call(None, "getdescriptorinfo", desc)
                oi, oe = ours.try_call("getdescriptorinfo", [desc])
                lab = f"getdescriptorinfo {c['name']} ({form})"
                if ci is None or oi is None: ck(lab, ci is None and oi is None, f"core={ce} ours={oe}"); continue
                same = all(ci.get(k) == oi.get(k) for k in ("descriptor", "checksum", "isrange", "issolvable", "hasprivatekeys"))
                ck(lab, same, f"core={json.dumps(ci)} ours={json.dumps(oi)}")
                full = ci["descriptor"] if form == "pub" else desc + "#" + ci["checksum"]   # the public form already carries its checksum
                rng = [0, 1] if ci["isrange"] else None
                ca = core.call(None, "deriveaddresses", full, *([rng] if rng else []))
                oa, oe = ours.try_call("deriveaddresses", [full] + ([rng] if rng else []))
                ck(f"deriveaddresses {c['name']} ({form})", ca == oa, f"core={ca} ours={oa} {oe or ''}")

        print("== part 2: fund, sign with descriptorprocesspsbt, Core judges ==")
        spends = [c for c in CORPUS if c["spend"]]
        for n, c in enumerate(spends):
            info = core.call(None, "getdescriptorinfo", c["prv"])
            full_pub = info["descriptor"]
            rng = [0, 1] if info["isrange"] else None
            addr = core.call(None, "deriveaddresses", full_pub, *([rng] if rng else []))[0]
            c["addr"] = addr; c["pub"] = full_pub
            c["txid"] = core.call("w", "sendtoaddress", addr, 1.0)
            if n % 8 == 7: core.call("w", "generatetoaddress", 1, mine_addr)   # settle the change chain
        core.call("w", "generatetoaddress", 1, mine_addr)
        # timelocks: older() up to 3 blocks, after(AFTER_H): get past AFTER_H
        h = core.call(None, "getblockcount")
        core.call("w", "generatetoaddress", max(3, AFTER_H + 1 - h), mine_addr)
        dest = core.call("w", "getnewaddress")
        for c in spends:
            lab = f"spend {c['name']}"
            tx = core.call(None, "getrawtransaction", c["txid"], True)
            vout = next(o["n"] for o in tx["vout"] if o["scriptPubKey"].get("address") == c["addr"])
            inp = {"txid": c["txid"], "vout": vout}
            if c["seq"] is not None: inp["sequence"] = c["seq"]
            psbt = core.call(None, "createpsbt", [inp], {dest: 0.999}, c["locktime"], False, 2, 0)   # PSBT v0: Core v31 defaults to v2, which this node's signer does not process yet
            psbt = core.call(None, "utxoupdatepsbt", psbt, [c["pub"]])
            if c["pre"]: psbt = add_preimages(psbt, c["pre"])
            signing = restrict(c["prv"], c["keys"])
            res, err = ours.try_call("descriptorprocesspsbt", [psbt, [signing]])
            if not c["complete"]:
                ck(lab + " (negative: incomplete)", res is not None and not res.get("complete"), f"ours={json.dumps(res)[:200] if res else err}")
                if res and res.get("psbt"):
                    fin = core.call(None, "finalizepsbt", res["psbt"])
                    ck(lab + " (negative: Core cannot finalize it either)", not fin.get("complete"), json.dumps(fin)[:200])
                continue
            ck(lab + ": complete", res is not None and res.get("complete") and res.get("hex"), f"ours={json.dumps(res)[:300] if res else err}")
            if not (res and res.get("complete") and res.get("hex")): continue
            tma = core.call(None, "testmempoolaccept", [res["hex"]], 0)[0]
            ck(lab + ": Core testmempoolaccept", tma.get("allowed") is True, json.dumps(tma))
            if tma.get("allowed"):
                sent, e = core.try_call(None, "sendrawtransaction", res["hex"], 0)
                core.call("w", "generatetoaddress", 1, mine_addr)
                conf = core.call(None, "getrawtransaction", sent, True).get("confirmations", 0) if sent else 0
                ck(lab + ": mined", conf >= 1, f"{e or ''}")
            # Core's own decode of our finalized PSBT agrees it is final
            dec = core.call(None, "decodepsbt", res["psbt"])
            ck(lab + ": Core decodepsbt sees final_scriptwitness", "final_scriptwitness" in dec["inputs"][0], json.dumps(dec["inputs"][0])[:200])
        print("== part 3: MuSig2 session -- Core wallets 0 and 1, this node as participant 2 with a tr(musig()) descriptor; the funded PSBT's musig fields are STRIPPED so this node's Updater must recreate them ==")
        musig_session(core, ours, mine_addr, "tr(musig($0,$1,$2)/0/*)")
        musig_session(core, ours, mine_addr, "rawtr(musig($0,$1,$2)/0/*)")
        musig_session(core, ours, mine_addr, "tr(musig($0/0/*,$1/1/*,$2/2/*))")
    finally:
        try: ours.close()
        except Exception: pass
        core.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"RESULT: {checks - fails} ok, {fails} fail")
    sys.exit(1 if fails else 0)
if __name__ == "__main__": main()
