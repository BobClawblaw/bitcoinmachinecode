#!/usr/bin/env python3
"""validation/musig_core_diff.py -- MuSig2 (BIP327/BIP373/BIP390) signing
sessions judged by Bitcoin Core.

Three Core regtest descriptor wallets hold the participant keys of a
tr(musig(...)) / rawtr(musig(...)) / tr(musig(...)/<0;1>/*) output, exactly
as Core's own test/functional/wallet_musig.py sets them up -- except that
participant 2 never imports the aggregate descriptor into Core: THIS node
signs for it through descriptorprocesspsbt, given only its own key. The two
Core wallets and this node exchange PSBTs through Core's combinepsbt for the
nonce round and the partial-signature round; this node then aggregates and
extracts the transaction. Core's finalizepsbt, testmempoolaccept and a
mined block judge the result, and Core's decodepsbt is compared with ours
on every intermediate PSBT (the musig2_* fields must match exactly).

Needs the scratch Core build (never the production install). Prints one
line per check and a final RESULT line; exit 0 only if every check passed.
"""
import base64, json, os, re, shutil, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE = os.environ.get("CORE_BIN", "/storage/bitcoin-core-source/build-zmq/bin")
PORT, RPCPORT = 18570, 18571
checks = 0; fails = 0
def ck(label, cond, detail=""):
    global checks, fails
    checks += 1
    if cond: print(f"OK   {label}")
    else: fails += 1; print(f"FAIL {label}" + (f" -- {detail}" if detail else ""))

# ---- build our RPC shell from the PSBT test's link line ----
def build_shell(tmp):
    asm = os.path.join(ROOT, "asm")
    out = subprocess.run(["make", "-n", "-B", "tests/test_rpc_psbtfinal"], cwd=asm, capture_output=True, text=True).stdout
    line = [l for l in out.splitlines() if re.match(r"^(cc|gcc).*-o tests/test_rpc_psbtfinal ", l)][-1]
    line = line.replace("tests/test_rpc_psbtfinal.c", "../validation/musig_shell.c").replace("-o tests/test_rpc_psbtfinal ", f"-o {tmp}/shell ")
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
    def close(self):
        self.p.stdin.close(); self.p.wait(timeout=10)

class Core:
    def __init__(self, tmp):
        self.tmp = tmp
        self.proc = subprocess.Popen([f"{CORE}/bitcoind", "-regtest", f"-datadir={tmp}", f"-port={PORT}", f"-rpcport={RPCPORT}",
                                      "-listen=0", "-connect=0", "-dnsseed=0", "-daemon=0", "-printtoconsole=0", "-rpcuser=u", "-rpcpassword=p", "-fallbackfee=0.0001"])
        for _ in range(60):
            try: self.call(None, "getblockcount"); break
            except Exception: time.sleep(1)
    def call(self, wallet, method, *args):
        cmd = [f"{CORE}/bitcoin-cli", "-regtest", f"-datadir={self.tmp}", f"-rpcport={RPCPORT}", "-rpcuser=u", "-rpcpassword=p"]
        if wallet: cmd.append(f"-rpcwallet={wallet}")
        cmd += ["-named", method] if any("=" in str(a) for a in args) else [method]
        cmd += [a if isinstance(a, str) else json.dumps(a) for a in args]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode: raise RuntimeError(f"core {method}: {r.stderr.strip()}")
        out = r.stdout.strip()
        try: return json.loads(out)
        except Exception: return out
    def stop(self):
        try: self.call(None, "stop")
        except Exception: pass
        try: self.proc.wait(timeout=60)
        except Exception: self.proc.kill()

def descsum(core, desc): return desc + "#" + core.call(None, "getdescriptorinfo", desc)["checksum"]   # keep the private keys; "descriptor" would strip them

PRIVKEY_RE = re.compile(r"^tr\((.+?)/.+\)#.{8}$")
PUBKEY_RE = re.compile(r"^tr\((\[.+?\].+?)/.+\)#.{8}$")
ORIGIN_PATH_RE = re.compile(r"^\[\w{8}(/.*)\].*$")

def musig_fields(dec, idx=0):
    """the musig2_* fields of input idx, order-normalised"""
    i = dec["inputs"][idx]; out = {}
    for f in ("musig2_participant_pubkeys", "musig2_pubnonces", "musig2_partial_sigs"):
        if f in i: out[f] = sorted(json.dumps(x, sort_keys=True) for x in i[f])
    for f in ("taproot_key_path_sig", "taproot_internal_key", "taproot_merkle_root"):
        if f in i: out[f] = i[f]
    return out

def run_pattern(core, ours, label, pattern, sighash=None, wallet_num=[0]):
    print(f"== {label}: {pattern} ==")
    wallets, keys = [], []
    for _ in range(3):
        name = f"musig_{wallet_num[0]}"; wallet_num[0] += 1
        core.call(None, "createwallet", name); wallets.append(name)
        priv = pub = None
        for d in core.call(name, "listdescriptors", True)["descriptors"]:
            if d["desc"].startswith("tr("): priv = PRIVKEY_RE.search(d["desc"]).group(1); break
        for d in core.call(name, "listdescriptors")["descriptors"]:
            if d["desc"].startswith("tr("): pub = PUBKEY_RE.search(d["desc"]).group(1); priv += ORIGIN_PATH_RE.search(pub).group(1); break
        keys.append((priv, pub))
    # wallets 0 and 1 import the aggregate descriptor (their own key private); wallet 2 is this node
    for i in (0, 1):
        desc = pattern
        for j, (priv, pub) in enumerate(keys): desc = desc.replace(f"${j}", priv if j == i else pub)
        res = core.call(wallets[i], "importdescriptors", [{"desc": descsum(core, desc), "active": True, "timestamp": "now"}])
        ck(f"{label}: Core wallet {i} imports the musig descriptor", res[0]["success"], json.dumps(res) + " desc=" + desc + " keys=" + json.dumps(keys))
    # our node's key material: participant 2's private key at the branches the pattern derives it on
    m = re.search(r"\$2(/<(\d+);(\d+)>/\*)?", pattern)
    ours_descs = []
    if m.group(1): ours_descs = [{"desc": f"pk({keys[2][0]}/{b}/*)", "range": [0, 20]} for b in (m.group(2), m.group(3))]
    else: ours_descs = [f"pk({keys[2][0]})"]
    addr = core.call(wallets[0], "getnewaddress", "", "bech32m")
    ck(f"{label}: both Core wallets derive the same aggregate address", addr == core.call(wallets[1], "getnewaddress", "", "bech32m"))
    core.call("def", "sendtoaddress", addr, 10); core.call(None, "generatetoaddress", 1, core.call("def", "getnewaddress"))
    utxo = core.call(wallets[0], "listunspent")[0]
    dest = core.call("def", "getnewaddress")
    # PSBT v0: this node's PSBT code speaks BIP174 v0 (master Core defaults to v2)
    psbt = core.call(wallets[0], "walletcreatefundedpsbt", f"inputs={json.dumps([utxo])}", f"outputs={json.dumps([{dest: 5}])}",
                     'options={"changePosition":1,"change_type":"bech32m"}', "psbt_version=0")["psbt"]
    sh = [sighash] if sighash else []
    def ours_process(p):
        return ours.call("descriptorprocesspsbt", [p, ours_descs] + sh)
    def core_process(w, p):
        return core.call(w, "walletprocesspsbt", p, *([True, sighash] if sighash else []))
    def same_decode(p, what):
        cd, od = core.call(None, "decodepsbt", p), ours.call("decodepsbt", [p])
        cf, of = musig_fields(cd), musig_fields(od)
        ck(f"{label}: decodepsbt musig2 fields match Core's ({what})", cf == of, f"core={json.dumps(cf)[:300]} ours={json.dumps(of)[:300]}")
        return cd
    d0 = same_decode(psbt, "funded PSBT")
    ck(f"{label}: Core's PSBT carries one aggregate with 3 participants", len(d0["inputs"][0].get("musig2_participant_pubkeys", [])) == 1 and len(d0["inputs"][0]["musig2_participant_pubkeys"][0]["participant_pubkeys"]) == 3)
    # ---- round 1: nonces ----
    r1 = [core_process(wallets[0], psbt), core_process(wallets[1], psbt), ours_process(psbt)]
    ck(f"{label}: round 1 -- nobody is complete", not any(r["complete"] for r in r1))
    d2 = same_decode(r1[2]["psbt"], "our nonce PSBT")
    ck(f"{label}: round 1 -- our PSBT holds exactly our pubnonce", len(d2["inputs"][0].get("musig2_pubnonces", [])) == 1)
    comb1 = core.call(None, "combinepsbt", [r["psbt"] for r in r1])
    d3 = same_decode(comb1, "combined nonces")
    ck(f"{label}: round 1 -- 3 pubnonces after combine, no partial sigs", len(d3["inputs"][0].get("musig2_pubnonces", [])) == 3 and "musig2_partial_sigs" not in d3["inputs"][0])
    # ---- round 2: partial signatures ----
    r2 = [core_process(wallets[0], comb1), core_process(wallets[1], comb1), ours_process(comb1)]
    ck(f"{label}: round 2 -- nobody is complete", not any(r["complete"] for r in r2))
    d4 = same_decode(r2[2]["psbt"], "our partial-sig PSBT")
    ck(f"{label}: round 2 -- our PSBT holds our partial signature", len(d4["inputs"][0].get("musig2_partial_sigs", [])) == 1)
    comb2 = core.call(None, "combinepsbt", [r["psbt"] for r in r2])
    d5 = same_decode(comb2, "combined partial sigs")
    ck(f"{label}: round 2 -- 3 partial sigs after combine", len(d5["inputs"][0].get("musig2_partial_sigs", [])) == 3)
    # ---- round 3: aggregation, ours ----
    r3 = ours_process(comb2)
    ck(f"{label}: round 3 -- our node aggregates and reports complete", r3["complete"] and "hex" in r3, json.dumps(r3)[:200])
    if r3.get("complete"):
        fin = core.call(None, "finalizepsbt", r3["psbt"])
        ck(f"{label}: Core finalizes our PSBT (complete)", fin["complete"])
        ck(f"{label}: Core's extracted tx equals ours", fin.get("hex") == r3["hex"])
        tma = core.call(None, "testmempoolaccept", [r3["hex"]])
        ck(f"{label}: Core's testmempoolaccept allows our transaction", tma[0]["allowed"], json.dumps(tma))
        # Core's own aggregation from the same partial sigs must give the same witness
        c3 = core_process(wallets[0], comb2)
        cfin = core.call(None, "finalizepsbt", c3["psbt"])
        ck(f"{label}: Core wallet 0 aggregates to the identical transaction", cfin["complete"] and cfin["hex"] == r3["hex"])
        txid = core.call(None, "sendrawtransaction", r3["hex"])
        bh = core.call(None, "generatetoaddress", 1, dest)[0]
        ck(f"{label}: mined", core.call(None, "getrawtransaction", txid, True, bh).get("confirmations", 0) == 1)
    # a second partial-signature attempt must NOT reuse the erased nonce
    again = ours_process(comb1)
    da = ours.call("decodepsbt", [again["psbt"]])
    ck(f"{label}: replaying the nonce round yields no second partial signature (secnonce erased)",
       len(da["inputs"][0].get("musig2_partial_sigs", [])) == 0)

def main():
    tmp = tempfile.mkdtemp(prefix="musig_core_diff.", dir=os.environ.get("CLAUDE_JOB_DIR", "/tmp"))
    shell = build_shell(tmp)
    core = Core(os.path.join(tmp, "core") if os.path.isdir(os.path.join(tmp, "core")) or os.makedirs(os.path.join(tmp, "core")) is None else tmp)
    ours = Ours(shell)
    try:
        core.call(None, "createwallet", "def")
        core.call(None, "generatetoaddress", 101, core.call("def", "getnewaddress"))
        run_pattern(core, ours, "tr(musig(keys/*))", "tr(musig($0/<0;1>/*,$1/<1;2>/*,$2/<2;3>/*))")
        run_pattern(core, ours, "rawtr(musig(keys/*))", "rawtr(musig($0/<0;1>/*,$1/<1;2>/*,$2/<2;3>/*))")
        run_pattern(core, ours, "tr(musig/*) derived aggregate", "tr(musig($0,$1,$2)/<0;1>/*)")
        run_pattern(core, ours, "rawtr(musig/*) derived aggregate", "rawtr(musig($0,$1,$2)/<0;1>/*)")
        run_pattern(core, ours, "tr(musig(keys/*)) ALL|ANYONECANPAY", "tr(musig($0/<0;1>/*,$1/<1;2>/*,$2/<2;3>/*))", sighash="ALL|ANYONECANPAY")
    finally:
        ours.close(); core.stop(); shutil.rmtree(tmp, ignore_errors=True)
    print(f"RESULT: {checks - fails} ok, {fails} fail")
    sys.exit(1 if fails else 0)
if __name__ == "__main__": main()
