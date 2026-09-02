#!/usr/bin/env python3
"""validation/psbt_v2_core_diff.py -- PSBT version 2 (BIP370) judged by Bitcoin Core.

A scratch regtest Core v31.99 holds keys we also hold. For P2WPKH, P2TR, P2PKH,
P2SH-P2WPKH and P2WSH(pk):
  * Core's walletcreatefundedpsbt (v2 by default on master) -> OUR decodepsbt
    vs Core's decodepsbt; OUR descriptorprocesspsbt signs; Core finalizes to
    the same hex, testmempoolaccept, mined;
  * OUR createpsbt (version 2) -> Core utxoupdatepsbt + walletprocesspsbt +
    finalizepsbt, mined; and our createpsbt/converttopsbt bytes are identical
    to Core's for the same arguments;
  * an injected required height locktime decodes identically on both sides and
    still finalizes; combinepsbt bytes agree; the version-mismatch and joinpsbts
    errors carry Core's text.
Needs the scratch Core build (never the production install)."""
import base64, json, os, re, subprocess, sys, tempfile, time, hashlib
CORE = os.environ.get("CORE_BIN", "/storage/bitcoin-core-source/build-zmq/bin")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT, RPCPORT = int(os.environ.get("PORT_BASE", "18590")), int(os.environ.get("PORT_BASE", "18590")) + 1
FAILS = []; OK = 0
def ck(label, cond, detail=""):
    global OK
    if cond: OK += 1; print(f"OK   {label}")
    else: FAILS.append(label); print(f"FAIL {label}  {detail[:1500]}")
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
        raise RuntimeError(line)
    def try_call(self, method, params):
        try: return self.call(method, params), None
        except RuntimeError as e: return None, str(e)
    def close(self):
        try: self.p.stdin.close(); self.p.wait(timeout=5)
        except Exception: self.p.kill()
class Core:
    def __init__(self, tmp):
        self.tmp = tmp
        self.proc = subprocess.Popen([f"{CORE}/bitcoind", "-regtest", f"-datadir={tmp}", f"-port={PORT}", f"-rpcport={RPCPORT}",
                                      "-listen=0", "-connect=0", "-dnsseed=0", "-printtoconsole=0", "-rpcuser=u", "-rpcpassword=p", "-fallbackfee=0.0001"])
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
    def try_call(self, wallet, method, *args, named=False):
        try: return self.call(wallet, method, *args, named=named), None
        except RuntimeError as e: return None, str(e)
    def stop(self):
        try: self.call(None, "stop")
        except Exception: pass
        try: self.proc.wait(timeout=60)
        except Exception: self.proc.kill()
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58check(payload):
    d = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(d, "big"); s = ""
    while n: n, r = divmod(n, 58); s = B58[r] + s
    for b in d:
        if b == 0: s = "1" + s
        else: break
    return s
def wif(priv): return b58check(b"\xef" + priv + b"\x01")
PRIV = [bytes([i]) * 32 for i in (0x11, 0x22, 0x33)]
A, B, C = [wif(p) for p in PRIV]
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
def inject_height_lock(psbt_b64, height):
    b = base64.b64decode(psbt_b64); maps = psbt_maps(b)
    maps[1].append((b"\x12", height.to_bytes(4, "little")))
    return base64.b64encode(psbt_ser(maps)).decode()
def canon(x): return json.dumps(x, sort_keys=True)
CMP_GLOBAL = ("psbt_version", "tx_version", "fallback_locktime", "input_count", "output_count", "inputs_modifiable", "outputs_modifiable", "has_sighash_single")
CMP_IN = ("previous_txid", "previous_vout", "sequence", "time_locktime", "height_locktime", "final_scriptSig", "final_scriptwitness", "taproot_key_path_sig")
def v2_view(dec):
    g = {k: dec.get(k) for k in CMP_GLOBAL if k in dec}
    ins = [{k: i.get(k) for k in CMP_IN if k in i} | {"has_witness_utxo": "witness_utxo" in i, "has_non_witness_utxo": "non_witness_utxo" in i} for i in dec["inputs"]]
    outs = [{"amount": o.get("amount"), "hex": (o.get("script") or {}).get("hex"), "type": (o.get("script") or {}).get("type"), "address": (o.get("script") or {}).get("address")} for o in dec["outputs"]]
    return {"g": g, "in": ins, "out": outs}
def decode_both(label, core, ours, psbt, findings):
    cd = core.call(None, "decodepsbt", psbt); od, oe = ours.try_call("decodepsbt", [psbt])
    ck(f"{label}: decodepsbt v2 view matches Core (globals, per-input v2/final fields, outputs amount/script)", od is not None and v2_view(cd) == v2_view(od), f"core={canon(v2_view(cd))[:300]} ours={canon(v2_view(od)) if od else oe}")
    if od is not None and canon(cd) != canon(od):
        paths = []
        def walk(a, b, path):
            if isinstance(a, dict) and isinstance(b, dict):
                for k in sorted(set(a) | set(b)):
                    if k not in a or k not in b: paths.append(f"{path}/{k} ({'core only' if k in a else 'ours only'})")
                    else: walk(a[k], b[k], f"{path}/{k}")
            elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
                for i, (x, y) in enumerate(zip(a, b)): walk(x, y, f"{path}[{i}]")
            elif a != b: paths.append(f"{path}: core={json.dumps(a)[:80]} ours={json.dumps(b)[:80]}")
        walk(cd, od, "")
        findings.append(f"{label}: full decodepsbt JSON differs: " + "; ".join(paths[:6]))
    return cd, od
KINDS = [("wpkh", lambda k: f"wpkh({k})", "bech32"), ("tr", lambda k: f"tr({k})", "bech32m"), ("pkh", lambda k: f"pkh({k})", "legacy"),
         ("sh-wpkh", lambda k: f"sh(wpkh({k}))", "p2sh-segwit"), ("wsh-pk", lambda k: f"wsh(pk({k}))", "bech32")]
def main():
    tmp = tempfile.mkdtemp(prefix="psbtv2.", dir=os.environ.get("CLAUDE_JOB_DIR", "/tmp"))
    shell = build_shell(tmp); ours = Ours(shell); core = Core(tmp); findings = []
    try:
        core.call(None, "createwallet", "w"); mine = core.call("w", "getnewaddress"); core.call("w", "generatetoaddress", 120, mine)
        core.call(None, "createwallet", "k", False, True)   # blank descriptor wallet; imports below
        def cs(d): return core.call(None, "getdescriptorinfo", d)["checksum"]
        addrs = {}
        for name, mk, _ in KINDS:
            d = mk(A); res = core.call("k", "importdescriptors", [{"desc": d + "#" + cs(d), "timestamp": "now"}])
            ck(f"import {name} into Core", res[0]["success"], json.dumps(res)[:200])
            addrs[name] = core.call(None, "deriveaddresses", core.call(None, "getdescriptorinfo", d)["descriptor"])[0]
            core.call("w", "sendtoaddress", addrs[name], 1)
        core.call("w", "generatetoaddress", 1, mine)
        dest = core.call("w", "getnewaddress")
        print("== A. Core creates v2, we decode + sign, Core finalizes ==")
        for name, mk, _ in KINDS:
            utxo = [u for u in core.call("k", "listunspent") if u["address"] == addrs[name]][0]
            psbt = core.call("k", "walletcreatefundedpsbt", [{"txid": utxo["txid"], "vout": utxo["vout"]}], [{dest: 0.5}], 0, {"changeAddress": addrs[name], "subtractFeeFromOutputs": [0]})["psbt"]
            cd, od = decode_both(f"{name}", core, ours, psbt, findings)
            ck(f"{name}: Core's PSBT is v2", cd.get("psbt_version") == 2)
            r, e = ours.try_call("descriptorprocesspsbt", [psbt, [mk(A)]])
            ck(f"{name}: our descriptorprocesspsbt signs the v2 PSBT to completion", r is not None and r.get("complete") and "hex" in r, e or json.dumps(r)[:200])
            if r and r.get("complete"):
                d2 = core.call(None, "decodepsbt", r["psbt"])
                ck(f"{name}: our signed PSBT is still v2 with the v2 input fields", d2.get("psbt_version") == 2 and "previous_txid" in d2["inputs"][0])
                fin = core.call(None, "finalizepsbt", r["psbt"])
                ck(f"{name}: Core finalizes our v2 PSBT to the same hex", fin.get("complete") and fin.get("hex") == r["hex"])
                tma = core.call(None, "testmempoolaccept", [r["hex"]])[0]
                ck(f"{name}: Core testmempoolaccept", tma.get("allowed") is True, json.dumps(tma))
                if tma.get("allowed"): core.call(None, "sendrawtransaction", r["hex"]); core.call("w", "generatetoaddress", 1, mine)
        print("== B. we create v2, Core updates/signs/finalizes; creator bytes identical ==")
        for name, mk, _ in KINDS:
            core.call("w", "sendtoaddress", addrs[name], 1); core.call("w", "generatetoaddress", 1, mine)
            utxo = max([u for u in core.call("k", "listunspent") if u["address"] == addrs[name]], key=lambda u: u["amount"])
            ins = [{"txid": utxo["txid"], "vout": utxo["vout"]}]; outs = [{dest: round(float(utxo["amount"]) - 0.001, 8)}]
            ours_p = ours.call("createpsbt", [ins, outs, 0, True, 2, 2]); core_p = core.call(None, "createpsbt", ins, outs, 0, True, 2, 2)
            ck(f"{name}: our createpsbt(version 2) is byte-identical to Core's", ours_p == core_p, f"ours={ours_p[:60]} core={core_p[:60]}")
            up = core.call(None, "utxoupdatepsbt", ours_p, [mk(A)] if name in ("wsh-pk", "sh-wpkh") else [])
            signed = core.call("k", "walletprocesspsbt", up)
            ck(f"{name}: Core signs our v2 PSBT", signed.get("complete"), json.dumps(signed)[:200])
            od, oe = ours.try_call("decodepsbt", [signed["psbt"]]); cd = core.call(None, "decodepsbt", signed["psbt"])
            ck(f"{name}: our decodepsbt of Core's signed v2 matches Core's view", od is not None and v2_view(cd) == v2_view(od), oe or f"core={canon(v2_view(cd))} ours={canon(v2_view(od))}")
            fin = core.call(None, "finalizepsbt", signed["psbt"]); ofin, ofe = ours.try_call("finalizepsbt", [signed["psbt"]])
            ck(f"{name}: our finalizepsbt extracts the same hex as Core", ofin is not None and ofin.get("hex") == fin.get("hex"), ofe or "")
            tma = core.call(None, "testmempoolaccept", [fin["hex"]])[0]
            ck(f"{name}: mempool accepts", tma.get("allowed") is True, json.dumps(tma))
            if tma.get("allowed"): core.call(None, "sendrawtransaction", fin["hex"]); core.call("w", "generatetoaddress", 1, mine)
        print("== C. creator/converter byte identity across arguments ==")
        utxo = core.call("w", "listunspent")[0]; ins = [{"txid": utxo["txid"], "vout": utxo["vout"], "sequence": 7}]
        for label, args in (("locktime 500 + replaceable false", (ins, [{dest: 0.1}], 500, False, 2, 2)), ("two outputs + data", (ins, [{dest: 0.1}, {"data": "aabbcc"}], 0, True, 2, 2)),
                            ("tx version 1", (ins, [{dest: 0.1}], 0, True, 1, 2)), ("psbt_version 0", (ins, [{dest: 0.1}], 0, True, 2, 0))):
            o = ours.call("createpsbt", list(args)); c = core.call(None, "createpsbt", *args)
            ck(f"createpsbt {label}: byte-identical", o == c, f"ours={o[:50]} core={c[:50]}")
        raw = core.call(None, "createrawtransaction", ins, [{dest: 0.1}], 33)
        for v in (2, 0):
            o = ours.call("converttopsbt", [raw, False, None, v]); c = core.call(None, "converttopsbt", raw, False, False, v)
            ck(f"converttopsbt psbt_version {v}: byte-identical", o == c, f"ours={o[:50]} core={c[:50]}")
        o, e = ours.try_call("createpsbt", [ins, [{dest: 0.1}], 0, True, 2, 1]); c, ce = core.try_call(None, "createpsbt", ins, [{dest: 0.1}], 0, True, 2, 1)
        ck("createpsbt psbt_version 1: both refuse with the same message", o is None and c is None and "The PSBT version can only be 2 or 0" in (e or "") and "The PSBT version can only be 2 or 0" in (ce or ""), f"{e} | {ce}")
        print("== D. required height locktime injected into Core's v2 ==")
        core.call("w", "sendtoaddress", addrs["wpkh"], 1); core.call("w", "generatetoaddress", 1, mine)
        utxo = [u for u in core.call("k", "listunspent") if u["address"] == addrs["wpkh"]][0]
        psbt = core.call("k", "walletcreatefundedpsbt", [{"txid": utxo["txid"], "vout": utxo["vout"]}], [{dest: 0.5}], 0, {"changeAddress": addrs["wpkh"], "subtractFeeFromOutputs": [0]})["psbt"]
        h = core.call(None, "getblockcount"); lp = inject_height_lock(psbt, h - 1)
        cd, od = decode_both("height-locked", core, ours, lp, findings)
        ck("height-locked: both decode the height_locktime", od is not None and cd["inputs"][0].get("height_locktime") == h - 1 == od["inputs"][0].get("height_locktime"))
        r, e = ours.try_call("descriptorprocesspsbt", [lp, ["wpkh(" + A + ")"]])
        ck("height-locked: our signer folds the locktime into the tx (Core finalizes + accepts)", r is not None and r.get("complete") and core.call(None, "finalizepsbt", r["psbt"]).get("hex") == r["hex"] and core.call(None, "testmempoolaccept", [r["hex"]])[0].get("allowed") is True, e or "")
        if r and r.get("complete"):
            dtx = core.call(None, "decoderawtransaction", r["hex"]); ck("height-locked: the extracted tx carries locktime = the required height", dtx.get("locktime") == h - 1)
        print("== E. combine / join / mixed versions ==")
        half = core.call("k", "walletprocesspsbt", psbt, False)["psbt"]   # Core adds bip32 derivs / utxos without signing
        oc, oe = ours.try_call("combinepsbt", [[psbt, half]]); cc = core.call(None, "combinepsbt", [psbt, half])
        ck("combinepsbt of two v2 PSBTs: byte-identical to Core", oc == cc, f"{oe or oc[:60]} | {cc[:60]}")
        v0 = core.call(None, "converttopsbt", core.call(None, "createrawtransaction", [{"txid": utxo["txid"], "vout": utxo["vout"]}], [{dest: 0.5}]), False, False, 0)
        o, e = ours.try_call("combinepsbt", [[psbt, v0]]); c, ce = core.try_call(None, "combinepsbt", [psbt, v0])
        ck("combinepsbt v2+v0 of the same tx: both refuse, same message", o is None and c is None and "PSBTs not compatible (different transactions)" in (e or "") and "PSBTs not compatible (different transactions)" in (ce or ""), f"{e} | {ce}")
        o, e = ours.try_call("joinpsbts", [[psbt, psbt]]); c, ce = core.try_call(None, "joinpsbts", [psbt, psbt])
        ck("joinpsbts on v2: both refuse, same message", o is None and c is None and "joinpsbts only operates on version 0 PSBTs" in (e or "") and "joinpsbts only operates on version 0 PSBTs" in (ce or ""), f"{e} | {ce}")
        oa, oe = ours.try_call("analyzepsbt", [psbt]); ca = core.call(None, "analyzepsbt", psbt)
        ck("analyzepsbt on Core's v2: next role agrees", oa is not None and oa.get("next") == ca.get("next"), f"{oe or oa} | {ca}")
    finally:
        ours.close(); core.stop()
    for f in findings: print("FINDING", f)
    print(f"RESULT: {OK} ok, {len(FAILS)} fail" + (f"; {len(findings)} finding(s) on full-JSON decode parity" if findings else ""))
    return 1 if FAILS else 0
if __name__ == "__main__": sys.exit(main())
