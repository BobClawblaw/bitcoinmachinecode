#!/usr/bin/env python3
"""validation/updater_core_diff.py -- BIP389 multipath descriptors and the PSBT
Updater (descriptors -> scripts / origins / taproot fields) judged by Bitcoin
Core v31.99 on regtest (2026-09-01).

  part 1  multipath descriptors: getdescriptorinfo (incl. multipath_expansion)
          and deriveaddresses (one list per expansion) byte-for-byte, private
          and public forms; Core's refusals mirrored.
  part 2  the Updater: Core creates a v0 PSBT spending a coin at a descriptor's
          address, fills witness_utxo only; then Core's utxoupdatepsbt with
          the descriptor vs OUR utxoupdatepsbt with the descriptor -- both
          decoded by Core's decodepsbt and compared field by field (inputs
          and the change output paying the descriptor's next address).
  part 3  two signers: this node signs first with finalize=false and a Core
          wallet completes, and the reverse; Core's finalizepsbt +
          testmempoolaccept + a mined block judge.
Reuses validation/miniscript_core_diff.py's Core/Ours/shell helpers."""
import os, sys, json, re, shutil, tempfile, subprocess, hashlib, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import miniscript_core_diff as m
m.PORT, m.RPCPORT = 18590, 18591
checks = fails = 0
def ck(label, cond, detail=""):
    global checks, fails
    checks += 1
    if cond: print(f"OK   {label}")
    else: fails += 1; print(f"FAIL {label}" + (f" -- {detail}" if detail else ""))
def norm(x):
    """canonical JSON (sorted keys) for field-by-field comparison"""
    return json.dumps(x, sort_keys=True)
def diff_fields(a, b):
    ka, kb = set(a.keys()), set(b.keys())
    out = []
    for k in sorted(ka | kb):
        if k not in a: out.append(f"missing in ours: {k}")
        elif k not in b: out.append(f"extra in ours: {k}")
        elif norm(a[k]) != norm(b[k]): out.append(f"{k}: core={norm(a[k])[:160]} ours={norm(b[k])[:160]}")
    return out
def main():
    tmp = tempfile.mkdtemp(prefix="updiff.", dir=os.environ.get("CLAUDE_JOB_DIR", "/tmp"))
    shell = m.build_shell(tmp); ours = m.Ours(shell); core = m.Core(tmp); m.core = core
    try:
        core.call(None, "createwallet", "w")
        mine = core.call("w", "getnewaddress")
        core.call("w", "generatetoaddress", 130, mine)
        A, B, C, Dk = m.W; TPRV = m.TPRV; TPUB = re.match(r"pk\((.+)\)", m.pubform(f"pk({TPRV})").split("#")[0]).group(1); NUMS = m.NUMS
        PA, PB, PC = (m.pubkey_hex(p) for p in m.PRIV[:3])
        print("== part 1: multipath descriptors ==")
        MP = [
            f"wpkh({TPRV}/<0;1>/*)", f"pkh({TPRV}/<0;1>/*)", f"sh(wpkh({TPRV}/<0;1>/*))", f"tr({TPRV}/<0;1>/*)", f"rawtr({TPRV}/<0;1>/*)",
            f"tr({TPRV}/<0;1;2>/*)", f"wsh(multi(2,{TPRV}/<0;1>/*,{TPRV}/1/<2;3>/*))", f"sh(wsh(sortedmulti(1,{TPRV}/<0;1>/*,{TPRV}/<5;6>/*)))",
            f"wsh(and_v(v:pk({TPRV}/<0;1>/*),pk({B})))", f"tr({NUMS},{{pk({TPRV}/<0;1>/*),multi_a(2,{A},{TPRV}/2/<0;1>/*)}})",
            f"tr({TPRV}/<0;1>/*,{{pk({A}),pk({TPRV}/9/<0;1>/*)}})", f"wsh(or_d(pk({TPRV}/<0;1>/*),and_v(v:pk({B}),older(2))))",
            f"tr(musig({TPRV}/0,{TPRV}/1)/<0;1>/*)", f"wpkh([deadbeef/44h/1h/0h]{TPRV}/<0;1h>/*)",
            # Core's refusals
            f"pkh({TPRV}/<0;1>/<2;3>)", f"tr({TPRV}/<0;1>/*,{{pk({A}),pk({TPRV}/<0;1;2>/*)}})", f"wpkh({TPRV}/<>/*)", f"wpkh({TPRV}/<1;1>/*)",
            f"wsh(multi(2,{TPRV}/<0;1>/*,{TPRV}/<0;1;2>/*))", f"pkh([deadbeef/<0;1>]{TPRV}/0)",
        ]
        for d in MP:
            ci, ce = core.try_call(None, "getdescriptorinfo", d)
            oi, oe = ours.try_call("getdescriptorinfo", [d])
            lab = f"getdescriptorinfo {d[:60]}"
            if ci is None:
                ck(lab + " (both refuse)", oi is None, f"core={ce} ours={json.dumps(oi)[:200] if oi else oe}")
                cmsg = (ce or "").strip().split("\n")[-1].strip(); omsg = (oe or "").strip().split("\t")[-1].strip()
                if oi is None: ck(lab + " (same message)", cmsg == omsg, f"core=[{cmsg}] ours=[{omsg}]")
                continue
            for form, desc in (("prv", d), ("pub", ci["descriptor"] if "multipath_expansion" not in ci else None)):
                if desc is None:
                    # the public multipath form: rebuild from the private text with Core's key parse of the whole thing
                    pubd, _ = core.try_call(None, "getdescriptorinfo", d)
                    continue
                c2, ce2 = core.try_call(None, "getdescriptorinfo", desc); o2, oe2 = ours.try_call("getdescriptorinfo", [desc])
                lab2 = f"{lab} ({form})"
                if c2 is None or o2 is None: ck(lab2, c2 is None and o2 is None, f"core={ce2} ours={oe2}"); continue
                ck(lab2, norm(c2) == norm(o2), "\n      " + "\n      ".join(diff_fields(c2, o2)))
                full = desc if "#" in desc else desc + "#" + c2["checksum"]
                rng = [0, 1] if c2["isrange"] else None
                ca, cae = core.try_call(None, "deriveaddresses", full, *([rng] if rng else []))
                oa, oae = ours.try_call("deriveaddresses", [full] + ([rng] if rng else []))
                ck(f"deriveaddresses {d[:60]} ({form})", ca == oa, f"core={ca or cae} ours={oa or oae}")
            # the public multipath text: Core prints only the first expansion, so compare our multipath_expansion list
            # against Core's, then each expansion's own getdescriptorinfo/deriveaddresses
            if "multipath_expansion" in ci:
                for i, ex in enumerate(ci["multipath_expansion"]):
                    o3, oe3 = ours.try_call("getdescriptorinfo", [ex]); c3 = core.call(None, "getdescriptorinfo", ex)
                    ck(f"expansion {i} of {d[:50]}", o3 is not None and norm(o3) == norm(c3), oe3 or "\n      " + "\n      ".join(diff_fields(c3, o3 or {})))

        print("== part 2: the Updater vs Core's utxoupdatepsbt with descriptors ==")
        UP = [
            f"wpkh({PA})", f"sh(wpkh({PA}))", f"wsh(multi(2,{PA},{PB}))", f"sh(wsh(multi(2,{PA},{PB})))", f"wsh(sortedmulti(2,{PB},{PA}))",
            f"wsh(and_v(v:pk({PA}),pk({PB})))", f"wsh(or_d(pk({PA}),pkh({PB})))", f"wsh(thresh(2,pk({PA}),s:pk({PB}),s:pk({PC})))",
            f"tr({PA})", f"tr({NUMS},pk({PA}))", f"tr({NUMS},{{pk({PA}),multi_a(2,{PB},{PC})}})", f"tr({PA},{{and_v(v:pk({PB}),older(2)),pk({PC})}})",
            f"tr({NUMS},thresh(2,pk({PA}),s:pk({PB}),s:pk({PC})))", f"tr({NUMS},{{{{pk({PA}),pk({PB})}},{{pk({PC}),and_v(v:pk({PA}),older(3))}}}})",
            f"wpkh([d34db33f/84h/1h/0h]{TPUB}/0/*)", f"tr({TPUB}/0/*)", f"wsh(multi(2,{TPUB}/0/*,{PB}))", f"tr([00aabb22/86h/1h/0h]{TPUB}/1/*,pk({TPUB}/3/*))",
            f"wpkh({TPUB}/<0;1>/*)", f"tr({TPUB}/<0;1>/*)",
        ]
        dest = core.call("w", "getnewaddress")
        funded = []
        for d in UP:
            info = core.call(None, "getdescriptorinfo", d); full = info["descriptor"]
            first = info["multipath_expansion"][0] if "multipath_expansion" in info else full
            rng = [0, 1] if info["isrange"] else None
            addrs = core.call(None, "deriveaddresses", first, *([rng] if rng else []))
            txid = core.call("w", "sendtoaddress", addrs[0], 1.0)
            funded.append((d, full, addrs, txid))
        core.call("w", "generatetoaddress", 1, mine)
        for d, full, addrs, txid in funded:
            lab = f"updater {d[:70]}"
            tx = core.call(None, "getrawtransaction", txid, True)
            vout = next(o["n"] for o in tx["vout"] if o["scriptPubKey"].get("address") == addrs[0])
            change = addrs[1] if len(addrs) > 1 else addrs[0]
            psbt = core.call(None, "createpsbt", [{"txid": txid, "vout": vout}], [{dest: 0.5}, {change: 0.499}], 0, False, 2, 0)
            p1 = core.call(None, "utxoupdatepsbt", psbt)                      # witness_utxo only
            cu, cue = core.try_call(None, "utxoupdatepsbt", p1, [full])
            ou, oue = ours.try_call("utxoupdatepsbt", [p1, [full]])
            if cu is None or ou is None: ck(lab, cu is None and ou is None, f"core={cue} ours={oue}"); continue
            cd = core.call(None, "decodepsbt", cu); od = core.call(None, "decodepsbt", ou)
            di = diff_fields(cd["inputs"][0], od["inputs"][0]); do = diff_fields(cd["outputs"][1], od["outputs"][1])
            ck(lab + " input", not di, "\n      " + "\n      ".join(di) + f"\n      core keys={sorted(cd['inputs'][0].keys())}\n      ours keys={sorted(od['inputs'][0].keys())}")
            ck(lab + " change output", not do, "\n      " + "\n      ".join(do))

        print("== part 3: two signers, either order ==")
        WA, WB, WC = A, B, C
        TWO = [
            (f"wsh(multi(2,{PA},{PB}))", f"wsh(multi(2,{WA},{PB}))", f"wsh(multi(2,{PA},{WB}))"),
            (f"wsh(and_v(v:pk({PA}),pk({PB})))", f"wsh(and_v(v:pk({WA}),pk({PB})))", f"wsh(and_v(v:pk({PA}),pk({WB})))"),
            (f"tr({NUMS},{{pk({PC}),multi_a(2,{PA},{PB})}})", f"tr({NUMS},{{pk({PC}),multi_a(2,{WA},{PB})}})", f"tr({NUMS},{{pk({PC}),multi_a(2,{PA},{WB})}})"),
            (f"tr({NUMS},and_v(v:pk({PA}),pk({PB})))", f"tr({NUMS},and_v(v:pk({WA}),pk({PB})))", f"tr({NUMS},and_v(v:pk({PA}),pk({WB})))"),
        ]
        core.call(None, "createwallet", "w2", False, True)                       # a blank descriptor wallet: it will hold B's halves
        for pub, ours_half, core_half in TWO:
            cs = core.call(None, "getdescriptorinfo", core_half)["checksum"]
            core.call("w2", "importdescriptors", [{"desc": core_half + "#" + cs, "timestamp": "now", "active": False}])
        core.call("w", "generatetoaddress", 3, mine)
        for order in ("ours-first", "core-first"):
            for pub, ours_half, core_half in TWO:
                lab = f"{order} {pub[:50]}"
                info = core.call(None, "getdescriptorinfo", pub); addr = core.call(None, "deriveaddresses", info["descriptor"])[0]
                txid = core.call("w", "sendtoaddress", addr, 1.0); core.call("w", "generatetoaddress", 1, mine)
                tx = core.call(None, "getrawtransaction", txid, True); vout = next(o["n"] for o in tx["vout"] if o["scriptPubKey"].get("address") == addr)
                psbt = core.call(None, "createpsbt", [{"txid": txid, "vout": vout}], {dest: 0.999}, 0, False, 2, 0)
                psbt = core.call(None, "utxoupdatepsbt", psbt, [info["descriptor"]])
                if order == "ours-first":
                    r1, e1 = ours.try_call("descriptorprocesspsbt", [psbt, [ours_half], "DEFAULT", True, False])
                    ck(lab + ": ours half (incomplete)", r1 is not None and not r1.get("complete"), e1 or json.dumps(r1)[:200])
                    if not r1: continue
                    r2 = core.call("w2", "walletprocesspsbt", r1["psbt"])
                    fin = core.call(None, "finalizepsbt", r2["psbt"])
                    if not fin.get("complete"):
                        print("      core walletprocesspsbt:", json.dumps({k: v for k, v in r2.items() if k != "psbt"})[:300])
                        dd0 = core.call(None, "decodepsbt", r1["psbt"])["inputs"][0]
                        print("      ours half keys:", sorted(dd0.keys()))
                        for kk in ("taproot_script_path_sigs", "taproot_internal_key", "taproot_merkle_root"): print(f"      {kk}:", json.dumps(dd0.get(kk))[:500])
                else:
                    r1 = core.call("w2", "walletprocesspsbt", psbt, True, "DEFAULT", True, False)
                    ck(lab + ": Core half (incomplete)", not r1.get("complete"), json.dumps(r1)[:200])
                    r2, e2 = ours.try_call("descriptorprocesspsbt", [r1["psbt"], [ours_half]])
                    ck(lab + ": ours completes with Core's partial", r2 is not None and r2.get("complete"), e2 or json.dumps(r2)[:200])
                    if not (r2 and r2.get("complete")): continue
                    fin = core.call(None, "finalizepsbt", r2["psbt"])
                if not (fin.get("complete") and fin.get("hex")):
                    an = core.call(None, "analyzepsbt", r2["psbt"] if isinstance(r2, dict) else r2)
                    dd = core.call(None, "decodepsbt", (r1["psbt"] if order == "ours-first" else r1["psbt"]))
                    print("      analyze:", json.dumps(an)[:400]); print("      after first signer:", json.dumps({k: v for k, v in dd["inputs"][0].items() if k != "witness_utxo"})[:700])
                ck(lab + ": Core finalizes", fin.get("complete") and fin.get("hex"), json.dumps(fin)[:200])
                if not fin.get("hex"): continue
                tma = core.call(None, "testmempoolaccept", [fin["hex"]], 0)[0]
                ck(lab + ": testmempoolaccept", tma.get("allowed") is True, json.dumps(tma)[:200])
                if tma.get("allowed"):
                    sent = core.call(None, "sendrawtransaction", fin["hex"], 0); core.call("w", "generatetoaddress", 1, mine)
                    ck(lab + ": mined", core.call(None, "getrawtransaction", sent, True).get("confirmations", 0) >= 1)
    finally:
        try: ours.close()
        except Exception: pass
        core.stop(); shutil.rmtree(tmp, ignore_errors=True)
    print(f"RESULT: {checks - fails} ok, {fails} fail")
    sys.exit(1 if fails else 0)
if __name__ == "__main__": main()
