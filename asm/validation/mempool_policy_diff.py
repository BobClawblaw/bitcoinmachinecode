#!/usr/bin/env python3
"""Differential mempool-ADMISSION harness: identical raw transactions fed to
a scratch Bitcoin Core regtest node AND this repo's bmc regtest node via
sendrawtransaction; verdicts and reject-reason strings must agree.

Ports (parity-fork allocation): Core 19781(p2p,+1 tor)/19783(rpc), bmc 19787(p2p)/19786(rpc).
Both nodes run -datacarriersize=83 so the datacarrier budget case is
exercised on both sides (Core v31's default budget is 100k).

VERSION-TARGET DELTAS (recorded, not failures): the available oracle is a
v31 CLUSTER-mempool build -- its chain limits are cluster limits (a 26-deep
chain is legal there) and some reject strings moved. Cases marked
`delta=...` assert the EXPECTED DIVERGENCE explicitly instead of agreement,
so a silent behaviour change on either side still fails the harness.
"""
import json, subprocess, time, urllib.request, base64, sys, os, signal

CORE = "/storage/bitcoin-core-source/build/bin/bitcoind"
CLI  = "/storage/bitcoin-core-source/build/bin/bitcoin-cli"
HERE = os.path.dirname(os.path.abspath(__file__))
BMCD = os.path.join(HERE, "..", "daemon", "bitcoind")
WORK = os.path.join(os.environ.get("TMPDIR", "/tmp"), "bmc-mpolicy-diff")
CORE_DIR = WORK + "/core"; BMC_DIR = WORK + "/bmc"
# Core binds its tor TARGET on P2P+1 even with listenonion=0 (the same
# collision DEPLOYMENT.md records for 18445) -- keep P2P+1 free.
CORE_P2P, CORE_RPC, BMC_P2P, BMC_RPC = 19781, 19783, 19785, 19786

def core(*a):
    r = subprocess.run([CLI, "-datadir="+CORE_DIR, "-rpcport=%d"%CORE_RPC, *a],
                       capture_output=True, text=True)
    return r.returncode, (r.stdout.strip() or r.stderr.strip())

def bmc(method, params=None):
    req = urllib.request.Request("http://127.0.0.1:%d/"%BMC_RPC, json.dumps(
        {"jsonrpc":"2.0","id":1,"method":method,"params":params or []}).encode(),
        {"Authorization":"Basic "+base64.b64encode(b"d:d").decode()})
    try:
        r = json.load(urllib.request.urlopen(req, timeout=120))
    except Exception as e:
        return -99, str(e)
    if r.get("error"): return r["error"]["code"], r["error"]["message"]
    return 0, r["result"]

results = []
def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(("  ok  " if ok else "  FAIL ") + name + ("  ["+detail+"]" if detail else ""))

def send_both(rawhex):
    """returns (core_ok, core_msg, bmc_ok, bmc_msg); 'already in pool' counts
    as accept (P2P relay between the nodes can race the RPC submission)."""
    crc, cmsg = core("sendrawtransaction", rawhex)
    cok = (crc == 0) or ("txn-already-in-mempool" in cmsg)
    brc, bmsg = bmc("sendrawtransaction", [rawhex])
    bok = (brc == 0) or ("txn-already-in-mempool" in str(bmsg))
    return cok, cmsg, bok, str(bmsg)

def diff_case(name, rawhex, want_reason=None):
    cok, cmsg, bok, bmsg = send_both(rawhex)
    if cok != bok:
        check(name, False, "verdict split: core=%s bmc=%s" % (cmsg[:60], bmsg[:60])); return
    if cok:
        check(name, True, "both accept"); return
    if want_reason:
        check(name, want_reason in cmsg and want_reason in bmsg,
              "core=%r bmc=%r want=%r" % (cmsg[:48], bmsg[:48], want_reason))
    else:
        check(name, True, "both reject (core=%r bmc=%r)" % (cmsg[:40], bmsg[:40]))

def main():
    os.makedirs(CORE_DIR, exist_ok=True); os.makedirs(BMC_DIR, exist_ok=True)
    open(CORE_DIR+"/bitcoin.conf","w").write(
        "regtest=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=d\nrpcpassword=d\n"
        "listen=1\nlistenonion=0\nfallbackfee=0.0001\ndatacarriersize=83\n"
        "minrelaytxfee=0.00001\n"   # v31 default dropped to 0.1 sat/vB; pin the classic default this node implements

        "debug=mempoolrej\n" % (CORE_P2P, CORE_RPC))
    # bmc is kept FULLY OFFLINE (connect= to TEST-NET-1, the repo's own
    # offline-bench pattern) and receives the oracle's chain via RPC
    # submitblock -- no P2P between the nodes, no port coupling, no relay
    # cross-talk racing the differential submissions.
    open(BMC_DIR+"/bitcoin.conf","w").write(
        "chain=regtest\nport=19787\nrpcport=%d\nrpcuser=d\nrpcpassword=d\n"
        "connect=192.0.2.1\ndatacarriersize=83\n" % BMC_RPC)
    procs = []
    try:
        procs.append(subprocess.Popen([CORE, "-datadir="+CORE_DIR, "-daemon=0"],
                     stdout=open(CORE_DIR+"/out.log","w"), stderr=subprocess.STDOUT))
        for _ in range(60):
            if core("getblockcount")[0] == 0: break
            time.sleep(0.5)
        core("createwallet", "w")
        addr = core("getnewaddress")[1]
        core("generatetoaddress", "120", addr)

        procs.append(subprocess.Popen([BMCD, "serve", BMC_DIR],
                     stdout=open(BMC_DIR+"/out.log","w"), stderr=subprocess.STDOUT))
        for _ in range(90):
            rc, res = bmc("getblockcount")
            if rc == 0: break
            time.sleep(1)
        # wait for the worker's FIRST utxo catch-up (genesis applied) before
        # staging any submit: a staged block pre-empts the catch-up step in
        # the worker loop, so an early submit spins "inconclusive" forever
        # against applied=-1.
        for _ in range(90):
            log = open(BMC_DIR+"/out.log").read()
            if "updating utxo: applied" in log or "now at height 0" in log: break
            time.sleep(1)
        else:
            print("bmc utxo never settled"); sys.exit(3)
        # feed the oracle's chain over RPC: getblock hex -> submitblock.
        # EVERY oracle call is rc-checked: an error string mistaken for block
        # hex produced a phantom "Block decode failed" on the first run.
        for _ in range(60):
            if core("getblockhash", "120")[0] == 0: break
            time.sleep(1)
        for h in range(1, 121):
            rc1, bh = core("getblockhash", str(h))
            if rc1 != 0: print("getblockhash %d: %s" % (h, bh)); sys.exit(3)
            rc2, bx = core("getblock", bh, "0")
            if rc2 != 0: print("getblock %d: %s" % (h, bx)); sys.exit(3)
            rc, res = bmc("submitblock", [bx])
            if rc == -99:                      # transport timeout: retry once
                rc, res = bmc("submitblock", [bx])
                if "duplicate" in str(res): rc, res = 0, None
            if rc != 0 and res not in (None, "None"):
                print("submitblock h=%d failed: %s %s" % (h, rc, res)); sys.exit(3)
            # the daemon's submit stage is one-deep: wait for the connect
            for _ in range(100):
                rc2, hh = bmc("getblockcount")
                if rc2 == 0 and hh >= h: break
                time.sleep(0.2)
            else:
                print("block %d did not connect (tip=%s)" % (h, hh)); sys.exit(3)
        for _ in range(60):
            rc, res = bmc("getblockcount")
            if rc == 0 and res >= 120: break
            time.sleep(1)
        rc, res = bmc("getblockcount")
        if not (rc == 0 and res >= 120):
            print("bmc did not adopt the chain (rc=%s res=%s)" % (rc, res)); sys.exit(3)
        print("== nodes at height %s (RPC-fed, no P2P coupling) ==" % res)

        # helper: a fresh confirmed coin -> raw tx paying `outputs`, signed
        def make_signed(outputs, replaceable=True, utxo=None):
            if utxo is None:
                _, unsp = core("listunspent", "1", "9999999")
                u = json.loads(unsp)[0]
            else: u = utxo
            ins = json.dumps([{"txid":u["txid"], "vout":u["vout"],
                               "sequence": 0xfffffffd if replaceable else 0xffffffff}])
            _, raw = core("createrawtransaction", ins, json.dumps(outputs))
            _, sig = core("signrawtransactionwithwallet", raw)
            return json.loads(sig)["hex"], u

        _, unsp = core("listunspent", "1", "9999999")
        coins = json.loads(unsp)
        print("== battery ==")

        # 1. simple accept (spend minus a sane fee -- the first draft paid a
        # 49 BTC fee and tripped Core's client-side maxfeerate guard; NOTE:
        # bmc's sendrawtransaction has no maxfeerate client guard, an RPC-
        # surface delta recorded in the report)
        a = core("getnewaddress")[1]
        h1, c1 = make_signed([{a: round(float(coins[0]["amount"])-0.0001, 8)}], utxo=coins[0])
        diff_case("simple accept", h1)

        # 2. zero-fee (below min relay)
        a = core("getnewaddress")[1]
        amt = coins[1]["amount"]
        h2, _ = make_signed([{a: round(float(amt), 8)}], utxo=coins[1])
        diff_case("zero fee", h2, "min relay fee not met")

        # 3. dust output (200 sat)
        a = core("getnewaddress")[1]
        h3, _ = make_signed([{a: 0.00000200},
                             {core("getnewaddress")[1]: round(float(coins[2]["amount"])-0.001, 8)}],
                            utxo=coins[2])
        diff_case("dust output", h3, "dust")

        # 4. datacarrier over budget (both sides run -datacarriersize=83)
        _, raw = core("createrawtransaction",
                      json.dumps([{"txid":coins[3]["txid"],"vout":coins[3]["vout"]}]),
                      json.dumps([{"data": "aa"*90},
                                  {core("getnewaddress")[1]: round(float(coins[3]["amount"])-0.001, 8)}]))
        _, sig = core("signrawtransactionwithwallet", raw)
        h4 = json.loads(sig)["hex"]
        diff_case("datacarrier over budget", h4, "datacarrier")

        # 5. RBF: replaceable original, then a higher-fee replacement
        a5 = core("getnewaddress")[1]
        amt5 = float(coins[4]["amount"])
        o1, _ = make_signed([{a5: round(amt5-0.0005, 8)}], True, coins[4])
        diff_case("rbf original", o1)
        r1, _ = make_signed([{a5: round(amt5-0.002, 8)}], True, coins[4])
        diff_case("rbf replacement (higher fee)", r1)

        # 6. RBF insufficient: replace the REPLACEMENT with a fee lower than it
        r2, _ = make_signed([{a5: round(amt5-0.001, 8)}], True, coins[4])
        diff_case("rbf lower-fee re-replacement", r2, "insufficient fee")

        # 7. chain-limit VERSION-TARGET DELTA: build a 26-deep self-spend
        # chain; classic policy (ours) rejects link 26 with
        # "too-long-mempool-chain"; the v31 cluster oracle ACCEPTS it.
        a7 = core("getnewaddress")[1]
        u = {"txid":coins[5]["txid"], "vout":coins[5]["vout"], "amount":coins[5]["amount"]}
        amt = float(u["amount"]); deep_ok = True; delta_seen = None
        for depth in range(1, 27):
            amt = round(amt - 0.0002, 8)
            ins = json.dumps([{"txid":u["txid"],"vout":u["vout"]}])
            _, raw = core("createrawtransaction", ins, json.dumps([{a7: amt}]))
            _, sig = core("signrawtransactionwithwallet", raw)
            hx = json.loads(sig)["hex"]
            cok, cmsg, bok, bmsg = send_both(hx)
            if depth <= 25:
                if not (cok and bok): deep_ok = False; delta_seen = (depth, cmsg, bmsg); break
            else:
                # v31 accepts (cluster limit 64); classic bmc rejects
                delta_seen = (depth, cmsg, bmsg)
                check("26-deep link: v31 accepts, classic rejects (EXPECTED DELTA)",
                      cok and (not bok) and "too-long-mempool-chain" in bmsg,
                      "core=%s bmc=%r" % ("accept" if cok else cmsg[:30], bmsg[:44]))
            _, dec = core("decoderawtransaction", hx)
            u = {"txid": json.loads(dec)["txid"], "vout": 0}
        check("25-deep chain accepted by both", deep_ok,
              "" if deep_ok else "broke at %s core=%r bmc=%r" % delta_seen)

        # 8. mempoolminfee floors agree while quiet
        _, ci = core("getmempoolinfo")
        _, bi = bmc("getmempoolinfo")
        cmin = json.loads(ci)["mempoolminfee"]; bmin = bi["mempoolminfee"]
        check("quiet mempoolminfee equal", abs(cmin - bmin) < 1e-9,
              "core=%.8f bmc=%.8f" % (cmin, bmin))

        print("\n== verdicts ==")
        bad = [r for r in results if not r[1]]
        print("%d checks, %d failures" % (len(results), len(bad)))
        sys.exit(1 if bad else 0)
    finally:
        for p in procs:
            try: p.send_signal(signal.SIGTERM)
            except Exception: pass
        for p in procs:
            try: p.wait(timeout=20)
            except Exception:
                try: p.kill()
                except Exception: pass

if __name__ == "__main__":
    main()
