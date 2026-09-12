#!/usr/bin/env python3
"""Field-level RPC parity against a live Bitcoin Core oracle.

WHY THIS EXISTS. The parity register tracked METHOD NAMES. Every Core method
existed, so the surface read as complete -- while `getrawmempool true` returned
four fields where Core returns sixteen, for weeks, and `getpeerinfo` returns
nineteen where Core returns seventy-six. A name is not a contract; the response
shape is. The same lesson had already been learned once on the REST surface
("compare whole documents, name each divergence") and was never applied here.

It calls each method on BOTH nodes with the same arguments and diffs the set of
JSON key paths. Keys only: values legitimately differ between two nodes at
different tips, and a value diff would drown the signal. Nested objects recurse;
arrays are sampled at their first element, which is enough to catch a missing
per-entry field.

Fields Core has and we do not are the work. Fields we have and Core does not are
this node's own extensions and are listed separately, not as errors.

  python3 validation/rpc_field_parity.py [--json out.json]
"""
import json, subprocess, sys

BMC  = ["/storage/bitcoinmachinecode/asm/daemon/bmc_cli", "-rpcport=8331",
        "-datadir=/storage/bitcoinmachinecode/data"]
CORE = ["/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli",
        "-conf=/storage/core-oracle/bitcoin.conf", "-datadir=/storage/core-oracle"]

def raw(base, args, timeout=180):
    try:
        r = subprocess.run(base + args, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None

def call(base, args, timeout=180):
    s = raw(base, args, timeout)
    if s is None: return None
    try: return json.loads(s)
    except Exception: return s

def _is_id(k):
    return len(k) == 64 and all(c in "0123456789abcdef" for c in k)

def keypaths(o, pre=""):
    """Key paths, with maps KEYED BY TXID collapsed to one sample.

    getrawmempool verbose is an object keyed by txid, so two nodes holding
    different transactions produce disjoint key sets and the diff reports the
    whole mempool as missing -- 194,561 phantom "gaps" on the first run of this
    tool. What matters there is the shape of an ENTRY, not which transactions
    happen to be in each pool, so an id-keyed map is sampled like an array."""
    s = set()
    if isinstance(o, dict):
        ks = list(o.keys())
        if ks and all(_is_id(k) for k in ks):
            return keypaths(o[ks[0]], pre + "<id>.")
        for k, v in o.items():
            s.add(pre + k); s |= keypaths(v, pre + k + ".")
    elif isinstance(o, list) and o:
        s |= keypaths(o[0], pre)
    return s

# A height and a block both nodes certainly have, and live ids for the rest.
H = "966000"
BH = (raw(CORE, ["getblockhash", H]) or "").strip('"')
blk = call(CORE, ["getblock", BH, "2"]) or {}
TXID = blk.get("tx", [{}, {}])[1].get("txid", "") if len(blk.get("tx", [])) > 1 else ""
mp = call(CORE, ["getrawmempool"]) or []
MPTX = mp[0] if mp else ""
ADDR = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
DESC = "pkh(02e8b0c2d0a2c1b4a8f0e7d6c5b4a3928170695847362514038271605948372615)"
RAWTX = raw(CORE, ["getrawtransaction", TXID, "0", BH]) if TXID else None

# Read-only calls only. Nothing here changes node state on either side.
CASES = [
    ("getblockchaininfo", []), ("getchaintips", []), ("getchaintxstats", []),
    ("getdifficulty", []), ("getblockcount", []), ("getbestblockhash", []),
    ("getdeploymentinfo", []), ("getindexinfo", []), ("getblockstats", [H]),
    ("getblockheader", [BH]), ("getblockheader", [BH, "false"]),
    ("getblock", [BH, "1"]), ("getblock", [BH, "2"]), ("getblock", [BH, "3"]),
    ("gettxoutproof", None), ("getnetworkinfo", []), ("getnettotals", []),
    ("getpeerinfo", []), ("getconnectioncount", []), ("listbanned", []),
    ("getaddednodeinfo", []), ("getnodeaddresses", ["5"]),
    ("getmempoolinfo", []), ("getrawmempool", []), ("getrawmempool", ["true"]),
    ("getmininginfo", []), ("getnetworkhashps", []),
    ("getblocktemplate", ['{"rules":["segwit"]}']),
    ("estimatesmartfee", ["6"]), ("uptime", []), ("getrpcinfo", []),
    ("getmemoryinfo", ["mallocinfo"]),
    ("validateaddress", [ADDR]), ("getdescriptorinfo", [DESC]),
    ("deriveaddresses", ["addr(%s)#nkvcnuc7" % ADDR]),
    ("decodescript", ["76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"]),
    ("getzmqnotifications", []),
]
if TXID:
    CASES += [("getrawtransaction", [TXID, "1", BH]), ("getrawtransaction", [TXID, "2", BH]),
              ("gettxout", [TXID, "0"])]
if RAWTX:
    CASES += [("decoderawtransaction", [RAWTX])]
if MPTX:
    CASES += [("getmempoolentry", [MPTX]), ("getmempoolancestors", [MPTX, "true"]),
              ("getmempooldescendants", [MPTX, "true"])]

rows, gaps, extras, skipped = [], 0, 0, 0
for m, a in CASES:
    if a is None: skipped += 1; continue
    o, c = call(BMC, [m] + a), call(CORE, [m] + a)
    label = m + (("(" + ",".join(x[:12] for x in a[1:]) + ")") if len(a) > 1 else "")
    if o is None or c is None:
        rows.append((label, None, None, [], [], "ours=%s core=%s" % ("ok" if o is not None else "ERR",
                                                                    "ok" if c is not None else "ERR")))
        continue
    ko, kc = keypaths(o), keypaths(c)
    # Two DELIBERATE additive keys: the operator asked for build attestation
    # over RPC, and Core has no equivalent. Everything else additive has been
    # removed for exactness. Named here so they read as a decision, not drift.
    ext_ok = {"bmc_build_commit", "bmc_build_dirty"}
    miss, ext = sorted(kc - ko), sorted((ko - kc) - ext_ok)
    if miss: gaps += 1
    if ext: extras += 1
    rows.append((label, len(ko), len(kc), miss, ext, ""))

print("%-34s %5s %5s  %s" % ("call", "ours", "core", "fields Core returns and we do not"))
print("-" * 110)
for label, no, nc, miss, ext, note in rows:
    if note:
        print("%-34s %5s %5s  (%s)" % (label, "--", "--", note)); continue
    print("%-34s %5d %5d  %s" % (label, no, nc, ", ".join(miss) if miss else "none"))
print("-" * 110)
print("%d of %d calls have missing fields; %d also carry fields Core does not"
      % (gaps, len([r for r in rows if r[1] is not None]), extras))
if "--json" in sys.argv:
    out = sys.argv[sys.argv.index("--json") + 1]
    json.dump([{"call": r[0], "ours": r[1], "core": r[2], "missing": r[3], "extra": r[4], "note": r[5]}
               for r in rows], open(out, "w"), indent=1)
    print("wrote", out)
sys.exit(1 if gaps else 0)
