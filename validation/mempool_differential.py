#!/usr/bin/env python3
"""mempool_differential.py -- bmc's mempool against Core's, transaction by transaction.

WHY THIS EXISTS. On 2026-10-01 BlockYard compared the two nodes' chunk feerates
and found clusters ranked differently. The causes were three policy divergences
in bmc (fixed in #363): the 25-transaction chain limit, pre-v31 replacement
rules, and greedy chunking. This script repeats that measurement from the bmc
side, so the fix can be checked and a regression caught:

  1. MISSING: transactions Core holds that bmc does not. Each is fetched from
     Core and offered to bmc's testmempoolaccept (which changes nothing), and
     bmc's reject reasons are tallied. A child whose parent bmc also lacks comes
     back missing-inputs; that is relay timing, not policy.
  2. CHUNKS: transactions both hold. Their chunk feerates (fees.chunk /
     chunkweight from getmempoolentry) are compared exactly, by
     cross-multiplication.
  3. CLUSTERS: for each disagreeing transaction, getmempoolcluster on both: the
     same members means the two chunked one cluster differently (a
     linearization difference); different members means the nodes hold
     different transactions (a policy or relay difference).

Read-only on both nodes. Two mempools a few seconds apart always differ a
little; compare runs, not single transactions, and read the classes.

  python3 validation/mempool_differential.py \\
      --bmc http://127.0.0.1:8331 --bmc-cookie data/main/.cookie \\
      --core http://127.0.0.1:8335 --core-cookie /storage/core-oracle/.cookie
"""
import argparse, base64, json, sys, urllib.request
from collections import Counter
from decimal import Decimal

class Node:
    def __init__(self, url, cookie, name):
        self.url, self.name = url, name
        tok = open(cookie).read().strip()
        self.auth = "Basic " + base64.b64encode(tok.encode()).decode()
        self.batch_ok = True
    def _post(self, payload):
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(),
                                     headers={"Authorization": self.auth, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=600) as r:
            return json.loads(r.read(), parse_float=Decimal)
    def call(self, method, *params):
        r = self._post({"jsonrpc": "1.0", "id": 0, "method": method, "params": list(params)})
        if r.get("error"): raise RuntimeError(f"{self.name} {method}: {r['error']}")
        return r["result"]
    def many(self, method, param_lists, chunk=500):
        """results in order; None where the call errored"""
        out = []
        for i in range(0, len(param_lists), chunk):
            part = param_lists[i:i + chunk]
            if self.batch_ok:
                try:
                    rs = self._post([{"jsonrpc": "1.0", "id": k, "method": method, "params": p} for k, p in enumerate(part)])
                    if isinstance(rs, list):
                        byid = {x["id"]: x for x in rs}
                        out += [None if byid[k].get("error") else byid[k]["result"] for k in range(len(part))]
                        continue
                except Exception:
                    pass
                self.batch_ok = False
            for p in part:
                try: out.append(self.call(method, *p))
                except Exception: out.append(None)
        return out

def chunk_rate(entry):
    """(fee in sat, chunkweight) from a getmempoolentry result, or None"""
    if not entry or "chunkweight" not in entry: return None
    fee = entry.get("fees", {}).get("chunk")
    if fee is None: return None
    return (int((Decimal(str(fee)) * 100_000_000).to_integral_value()), int(entry["chunkweight"]))

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bmc", required=True); ap.add_argument("--bmc-cookie", required=True)
    ap.add_argument("--core", required=True); ap.add_argument("--core-cookie", required=True)
    ap.add_argument("--max-missing", type=int, default=5000, help="cap on missing transactions offered to testmempoolaccept")
    ap.add_argument("--examples", type=int, default=5)
    a = ap.parse_args()
    bmc, core = Node(a.bmc, a.bmc_cookie, "bmc"), Node(a.core, a.core_cookie, "core")

    b_ids, c_ids = set(bmc.call("getrawmempool")), set(core.call("getrawmempool"))
    both, missing, extra = b_ids & c_ids, sorted(c_ids - b_ids), b_ids - c_ids
    print(f"mempools: bmc {len(b_ids)}, Core {len(c_ids)}, both {len(both)}, Core-only {len(missing)}, bmc-only {len(extra)}")

    # 1. why bmc lacks what Core holds
    sample = missing[:a.max_missing]
    raws = core.many("getrawtransaction", [[t] for t in sample])
    offered = [(t, r) for t, r in zip(sample, raws) if r]
    verdicts = bmc.many("testmempoolaccept", [[[r]] for _, r in offered])
    reasons = Counter(); ex = {}
    for (t, _), v in zip(offered, verdicts):
        if not v: why = "(rpc error)"
        else:
            v0 = v[0]
            why = "allowed" if v0.get("allowed") else (v0.get("reject-reason") or "(no reason)")
        reasons[why] += 1; ex.setdefault(why, []).append(t)
    print(f"\n1. Core-only transactions offered to bmc's testmempoolaccept: {len(offered)} of {len(missing)}")
    for why, n in reasons.most_common():
        print(f"   {n:6d}  {why}" + (f"   e.g. {ex[why][0]}" if a.examples else ""))

    # 2. chunk feerates of what both hold
    ids = sorted(both)
    be = bmc.many("getmempoolentry", [[t] for t in ids])
    ce = core.many("getmempoolentry", [[t] for t in ids])
    disagree, compared = [], 0
    for t, x, y in zip(ids, be, ce):
        rb, rc = chunk_rate(x), chunk_rate(y)
        if not rb or not rc or rb[1] == 0 or rc[1] == 0: continue
        compared += 1
        if rb[0] * rc[1] != rc[0] * rb[1]: disagree.append((t, rb, rc))
    print(f"\n2. shared transactions with chunk feerates on both: {compared}; disagreeing: {len(disagree)}")

    # 3. same cluster members or not. Each disagreement is re-read from both
    # nodes back to back first: the step-2 reads are seconds apart (all of
    # bmc's entries, then all of Core's), and a cluster being fee-bumped by
    # same-size replacements meanwhile shows up as "same members, different
    # chunk" with bmc always lower (2026-10-01: six members of one cluster read
    # 544, then 2028, then 2245 sat over ~6,690 weight within minutes).
    seen, same, diff, churn = set(), [], [], 0
    for t, rb, rc in disagree:
        if t in seen: continue
        try:
            rb2, rc2 = chunk_rate(bmc.call("getmempoolentry", t)), chunk_rate(core.call("getmempoolentry", t))
        except Exception:
            churn += 1; seen.add(t); continue                  # left a pool in between
        if rb2 and rc2 and rb2[0] * rc2[1] == rc2[0] * rb2[1]:
            churn += 1; seen.add(t); continue
        if rb2 and rc2: rb, rc = rb2, rc2
        cb, cc = bmc.call("getmempoolcluster", t), core.call("getmempoolcluster", t)
        mb = {x for ch in cb.get("chunks", []) for x in ch.get("txs", [])}
        mc = {x for ch in cc.get("chunks", []) for x in ch.get("txs", [])}
        seen |= mb | mc
        (same if mb == mc else diff).append((t, rb, rc, len(mb), len(mc)))
    print(f"3. disagreements that agree when re-read back to back (the pools changed between reads): {churn}")
    print(f"   still disagreeing, by cluster: {len(same) + len(diff)} -- same members (chunked differently): {len(same)}, different members: {len(diff)}")
    for label, rows in (("same members", same), ("different members", diff)):
        for t, rb, rc, nb, nc in rows[:a.examples]:
            print(f"   {label}: {t}  bmc {rb[0]*4/rb[1]:.2f} sat/vB ({nb} tx)  Core {rc[0]*4/rc[1]:.2f} sat/vB ({nc} tx)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
