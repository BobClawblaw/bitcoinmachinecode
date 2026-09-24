"""fetch_tn4.py's fixtures from any node that answers JSON-RPC with cookie
auth -- a bmc node included (its getblock 3 carries prevouts). No bitcoin-cli
needed, which is how the Mac run got its fixtures (testnet4 node B, 2026-09-24).
Usage: fetch_tn4_rpc.py <outdir> <rpc url> <cookie file>
  e.g. fetch_tn4_rpc.py fx http://127.0.0.1:48332/ ~/.bitcoin/testnet4/.cookie"""
import base64, json, os, sys, urllib.request
out, url, cookie = sys.argv[1], sys.argv[2], os.path.expanduser(sys.argv[3])
AUTH = "Basic " + base64.b64encode(open(cookie).read().strip().encode()).decode()
def rpc(m, *ps):
    req = urllib.request.Request(url, json.dumps({"method": m, "params": list(ps)}).encode(), {"Authorization": AUTH})
    r = json.load(urllib.request.urlopen(req))
    if r.get("error"): raise SystemExit(f"{m} {ps}: {r['error']}")
    return r["result"]
os.makedirs(out, exist_ok=True)
for target in (124864, 125673, 126361):
    hs = list(range(target - 5, target + 1))
    created = set(); lines = []
    for h in hs:
        bh = rpc("getblockhash", h)
        open(f"{out}/blk_{h}.bin", "wb").write(bytes.fromhex(rpc("getblock", bh, 0)))
        for tx in rpc("getblock", bh, 3)["tx"]:
            for vin in tx["vin"]:
                if "coinbase" in vin: continue
                key = (vin["txid"], vin["vout"])
                if key in created: continue
                p = vin["prevout"]
                lines.append(f'{vin["txid"]} {vin["vout"]} {round(p["value"]*1e8)} {p["scriptPubKey"]["hex"]}')
            for o in tx["vout"]: created.add((tx["txid"], o["n"]))
    open(f"{out}/batch_{target}.prevouts", "w").write("\n".join(lines) + "\n")
    print(target, "blocks", hs[0], "-", hs[-1], "prevouts", len(lines))
with open(f"{out}/headers.txt", "w") as f:
    for target in (124864, 125673, 126361):
        for h in range(target - 17, target + 1):
            f.write(f'{h} {rpc("getblockheader", rpc("getblockhash", h), False)}\n')
