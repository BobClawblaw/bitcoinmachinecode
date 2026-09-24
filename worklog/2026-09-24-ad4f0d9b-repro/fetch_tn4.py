"""Fetch the three testnet4 runs tn4_replay.c replays: blocks target-5..target
for 124864 / 125673 / 126361 (raw), their prevouts (minus outputs created
inside the run), and the 18-header windows the median-time-past check reads.
Usage: fetch_tn4.py <outdir>   (a testnet4 Core with -rpcport=48332; edit CLI)"""
import json, subprocess, sys
CLI = ["/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli", "-datadir=/storage/core-oracle-testnet4", "-chain=testnet4", "-rpcport=48332"]
def rpc(*a): return subprocess.run(CLI + [str(x) for x in a], check=True, capture_output=True, text=True).stdout.strip()
out = sys.argv[1]
for target in (124864, 125673, 126361):
    hs = list(range(target - 5, target + 1))
    created = set(); lines = []
    for h in hs:
        bh = rpc("getblockhash", h)
        open(f"{out}/blk_{h}.bin", "wb").write(bytes.fromhex(rpc("getblock", bh, 0)))
        b = json.loads(rpc("getblock", bh, 3))
        for tx in b["tx"]:
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
            f.write(f'{h} {rpc("getblockheader", rpc("getblockhash", h), "false")}\n')
