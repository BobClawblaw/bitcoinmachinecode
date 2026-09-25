#!/usr/bin/env python3
"""fetch_block_prevouts.py HEIGHT... -- a mainnet block and every prevout it
spends, as the apply-path fixtures under tests/fixtures expect them (used by
test_block_481827_pool_stack):

    blk_<h>.bin        the raw block (getblock <hash> 0)
    blk_<h>.prevouts   one line per non-coinbase input:
                       <txid hex, display order> <vout> <value sat> <scriptPubKey hex>
    blk_<h>.headers    the 11 headers before it, "<height> <80-byte hex>" per
                       line: the median-time-past window the finality rule
                       (VAL-4, BIP113) reads once CSV is active

Prevouts created inside the block itself are left out (the apply path creates
them). The block comes from Core, not this project's archive: the fixture
must carry witnesses. Needs a Core node with the block and its undo data
(getblock verbosity 3).

2026-09-24: rewritten. The previous version read the block from the
production archive and the prevouts from Core's txindex, wrote prevouts for
outputs the block itself creates, and fetched no headers.

Usage (from asm/):
    validation/fetch_block_prevouts.py <height> [<height> ...]

The node is reached with $BITCOIN_CLI, split on whitespace; the default is
the reference host's scratch oracle.
"""
import json
import os
import shlex
import subprocess
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "fixtures")
DEFAULT_CLI = ("/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli "
               "-conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle")


def rpc(cli, *args):
    return subprocess.run(cli + [str(a) for a in args], check=True,
                          capture_output=True, text=True).stdout.strip()


def fetch(cli, height):
    bh = rpc(cli, "getblockhash", height)
    raw = bytes.fromhex(rpc(cli, "getblock", bh, 0))
    blk = json.loads(rpc(cli, "getblock", bh, 3))
    created, lines = set(), []
    for tx in blk["tx"]:
        for vin in tx["vin"]:
            if "coinbase" in vin:
                continue
            if (vin["txid"], vin["vout"]) in created:
                continue
            p = vin["prevout"]
            sats = round(p["value"] * 100_000_000)
            lines.append(f'{vin["txid"]} {vin["vout"]} {sats} {p["scriptPubKey"]["hex"]}')
        for o in tx["vout"]:
            created.add((tx["txid"], o["n"]))
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, f"blk_{height}.bin"), "wb") as f:
        f.write(raw)
    with open(os.path.join(OUT, f"blk_{height}.prevouts"), "w") as f:
        f.write("\n".join(lines) + "\n")
    with open(os.path.join(OUT, f"blk_{height}.headers"), "w") as f:
        for h in range(max(0, height - 11), height):
            f.write(f'{h} {rpc(cli, "getblockheader", rpc(cli, "getblockhash", h), "false")}\n')
    print(f"{height} {bh}: {len(raw)} bytes, {len(lines)} prevouts, headers {max(0, height - 11)}..{height - 1}")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cli = shlex.split(os.environ.get("BITCOIN_CLI", DEFAULT_CLI))
    for h in sys.argv[1:]:
        fetch(cli, int(h))


if __name__ == "__main__":
    main()
