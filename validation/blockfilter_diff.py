#!/usr/bin/env python3
"""blockfilter_diff.py -- our basic block filter vs CORE'S, over real blocks.

STO-14 (audit 2026-09-03) changed block_filter.c to de-duplicate the byte-wise
ELEMENT SET, as Core's GCSFilter does, rather than the 64-bit SipHash. The two
disagree only when two distinct scripts in one block collide on 64 bits
(~2^-40 per block), so the change cannot be shown by constructing that case.

What CAN be shown -- and is what "in consensus with Core" means operationally
-- is that our filter is byte-identical to Core's over a wide span of real
blocks. This asks the ORACLE for both the block (verbosity 3, so the spent
prevout scripts come with it) and Core's own `getblockfilter`, builds the
filter with our code, and diffs.

MANUAL, like the other validation/*_diff.py tools: it needs the oracle and is
too slow for the gate. The gate carries the frozen Core KATs in
asm/tests/test_block_filter.c and the element-set semantics tests beside them.

    python3 validation/blockfilter_diff.py [height ...]
"""
import json, os, subprocess, sys

CONF    = "/storage/core-oracle/bitcoin.conf"
DATADIR = "/storage/core-oracle"
CLI     = "/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli"
HERE    = os.path.dirname(os.path.abspath(__file__))
SHIM    = os.path.join(HERE, "..", "asm", "tests", "bfilter_shim")

DEFAULT_HEIGHTS = [1, 170, 100_000, 250_000, 481_824, 500_000,
                   600_000, 700_038, 709_632, 800_000, 900_000]

def cli(*args):
    r = subprocess.run([CLI, f"-conf={CONF}", f"-datadir={DATADIR}", *args],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"bitcoin-cli {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout.strip()

def our_filter(blockhash, blockhex, prevouts):
    """Drive the shim. A BINARY, not a dlopen: this tree's asm is
    non-relocatable (-no-pie), so there is no shared object to load."""
    payload = [blockhash, blockhex, str(len(prevouts))] + [p.hex() for p in prevouts]
    r = subprocess.run([SHIM], input="\n".join(payload) + "\n",
                       capture_output=True, text=True)
    out = r.stdout.strip()
    if r.returncode != 0 or out.startswith("ERR"):
        return None, (out or r.stderr.strip() or f"shim exit {r.returncode}")
    return out, None

def main():
    heights = [int(a) for a in sys.argv[1:]] or DEFAULT_HEIGHTS
    if not os.path.exists(SHIM):
        sys.exit("build the shim first:  make -C asm tests/bfilter_shim")

    tip = int(cli("getblockcount"))
    bad = skipped = 0
    for h in heights:
        if h > tip:
            print(f"  {h:>8}  SKIP (above oracle tip {tip})"); skipped += 1; continue
        bh   = cli("getblockhash", str(h))
        blk  = cli("getblock", bh, "0")
        want = json.loads(cli("getblockfilter", bh, "basic"))["filter"]

        # spent prevout scripts, in block order, from Core's own verbosity 3
        v3 = json.loads(cli("getblock", bh, "3"))
        prevs = []
        for tx in v3["tx"][1:]:                      # the coinbase spends nothing
            for vin in tx.get("vin", []):
                po = vin.get("prevout")
                if po and "scriptPubKey" in po:
                    prevs.append(bytes.fromhex(po["scriptPubKey"]["hex"]))

        got, err = our_filter(bh, blk, prevs)
        if err:
            print(f"  {h:>8}  ERROR  {err}"); bad += 1; continue
        ok = (got == want)
        if not ok: bad += 1
        print(f"  {h:>8}  {'OK  ' if ok else 'DIFF'}  {len(prevs):>6} prevouts   "
              f"ours={len(got)//2}B core={len(want)//2}B{'' if ok else '   <-- MISMATCH'}")
    print(f"\n{len(heights) - skipped} height(s) compared, {bad} mismatch(es)")
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
