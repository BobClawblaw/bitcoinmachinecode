#!/usr/bin/env python3
"""Fetch real mainnet blocks from the scratch Core oracle as raw .bin fixtures
for tests/test_witness_commitment.c.

The test always runs against the ONE committed fixture
(tests/fixtures/blk_witness_small.bin, block 0000...ee137e5e, 1563 bytes, a
segwit-era block small enough to keep in git), genesis (from constants) and
the regtest block in tests/block_vec.h. The ~1 MB mainnet blocks below are
optional and gitignored: when present the test runs the same checks on them,
when absent it reports SKIP for those cases only (never a silent pass).

Usage (oracle must be up; see memory/project_core_oracle):
    python3 validation/fetch_witness_blocks.py            # 481823 481824 600000
    python3 validation/fetch_witness_blocks.py 481824 500000 ...

Blocks:
  481823  last pre-activation block; its coinbase already carries a
          commitment but (necessarily) no witness -- evaluated as-if-active
          it must fail bad-witness-nonce-size, Core's check order.
  481824  first block with segwit active; coinbase commits, many witness txs.
          Stripping its witnesses yields byte-for-byte what the archive held
          until 2026-08-22 -- the regression case.
  600000  deep in the segwit era.
"""
import subprocess, sys, os, hashlib

CLI = ["/storage/bitcoin-core-source/build/bin/bitcoin-cli",
       "-conf=/storage/core-oracle/bitcoin.conf", "-datadir=/storage/core-oracle"]
OUT = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures")

def rpc(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True)
    if r.returncode: sys.exit("rpc %s failed: %s" % (a, r.stderr.strip()))
    return r.stdout.strip()

def main():
    heights = [int(h) for h in sys.argv[1:]] or [481823, 481824, 600000]
    os.makedirs(OUT, exist_ok=True)
    for h in heights:
        hh = rpc("getblockhash", str(h))
        raw = bytes.fromhex(rpc("getblock", hh, "0"))
        got = hashlib.sha256(hashlib.sha256(raw[:80]).digest()).digest()[::-1].hex()
        assert got == hh, "hash mismatch for %d" % h
        p = os.path.join(OUT, "blk_%d.bin" % h)
        open(p, "wb").write(raw)
        print("%s  %d bytes  %s" % (p, len(raw), hh))

if __name__ == "__main__":
    main()
