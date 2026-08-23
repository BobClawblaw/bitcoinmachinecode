#!/usr/bin/env python3
"""fetch_taproot_blocks.py HEIGHT... -- fixtures for tests/test_taproot_block_diff.

For each height, writes

    tests/fixtures/blk_<H>.bin        raw block bytes
    tests/fixtures/blk_<H>.prevouts   one line per non-coinbase input:
                                      txid_hex index value_sat spk_hex

Both come from the SCRATCH Core oracle (/storage/core-oracle), never from the
production install at /storage/bitcoin and never from this project's own
archive:

  * the archive is witness-stripped for every block at or above 481,824
    (recorded 2026-08-22), so a taproot block read from it would carry no
    signatures at all -- the differential would be measuring nothing;
  * the whole point of the differential is that Bitcoin Core, not our own
    previous answer, is ground truth. Reading the block from the same place
    that produced our last verdict would defeat it.

`getblock <hash> 3` inlines every input's prevout (amount + scriptPubKey), so
one RPC per block replaces one getrawtransaction per distinct funding tx.
Verbosity 3 needs Core's txindex, which the oracle has.

The fixtures are large and gitignored; the test SKIPs when they are absent.

Usage:
    python3 validation/fetch_taproot_blocks.py 825000 825001 840000 870000
"""
import sys, os, json, subprocess

CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli"
       " -conf=/storage/core-oracle/bitcoin.conf"
       " -datadir=/storage/core-oracle").split()


def rpc(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("rpc failed: %s: %s" % (a, r.stderr.strip()))
    return r.stdout.strip()


def sat(v):
    """BTC float -> satoshis. Core prints 8 decimals; float64 carries 53 bits,
    so 21e14 satoshis round-trips exactly. A silent error here would show up
    as a taproot FALSE REJECT (the amount is committed in the BIP341
    sighash), not as a silent accept."""
    return int(round(float(v) * 1e8))


here = os.path.dirname(os.path.abspath(__file__))
fx = os.path.join(here, '..', 'tests', 'fixtures')
os.makedirs(fx, exist_ok=True)

for H in [int(x) for x in sys.argv[1:]]:
    bh = rpc("getblockhash", str(H))
    raw = rpc("getblock", bh, "0")
    blk = bytes.fromhex(raw)
    with open(os.path.join(fx, 'blk_%d.bin' % H), 'wb') as f:
        f.write(blk)
    b = json.loads(rpc("getblock", bh, "3"))
    n = 0
    ntap = 0
    with open(os.path.join(fx, 'blk_%d.prevouts' % H), 'w') as out:
        for tx in b['tx'][1:]:
            for v in tx['vin']:
                po = v['prevout']
                spk = po['scriptPubKey']
                out.write("%s %d %d %s\n" % (v['txid'], v['vout'],
                                             sat(po['value']), spk['hex']))
                n += 1
                if spk.get('type') == 'witness_v1_taproot':
                    ntap += 1
    print("block %d %s: %d bytes, %d tx, %d prevouts, %d taproot inputs"
          % (H, bh, len(blk), len(b['tx']) - 1, n, ntap))
