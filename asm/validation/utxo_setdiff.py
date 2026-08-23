#!/usr/bin/env python3
"""utxo_setdiff.py -- when our UTXO set and Core's disagree, find the exact
BLOCK where they first did.

diff_utxo_setinfo.py answers "do they match at height H". This answers the
question that actually matters when they do not: WHICH entries differ. It does
that by bisection on height, which turns a 32-byte disagreement into a single
block number, and then prints that block's contents so the offending coins can
be named.

Why bisection rather than dumping both sets and diffing them: Core can dump
its set (`dumptxoutset ... rollback=H`), but rolling the oracle back is not a
read-only operation, and the oracle is read-only to us. Bisection needs
nothing but `gettxoutsetinfo <type> <height>`, which coinstatsindex answers
instantly at any height. It also localises to a BLOCK rather than to a coin,
which is strictly more useful: a set difference is always caused by a block
being applied differently, and the block is where the fix goes.

Each probe rebuilds our set from genesis to the probe height with
daemon/build_utxo into a scratch datadir, then measures it with
daemon/utxo_setinfo. That is O(height) per probe rather than incremental,
which sounds wasteful and is not: build_utxo replays the first ~200k blocks in
about a minute, and a bisection is ~log2(range) probes.

    # find the first height whose COUNT differs (cheap: no hashing)
    python3 validation/utxo_setdiff.py --lo 0 --hi 200000 --field txouts

    # then the first whose CONTENTS differ (the count can agree while the
    # contents do not -- that is exactly what a set hash is for)
    python3 validation/utxo_setdiff.py --lo 0 --hi 200000 --field muhash

SAFETY: the scratch datadir gets a COPY of index.dat (build_utxo's store_init
opens it O_RDWR) and SYMLINKS to the block files (the read path opens those
O_RDONLY). The archive's own stat is captured before and after and any change
is reported as a failure -- ENGINEERING_RULES.md 3: a tool that touches real
data gets proven not to, it does not get assumed not to.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ASM = os.path.dirname(HERE)
DEFAULT_CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli "
               "-rpcport=8335 -datadir=/storage/core-oracle").split()
DEFAULT_ARCHIVE = "/storage/bitcoinmachinecode/data"


def archive_stat(archive):
    out = {}
    for name in sorted(os.listdir(archive)):
        if not (name.startswith("blk") and name.endswith(".dat")) and name != "index.dat":
            continue
        st = os.stat(os.path.join(archive, name))
        out[name] = (st.st_ino, st.st_size, st.st_mtime_ns)
    return out


def prepare(scratch, archive):
    if os.path.exists(scratch):
        shutil.rmtree(scratch)
    os.makedirs(scratch)
    shutil.copy2(os.path.join(archive, "index.dat"), os.path.join(scratch, "index.dat"))
    for name in os.listdir(archive):
        if name.startswith("blk") and name.endswith(".dat"):
            os.symlink(os.path.join(archive, name), os.path.join(scratch, name))


def build_and_measure(args, height, want_muhash):
    prepare(args.scratch, args.archive)
    r = subprocess.run([os.path.join(ASM, "daemon", "build_utxo"), args.scratch,
                        str(args.slots_log2), str(args.blob_gb), "0", str(height)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("utxo_setdiff: build_utxo failed at height %d:\n%s" % (height, r.stderr[-2000:]))
    for line in r.stderr.splitlines():
        if "WARNING: hole" in line or "CORRUPT" in line and "bad_hash=0" not in line:
            print("  !! %s" % line.strip())

    cmd = [os.path.join(ASM, "daemon", "utxo_setinfo"), args.scratch,
           "--height", str(height), "--settle-ms", "150",
           "--exclude-genesis-coinbase"]
    if want_muhash:
        cmd.append("--muhash")
    m = subprocess.run(cmd, capture_output=True, text=True)
    if not m.stdout.strip():
        sys.exit("utxo_setdiff: utxo_setinfo produced nothing at %d:\n%s" % (height, m.stderr))
    return json.loads(m.stdout)


def core_at(cli, height, want_muhash):
    r = subprocess.run(cli + ["gettxoutsetinfo", "muhash" if want_muhash else "none",
                              str(height)], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("utxo_setdiff: oracle refused at height %d:\n%s" % (height, r.stderr.strip()))
    return json.loads(r.stdout)


def agrees(args, height, field):
    want_muhash = (field == "muhash")
    mine = build_and_measure(args, height, want_muhash)
    theirs = core_at(args.cli, height, want_muhash)
    if field == "txouts":
        a, b = mine["txouts"], theirs["txouts"]
    elif field == "bogosize":
        a, b = mine["bogosize"], theirs["bogosize"]
    elif field == "total_amount":
        a, b = mine["total_amount_sat"], int(round(float(theirs["total_amount"]) * 1e8))
    elif field == "muhash":
        a, b = mine["muhash"], theirs["muhash"]
    else:
        sys.exit("utxo_setdiff: unknown field %r" % field)
    same = (a == b)
    extra = ""
    if not same and field != "muhash":
        extra = "  (delta %+d)" % (a - b)
    print("  h=%-8d %-13s ours=%-22s core=%-22s %s%s"
          % (height, field, a, b, "MATCH" if same else "DIFFER", extra))
    return same, mine, theirs


def describe_block(cli, height):
    h = subprocess.run(cli + ["getblockhash", str(height)], capture_output=True, text=True)
    if h.returncode != 0:
        return
    bh = h.stdout.strip()
    b = subprocess.run(cli + ["getblock", bh, "2"], capture_output=True, text=True)
    if b.returncode != 0:
        return
    blk = json.loads(b.stdout)
    print("\nBlock %d  %s" % (height, bh))
    print("  ntx=%d  time=%s" % (len(blk["tx"]), blk.get("time")))
    cb = blk["tx"][0]
    print("  coinbase txid : %s" % cb["txid"])
    for i, o in enumerate(cb["vout"]):
        spk = o["scriptPubKey"]
        print("    vout[%d] %.8f BTC  type=%s  len=%d"
              % (i, o["value"], spk.get("type"), len(spk.get("hex", "")) // 2))
    print("  (a duplicate coinbase txid here means BIP30: Core OVERWRITES the earlier")
    print("   coin, so its chainstate keeps the LATER height; utxo_lsm_put returns")
    print("   'duplicate' and keeps the EARLIER one. Same txid, index, value and")
    print("   script -- so count, amount and bogosize are all blind to it, and only")
    print("   the set hash can see it.)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lo", type=int, default=0, help="height believed to AGREE")
    ap.add_argument("--hi", type=int, required=True, help="height known to DIFFER")
    ap.add_argument("--field", default="muhash",
                    choices=["txouts", "total_amount", "bogosize", "muhash"])
    ap.add_argument("--scratch", default="/storage/bmc-setinfo-scratch/bisect")
    ap.add_argument("--archive", default=DEFAULT_ARCHIVE)
    ap.add_argument("--slots-log2", type=int, default=22)
    ap.add_argument("--blob-gb", type=float, default=1.0)
    ap.add_argument("--cli", default=None)
    args = ap.parse_args()
    args.cli = args.cli.split() if args.cli else DEFAULT_CLI

    before = archive_stat(args.archive)

    print("bisecting first %s divergence in [%d, %d]" % (args.field, args.lo, args.hi))
    ok_lo, _, _ = agrees(args, args.lo, args.field)
    if not ok_lo:
        print("\n--lo %d ALREADY differs -- lower the bracket." % args.lo)
        describe_block(args.cli, args.lo)
        return 1
    ok_hi, _, _ = agrees(args, args.hi, args.field)
    if ok_hi:
        print("\n--hi %d AGREES -- there is no divergence in this range." % args.hi)
        return 0

    lo, hi = args.lo, args.hi
    while hi - lo > 1:
        mid = (lo + hi) // 2
        ok, _, _ = agrees(args, mid, args.field)
        if ok:
            lo = mid
        else:
            hi = mid

    print("\nFIRST DIVERGENCE: applying block %d makes our %s differ from Core's."
          % (hi, args.field))
    print("  height %d still agrees." % lo)
    describe_block(args.cli, hi)

    after = archive_stat(args.archive)
    if before != after:
        changed = [k for k in before if before.get(k) != after.get(k)]
        print("\n!! THE BLOCK ARCHIVE CHANGED during this run: %s" % changed[:8])
        print("!! That must not happen -- this tool only reads it. Investigate.")
        return 2
    print("\n(block archive verified unchanged: %d files, identical inode/size/mtime)"
          % len(before))
    return 1


if __name__ == "__main__":
    sys.exit(main())
