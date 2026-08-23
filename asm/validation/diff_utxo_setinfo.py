#!/usr/bin/env python3
"""diff_utxo_setinfo.py -- prove our UTXO set IS Bitcoin Core's, at a stated
height, by asking a real Core node and diffing field by field.

This is the harness that turns Stage D's acceptance test from "no block was
rejected" into "the UTXO set is provably identical to Core's". ASSESSMENT.md
section 4 is the argument for why that matters: a clean full-chain replay
would NOT have proven consensus correctness -- it proves the node accepts what
the chain contains, and says nothing about what it would accept that Core
rejects. A set hash is the one check that compares STATE rather than verdicts.

Ground truth is a live Core node, queried on demand. Nothing here is baked.

    python3 validation/diff_utxo_setinfo.py --dir /path/to/datadir
    python3 validation/diff_utxo_setinfo.py --dir ... --height 200000 --no-muhash

What it compares, in the order the stages were designed to be verified:

  1. txouts        -- cardinality. Proves the unspendable filter is exactly
                      Core's, with no crypto involved. Our storage holds every
                      output including provably-unspendable ones; the tool
                      filters them at read time, so this number is the first
                      thing that can be wrong and the easiest to diagnose.
  2. total_amount  -- value accounting. Catches a whole class of per-entry
                      bugs the count cannot.
  3. bogosize      -- Core's database-independent size metric,
                      32+4+4+8+2+len(scriptPubKey) summed. Free, and it can
                      only match if every surviving entry's script LENGTH
                      matches -- a much sharper check than the count for the
                      same cost, and it sits between the count and the hash.
  4. muhash        -- contents. The actual goal.

WHY muhash AND NOT hash_serialized_3: Core REFUSES
`gettxoutsetinfo hash_serialized_3 <height>` ("hash type cannot be queried for
a specific block") -- only muhash is answerable at an arbitrary height,
because only muhash is what coinstatsindex stores. Our node is never at the
oracle's tip, so hash_serialized_3 would have had no ground truth at all.
MuHash is also order-independent, which matters here: see bitcoin_muhash.asm's
header for the ordering analysis that rules hash_serialized_3 out on a second,
independent ground.

KNOWN, EXPECTED DELTAS -- reported, never silently absorbed:
  * genesis coinbase. Core never writes it to the chainstate. daemon/
    utxo_live.c excludes it for exactly this reason; daemon/build_utxo.c does
    NOT, so a set built by build_utxo carries one extra 50 BTC entry.
  * BIP30 duplicate coinbases (heights 91,722 / 91,812 / 91,842 / 91,880).
    Core's later block OVERWRITES the earlier coin, so its chainstate holds
    the LATER coin -- same txid, same index, same value, same script, but a
    different HEIGHT. Our utxo_lsm_put returns "duplicate" and keeps the
    EARLIER one. Count, amount and bogosize are all blind to this; only the
    hash sees it, because height is part of what Core serializes.
--known-genesis makes the tool EXCLUDE the genesis coinbase, so all four
fields are computed over the same set rather than three of them being
arithmetically adjusted and the hash left alone. --explain-bip30 re-hashes the
two duplicated outpoints with the heights Core's overwrite gives them: if the
hash then matches, that was the whole difference, and if it does not, the
hypothesis is wrong. Either flag makes the RESULT line say "identical ONLY
AFTER N documented adjustment(s)" and return non-zero -- a set that needs an
adjustment to agree is a set that does not agree.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ASM = os.path.dirname(HERE)
DEFAULT_CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli "
               "-rpcport=8335 -datadir=/storage/core-oracle").split()

BIP30_HEIGHTS = (91722, 91812, 91842, 91880)


def run(cmd, **kw):
    p = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return p


# The two BIP30 duplicate coinbases, with the heights CORE's chainstate holds
# (the LATER block's, because Core's exception path overwrites). Ours keep the
# earlier heights. Applying these is a HYPOTHESIS TEST, never a fix.
BIP30_COINS = [
    ("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468", 0, 91880),
    ("d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599", 0, 91842),
]


def ours(tool, datadir, want_muhash, settle_ms, force, height,
         excl_genesis=False, overrides=()):
    cmd = [tool, datadir, "--settle-ms", str(settle_ms)]
    if want_muhash:
        cmd.append("--muhash")
    if force:
        cmd.append("--force")
    if excl_genesis:
        cmd.append("--exclude-genesis-coinbase")
    for txid, n, h in overrides:
        cmd += ["--override-coin", "%s:%d=%d" % (txid, n, h)]
    if height is not None:
        cmd += ["--height", str(height)]
    p = run(cmd)
    if p.stderr.strip():
        sys.stderr.write(p.stderr)
    if not p.stdout.strip():
        sys.exit("diff_utxo_setinfo: %s produced no output (exit %d)" % (tool, p.returncode))
    try:
        j = json.loads(p.stdout)
    except json.JSONDecodeError:
        sys.stderr.write(p.stdout)
        sys.exit("diff_utxo_setinfo: could not parse tool output as JSON")
    j["_exit"] = p.returncode
    return j


def core(cli, hash_type, height):
    p = run(cli + ["gettxoutsetinfo", hash_type, str(height)])
    if p.returncode != 0:
        sys.exit("diff_utxo_setinfo: oracle refused `gettxoutsetinfo %s %d`:\n%s"
                 % (hash_type, height, p.stderr.strip()))
    return json.loads(p.stdout)


def btc_to_sat(x):
    # Core reports total_amount as a JSON number of BTC. Going through the
    # decimal string keeps this exact rather than trusting float rounding at
    # 21e14 satoshis.
    return int(round(float(x) * 1e8))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="our datadir (must be QUIESCED)")
    ap.add_argument("--tool", default=os.path.join(ASM, "daemon", "utxo_setinfo"))
    ap.add_argument("--cli", default=None, help="bitcoin-cli invocation (quoted)")
    ap.add_argument("--height", type=int, default=None,
                    help="height to compare at; default is the datadir's applied height")
    ap.add_argument("--no-muhash", action="store_true",
                    help="stages 1-3 only (count/amount/bogosize), skipping the hash")
    ap.add_argument("--settle-ms", type=int, default=1500)
    ap.add_argument("--force", action="store_true",
                    help="read a datadir that is being written; results are NOT comparable")
    ap.add_argument("--known-genesis", action="store_true",
                    help="exclude the genesis coinbase, which Core's chainstate never "
                         "holds and daemon/build_utxo.c keeps; applies to ALL four "
                         "fields including the hash, so they stay mutually consistent")
    ap.add_argument("--explain-bip30", action="store_true",
                    help="HYPOTHESIS TEST: re-hash the two BIP30 duplicate coinbases "
                         "with the heights Core's overwrite semantics give them. If "
                         "the hash then matches, that WAS the whole difference. This "
                         "does not make our set correct; it says exactly how it is "
                         "wrong.")
    args = ap.parse_args()

    cli = args.cli.split() if args.cli else DEFAULT_CLI
    if not os.path.exists(args.tool):
        sys.exit("diff_utxo_setinfo: %s not built (make daemon/utxo_setinfo)" % args.tool)

    overrides = BIP30_COINS if args.explain_bip30 else ()
    mine = ours(args.tool, args.dir, not args.no_muhash, args.settle_ms, args.force,
                args.height, excl_genesis=args.known_genesis, overrides=overrides)
    height = args.height if args.height is not None else mine["height"]
    if height is None or height < 0:
        sys.exit("diff_utxo_setinfo: no height (pass --height, or point at a datadir "
                 "with utxo_applied_height.dat)")

    if not mine.get("quiesced", False):
        print("!! our datadir was NOT quiesced -- these numbers are a mixture of states")
    if not mine.get("consistent", False):
        print("!! our tool reported an internal inconsistency -- see its stderr above")

    theirs = core(cli, "muhash" if not args.no_muhash else "none", height)
    if theirs["height"] != height:
        sys.exit("diff_utxo_setinfo: oracle answered for height %d, asked %d"
                 % (theirs["height"], height))

    core_txouts = theirs["txouts"]
    core_amt = btc_to_sat(theirs["total_amount"])
    core_bogo = theirs["bogosize"]

    adj_txouts = mine["txouts"]
    adj_amt = mine["total_amount_sat"]
    adj_bogo = mine["bogosize"]
    notes = []
    adjusted = 0
    if args.known_genesis:
        adjusted += 1
        notes.append("--known-genesis: the tool excluded the genesis coinbase "
                     "(genesis_excluded=%s). Core never writes it to the chainstate; "
                     "daemon/utxo_live.c excludes it, daemon/build_utxo.c does not."
                     % mine.get("genesis_excluded"))
    if args.explain_bip30:
        adjusted += 1
        n = sum(1 for h in BIP30_HEIGHTS if h <= height)
        notes.append("--explain-bip30: %d of the 4 BIP30 heights are in range; the tool "
                     "re-hashed %d outpoint(s) with Core's post-overwrite heights. This "
                     "is a HYPOTHESIS TEST, not a fix -- our stored set still holds the "
                     "earlier heights." % (n, mine.get("coin_overrides", 0)))

    print("=" * 78)
    print("UTXO set comparison at height %d" % height)
    print("  ours   : %s" % os.path.abspath(args.dir))
    print("  theirs : %s" % " ".join(cli))
    print("  block  : %s" % theirs["bestblock"])
    print("=" * 78)

    rows = [
        ("1. txouts", adj_txouts, core_txouts),
        ("2. total_amount (sat)", adj_amt, core_amt),
        ("3. bogosize", adj_bogo, core_bogo),
    ]
    bad = 0
    for name, got, want in rows:
        delta = got - want
        flag = "MATCH" if delta == 0 else "DIFFER"
        if delta:
            bad += 1
        print("%-24s ours %20d   core %20d   delta %+d   %s"
              % (name, got, want, delta, flag))

    if not args.no_muhash:
        got = mine["muhash"]
        want = theirs["muhash"]
        same = got == want
        if not same:
            bad += 1
        print("%-24s ours %s" % ("4. muhash", got))
        print("%-24s core %s   %s" % ("", want, "MATCH" if same else "DIFFER"))

    print("-" * 78)
    print("our raw (unfiltered) live entries : %d" % mine["raw_txouts"])
    print("filtered out as unspendable       : %d  (%.8f BTC)"
          % (mine["unspendable_txouts"], mine["unspendable_amount_sat"] / 1e8))
    print("our runs in manifest              : %d" % mine.get("manifest_runs", -1))
    for n in notes:
        print("note: %s" % n)

    if bad == 0:
        if adjusted:
            print("\nRESULT: identical at height %d ONLY AFTER %d documented adjustment(s)"
                  % (height, adjusted))
            print("        (see the notes above). Our stored set is NOT identical to Core's;")
            print("        the adjustments say precisely how it differs.")
            return 1
        print("\nRESULT: IDENTICAL at height %d." % height)
        return 0
    print("\nRESULT: %d field(s) DIFFER at height %d." % (bad, height))
    print("A mismatch reported honestly is a better outcome than a matching number")
    print("obtained by adjusting the filter until it agrees. The interesting question")
    print("now is WHICH entries differ -- see validation/utxo_setdiff.py.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
