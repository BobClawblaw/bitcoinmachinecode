#!/usr/bin/env python3
"""diff_bip143_corpus.py -- prove that a change to bitcoin_segwit.c does not
move a single BIP143 sighash, over a LARGE corpus of REAL mainnet
transactions, against Bitcoin Core.

This is the equivalence half that any performance change to the segwit sighash
path owes. tests/segwit_txout_vec.h carries 120 baked vectors because a header
has to stay a sane size; this pulls thousands, on demand, and does not bake
anything.

What it does:
  1. Pulls real transactions off the Core oracle across the whole segwit era
     (heights 481,824 -> tip), preferring the ones with the most inputs and
     the most outputs in each sampled block, since those are where the
     aggregate-hash loops actually work.
  2. Expands each into vectors: three input indices x six hashtypes
     (ALL, NONE, SINGLE, and each with ANYONECANPAY). The amount and the
     scriptCode are FIXED -- what is under test is the sighash over a real
     transaction's STRUCTURE, and Core is asked the identical question.
  3. Asks Bitcoin Core for every expected sighash via
     validation/core_verify_oracle.cpp's BIP143 command, which runs Core's own
     SignatureHash(..., SigVersion::WITNESS_V0). The oracle is self-checked
     against BIP-0143's published worked example before any answer is used.
  4. Compiles validation/bip143_corpus_dump.c against each bitcoin_segwit.c it
     was given (typically: the working tree, and `git show <ref>:...` of the
     baseline) and diffs the two outputs against each other AND against Core.

Ground truth is Core. Our own previous answer is never the standard --
"identical to before" only means something once "identical to Core" holds.

Build the oracle first (from the repo root):
  SRC=/storage/bitcoin-core-source; B=$SRC/build
  g++ -std=c++20 -O1 -I$SRC/src -I$B/src -I$SRC/src/univalue/include \
      -o /tmp/core_verify_oracle validation/core_verify_oracle.cpp \
      -Wl,--start-group $B/lib/libbitcoin_common.a $B/lib/libbitcoin_consensus.a \
      $B/lib/libbitcoin_crypto.a $B/lib/libbitcoin_util.a \
      $B/lib/libbitcoin_clientversion.a $B/src/univalue/libunivalue.a \
      $B/src/secp256k1/lib/libsecp256k1.a -Wl,--end-group

Usage (from asm/):
  python3 validation/diff_bip143_corpus.py --baseline main
  python3 validation/diff_bip143_corpus.py --baseline main --step 6000
  python3 validation/diff_bip143_corpus.py --oracle /tmp/core_verify_oracle
"""
import argparse, json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ASM = os.path.dirname(HERE)
CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli "
       "-rpcport=8335 -datadir=/storage/core-oracle").split()

SC = "76a914" + "".join("%02x" % i for i in range(20)) + "88ac"
AMT = 123456789
HASHTYPES = [(1, "all"), (2, "none"), (3, "single"),
             (0x81, "all_acp"), (0x82, "none_acp"), (0x83, "single_acp")]

# The objects bitcoin_segwit.c needs at link time (same set the Makefile's
# SEGWITOBJS uses, minus the taproot/interp half the dumper never reaches).
LINK = ("sha256.o bitcoin_hash.o ripemd160.o bitcoin_addr.o bitcoin_script.o "
        "bitcoin_sighash.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o "
        "secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o "
        "secp256k1_scalar.o secp256k1_scalar_c.o").split()


def rpc(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("rpc failed: %s: %s" % (a, r.stderr.strip()))
    return r.stdout.strip()


def build_corpus(lo, hi, step, maxbytes):
    """(name, n_in, hashtype, amount, tx_hex, sc_hex) for real mainnet txs."""
    heights = sorted(set(list(range(lo, hi, step)) +
                         [481824, 481827, 482566, 508008, 927500, 952325]))
    out, ntx = [], 0
    for h in heights:
        try:
            blk = json.loads(rpc("getblock", rpc("getblockhash", str(h)), "2"))
        except SystemExit:
            continue
        txs = [t for t in blk["tx"][1:]
               if any("txinwitness" in v for v in t["vin"])]
        if not txs:
            continue
        cand, seen = [], set()
        for t in (sorted(txs, key=lambda x: -len(x["vin"]))[:2] +
                  sorted(txs, key=lambda x: -len(x["vout"]))[:2] + txs[:3]):
            if t["txid"] not in seen:
                seen.add(t["txid"]); cand.append(t)
        for t in cand:
            if len(t["hex"]) // 2 > maxbytes:
                continue
            ntx += 1
            nin = len(t["vin"])
            for n_in in sorted(set([0, nin // 2, nin - 1])):
                for (ht, htn) in HASHTYPES:
                    out.append(("real_%d_%s_i%d_%s" % (h, t["txid"][:12], n_in, htn),
                                n_in, ht, AMT, t["hex"], SC))
    return ntx, out


def core_answers(oracle, corpus):
    lines = ["BIP143 %d %d %d %s %s" % (n, ht, amt, tx, sc)
             for (_, n, ht, amt, tx, sc) in corpus] + ["QUIT"]
    p = subprocess.run([oracle], input="\n".join(lines) + "\n",
                       capture_output=True, text=True)
    res = [l for l in p.stdout.splitlines() if l.startswith(("OK ", "ERR "))]
    if len(res) != len(corpus):
        sys.exit("oracle returned %d lines for %d vectors\n%s"
                 % (len(res), len(corpus), p.stderr[-2000:]))
    for l in res:
        if not l.startswith("OK "):
            sys.exit("oracle refused a vector: %s" % l)
    return [l.split()[1] for l in res]


DOC_TX = ("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
          "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57"
          "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85"
          "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2"
          "f0167faa815988ac11000000")
DOC_SC = "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"
DOC_EXPECT = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"


def build_dumper(segwit_c, out_bin, tmp):
    cmd = (["gcc", "-no-pie", "-O2", "-w", "-I", ASM, "-o", out_bin,
            os.path.join(HERE, "bip143_corpus_dump.c"), segwit_c] +
           [os.path.join(ASM, o) for o in LINK])
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=ASM)
    if r.returncode != 0:
        sys.exit("build failed for %s:\n%s" % (segwit_c, r.stderr[-4000:]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", default="/tmp/core_verify_oracle")
    ap.add_argument("--baseline", default=None,
                    help="git ref whose asm/bitcoin_segwit.c is the 'before' "
                         "build; omit to check the working tree against Core only")
    ap.add_argument("--lo", type=int, default=481824)
    ap.add_argument("--hi", type=int, default=0, help="0 = the oracle's tip")
    ap.add_argument("--step", type=int, default=12000)
    ap.add_argument("--maxbytes", type=int, default=200000)
    a = ap.parse_args()
    if not os.path.exists(a.oracle):
        sys.exit("core_verify_oracle not built at %s -- see this file's header"
                 % a.oracle)
    if core_answers(a.oracle, [("doc", 1, 1, 600000000, DOC_TX, DOC_SC)])[0] != DOC_EXPECT:
        sys.exit("oracle self-check FAILED against BIP-0143's worked example")
    hi = a.hi or int(rpc("getblockcount"))

    ntx, corpus = build_corpus(a.lo, hi, a.step, a.maxbytes)
    print("corpus: %d real mainnet transactions, %d vectors, heights %d..%d"
          % (ntx, len(corpus), a.lo, hi))
    want = core_answers(a.oracle, corpus)

    tmp = tempfile.mkdtemp(prefix="bip143diff.")
    cpath = os.path.join(tmp, "corpus.txt")
    with open(cpath, "w") as f:
        for (nm, n, ht, amt, tx, sc) in corpus:
            f.write("%s %d %d %d %s %s\n" % (nm, n, ht, amt, tx, sc))

    builds = [("worktree", os.path.join(ASM, "bitcoin_segwit.c"))]
    if a.baseline:
        base = os.path.join(tmp, "baseline_segwit.c")
        r = subprocess.run(["git", "show", "%s:asm/bitcoin_segwit.c" % a.baseline],
                           capture_output=True, text=True, cwd=ASM)
        if r.returncode != 0:
            sys.exit("git show failed: %s" % r.stderr.strip())
        open(base, "w").write(r.stdout)
        builds.append(("baseline(%s)" % a.baseline, base))

    got = {}
    for (label, src) in builds:
        binp = os.path.join(tmp, "dump_" + label.replace("(", "_").replace(")", ""))
        build_dumper(src, binp, tmp)
        r = subprocess.run([binp, cpath], capture_output=True, text=True)
        got[label] = [l.split("\t")[1] for l in r.stdout.splitlines()]
        if len(got[label]) != len(corpus):
            sys.exit("%s produced %d lines for %d vectors" % (label, len(got[label]), len(corpus)))

    rc = 0
    for (label, _) in builds:
        bad = [i for i in range(len(corpus)) if got[label][i] != want[i]]
        print("%-18s vs Bitcoin Core : %d/%d match%s"
              % (label, len(corpus) - len(bad), len(corpus),
                 "" if not bad else "   <-- MISMATCH"))
        for i in bad[:5]:
            print("    %s: ours %s core %s" % (corpus[i][0], got[label][i], want[i]))
        rc |= 1 if bad else 0
    if len(builds) == 2:
        bad = [i for i in range(len(corpus))
               if got[builds[0][0]][i] != got[builds[1][0]][i]]
        print("worktree vs %-6s     : %d/%d byte-identical%s"
              % (a.baseline, len(corpus) - len(bad), len(corpus),
                 "" if not bad else "   <-- MISMATCH"))
        for i in bad[:5]:
            print("    %s: %s vs %s" % (corpus[i][0], got[builds[0][0]][i],
                                        got[builds[1][0]][i]))
        rc |= 1 if bad else 0
    print("RESULT:", "PASS" if rc == 0 else "FAIL")
    return rc


if __name__ == "__main__":
    sys.exit(main())
