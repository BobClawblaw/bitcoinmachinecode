#!/usr/bin/env python3
"""diff_bip341_corpus.py -- prove that a change to bitcoin_taproot_sighash.c
does not move a single BIP341 sighash, over a LARGE corpus of REAL mainnet
taproot transactions, against Bitcoin Core.

The taproot counterpart of validation/diff_bip143_corpus.py, and it exists for
the same reason: tests/taproot_vec.h carries the seven official BIP-341
wallet-test-vectors because a header has to stay a sane size, and seven
hand-built two-input transactions do not exercise an O(n^2). This pulls
thousands of vectors off real chain data, on demand, and bakes nothing.

What it does:
  1. Pulls real mainnet transactions with at least one P2TR input, from
     heights 709,632 (taproot activation) upward, via `getblock <hash> 3` --
     verbosity 3 because BIP341 commits to EVERY spent output's amount and
     scriptPubKey, and verbosity 3 is the only call that returns them for a
     whole block in one request. Prefers the transactions with the most
     inputs and the most outputs in each sampled block, since that is where
     the aggregate-hash loops actually do work.
  2. Expands each into vectors: three input indices x seven hash types
     (DEFAULT/ALL/NONE/SINGLE and ALL/NONE/SINGLE with ANYONECANPAY) x
     key-path and script-path (ext_flag 0 and 1), plus annex variants.
  3. Asks Bitcoin Core for every expected sighash via
     validation/core_verify_oracle.cpp's BIP341 command, which runs Core's own
     SignatureHashSchnorr. The oracle is self-checked against all seven
     published BIP-341 vectors (tests/taproot_spend.json) before any answer is
     used -- if that self-check fails, nothing else runs.
  4. Compiles validation/bip341_corpus_dump.c against each
     bitcoin_taproot_sighash.c it was given (typically: the working tree, and
     `git show <ref>:...` of the baseline) and diffs the two outputs against
     each other AND against Core.

Ground truth is Core. Our own previous answer is never the standard --
"identical to before" only means something once "identical to Core" holds.

Build the oracle first (from the repo root):
  SRC=/storage/bitcoin-core-source; B=$SRC/build
  cd $B && g++ -std=c++20 -I../src -I./src -I../src/univalue/include \
      -o /tmp/core_verify_oracle_b341 \
      /storage/bitcoinmachinecode/validation/core_verify_oracle.cpp \
      ./lib/libbitcoin_common.a ./lib/libbitcoin_consensus.a \
      ./lib/libbitcoin_util.a ./lib/libbitcoin_crypto.a \
      ./lib/libbitcoin_clientversion.a ./src/univalue/libunivalue.a \
      ./src/secp256k1/lib/libsecp256k1.a -levent -levent_pthreads

Usage (from asm/):
  python3 validation/diff_bip341_corpus.py --baseline main
  python3 validation/diff_bip341_corpus.py --step 4000 --lo 709632
"""
import argparse, json, os, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ASM = os.path.dirname(HERE)
REPO = os.path.dirname(ASM)
CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli "
       "-rpcport=8335 -datadir=/storage/core-oracle").split()

TAPROOT_ACTIVATION = 709632
# A dummy tapleaf for the script-path (ext_flag=1) vectors. BIP341 commits to
# it verbatim; what it hashes to is irrelevant to the serialization under test,
# and Core is handed the identical 32 bytes.
DUMMY_LEAF = "ab" * 32
DUMMY_ANNEX = "50112233"

# hash_type, name. 0x00 is SIGHASH_DEFAULT (taproot-only; not a BIP143 value).
HASHTYPES = [(0x00, "default"), (0x01, "all"), (0x02, "none"), (0x03, "single"),
             (0x81, "all_acp"), (0x82, "none_acp"), (0x83, "single_acp")]

# INVALID hash types. Core: "if (!(hash_type <= 0x03 || (hash_type >= 0x81 &&
# hash_type <= 0x83))) return false" -- the input is invalid, full stop. These
# are here because the last byte of a 65-byte Schnorr signature IS the hash
# type and is entirely attacker-chosen, so the refusal boundary is as much a
# consensus rule as any hash. 0x80 is included deliberately: it is
# ANYONECANPAY with an output type of 0, which looks plausible and is not.
BAD_HASHTYPES = [(0x04, "bad04"), (0x05, "bad05"), (0x41, "bad41"),
                 (0x80, "bad80"), (0x84, "bad84"), (0xff, "badff")]

# Objects bitcoin_taproot_sighash.c needs at link time (the Makefile's
# SEGWITOBJS set minus bitcoin_segwit.c, which the dumper never reaches).
LINK = ("secp256k1_schnorr.o secp256k1_taproot.o bitcoin_script.o "
        "bitcoin_sighash.o bitcoin_pubkey.o secp256k1_ecdsa.o "
        "secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o "
        "secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o sha256.o "
        "bitcoin_hash.o ripemd160.o bitcoin_addr.o bitcoin_interp.o "
        "bitcoin_scriptcodec.o sha1.o").split()


def rpc(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("rpc failed: %s: %s" % (a, r.stderr.strip()))
    return r.stdout.strip()


# ------------------------------------------------------------- serialization
def cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


class R:
    def __init__(self, b): self.b = b; self.i = 0
    def take(self, n):
        v = self.b[self.i:self.i+n]; self.i += n
        if len(v) != n: raise EOFError
        return v
    def u8(self): return self.take(1)[0]
    def u32(self): return struct.unpack("<I", self.take(4))[0]
    def varint(self):
        n = self.u8()
        if n < 0xfd: return n
        if n == 0xfd: return struct.unpack("<H", self.take(2))[0]
        if n == 0xfe: return struct.unpack("<I", self.take(4))[0]
        return struct.unpack("<Q", self.take(8))[0]


def strip_witness(raw):
    """Raw tx bytes -> (stripped serialization, [36-byte outpoints], nin).

    Independent of asm/bitcoin_segwit.c's strip_witness() on purpose: the
    thing under test must not also be the thing that prepares its own input.
    """
    r = R(raw)
    ver = r.take(4)
    segwit = False
    save = r.i
    if r.b[r.i] == 0x00 and r.b[r.i+1] == 0x01:
        segwit = True; r.i += 2
    else:
        r.i = save
    nin = r.varint()
    ins, outpoints = [], []
    for _ in range(nin):
        op = r.take(36); outpoints.append(op)
        sl = r.varint(); ss = r.take(sl); seq = r.take(4)
        ins.append(op + cs(sl) + ss + seq)
    nout = r.varint()
    outs = []
    for _ in range(nout):
        val = r.take(8); sl = r.varint(); spk = r.take(sl)
        outs.append(val + cs(sl) + spk)
    if segwit:
        for _ in range(nin):
            for _ in range(r.varint()):
                r.take(r.varint())
    lock = r.take(4)
    return ver + cs(nin) + b"".join(ins) + cs(nout) + b"".join(outs) + lock, outpoints, nin


# ------------------------------------------------------------------- corpus
def build_corpus(lo, hi, step, maxbytes, per_block):
    """(name, n_in, ht, ext, csp, annex, leaf, txhex, numin, po, am, sp, prevs)"""
    heights = sorted(set(list(range(max(lo, TAPROOT_ACTIVATION), hi, step)) +
                         [709632, 709635, 750000, 775000, 800000, 850000]))
    out, ntx, nblocks = [], 0, 0
    for h in heights:
        if h < TAPROOT_ACTIVATION or h > hi:
            continue
        try:
            blk = json.loads(rpc("getblock", rpc("getblockhash", str(h)), "3"))
        except SystemExit:
            continue
        nblocks += 1
        # transactions with at least one P2TR input (witness_v1_taproot)
        txs = []
        for t in blk["tx"][1:]:
            if len(t["hex"]) // 2 > maxbytes:
                continue
            if any(v.get("prevout", {}).get("scriptPubKey", {}).get("type")
                   == "witness_v1_taproot" for v in t["vin"] if "prevout" in v):
                txs.append(t)
        if not txs:
            continue
        cand, seen = [], set()
        for t in (sorted(txs, key=lambda x: -len(x["vin"]))[:2] +
                  sorted(txs, key=lambda x: -len(x["vout"]))[:2] + txs[:2]):
            if t["txid"] not in seen:
                seen.add(t["txid"]); cand.append(t)
        for t in cand[:per_block]:
            raw = bytes.fromhex(t["hex"])
            try:
                stripped, outpoints, nin = strip_witness(raw)
            except EOFError:
                continue
            if nin != len(t["vin"]):
                continue
            prevs = []
            ok = True
            for v in t["vin"]:
                pv = v.get("prevout")
                if not pv: ok = False; break
                spk = bytes.fromhex(pv["scriptPubKey"]["hex"])
                # daemon/tx_verify.c refuses a spent scriptPubKey >= 0xfd
                # before it ever calls in here, so the corpus matches that.
                if len(spk) >= 0xfd: ok = False; break
                sats = int(round(float(pv["value"]) * 1e8))
                prevs.append((sats, spk))
            if not ok or len(prevs) != nin:
                continue
            po = b"".join(outpoints).hex()
            am = b"".join(struct.pack("<Q", s) for (s, _) in prevs).hex()
            sp = b"".join(cs(len(k)) + k for (_, k) in prevs).hex()
            txhex = stripped.hex()
            ntx += 1
            for n_in in sorted(set([0, nin // 2, nin - 1])):
                # Invalid hash types: key-path only, one variant each -- the
                # rule is on hash_type alone, so multiplying it by the spend
                # paths would add vectors without adding coverage.
                for (ht, htn) in BAD_HASHTYPES:
                    out.append(("real_%d_%s_i%d_%s_key"
                                % (h, t["txid"][:12], n_in, htn),
                                n_in, ht, 0, 0xffffffff, "-", "-",
                                txhex, nin, po, am, sp, prevs))
                for (ht, htn) in HASHTYPES:
                    for (ext, csp, leaf, anx, en) in (
                            (0, 0xffffffff, "-", "-", "key"),
                            (1, 0xffffffff, DUMMY_LEAF, "-", "script"),
                            (1, 3, DUMMY_LEAF, "-", "script_cs3"),
                            (0, 0xffffffff, "-", DUMMY_ANNEX, "key_annex"),
                            (1, 0xffffffff, DUMMY_LEAF, DUMMY_ANNEX, "script_annex")):
                        out.append(("real_%d_%s_i%d_%s_%s"
                                    % (h, t["txid"][:12], n_in, htn, en),
                                    n_in, ht, ext, csp, anx, leaf,
                                    txhex, nin, po, am, sp, prevs))
    return ntx, nblocks, out


def core_answers(oracle, corpus, chunk=200):
    """Ask Core for every vector. Returns a list of hex strings or 'ERR:<r>'."""
    want = []
    for i in range(0, len(corpus), chunk):
        part = corpus[i:i+chunk]
        lines = []
        for (_, n, ht, ext, csp, anx, leaf, tx, numin, _po, _am, _sp, prevs) in part:
            pv = " ".join("%d %s" % (s, k.hex() if k else "-") for (s, k) in prevs)
            lines.append("BIP341 %d %d %d %d %s %s %s %d %s"
                         % (n, ht, ext, csp, anx, leaf, tx, numin, pv))
        lines.append("QUIT")
        p = subprocess.run([oracle], input="\n".join(lines) + "\n",
                           capture_output=True, text=True)
        res = [l for l in p.stdout.splitlines() if l.startswith(("OK ", "ERR "))]
        if len(res) != len(part):
            sys.exit("oracle returned %d lines for %d vectors\n%s"
                     % (len(res), len(part), p.stderr[-2000:]))
        for l in res:
            want.append(l.split()[1] if l.startswith("OK ") else "ERR:" + l.split()[1])
    return want


# ---------------------------------------------- oracle self-check (BIP-341)
def official_vectors():
    """The seven published BIP-341 wallet-test-vectors, as corpus tuples."""
    j = json.load(open(os.path.join(ASM, "tests", "taproot_spend.json")))
    vecs = []
    for v in j:
        tx = v["tx"]
        ins, outpoints = [], []
        for i in tx["inputs"]:
            op = bytes.fromhex(i["outpoint"]); outpoints.append(op)
            ins.append(op + b"\x00" + struct.pack("<I", i["sequence"]))
        outs = []
        for o in tx["outputs"]:
            s = bytes.fromhex(o["script"])
            outs.append(struct.pack("<Q", o["value"]) + cs(len(s)) + s)
        raw = (struct.pack("<i", tx["version"]) + cs(len(ins)) + b"".join(ins) +
               cs(len(outs)) + b"".join(outs) + struct.pack("<I", tx["locktime"]))
        prevs = [(a, bytes.fromhex(s)) for a, s in zip(tx["amounts"], v["spks"])]
        anx = v.get("annex") or "-"
        leaf = v["leaf"] if v.get("leaf") else "-"
        vecs.append((v["name"], v["index"], v["hash_type"], v["spend_type"],
                     0xffffffff, anx, leaf, raw.hex(), len(ins),
                     b"".join(outpoints).hex(),
                     b"".join(struct.pack("<Q", a) for a, _ in prevs).hex(),
                     b"".join(cs(len(k)) + k for _, k in prevs).hex(),
                     prevs))
    return vecs, [v["sighash"] for v in j]


# ------------------------------------------------------------------ builds
def build_dumper(tap_c, out_bin):
    cmd = (["gcc", "-no-pie", "-O2", "-w", "-I", ASM, "-o", out_bin,
            os.path.join(HERE, "bip341_corpus_dump.c"), tap_c] +
           [os.path.join(ASM, o) for o in LINK])
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=ASM)
    if r.returncode != 0:
        sys.exit("build failed for %s:\n%s" % (tap_c, r.stderr[-4000:]))


def run_dumper(binp, corpus, tmp, label):
    cpath = os.path.join(tmp, "corpus_%s.txt" % label)
    with open(cpath, "w") as f:
        for (nm, n, ht, ext, csp, anx, leaf, tx, numin, po, am, sp, _p) in corpus:
            f.write("%s %d %d %d %d %s %s %s %d %s %s %s\n"
                    % (nm, n, ht, ext, csp, anx, leaf, tx, numin, po, am, sp))
    r = subprocess.run([binp, cpath], capture_output=True, text=True)
    return [l.split("\t")[1] for l in r.stdout.splitlines()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", default="/tmp/core_verify_oracle_b341")
    ap.add_argument("--baseline", default=None,
                    help="git ref whose asm/bitcoin_taproot_sighash.c is the "
                         "'before' build; omit to check the working tree "
                         "against Core only")
    ap.add_argument("--lo", type=int, default=TAPROOT_ACTIVATION)
    ap.add_argument("--hi", type=int, default=0, help="0 = the oracle's tip")
    ap.add_argument("--step", type=int, default=8000)
    ap.add_argument("--maxbytes", type=int, default=200000)
    ap.add_argument("--per-block", type=int, default=4)
    a = ap.parse_args()
    if not os.path.exists(a.oracle):
        sys.exit("oracle not built at %s -- see this file's header" % a.oracle)

    # --- self-check FIRST: an oracle that cannot reproduce the published
    # BIP-341 vectors is not a ground truth and nothing below it means
    # anything.
    off, off_want = official_vectors()
    off_got = core_answers(a.oracle, off)
    bad = [i for i in range(len(off)) if off_got[i] != off_want[i]]
    if bad:
        for i in bad:
            print("  %s: oracle %s  published %s" % (off[i][0], off_got[i], off_want[i]))
        sys.exit("oracle self-check FAILED against the published BIP-341 vectors")
    print("oracle self-check: %d/%d published BIP-341 vectors reproduced"
          % (len(off), len(off)))

    hi = a.hi or int(rpc("getblockcount"))
    ntx, nblocks, corpus = build_corpus(a.lo, hi, a.step, a.maxbytes, a.per_block)
    if not corpus:
        sys.exit("empty corpus")
    print("corpus: %d real mainnet taproot transactions from %d blocks, "
          "%d vectors, heights %d..%d" % (ntx, nblocks, len(corpus), a.lo, hi))
    want = core_answers(a.oracle, corpus)
    nerr = sum(1 for w in want if w.startswith("ERR:"))
    if nerr:
        print("note: Core refused %d vectors (reported separately)" % nerr)

    tmp = tempfile.mkdtemp(prefix="bip341diff.")
    builds = [("worktree", os.path.join(ASM, "bitcoin_taproot_sighash.c"))]
    if a.baseline:
        base = os.path.join(tmp, "baseline_taproot.c")
        r = subprocess.run(["git", "show",
                            "%s:asm/bitcoin_taproot_sighash.c" % a.baseline],
                           capture_output=True, text=True, cwd=ASM)
        if r.returncode != 0:
            sys.exit("git show failed: %s" % r.stderr.strip())
        open(base, "w").write(r.stdout)
        builds.append(("baseline(%s)" % a.baseline, base))

    got = {}
    for (label, src) in builds:
        binp = os.path.join(tmp, "dump_" + label.replace("(", "_").replace(")", ""))
        build_dumper(src, binp)
        got[label] = run_dumper(binp, corpus, tmp, label.replace("(", "_").replace(")", ""))
        if len(got[label]) != len(corpus):
            sys.exit("%s produced %d lines for %d vectors"
                     % (label, len(got[label]), len(corpus)))

    rc = 0
    # Two separate questions, and the second one is not optional. Core
    # REFUSING a vector is itself an answer -- SignatureHashSchnorr returns
    # false for an invalid hash_type and for SIGHASH_SINGLE past the end of
    # the output list, and CheckSchnorrSignature turns that into
    # SCRIPT_ERR_SCHNORR_SIG_HASHTYPE, i.e. the input is invalid. Anything
    # that answers such a vector with a usable sighash is a FALSE ACCEPT, so
    # the refusal boundary is checked as strictly as the hashes are.
    live = [i for i in range(len(corpus)) if not want[i].startswith("ERR:")]
    dead = [i for i in range(len(corpus)) if want[i].startswith("ERR:")]
    for (label, _) in builds:
        bad = [i for i in live if got[label][i] != want[i]]
        print("%-20s vs Bitcoin Core : %d/%d match%s"
              % (label, len(live) - len(bad), len(live),
                 "" if not bad else "   <-- MISMATCH"))
        for i in bad[:5]:
            print("    %s: ours %s core %s" % (corpus[i][0], got[label][i], want[i]))
        rc |= 1 if bad else 0
        if dead:
            fa = [i for i in dead if got[label][i] != "REFUSED"]
            print("%-20s refusals        : %d/%d also refused%s"
                  % (label, len(dead) - len(fa), len(dead),
                     "" if not fa else "   <-- %d FALSE ACCEPTS" % len(fa)))
            for i in fa[:5]:
                print("    %s: core %s, ours %s"
                      % (corpus[i][0], want[i], got[label][i]))
            # Only the worktree's refusal boundary is a pass/fail gate. The
            # baseline is EXPECTED to have false accepts here -- that is the
            # pre-existing divergence this change fixes, and printing it is
            # the point.
            if label == "worktree":
                rc |= 1 if fa else 0
    if len(builds) == 2:
        w, b = builds[0][0], builds[1][0]
        diff = [i for i in range(len(corpus)) if got[w][i] != got[b][i]]
        # A difference is INTENDED exactly when Core refuses the vector, the
        # worktree refuses it too, and the baseline did not. Anything else is
        # a hash that moved, which this change is not allowed to do.
        intended = [i for i in diff if want[i].startswith("ERR:")
                    and got[w][i] == "REFUSED" and got[b][i] != "REFUSED"]
        unexplained = [i for i in diff if i not in set(intended)]
        print("worktree vs %-8s   : %d/%d byte-identical, "
              "%d intended refusals (Core refuses these), %d unexplained%s"
              % (a.baseline, len(corpus) - len(diff), len(corpus),
                 len(intended), len(unexplained),
                 "" if not unexplained else "   <-- MISMATCH"))
        for i in unexplained[:5]:
            print("    %s: %s vs %s" % (corpus[i][0], got[w][i], got[b][i]))
        rc |= 1 if unexplained else 0
    print("RESULT:", "PASS" if rc == 0 else "FAIL")
    return rc


if __name__ == "__main__":
    sys.exit(main())
