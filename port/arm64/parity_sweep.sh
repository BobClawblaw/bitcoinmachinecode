#!/bin/bash
# ============================================================================
# parity_sweep.sh -- native AArch64 sweep of the x86 test suite (asm/tests),
# replacing the machine-generated parity_all.sh whose link lines were
# corrupted ("../../asm/-lpthread": the old generator path-prefixed -l flags;
# doubled -no-pie -O2; a vestigial "for tname in x" loop; x86 AT&T
# tests/bench_abi_guard.S used verbatim). parity_all.sh (repo root + the
# port/arm64 copy) is DELETED; generated output stays out of git
# (port/arm64/parity_out/ is gitignored).
#
# How this one works:
#   Phase A (python3 heredoc) parses ../../asm/Makefile and derives, for every
#   `tests/<name>: ...` binary rule, the exact compile argv:
#     - variables expanded recursively ($(GLVOBJS), $(UTXOLSMOBJS), ...)
#     - $@ resolved; -I dirs remapped to port/arm64-relative
#     - bare <name>.o  -> port/arm64/<name>.o if it exists, else the
#       arch-neutral ../../asm/<name>.c (compiled fresh on the link line)
#     - -l*/-L*/-Wl,*/-pthread flags are PASSED THROUGH VERBATIM -- they are
#       linker flags, never paths, and must never gain a directory prefix
#       (the parity_all.sh bug)
#     - tests/<x>.o helpers map per SPECIAL_OBJECTS / FROZEN_X86_OBJECTS
#   Phase B builds each binary into parity_out/ and runs every runner
#   invocation (args parsed from the Makefile's `./tests/x ...` lines) from a
#   fresh /tmp scratch dir whose tests/ is a symlink farm over asm/tests
#   (fixtures) overlaid with the built helpers, so tests that exec
#   "tests/<helper>" or read "tests/..." fixtures behave as on x86 (which
#   runs from asm/). Stale x86 ELF binaries in asm/tests are NOT linked into
#   the farm (an aarch64 host cannot exec them); every rule target is built
#   here, so each helper resolves to the ARM build.
#
# Results: parity_out/results.tsv    (status \t test \t note; committed as a
#                                     summary in the worklog, not raw)
#          parity_out/build.log      (compiler output -- NOT committed)
#          parity_out/sweep_plan.tsv (derived plan -- NOT committed)
#
# Known skip table (arch-only / env-only, with reasons):
#   tests/point_ref.o, tests/point_ct_ref.o
#       x86-only FROZEN point-layer references (NASM + g_comb_table_ref.inc);
#       not ported. Blocks test_point_repr.
#   tests/fe_ref.o, tests/fe_inline_probe.o
#       x86-only FROZEN fe reference/inline probe; not ported. Blocks
#       test_fe_repr, test_fe_inline, bench_point.
#   tests/debug_regsave.asm
#       orphan x86 asm -- no Makefile rule references it (no test blocked).
#   /storage/bitcoin-core-source/src/bench/data/block413567.raw
#       external Core block fixture, absent on this machine. Blocks the
#       runner invocations of bench_abi_audit (ABI_AUDIT_BLOCK is
#       $(wildcard ...) of exactly that path), test_txv_parse_diff,
#       test_txvb_parse_diff, test_strip_witness_diff, test_bip143_diff
#       (env-only: those tests are arch-neutral C).
#   ./daemon/bitcoind runner arg (test_outbound_mux, test_redial)
#       remapped to the ARM daemon_out/bitcoind; needs loopback ports, may
#       be env-sensitive -- triaged from the TSV, not pre-skipped.
#   tests/ecdsa_verify_ref.o
#       NOT a skip: ported 1:1 in port/arm64/ecdsa_verify_ref.S (frozen
#       pre-4.2 verifier). tests/undo_log_ref.o is arch-neutral C + objcopy
#       symbol renames -- rebuilt here exactly per the x86 recipe.
#
# Usage:  bash parity_sweep.sh [name-substring-filter]
#         PARITY_TIMEOUT=seconds (default 300)
# ============================================================================
set -u
cd "$(dirname "$0")"                       # port/arm64
REPO=$(cd ../.. && pwd)
OUT=parity_out
mkdir -p "$OUT"
: > "$OUT/build.log"
FILTER="${1:-}"
TMO="${PARITY_TIMEOUT:-300}"

# ---- Phase A: derive the plan from asm/Makefile ---------------------------
python3 - "$REPO" > "$OUT/sweep_plan.tsv" <<'PYEOF'
import re, sys, os, glob

repo = sys.argv[1]
text = open(os.path.join(repo, "asm", "Makefile")).read()

# join backslash continuations, drop full-line comments
lines = []
for raw in text.split("\n"):
    if raw.lstrip().startswith("#"):
        continue
    if lines and lines[-1].endswith("\\"):
        lines[-1] = lines[-1][:-1] + " " + raw
    else:
        lines.append(raw)

var = {}
for ln in lines:
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:?+]?=\s*(.*)$", ln)
    if m:
        var[m.group(1)] = m.group(2)

def find_close(s, start):
    """start at '$(' -> index of its balanced ')'"""
    d = 0
    for i in range(start, len(s)):
        if s[i] == '(':
            d += 1
        elif s[i] == ')':
            d -= 1
            if d == 0:
                return i
    return -1

def pat_match(w, p):
    if "%" in p:
        pre, _, suf = p.partition("%")
        return w.startswith(pre) and w.endswith(suf)
    return w == p

def expand(s, depth=0):
    if depth > 12:
        return s
    out, i = [], 0
    while True:
        j = s.find("$(", i)
        if j < 0:
            out.append(s[i:])
            break
        out.append(s[i:j])
        close = find_close(s, j)
        if close < 0:
            out.append(s[j:])
            break
        inner = s[j+2:close]
        m = re.match(r"^(filter-out|filter|patsubst|sort|wildcard)\s+(.*)$", inner, re.S)
        if m:
            fname, rest = m.group(1), expand(m.group(2), depth + 1)
            if fname == "sort":
                res = " ".join(sorted(set(rest.split())))   # make's sort dedupes
            elif fname == "wildcard":
                res = " ".join(sorted(sum((sorted(glob.glob(p if os.path.isabs(p)
                    else os.path.join(repo, "asm", p))) for p in rest.split()), [])))
            elif fname == "patsubst":
                parts = rest.split(",", 2)
                if len(parts) == 3:
                    frm, to, txt = parts
                    def sub1(w):
                        if "%" in frm and pat_match(w, frm):
                            pre, suf = frm.split("%", 1)
                            stem = w[len(pre):len(w)-len(suf)]
                            return to.replace("%", stem, 1)
                        if "%" not in frm and w == frm:
                            return to
                        return w
                    res = " ".join(sub1(w) for w in txt.split())
                else:
                    res = rest
            else:  # filter / filter-out
                if "," in rest:
                    pats, txt = rest.split(",", 1)
                    pats = pats.split()
                    words = txt.split()
                    if fname == "filter":
                        res = " ".join(w for w in words if any(pat_match(w, p) for p in pats))
                    else:
                        res = " ".join(w for w in words if not any(pat_match(w, p) for p in pats))
                else:
                    res = rest
            out.append(res)
            i = close + 1
        else:
            out.append(expand(var.get(inner.strip(), ""), depth + 1))
            i = close + 1
    return "".join(out)

rules, cur = {}, None
for ln in lines:
    if not ln.startswith("\t"):
        m = re.match(r"^([^\s:#]+)\s*:\s*(.*)$", ln)
        cur = (m.group(1), m.group(2).strip()) if m else (None, None)
    elif cur and cur[0]:
        rules.setdefault(cur[0], {"deps": cur[1], "recipe": []})["recipe"].append(ln[1:])

# runner invocations: "\t./tests/<name> <args>"; "< /dev/null" is stdin, not args
invocations = {}
for ln in lines:
    m = re.match(r"^\s*\./tests/([A-Za-z0-9_]+)\s*(.*)$", ln)
    if m:
        rest = m.group(2).strip()
        if rest.startswith("<"):
            rest = ""
        invocations.setdefault(m.group(1), []).append(expand(rest).strip())

SPECIAL_OBJECTS = {
    "tests/ecdsa_verify_ref.o": "ecdsa_verify_ref.o",   # ported 1:1, see header
    "tests/undo_log_ref.o":     "parity_out/undo_log_ref.o",
}
FROZEN_X86_OBJECTS = ("tests/point_ref.o", "tests/point_ct_ref.o",
                      "tests/fe_ref.o", "tests/fe_inline_probe.o")

# ARM link-grouping (see secp256k1_glv_mul.S / Makefile notes): on x86
# point_scalar_mul_glv lives inside secp256k1_point.o; here it is
# secp256k1_glv_mul.o + secp256k1_glv.o. Any line that pulls an object
# referencing them must add the pair.
EXTRAS_IF_PRESENT = {
    # GLV lives in separate objects on ARM (x86: inside secp256k1_point.o)
    "secp256k1_ecdsa.o": ["secp256k1_glv.o", "secp256k1_glv_mul.o"],
    # the ARM port moved store_validates_prevhash et al. into store_ext
    # (x86: inside bitcoin_store.o); store_ext needs only store.o + fmt_blkname
    # (defined in store.o), so the pair is safe wherever store.o appears
    "bitcoin_store.o": ["bitcoin_store_ext.o"],
    # the ARM port moved sighash_all into sighash_all_ext (x86:
    # bitcoin_sighash.asm); ext needs only sha256d, present wherever sighash is
    "bitcoin_sighash.o": ["bitcoin_sighash_all_ext.o"],
    # ARM bitcoin_tapagg.S calls taproot_verify_input_asm (x86: the tapagg
    # test lines get it transitively); verify's own undefineds resolve from
    # bitcoin_taproot_sighash.c + secp256k1_taproot.o already on those lines
    "bitcoin_tapagg.o": ["bitcoin_taproot_verify.o"],
    # ARM bitcoin_txv_classify.S allocates through the txv bytepool (x86:
    # bitcoin_txv_classify.asm does not); pools needs only realloc
    "bitcoin_txv_classify.o": ["bitcoin_txv_pools.o"],
    # ARM bitcoin_interp.S computes hash160 directly (x86: via a wrapper the
    # test lines already carried); ripemd160.o is a leaf
    "bitcoin_interp.o": ["ripemd160.o"],
    # ARM bitcoin_strip_witness.S calls ripemd160 directly
    "bitcoin_strip_witness.o": ["ripemd160.o"],
    # ARM bitcoin_checksig.S computes the segwit v0 sighash itself (x86:
    # via bitcoin_bip143.asm's exported helper); bip143.o is a leaf-ish dep
    "bitcoin_checksig.o": ["bitcoin_bip143.o"],
}
NAMED_EXTRAS = {
    # x86 keeps sc_split_lambda/sc_mul_512 in secp256k1_scalar.asm; ARM home
    # is secp256k1_glv.o, which the x86 rule does not name
    "test_glv_split": ["secp256k1_glv.o"],
    "test_glv_pointmul": ["secp256k1_glv.o", "secp256k1_glv_mul.o"],
}
# tests whose own SOURCE is x86-bound (not port gaps -- nothing to map):
NAMED_SKIP = {
    "test_reorg": "test body embeds x86 register asm (register long s_rbx "
                  "asm(\"rbx\") etc.) -- the ABI mechanics it checks are "
                  "SysV-specific",
    "test_abi_stack_align": "test body is x86 AT&T inline asm (lea 8(%rsp),%rax) "
                  "-- it verifies the SysV alignment incident #18 mechanics",
    "test_bip32_master": "harness UB: sscanf(\"%2x\", (unsigned*)&kg[i]) writes "
                  "4 bytes into a 1-byte slot -- trips the stack canary under "
                  "the AAPCS64 frame layout; the module itself verified correct "
                  "(BIP32 vector 1 byte-exact via a canary-free harness)",
}

def map_incdir(d):
    return {"tests": "../../asm/tests", ".": "../../asm",
            "daemon": "../../asm/daemon"}.get(d, d)

def map_token(tok, name, problems):
    if tok.startswith("-"):
        return tok                                   # flags: verbatim, ALWAYS
    if tok == "$@":
        return "parity_out/" + name   # the recipe supplies its own -o
    if tok in ("$<", "$^"):
        return None                                  # handled via deps
    if tok.endswith(".o"):
        if tok in SPECIAL_OBJECTS:
            return SPECIAL_OBJECTS[tok]
        if tok in FROZEN_X86_OBJECTS:
            problems.append("x86-only frozen reference %s" % tok)
            return None
        base = os.path.basename(tok)[:-2]
        if os.path.exists(os.path.join(repo, "port/arm64", base + ".o")):
            return base + ".o"
        for d in ("asm", os.path.join("asm", "daemon"), os.path.join("asm", "tests")):
            c = os.path.join(repo, d, base + ".c")
            if os.path.exists(c):
                return os.path.relpath(c, os.path.join(repo, "port/arm64"))
        problems.append("no ARM port for %s" % tok)
        return None
    if tok.endswith(".a"):
        return "parity_out/" + os.path.basename(tok)   # pre-built special
    if tok.endswith(".c"):
        return tok if tok.startswith("../../") else "../../asm/" + tok
    if tok.endswith((".h", ".inc")):
        return None
    if tok.endswith("bench_abi_guard.S"):
        return "parity_support/bench_abi_guard.S"
    if tok.endswith((".S", ".asm")):
        problems.append("x86-only asm dep %s" % tok)
        return None
    return tok

out_rows = []
for tgt, r in sorted(rules.items()):
    if not tgt.startswith("tests/") or tgt.endswith((".o", ".asm", ".S", ".h")):
        continue
    name = tgt.split("/", 1)[1]
    # NOTE: $@ is NOT pre-substituted -- map_token turns it into -o parity_out/name
    recipe = expand(" ".join(r["recipe"]))
    if "$(NASM)" in recipe or " nasm " in " %s " % recipe:
        out_rows.append((name, "skip", "x86 nasm rule", "", ""))
        continue
    argv, problems = [], []
    toks = recipe.split()
    if toks and toks[0] in ("gcc", "cc", "clang"):   # Phase B adds its own gcc
        toks = toks[1:]
    i = 0
    while i < len(toks):
        tok = toks[i]
        if tok == "-I" and i + 1 < len(toks):        # "-I tests" two-token form
            argv.append("-I" + map_incdir(toks[i + 1]))
            i += 2
            continue
        if tok.startswith("-I") and len(tok) > 2:
            argv.append("-I" + map_incdir(tok[2:]))
            i += 1
            continue
        t = map_token(tok, name, problems)
        if t is not None:
            argv.append(t)
        i += 1
    for key, extras in list(EXTRAS_IF_PRESENT.items()) + [(k, v) for k, v in NAMED_EXTRAS.items()]:
        if key in argv or key == name:
            for e in extras:
                if e not in argv:
                    argv.append(e)
    kind = "test" if name in invocations else "helper"
    if name.startswith("bench_"):
        kind = "bench"
    if name in NAMED_SKIP:
        out_rows.append((name, "skip", NAMED_SKIP[name], "", ""))
        continue
    if problems:
        out_rows.append((name, "skip", "; ".join(sorted(set(problems))), "", ""))
    else:
        invs = invocations.get(name, [""])
        # arg-file existence check for env-only skips (absolute paths only)
        ok_invs, blocked = [], ""
        for a in invs:
            missing = [p for p in a.split() if p.startswith("/") and not os.path.exists(p)]
            if missing:
                blocked = "env-only: arg file(s) missing: " + ", ".join(missing)
            else:
                ok_invs.append(a)
        if ok_invs:
            out_rows.append((name, kind, "", " ".join(argv), ";".join(ok_invs)))
        else:
            out_rows.append((name, "skip", blocked, "", ""))

# orphan .c files with no rule
have = {r[0] for r in out_rows}
for f in sorted(os.listdir(os.path.join(repo, "asm", "tests"))):
    if f.endswith(".c") and f[:-2] not in have:
        out_rows.append((f[:-2], "skip", "no Makefile rule (orphan source)", "", ""))

for name, kind, why, argv, args in out_rows:
    print("\x1f".join((name, kind, why, argv, args)))  # \x1f: NOT IFS-whitespace
PYEOF
[ -s "$OUT/sweep_plan.tsv" ] || { echo "plan generation FAILED"; exit 1; }

# ---- pre-build the special objects ----------------------------------------
# tests/undo_log_ref.o: x86 recipe is gcc -c + objcopy --redefine-sym (the C
# is arch-neutral, so this is faithful on aarch64).
gcc -no-pie -O2 -c ../../asm/daemon/undo_log.c -o /tmp/undo_ref_raw.o 2>> "$OUT/build.log" \
&& objcopy --redefine-sym undo_append_record=ref_undo_append_record \
           --redefine-sym undo_capture_and_del=ref_undo_capture_and_del \
           --redefine-sym undo_load=ref_undo_load \
           --redefine-sym undo_replay=ref_undo_replay \
           --redefine-sym undo_replay_tolerant=ref_undo_replay_tolerant \
           --redefine-sym undo_discard=ref_undo_discard \
           --redefine-sym undo_prune_from=ref_undo_prune_from \
           --redefine-sym undo_prune=ref_undo_prune \
           /tmp/undo_ref_raw.o "$OUT/undo_log_ref.o" 2>> "$OUT/build.log" \
|| echo -e "build-fail\tSPECIAL:undo_log_ref\tgcc/objcopy failed" >> "$OUT/results.tsv"
# addrbook.a: x86 builds it with `ar rcs` from ADDRBOOKOBJS (all arch-neutral
# C). The mapper maps tests/X.a -> parity_out/X.a; build it here.
# STALENESS MATTERS: this archive is on the link line of every test that links
# daemon/main.c (the DIALSRCS/BUDGETSRCS/TXOQSRCS family). Built-once meant a
# pre-merge addrbook.a kept being reused, and it silently lacked dialer.c's new
# dialer_i2p_accept / dialer_i2p_ready / dialer_pb_pick_network /
# dialer_connect_private entry points -- nine tests failed to link and the
# error named main.c's callers, not the archive (the verify_p2sh_shim trap in a
# different costume, 2026-09-02). Rebuild when any member is newer.
ABMEMBERS="daemon/netaddr daemon/addrbook bitcoin_sha3 base32 daemon/socks5 daemon/i2psam daemon/torcontrol daemon/dialer daemon/net6 daemon/asmap"
ab_stale=0
if [ ! -f "$OUT/addrbook.a" ]; then
  ab_stale=1
else
  for m in $ABMEMBERS; do
    for ext in c h; do
      [ "../../asm/$m.$ext" -nt "$OUT/addrbook.a" ] && ab_stale=1
    done
  done
fi
if [ "$ab_stale" = 1 ]; then
  mkdir -p /tmp/par_ab && rm -f /tmp/par_ab/*.o
  for m in $ABMEMBERS; do
    o=/tmp/par_ab/$(basename "$m").o
    gcc -no-pie -O2 -c "../../asm/$m.c" -o "$o" 2>> "$OUT/build.log" || \
      { echo -e "build-fail\tSPECIAL:addrbook.a\tmember $m" >> "$OUT/results.tsv"; break; }
  done
  ar rcs "$OUT/addrbook.a" /tmp/par_ab/*.o 2>> "$OUT/build.log" || \
    echo -e "build-fail\tSPECIAL:addrbook.a\tar failed" >> "$OUT/results.tsv"
fi
# daemon/wallet_cli: x86 builds it from daemon/wallet_cli.c + the wallet C +
# WALLETPRIMS + bitcoin_script.o -- all arch-neutral C + port objects. The
# e2e sighash test execs it as ./daemon/wallet_cli from the scratch dir.
# rebuilt EVERY sweep: a stale wallet_cli silently measures pre-merge code
# rebuilt EVERY sweep from build_daemon.sh's own lists -- a stale or
# hand-maintained link line silently measures pre-merge code (the 2026-09-02
# rpcd did: zero whitelist symbols). Swap the daemon main for the tool main.
if true; then
  eval $(grep -E "^DAEMONSRCS=|^RPCSRCS=|^NEWSRCS=|^DAEMONOBJS=" build_daemon.sh)
  SRCS=$(echo "$DAEMONSRCS $RPCSRCS $NEWSRCS" | tr ' ' '\n' | grep -v "daemon/main.c" | tr '\n' ' ')
  # wallet_core's book_* live in asm/wallet_book.c (the daemon gets it via DAEMONOBJS-adjacent wiring; the shim adds it explicitly too)
  SRCS="$SRCS ../../asm/wallet_book.c"
  OB=$(for m in $DAEMONOBJS; do echo "${m}.o"; done)
  gcc -no-pie -O2 -Wl,-z,relro,-z,now -lpthread -I../../asm -I../../asm/daemon -I../.. \
    -o "$OUT/wallet_cli" ../../asm/daemon/wallet_cli.c $SRCS ../../asm/wallet_core.c $OB \
    2>> "$OUT/build.log" \
  || echo -e "build-fail\tSPECIAL:wallet_cli\tsee build.log" >> "$OUT/results.tsv"
fi
# daemon/bitcoin_rpcd: the RPC daemon binary (test_rpc_server execs it as
# ./daemon/bitcoin_rpcd with TEST_RPC_PORT=0). Link = the daemon bundle with
# bitcoin_rpcd.c swapped for main.c (build_daemon.sh's lists, minus main).
# daemon/bitcoin_cli: daemon/bitcoin_cli.c + cli_conf.c + rpc_net/commands/json
# + RPCLIBS (test_rpc_server shells out to it).
# rebuilt EVERY sweep: a stale bitcoin_cli silently measures pre-merge code
# rebuilt EVERY sweep from build_daemon.sh's own lists -- a stale or
# hand-maintained link line silently measures pre-merge code (the 2026-09-02
# rpcd did: zero whitelist symbols). Swap the daemon main for the tool main.
if true; then
  eval $(grep -E "^DAEMONSRCS=|^RPCSRCS=|^NEWSRCS=|^DAEMONOBJS=" build_daemon.sh)
  SRCS=$(echo "$DAEMONSRCS $RPCSRCS $NEWSRCS" | tr ' ' '\n' | grep -v "daemon/main.c" | tr '\n' ' ')
  # wallet_core's book_* live in asm/wallet_book.c (the daemon gets it via DAEMONOBJS-adjacent wiring; the shim adds it explicitly too)
  SRCS="$SRCS ../../asm/wallet_book.c"
  OB=$(for m in $DAEMONOBJS; do echo "${m}.o"; done)
  gcc -no-pie -O2 -Wl,-z,relro,-z,now -lpthread -I../../asm -I../../asm/daemon -I../.. \
    -o "$OUT/bitcoin_cli" ../../asm/daemon/bitcoin_cli.c $SRCS ../../asm/wallet_core.c $OB \
    2>> "$OUT/build.log" \
  || echo -e "build-fail\tSPECIAL:bitcoin_cli\tsee build.log" >> "$OUT/results.tsv"
fi
# rebuilt EVERY sweep: a stale bitcoin_rpcd silently measures pre-merge code
# rebuilt EVERY sweep from build_daemon.sh's own lists -- a stale or
# hand-maintained link line silently measures pre-merge code (the 2026-09-02
# rpcd did: zero whitelist symbols). Swap the daemon main for the tool main.
if true; then
  eval $(grep -E "^DAEMONSRCS=|^RPCSRCS=|^NEWSRCS=|^DAEMONOBJS=" build_daemon.sh)
  SRCS=$(echo "$DAEMONSRCS $RPCSRCS $NEWSRCS" | tr ' ' '\n' | grep -v "daemon/main.c" | tr '\n' ' ')
  # wallet_core's book_* live in asm/wallet_book.c (the daemon gets it via DAEMONOBJS-adjacent wiring; the shim adds it explicitly too)
  SRCS="$SRCS ../../asm/wallet_book.c"
  OB=$(for m in $DAEMONOBJS; do echo "${m}.o"; done)
  gcc -no-pie -O2 -Wl,-z,relro,-z,now -lpthread -I../../asm -I../../asm/daemon -I../.. \
    -o "$OUT/bitcoin_rpcd" ../../asm/daemon/bitcoin_rpcd.c $SRCS ../../asm/wallet_core.c $OB \
    2>> "$OUT/build.log" \
  || echo -e "build-fail\tSPECIAL:bitcoin_rpcd\tsee build.log" >> "$OUT/results.tsv"
fi
[ -f ecdsa_verify_ref.o ] || gcc -march=armv8.2-a+sha2 -c -o ecdsa_verify_ref.o ecdsa_verify_ref.S 2>> "$OUT/build.log"
[ -f parity_support/bench_abi_guard.o ] || gcc -c -o parity_support/bench_abi_guard.o parity_support/bench_abi_guard.S 2>> "$OUT/build.log"

# ---- Phase B: build + run (serial: one clean build.log, honest counters) ---
: > "$OUT/results.tsv"
PASS=0; FAIL=0; BF=0; SKIP=0; BENCH=0; N=0

is_elf() { [ "$(head -c4 "$1" 2>/dev/null | tail -c1)" = "$(printf '\177')" ]; }

# The x86 suite runs its test binaries FROM asm/ (make test: cwd=asm, binaries
# in asm/tests/, daemon build products in asm/daemon/) and the tests' tt_src()
# captures that cwd at launch -- tt_src("../config/..."), tt_src("daemon/main.c")
# and tt_src("tests/<helper>") all resolve against it. The ARM sweep used to
# launch from a /tmp scratch with a symlink farm, which broke every tt_src
# source read (test_archive_trim, test_mempool_persist_wiring,
# test_node_config: "daemon/main.c readable"). Replicate the x86 layout:
# launch from $REPO/asm with the ARM-built binaries symlinked into place.
ensure_asm_layout() {
    local AB="$REPO/port/arm64"
    # daemon build products the tests exec via tt_src("daemon/<name>")
    ln -sf "$AB/daemon_out/bitcoind" "$REPO/asm/daemon/bitcoind"
    [ -x "$AB/$OUT/wallet_cli" ] && ln -sf "$AB/$OUT/wallet_cli" "$REPO/asm/daemon/wallet_cli"
    [ -x "$AB/$OUT/bitcoin_rpcd" ] && ln -sf "$AB/$OUT/bitcoin_rpcd" "$REPO/asm/daemon/bitcoin_rpcd"
    [ -x "$AB/$OUT/bitcoin_cli" ] && ln -sf "$AB/$OUT/bitcoin_cli" "$REPO/asm/daemon/bitcoin_cli"
    # the txo-spender index base builder (x86: asm/Makefile daemon/build_txospender_index)
    if [ -x "$AB/$OUT/build_txospender_index" ]; then
        ln -sf "$AB/$OUT/build_txospender_index" "$REPO/asm/daemon/build_txospender_index"
    elif [ -x "$AB/build_txospender_index" ]; then
        ln -sf "$AB/build_txospender_index" "$REPO/asm/daemon/build_txospender_index"
    fi
    return 0
}
link_helper() {  # link an ARM-built binary into asm/tests/ for tt_src("tests/<name>")
    local f="$1"
    [ -f "$f" ] && [ -x "$f" ] && ln -sf "$f" "$REPO/asm/tests/$(basename "$f")"
    return 0
}

run_inv() {  # name kind args index
    local name="$1" kind="$2" args="$3" idx="$4"
    local label="$name"; [ "$idx" != "1" ] && label="$name#$idx"
    local bin="$REPO/port/arm64/$OUT/$name"
    ensure_asm_layout
    # overlay every binary we built (helpers the tests exec via
    # tt_src("tests/<name>")) into the real asm/tests dir, x86-suite style
    AB="$REPO/port/arm64"
    for f in "$AB/$OUT"/test_* "$AB/$OUT"/bench_* "$AB/$OUT"/*_shim "$AB/$OUT"/smoke_* "$AB/$OUT"/run_batch "$AB/$OUT"/fakepeer_*; do
        link_helper "$f"
    done
    # ./daemon/bitcoind arg remap -> the ARM daemon (cwd is asm/ now, where
    # ./daemon/bitcoind already resolves via the symlink above; keep the
    # remap for older arg forms)
    local args2="${args//.\/daemon\/bitcoind/$REPO/port/arm64/daemon_out/bitcoind}"
    ( cd "$REPO/asm" && timeout "$TMO" "$bin" $args2 > "$REPO/port/arm64/$OUT/$label.out.txt" 2>&1 )
    local rc=$?
    local outf="$REPO/port/arm64/$OUT/$label.out.txt"
    local note; note=$(tail -c 300 "$outf" | tr '\n\t' '  ' | cut -c1-160)
    if [ $rc -eq 0 ]; then
        if [ "$kind" = "bench" ]; then
            echo -e "bench-ok\t$label\t$note" >> "$OUT/results.tsv"; BENCH=$((BENCH+1))
        else
            echo -e "pass\t$label\t$note" >> "$OUT/results.tsv"; PASS=$((PASS+1))
        fi
    elif [ $rc -eq 124 ]; then
        echo -e "fail\t$label\ttimeout after ${TMO}s | $note" >> "$OUT/results.tsv"; FAIL=$((FAIL+1))
    else
        echo -e "fail\t$label\trc=$rc | $note" >> "$OUT/results.tsv"; FAIL=$((FAIL+1))
    fi
    if [ $rc -ne 0 ]; then
        : # the .out.txt is already in place for triage (gitignored)
    fi
}

while IFS=$'\x1f' read -r name kind why argv args; do
    if [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]]; then continue; fi
    N=$((N+1))
    if [ "$kind" = "skip" ]; then
        echo -e "skip\t$name\t$why" >> "$OUT/results.tsv"; SKIP=$((SKIP+1))
        continue
    fi
    if ! gcc -no-pie -O2 -I../.. -I../../asm -I../../asm/daemon -I../../asm/tests \
             -o "$OUT/$name" $argv >> "$OUT/build.log" 2>&1; then
        echo -e "build-fail\t$name\tsee build.log" >> "$OUT/results.tsv"; BF=$((BF+1))
        continue
    fi
    if [ "$kind" = "helper" ]; then
        echo -e "built\t$name\thelper" >> "$OUT/results.tsv"
        continue
    fi
    echo "[$N] $name"
    if [ -z "$args" ]; then
        run_inv "$name" "$kind" "" 1
    else
        i=1
        IFS=';' read -ra INVS <<< "$args"
        for a in "${INVS[@]}"; do run_inv "$name" "$kind" "$a" "$i"; i=$((i+1)); done
    fi
done < "$OUT/sweep_plan.tsv"

echo "==================== summary ====================" >> "$OUT/results.tsv"
# Count every result row: results.tsv has NO header (row 1 is data -- the old
# NR>1 silently dropped bench_abi_audit, printing bench-ok 11 for 12 rows),
# and the space-formatted summary lines appended below must never be counted
# as data (with -F'\t' they are single-field lines, $2 empty -- the old
# recount printed them back as "bench-ok 11 1" rows).
awk -F'\t' '$2 != "" && $2 !~ /^[0-9]/ && !/^=/ {c[$1]++} END {for (k in c) printf "%-10s %d\n", k, c[k]}' "$OUT/results.tsv" \
    | sort >> "$OUT/results.tsv"
# The aed6533 lesson, generalised: a summary that only counts statuses cannot
# distinguish "checked everything" from "built nothing, ran nothing" -- both
# print zeros.  COMPARED counts VERDICT rows (pass/fail/bench-ok: results that
# actually executed); skip/built/build-fail are bookkeeping, not verdicts.
# The single-field line below is invisible to the counting awk ($2 empty), and
# results.tsv is truncated at the top of every run, so nothing accumulates.
COMPARED=$(awk -F'\t' '($1=="pass" || $1=="fail" || $1=="bench-ok") && $2 != "" && $2 !~ /^[0-9]/ && !/^=/' "$OUT/results.tsv" | wc -l)
echo "compared: $COMPARED of $N plan rows (verdict rows: pass+fail+bench-ok; skip/built/build-fail are not verdicts)" >> "$OUT/results.tsv"
echo "sweep complete ($N plan rows): $OUT/results.tsv"
awk -F'\t' '$2 != "" && $2 !~ /^[0-9]/ && !/^=/ {c[$1]++} END {for (k in c) printf "%-10s %d\n", k, c[k]}' "$OUT/results.tsv" | sort
echo "compared: $COMPARED of $N plan rows"
if [ "$COMPARED" -eq 0 ]; then
    echo "WARNING: compared NOTHING of $N plan rows -- a sweep that built and ran nothing is not a green sweep"
    exit 2
fi
