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
# C). The mapper maps tests/X.a -> parity_out/X.a; build it here once.
if [ ! -f "$OUT/addrbook.a" ]; then
  mkdir -p /tmp/par_ab && rm -f /tmp/par_ab/*.o
  for m in daemon/netaddr daemon/addrbook bitcoin_sha3 base32 daemon/socks5 \
           daemon/i2psam daemon/torcontrol daemon/dialer daemon/net6 daemon/asmap; do
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
if [ ! -x "$OUT/wallet_cli" ]; then
  gcc -no-pie -O2 -I../../asm -o "$OUT/wallet_cli" \
    ../../asm/daemon/wallet_cli.c ../../asm/wallet_core.c ../../asm/wallet_store.c \
    ../../asm/wallet_book.c ../../asm/wallet_txlog.c ../../asm/wallet_msgsign.c \
    secp256k1_fe.o secp256k1_point.o ../../asm/secp256k1_glv_c.c secp256k1_point_ct.o \
    secp256k1_scalar.o ../../asm/secp256k1_scalar_c.c secp256k1_ecdsa.o \
    bitcoin_keys.o bitcoin_addr.o bitcoin_pubkey.o bitcoin_sighash.o \
    bitcoin_hash.o sha256.o ripemd160.o bitcoin_bip39.o sha512.o bitcoin_hmac.o \
    bitcoin_bip32.o bech32.o bitcoin_utxo.o bitcoin_script.o \
    bitcoin_sighash_all_ext.o secp256k1_glv.o secp256k1_glv_mul.o 2>> "$OUT/build.log" \
  || echo -e "build-fail\tSPECIAL:wallet_cli\tsee build.log" >> "$OUT/results.tsv"
fi
# daemon/bitcoin_rpcd: the RPC daemon binary (test_rpc_server execs it as
# ./daemon/bitcoin_rpcd with TEST_RPC_PORT=0). Link = the daemon bundle with
# bitcoin_rpcd.c swapped for main.c (build_daemon.sh's lists, minus main).
# daemon/bitcoin_cli: daemon/bitcoin_cli.c + cli_conf.c + rpc_net/commands/json
# + RPCLIBS (test_rpc_server shells out to it).
if [ ! -x "$OUT/bitcoin_cli" ]; then
  gcc -no-pie -O2 -I../../asm -o "$OUT/bitcoin_cli" \
    ../../asm/daemon/bitcoin_cli.c ../../asm/daemon/cli_conf.c \
    ../../asm/rpc_net.c ../../asm/rpc_commands.c ../../asm/rpc_json.c \
    ../../asm/rpc_node.c ../../asm/daemon/mempool_persist.c ../../asm/rpc_wallet_ops.c \
    ../../asm/rpc_signer.c ../../asm/daemon/bfilter_index.c \
    ../../asm/daemon/addr_index_tail.c ../../asm/wallet_labels.c \
    ../../asm/wallet_scan.c ../../asm/wallet_scan_hash.c \
    ../../asm/daemon/wallet_enc_state.c ../../asm/daemon/wallet_crypter.c \
    ../../asm/bitcoin_aes.c ../../asm/rpc_chain.c ../../asm/bitcoin_pow_rules.c \
    ../../asm/block_filter.c ../../asm/bip32_ckdpub.c \
    ../../asm/daemon/wallet_pass.c ../../asm/wallet_core.c ../../asm/wallet_msgsign.c \
    ../../asm/wallet_store.c ../../asm/wallet_bnb.c ../../asm/wallet_txlog.c \
    secp256k1_fe.o secp256k1_point.o ../../asm/secp256k1_glv_c.c secp256k1_point_ct.o \
    secp256k1_scalar.o ../../asm/secp256k1_scalar_c.c secp256k1_ecdsa.o \
    bitcoin_keys.o bitcoin_addr.o bitcoin_pubkey.o bitcoin_sighash.o \
    bitcoin_sighash_all_ext.o secp256k1_glv.o secp256k1_glv_mul.o \
    bitcoin_hash.o sha256.o ripemd160.o bitcoin_bip39.o sha512.o bitcoin_hmac.o \
    bitcoin_bip32.o bech32.o bitcoin_utxo.o bitcoin_script.o \
    bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o \
    bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_tx.o \
    bitcoin_chainwork.o parity_out/addrbook.a 2>> "$OUT/build.log" \
  || echo -e "build-fail\tSPECIAL:bitcoin_cli\tsee build.log" >> "$OUT/results.tsv"
fi
if [ ! -x "$OUT/bitcoin_rpcd" ]; then
  DS="../../asm/daemon/utxo_live.c ../../asm/daemon/block_witness.c ../../asm/daemon/tx_accept.c ../../asm/daemon/zmq_notify.c ../../asm/daemon/zmq_pub.c ../../asm/daemon/reorg.c ../../asm/daemon/undo_log.c ../../asm/daemon/locator_build.c ../../asm/daemon/archive_verify.c ../../asm/daemon/addr_ingest.c ../../asm/daemon/net_policy.c ../../asm/daemon/node_config.c ../../asm/daemon/chainparams.c ../../asm/daemon/mempool_cfg.c ../../asm/daemon/upload_cap.c ../../asm/daemon/tx_submit.c ../../asm/daemon/tx_relay.c ../../asm/daemon/tx_index_tail.c ../../asm/daemon/blk_submit.c ../../asm/daemon/utxo_setinfo_rpc.c ../../asm/daemon/coinstats_index.c ../../asm/daemon/addr_self.c ../../asm/daemon/bfilter_index.c ../../asm/daemon/block_strip.c ../../asm/wallet_store.c ../../asm/bitcoin_mempool_policy.c ../../asm/daemon/mempool_compact.c ../../asm/bitcoin_txval_modern.c ../../asm/bitcoin_segwit.c ../../asm/bitcoin_taproot_sighash.c ../../asm/daemon/tx_verify.c ../../asm/bitcoin_scriptverify.c ../../asm/bitcoin_witness_v0.c ../../asm/daemon/serve_cfilters.c ../../asm/wallet_msgsign.c"
  RS="../../asm/rpc_server.c ../../asm/rpc_commands.c ../../asm/rpc_chain.c ../../asm/bitcoin_pow_rules.c ../../asm/block_filter.c ../../asm/utxo_snapshot.c ../../asm/rpc_signer.c ../../asm/bip32_ckdpub.c ../../asm/rpc_json.c ../../asm/rpc_net.c ../../asm/rpc_node.c ../../asm/daemon/mempool_persist.c ../../asm/rpc_wallet_ops.c ../../asm/daemon/addr_index_tail.c ../../asm/wallet_labels.c ../../asm/wallet_scan.c ../../asm/wallet_scan_hash.c ../../asm/daemon/wallet_enc_state.c ../../asm/daemon/wallet_crypter.c ../../asm/bitcoin_aes.c ../../asm/wallet_txlog.c ../../asm/wallet_bnb.c"
  NS="../../asm/daemon/addrbook.c ../../asm/daemon/asmap.c ../../asm/daemon/dialer.c ../../asm/daemon/i2psam.c ../../asm/daemon/minchainwork.c ../../asm/daemon/net6.c ../../asm/daemon/netaddr.c ../../asm/daemon/netperm.c ../../asm/daemon/notify.c ../../asm/daemon/serve_addr.c ../../asm/daemon/serve_invbounds.c ../../asm/daemon/signet.c ../../asm/daemon/signet_block.c ../../asm/daemon/signet_verify.c ../../asm/daemon/socks5.c ../../asm/daemon/subnet.c ../../asm/daemon/torcontrol.c ../../asm/daemon/txrecon.c ../../asm/daemon/v2transport.c ../../asm/daemon/wallet_pass.c ../../asm/base32.c ../../asm/bitcoin_sha3.c ../../asm/crypto_chacha20.c ../../asm/crypto_hkdf.c ../../asm/crypto_poly1305.c ../../asm/crypto_ellswift.c ../../asm/crypto_ellswift_ecdh.c ../../asm/crypto_ellswift_enc.c ../../asm/crypto_fe_sqrt.c ../../asm/crypto_bip324.c ../../asm/crypto_bip324_fs.c ../../asm/crypto_bip324_transport.c ../../asm/daemon/rpc_acl.c ../../asm/daemon/cli_conf.c ../../asm/daemon/lsm_manifest.c ../../asm/daemon/archive_reindex.c"
  OB="sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o bitcoin_cons.o bitcoin_store.o bitcoind.o node_log.o bitcoin_headers.o bitcoin_addrmgr.o bitcoin_idx.o bitcoin_serve.o bitcoin_mempool.o bitcoin_sigops.o bitcoin_cmpct.o bitcoin_idxscan.o bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o bitcoin_utxo.o bitcoin_store_fast.o secp256k1_schnorr.o secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o ../../asm/secp256k1_glv_c.c secp256k1_point_ct.o secp256k1_glv.o secp256k1_glv_mul.o secp256k1_fe.o secp256k1_scalar.o ../../asm/secp256k1_scalar_c.c ripemd160.o bitcoin_addr.o bitcoin_chainwork.o bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_script_flags.o sha1.o bitcoin_utxo_stats.o bitcoin_muhash.o bitcoin_strip_witness.o bitcoin_store_ext.o bech32.o bitcoin_bip32.o bitcoin_bip39.o bitcoin_hmac.o sha512.o bitcoin_keys.o bitcoin_sighash_all_ext.o"
  gcc -no-pie -O2 -Wl,-z,relro,-z,now -lpthread -I../../asm -I../../asm/daemon -I../.. \
    -o "$OUT/bitcoin_rpcd" ../../asm/daemon/bitcoin_rpcd.c $DS $RS $NS ../../asm/wallet_core.c \
    $(for m in $OB; do echo "$m"; done) 2>> "$OUT/build.log" \
  || echo -e "build-fail\tSPECIAL:bitcoin_rpcd\tsee build.log" >> "$OUT/results.tsv"
fi
[ -f ecdsa_verify_ref.o ] || gcc -march=armv8.2-a+sha2 -c -o ecdsa_verify_ref.o ecdsa_verify_ref.S 2>> "$OUT/build.log"
[ -f parity_support/bench_abi_guard.o ] || gcc -c -o parity_support/bench_abi_guard.o parity_support/bench_abi_guard.S 2>> "$OUT/build.log"

# ---- Phase B: build + run (serial: one clean build.log, honest counters) ---
: > "$OUT/results.tsv"
PASS=0; FAIL=0; BF=0; SKIP=0; BENCH=0; N=0

is_elf() { [ "$(head -c4 "$1" 2>/dev/null | tail -c1)" = "$(printf '\177')" ]; }

run_inv() {  # name kind args index
    local name="$1" kind="$2" args="$3" idx="$4"
    local label="$name"; [ "$idx" != "1" ] && label="$name#$idx"
    local scratch="/tmp/par_run_$label"
    local bin="$REPO/port/arm64/$OUT/$name"
    rm -rf "$scratch"; mkdir -p "$scratch/tests"
    # symlink farm over asm/tests, minus stale executables (x86 ELF)
    for f in "$REPO/asm/tests"/*; do
        [ -x "$f" ] && is_elf "$f" && continue
        ln -s "$f" "$scratch/tests/" 2>> "$OUT/build.log"
    done
    # overlay every binary we built (helpers the tests exec). Targets must be
    # ABSOLUTE: $OUT is relative to port/arm64 and the symlink is resolved
    # from the scratch cwd in /tmp, where "parity_out/..." does not exist.
    AB="$REPO/port/arm64"
    for f in "$AB/$OUT"/test_* "$AB/$OUT"/bench_* "$AB/$OUT"/*_shim "$AB/$OUT"/smoke_* "$AB/$OUT"/run_batch "$AB/$OUT"/fakepeer_*; do
        [ -f "$f" ] && [ -x "$f" ] && ln -sf "$f" "$scratch/tests/$(basename "$f")"
    done
    # tests that spawn/inspect the daemon expect ./daemon/bitcoind and
    # ./daemon/wallet_cli (the x86 suite runs from asm/, where daemon/ holds
    # those build products)
    mkdir -p "$scratch/daemon"
    ln -sf "$REPO/port/arm64/daemon_out/bitcoind" "$scratch/daemon/bitcoind"
    [ -x "$AB/$OUT/wallet_cli" ] && ln -sf "$AB/$OUT/wallet_cli" "$scratch/daemon/wallet_cli"
    [ -x "$AB/$OUT/bitcoin_rpcd" ] && ln -sf "$AB/$OUT/bitcoin_rpcd" "$scratch/daemon/bitcoin_rpcd"
    [ -x "$AB/$OUT/bitcoin_cli" ] && ln -sf "$AB/$OUT/bitcoin_cli" "$scratch/daemon/bitcoin_cli"
    # ./daemon/bitcoind arg remap -> the ARM daemon
    local args2="${args//.\/daemon\/bitcoind/$REPO/port/arm64/daemon_out/bitcoind}"
    ( cd "$scratch" && timeout "$TMO" "$bin" $args2 > out.txt 2>&1 )
    local rc=$?
    local note; note=$(tail -c 300 "$scratch/out.txt" | tr '\n\t' '  ' | cut -c1-160)
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
        cp "$scratch/out.txt" "$OUT/$label.out.txt" 2>/dev/null   # kept for triage, gitignored
    fi
    rm -rf "$scratch"
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
awk -F'\t' 'NR>1 && !/^=/ {c[$1]++} END {for (k in c) printf "%-10s %d\n", k, c[k]}' "$OUT/results.tsv" \
    | sort >> "$OUT/results.tsv"
echo "sweep complete ($N plan rows): $OUT/results.tsv"
awk -F'\t' 'NR>1 && !/^=/ {c[$1]++} END {for (k in c) printf "%-10s %d\n", k, c[k]}' "$OUT/results.tsv" | sort
