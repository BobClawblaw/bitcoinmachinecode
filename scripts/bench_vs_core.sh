#!/usr/bin/env bash
# scripts/bench_vs_core.sh -- run this project and Bitcoin Core back to back on
# the same CPU at the same moment, and emit the BENCHMARKS.md tables.
#
# The point of this script is that BENCHMARKS.md is REPRODUCIBLE. Every number
# in that document comes from one run of this script; re-running it is how you
# check a claim or re-measure after a change. Nothing here is transcribed by
# hand.
#
# WHAT IT WILL NOT DO
#   - It never touches /storage/bitcoin or bitcoind.service (a production Core
#     install), and never stops, starts or reconfigures any systemd service.
#   - It never builds in /storage/bitcoin-core-source/build. A Core oracle
#     daemon runs from that directory and other work depends on it staying up.
#     Core's benchmarks are built in a SEPARATE, out-of-tree directory
#     ($CORE_BENCH_DIR, default /storage/core-bench-build) so the oracle's build
#     is not disturbed. /storage/bitcoin-core-source itself is root-owned and
#     read-only to us, which is also why the build is out-of-tree rather than
#     the in-tree `build-bench` a writable checkout would use.
#   - It never writes to the live replay's datadir.
#
# METHODOLOGY -- see BENCHMARKS.md section "Methodology" for the reasoning.
#   - Every binary is pinned to ONE core with taskset (--cpu, default 25) so the
#     two sides contend identically and neither gets a different core's boost
#     state.
#   - Both sides are reduced to a MINIMUM over repetitions. Our harnesses use
#     CLOCK_THREAD_CPUTIME_ID / CLOCK_PROCESS_CPUTIME_ID internally and report
#     min-of-N. Core's nanobench uses wall clock and reports a median, but its
#     -output-csv carries a per-epoch `min` column, and that is the column read
#     here -- so both sides are compared min-to-min.
#   - Each Core benchmark process is additionally run --reps times and the
#     smallest of those minima is taken, which removes a process that happened
#     to land in a busy window.
#   - The cpu/wall ratio of every Core process is recorded. Core's inner timing
#     is wall-clock, so that ratio is the evidence for whether its numbers were
#     inflated by preemption. A ratio near 1.00 means the process was not
#     descheduled and its wall-clock measurements are sound. The table prints
#     the worst ratio seen.
#
# USAGE
#   scripts/bench_vs_core.sh                 # everything, default settings
#   scripts/bench_vs_core.sh --tier 1        # tier 1 only
#   scripts/bench_vs_core.sh --reps 5 --cpu 30
#   scripts/bench_vs_core.sh --list          # what it would run
#
# Raw output from every command is kept under --out (default
# ./bench-results/<timestamp>) so a surprising row can be traced back to the
# text it came from.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASM_DIR="$REPO_ROOT/asm"

CORE_SRC="${CORE_SRC:-/storage/bitcoin-core-source}"
CORE_BENCH_DIR="${CORE_BENCH_DIR:-/storage/core-bench-build}"
CORE_BENCH="$CORE_BENCH_DIR/bin/bench_bitcoin"
BLOCK_RAW="${BLOCK_RAW:-$CORE_SRC/src/bench/data/block413567.raw}"

CPU=25
REPS=3
MIN_TIME=1000          # nanobench -min-time, milliseconds
ROUNDS=15              # min-of-N for our own harnesses
TIERS="1 2 3"
OUT=""
LIST_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        --cpu)      CPU="$2"; shift 2 ;;
        --reps)     REPS="$2"; shift 2 ;;
        --min-time) MIN_TIME="$2"; shift 2 ;;
        --rounds)   ROUNDS="$2"; shift 2 ;;
        --tier)     TIERS="$2"; shift 2 ;;
        --out)      OUT="$2"; shift 2 ;;
        --list)     LIST_ONLY=1; shift ;;
        -h|--help)  sed -n '2,50p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ -n "$OUT" ] || OUT="$REPO_ROOT/bench-results/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

PIN=(taskset -c "$CPU")
has_tier(){ case " $TIERS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

say(){ printf '%s\n' "$*"; }
hr(){ printf '%s\n' "----------------------------------------------------------------------------"; }

# --------------------------------------------------------------------------
# Environment capture. A benchmark without its conditions is not a measurement.
# --------------------------------------------------------------------------
capture_env(){
    {
        echo "date_utc:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "host:            $(uname -srm)"
        echo "cpu_model:       $(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | sed 's/^ *//')"
        echo "cpu_online:      $(nproc)"
        echo "pinned_to_cpu:   $CPU"
        echo "loadavg:         $(cut -d' ' -f1-3 /proc/loadavg)"
        echo "governor:        $(cat /sys/devices/system/cpu/cpu$CPU/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
        echo "our_git_head:    $(cd "$REPO_ROOT" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
        echo "our_git_branch:  $(cd "$REPO_ROOT" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
        echo "core_version:    $("$CORE_SRC"/build/bin/bitcoind -version 2>/dev/null | head -1 || echo unknown)"
        echo "core_bench_type: $(awk -F= '/^CMAKE_BUILD_TYPE:/{print $2}' "$CORE_BENCH_DIR/CMakeCache.txt" 2>/dev/null || echo unknown)"
        echo "reps:            $REPS"
        echo "nanobench_min_ms:$MIN_TIME"
        echo "our_rounds:      $ROUNDS"
        echo
        echo "--- concurrent load at start (this box is shared; see BENCHMARKS.md) ---"
        ps -eo pcpu,etime,comm --sort=-pcpu | head -8
    } > "$OUT/environment.txt"
    cat "$OUT/environment.txt"
}

# --------------------------------------------------------------------------
# Build helpers. Neither of these touches the oracle's build directory.
# --------------------------------------------------------------------------
ensure_secp_bench(){
    SECP_BENCH="$OUT/../secp-bench/bin/bench"
    if [ -x "$SECP_BENCH" ]; then return 0; fi
    say "building libsecp256k1's own bench (Core's vendored source, Core's shipped config)..."
    # Exactly the invocation PERF_SCOPE.md section 1 used, so this number is
    # comparable to the one recorded there.
    cmake -S "$CORE_SRC/src/secp256k1" -B "$OUT/../secp-bench" \
        -DCMAKE_BUILD_TYPE=Release -DSECP256K1_BUILD_BENCHMARK=ON \
        -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
        -DSECP256K1_BUILD_CTIME_TESTS=OFF -DSECP256K1_BUILD_EXAMPLES=OFF \
        > "$OUT/secp-cmake.log" 2>&1 &&
    cmake --build "$OUT/../secp-bench" --target bench -j 4 >> "$OUT/secp-cmake.log" 2>&1
    [ -x "$SECP_BENCH" ]
}

ensure_core_bench(){
    if [ -x "$CORE_BENCH" ]; then return 0; fi
    say "building Core's bench_bitcoin in $CORE_BENCH_DIR (NOT $CORE_SRC/build -- the oracle lives there)..."
    cmake -S "$CORE_SRC" -B "$CORE_BENCH_DIR" \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_BENCH=ON \
        -DBUILD_TESTS=OFF -DBUILD_GUI=OFF -DBUILD_DAEMON=OFF -DBUILD_CLI=OFF \
        -DBUILD_TX=OFF -DBUILD_UTIL=OFF -DBUILD_WALLET_TOOL=OFF \
        -DENABLE_WALLET=OFF -DENABLE_IPC=OFF \
        > "$OUT/core-cmake.log" 2>&1 &&
    cmake --build "$CORE_BENCH_DIR" --target bench_bitcoin -j 8 >> "$OUT/core-cmake.log" 2>&1
    [ -x "$CORE_BENCH" ]
}

# --------------------------------------------------------------------------
# Core's nanobench: run REPS times, keep the smallest per-epoch `min`, and
# record the worst cpu/wall ratio seen across those processes.
#
# The CSV columns are: name, evals, iterations, total, min, max, median -- where
# min/max/median are SECONDS PER ITERATION. We keep `min`.
# --------------------------------------------------------------------------
core_bench(){
    local filter="$1" tag="$2"
    local csv best_ratio="" i
    : > "$OUT/core-$tag.raw"
    for i in $(seq 1 "$REPS"); do
        csv="$OUT/core-$tag.$i.csv"
        # `times` after a subshell gives child CPU; simpler and more portable to
        # ask the kernel via /usr/bin/time.
        /usr/bin/time -f "%e %U %S" -o "$OUT/core-$tag.$i.time" \
            "${PIN[@]}" "$CORE_BENCH" -filter="$filter" -min-time="$MIN_TIME" \
            -output-csv="$csv" >> "$OUT/core-$tag.raw" 2>&1
    done
    # cpu/wall over all reps -- the evidence that Core's wall-clock inner timing
    # was not distorted by preemption.
    awk '{ if ($1 > 0) { r = ($2+$3)/$1; if (r > mx || NR == 1) mx = r } }
         END { if (NR) printf "%.3f\n", mx }' "$OUT"/core-"$tag".*.time > "$OUT/core-$tag.ratio"
    # min-of-reps per benchmark name
    awk -F', *' 'FNR==1 { next }
                 { name=$1; v=$5+0; if (!(name in m) || v < m[name]) m[name]=v }
                 END { for (n in m) printf "%s\t%.12g\n", n, m[n] }' \
        "$OUT"/core-"$tag".*.csv | sort > "$OUT/core-$tag.min"
    cat "$OUT/core-$tag.min"
}

core_get(){ awk -F'\t' -v n="$1" '$1==n || index($1, n": ")==1 || index($1, n" ")==1 {print $2; exit}' "$2"; }

ours(){ "${PIN[@]}" "$@" 2>&1; }

# --------------------------------------------------------------------------
if [ "$LIST_ONLY" = 1 ]; then
    say "tier 1  ecdsa_verify, schnorrsig_verify, SHA256(1MB/32B), SHA256d64, SHA1, SHA512, RIPEMD160, MerkleRoot"
    say "tier 2  CheckBlock, block deserialize/walk, BIP143 + BIP341 sighash, UTXO lookup, block read"
    say "tier 3  full-verification replay over a bounded height range -- see BENCHMARKS.md for the protocol"
    exit 0
fi

say "output directory: $OUT"
hr
capture_env
hr

say "building our harnesses..."
( cd "$ASM_DIR" && make bench-vs-core ) > "$OUT/our-build.log" 2>&1 || {
    say "FAILED to build our harnesses -- see $OUT/our-build.log"; exit 1; }

# The ABI audit runs FIRST and unconditionally. If a primitive the suite times
# does not return the caller's callee-saved registers, every number below it is
# suspect -- that is not a hypothetical, it is how three violations were found.
say
say "== callee-saved register audit (runs before any timing) =="
ours "$ASM_DIR/tests/bench_abi_audit" "$BLOCK_RAW" | tee "$OUT/abi_audit.txt"
ABI_RC=${PIPESTATUS[0]}
if [ "$ABI_RC" != 0 ]; then
    say
    say "NOTE: the audit above is FAILING. Every affected primitive is called through"
    say "      tests/bench_abi_guard.S in the harnesses below, so the timings are still"
    say "      valid, but the violations are real and are recorded in BENCHMARKS.md."
fi
hr

# ==========================================================================
if has_tier 1; then
say
say "############ TIER 1 -- primitives, directly comparable ############"
say

if ensure_secp_bench; then
    say "-- libsecp256k1 (Core's vendored copy, Core's shipped config) --"
    : > "$OUT/secp.raw"
    for i in $(seq 1 "$REPS"); do
        SECP256K1_BENCH_ITERS=2000 "${PIN[@]}" "$SECP_BENCH" ecdsa_verify schnorrsig_verify \
            >> "$OUT/secp.raw" 2>&1
    done
    grep -E 'ecdsa_verify|schnorrsig_verify' "$OUT/secp.raw" | tee "$OUT/secp.txt"
    say "   (columns are us/op: min, avg, max -- min-of-$REPS processes below)"
    awk -F, '/ecdsa_verify|schnorrsig_verify/ {
                gsub(/ /,"",$1); v=$2+0; if (!(($1) in m) || v<m[$1]) m[$1]=v }
             END { for (n in m) printf "%s\tmin %.3f us\n", n, m[n] }' "$OUT/secp.raw" | sort
else
    say "SKIP libsecp256k1 bench -- could not build (see $OUT/secp-cmake.log)"
fi

say
say "-- this project --"
ours "$ASM_DIR/tests/bench_ecdsa"  2000 "$ROUNDS" | tee "$OUT/our_ecdsa.txt"
( cd "$ASM_DIR" && ours ./tests/bench_schnorr 2000 "$ROUNDS" ) | tee "$OUT/our_schnorr.txt"

say
say "-- hashes: Core's own benchmark shapes, both sides --"
if ensure_core_bench; then
    core_bench '^(SHA256_SHANI|SHA256_32b_SHANI|SHA256D64_1024_SHANI|SHA1|SHA512|BenchRIPEMD160|MerkleRoot)$' hash \
        > "$OUT/core_hash.txt"
    cat "$OUT/core_hash.txt"
    say "   Core worst cpu/wall over $REPS processes: $(cat "$OUT/core-hash.ratio" 2>/dev/null)"
else
    say "SKIP Core hash benches -- could not build (see $OUT/core-cmake.log)"
fi
ours "$ASM_DIR/tests/bench_hash_core" "$ROUNDS" | tee "$OUT/our_hash.txt"
ours "$ASM_DIR/tests/bench_merkle"    "$ROUNDS" | tee "$OUT/our_merkle.txt"
fi

# ==========================================================================
if has_tier 2; then
say
say "############ TIER 2 -- components, comparable WITH the stated caveats ############"
say

if [ -x "$CORE_BENCH" ]; then
    say "-- Core --"
    core_bench '^(CheckBlockTest|DeserializeBlockTest|VerifyScriptP2WPKH|VerifyScriptP2TR_KeyPath|VerifyScriptP2TR_ScriptPath|CCoinsCaching|ReadRawBlockBench|ReadBlockBench|ConnectBlockAllEcdsa|ConnectBlockAllSchnorr|ConnectBlockMixedEcdsaSchnorr)$' comp \
        > "$OUT/core_comp.txt"
    cat "$OUT/core_comp.txt"
    say "   Core worst cpu/wall over $REPS processes: $(cat "$OUT/core-comp.ratio" 2>/dev/null)"
fi

say
say "-- this project --"
ours "$ASM_DIR/tests/bench_checkblock" "$BLOCK_RAW" "$ROUNDS" | tee "$OUT/our_checkblock.txt"
say
( cd "$ASM_DIR" && ours ./tests/bench_segwit_sighash  "$ROUNDS" ) | tee "$OUT/our_segwit_sighash.txt"
say
( cd "$ASM_DIR" && ours ./tests/bench_taproot_sighash "$ROUNDS" ) | tee "$OUT/our_taproot_sighash.txt"
say
say "-- UTXO lookup (NOT comparable to Core's CCoinsCaching -- different object, see BENCHMARKS.md) --"
( cd "$ASM_DIR" && ours ./tests/bench_lsm_get 200000 ) | tee "$OUT/our_lsm_get.txt"
fi

# ==========================================================================
if has_tier 3; then
say
say "############ TIER 3 -- end-to-end full-verification replay ############"
say
say "NOT RUN BY THIS SCRIPT, deliberately."
say
say "A tier-3 number taken while a full-chain replay and other agents are"
say "consuming this box is worthless -- PERF_SCOPE.md section 9 documents a"
say "window where a change measured at +16% on one function appeared as a 43%"
say "end-to-end IMPROVEMENT, purely from contention. Pinning does not save a"
say "multi-hour run the way it saves a 40 ms one: the replay's own I/O, page"
say "cache pressure and memory bandwidth are shared no matter which core each"
say "side is pinned to."
say
say "The exact protocol -- fairness controls, both command lines, what each side"
say "is and is not doing -- is written out in BENCHMARKS.md, section 'Tier 3'."
say "scripts/bench_tier3_core.sh prepares and runs the Core half once the box is"
say "quiet. Run it only on an idle machine, and record what else was running."
fi

hr
say "raw output kept in $OUT"
