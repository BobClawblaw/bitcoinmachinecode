#!/bin/bash
# ibd_harness_lib.sh -- the IBD benchmark harness's readers and verdict, as
# functions that can be tested.
#
# WHY THIS FILE EXISTS. On 2026-09-12 a day of work found FIVE defects in the
# benchmark harness and ZERO in the node. Two of them did not fail -- they
# reported success:
#
#   * the progress heartbeat recorded hb='' for three runs. Three things were
#     wrong at once: it read console.log (which holds only the startup banner;
#     the daemon logs to data/main/debug.log), the pattern '\[dl\] ' cannot
#     match '[dlc]', and debug.log carries NUL bytes so grep calls it binary
#     and prints nothing -- counts included.
#   * the bad-marker check read that same wrong file, so it could never fire.
#     A run with FATAL lines in its log would have been reported clean.
#   * the capstone hashed a LIVE, still-writing UTXO set and called the result
#     a coin-metadata defect in the node. It was a torn read.
#   * before that, an empty hash compared equal to an empty oracle value, and
#     every run "passed" a check that never executed.
#   * a readiness probe pointed at a path that does not exist, so the loop spun
#     forever and a 20-hour run recorded nothing.
#
# Every one of those lived inline in a 200-line script that nothing could call
# a piece of. They are functions here so test_ibd_harness.sh can run them
# against a fixture and fail when they stop working. A harness that can
# silently pass is worse than one that crashes.
#
# Every reader takes the log path as an argument and uses grep -a. Do not
# "simplify" that flag away: without it a log with one NUL byte reads as empty.

# The download heartbeat, e.g. "elapsed 18:55:25 | eta ... | applied=966241 lag=287".
# Empty output means no heartbeat has been written yet -- a legitimate state
# early in a run, and the reason this cannot simply fail when it finds nothing.
ibd_heartbeat() {
    local log="$1" hb
    hb=$(grep -a '\[dlc\] == elapsed' "$log" 2>/dev/null | tail -1 | sed 's/.*== //;s/ ==.*//')
    [ -z "$hb" ] && hb=$(grep -a '\[dl\] heartbeat' "$log" 2>/dev/null | tail -1 | sed 's/.*heartbeat: //')
    printf '%s' "$hb"
}

# Count of lines that mean the run is compromised. The [reorg] exclusions are
# normal operation: a rejected fork candidate and a probe are not failures.
ibd_bad_markers() {
    local log="$1"
    grep -aE 'FATAL|REJECT|HALTED|SEGV' "$log" 2>/dev/null \
        | grep -vE '\[reorg\] (candidate REJECTED|probe of )' | grep -c .
}

# The download pool's idle share, e.g. "pool idle 1%". Idle is time before the
# first byte of a read, not time spent inside it.
ibd_occupancy() {
    local log="$1"
    grep -aoE 'pool idle [0-9]+%' "$log" 2>/dev/null | tail -1
}

# The capstone verdict. Prints "PASS <h>" or "FAIL <why>"; returns 0 only on PASS.
#
# The rules, each of which exists because its absence produced a false verdict:
#   - an EMPTY hash on either side is a FAIL, never a pass. Empty == empty was
#     read as agreement for months.
#   - a hash that is not 64 hex characters is a FAIL, not a comparison.
#   - the two sides must be at the SAME height. Run 22 compared our set at one
#     height against Core's at another and the difference was written up as a
#     node defect.
ibd_capstone_verdict() {
    local ours="$1" theirs="$2" ours_h="$3" core_h="$4"
    case "$ours"   in ''|*[!0-9a-f]*) printf 'FAIL our side returned no usable hash (%s)' "'$ours'";   return 1;; esac
    case "$theirs" in ''|*[!0-9a-f]*) printf 'FAIL the oracle returned no usable hash (%s)' "'$theirs'"; return 1;; esac
    [ ${#ours}   -eq 64 ] || { printf 'FAIL our hash is %d chars, not 64' "${#ours}";   return 1; }
    [ ${#theirs} -eq 64 ] || { printf 'FAIL the oracle hash is %d chars, not 64' "${#theirs}"; return 1; }
    case "$ours_h" in ''|*[!0-9]*) printf 'FAIL our height is not a number (%s)' "'$ours_h'"; return 1;; esac
    case "$core_h" in ''|*[!0-9]*) printf 'FAIL the oracle height is not a number (%s)' "'$core_h'"; return 1;; esac
    [ "$ours_h" = "$core_h" ] || {
        printf 'FAIL heights differ: ours=%s oracle=%s -- comparing two different sets' "$ours_h" "$core_h"; return 1; }
    [ "$ours" = "$theirs" ] || { printf 'FAIL muhash differs at %s' "$ours_h"; return 1; }
    printf 'PASS %s' "$ours_h"; return 0
}

# A program the harness is about to run must exist and be executable. Announcing
# a launch without this is how a queue logged "launched, pid 80864" while nohup
# wrote "Permission denied" to the same file, and how a gate reported 34
# unrelated assertion failures because a build artifact sat at mode 644.
ibd_require_exec() {
    local p="$1"
    [ -x "$p" ] || { printf 'FAIL not executable: %s' "$p"; return 1; }
    printf 'OK %s' "$p"; return 0
}

# --------------------------------------------------------------------------
# Readers for the Core-side bench runner (run_core_bench.sh).
#
# Its originals were written as
#     h=$(echo "$info" | python3 -c "...get('blocks',0)" || echo 0)
# which cannot tell "the node says height 0" from "the RPC is dead". A run whose
# daemon stopped answering reports blocks=0 forever and the loop waits forever:
# the same silent-success shape as the heartbeat that logged '' for three runs.
# Worse, the tip test read
#     [ "$h" -ge $(( ${theirs:-99999999} - 1 )) ]
# so an oracle that stopped answering made the tip UNREACHABLE rather than
# raising anything -- a 20-hour run that could never finish and never say why.
# --------------------------------------------------------------------------

# Print one top-level field of a JSON object. Returns 1 (printing nothing) when
# the input is not an object or the field is absent -- ABSENT IS NOT ZERO.
bench_json_field() {
    local json="$1" field="$2"
    printf '%s' "$json" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if not isinstance(d, dict) or sys.argv[1] not in d:
    sys.exit(1)
v = d[sys.argv[1]]
sys.stdout.write("" if v is None else str(v))
' "$field" 2>/dev/null
}

# Has the run reached the oracle's tip? Returns 0 only when every input is a
# real number AND the condition holds. An unreadable side is rc 2 ("cannot
# tell"), which a caller must treat as a problem, never as "not yet".
bench_tip_reached() {
    local ours="$1" theirs="$2" vbf="$3"
    case "$ours"   in ''|*[!0-9]*)      return 2;; esac
    case "$theirs" in ''|*[!0-9]*)      return 2;; esac
    case "$vbf"    in ''|*[!0-9.eE+-]*) return 2;; esac
    [ "$ours" -ge $(( theirs - 1 )) ] || return 1
    python3 -c "import sys; sys.exit(0 if float('$vbf') > 0.9999 else 1)" 2>/dev/null || return 1
    return 0
}

# Where this daemon actually writes its running log, given a DATADIR.
#
# Harnesses kept reading <datadir>/console.log, which holds ONLY the startup
# banner -- the daemon says so itself in its first [boot] line and then logs to
# <datadir>/<chain>/debug.log. The split matters and both halves are legitimate:
#   console.log : the banner, the "no config file" refusal, the [config] lines
#                 printed before logging is redirected. Startup checks read it.
#   debug.log   : everything the running node emits. Every heartbeat, every
#                 throughput line, every FATAL. Progress checks read this.
# Three harnesses read the wrong half and measured nothing at all.
ibd_daemon_log() {
    local datadir="$1" chain="${2:-main}"
    printf '%s/%s/debug.log' "$datadir" "$chain"
}

# The download pool's most recent average receive rate, e.g. "avg 10.8MB/s".
# download_worker_sweep.sh read this from console.log, where the string appears
# ZERO times -- it appears 5,916 times in one archived debug.log. The sweep's
# cross-check on bytes_total would have been empty for every arm.
ibd_throughput() {
    local log="$1"
    grep -aoE 'avg [0-9.]+MB/s' "$log" 2>/dev/null | tail -1
}
