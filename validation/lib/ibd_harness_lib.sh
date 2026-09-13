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
