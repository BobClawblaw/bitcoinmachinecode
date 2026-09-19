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

# Every helper the daemon execs must sit, executable, beside it. The daemon
# finds them by its own path (readlink /proc/self/exe) and, without one, keeps
# running and never builds that index: run 27 built only bmcbitcoind and
# bmc_cli, so its txindex tail was never folded into a run -- work Core does --
# for the whole benchmark. The names come from `make print-runtime-helpers`
# (asm/Makefile RUNTIME_HELPERS), so the harness and the build cannot drift.
#   ibd_require_helpers <daemon dir> <name>...   rc 1 names every one missing
ibd_require_helpers() {
    local dir="$1"; shift
    [ $# -gt 0 ] || { printf 'FAIL no helper names given (is print-runtime-helpers broken?)'; return 1; }
    local miss="" h
    for h in "$@"; do [ -x "$dir/$h" ] || miss="$miss $h"; done
    [ -z "$miss" ] || { printf 'FAIL missing beside the daemon:%s' "$miss"; return 1; }
    printf 'OK %d helper(s) beside the daemon' "$#"; return 0
}

# The daemon's own admission that a helper is missing: the index trail and
# the coinstats repair print "builder ... not executable" (merger, too) once,
# and "... missing beside the daemon" on every status line after. Prints the
# first such line and returns 0 when one is there; prints nothing, rc 1, when
# none is. grep -a: the log carries NUL bytes.
ibd_missing_helper() {
    local log="$1" l
    l=$(grep -aE '(builder|merger) [^ ]+ not executable|missing beside the daemon' "$log" 2>/dev/null | head -1)
    [ -n "$l" ] || return 1
    printf '%s' "$l"; return 0
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

# ---- run 28: a timed IBD is read from its LOG, never over RPC (2026-09-19) ----
# Operator rule after run 27: nothing queries a timed node's RPC until its IBD
# is over. Run 27's RPC side read 10.2 TB of disk answering a monitor's polls,
# more than the sync itself read, and a per-minute gettxoutsetinfo forced Core's
# first baseline to flush its UTXO cache every minute.
# So the harness takes the tip from the download heartbeat. It makes no RPC call
# until that heartbeat says the download is complete. The readers below are how
# it does that, and how it notices anybody else calling in.

# "APPLIED STORED TIP" from the latest heartbeat that carries all three:
#   [dlc] == elapsed .. | overall: 337441/967593 stored (..) | .. | applied=337440 lag=0 ==
# Empty until the first such line.
ibd_log_progress() {
    local log="$1"
    grep -a '\[dlc\] == elapsed.*overall: [0-9]*/[0-9]* stored.*applied=[0-9]*' "$log" 2>/dev/null | tail -1 \
        | sed -E 's/.*overall: ([0-9]+)\/([0-9]+) stored.*applied=([0-9]+).*/\3 \1 \2/'
}

# rc 0 when the download says it is done: every block up to the real tip is
# stored and the UTXO engine is within 6 of it. Not "within 1": run 26's final
# heartbeat reads "967588/967588 stored ... applied=967586", so the last line the
# download ever writes can be 2 behind, and a strict rule never fires. The
# capstone waits for a stable height before it hashes anything, so ending a
# couple of blocks early costs nothing. "APPLIED STORED TIP" on stdin.
ibd_log_tip_reached() {
    local a s t
    read -r a s t || return 1
    [ -n "${t:-}" ] || return 1
    [ "$s" -ge "$t" ] && [ "$a" -ge $((t - 6)) ]
}

# The log's own timestamp of the FIRST heartbeat that reached the tip, as
# "YYYY-MM-DD HH:MM:SS". This is the run's end, to the second. The monitor loop
# only looks every 5 minutes, and Core's end is likewise read from its log
# ("Leaving InitialBlockDownload").
ibd_log_tip_time() {
    local log="$1"
    grep -a '\[dlc\] == elapsed.*overall: [0-9]*/[0-9]* stored.*applied=[0-9]*' "$log" 2>/dev/null \
        | sed -E 's/^([0-9-]+ [0-9:]+).*overall: ([0-9]+)\/([0-9]+) stored.*applied=([0-9]+).*/\1 \4 \2 \3/' \
        | awk '$4 >= $5 && $3 >= $5 - 6 { print $1, $2; exit }'
}

# Clients connected to an RPC port, from `ss -tnpH state established` output on
# stdin: one "pid:name" per distinct process. The harness makes no RPC call
# during IBD, so during IBD anything printed here is a stranger.
ibd_parse_ss_clients() {
    grep -oE 'users:\(\("[^"]+",pid=[0-9]+' | sed -E 's/users:\(\("([^"]+)",pid=([0-9]+)/\2:\1/' | sort -u
}
ibd_rpc_clients() {
    local port="$1"
    ss -tnpH state established "( dport = :$port )" 2>/dev/null | ibd_parse_ss_clients
}

# Connections to the RPC port that CLOSED in the last ~60 s (TCP TIME-WAIT).
# A poller that opens, asks and closes within milliseconds is never caught by a
# snapshot of established sockets taken every 5 minutes. Production's pollers
# showed 0 established and ~60 in TIME-WAIT at once. The closed socket lingers
# for a minute either way, so this catches them. It cannot name the process;
# the established check above names it when it happens to be caught open.
ibd_rpc_recent_closes() {
    local port="$1"
    ss -tnH state time-wait "( sport = :$port or dport = :$port )" 2>/dev/null | grep -c .
}
