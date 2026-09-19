#!/bin/bash
# validation/fresh_ibd_run.sh -- a fresh mainnet IBD benchmark that can EXPLAIN
# a muhash failure instead of merely reporting one.
#
# WHY THIS EXISTS. Run 22 (2026-09-10/11) synced 966,369 blocks in 20h08m with
# zero bad blocks, no gaps, a tip identical to the Core oracle by hash -- and a
# UTXO set whose muhash differed from Core's. Every aggregate matched exactly:
# txouts, bogosize, total_amount. Only the set hash differed. Production, built
# by reindex, matches Core on BOTH its walk and its index, so the code is sound
# and the fresh-sync path produced subtly wrong data.
#
# Two things made that finding cost twenty hours instead of minutes:
#
#   1. THE CHECK HAD NEVER RUN. Earlier runs' muhash comparison timed out, and
#      an empty result compared equal to an empty oracle value, so the harness
#      printed nothing and the run passed. Run 22 is the first time the
#      comparison actually completed. A check that cannot fail is not a check;
#      this one now refuses to render a verdict on anything that is not 64 hex
#      characters from BOTH sides.
#
#   2. THE ANSWER WAS A SINGLE BIT. "The set differs at the tip" does not say
#      which block broke it. With coinstatsindex on, the node records a muhash
#      for EVERY height as it syncs, so the first divergent height can be found
#      by bisection in seconds against the oracle's own index -- one block, then
#      one coin.
#
# The index costs sync time, so this run's wall clock is NOT comparable with
# run 22's or with Core's. That is deliberate: run 22 already settled the
# timing question, and correctness is now the open one.
set -u
DEST=${DEST:-/mnt/2tbssd/bmc-bench}
SRCREF=${SRCREF:-HEAD}
P2P=${P2P:-8462}; RPC=${RPC:-8461}
WORKERS=${WORKERS:-8}
# NICE: the daemon's CPU niceness. 10 suits a correctness run sharing the box;
# a TIMED run against Core must use 0, because the Core baseline runs at
# Nice=0 under systemd and a niced node measures the scheduler, not the code.
NICE=${NICE:-10}
# EXTRA_CONF: newline-separated keys appended to the conf, so a benchmark can
# match the Core baseline's protocol (txindex, blockfilterindex, maxconnections)
# without editing this file.
EXTRA_CONF=${EXTRA_CONF:-}
. "$(dirname "$0")/lib/ibd_harness_lib.sh"
ORACLE=${ORACLE:-"/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"}
PH="$DEST/phase.log"; PROG="$DEST/progress.log"
ts(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
ph(){ echo "$(ts) $*" | tee -a "$PH"; }

mkdir -p "$DEST" && cd "$DEST" || exit 2
: > "$PH"; : > "$PROG"; rm -f RESULT 2>/dev/null

ph "START host=$(hostname) kernel=$(uname -r) workers=$WORKERS"
[ -d src ] || git clone -q /storage/bitcoinmachinecode src
# Hard-reset to the REMOTE ref. `checkout <branch>` on an existing clone keeps
# whatever that branch pointed at when it was cloned, which silently built the
# previous commit on 2026-09-11 and put the wrong binary into a 20-hour run.
git -C src fetch -q origin "+refs/heads/*:refs/remotes/origin/*" 2>/dev/null
git -C src checkout -q --detach "origin/$SRCREF" 2>/dev/null || git -C src checkout -q --detach "$SRCREF" 2>/dev/null
COMMIT=$(git -C src rev-parse --short HEAD)
ph "SRC commit=$COMMIT ref=$SRCREF"
# `make runtime`: the daemon, bmc_cli, and every helper the daemon execs from
# its own directory (asm/Makefile RUNTIME_HELPERS). bmc_cli because the
# monitor loop below asks it for the height -- only the daemon was built here
# once, so on a FRESH clone every getblockcount came back empty and the tip
# and capstone could never fire. The helpers because run 27 built neither
# them nor the index they make: its log said "builder ... not executable" and
# its txindex was never folded into a run, for the whole benchmark.
( cd src/asm && make -j8 runtime ) > build.log 2>&1 || { ph "FAIL build"; echo FAIL > RESULT; exit 1; }
[ -x src/asm/daemon/bmc_cli ] || { ph "FAIL build: no bmc_cli"; echo FAIL > RESULT; exit 1; }
HELPERS=$(make -s -C src/asm print-runtime-helpers 2>/dev/null)
# shellcheck disable=SC2086  # one word per helper, by design
hc=$(ibd_require_helpers src/asm/daemon $HELPERS) || { ph "FAIL build: $hc"; echo FAIL > RESULT; exit 1; }
ph "BUILD ok ($hc: $HELPERS)"

mkdir -p data
cp src/config/bitcoin.sample.conf data/bitcoin.conf 2>/dev/null
cat >> data/bitcoin.conf <<CONF

# fresh IBD run $(ts)
port=$P2P
rpcport=$RPC
dbcache=8192
bmc.bootcatchup=0
bmc.catchupworkers=$WORKERS
# THE POINT OF THIS RUN: a per-height muhash record, so a set that diverges
# from Core names the block it diverged on instead of only the tip.
coinstatsindex=1
CONF
[ -n "$EXTRA_CONF" ] && printf '%s\n' "$EXTRA_CONF" >> data/bitcoin.conf
ph "CONF port=$P2P rpcport=$RPC dbcache=8192 workers=$WORKERS coinstatsindex=1 nice=$NICE extra=[$(printf '%s' "$EXTRA_CONF" | tr '\n' ' ')]"

T0=$(date +%s); echo "$T0" > epoch.start
setsid nohup nice -n "$NICE" src/asm/daemon/bmcbitcoind serve "$DEST/data" > console.log 2>&1 < /dev/null &
echo $! > daemon.pid; sleep 8
kill -0 "$(cat daemon.pid)" 2>/dev/null || { ph "FAIL daemon exited at once"; echo FAIL > RESULT; exit 1; }
ph "DAEMON pid=$(cat daemon.pid) epoch=$T0"

# A missing helper is a benchmark that cannot be compared with Core: the node
# skips index work Core does. The pre-launch check above covers the build;
# this covers the daemon's own view (a path it resolves differently, a helper
# that is present but refuses to run). Watched closely for the first
# HELPER_WATCH_S seconds, then on every monitor tick below. On a hit the run
# is over: the daemon is stopped and the line that proved it is in phase.log.
HELPER_WATCH_S=${HELPER_WATCH_S:-900}
helper_fail(){ ph "FAIL helper missing: $1"; kill -TERM "$(cat daemon.pid)" 2>/dev/null; echo FAIL > RESULT; exit 1; }
w=0
while [ "$w" -lt "$HELPER_WATCH_S" ]; do
    mh=$(ibd_missing_helper "$(ibd_daemon_log "$DEST/data")") && helper_fail "$mh"
    kill -0 "$(cat daemon.pid)" 2>/dev/null || { ph "FAIL daemon exited during the first $w s"; echo FAIL > RESULT; exit 1; }
    sleep 15; w=$((w+15))
done
ph "HELPERS no missing-helper line in the first ${HELPER_WATCH_S}s"

# -rpcclienttimeout=0 (wait forever): gettxoutsetinfo walks the whole UTXO set
# and blows past the 900s default on a mainnet-sized node.
CLI="src/asm/daemon/bmc_cli -rpcport=$RPC -datadir=$DEST/data -rpcclienttimeout=0"
SEEN_CLIENTS=""; LAST_PROG=""; PROG_AT=$(date +%s); STALE_SAID=0; TW_SAID=0
HB_STALE_S=${HB_STALE_S:-3600}
while :; do
    sleep 300
    # The readers live in lib/ibd_harness_lib.sh and are tested by
    # test_ibd_harness.sh. They were inline here until 2026-09-12, which is how
    # three of them stayed broken for three runs: nothing could call a piece of
    # this script, so nothing ever checked that the heartbeat it recorded was a
    # heartbeat. Two of those defects reported success rather than failing.
    LOG=data/main/debug.log
    hb=$(ibd_heartbeat "$LOG")
    bad=$(ibd_bad_markers "$LOG")
    mh=$(ibd_missing_helper "$LOG") && helper_fail "$mh"
    du=$(du -sh data 2>/dev/null | cut -f1)
    idle=$(ibd_occupancy "$LOG")
    echo "$(ts) hb='$hb' disk=$du ${idle:+$idle} bad=$bad" >> "$PROG"
    [ "${bad:-0}" != "0" ] && { ph "FAIL bad markers"; echo FAIL > RESULT; exit 1; }
    # NO RPC TO THE NODE UNTIL ITS IBD IS OVER (operator rule, 2026-09-19).
    # Run 27's RPC side read 10.2 TB answering a monitor's polls. So the tip is
    # read from the download's own heartbeat, and anyone else connected to the
    # RPC port is named in phase.log. The harness itself has no connection open
    # here, so any client is a stranger. Each one is reported once.
    for c in $(ibd_rpc_clients "$RPC"); do
        case " $SEEN_CLIENTS " in *" $c "*) ;; *) SEEN_CLIENTS="$SEEN_CLIENTS $c"
            ph "WARN rpc client during IBD: $c ($(tr '\0' ' ' < /proc/${c%%:*}/cmdline 2>/dev/null | cut -c1-120)) -- the run is being perturbed";; esac
    done
    tw=$(ibd_rpc_recent_closes "$RPC")
    if [ "${tw:-0}" -gt 0 ]; then
        [ "$TW_SAID" = 0 ] && ph "WARN $tw connection(s) to the RPC port closed in the last minute during IBD -- something is polling the run"
        TW_SAID=1
    else TW_SAID=0; fi
    prog=$(ibd_log_progress "$LOG")
    if [ "$prog" != "$LAST_PROG" ]; then LAST_PROG=$prog; PROG_AT=$(date +%s); STALE_SAID=0
    elif [ $(( $(date +%s) - PROG_AT )) -ge "$HB_STALE_S" ] && [ "$STALE_SAID" = 0 ]; then
        ph "WARN the heartbeat has not moved in $(( ($(date +%s) - PROG_AT) / 60 )) min (last: '$prog')"; STALE_SAID=1
    fi
    printf '%s\n' "$prog" | ibd_log_tip_reached || continue
    # The download's "real tip" is the best header it saw. The oracle confirms
    # it is not stale. The oracle is not being timed, so asking it costs nothing.
    set -- $prog; theirs=$($ORACLE getblockcount 2>/dev/null)
    [ -n "$theirs" ] && [ "$3" -lt $((theirs - 6)) ] && { ph "WAIT the download finished at $3 but the oracle is at $theirs"; continue; }
    END_TS=$(ibd_log_tip_time "$LOG")
    END_EPOCH=$(date -u -d "$END_TS" +%s 2>/dev/null || echo 0)
    ph "IBD_END $END_TS UTC (from the log) elapsed=$(( END_EPOCH - T0 ))s -- applied=$1 stored=$2/$3 oracle=$theirs"

    ph "TIP reached: applied=$1 tip=$3 oracle=$theirs elapsed=$(( $(date +%s)-T0 ))s (RPC to the node is allowed from here)"

    # ------------------------------------------------------------------
    # THE CAPSTONE. Three ways this has lied, all fixed here:
    #
    # 1. Run 22 (2026-09-11) hashed a LIVE set. The comparison ran six minutes
    #    after the tip line while the engine was still applying and flushing,
    #    so the walk saw a moving LSM. It reported FAIL and a coin-metadata bug
    #    was written up. On 2026-09-12 the archived store was walked offline,
    #    quiesced, and matched Core on muhash AND every aggregate exactly. The
    #    set was always right; the read was torn. Note what made the torn read
    #    convincing: `txouts` AGREED, because on the live path that figure is a
    #    maintained counter rather than the walk's own count -- so "aggregates
    #    match but the hash differs" is the signature of an inconsistent read,
    #    not of good data with bad metadata.
    #
    # 2. Run 23 asked OUR node for a HISTORICAL height (ours-20). That answer
    #    comes from the coinstatsindex, which on a fresh sync has not caught up
    #    to the tip yet, so the call errored and returned ''. Asking our own
    #    node for a height it cannot yet answer is a harness bug, not a defect.
    #
    # 3. Before both, an empty hash compared equal to an empty oracle value and
    #    every run "passed" a check that never executed.
    #
    # The fix: quiesce, then ask OUR side for its CURRENT set with no height
    # argument -- always answerable, no index dependency -- and let it tell us
    # which height that was. Then ask the oracle for THAT height, where the
    # index makes it O(1). The height is pinned by the answer, not assumed.
    # ------------------------------------------------------------------
    $CLI setnetworkactive false >/dev/null 2>&1 && ph "CAPSTONE network disabled for a still set"
    prev=-1; stable=0
    for i in $(seq 1 60); do
        cur=$($CLI getblockcount 2>/dev/null)
        if [ -n "$cur" ] && [ "$cur" = "$prev" ]; then
            stable=$(( stable + 1 ))
            [ $stable -ge 3 ] && { ph "CAPSTONE quiesced at height $cur"; break; }
        else stable=0; fi
        prev=$cur; sleep 20
    done
    [ $stable -ge 3 ] || ph "WARN capstone proceeding without a stable height (last=$prev)"

    OURJSON=$($CLI gettxoutsetinfo muhash 2>/dev/null)
    OM=$(echo "$OURJSON" | sed -n 's/.*"muhash": *"\([0-9a-f]*\)".*/\1/p' | head -1)
    H=$(echo  "$OURJSON" | sed -n 's/.*"height": *\([0-9]*\).*/\1/p' | head -1)
    case "$H" in ''|*[!0-9]*) ph "FAIL capstone: our side reported no height"; echo FAIL > RESULT; exit 1;; esac
    ph "CAPSTONE ours is at height $H; asking the oracle for the same height"
    CM=$($ORACLE gettxoutsetinfo muhash "$H" 2>/dev/null | sed -n 's/.*"muhash": *"\([0-9a-f]*\)".*/\1/p' | head -1)
    # THE GUARD THAT WAS MISSING: an empty answer is not a passing answer.
    case "$OM" in *[!0-9a-f]*|"") ph "FAIL muhash: our side returned no usable hash ('$OM')"; echo FAIL > RESULT; exit 1;; esac
    case "$CM" in *[!0-9a-f]*|"") ph "FAIL muhash: the oracle returned no usable hash ('$CM')"; echo FAIL > RESULT; exit 1;; esac
    [ ${#OM} -eq 64 ] && [ ${#CM} -eq 64 ] || { ph "FAIL muhash: a hash was not 64 hex chars (ours ${#OM}, oracle ${#CM})"; echo FAIL > RESULT; exit 1; }

    if [ "$OM" = "$CM" ]; then
        ph "PASS muhash identical at $H ($OM)"; echo "PASS $H" > RESULT; exit 0
    fi
    ph "FAIL muhash differs at $H: ours=$OM oracle=$CM"
    # The bisect reads OUR per-height digests, which come from the
    # coinstatsindex. On a fresh sync that index trails the chain, and asking it
    # for a height it has not reached returns nothing -- which is how run 23
    # produced an empty hash and no verdict. Check it is actually caught up
    # before trusting a single answer from it.
    CSI=$($CLI getindexinfo 2>/dev/null | sed -n '/coinstatsindex/,/}/p' | sed -n 's/.*"best_block_height": *\([0-9]*\).*/\1/p' | head -1)
    case "$CSI" in ''|*[!0-9]*) CSI=0;; esac
    if [ "$CSI" -lt "$H" ]; then
        ph "BISECT unavailable: our coinstatsindex is at $CSI, below $H -- per-height"
        ph "      digests do not exist yet, so a bisect would read empty answers as"
        ph "      divergence. Re-run the bisect once the index catches up."
        echo "FAIL muhash-differs-at=$H (bisect deferred: coinstatsindex at $CSI)" > RESULT
        exit 1
    fi
    ph "BISECT: finding the first height whose set diverges (coinstatsindex at $CSI)"
    LO=1; HI=$H
    while [ $LO -lt $HI ]; do
        MID=$(( (LO+HI)/2 ))
        A=$($CLI gettxoutsetinfo muhash "$MID" 2>/dev/null | sed -n 's/.*"muhash": *"\([0-9a-f]*\)".*/\1/p' | head -1)
        B=$($ORACLE gettxoutsetinfo muhash "$MID" 2>/dev/null | sed -n 's/.*"muhash": *"\([0-9a-f]*\)".*/\1/p' | head -1)
        if [ ${#A} -ne 64 ] || [ ${#B} -ne 64 ]; then ph "BISECT stopped: no usable hash at $MID"; break; fi
        if [ "$A" = "$B" ]; then LO=$(( MID+1 )); else HI=$MID; fi
        ph "BISECT  height $MID  $( [ "$A" = "$B" ] && echo same || echo DIFFERS )  window [$LO,$HI]"
    done
    ph "BISECT first divergent height = $LO"
    ph "NEXT: diff that block's coins. getblock $LO, then gettxout each output on"
    ph "      both nodes; the aggregates matched in run 22, so look at the coin's"
    ph "      HEIGHT and COINBASE FLAG, which feed muhash but no aggregate."
    echo "FAIL first-divergent-height=$LO" > RESULT
    exit 1
done
