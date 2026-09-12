#!/bin/bash
# Wait for the running bmc benchmark to finish, preserve it, then start a
# fresh Bitcoin Core v31.1 baseline on the same disk.
#
# WHY. The Core baseline in core-bench is from 2026-09-05 -- seven days old,
# a different peer set, and carrying ONE anomaly: 138 minutes between heights
# 835,000 and 840,000, lost to a single stalling peer that Core's own log
# names at the moment its timeout fired. Every neighbouring 5,000-block
# stretch took 10-15 minutes. That hole contaminates every comparison past
# 835,000 and has had to be caveated in every report since.
#
# The node has also changed a great deal since that baseline: the leg-churn
# fix, the stalling-peer ban, eight download workers, the occupancy work.
#
# ONE FRESH RUN DOES NOT SETTLE THIS. The stall was a random peer event and a
# new run can hit its own. What this gives is a baseline taken close in time
# to ours, on the same link; whether Core's stall is typical needs a second
# run, and that question is worth more than a few percent of throughput.
#
# Compared against RUN 22, not run 23: run 23 carries coinstatsindex=1, which
# costs 3-13%, so it is not a timing counterpart. Core here keeps run 22's own
# nice/ionice treatment so the two are handled identically by the scheduler.
set -u
B=/mnt/2tbssd/bmc-bench
ARCH=/mnt/10gbusb1/bench-archive
L=/mnt/2tbssd/core-queue.log
say(){ echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" >> "$L"; }

say "=== queued: waiting for the bmc run to finish"
# Finished = RESULT written, or the daemon is gone. Both, because a run that
# dies without writing RESULT must not leave this waiting for ever.
while :; do
    [ -f "$B/RESULT" ] && { say "RESULT: $(cat "$B/RESULT")"; break; }
    P=$(cat "$B/daemon.pid" 2>/dev/null)
    if [ -n "${P:-}" ] && ! kill -0 "$P" 2>/dev/null; then say "daemon $P gone with no RESULT"; break; fi
    sleep 120
done
say "bmc run ended; tip=$(tail -40 "$B/data/main/debug.log" 2>/dev/null | grep -oE 'overall: [0-9]+/[0-9]+' | tail -1)"

# stop it cleanly if it is still up (a PASS leaves the node following the tip)
P=$(cat "$B/daemon.pid" 2>/dev/null)
if [ -n "${P:-}" ] && kill -0 "$P" 2>/dev/null; then
    say "stopping the bmc daemon by pid $P"
    kill -TERM "$P" 2>/dev/null
    for i in $(seq 1 120); do kill -0 "$P" 2>/dev/null || break; sleep 5; done
fi

# --- preserve, before anything is freed ---------------------------------
D="$ARCH/run23-$(date -u +%Y%m%d)-coinstatsindex"
mkdir -p "$D/evidence"
cp -a "$B"/console*.log "$B"/progress.log "$B"/phase.log "$B"/RESULT "$B"/epoch.start "$D/" 2>/dev/null
cp -a "$B"/data/main/debug.log "$D/" 2>/dev/null
# the UTXO and header stores are the only non-reproducible part: 17 GB, and
# the thing a muhash failure has to be re-examined against.
cp -a "$B"/data/main/utxo_*.dat "$B"/data/main/utxo_*.map "$B"/data/main/headers.dat "$D/evidence/" 2>/dev/null
say "preserved run 23 to $D ($(du -sh "$D" 2>/dev/null | cut -f1))"

# the PREVIOUS Core baseline: keep it, it is what every comparison so far used
if [ -f /mnt/2tbssd/core-bench/console.log ]; then
    C="$ARCH/core-v31.1-20260905-baseline"
    mkdir -p "$C"
    cp -a /mnt/2tbssd/core-bench/console.log /mnt/2tbssd/core-bench/phase.log \
          /mnt/2tbssd/core-bench/progress.log /mnt/2tbssd/core-bench/RESULT \
          /mnt/2tbssd/core-bench/epoch.start "$C/" 2>/dev/null
    say "preserved the 2026-09-05 Core baseline to $C"
fi

# --- free the SSD -------------------------------------------------------
say "moving run 23's blocks to the archive (frees the SSD for Core)"
nice -n 5 rsync -a --remove-source-files "$B/data/main/" "$D/blocks/" >> "$L" 2>&1
find "$B/data" -type d -empty -delete 2>/dev/null
say "free after move: $(df -h /mnt/2tbssd | awk 'NR==2{print $4}')"

AVAIL=$(df --output=avail -BG /mnt/2tbssd | tail -1 | tr -dc '0-9')
if [ "${AVAIL:-0}" -lt 800 ]; then say "ABORT: only ${AVAIL}G free; Core needs ~700G plus headroom"; exit 1; fi

# --- start Core ---------------------------------------------------------
# the old RESULT says PASS and the runner refuses to rerun on it
[ -f /mnt/2tbssd/core-bench/RESULT ] && mv /mnt/2tbssd/core-bench/RESULT "/mnt/2tbssd/core-bench/RESULT.20260905"
for f in console.log phase.log progress.log; do
    [ -f "/mnt/2tbssd/core-bench/$f" ] && mv "/mnt/2tbssd/core-bench/$f" "/mnt/2tbssd/core-bench/$f.20260905"
done
rm -rf /mnt/2tbssd/core-bench/data 2>/dev/null
say "starting the Core v31.1 baseline"
# 2026-09-12: check the runner is executable BEFORE announcing a launch. This
# script once reported "launched, pid 80864" while nohup wrote "Permission
# denied" to the same log -- an edit had stripped the exec bit -- so the queue
# recorded a success, the SSD had already been cleared for the run, and nothing
# was syncing for 1h46m until someone read the log.
RUNNER=/mnt/2tbssd/run_core_bench.sh
[ -x "$RUNNER" ] || { say "FAIL $RUNNER is not executable ($(ls -ld "$RUNNER" 2>&1))"; exit 1; }
setsid nohup "$RUNNER" >> "$L" 2>&1 < /dev/null &
pid=$!
sleep 5
kill -0 "$pid" 2>/dev/null || { say "FAIL $RUNNER died within 5s of launch; see $L"; exit 1; }
say "run_core_bench.sh launched, pid $pid (alive after 5s)"
