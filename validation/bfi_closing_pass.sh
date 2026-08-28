#!/usr/bin/env bash
# bfi_closing_pass.sh -- finish the block-filter backfill and hand it to the
# daemon, unattended.
#
# WHY THIS EXISTS. The long backfill was launched with a FIXED target (964000,
# the tip at the time). The tip moves ~6/hour, so on completion the index sits
# ~500 short and the daemon's adopt gate (BFI_ADOPT_GAP=144) correctly
# DECLINES -- the whole multi-hour run would sit on disk unused. A short
# second pass to the CURRENT tip is what makes it live.
#
# WHY IT STOPS THE DAEMON. The builder and the daemon's tail both append to
# bfilters.dat/.idx and there is NO lock between them (bfi_open takes none).
# The 144 gate is the only thing keeping them apart, and this pass is exactly
# the operation that walks the index ACROSS that gate while writing. If a
# block connects while the gap is between 0 and 144, the daemon adopts
# mid-build and two processes append to the same files. The window is short
# (~15s of a ~1min pass) but the cost is a corrupt index and a full rebuild,
# so the pass runs with the daemon down and the daemon adopts cleanly after.
#
# Sequence: wait for the running builder -> sanity-check the remaining gap ->
# stop daemon -> build to the store tip -> start daemon -> confirm ADOPTED.
set -u
DATA=/storage/bitcoinmachinecode/data
ASM=/storage/bitcoinmachinecode/asm
BUILDER=$ASM/daemon/build_block_filters
PLOG=${PLOG:-/storage/bitcoinmachinecode/logs/bitcoind.production.log}
LOG=/storage/bitcoinmachinecode/logs/bfi_closing_pass.log
# If the first builder leaves MORE than this to do, closing it with the daemon
# down would mean hours of downtime -- refuse and leave it for a human.
MAX_GAP=${MAX_GAP:-5000}
WATCH_PID=${WATCH_PID:-709681}

say(){ echo "$(date -u +'%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }
idxn(){ python3 -c "
import os
p='$DATA/bfilters.idx'
print((os.path.getsize(p)-48)//48 if os.path.exists(p) else -1)"; }
say "=== closing pass armed; watching builder pid $WATCH_PID ==="

# 1. wait for the running backfill to finish
while kill -0 "$WATCH_PID" 2>/dev/null; do sleep 60; done
say "builder $WATCH_PID exited; index at $(idxn) records"

# 2. never run the builder once the daemon owns the files
if grep -q "\[bfilter\] ADOPTED at" "$PLOG"; then
    say "ABORT: the daemon has already ADOPTED the index -- the builder must"
    say "       never run against files the daemon is maintaining."
    exit 0
fi
if pgrep -f "build_block_filters $DATA" >/dev/null; then
    say "ABORT: another build_block_filters is running against $DATA"; exit 1
fi

# 3. how far short are we? (tip from the live daemon, before we stop it)
CONF=/storage/bitcoinmachinecode/config/bitcoin.conf
RU=$(grep -m1 '^rpcuser=' "$CONF" | cut -d= -f2)
RP=$(grep -m1 '^rpcpassword=' "$CONF" | cut -d= -f2)
RPORT=$(grep -m1 '^rpcport=' "$CONF" | cut -d= -f2); RPORT=${RPORT:-8332}
TIP=$(curl -s --max-time 20 --user "$RU:$RP" -H 'content-type:text/plain' \
      --data-binary '{"jsonrpc":"1.0","id":"c","method":"getblockcount","params":[]}' \
      http://127.0.0.1:$RPORT/ | python3 -c "import sys,json
try: print(json.load(sys.stdin)['result'])
except Exception: print(-1)")
N=$(idxn)
if [ "$TIP" -lt 0 ]; then say "ABORT: could not read the tip over RPC"; exit 1; fi
GAP=$((TIP - (N - 1)))
say "index height $((N-1)), tip $TIP, gap $GAP"
if [ "$GAP" -le 144 ]; then
    say "gap already within the adopt threshold -- nothing to build; the daemon"
    say "will adopt on its next connected block."
    exit 0
fi
if [ "$GAP" -gt "$MAX_GAP" ]; then
    say "ABORT: gap $GAP exceeds MAX_GAP=$MAX_GAP. Closing that with the daemon"
    say "       down would mean hours of downtime. The first backfill probably"
    say "       died early -- restart it by hand and re-arm this script."
    exit 1
fi

# 4. stop the daemon (only safe when it is AT TIP, not mid-catch-up: a stop
#    during bulk catch-up is the SIGKILL/checkpoint hazard)
say "stopping bmc-bitcoind for the crossing"
sudo systemctl stop bmc-bitcoind.service || { say "ABORT: stop failed"; exit 1; }
sleep 5
if pgrep -f "$ASM/daemon/bitcoind serve $DATA" >/dev/null; then
    say "ABORT: daemon still running after stop -- refusing to build"; exit 1
fi
if journalctl -u bmc-bitcoind.service --since "-3min" --no-pager 2>/dev/null | grep -qi "killing"; then
    say "WARNING: systemd had to SIGKILL the daemon; checkpoint may lag (ghost"
    say "         guard handles it on boot, but note it)"
fi

# 5. build to the store tip (no target argument = the archive's own tip)
say "closing pass: building to the store tip"
( cd "$DATA" && "$BUILDER" "$DATA" ) >> "$LOG" 2>&1
say "closing pass done; index at $(idxn) records (height $(( $(idxn) - 1 )))"

# 6. bring the daemon back; it adopts on the next connected block and closes
#    any residual gap from undo data
say "starting bmc-bitcoind"
sudo systemctl start bmc-bitcoind.service || { say "ABORT: start failed -- NODE IS DOWN"; exit 1; }

# 7. confirm adoption (a block may take ~10min to arrive; wait up to 45)
for i in $(seq 90); do
    if grep -q "\[bfilter\] ADOPTED at" "$PLOG"; then
        say "ADOPTED: $(grep -m1 '\[bfilter\] ADOPTED at' "$PLOG" | sed 's/^.*\[bfilter\] //')"
        say "=== closing pass complete: the filter index is LIVE ==="
        exit 0
    fi
    sleep 30
done
say "daemon restarted but no ADOPTED line yet after 45min -- check $PLOG"
say "(index $(idxn) records; if the gap is <=144 this is just block timing)"
exit 0
