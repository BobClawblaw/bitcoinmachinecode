#!/usr/bin/env bash
# peerstats.sh -- live view of dl_catchup's per-worker peer stats (peer IP,
# chunks/blocks pulled, real measured bandwidth from /proc/<pid>/io) as they
# refresh every 10s, plus dead-weight drops and chunk completions as they
# happen. Just tails the running daemon's stderr log -- sits and refreshes
# until Ctrl-C, nothing to configure.
#
# Usage: peerstats.sh [log_file]
#   Defaults to /tmp/bitcoind_real.log (where the current manual launches
#   redirect to). Point it at a different file if you started the daemon
#   with a different redirect target.
set -euo pipefail

LOG="${1:-/tmp/bitcoind_real.log}"

if [ ! -f "$LOG" ]; then
    echo "peerstats.sh: $LOG doesn't exist yet -- is bitcoind serve running?" >&2
    exit 1
fi

echo "peerstats.sh: watching $LOG (Ctrl-C to stop)"
exec tail -n 40 -f "$LOG"
