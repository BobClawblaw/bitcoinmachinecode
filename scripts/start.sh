#!/usr/bin/env bash
# Start the node.
#
# DMN-11 (audit 2026-09-03): this used to run `bitcoind -daemon -conf= -datadir=`
# -- a Core command line this daemon does not accept. There is no -daemon flag
# and no default mode, so it exited 2 with a usage line, every time, for as long
# as it has been advertised in docs/ENGINEERING.md. The audit recommended
# deleting these three scripts; they are repaired instead, so the documented
# entry points work rather than vanish.
#
# systemd is the production path (that is what a deploy restarts), so this
# defers to the unit when it exists and only falls back to a foreground run.

set -euo pipefail

UNIT="${BMC_UNIT:-bmc-bitcoind}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${BITCOIN_DATA_DIR:-$HERE/data}"
BIN="${BMC_BITCOIND:-$HERE/asm/daemon/bitcoind}"

if systemctl list-unit-files "$UNIT.service" >/dev/null 2>&1 &&
   systemctl cat "$UNIT" >/dev/null 2>&1; then
    echo "starting via systemd unit $UNIT"
    exec sudo systemctl start "$UNIT"
fi

[ -x "$BIN" ] || { echo "no daemon binary at $BIN (run: make -C asm daemon/bitcoind)" >&2; exit 1; }
echo "no $UNIT unit found; running in the foreground from $DATA"
exec "$BIN" -datadir="$DATA" serve
