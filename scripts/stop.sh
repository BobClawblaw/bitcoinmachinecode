#!/usr/bin/env bash
# Stop the node.
#
# DMN-11 (audit 2026-09-03): this used to call `bitcoin-cli` -- Core's binary
# name, not the one this tree builds (bitcoin_cli) -- and then fall back to
# `killall bitcoind` on failure. That fallback was the real hazard: it SIGTERMs
# any process named bitcoind, including an unrelated Bitcoin Core node on the
# same host, while MISSING this node's own deployed binary, which runs as
# bitcoind.live. It is gone; nothing here kills by name.

set -euo pipefail

UNIT="${BMC_UNIT:-bmc-bitcoind}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="${BMC_BITCOIN_CLI:-$HERE/asm/daemon/bitcoin_cli}"

if systemctl list-unit-files "$UNIT.service" >/dev/null 2>&1 &&
   systemctl cat "$UNIT" >/dev/null 2>&1; then
    echo "stopping via systemd unit $UNIT"
    exec sudo systemctl stop "$UNIT"
fi

[ -x "$CLI" ] || { echo "no cli binary at $CLI (run: make -C asm daemon/bitcoin_cli)" >&2; exit 1; }
echo "asking the node to stop over RPC"
exec "$CLI" stop
