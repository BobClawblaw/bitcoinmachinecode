#!/usr/bin/env bash
# Report node status.
#
# DMN-11 (audit 2026-09-03): this used to call `bitcoin-cli` (Core's binary
# name, not this tree's bmc_cli) and to test `pgrep bitcoind`, which matches
# an unrelated Bitcoin Core process and misses this node's deployed binary,
# bitcoind.live. Both are fixed; the RPC answer is the authority, and the
# process check is only a hint when RPC is unreachable.

set -euo pipefail

UNIT="${BMC_UNIT:-$(systemctl cat bmcbitcoind >/dev/null 2>&1 && echo bmcbitcoind || echo bmc-bitcoind)}"   # the reference box's unit until the operator renames it
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="${BMC_BITCOIN_CLI:-$HERE/asm/daemon/bmc_cli}"

if systemctl list-unit-files "$UNIT.service" >/dev/null 2>&1 &&
   systemctl cat "$UNIT" >/dev/null 2>&1; then
    systemctl --no-pager --lines=0 status "$UNIT" || true
fi

if [ -x "$CLI" ] && "$CLI" getblockchaininfo 2>/dev/null; then
    exit 0
fi

echo "RPC did not answer."
if pgrep -f 'bitcoin(mc)?d(\.live)?( |$)' >/dev/null; then
    echo "a bmcbitcoind-like process IS running (pgrep -f 'bitcoin(mc)?d(.live)?'):"
    pgrep -af 'bitcoin(mc)?d(\.live)?( |$)' | head -5
else
    echo "no bmcbitcoind process found"
fi
exit 1
