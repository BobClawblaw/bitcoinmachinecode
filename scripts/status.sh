#!/usr/bin/env bash
# Report node status.
#
# DMN-11 (audit 2026-09-03): this used to call `bitcoin-cli` (Core's binary
# name, not this tree's bitcoin_cli) and to test `pgrep bitcoind`, which matches
# an unrelated Bitcoin Core process and misses this node's deployed binary,
# bitcoind.live. Both are fixed; the RPC answer is the authority, and the
# process check is only a hint when RPC is unreachable.

set -euo pipefail

UNIT="${BMC_UNIT:-bmc-bitcoind}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="${BMC_BITCOIN_CLI:-$HERE/asm/daemon/bitcoin_cli}"

if systemctl list-unit-files "$UNIT.service" >/dev/null 2>&1 &&
   systemctl cat "$UNIT" >/dev/null 2>&1; then
    systemctl --no-pager --lines=0 status "$UNIT" || true
fi

if [ -x "$CLI" ] && "$CLI" getblockchaininfo 2>/dev/null; then
    exit 0
fi

echo "RPC did not answer."
if pgrep -f 'bitcoind(\.live)?( |$)' >/dev/null; then
    echo "a bitcoind-like process IS running (pgrep -f 'bitcoind(.live)?'):"
    pgrep -af 'bitcoind(\.live)?( |$)' | head -5
else
    echo "no bitcoind process found"
fi
exit 1
