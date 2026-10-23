#!/usr/bin/env bash
# formal/parsers/cbmc1.sh HARNESS SRC [cbmc args...] -- one ad-hoc CBMC run
# (a counterexample trace, a single --property) under the same cap as run.sh.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
FORMAL_TOOLS="${FORMAL_TOOLS:-$HOME/.local/opt/formal}"
export LD_LIBRARY_PATH="$FORMAL_TOOLS/cbmc/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
h="$1"; src="$2"; shift 2
[ "$(free -g | awk '/^Mem:/{print $7}')" -ge 25 ] || { echo "under 25 GB available" >&2; exit 3; }
while pgrep -x cbmc >/dev/null; do sleep 5; done
exec systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout "${FP_TIMEOUT:-900}" \
  "$FORMAL_TOOLS/cbmc/usr/bin/cbmc" "$HERE/harness/$h" -I"$HERE/harness" -I"$(dirname "$src")" -DSRC="\"$src\"" "$@"
