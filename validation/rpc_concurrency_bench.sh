#!/bin/bash
# rpc_concurrency_bench.sh -- N simultaneous clients, each making M calls of
# one RPC method, against one node over loopback; prints the wall for the
# whole wave and the per-call median. The method docs/PERFORMANCE.md s.4
# used by hand (2026-09-17), written down so the release report's RPC rows
# are reproducible on both nodes (2026-10-05).
#
#   rpc_concurrency_bench.sh <url> <cookiefile> <clients> <calls> <method> [params-json]
#
# e.g. rpc_concurrency_bench.sh http://127.0.0.1:8331 data/main/.cookie 32 5 getmempoolinfo
#      rpc_concurrency_bench.sh http://127.0.0.1:8335 /storage/core-oracle/.cookie 32 5 getblock '["<hash>",2]'
#
# Output, one line: method clients calls wall_ms median_ms p90_ms errors
# Each client is a curl process making its calls serially over one
# connection (curl reuses it); the wave starts all clients at once.
set -u
URL=${1:?url}; CK=${2:?cookie}; N=${3:?clients}; M=${4:?calls}; METHOD=${5:?method}; PARAMS=${6:-[]}
[ -r "$CK" ] || { echo "cannot read cookie $CK" >&2; exit 2; }
AUTH=$(cat "$CK")
T=$(mktemp -d)
client(){ # $1 = client index
    local i out
    for ((i=0;i<M;i++)); do
        local t0 t1
        t0=$(date +%s%N)
        out=$(curl -s --max-time 60 -u "$AUTH" -H 'content-type: text/plain' \
              --data "{\"jsonrpc\":\"1.0\",\"id\":\"b\",\"method\":\"$METHOD\",\"params\":$PARAMS}" "$URL" 2>/dev/null)
        t1=$(date +%s%N)
        if echo "$out" | grep -q '"error":null'; then echo $(( (t1-t0)/1000000 )); else echo "ERR"; fi
    done > "$T/c$1"
}
W0=$(date +%s%N)
for ((c=0;c<N;c++)); do client "$c" & done
wait
W1=$(date +%s%N)
cat "$T"/c* > "$T/all"
errs=$(grep -c ERR "$T/all"); grep -v ERR "$T/all" | sort -n > "$T/ok"
n=$(wc -l < "$T/ok")
if [ "$n" -gt 0 ]; then
    med=$(sed -n "$(( (n+1)/2 ))p" "$T/ok"); p90=$(sed -n "$(( (n*9+9)/10 ))p" "$T/ok")
else med=-; p90=-; fi
printf '%s clients=%d calls=%d wall_ms=%d median_ms=%s p90_ms=%s errors=%d\n' "$METHOD" "$N" "$M" $(( (W1-W0)/1000000 )) "$med" "$p90" "$errs"
rm -rf "$T"
