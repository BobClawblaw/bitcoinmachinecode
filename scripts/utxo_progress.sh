#!/bin/bash
# Live view of the UTXO rebuild.
#
# NOTE ON ETA: build_utxo's own per-interval "blk/s" is the honest basis. An
# average-since-start rate is badly optimistic here -- early blocks run at
# ~700k blk/s (empty chain, tiny blocks) and current ones at ~100, because
# both block size and the live UTXO set grow. We report the recent-interval
# rate and base the ETA on that; it will still drift as things get heavier.
LOG=/storage/bitcoinmachinecode/logs/build_utxo_seed.log
while true; do
  line=$(grep '^\[build_utxo\] h=' "$LOG" | tail -1)
  [ -z "$line" ] && { echo "waiting for first progress line..."; sleep 5; continue; }

  h=$(sed -E 's/.*h=([0-9]+)\/.*/\1/' <<<"$line")
  end=$(sed -E 's/.*h=[0-9]+\/([0-9]+).*/\1/' <<<"$line")
  pct=$(sed -E 's/.*\(([0-9.]+)%\).*/\1/' <<<"$line")
  live=$(sed -E 's/.*live=([0-9]+).*/\1/' <<<"$line")
  runs=$(sed -E 's/.*runs=([0-9]+).*/\1/' <<<"$line")
  rate=$(sed -E 's/.*[[:space:]]([0-9]+) blk\/s.*/\1/' <<<"$line")

  if ! pgrep -f 'daemon/build_utxo' >/dev/null; then
    printf "\n[seed finished or stopped]\n"; tail -4 "$LOG"; exit 0
  fi

  pid=$(pgrep -f 'daemon/build_utxo' | head -1)
  secs=$(ps -o etimes= -p "$pid" | tr -d ' ')
  left=$((end - h))
  if [ "${rate:-0}" -gt 0 ] 2>/dev/null; then
    eta=$(awk "BEGIN{printf \"%.0f\", $left/$rate/60}")
    printf "\r h=%s/%s (%s%%) live=%s runs=%s recent=%s blk/s elapsed=%dm ETA~%sm (at current rate)   " \
           "$h" "$end" "$pct" "$live" "$runs" "$rate" "$((secs/60))" "$eta"
  else
    printf "\r h=%s/%s (%s%%) live=%s runs=%s elapsed=%dm   " "$h" "$end" "$pct" "$live" "$runs" "$((secs/60))"
  fi
  sleep 10
done
