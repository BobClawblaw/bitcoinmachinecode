#!/bin/bash
# Live view of the UTXO rebuild running inside bmc-bitcoind.service.
#
# NOTE: this used to watch build_utxo_seed.log, the log of a separate,
# one-off standalone seeding tool (daemon/build_utxo) -- not what actually
# runs day to day. The live daemon logs its own catchup progress to
# bitcoind.production.log instead, at a WIDE interval (every 20000 heights).
# During a slow bulk-mode stretch that can be tens of minutes between log
# lines with nothing new on screen even though the process is actively
# working. This script re-polls every 2s and fills that gap with LIVE
# process stats (seconds since the last log line, CPU%, RSS) read straight
# from /proc via ps, not from the log, so the display keeps moving even
# between log lines.
#
# NOTE ON RATE/ETA: computed from the two most recent progress lines, not an
# average-since-start -- both block size and the live UTXO set grow over the
# run, so a recent-interval rate is the honest basis and an average-since-
# start rate would be badly optimistic.
LOG=/storage/bitcoinmachinecode/logs/bitcoind.production.log
while true; do
  mapfile -t lines < <(grep '\[utxo_live\] catchup progress' "$LOG" | tail -2)
  pids=$(pgrep -f 'daemon/bitcoind serve')

  if [ -z "$pids" ]; then
    printf "\n[daemon not running]\n"; exit 1
  fi
  if [ "${#lines[@]}" -eq 0 ]; then
    printf "\rwaiting for first progress line...  (pid(s)=%s)   " "$(tr '\n' ',' <<<"$pids")"
    sleep 2; continue
  fi

  cur="${lines[-1]}"
  h=$(sed -E 's/.*height=([0-9]+)\/.*/\1/' <<<"$cur")
  end=$(sed -E 's/.*height=[0-9]+\/([0-9]+).*/\1/' <<<"$cur")
  pct=$(sed -E 's/.*\(([0-9.]+)%\).*/\1/' <<<"$cur")
  cur_ts=$(awk '{print $1" "$2}' <<<"$cur")
  cur_epoch=$(date -d "$cur_ts" +%s 2>/dev/null)
  now_epoch=$(date +%s)
  age=$(( now_epoch - cur_epoch ))

  rate_str="rate n/a (first chunk since watcher started)"
  if [ "${#lines[@]}" -eq 2 ]; then
    prev="${lines[0]}"
    ph=$(sed -E 's/.*height=([0-9]+)\/.*/\1/' <<<"$prev")
    prev_ts=$(awk '{print $1" "$2}' <<<"$prev")
    prev_epoch=$(date -d "$prev_ts" +%s 2>/dev/null)
    dh=$(( h - ph ))
    dt=$(( cur_epoch - prev_epoch ))
    if [ "$dt" -gt 0 ]; then
      rate=$(awk "BEGIN{printf \"%.2f\", $dh/$dt}")
      left=$(( end - h ))
      eta=$(awk "BEGIN{ r=$dh/$dt; printf \"%.0f\", (r>0)?($left/r/60):-1 }")
      rate_str="${rate} blk/s (last chunk) ETA~${eta}m"
    fi
  fi

  # sum CPU%/RSS across every matching pid (parent + fork workers) --
  # whichever one is doing the real work varies by phase, so report both.
  read -r pcpu rss_kb <<<"$(ps -o %cpu=,rss= -p "$(tr '\n' ',' <<<"$pids" | sed 's/,$//')" \
                             | awk '{c+=$1; r+=$2} END{print c" "r}')"
  rss_mb=$(( rss_kb / 1024 ))
  npid=$(wc -l <<<"$pids")

  printf "\r h=%s/%s (%s%%) | %s | last log line %ds ago | %s proc(s) cpu=%s%% rss=%sMB   " \
         "$h" "$end" "$pct" "$rate_str" "$age" "$npid" "$pcpu" "$rss_mb"
  sleep 2
done
