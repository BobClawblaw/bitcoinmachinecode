#!/bin/bash
# Live view of the UTXO rebuild running inside bmc-bitcoind.service.
#
# BLD-9 (audit 2026-09-03): `set -u` and a pipefail are on now -- this had
# neither, so a typo'd variable read as empty and a failing stage in a
# pipeline was invisible. NOT `set -e`: the loop below is meant to survive a
# transient read failure and keep watching, so a blanket exit-on-error would
# change what the tool is for.
#
# It reads live process memory with `sudo dd if=/proc/<pid>/mem` and resolves
# symbols with `sudo nm`. That is a root read of a running daemon's address
# space: acceptable for a developer box, and stated here rather than
# discovered at the sudo prompt.
set -u
set -o pipefail
#
# NOTE: this used to watch build_utxo_seed.log, the log of a separate,
# one-off standalone seeding tool (daemon/build_utxo) -- not what actually
# runs day to day. The live daemon logs its own catchup progress to
# bitcoind.production.log instead, at a WIDE interval (every 20000 heights),
# so during a slow bulk-mode stretch that's tens of minutes of nothing new
# on screen even though the process is actively working.
#
# GRANULARITY: rather than wait on that log, this reads the daemon's own
# in-memory g_applied_height counter (daemon/utxo_live.c) directly out of
# the worker process's memory via /proc/$PID/mem -- a plain pread at the
# symbol's address, NOT a ptrace attach/gdb session, so it never stops the
# daemon even momentarily. The symbol address is resolved fresh from the
# running binary (via /proc/$PID/exe) each time this script starts, so it
# stays correct across rebuilds without needing an edit here. Needs root
# (reading another process's memory) -- run this with sudo if not root
# already; falls back to the coarse log-only view if the read ever fails
# (stripped binary, permission denied, symbol renamed, etc).
LOG=/storage/bitcoinmachinecode/logs/bitcoind.production.log
SYM=g_applied_height

as_root(){ if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

# little-endian hex (from `xxd -p`, e.g. "483e030000000000") -> decimal
le_hex_to_dec(){
  local hex=$1 rev="" i
  for ((i=${#hex}-2; i>=0; i-=2)); do rev+="${hex:$i:2}"; done
  echo $((16#$rev))
}

# whole seconds -> "DD:HH:MM:SS" (days can exceed 2 digits; the rest are
# zero-padded). A bare "459s" reads as noise once it climbs past a minute or
# two -- this is the one format that stays legible from seconds out to days.
fmt_dhms(){
  local s=$1
  if [ -z "$s" ] || ! [ "$s" -ge 0 ] 2>/dev/null; then echo "n/a"; return; fi
  local d=$((s/86400)); s=$((s%86400))
  local h=$((s/3600));  s=$((s%3600))
  local m=$((s/60));    s=$((s%60))
  printf "%d:%02d:%02d:%02d" "$d" "$h" "$m" "$s"
}

read_live_height(){
  local pid=$1 addr=$2 hex
  hex=$(as_root dd if="/proc/$pid/mem" bs=1 skip="$((addr))" count=8 status=none 2>/dev/null | xxd -p 2>/dev/null)
  [ "${#hex}" -eq 16 ] && le_hex_to_dec "$hex"
}

prev_live_h="" prev_live_t="" addr="" tip=""

while true; do
  mapfile -t lines < <(grep '\[utxo_live\] catchup progress' "$LOG" | tail -2)
  pids=$(pgrep -f 'daemon/bitcoind serve')

  if [ -z "$pids" ]; then
    printf "\n[daemon not running]\n"; exit 1
  fi

  # of the (usually 2: parent + fork worker) matching pids, the worker
  # actually running catchup is whichever one is burning CPU right now --
  # the parent idles in serve_mux's poll(). In steady-state serving (no
  # fork worker) there's only one pid and it IS the one to read.
  worker=$(ps -o pid=,pcpu= -p "$(tr '\n' ',' <<<"$pids" | sed 's/,$//')" \
             | sort -k2 -rn | head -1 | awk '{print $1}')

  if [ -z "$addr" ]; then
    # Read symbols through the /proc/$pid/exe magic symlink DIRECTLY -- do
    # NOT readlink -f it first. If the on-disk binary has since been
    # rebuilt (e.g. `make` ran while this daemon kept running), the old
    # inode is unlinked and readlink -f resolves to a "(deleted)" path
    # that doesn't exist on disk; nm on that string then fails silently.
    # /proc/$pid/exe itself still points at the process's real, currently
    # -running (possibly now-deleted-on-disk) binary either way.
    addr=$(as_root nm "/proc/$worker/exe" 2>/dev/null | awk -v s="$SYM" '$3==s{print "0x"$1}')
  fi

  live_h=""
  [ -n "$addr" ] && live_h=$(read_live_height "$worker" "$addr")

  log_str="no log line yet" end=""
  if [ "${#lines[@]}" -gt 0 ]; then
    cur="${lines[-1]}"
    h=$(sed -E 's/.*height=([0-9]+)\/.*/\1/' <<<"$cur")
    end=$(sed -E 's/.*height=[0-9]+\/([0-9]+).*/\1/' <<<"$cur")
    pct=$(sed -E 's/.*\(([0-9.]+)%\).*/\1/' <<<"$cur")
    cur_ts=$(awk '{print $1" "$2}' <<<"$cur")
    cur_epoch=$(date -d "$cur_ts" +%s 2>/dev/null)
    age=$(( $(date +%s) - cur_epoch ))
    log_str="log: h=${h}/${end} (${pct}%) last line $(fmt_dhms "$age") ago"
    [ -z "$tip" ] && tip=$end
  fi

  live_str="live height n/a (symbol read failed -- falling back to log-only)"
  if [ -n "$live_h" ]; then
    now=$(date +%s)
    if [ -n "$prev_live_h" ] && [ "$now" != "$prev_live_t" ]; then
      dh=$((live_h - prev_live_h)); dt=$((now - prev_live_t))
      rate=$(awk "BEGIN{printf \"%.2f\", $dh/$dt}")
      if [ -n "$tip" ]; then
        left=$((tip - live_h))
        eta_secs=$(awk "BEGIN{ r=$dh/$dt; printf \"%d\", (r>0)?($left/r):-1 }")
        eta=$(fmt_dhms "$eta_secs")
        live_str="LIVE h=${live_h} (${rate} blk/s now, ETA~${eta} [D:H:M:S])"
      else
        live_str="LIVE h=${live_h} (${rate} blk/s now)"
      fi
    else
      live_str="LIVE h=${live_h} (measuring rate...)"
    fi
    prev_live_h=$live_h; prev_live_t=$now
  fi

  read -r pcpu rss_kb <<<"$(ps -o %cpu=,rss= -p "$(tr '\n' ',' <<<"$pids" | sed 's/,$//')" \
                             | awk '{c+=$1; r+=$2} END{print c" "r}')"
  rss_mb=$(( rss_kb / 1024 ))

  printf "\r %s | %s | cpu=%s%% rss=%sMB   " "$live_str" "$log_str" "$pcpu" "$rss_mb"
  sleep 2
done
