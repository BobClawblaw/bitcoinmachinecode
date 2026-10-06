#!/bin/bash
# Read-only I/O and stall diagnostics beside a bench run. No RPC, no signals.
# Every 5 s: PSI io/memory, Dirty/Writeback, nvme deltas, inflight queue.
# When the daemon's "[dlc] == elapsed" stored count has not moved for 30 s,
# dump the state/wchan/syscall of every process whose cwd is under the run.
RUN="$1"; OUT="$2"; DEV="${3:-nvme1n1}"
LOG="$RUN/data/main/debug.log"
last_stored=-1; last_move=$(date +%s); dumped=0
pr=0; pw=0; pt=0
while [ -d "$RUN" ]; do
    now=$(date -u +%FT%TZ); nows=$(date +%s)
    psi_io=$(awk '/^full/{print $2,$3}' /proc/pressure/io | tr -d '\n')
    psi_mem=$(awk '/^full/{print $2}' /proc/pressure/memory)
    dirty=$(awk '/^Dirty:/{d=$2} /^Writeback:/{w=$2} END{print "dirty_mb=" int(d/1024) " wb_mb=" int(w/1024)}' /proc/meminfo)
    set -- $(awk -v d="$DEV" '$3==d{print $6, $10, $13}' /proc/diskstats)   # sectors read, sectors written, io_ticks
    r=$1; w=$2; t=$3
    dr=$(( (r - pr) * 512 / 1024 / 1024 )); dw=$(( (w - pw) * 512 / 1024 / 1024 )); dt=$(( t - pt ))
    pr=$r; pw=$w; pt=$t
    infl=$(tr -s ' ' < /sys/block/$DEV/inflight | sed 's/^ //')
    stored=$(grep -a "\[dlc\] == elapsed" "$LOG" 2>/dev/null | tail -n 1 | sed -n 's/.*overall: \([0-9]*\)\/.*/\1/p')
    if [ -n "$stored" ] && [ "$stored" != "$last_stored" ]; then last_stored=$stored; last_move=$nows; dumped=0; fi
    idle=$(( nows - last_move ))
    echo "$now psi_io_full=$psi_io psi_mem_full=$psi_mem $dirty rd_mb=$dr wr_mb=$dw io_ms=$dt inflight='$infl' stored=$stored idle_s=$idle" >> "$OUT"
    if [ "$idle" -ge 30 ] && [ "$dumped" -lt 3 ]; then
        dumped=$((dumped + 1))
        {
            echo "== $now STALL DUMP $dumped (stored $stored unchanged for ${idle}s)"
            for p in /proc/[0-9]*; do
                c=$(readlink "$p/cwd" 2>/dev/null) || continue
                case "$c" in "$RUN"*) ;; *) continue ;; esac
                pid=${p#/proc/}
                st=$(awk '{print $3}' "$p/stat" 2>/dev/null)
                wc=$(cat "$p/wchan" 2>/dev/null)
                sc=$(cut -c1-60 "$p/syscall" 2>/dev/null)
                io=$(awk '/^(rchar|wchar|read_bytes|write_bytes)/{printf "%s=%s ", $1, $2}' "$p/io" 2>/dev/null)
                echo "  pid=$pid comm=$(cat "$p/comm") state=$st wchan=$wc syscall='$sc' $io"
            done
            echo "  dirty: $(grep -E '^(Dirty|Writeback):' /proc/meminfo | tr -s ' ' | tr '\n' ' ')"
            ss -tnpo 2>/dev/null | grep -a "bmcbitcoind" | sed 's/^/  ss: /' | cut -c1-200
            echo "  tail: $(tail -n 1 "$LOG" | cut -c1-200)"
        } >> "$OUT"
    fi
    sleep 5
done
