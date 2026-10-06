#!/bin/bash
# proc_sampler.sh -- CPU seconds and memory of a set of processes, sampled
# from /proc, one line per sample. Read-only (it opens /proc files and
# nothing else), so it may run beside a timed benchmark: the rule is no RPC
# to the node, and this makes none. Written 2026-10-05 for run 35, so bmc's
# CPU time and peak memory stand beside Core's; the operator's rule since
# then: capture peak memory on every run, both sides, the same way.
#
#   proc_sampler.sh --cwd <dir>  <out.log> [interval_s=5]   processes whose cwd is under <dir> (bmc: the datadir)
#   proc_sampler.sh --exe <path> <out.log> [interval_s=5]   processes running that executable (Core: its bitcoind)
#
# Each line:
#   <UTC time> procs=N cpu_s=<utime+stime of the live set, s>
#   cpu_total_s=<the same plus the CPU of processes seen earlier and gone>
#   rss_mb=<sum of VmRSS> pss_mb=<sum of Pss from smaps_rollup: shared pages
#   counted once across the set, the honest figure for a multi-process node>
#   rss_peak_mb=<largest rss_mb seen> pss_peak_mb=<largest pss_mb seen>
#   anon_mb=<sum of Anonymous from smaps_rollup: the memory the node
#   allocated, as opposed to file pages it has mapped (the archive, the
#   runs); run 35's main process held 31 GB resident of which 8.5 GB was
#   anonymous> anon_peak_mb=<largest anon_mb seen>
# A process that exits between samples keeps its last CPU reading in
# cpu_total_s, so the total is a lower bound on what the run consumed; a
# spike shorter than the interval can be missed, which is why the default
# is 5 s. Reading smaps_rollup costs ~1 ms per process.
set -u
MODE=${1:?--cwd or --exe}; KEY=${2:?dir or exe}; OUT=${3:?out}; IV=${4:-5}
HZ=$(getconf CLK_TCK)
declare -A last_cpu
gone=0; rpeak=0; ppeak=0; apeak=0
while :; do
    n=0; cpu=0; rss=0; pss=0; anon=0; declare -A seen=()
    for p in /proc/[0-9]*; do
        case "$MODE" in
            --cwd) c=$(readlink "$p/cwd" 2>/dev/null) || continue
                   case "$c" in "$KEY"|"$KEY"/*) ;; *) continue;; esac;;
            --exe) e=$(readlink "$p/exe" 2>/dev/null) || continue
                   [ "$e" = "$KEY" ] || [ "${e% (deleted)}" = "$KEY" ] || continue;;
            *) echo "mode must be --cwd or --exe" >&2; exit 2;;
        esac
        pid=${p#/proc/}
        st=$(cat "$p/stat" 2>/dev/null) || continue
        rest=${st##*) }; set -- $rest          # fields 14/15 after ')' = utime/stime, ticks
        t=$(( ${12} + ${13} ))
        r=$(awk '/^VmRSS:/{print $2}' "$p/status" 2>/dev/null); r=${r:-0}
        sr=$(awk '/^Pss:/{s=$2} /^Anonymous:/{a=$2} END{print s+0, a+0}' "$p/smaps_rollup" 2>/dev/null); set -- ${sr:-0 0}
        s=$1; a=$2; [ "$s" -gt 0 ] || s=$r
        n=$((n+1)); cpu=$((cpu+t)); rss=$((rss+r)); pss=$((pss+s)); anon=$((anon+a)); seen[$pid]=$t; last_cpu[$pid]=$t
    done
    for pid in "${!last_cpu[@]}"; do
        [ -n "${seen[$pid]:-}" ] || { gone=$((gone+last_cpu[$pid])); unset "last_cpu[$pid]"; }
    done
    rmb=$((rss/1024)); pmb=$((pss/1024)); amb=$((anon/1024))
    [ $rmb -gt $rpeak ] && rpeak=$rmb; [ $pmb -gt $ppeak ] && ppeak=$pmb; [ $amb -gt $apeak ] && apeak=$amb
    printf '%s procs=%d cpu_s=%d cpu_total_s=%d rss_mb=%d pss_mb=%d rss_peak_mb=%d pss_peak_mb=%d anon_mb=%d anon_peak_mb=%d\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$n" $((cpu/HZ)) $(((cpu+gone)/HZ)) "$rmb" "$pmb" "$rpeak" "$ppeak" "$amb" "$apeak" >> "$OUT"
    # self-cleaning: once the set has been seen and then empty for 5 minutes
    # (the node was stopped), exit rather than sample nothing forever
    if [ "$n" -gt 0 ]; then seen_any=1; empty=0; elif [ "${seen_any:-0}" = 1 ]; then
        empty=$((${empty:-0}+1)); [ $((empty*IV)) -ge 300 ] && exit 0; fi
    sleep "$IV"
done
