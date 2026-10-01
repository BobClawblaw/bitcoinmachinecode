#!/bin/bash
# ibd_milestones.sh <rundir> -- elapsed (h:mm:ss from epoch.start) at the first
# "[utxo_live] catchup progress: height=" line at or past each milestone of a
# fresh_ibd_run.sh run directory. Reproduces run 31's published column exactly
# (docs/reports/2026-09-30-ibd-benchmarks-bmc-vs-core.md). Reads the log only.
# Run with TZ=UTC: the log timestamps are UTC and mktime is local.
R=$1
T0=$(cat "$R/epoch.start")
grep -a 'catchup progress: height=' "$R/data/main/debug.log" | tr -d '\000' | awk -v t0="$T0" '
  function ep(d,t){ gsub(/-/," ",d); split(t,a,/[:.]/); return mktime(d" "a[1]" "a[2]" "a[3]) }
  BEGIN{ n=split("50000 100000 200000 300000 400000 500000 600000 700000 800000 900000 950000 968987", M, " "); i=1 }
  { match($0,/height=[0-9]+/); h=substr($0,RSTART+7,RLENGTH-7)+0
    while (i<=n && h>=M[i]) { e=ep($1,$2)-t0; printf "%d %d:%02d:%02d\n", M[i], e/3600, (e%3600)/60, e%60; i++ } }'
