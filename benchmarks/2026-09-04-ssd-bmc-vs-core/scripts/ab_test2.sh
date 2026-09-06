#!/bin/bash
# A/B v2: same datadir, same peer pool; variant B drops the block-rate
# exemption (93fab72) -> byte floor binds at all chain depths.
# 5 min observation each. Eviction events counted as well as the rate.
set -u
BENCH=/mnt/2tbssd/bmc-bench
SRC=$BENCH/src
say(){ echo "$(date -u +%FT%TZ) $*" | tee -a "$BENCH/ab2.log"; }
get(){ grep '\[dlc\] -- average' $BENCH/console.log | tail -1 | sed -E 's/.*average since start: ([0-9.]+)(KB|MB)\/s.*/\1 \2/' | awk '{v=$1; if($2=="MB")v*=1024; print v+0}'; }
kills(){ grep -cE "dead weight" $BENCH/console.log; }
run(){ local bin=$1 tag=$2
  cd $BENCH
  kill -TERM $(cat daemon.pid 2>/dev/null) 2>/dev/null
  for i in $(seq 1 24); do kill -0 $(cat daemon.pid 2>/dev/null) 2>/dev/null || break; sleep 3; done
  kill -9 $(cat daemon.pid 2>/dev/null) 2>/dev/null; sleep 2
  mv -f console.log console.ab2.$tag.log 2>/dev/null
  setsid nohup nice -n 10 ionice -c3 "$bin" serve "$BENCH/data" > console.log 2>&1 < /dev/null &
  echo $! > daemon.pid
  sleep 180
  say "A/B2 $tag rate=$(get)KB/s kills=$(kills)"
}
cd $SRC
git stash -u -q 2>/dev/null || true
git checkout -q b0c4231
# control: current rule
( cd asm && make -j"$(nproc)" -s daemon/bitcoind ) >> $BENCH/ab2.log 2>&1
cp asm/daemon/bitcoind /tmp/ab/bitcoind.control
# variant: drop the block-rate exemption (byte floor binds at all depths)
python3 - <<'EOF'
import re
p='asm/daemon/main.c'
s=open(p).read()
old="    return byte_rate >= 0.0 && byte_rate < g_cfg.dead_weight_bps && blocks_this_tick < DLC_DEAD_WEIGHT_MIN_BLOCKS;"
new="    return byte_rate >= 0.0 && byte_rate < g_cfg.dead_weight_bps;"
assert old in s, "anchor not found"
open(p,'w').write(s.replace(old,new,1))
print("patched: byte floor binds without the block-rate exemption")
EOF
( cd asm && make -j"$(nproc)" -s daemon/bitcoind ) >> $BENCH/ab2.log 2>&1
cp asm/daemon/bitcoind /tmp/ab/bitcoind.noblockexempt
git checkout -q -- asm/daemon/main.c; git checkout -q b0c4231
run /tmp/ab/bitcoind.control control
run /tmp/ab/bitcoind.noblockexempt noblockexempt
run /tmp/ab/bitcoind.control control-2
say "A/B2 DONE"
