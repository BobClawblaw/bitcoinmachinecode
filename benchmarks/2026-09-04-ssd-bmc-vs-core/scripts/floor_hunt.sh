#!/bin/bash
# Measure dl_catchup throughput in the early-chain span with the SAME datadir
# across variants. Only the peer-eviction policy differs:
#   control      = the 93fab72 rule (byte floor AND low block rate)
#   blockfloor   = drop the byte floor's block-rate exemption (93fab72 revert)
# Each run: hole the first N blocks, launch, measure blocks restored per minute.
set -u
BENCH=/mnt/2tbssd/bmc-bench
SRC=$BENCH/src
DATA=$BENCH/data/main
say(){ echo "$(date -u +%FT%TZ) $*" | tee -a "$BENCH/floorhunt.log"; }
stop(){ local p=$(cat $BENCH/daemon.pid 2>/dev/null); kill -TERM "$p" 2>/dev/null
  for i in $(seq 1 24); do kill -0 "$p" 2>/dev/null || break; sleep 3; done; kill -9 "$p" 2>/dev/null; sleep 2; }
run(){ local bin=$1 tag=$2
  cd $BENCH
  stop
  python3 - <<EOF
import os,struct
idx="$DATA/index.dat"
# truncate index.dat records for blocks 20000..49999 -> dlc sees a hole there
rec=48
os.system(f"dd if=/dev/null of={idx} bs=1 seek=$((20000*rec)) count=$((30000*rec)) conv=notrunc status=none")
print("holed 20000..49999")
EOF
  mv -f console.log console.floor.$tag.log 2>/dev/null
  setsid nohup nice -n 10 ionice -c3 "$bin" serve "$BENCH/data" > console.log 2>&1 < /dev/null &
  echo $! > daemon.pid
  sleep 20
  local b0=$(grep -m1 "\[dlc\] == elapsed" console.log | sed -E 's/.*overall: ([0-9]+)\/.*/\1/')
  sleep 240
  local b1=$(grep '\[dlc\] == elapsed' console.log | tail -1 | sed -E 's/.*overall: ([0-9]+)\/.*/\1/')
  local avg=$(grep '\[dlc\] -- average' console.log | tail -1 | sed 's/.*start: //')
  local kills=$(grep -cE "dead weight" console.log)
  stop
  say "FLOOR $tag delta_blocks=$((b1-b0)) (240s) avg='$avg' kills=$kills"
}
mkdir -p /tmp/ab
cd $SRC
git stash -u -q 2>/dev/null || true
git checkout -q b0c4231
( cd asm && make -j"$(nproc)" -s daemon/bitcoind ) >> $BENCH/floorhunt.log 2>&1
cp asm/daemon/bitcoind /tmp/ab/bitcoind.control
patch_dl(){ # $1 = new dlc_dead_weight body line
  python3 - "$1" <<'EOF'
import sys
p='asm/daemon/main.c'
s=open(p).read()
old="    return byte_rate >= 0.0 && byte_rate < g_cfg.dead_weight_bps && blocks_this_tick < DLC_DEAD_WEIGHT_MIN_BLOCKS;"
new="    return "+sys.argv[1]
assert old in s, "anchor not found"
open(p,'w').write(s.replace(old,new,1))
EOF
}
# variant A: byte floor only (the pre-93fab72 rule)
patch_dl "byte_rate >= 0.0 && byte_rate < g_cfg.dead_weight_bps;"
( cd asm && make -j"$(nproc)" -s daemon/bitcoind ) >> $BENCH/floorhunt.log 2>&1
cp asm/daemon/bitcoind /tmp/ab/bitcoind.byteonly
# variant B: block-rate floor only (what the user intends: >=10 blocks/s)
git checkout -q -- asm/daemon/main.c
patch_dl "blocks_this_tick >= 0 && blocks_this_tick < DLC_DEAD_WEIGHT_MIN_BLOCKS;"
( cd asm && make -j"$(nproc)" -s daemon/bitcoind ) >> $BENCH/floorhunt.log 2>&1
cp asm/daemon/bitcoind /tmp/ab/bitcoind.blockfloor
git checkout -q -- asm/daemon/main.c
say "binaries: $(ls /tmp/ab)"
run /tmp/ab/bitcoind.byteonly byteonly
run /tmp/ab/bitcoind.blockfloor blockfloor
run /tmp/ab/bitcoind.control control
run /tmp/ab/bitcoind.blockfloor blockfloor-2
say "FLOORHUNT DONE"
