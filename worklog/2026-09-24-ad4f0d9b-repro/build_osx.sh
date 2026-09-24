#!/bin/bash
# build_osx.sh -- tn4_replay natively on macOS/arm64 (bmc_osx), against the
# daemon objects port/osx/build_daemon.sh left in port/osx/daemon_out.
# Usage: build_osx.sh <tx_verify.c to test> <fixture dir> [runs]
#   e.g. build_osx.sh daemon/tx_verify.c /tmp/tn4fx 3      (paths from asm/)
# The objects go into an archive, minus main.o, tx_verify.o and utxo_live.o
# (the harness includes utxo_live.c itself), so the harness's own
# definitions win; -undefined dynamic_lookup covers what nothing calls.
# 2026-09-24 on the m5ultra: main's tx_verify.c 18/18 in 3 of 3 runs,
# ad4f0d9b SIGSEGV at 124,864 in 2 of 2.
set -u
cd "$(dirname "$0")/../../asm"
TXV=$1; FX=$2; RUNS=${3:-3}
OUT=../port/osx/daemon_out
W=$(mktemp -d "${TMPDIR:-/tmp}/tn4replay.XXXX")
CC="cc -O2 -arch arm64 -I. -Idaemon -Itests -I../port/osx/compat -D_DARWIN_C_SOURCE -Dst_mtim=st_mtimespec -Dst_atim=st_atimespec -Dst_ctim=st_ctimespec -w"
[ -f "$OUT/utxo_live.o" ] || { echo "run port/osx/build_daemon.sh first"; exit 2; }
$CC -c -o "$W/txv.o" "$TXV" || exit 2
ar rcs "$W/dout.a" $(ls $OUT/*.o | grep -v -e '/main.o$' -e '/tx_verify.o$' -e '/utxo_live.o$')
$CC -o "$W/tn4_replay" ../worklog/2026-09-24-ad4f0d9b-repro/tn4_replay.c "$W/txv.o" "$W/dout.a" \
    -lpthread -Wl,-undefined,dynamic_lookup || exit 3
fails=0
for i in $(seq 1 "$RUNS"); do
  d=$(mktemp -d "$W/run.XXXX")
  (cd "$d" && "$W/tn4_replay" "$FX" > out.txt 2>err.txt); rc=$?
  echo "run $i: rc=$rc :: $(tail -1 "$d/out.txt")"
  [ $rc -eq 0 ] || fails=$((fails+1))
done
echo "work dir: $W"
exit $fails
