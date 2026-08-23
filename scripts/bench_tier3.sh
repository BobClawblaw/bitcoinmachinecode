#!/usr/bin/env bash
# scripts/bench_tier3.sh -- the end-to-end comparison: this node doing a
# full-verification replay over a bounded height range, against Bitcoin Core
# doing the same range with -assumevalid=0.
#
# This is the number that actually matters and it has never been run. This
# script exists so that when the box is quiet it can be run in four commands
# instead of being reinvented, and so that the fairness controls are code rather
# than good intentions.
#
# READ scripts/../BENCHMARKS.md section "Tier 3" before using this. In
# particular: it is NOT enough to pin both sides and call the comparison fair.
# The two programs do overlapping but different work, and the write-up has to
# enumerate the differences rather than hand-wave them.
#
# ===========================================================================
# WHY THE RANGE STARTS AT GENESIS
# ===========================================================================
# You cannot validate block H without the UTXO set as of H-1, and neither side
# can be handed the other's. A band starting at, say, 400,000 would require both
# sides to already hold a chainstate at 399,999 that was built the same way --
# which means replaying from genesis anyway. So the range is always [0, H], and
# H is the only knob.
#
# H also decides how REPRESENTATIVE the answer is, and the honest answer is
# "not very, until H is large". Blocks below ~200,000 carry a handful of
# transactions each; a run bounded there mostly measures block-file reading and
# database setup, not signature verification, and it will flatter whichever side
# has the cheaper fixed costs. Treat H < 300,000 as a smoke test of the harness,
# not as a result.
#
# ===========================================================================
# SAFETY -- what this script refuses to do
# ===========================================================================
#   - It never reads or writes /storage/bitcoin or touches bitcoind.service.
#   - It never writes to the live replay's datadir. The archive is opened
#     read-only and COPIED from; nothing is symlinked, because a symlinked
#     blk*.dat would let an appending writer reach the real archive.
#   - It never builds in, or writes to, /storage/bitcoin-core-source/build --
#     a Core oracle daemon runs from there.
#   - It refuses to start a timed run if the machine is busy, unless --force.
#     A tier-3 number taken under contention is worse than no number:
#     PERF_SCOPE.md section 9 documents a window where a change measured at
#     +16% on one function showed up as a 43% end-to-end IMPROVEMENT purely
#     because the competing load happened to ease.
#
# ===========================================================================
# USAGE
# ===========================================================================
#   scripts/bench_tier3.sh prepare-ours --height H [--src DIR] [--dest DIR]
#   scripts/bench_tier3.sh prepare-core --height H [--src DIR] [--dest DIR]
#   scripts/bench_tier3.sh run-ours     --height H [--dest DIR] [--cpus LIST]
#   scripts/bench_tier3.sh run-core     --height H [--dest DIR] [--cpus LIST]
#                                       [--par N] [--dbcache MB]
#   scripts/bench_tier3.sh check        # is the box quiet enough?
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUR_ARCHIVE="${OUR_ARCHIVE:-/storage/bitcoinmachinecode/data}"
CORE_BLOCKS="${CORE_BLOCKS:-/storage/core-oracle/blocks}"
CORE_BIN="${CORE_BIN:-/storage/bitcoin-core-source/build/bin/bitcoind}"
OUR_BIN="${OUR_BIN:-$REPO_ROOT/asm/daemon/bitcoind}"
WORK="${WORK:-/storage/bench-tier3}"

HEIGHT=""
CPUS="16-23"          # 8 cores, well away from cpu0
PAR=8                 # Core -par: script-verification threads
DBCACHE=4096          # MB
FORCE=0
CMD="${1:-}"; shift || true

while [ $# -gt 0 ]; do
    case "$1" in
        --height)  HEIGHT="$2"; shift 2 ;;
        --src)     SRC_OVERRIDE="$2"; shift 2 ;;
        --dest)    WORK="$2"; shift 2 ;;
        --cpus)    CPUS="$2"; shift 2 ;;
        --par)     PAR="$2"; shift 2 ;;
        --dbcache) DBCACHE="$2"; shift 2 ;;
        --force)   FORCE=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

die(){ echo "ERROR: $*" >&2; exit 1; }
say(){ printf '%s\n' "$*"; }

# --------------------------------------------------------------------------
# Guard rails that apply to every subcommand.
# --------------------------------------------------------------------------
case "$WORK" in
    /storage/bitcoin|/storage/bitcoin/*|/storage/bitcoinmachinecode/data|/storage/bitcoinmachinecode/data/*|/storage/core-oracle|/storage/core-oracle/*|/storage/bitcoin-core-source*)
        die "--dest $WORK points at production/oracle state. Refusing." ;;
esac

quiet_check(){
    local load busy
    load=$(cut -d' ' -f1 /proc/loadavg)
    busy=$(ps -eo pcpu --no-headers | awk '{s+=$1} END {printf "%.0f", s/100}')
    say "loadavg(1m) = $load ; approx busy cores = $busy of $(nproc)"
    ps -eo pcpu,etime,comm --sort=-pcpu --no-headers | head -6 | sed 's/^/    /'
    if [ "$(printf '%.0f' "$load")" -gt 2 ]; then
        say ""
        say "The box is NOT quiet. A tier-3 run taken now measures contention, not code."
        say "Specifically: the live replay (bmc-bitcoind.service) and any other agents"
        say "share this machine's memory bandwidth and page cache no matter which cores"
        say "each side is pinned to, so taskset does not rescue a multi-hour run the way"
        say "it rescues a 40 ms microbenchmark."
        return 1
    fi
    return 0
}

need_quiet(){
    quiet_check && return 0
    [ "$FORCE" = 1 ] || die "refusing to take a timed measurement on a busy box (--force to override, and then SAY SO in the write-up)"
    say "--force given: proceeding anyway. The resulting number MUST be labelled contaminated."
}

# --------------------------------------------------------------------------
# prepare-ours: build a bounded, writable COPY of this project's archive.
#
# Layout of our archive (bitcoin_store.asm / bitcoin_headers.asm):
#   index.dat   : 48 bytes per height -- hash[32] file_no(u32) pos(u64) size(u32)
#   blk%05u.dat : block bodies, each preceded by an 8-byte frame
#   headers.dat : 112 bytes per height -- header[80] block_hash[32]
#   chainwork.dat : cumulative work; deliberately NOT copied, it is recomputed
#                   from headers when absent (see FEATURE_GAPS.md).
#
# Bounding is done by TRUNCATING index.dat to (H+1) records. There is no
# -stopatheight equivalent on the UTXO side: node_config's stopatheight clamps
# the DOWNLOAD span (daemon/main.c dlc_span), not utxo_live_catchup, which
# always runs to the store's tip. Truncating the index moves the tip, which is
# the bound that actually takes effect.
# --------------------------------------------------------------------------
prepare_ours(){
    [ -n "$HEIGHT" ] || die "prepare-ours needs --height"
    local src="${SRC_OVERRIDE:-$OUR_ARCHIVE}"
    local dest="$WORK/ours"
    [ -r "$src/index.dat" ] || die "no index.dat under $src"
    mkdir -p "$dest" || die "cannot create $dest"

    say "preparing our side: heights 0..$HEIGHT from $src (READ-ONLY) into $dest"
    python3 - "$src" "$dest" "$HEIGHT" <<'PY'
import os, struct, shutil, sys
src, dest, H = sys.argv[1], sys.argv[2], int(sys.argv[3])
rec = 48
with open(os.path.join(src, "index.dat"), "rb") as f:
    f.seek(0, 2)
    total = f.tell() // rec
    if H >= total:
        sys.exit("archive holds %d records; --height %d is past its tip" % (total, H))
    f.seek(0)
    data = f.read((H + 1) * rec)
files = set()
for h in range(H + 1):
    r = data[h*rec:(h+1)*rec]
    fno, pos, sz = struct.unpack_from("<IQ", r, 32)[0], struct.unpack_from("<Q", r, 36)[0], struct.unpack_from("<I", r, 44)[0]
    if sz == 0:
        sys.exit("hole at height %d -- the archive is not contiguous over this range" % h)
    files.add(fno)
print("  heights 0..%d span %d blk file(s): %s" % (H, len(files), sorted(files)))
total_bytes = 0
for fno in sorted(files):
    name = "blk%05u.dat" % fno
    s, d = os.path.join(src, name), os.path.join(dest, name)
    total_bytes += os.path.getsize(s)
    if os.path.exists(d) and os.path.getsize(d) == os.path.getsize(s):
        continue
    print("  copying %s (%.1f GB so far)" % (name, total_bytes/1e9))
    shutil.copyfile(s, d)          # a real copy, never a symlink -- see header
with open(os.path.join(dest, "index.dat"), "wb") as f:
    f.write(data)
hp = os.path.join(src, "headers.dat")
if os.path.exists(hp):
    with open(hp, "rb") as f:
        hdr = f.read((H + 1) * 112)
    with open(os.path.join(dest, "headers.dat"), "wb") as f:
        f.write(hdr)
    print("  headers.dat truncated to %d records" % ((H+1)))
for junk in ("chainwork.dat",):
    p = os.path.join(dest, junk)
    if os.path.exists(p):
        os.remove(p)
        print("  removed %s (recomputed from headers at boot)" % junk)
print("  total blk bytes copied: %.1f GB" % (total_bytes/1e9))
PY
    [ $? -eq 0 ] || die "prepare-ours failed"

    # Networking fully off: this run must read blocks from the local copy only,
    # exactly like Core's -reindex side. Any peer traffic would make the two
    # incomparable and would also put load on the oracle.
    # connect= is the ONLY setting that actually takes this node offline.
    # MEASURED 2026-08-22, the first time this harness was run: with
    # listen=0 dnsseed=0 maxconnections=0 the daemon still printed
    #   [boot] dnsseed=0 -- not querying the DNS seeds
    #   [dl] no discovered peers; temporary seed fallback
    # and then dialled seed.bitcoin.sipa.be, dnsseed.bluematt.me and two more,
    # and downloaded 350 blocks past the truncated tip within three minutes --
    # which would have silently un-bounded the range and put the run's block
    # source back on the network. The fallback at daemon/main.c:2066 is
    # deliberate ("DEGRADED fallback so the node still syncs") but it consults
    # neither dnsseed nor maxconnections. daemon/main.c:1020 shows connect_only
    # is the one flag that short-circuits all discovery, so that is what is set
    # here. This is reported in BENCHMARKS.md, not fixed here.
    #
    # 192.0.2.1 is RFC 5737 TEST-NET-1: guaranteed never routed. It must NOT be
    # 127.0.0.1 -- the production node listens on 8333 and this node's config
    # only supports port 8333 for named peers, so a loopback entry would dial
    # straight into production.
    cat > "$dest/bitcoin.conf" <<EOF
# scripts/bench_tier3.sh -- bounded full-verification replay, no networking.
connect=192.0.2.1
listen=0
dnsseed=0
txindex=0
prune=0
dbcache=$DBCACHE
EOF
    say "prepared. Blocks 0..$HEIGHT, networking off, config written."
    say "NOTE: this node has no -assumevalid to disable -- it never had one."
    say "      node_config.c logs 'assumevalid IGNORED'. Full script verification"
    say "      on every historical block is unconditional here, which is exactly"
    say "      why Core must be given -assumevalid=0 to match."
}

# --------------------------------------------------------------------------
# prepare-core: a bounded, writable COPY of the oracle's block files.
#
# Copied, never hardlinked or symlinked: the oracle is a RUNNING bitcoind and it
# appends to its newest blk file. A hardlink would let Core's reindex and the
# oracle's writer share an inode. The newest file is skipped for the same reason.
# --------------------------------------------------------------------------
prepare_core(){
    [ -n "$HEIGHT" ] || die "prepare-core needs --height"
    local src="${SRC_OVERRIDE:-$CORE_BLOCKS}"
    local dest="$WORK/core"
    [ -d "$src" ] || die "no block directory at $src"
    mkdir -p "$dest/blocks" || die "cannot create $dest/blocks"

    # Core's blk files are written in chain order during IBD, so heights 0..H
    # live in the first ceil(bytes/128MB) files. Rather than parse leveldb, take
    # generous coverage: 1 GB of blk data per ~24,000 early blocks is far more
    # than needed, and -stopatheight bounds the actual work regardless of how
    # many files are present. Extra files cost disk and index time, not
    # correctness.
    # The destination MUST be pristine. MEASURED 2026-08-22: a first attempt was
    # made without blocks/xor.dat, so Core generated its own obfuscation key and
    # -- because -reindex opens the block files for writing -- rewrote the head
    # of blk00000.dat under that new key and truncated it. Re-copying xor.dat
    # afterwards then left the directory internally inconsistent, and every
    # subsequent reindex reported "Loaded 0 blocks from external file" for all
    # 15 files while printing no error at all. A reused blocks/ directory is
    # therefore treated as poisoned, not as a cache.
    if [ -n "$(ls -A "$dest/blocks" 2>/dev/null)" ]; then
        if [ "$FORCE" = 1 ]; then
            say "  --force: wiping the existing $dest/blocks (it may have been rewritten by a previous reindex)"
            rm -rf "$dest/blocks" "$dest/chainstate" "$dest/blocks.tmp"
            mkdir -p "$dest/blocks"
        else
            die "$dest/blocks is not empty. -reindex WRITES to block files, so a reused
       directory cannot be trusted as a source. Delete it, or pass --force."
        fi
    fi

    local newest count=0 total=0
    newest=$(ls -1 "$src"/blk*.dat 2>/dev/null | sort | tail -1)
    say "preparing Core side into $dest/blocks (skipping the oracle's newest file, $newest)"
    # Bytes-needed estimate. The old formula, HEIGHT*400 + 2GB, dropped a
    # factor of 1000: it multiplies by 400 BYTES per block where its own
    # calibration comment ("mainnet reaches ~500,000 in about 180 GB")
    # implies ~400 KB per block. 500,000*400 is 200 MB, so the cap was always
    # ~2 GB and any prepare-core past the earliest heights would have copied
    # far too little -- run-core then dies hours later at whatever height the
    # copied files happen to end. It never bit because the only run to date
    # was the H=1000 harness validation, where 2 GB is plenty.
    # MEASURED anchors (2026-08-23): 180 GB @ 500k (the original comment's
    # own anchor) and the oracle's blocks dir at 811 GB @ 963,764 -- so
    # blocks 500k..963k average ~1.36 MB each. Piecewise-linear between the
    # anchors, plus 5 GB margin; still capped by "never take the oracle's
    # active file".
    local need_bytes
    if [ "$HEIGHT" -le 500000 ]; then
        need_bytes=$(( (HEIGHT * 400000) + 5000000000 ))
    else
        need_bytes=$(( 180000000000 + (HEIGHT - 500000) * 1360000 + 5000000000 ))
    fi
    say "  copy budget: $(( need_bytes / 1000000000 )) GB for height $HEIGHT"
    for f in $(ls -1 "$src"/blk*.dat 2>/dev/null | sort); do
        [ "$f" = "$newest" ] && { say "  stop: reached the oracle's active file"; break; }
        cp "$f" "$dest/blocks/" || die "copy failed for $f"
        count=$((count+1))
        total=$((total + $(stat -c %s "$f")))
        if [ "$total" -gt "$need_bytes" ]; then
            say "  copied $count file(s), $(( total / 1000000000 )) GB -- enough for height $HEIGHT"
            break
        fi
    done
    [ "$count" -gt 0 ] || die "copied nothing -- is $src really Core's blocks dir?"

    # blocks/xor.dat is NOT optional. Since Core v28 every byte written to a blk
    # file is XORed with an 8-byte per-datadir key kept in blocks/xor.dat, and a
    # fresh datadir generates its own. MEASURED 2026-08-22: copying blk*.dat
    # without it produced a reindex that read all 15 files, reported "93%
    # complete", and then sat at height 0 -- Core had de-obfuscated every block
    # with the wrong key, so nothing parsed as a block and only the hard-coded
    # genesis was in the chain. It printed no error. Copy the key with the data.
    if [ -r "$src/xor.dat" ]; then
        cp -f "$src/xor.dat" "$dest/blocks/xor.dat" || die "could not copy xor.dat"
        say "  copied blocks/xor.dat (the block obfuscation key -- without it the"
        say "  copied blk files decode to garbage and the reindex silently stops at height 0)"
    else
        say "  NOTE: $src has no xor.dat, so these blocks are unobfuscated. Fine, but"
        say "  confirm the reindex actually reaches your target height before believing it."
    fi
    say "prepared. $count blk file(s), $(( total / 1000000000 )) GB."
}

# --------------------------------------------------------------------------
# The two timed runs.
# --------------------------------------------------------------------------
run_ours(){
    [ -n "$HEIGHT" ] || die "run-ours needs --height"
    local dest="$WORK/ours"
    [ -r "$dest/index.dat" ] || die "run prepare-ours first"
    [ -x "$OUR_BIN" ] || die "no daemon at $OUR_BIN (build it: cd asm && make daemon/bitcoind)"
    need_quiet

    local log="$WORK/ours-run-$(date -u +%Y%m%dT%H%M%SZ).log"
    rm -f "$dest/utxo_applied_height.dat"
    local idx_before
    idx_before=$(stat -c %s "$dest/index.dat")
    say "starting our replay: 0..$HEIGHT, pinned to cpus $CPUS, log $log"

    # `serve` has no "stop when caught up" mode -- it keeps serving. So the run
    # is timed by POLLING the applied-height checkpoint, which utxo_live.c
    # rewrites after every block (12 bytes: u32 magic, i64 height), and stopped
    # as soon as it reaches H. Polling the checkpoint rather than the log is
    # deliberate: it is the post-condition the replay exists to produce, not a
    # message about it.
    local t0 t1 h=-1 last=-1 stall=0
    t0=$(date +%s.%N)
    taskset -c "$CPUS" "$OUR_BIN" serve "$dest" 18444 > "$log" 2>&1 &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        h=$(python3 -c "
import struct,sys
try:
    d=open('$dest/utxo_applied_height.dat','rb').read()
    print(struct.unpack_from('<q', d, 4)[0] if len(d)>=12 else -1)
except Exception:
    print(-1)" 2>/dev/null)
        [ "$h" -ge "$HEIGHT" ] 2>/dev/null && break
        if [ "$h" = "$last" ]; then stall=$((stall+1)); else stall=0; last=$h; fi
        # 20 minutes with no progress at all means something is wrong, not slow.
        if [ "$stall" -gt 1200 ]; then say "STALLED at applied height $h"; break; fi
        sleep 1
    done
    t1=$(date +%s.%N)

    # Stop it. SIGTERM first; the catch-up loop checks a shutdown flag at each
    # block boundary. SIGKILL only if it does not go, which is safe here because
    # $dest is a disposable copy, never the live archive.
    pkill -TERM -P "$pid" 2>/dev/null; kill -TERM "$pid" 2>/dev/null
    local w=0
    while kill -0 "$pid" 2>/dev/null && [ "$w" -lt 30 ]; do sleep 1; w=$((w+1)); done
    pkill -KILL -f "serve $dest" 2>/dev/null; kill -KILL "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null

    # ---- post-conditions, asserted rather than suggested --------------------
    # This node cannot be taken fully offline by configuration. MEASURED
    # 2026-08-22: even with connect=192.0.2.1, which the boot path honours
    # ("[boot] connect= set -- skipping all peer discovery", daemon/main.c:1020),
    # the download worker's degraded fallback at daemon/main.c:2066 still fires
    # and dials the hard-coded DNS seeds -- it consults neither dnsseed nor
    # maxconnections nor connect_only, though the code at main.c:1017 states
    # connect= means "these are the ONLY peers. No DNS, no seednode getaddr, no
    # book growth". Unprivileged network namespaces are unavailable on this box
    # (`unshare -rn` -> "write failed /proc/self/uid_map: Operation not
    # permitted"), so the harness cannot enforce isolation either. What it CAN
    # do is check the post-condition -- did the archive grow? -- and refuse to
    # report a rate if it did. Reported in BENCHMARKS.md, not fixed here.
    local idx_after leaks
    idx_after=$(stat -c %s "$dest/index.dat")
    leaks=$(grep -c 'seed fallback' "$log" 2>/dev/null || echo 0)

    say ""
    say "applied height reached: $h  (target $HEIGHT)"
    say "elapsed: $(echo "$t1 - $t0" | bc) s"
    say "index.dat: $idx_before -> $idx_after bytes (expected $(( (HEIGHT+1) * 48 )), unchanged)"
    say "seed-fallback lines in the log: $leaks (should be 0; see the comment above)"

    if [ "$idx_after" != "$idx_before" ]; then
        say ""
        say "REFUSING TO REPORT A RATE: the archive grew during the run, so blocks were"
        say "downloaded from the network and the range was NOT bounded to $HEIGHT."
        say "Discard this run."
        return 1
    fi
    if [ "$h" -ge "$HEIGHT" ] 2>/dev/null; then
        say "rate: $(echo "scale=2; ($HEIGHT + 1) / ($t1 - $t0)" | bc) blocks/s over heights 0..$HEIGHT"
        [ "$leaks" = 0 ] || say "  (the run did contact a DNS seed; it downloaded nothing, but say so)"
    else
        say "DID NOT REACH $HEIGHT -- this is not a result. See $log"
        return 1
    fi
}

run_core(){
    [ -n "$HEIGHT" ] || die "run-core needs --height"
    local dest="$WORK/core"
    [ -d "$dest/blocks" ] || die "run prepare-core first"
    [ -x "$CORE_BIN" ] || die "no bitcoind at $CORE_BIN"
    case "$dest" in /storage/bitcoin|/storage/bitcoin/*) die "refusing" ;; esac
    need_quiet

    local log="$WORK/core-run-$(date -u +%Y%m%dT%H%M%SZ).log"
    say "starting Core: reindex to height $HEIGHT with FULL script verification"
    say "  -assumevalid=0 is what makes this comparable at all. Core's default"
    say "  skips script checks below a hard-coded known-good hash, and its"
    say "  advertised IBD times reflect that shortcut."
    local t0 t1
    t0=$(date +%s.%N)
    taskset -c "$CPUS" "$CORE_BIN" \
        -datadir="$dest" \
        -reindex \
        -assumevalid=0 \
        -stopatheight="$HEIGHT" \
        -par="$PAR" \
        -dbcache="$DBCACHE" \
        -connect=0 -listen=0 -dnsseed=0 -natpmp=0 \
        -rpcport=18443 -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 -port=18445 \
        -txindex=0 -blockfilterindex=0 -coinstatsindex=0 \
        -printtoconsole=1 -debug=bench \
        > "$log" 2>&1
    t1=$(date +%s.%N)

    # Post-condition, asserted. Core exits on its own when -stopatheight is
    # reached; if it exits for any other reason the elapsed time is not a
    # measurement of anything. The tip height is read from Core's own UpdateTip
    # line rather than inferred from the exit status.
    local tip
    tip=$(grep -oE 'UpdateTip: new best=[0-9a-f]+ height=[0-9]+' "$log" | tail -1 | grep -oE '[0-9]+$')
    tip="${tip:--1}"
    say ""
    say "Core tip reached: $tip  (target $HEIGHT)"
    say "elapsed: $(echo "$t1 - $t0" | bc) s"
    if [ "$tip" -ge "$HEIGHT" ] 2>/dev/null; then
        say "rate: $(echo "scale=2; ($HEIGHT + 1) / ($t1 - $t0)" | bc) blocks/s over heights 0..$HEIGHT"
    else
        say "DID NOT REACH $HEIGHT -- this is not a result."
        say "  Most likely cause: blocks/xor.dat missing or from a different datadir."
        say "  grep -E 'Reindexing|UpdateTip|Error' $log | tail"
        return 1
    fi
    say ""
    say "Core's own accounting, for cross-checking the wall time:"
    grep -E 'Connect block|Connect total|Flush|Verify [0-9]+ txins' "$log" | tail -8 | sed 's/^/    /'
}

case "$CMD" in
    prepare-ours) prepare_ours ;;
    prepare-core) prepare_core ;;
    run-ours)     run_ours ;;
    run-core)     run_core ;;
    check)        quiet_check ;;
    *) sed -n '2,60p' "$0"; exit 2 ;;
esac
