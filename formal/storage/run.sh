#!/bin/bash
# formal/storage/run.sh -- every TLC check of StorageCrash.tla and every
# crash-injection confirmation, each against its expected outcome.
# Exits 0 only if every check ends as recorded in README.md (PASS where the
# property must hold, VIOLATED where a mutation, a defect or a vacuity probe
# must make it fail).
#
#   FORMAL_TOOLS (default $HOME/.local/opt/formal): jre/ and tla2tools.jar
#   SCRATCH      (default a mktemp dir): TLC metadirs, crash-test directories
#   ONLY=<regex> runs only the checks whose name matches
#   STORAGE_EXPECT=fixed (default) | found
#                fixed: the code has the STO-A..E/D/W fixes (main since #431,
#                #432): asm's tests/test_sto_crash (the crash driver turned
#                around) must heal in every scenario, and each mutant that
#                removes one fix piece must fail its scenario.
#                found: the code before the fixes (b841251b): crash/ must
#                reproduce every hole and keep every control clean.
#                The TLC checks model the protocol, not a commit: the same in
#                both modes.
set -u
FORMAL_TOOLS=${FORMAL_TOOLS:-$HOME/.local/opt/formal}
here=$(cd "$(dirname "$0")" && pwd)
SCRATCH=${SCRATCH:-$(mktemp -d)}
mkdir -p "$SCRATCH"
LIM="systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15"
fail=0; t0=$(date +%s)

waitmem(){ while [ "$(free -g | awk '/Mem:/{print $7}')" -lt 25 ]; do sleep 30; done; }

# cfg <name> key=value ... : write a TLC config (defaults = the fixed protocol)
cfg(){
    local name=$1; shift
    declare -A v=( [N]=2 [ASYNC]=TRUE [FS]='"ext4"' [MaxFlush]=2 [CompactOn]=TRUE [MaxCrash]=2
                   [PowerOn]=TRUE [KillOn]=TRUE [MaxDirFail]=1 [FixUndo]=TRUE [FixRecov]=TRUE
                   [FixArch]=TRUE [FixDir]=TRUE [FixLogOff]=TRUE [FixWeakDir]=TRUE [MUT]='"none"' )
    local inv="RecConsistent NoResurrection NoLoss HeightInRange UndoAgrees StoreReadable NoFalseReject ArchiveCovers SteadyState"
    for kv in "$@"; do
        case $kv in INV=*) inv=${kv#INV=} ;; *) v[${kv%%=*}]=${kv#*=} ;; esac
    done
    { echo "CONSTANTS"; for k in N ASYNC FS MaxFlush CompactOn MaxCrash PowerOn KillOn MaxDirFail \
        FixUndo FixRecov FixArch FixDir FixLogOff FixWeakDir MUT; do echo "  $k = ${v[$k]}"; done
      echo "SPECIFICATION Spec"; echo "INVARIANTS $inv"; echo "CHECK_DEADLOCK FALSE"; } > "$SCRATCH/$name.cfg"
}
# tlc <name> <expect: PASS|VIOLATED> [<invariant that must be the one violated>]
tlc(){
    local name=$1 expect=$2 want=${3:-}
    [ -n "${ONLY:-}" ] && ! [[ $name =~ $ONLY ]] && return
    waitmem
    local s=$(date +%s) log="$SCRATCH/$name.log"
    ( cd "$here/tla" && $LIM timeout 1800 "$FORMAL_TOOLS/jre/bin/java" -Xmx6g -XX:+UseParallelGC \
        -cp "$FORMAL_TOOLS/tla2tools.jar" tlc2.TLC -workers 4 -metadir "$SCRATCH/meta-$name" \
        -config "$SCRATCH/$name.cfg" StorageCrash.tla ) > "$log" 2>&1
    local got=OTHER inv=$(grep -oE 'Invariant [A-Za-z]+ is violated' "$log" | awk '{print $2}')
    if [ -n "$inv" ]; then got=VIOLATED
    elif grep -q 'No error has been found' "$log"; then got=PASS; fi
    local st=$(grep -oE '[0-9,]+ distinct states found' "$log" | tail -1 | cut -d' ' -f1)
    local ok=1
    [ "$got" = "$expect" ] || ok=0
    [ -n "$want" ] && [ "$inv" != "$want" ] && ok=0
    printf '%-34s expect %-8s got %-8s %-16s %10s states %5ss %s\n' "$name" "$expect" "$got" "${inv:-}" "${st:-?}" $(( $(date +%s) - s )) \
        "$([ $ok = 1 ] && echo ok || echo MISMATCH)"
    [ $ok = 1 ] || fail=1
}

# ---- 1. the protocol as written (no candidate fix) ----
cfg faithful-ext4    N=3 MaxFlush=1 CompactOn=FALSE MaxCrash=1 MaxDirFail=0 FixUndo=FALSE FixRecov=FALSE FixArch=FALSE FixDir=FALSE FixLogOff=FALSE FixWeakDir=FALSE
cfg faithful-weak    N=3 MaxFlush=1 CompactOn=FALSE MaxCrash=1 MaxDirFail=0 FixUndo=FALSE FixRecov=FALSE FixArch=FALSE FixDir=FALSE FixLogOff=FALSE FixWeakDir=FALSE FS='"weak"'
tlc faithful-ext4 VIOLATED
tlc faithful-weak VIOLATED
# ---- 2. one hole at a time: every candidate fix on except the one under test ----
cfg hole-A-undo-ext4    FixUndo=FALSE INV=RecConsistent
cfg hole-A-undo-weak    FixUndo=FALSE INV=RecConsistent FS='"weak"'
cfg hole-B-recov-kill   PowerOn=FALSE FixRecov=FALSE INV=RecConsistent
cfg hole-B-fixed-kill   PowerOn=FALSE N=3
cfg hole-C-arch-ext4    FixArch=FALSE INV=ArchiveCovers
cfg hole-E-logoff-ext4  FixLogOff=FALSE INV=RecConsistent
cfg hole-E-logoff-weak  FixLogOff=FALSE INV=RecConsistent FS='"weak"'
cfg hole-D-dirfail-ext4 FixDir=FALSE
cfg hole-D-dirfail-weak FixDir=FALSE FS='"weak"'
cfg hole-W-weakdir-weak FixWeakDir=FALSE FS='"weak"'
cfg hole-W-weakdir-ext4 FixWeakDir=FALSE
tlc hole-A-undo-ext4    VIOLATED RecConsistent
tlc hole-A-undo-weak    VIOLATED RecConsistent
tlc hole-B-recov-kill   VIOLATED RecConsistent
tlc hole-B-fixed-kill   PASS
tlc hole-C-arch-ext4    VIOLATED ArchiveCovers
tlc hole-E-logoff-ext4  VIOLATED RecConsistent
tlc hole-E-logoff-weak  VIOLATED RecConsistent
tlc hole-D-dirfail-ext4 PASS
tlc hole-D-dirfail-weak VIOLATED
tlc hole-W-weakdir-weak VIOLATED StoreReadable
tlc hole-W-weakdir-ext4 PASS
# ---- 3. the protocol with every candidate fix: must hold ----
for fs in ext4 weak; do for as in TRUE FALSE; do
    n=fixed-$fs-$([ $as = TRUE ] && echo async || echo inline)
    cfg $n FS="\"$fs\"" ASYNC=$as
    cfg $n-n3 FS="\"$fs\"" ASYNC=$as N=3 MaxFlush=1 CompactOn=FALSE MaxCrash=2 MaxDirFail=0
    tlc $n PASS
    tlc $n-n3 PASS
done; done
cfg fixed-ext4-async-n3full N=3
tlc fixed-ext4-async-n3full PASS
# ---- 4. vacuity: recovery and the end are reachable in the fixed model ----
cfg vac-recovers INV=NeverRecovers
cfg vac-ends     INV=NeverEnds
tlc vac-recovers VIOLATED NeverRecovers
tlc vac-ends     VIOLATED NeverEnds
# ---- 5. mutations of the fixed model: each must fail ----
cfg mut-noWalFsync     MUT='"noWalFsync"'
cfg mut-noUndoSync     MUT='"noUndoSync"' FixUndo=FALSE
cfg mut-noDirSync      MUT='"noDirSync"' FS='"weak"'
cfg mut-truncBeforeDir MUT='"truncBeforeDir"' ASYNC=FALSE FS='"weak"'
cfg mut-punchBeforeIdx MUT='"punchBeforeIdx"'
cfg mut-noRunFsync     MUT='"noRunFsync"'
for m in noWalFsync noUndoSync noDirSync truncBeforeDir punchBeforeIdx noRunFsync; do tlc mut-$m VIOLATED; done

# ---- 6. crash injection on the real code ----
EXPECT=${STORAGE_EXPECT:-fixed}
crash_found(){
    local bin="$SCRATCH/crash_storage"
    if ! "$here/crash/build.sh" "$bin" > "$SCRATCH/crash-build.log" 2>&1; then echo "crash build FAILED (see $SCRATCH/crash-build.log)"; fail=1; return; fi
    for s in ghostkill ghostkill-ctl ghostkill-close flushundo flushundo-ctl walwb logoff logoff-ctl archive archive-ctl; do
        waitmem; st=$(date +%s)
        rm -rf "$SCRATCH/crash-$s"
        $LIM timeout 600 "$bin" "$s" "$SCRATCH/crash-$s" > "$SCRATCH/crash-$s.log" 2>&1; rc=$?
        printf '%-34s %s  %3ss  %s\n' "crash:$s" "$(tail -1 "$SCRATCH/crash-$s.log")" $(( $(date +%s) - st )) "$([ $rc = 0 ] && echo ok || echo MISMATCH)"
        [ $rc = 0 ] || fail=1
    done
}
# The fixed code. crash/ does not carry over: the fix removed the block-end
# WAL drain, so its walwb image holds no record of 151..152 to lose (it heals
# with nothing at stake), and its archive scenario cuts the index.dat record
# by hand, a write the fix now syncs (it "reproduces" a state the code no
# longer reaches). tests/test_sto_crash is the same trace set rewritten for
# the fixed code (an explicit drain where a full buffer would land, the
# archive image from the recorded syncs alone) plus the D/W scenarios. Its
# mutants run on a copy of asm/ in SCRATCH, so the worktree is never edited.
STO_SCEN=42   # 21 scenarios x {scenario, control}
# mutant <name> <file> <perl substitution> <scenario that must fail>...
STO_MUT=(
  "pre-drain-hook|daemon/utxo_live.c|s/utxo_store_set_predrain_hook\(live_durable_prefix\);/utxo_store_set_predrain_hook(0);/|STO-A1 flushundo|STO-A2 walwb|STO-A3 cbflush"
  "discard-hook|daemon/utxo_live.c|s/undo_set_discard_hook\(live_before_discard\);/undo_set_discard_hook(0 ? live_before_discard : 0);/|STO-B ghostkill"
  "archive-sync|daemon/utxo_live.c|s/if \(archive_sync_heights\(g_pfx_lo, g_pfx_hi\) != 0\)\{/if (0 \&\& archive_sync_heights(g_pfx_lo, g_pfx_hi) != 0){/|STO-C1 archive|STO-C2 archive-nosync"
  "logoff-fsync+heal|daemon/utxo_live.c bitcoin_utxo_store.asm|s/if \(g_utxo_lst.log_fd >= 0 \&\& fsync\(\(int\)g_utxo_lst.log_fd\) != 0\)\{(\n\s+fprintf\(stderr, \"\[utxo_live\] WARNING: fsync of the WAL before retiring)/if (0){\1/;s/    cmp  rax, rbx\n    jbe  \.lo_ok\n/    cmp  rax, rbx\n    jmp  .lo_ok\n/|STO-E logoff"
  "retire-dir-retry|daemon/utxo_live.c|s/    if \(g_fz_dir_unsynced\)\{\n        if \(lsm_dir_sync\(\) != 0\)\{/    if (0){\n        if (lsm_dir_sync() != 0){/|STO-D1 dirpub"
  "publish-pre-rename-fsync|daemon/lsm_manifest.c|s/    if \(lsm_dir_sync\(\) != 0\) return -1;\n    int fd = open\(LSM_MANIFEST_PUB/    if (0 \&\& lsm_dir_sync() != 0) return -1;\n    int fd = open(LSM_MANIFEST_PUB/|STO-W1 runcreate"
)
crash_fixed(){
    local repo=$(cd "$here/../.." && pwd) w="$SCRATCH/asm-copy"
    rm -rf "$w"; mkdir -p "$w"
    ( cd "$repo" && git ls-files -z asm | tar --null -T - -cf - ) | tar -C "$w" -xf - || { echo "crash: copy of asm/ FAILED"; fail=1; return; }
    local a="$w/asm"
    sto_run(){  # build + run; $1 = log name
        $LIM timeout 1800 make -C "$a" -j8 tests/test_sto_crash > "$SCRATCH/$1.build" 2>&1 || return 2
        ( cd "$a" && $LIM timeout 900 ./tests/test_sto_crash ) > "$SCRATCH/$1.log" 2>&1
        return 0
    }
    waitmem; local st=$(date +%s)
    if ! sto_run crash-fixed; then echo "crash: test_sto_crash build FAILED (see $SCRATCH/crash-fixed.build)"; fail=1; return; fi
    local np=$(grep -c '^PASS ' "$SCRATCH/crash-fixed.log") nf=$(grep -c '^FAIL ' "$SCRATCH/crash-fixed.log")
    local ok=$([ "$np" = $STO_SCEN ] && [ "$nf" = 0 ] && grep -q '^ALL TESTS PASSED' "$SCRATCH/crash-fixed.log" && echo ok || echo MISMATCH)
    printf '%-34s %s of %s healed, %s not  %4ss  %s\n' "crash:test_sto_crash" "$np" $STO_SCEN "$nf" $(( $(date +%s) - st )) "$ok"
    [ "$ok" = ok ] || fail=1
    for m in "${STO_MUT[@]}"; do
        IFS='|' read -r name files subst want <<< "$m"
        [ -n "${ONLY:-}" ] && ! [[ crash:mut-$name =~ $ONLY ]] && ! [[ crash =~ $ONLY ]] && continue
        local f changed=0
        for f in $files; do
            cp "$a/$f" "$SCRATCH/mut-orig-${f//\//_}"
            perl -0pi -e "$subst" "$a/$f"
            cmp -s "$a/$f" "$SCRATCH/mut-orig-${f//\//_}" || changed=$((changed + 1))
        done
        st=$(date +%s); local got="" res
        if [ $changed != $(wc -w <<< "$files") ]; then res="pattern did not apply"
        elif ! sto_run "crash-mut-$name"; then res="build FAILED"
        else
            got=$(grep -E '^FAIL ' "$SCRATCH/crash-mut-$name.log" | sed 's/^FAIL //; s/: NOT healed$//' | paste -sd, -)
            res=caught
            local sc; IFS='|' read -ra sc <<< "$want"
            for w in "${sc[@]}"; do grep -qxF "FAIL $w: NOT healed" "$SCRATCH/crash-mut-$name.log" || res="NOT caught by $w"; done
        fi
        printf '%-34s %-28s %4ss  %s  [failed: %s]\n' "crash:mut-$name" "$res" $(( $(date +%s) - st )) \
            "$([ "$res" = caught ] && echo ok || echo MISMATCH)" "${got:-none}"
        [ "$res" = caught ] || fail=1
        for f in $files; do cp "$SCRATCH/mut-orig-${f//\//_}" "$a/$f"; done
    done
}
if [ -z "${ONLY:-}" ] || [[ crash =~ $ONLY ]] || [[ $ONLY == crash* ]]; then
    case $EXPECT in
        found) crash_found ;;
        fixed) crash_fixed ;;
        *) echo "STORAGE_EXPECT must be fixed or found"; fail=1 ;;
    esac
fi
echo "total $(( $(date +%s) - t0 ))s; logs in $SCRATCH; $([ $fail = 0 ] && echo ALL AS EXPECTED || echo SOME CHECKS DID NOT END AS EXPECTED)"
exit $fail
