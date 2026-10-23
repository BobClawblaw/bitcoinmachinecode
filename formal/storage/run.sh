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
if [ -z "${ONLY:-}" ] || [[ crash =~ $ONLY ]]; then
    bin="$SCRATCH/crash_storage"
    if ! "$here/crash/build.sh" "$bin" > "$SCRATCH/crash-build.log" 2>&1; then echo "crash build FAILED (see $SCRATCH/crash-build.log)"; fail=1
    else
        for s in ghostkill ghostkill-ctl ghostkill-close flushundo flushundo-ctl walwb logoff logoff-ctl archive archive-ctl; do
            waitmem; st=$(date +%s)
            rm -rf "$SCRATCH/crash-$s"
            $LIM timeout 600 "$bin" "$s" "$SCRATCH/crash-$s" > "$SCRATCH/crash-$s.log" 2>&1; rc=$?
            printf '%-34s %s  %3ss  %s\n' "crash:$s" "$(tail -1 "$SCRATCH/crash-$s.log")" $(( $(date +%s) - st )) "$([ $rc = 0 ] && echo ok || echo MISMATCH)"
            [ $rc = 0 ] || fail=1
        done
    fi
fi
echo "total $(( $(date +%s) - t0 ))s; logs in $SCRATCH; $([ $fail = 0 ] && echo ALL AS EXPECTED || echo SOME CHECKS DID NOT END AS EXPECTED)"
exit $fail
