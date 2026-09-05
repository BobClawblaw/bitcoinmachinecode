#!/bin/sh
# BLD-8 (audit 2026-09-03): does the committed script-flag table still match
# the Core tree on disk?
#
# validation/gen_script_flags.py DERIVES asm/script_flags_consts.{inc,h} from
# Core's kernel/chainparams.cpp and script/interpreter.h. It is run BY HAND
# after a Core upgrade, and nothing asserted the committed output still
# matched its inputs -- so a Core bump could silently leave this node's
# consensus flag schedule describing the previous release.
#
# This regenerates into a scratch directory and diffs. It does NOT overwrite
# the committed files: a generator that rewrites tracked sources during a test
# run would make the gate non-idempotent.
#
# SKIPS (exit 0) when the Core source tree is absent -- it is a developer
# checkout, not a build dependency, and a machine without it must still be
# able to run the gate.
set -eu
CORE_SRC=/storage/bitcoin-core-source
if [ ! -d "$CORE_SRC/src/kernel" ]; then
    echo "SCRIPT-FLAGS CHECK SKIPPED: no Core source tree at $CORE_SRC"
    exit 0
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cp asm/script_flags_consts.inc "$TMP/committed.inc"
cp asm/script_flags_consts.h   "$TMP/committed.h"
python3 validation/gen_script_flags.py >/dev/null 2>&1 || {
    echo "SCRIPT-FLAGS CHECK FAILED: the generator errored against the Core tree"
    python3 validation/gen_script_flags.py 2>&1 | tail -5
    exit 1
}
rc=0
if ! diff -u "$TMP/committed.inc" asm/script_flags_consts.inc; then rc=1; fi
if ! diff -u "$TMP/committed.h"   asm/script_flags_consts.h;   then rc=1; fi
if [ "$rc" -ne 0 ]; then
    # put the committed versions back so a failed check leaves no edit behind
    cp "$TMP/committed.inc" asm/script_flags_consts.inc
    cp "$TMP/committed.h"   asm/script_flags_consts.h
    echo "SCRIPT-FLAGS CHECK FAILED: the committed table does not match the Core"
    echo "  tree at $CORE_SRC. Re-run validation/gen_script_flags.py and review"
    echo "  the diff above -- this is a CONSENSUS table."
    exit 1
fi
echo "SCRIPT-FLAGS CHECK OK: the committed table matches $CORE_SRC"
