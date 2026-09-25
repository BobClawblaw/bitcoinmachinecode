#!/bin/bash
# build_tools.sh -- the daemon's helper tools, natively on macOS/arm64 (bmc_osx).
#
# The x86 Makefile builds every daemon/bmc_* tool; the Mac scripts built only
# bmcbitcoind (build_daemon.sh) and bmc_wallet_cli (build_wallet_cli.sh), so
# the tests that exec a tool -- the index builders, the merger, bmc_cli,
# bmc_rpcd, the daemon itself -- found nothing at the path they spawn
# (phase-4 sweep, 2026-09-25). This builds each tool from ITS OWN Makefile
# rule: the .c files on the rule's recipe line, linked STRICTLY (no
# -undefined dynamic_lookup) against the objects build_daemon.sh left in
# port/osx/daemon_out -- the Mac twins stand in for the x86 .o files by
# symbol. A tool that needs code only the x86 build has fails to link and is
# reported with the missing symbols, instead of crashing where it calls them.
#
# Installs into asm/daemon/ (gitignored), where the tests and the daemon look.
# Usage: build_tools.sh [tool ...]     (default: every daemon/bmc_* rule)
# Run build_daemon.sh first.
set -u
cd "$(dirname "$0")/../../asm"
OUT=../port/osx/daemon_out
[ -f "$OUT/bmcbitcoind" ] || { echo "run port/osx/build_daemon.sh first"; exit 2; }
CC="cc -O2 -arch arm64 -I. -Idaemon -Itests -I../port/osx/compat -D_DARWIN_C_SOURCE -Dst_mtim=st_mtimespec -Dst_atim=st_atimespec -Dst_ctim=st_ctimespec -w"
W=$(mktemp -d "${TMPDIR:-/tmp}/bmc_tools.XXXX")
trap 'rm -rf "$W"' EXIT

if [ $# -gt 0 ]; then TOOLS="$*"
else TOOLS=$(grep -o -E '^daemon/bmc_[a-z0-9_]+:' Makefile | sed 's#^daemon/##; s#:$##' | sort -u); fi

ok=0; fail=0; failed=""
for t in $TOOLS; do
    case "$t" in
      bmc_wallet_cli)                                   # its own script (build_wallet_cli.sh)
        bash ../port/osx/build_wallet_cli.sh >/dev/null 2>&1 && cp "$OUT/bmc_wallet_cli" daemon/ \
            && { echo "  ok   $t"; ok=$((ok+1)); } || { echo "  FAIL $t (build_wallet_cli.sh)"; fail=$((fail+1)); failed="$failed $t"; }
        continue;;
    esac
    # the rule's first recipe line (tab-indented, right after the target line)
    recipe=$(awk -v tgt="daemon/$t:" 'found && /^\t/ {print; exit} index($0, tgt) == 1 {found=1}' Makefile)
    srcs=$(echo "$recipe" | tr ' ' '\n' | grep -E '\.c$' | tr '\n' ' ')
    [ -n "$srcs" ] || { echo "  skip $t (no .c on its recipe line)"; continue; }
    # daemon_out minus main.o and minus the objects of this tool's own sources
    excl='/main\.o$'; for s in $srcs; do excl="$excl|/$(basename "${s%.c}")\.o$"; done
    rm -f "$W/lib.a"; ar rcs "$W/lib.a" $(ls $OUT/*.o | grep -v -E "$excl")
    # tx_relay.c's WEAK hooks, defined only in the daemon's main.c and checked
    # with `if (fn)` before any call: ELF leaves an undefined weak reference
    # NULL; ld64 still refuses it unless told the symbol may stay undefined.
    WEAK="-Wl,-U,_rpc_note_msg_recv -Wl,-U,_txr_report_violation_fd -Wl,-U,_txr_source_group_fd"
    if $CC -o "daemon/$t" $srcs "$W/lib.a" "$OUT/addrbook.a" -lpthread $WEAK 2>"$W/$t.err"; then
        echo "  ok   $t"; ok=$((ok+1))
    else
        miss=$(grep -o -E '"_[A-Za-z0-9_]+"' "$W/$t.err" | tr -d '"' | sed 's/^_//' | sort -u | head -6 | tr '\n' ' ')
        err=$(grep -m1 -E 'error' "$W/$t.err" | cut -c1-100)
        echo "  FAIL $t -- ${miss:+missing: $miss}${miss:-$err}"; fail=$((fail+1)); failed="$failed $t"
        rm -f "daemon/$t"
    fi
done
# the daemon itself, where the tests that start one look for it
[ $# -eq 0 ] && cp "$OUT/bmcbitcoind" daemon/bmcbitcoind && echo "  ok   bmcbitcoind (copied from daemon_out)"
echo "built $ok, failed $fail${failed:+:$failed}"
[ $fail -eq 0 ]
