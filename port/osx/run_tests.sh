#!/bin/bash
# run_tests.sh -- `make test`, natively on macOS/arm64 (bmc_osx).
#
# Builds the Mac daemon objects (build_daemon.sh), the daemon's tools and the
# test helpers (build_tools.sh), then runs every ./tests/* command of
# asm/Makefile's `test:` recipe through run_tests.py, which knows how to link
# each test against the Mac objects (see its header). Exit status is 0 when
# every test is PASS, SKIP or N/A.
#
#   port/osx/run_tests.sh                    the whole suite
#   port/osx/run_tests.sh test_bip152 ...    only those tests
#   port/osx/run_tests.sh --no-build ...     skip the three build steps
#   port/osx/run_tests.sh --timeout 300 ...  per-test limit (default 900 s)
#   port/osx/run_tests.sh --out DIR ...      keep results in DIR
#
# The x86-only tests are reported N/A (port/OSX_STATE.md). Three tests need
# 127.0.0.2-4 on lo0 and SKIP with the command when they are absent:
#   sudo ifconfig lo0 alias 127.0.0.2 up   (and .3, .4)
set -u
here="$(cd "$(dirname "$0")" && pwd)"
build=1
args=()
for a in "$@"; do
    if [ "$a" = "--no-build" ]; then build=0; else args+=("$a"); fi
done
if [ $build -eq 1 ]; then
    echo "== building: daemon objects, tools, test helpers"
    bash "$here/build_daemon.sh" 2>&1 | tail -1 || exit 2
    bash "$here/build_tools.sh" 2>&1 | tail -1 || exit 2
    bash "$here/build_tools.sh" --test-helpers 2>&1 | tail -1 || exit 2
fi
exec python3 "$here/run_tests.py" ${args[@]+"${args[@]}"}
