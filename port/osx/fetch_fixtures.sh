#!/bin/bash
# fetch_fixtures.sh -- the large, gitignored test fixtures, from the local Core.
#
# The x86 tree's `make fixtures` fetches them from the scratch oracle on the
# x86 box through bitcoin-cli. Here the same fetchers run against this Mac's
# Bitcoin Core (Bitcoin-Qt, RPC on 8332, txindex) through core_cli.py, a
# bitcoin-cli stand-in, via the CORE_CLI override the fetchers honour.
#
#   port/osx/fetch_fixtures.sh
#
# Fetches (into asm/tests/fixtures/, ~90 MB):
#   * the 36 taproot-dense blocks + prevouts of TAPROOT_DIFF_HEIGHTS, for
#     test_taproot_block_diff (it SKIPs without them);
#   * block413567.raw, the block Core's own benchmarks use, for
#     bench_abi_audit's cons_verify / hash160 sections and
#     test_strip_witness_diff (both SKIP without it; run_tests.sh points
#     CORE_BENCH_BLOCK at it when it is present).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here/../../asm"
export CORE_CLI="python3 $here/core_cli.py"
mkdir -p tests/fixtures

heights=$(make -s --no-print-directory -f <(printf 'include Makefile\nbmc-print-%%:\n\t@echo "$($*)"\n') bmc-print-TAPROOT_DIFF_HEIGHTS)
echo "== taproot blocks: $(echo $heights | wc -w | tr -d ' ') heights"
python3 validation/fetch_taproot_blocks.py $heights

echo "== block 413567"
hash=$($CORE_CLI getblockhash 413567)
$CORE_CLI getblock "$hash" 0 | xxd -r -p > tests/fixtures/block413567.raw
ls -l tests/fixtures/block413567.raw
