#!/usr/bin/env bash
# Proof-of-work proofs (rule group 2). Exits 0 only if every proof holds,
# every REACH witness is found and every mutant is caught. One line per
# check. Every solver/build runs through runlib's _lim (memory-capped scope).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../lib/runlib.sh"
A=$(cd "$here/../../../asm" && pwd)
PR=$A/bitcoin_pow_rules.c
HR=$A/daemon/hdrrules.h
G=$FORMAL_TOOLS/cbmc/usr/bin
U='--unwind 41 --unwinding-assertions --sat-solver cadical'
"$here/build.sh" || { echo "FAIL  build"; exit 1; }
B=$here/.build

ok_line(){ echo "PASS  $1  $2  $3  $4"; }
bad_line(){ echo "FAIL  $1  $2  $3  $4"; FAILS=$((FAILS+1)); }

# run_expect ID KIND WANT_RC_ZERO(1|0) CMD...   (KIND is a label)
run_expect(){
    local id=$1 kind=$2 want0=$3; shift 3
    local log=$LOGDIR/$id.$kind.log t=$(_t0)
    "$@" >"$log" 2>&1; local rc=$?
    local summary; summary=$(grep -E '^\[(P1|diff|port)\]|RESULT|repro|DIFFER' "$log" | tail -3 | tr '\n' ' ')
    if { [ "$want0" = 1 ] && [ $rc -eq 0 ]; } || { [ "$want0" = 0 ] && [ $rc -ne 0 ] && [ $rc -ne 124 ] && [ $rc -ne 137 ]; }; then
        ok_line "$id" "$kind" "$(_dt $t)" "rc=$rc $summary"
    else
        bad_line "$id" "$kind" "$(_dt $t)" "rc=$rc (see $log) $summary"
    fi
}

# prod_mutant ID FILE SED -- CMD-WITH-@F@ ...: copy a PRODUCT file to scratch,
# apply SED (must change it), run CMD with @F@ replaced by the copy's path;
# the run must report a failure (CBMC "VERIFICATION FAILED" or a nonzero rc).
prod_mutant(){
    local id=$1 f=$2 sedx=$3; shift 4
    local tmp; tmp=$(mktemp -d); local m=$tmp/$(basename "$f")
    cp "$f" "$m"; sed -i -E "$sedx" "$m"
    if cmp -s "$f" "$m"; then bad_line "$id" mutant - "sed did not change $(basename "$f")"; rm -rf "$tmp"; return; fi
    local args=() a; for a in "$@"; do args+=("${a//@F@/$m}"); done
    local log=$LOGDIR/$id.mutant.log t=$(_t0)
    ( cd "$tmp" && "${args[@]}" ) >"$log" 2>&1; local rc=$?
    # detection needs positive evidence from the checker, never just a nonzero
    # rc (a mutant that fails to build would otherwise count as "caught")
    if grep -qE '^VERIFICATION FAILED|^MISMATCH|mutant: DETECTED \(counterexample found\)' "$log"; then
        ok_line "$id" mutant "$(_dt $t)" "[$sedx] -> $(grep -m1 -E 'FAILURE|MISMATCH|NOT DETECTED|DETECTED|CEX' "$log" | sed 's/^ *//' | cut -c1-160)"
    else
        bad_line "$id" mutant "$(_dt $t)" "[$sedx] NOT detected (rc=$rc, see $log)"
    fi
    rm -rf "$tmp"
}
# a goto-cc + replace-calls pipeline for P4s
p4s(){ # p4s OUTDIR PRODFILE MODE [-DREACH]
    local d=$1 f=$2 mode=$3; shift 3
    _lim timeout 300 "$G/goto-cc" -DMODE=$mode "$@" -DBMC_POW_RULES_C="\"$f\"" -o "$d/s.gb" "$here/cbmc/p4s_schedule.c" &&
    _lim timeout 300 "$G/goto-instrument" --replace-calls pow_retarget_bits:stub_retarget "$d/s.gb" "$d/s2.gb" >/dev/null &&
    _lim timeout 900 "$CBMC" "$d/s2.gb" --unwind 6 --unwinding-assertions --sat-solver cadical
}

# ---- the Core reference itself: C port vs an independent Python transcription
run_expect PORT check 1 bash -c "_lim(){ systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 \"\$@\"; }; _lim timeout 300 '$B/diff_pow' dump 200000 | _lim timeout 300 '$PY' '$here/check_core_port.py'"

# ---- differential tests of the real objects (pow_check, diff_target, u256_div,
#      block_work, chainwork_add, pow_retarget_bits)
run_expect DIFF diff 1 _lim timeout 900 "$B/diff_pow" 2000000 1
prod_mutant DIFF-u256div "$A/bitcoin_chainwork.asm" 's/^    xor  eax, 1$/    nop/' -- \
    bash -c "systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 300 nasm -f elf64 -I'$A/' -Werror -o m.o @F@ && systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 300 gcc -no-pie -O2 -I'$here' -o d '$here/diff_pow.c' '$B/bitcoin_hash.o' m.o '$B/sha256.o' '$B/bitcoin_pow_rules.o' && systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 300 ./d 200000 1"
prod_mutant DIFF-retarget "$PR" 's/if \(ts > POW_TIMESPAN\*4\) ts = POW_TIMESPAN\*4;/if (ts > POW_TIMESPAN*4) ts = POW_TIMESPAN*4 + 1;/' -- \
    bash -c "systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 300 gcc -no-pie -O2 -I'$A' -c -o m.o @F@ && systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 300 gcc -no-pie -O2 -I'$here' -o d '$here/diff_pow.c' '$B/bitcoin_hash.o' '$B/bitcoin_chainwork.o' '$B/sha256.o' m.o && systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 300 ./d 200000 1"

# ---- P1: pow_check lifted with angr, every chain powLimit and the unarmed mode
run_expect P1 angr 1 _lim timeout 900 "$PY" "$here/p1_pow_check.py" "$B/bitcoin_hash.o" 0x1d00ffff 0x1e0377ae 0x207fffff 0x0
prod_mutant P1-limit "$A/bitcoin_hash.asm" 's/^    ja   \.invalid                  ; target > powLimit$/    jae  .invalid/' -- \
    bash -c "systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 300 nasm -f elf64 -I'$A/' -Werror -o m.o @F@ && systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 900 '$PY' '$here/p1_pow_check.py' m.o 0x1d00ffff --expect-fail"
prod_mutant P1-negative "$A/bitcoin_hash.asm" 's/^    test dword \[r12\+72\], 0x00800000$/    test dword [r12+72], 0/' -- \
    bash -c "systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 300 nasm -f elf64 -I'$A/' -Werror -o m.o @F@ && systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 900 '$PY' '$here/p1_pow_check.py' m.o 0x207fffff --expect-fail"

# ---- P2a / P3: powr_target_bytes and powr_compact (CBMC, real file included)
cbmc_prove P3  "$here/cbmc" p3_getcompact.c -DBMC_POW_RULES_C="\"$PR\"" --function p3 $U
cbmc_prove P2a "$here/cbmc" p3_getcompact.c -DBMC_POW_RULES_C="\"$PR\"" --function p2a $U
prod_mutant P3 "$PR" 's/if \(word & 0x00800000\)\{ word >>= 8; size\+\+; \}/if (word \& 0x00800000){ word >>= 8; }/' -- \
    _lim timeout 900 "$CBMC" "$here/cbmc/p3_getcompact.c" -I"$A" -DBMC_POW_RULES_C='"@F@"' --function p3 $U
prod_mutant P2a "$PR" 's/        word >>= 8 \* \(3 - size\);/        word >>= 8 * (2 - size);/' -- \
    _lim timeout 900 "$CBMC" "$here/cbmc/p3_getcompact.c" -I"$A" -DBMC_POW_RULES_C='"@F@"' --function p2a $U
# F1: put back the second shift that commit e0476262 removed; P3 must catch it
prod_mutant P3-F1 "$PR" 's/^    if \(word & 0x00800000\)\{ word >>= 8; size\+\+; \}$/    if (size < 3) word <<= 8 * (3 - size);\n&/' -- \
    _lim timeout 900 "$CBMC" "$here/cbmc/p3_getcompact.c" -I"$A" -DBMC_POW_RULES_C='"@F@"' --function p3 $U
run_expect F1 confirm 1 _lim timeout 60 "$B/confirm_p3c"

# ---- P4: retarget arithmetic: lemmas (z3) + cap lemma (CBMC); whole-function CBMC is OPEN
for l in 'unsigned long long v = (unsigned long long)n[i] * (unsigned long long)ts + carry;' \
         'n[i] = (u8)v; carry = v >> 8;' 'unsigned long long v = (rem << 8) | n[i];' \
         'n[i] = (u8)(v / (unsigned long long)POW_TIMESPAN);' 'rem = v % (unsigned long long)POW_TIMESPAN;' \
         'if (ts < POW_TIMESPAN/4) ts = POW_TIMESPAN/4;' 'if (ts > POW_TIMESPAN*4) ts = POW_TIMESPAN*4;' \
         '#define POW_TIMESPAN 1209600L'; do
    grep -qF -- "$l" "$PR" || bad_line P4-LEM grep - "modelled line changed: $l"
done
z3_run P4-LEM "$here/p4_lemmas.py"
for L in 0x1d00ffffu 0x1e0377aeu 0x207fffffu; do
    cbmc_prove P4-CAP-$L "$here/cbmc" p4_cap.c -DBMC_POW_RULES_C="\"$PR\"" -DCHAIN_BITS=$L $U
done
cbmc_reach P4-CAP-main "$here/cbmc" p4_cap.c -DBMC_POW_RULES_C="\"$PR\"" -DCHAIN_BITS=0x1d00ffffu $U

# ---- P4s: the schedule (goto-instrument --replace-calls isolates the arithmetic)
T4=$(mktemp -d)
for M in 1 2 3 4; do
    t=$(_t0); p4s "$T4" "$PR" $M >"$LOGDIR/P4s-$M.log" 2>&1
    if grep -q '^VERIFICATION SUCCESSFUL' "$LOGDIR/P4s-$M.log"; then ok_line P4s-mode$M proof "$(_dt $t)" ""; else bad_line P4s-mode$M proof "$(_dt $t)" "see $LOGDIR/P4s-$M.log"; fi
done
for M in 1 2; do
    t=$(_t0); p4s "$T4" "$PR" $M -DREACH >"$LOGDIR/P4s-r$M.log" 2>&1
    if grep -q '^VERIFICATION FAILED' "$LOGDIR/P4s-r$M.log" && ! grep -q 'REACH.*SUCCESS' "$LOGDIR/P4s-r$M.log"; then ok_line P4s-mode$M reach "$(_dt $t)" ""; else bad_line P4s-mode$M reach "$(_dt $t)" "see log"; fi
done
rm -rf "$T4"
prod_mutant P4s-bip94 "$PR" 's/u32 base_bits = enforce_bip94 \? rd32le\(hdr \+ 72\) : last_bits;/u32 base_bits = last_bits;/' -- \
    bash -c "$(declare -f _lim p4s); G='$G'; CBMC='$CBMC'; here='$here'; p4s . @F@ 2 -I'$A'"
prod_mutant P4s-20min "$PR" 's/if \(blocktime > \(long\)prev_time \+ 2\*POW_SPACING\) return pow_limit_bits;/if (blocktime >= (long)prev_time + 2*POW_SPACING) return pow_limit_bits;/' -- \
    bash -c "$(declare -f _lim p4s); G='$G'; CBMC='$CBMC'; here='$here'; p4s . @F@ 2 -I'$A'"

# ---- P5: u256_div / block_work / chainwork_add (hand semantics, z3)
for l in '    or   eax, r10d' '    setc r10b                       ; COUT (captured before anything clobbers CF)' \
         '    setc r11b                        ; CF_sub (1 = borrow, i.e. R<B)' '    cmp  ecx, 29' \
         '    jc   .overflow               ; target was 2^256-1 -> +1 wraps to 2^256' '    jnc  .no_ovf'; do
    grep -qF -- "$l" "$A/bitcoin_chainwork.asm" || bad_line P5 grep - "modelled line changed: $l"
done
z3_run P5 "$here/p5_work.py"

# ---- P6: BIP94 timewarp
cbmc_prove P6 "$here/cbmc" p6_timewarp.c -DHDRRULES_H="\"$HR\""
cbmc_reach P6 "$here/cbmc" p6_timewarp.c -DHDRRULES_H="\"$HR\""
prod_mutant P6 "$HR" 's/\(int64_t\)pt - HDR_MAX_TIMEWARP\)/(int64_t)pt - HDR_MAX_TIMEWARP - 1)/' -- \
    _lim timeout 300 "$CBMC" "$here/cbmc/p6_timewarp.c" -DHDRRULES_H='"@F@"'

echo "pow: $FAILS failure(s)"
exit $((FAILS > 0))
