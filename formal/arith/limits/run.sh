#!/usr/bin/env bash
# Limits proofs (rule group 4): CompactSize, block size/weight, sigop cost,
# vsize. Exits 0 only if every proof holds, every REACH witness is found and
# every mutant is caught. One line per check; every solver/build goes
# through runlib's _lim (memory-capped scope), one at a time.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../lib/runlib.sh"
A=$(cd "$here/../../../asm" && pwd)
B=$here/.build
"$here/gen.sh"   || { echo "FAIL  gen";   exit 1; }
"$here/build.sh" || { echo "FAIL  build"; exit 1; }
U='--unwind 17 --unwinding-assertions --sat-solver cadical'
U5='--unwind 5 --unwinding-assertions --sat-solver cadical'

# run_expect ID KIND want0 CMD...: the command's exit code must be 0 (want0=1)
# or nonzero but not a timeout/kill (want0=0)
run_expect(){
    local id=$1 kind=$2 want0=$3; shift 3
    local log=$LOGDIR/$id.$kind.log t=$(_t0)
    _lim timeout 900 "$@" >"$log" 2>&1; local rc=$?
    local s; s=$(grep -E 'cases|divergen|cons_verify|DIVERGE' "$log" | tail -2 | tr '\n' ' ')
    if { [ "$want0" = 1 ] && [ $rc -eq 0 ]; } || { [ "$want0" = 0 ] && [ $rc -ne 0 ] && [ $rc -ne 124 ] && [ $rc -ne 137 ]; }; then
        echo "PASS  $id  $kind  $(_dt $t)  rc=$rc $s"
    else
        echo "FAIL  $id  $kind  $(_dt $t)  rc=$rc see $log $s"; FAILS=$((FAILS+1))
    fi
}
# asm_mutant ID ASM OLD NEW LINKOBJS-EXCEPT-ITSELF -- DIFFSRC ARGS...:
# replace exactly one occurrence of OLD in a scratch copy of asm/ASM,
# assemble, link DIFFSRC against it, and require the differential to fail.
asm_mutant(){
    local id=$1 asm=$2 old=$3 new=$4 objs=$5 src=$6; shift 6
    local tmp; tmp=$(mktemp -d)
    if ! python3 - "$A/$asm.asm" "$tmp/m.asm" "$old" "$new" <<'PYEOF'
import sys
src, dst, old, new = sys.argv[1:5]
old = old.replace("\\n", "\n"); new = new.replace("\\n", "\n")
s = open(src).read(); n = s.count(old)
if n != 1: sys.exit("anchor occurs %d times" % n)
open(dst, "w").write(s.replace(old, new))
PYEOF
    then echo "FAIL  $id  mutant  anchor not unique in $asm.asm"; FAILS=$((FAILS+1)); rm -rf "$tmp"; return; fi
    local o=() x; for x in $objs; do o+=("$B/$x.o"); done
    if ! _lim timeout 300 nasm -f elf64 -I"$A/" -Werror -o "$tmp/m.o" "$tmp/m.asm" ||
       ! _lim timeout 300 gcc -no-pie -O2 -o "$tmp/bin" "$src" "$tmp/m.o" "${o[@]}"; then
        echo "FAIL  $id  mutant  build failed (not a catch)"; FAILS=$((FAILS+1)); rm -rf "$tmp"; return; fi
    run_expect "$id" mutant 0 "$tmp/bin" "$@"
    rm -rf "$tmp"
}

# cbmc_known ID DIR HARNESS FLAGS...: a documented divergence -- the run must
# FAIL on a property assertion (NOTES.md says why each one is not a finding)
cbmc_known(){
    local id=$1 dir=$2 h=$3; shift 3
    local log=$LOGDIR/$id.known.log t=$(_t0)
    ( cd "$dir" && _lim timeout 900 "$CBMC" "$h" "$@" ) >"$log" 2>&1
    local f; f=$(grep 'FAILURE' "$log" | grep -v 'unwinding assertion' | head -1 | sed 's/^ *//')
    if grep -q '^VERIFICATION FAILED' "$log" && [ -n "$f" ]; then
        echo "PASS  $id  known-divergence  $(_dt $t)  -> $f"
    else
        echo "FAIL  $id  known-divergence  $(_dt $t)  expected a counterexample, see $log"; FAILS=$((FAILS+1))
    fi
}

# ---- CompactSize readers (cs/cs_check.h: complete over every byte string) ----
for r in utxo_walk block_witness tx_verify mempool_policy; do
    cbmc_prove CS-$r "$here" cs/cs_$r.c $U
    cbmc_reach CS-$r "$here" cs/cs_$r.c $U
done
for r in segwit signet_block; do
    cbmc_prove CS-$r-norange "$here" cs/cs_$r.c -DNO_RANGE $U
    cbmc_reach CS-$r "$here" cs/cs_$r.c $U
done
for r in txval_modern tx_accept blk_submit; do
    cbmc_prove CS-$r-superset "$here" cs/cs_$r.c -DSUPERSET $U
    cbmc_reach CS-$r "$here" cs/cs_$r.c $U
done
# the weaker readers' gaps, shown as counterexamples (no MAX_SIZE; no canonical check)
for r in segwit signet_block; do cbmc_known CS-$r-full "$here" cs/cs_$r.c $U; done
for r in txval_modern tx_accept blk_submit; do cbmc_known CS-$r-full "$here" cs/cs_$r.c -DNO_RANGE $U; done
cbmc_mutant CS-utxo_walk     "$here" cs/cs_utxo_walk.c      gen/cs_utxo_walk.inc      's/if \(v < 0xfdULL \|\|/if (v < 0xfcULL ||/' $U
cbmc_mutant CS-block_witness "$here" cs/cs_block_witness.c  gen/cs_block_witness.inc  's/return \*v <= BW_CS_MAX_SIZE; \}$/return 1; }/' $U
cbmc_mutant CS-tx_verify     "$here" cs/cs_tx_verify.c      gen/cs_tx_verify.inc      's/if \(v <= 0xffffULL\)/if (v < 0xffffULL)/' $U
cbmc_mutant CS-mempool       "$here" cs/cs_mempool_policy.c gen/cs_mempool_policy.inc 's/minimum = 0xfdULL;/minimum = 0xfcULL;/' $U
cbmc_mutant CS-segwit        "$here" cs/cs_segwit.c         gen/cs_segwit.inc         's/min = 0x10000ULL;/min = 0xffffULL;/' -DNO_RANGE $U
cbmc_mutant CS-signet        "$here" cs/cs_signet_block.c   gen/cs_signet_block.inc   's/0xfdUL :/0xfcUL :/' -DNO_RANGE $U
cbmc_mutant CS-txval_modern  "$here" cs/cs_txval_modern.c   gen/cs_txval_modern.inc   's/if \(f < 0xfd\) v = f;/if (f < 0xfc) v = f;/' -DSUPERSET $U
cbmc_mutant CS-tx_accept     "$here" cs/cs_tx_accept.c      gen/cs_tx_accept.inc      's/if \(f < 0xfd\) v = f;/if (f < 0xfc) v = f;/' -DSUPERSET $U
cbmc_mutant CS-blk_submit    "$here" cs/cs_blk_submit.c     gen/cs_blk_submit.inc     's/if \(p\[0\] == 0xfe\)\{ if \(p\+5 > end\)/if (p[0] == 0xfe){ if (p+6 > end)/' -DSUPERSET $U

# tx_parse (bitcoin_tx.asm), the asm splitter, vs Core's deserializer
run_expect TXP-canonical diff 1 "$B/cs_txparse_diff" 1000000 0x1234 canonical
run_expect TXP-all       diff 1 "$B/cs_txparse_diff" 1000000 0x5678
asm_mutant TXP bitcoin_tx 'movzx r15, word [r9+1]\n    mov  r9,  rbx\n    jmp  .have_slen' \
    'movzx r15, byte [r9+1]\n    mov  r9,  rbx\n    jmp  .have_slen' "bitcoin_hash sha256" \
    "$here/cs/cs_txparse_diff.c" 1000000 0x1234 canonical

# ---- block size and weight ----
cbmc_prove  W "$here" weight/w_block.c -DNONEMPTY $U5
cbmc_reach  W "$here" weight/w_block.c -DNONEMPTY $U5
cbmc_mutant W-weight "$here" weight/w_block.c gen/w_phase027.inc 's/u64 weight = 3ULL \* stripped/u64 weight = 2ULL * stripped/' -DNONEMPTY $U5
cbmc_mutant W-length "$here" weight/w_block.c gen/w_phase010.inc 's/if \(stripped \* WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT\)/if (stripped * 3 > MAX_BLOCK_WEIGHT)/' -DNONEMPTY $U5
run_expect W-empty confirm 1 "$B/empty_block_confirm"

# ---- sigops ----
cbmc_prove  S-ledger "$here" sigops/s_ledger.c $U5
cbmc_reach  S-ledger "$here" sigops/s_ledger.c $U5
cbmc_mutant S-ledger "$here" sigops/s_ledger.c gen/s_phase46.inc 's/if \(sigops_cost > 80000ULL\)/if (sigops_cost > 80004ULL)/' $U5
cbmc_prove  S-lastpush "$here" sigops/s_lastpush.c --unwind 18 --unwinding-assertions --sat-solver cadical
cbmc_reach  S-lastpush "$here" sigops/s_lastpush.c --unwind 18 --unwinding-assertions --sat-solver cadical
cbmc_mutant S-lastpush "$here" sigops/s_lastpush.c gen/s_last_push.inc 's/\{ last = p; lastl = 0; continue; \}/{ last = p; lastl = 1; continue; }/' --unwind 18 --unwinding-assertions --sat-solver cadical
cbmc_prove  S-witness "$here" sigops/s_witness.c
cbmc_reach  S-witness "$here" sigops/s_witness.c
cbmc_mutant S-witness "$here" sigops/s_witness.c gen/s_witness_sigops.inc 's/if \(proglen == 32\)/if (proglen == 33)/'
cbmc_known  S-witness-emptystack "$here" sigops/s_witness.c -DALL
run_expect  S-count diff 1 "$B/sg_diff" 1000000 0x77
asm_mutant  S-count bitcoin_sigops 'add   qword [rbp-0x28], 20' 'add   qword [rbp-0x28], 19' \
    "bitcoin_scriptcodec" "$here/sigops/sg_diff.c" 100000 0x77

# ---- vsize ----
for P in 1 20 100000; do
    cbmc_prove V-bps$P "$here" vsize/v_vsize.c -DBPS=$P --sat-solver cadical
done
cbmc_reach  V "$here" vsize/v_vsize.c -DBPS=20 --sat-solver cadical
cbmc_known  V-bps0 "$here" vsize/v_vsize.c -DBPS0 --sat-solver cadical
cbmc_mutant V "$here" vsize/v_vsize.c gen/v_adjusted.inc 's/vsize = \(adj_w \+ 3\) \/ 4;/vsize = (adj_w + 2) \/ 4;/' -DBPS=20 --sat-solver cadical
echo "limits: $FAILS failure(s)"
exit $((FAILS > 0))
