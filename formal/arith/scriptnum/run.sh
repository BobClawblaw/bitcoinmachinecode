#!/usr/bin/env bash
# Script-number proofs (rule group 5). Exits 0 only if every proof holds and
# every mutant is caught. One line per check; every solver/build goes through
# runlib's _lim (memory-capped scope), one at a time.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/../lib/runlib.sh"
A=$(cd "$here/../../../asm" && pwd)
B=$here/.build
"$here/build.sh" || { echo "FAIL  build"; exit 1; }
DIFF_OBJS="bitcoin_interp bitcoin_scriptcodec bitcoin_sighash bitcoin_sigops bitcoin_tx bitcoin_hash ripemd160 sha1 sha256"

# run_expect ID KIND want0 CMD...: exit 0 wanted (want0=1), or a nonzero exit
# that is not a timeout/kill (want0=0)
run_expect(){
    local id=$1 kind=$2 want0=$3; shift 3
    local log=$LOGDIR/$id.$kind.log t=$(_t0)
    _lim timeout 900 "$@" >"$log" 2>&1; local rc=$?
    local s; s=$(grep -E 'cases|divergen|PROVED|MUTANT|FAILED' "$log" | tail -2 | tr '\n' ' ')
    if { [ "$want0" = 1 ] && [ $rc -eq 0 ]; } || { [ "$want0" = 0 ] && [ $rc -ne 0 ] && [ $rc -ne 124 ] && [ $rc -ne 137 ]; }; then
        echo "PASS  $id  $kind  $(_dt $t)  rc=$rc $s"
    else
        echo "FAIL  $id  $kind  $(_dt $t)  rc=$rc see $log $s"; FAILS=$((FAILS+1))
    fi
}
# mutate ASM OLD NEW OUT.asm: replace exactly one occurrence ("\n" = newline)
mutate(){
    python3 - "$A/$1.asm" "$4" "$2" "$3" <<'PYEOF'
import sys
src, dst, old, new = sys.argv[1:5]
old = old.replace("\\n", "\n"); new = new.replace("\\n", "\n")
s = open(src).read(); n = s.count(old)
if n != 1: sys.exit("anchor occurs %d times" % n)
open(dst, "w").write(s.replace(old, new))
PYEOF
}
# lift_mutant ID ONLY OLD NEW: mutate bitcoin_scriptcodec.asm, link the lift
# binary, require sn_lift.py to find a counterexample in property ONLY
lift_mutant(){
    local id=$1 only=$2 tmp; tmp=$(mktemp -d)
    if ! mutate bitcoin_scriptcodec "$3" "$4" "$tmp/m.asm" ||
       ! _lim timeout 300 nasm -f elf64 -I"$A/" -Werror -o "$tmp/m.o" "$tmp/m.asm" ||
       ! _lim timeout 300 gcc -no-pie -O2 -o "$tmp/bin" "$here/lift_main.c" "$tmp/m.o"; then
        echo "FAIL  $id  mutant  anchor/build failed (not a catch)"; FAILS=$((FAILS+1)); rm -rf "$tmp"; return; fi
    run_expect "$id" mutant 1 "$PY" "$here/sn_lift.py" "$tmp/bin" --expect-cex --only="$only"
    rm -rf "$tmp"
}
# diff_mutant ID ASM OLD NEW: mutate one interpreter object, relink sn_diff,
# require divergences
diff_mutant(){
    local id=$1 asm=$2 tmp; tmp=$(mktemp -d)
    local o=() x; for x in $DIFF_OBJS; do [ "$x" = "$asm" ] && o+=("$tmp/m.o") || o+=("$B/$x.o"); done
    if ! mutate "$asm" "$3" "$4" "$tmp/m.asm" ||
       ! _lim timeout 300 nasm -f elf64 -I"$A/" -Werror -o "$tmp/m.o" "$tmp/m.asm" ||
       ! _lim timeout 300 gcc -no-pie -O2 -o "$tmp/bin" "$here/sn_diff.c" "${o[@]}"; then
        echo "FAIL  $id  mutant  anchor/build failed (not a catch)"; FAILS=$((FAILS+1)); rm -rf "$tmp"; return; fi
    run_expect "$id" mutant 0 "$tmp/bin" 200000 0x99
    rm -rf "$tmp"
}

# ---- the primitives, lifted from the real object (angr -> z3) ----
run_expect SN-lift proof 1 "$PY" "$here/sn_lift.py" "$B/lift_bin"
lift_mutant SN-decode-size  decode    '    jbe   .size_ok' '    jb    .size_ok'
lift_mutant SN-decode-min   decode    '    test  cl, 0x7f\n    jnz   .min_ok' '    test  cl, 0x3f\n    jnz   .min_ok'
lift_mutant SN-serialize    serialize '    or    byte [rdi], 0x80' '    or    byte [rdi], 0x40'
lift_mutant SN-cast         cast      '    cmp   al, 0x80\n    je    .false' '    cmp   al, 0x81\n    je    .false'

# ---- the opcodes, real interpreter vs Core port (differential) ----
run_expect SN-ops diff 1 "$B/sn_diff" 1000000 0x99
diff_mutant SN-within bitcoin_interp '    cmp   r15, rbx\n    setl  r14b' '    cmp   r15, rbx\n    setle r14b'
diff_mutant SN-cltvneg bitcoin_interp '    test  rax, rax\n    jns   .cltv_nn' '    test  rax, rax\n    jmp   .cltv_nn'
echo "scriptnum: $FAILS failure(s)"
exit $((FAILS > 0))
