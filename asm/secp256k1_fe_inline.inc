; ============================================================================
; secp256k1_fe_inline.inc -- the field ADD and SUB, as inline register macros.
; 100% AI-generated. Included by secp256k1_point.asm and secp256k1_point_ct.asm.
;
; WHY THIS FILE EXISTS  (PERF_SCOPE.md 11.2, item 1)
;   A live profile at height ~700,000 put fe_add at 5.48 % and fe_sub at
;   3.32 % of ALL replay cycles -- 8.8 % across ~2,553 calls per
;   ecdsa_verify. Both routines are tiny (31 and 19 instructions), so most of
;   that 8.8 % is not arithmetic: it is the argument `lea`s, the call/ret, and
;   above all the four stores and four loads that every result makes through
;   the caller's stack frame even when the very next operation consumes it.
;
;   PERF_SCOPE.md 10.4 identified this as the ONE structural advantage
;   libsecp256k1's 5x52 representation actually realises -- not the
;   representation itself, but the fact that its field operations are inlined
;   into the EC formulas so consecutive results stay in registers.
;
;   These macros give 4x64 the same property: a chain such as
;       T = T - A ; T = T - C ; D = T + T
;   becomes ONE load of T, three in-register operations, and ONE store of D.
;
; THE REGISTER CONVENTION (deliberately fixed, so a reader can audit it once)
;   The "accumulator" V is always r8:r9:r10:r11 (limb 0 in r8).
;   rbx always holds C = 2^32 + 977. Every function that uses these macros
;   loads it once, in its prologue, with FE_C_INIT. rbx is callee-saved and
;   fe_mul / fe_sqr / point_double all preserve it, so it survives every
;   nested call and never has to be reloaded.
;   Scratch: rax, rcx, rdx, rsi, rdi. In point_double / point_add /
;   point_add_mixed / pointh_add / pointh_double those five are dead between
;   calls -- they exist only to pass arguments -- so NOTHING is spilled to
;   make room for this. That is the register-pressure argument in one line:
;   a field element is 4 registers, we need one live one plus five scratch,
;   and the frame pointer and the 3-4 pointer registers all live in
;   callee-saved registers that the macros never touch.
;
; CANONICALITY -- read this before changing anything
;   Every macro takes canonical operands in [0, p) and leaves V canonical in
;   [0, p). NO relaxed or lazily-reduced intermediate is ever produced. This
;   is not a style preference: point_add and point_add_mixed decide their
;   doubling branch by comparing field elements LIMB BY LIMB, so a
;   non-canonical value there would make two field-equal values compare
;   unequal and return the point at infinity where 2P is correct
;   (PERF_SCOPE.md 10.5). Nothing here relaxes that invariant.
; ============================================================================

; C = 2^32 + 977. p = 2^256 - C.
%define FE_C_VAL 0x1000003D1

; Load the fold constant into its permanent home. Once per function.
%macro FE_C_INIT 0
    mov  rbx, FE_C_VAL
%endmacro

; V := [%1]
%macro FE_LD 1
    mov  r8,  [%1 + 0]
    mov  r9,  [%1 + 8]
    mov  r10, [%1 + 16]
    mov  r11, [%1 + 24]
%endmacro

; [%1] := V
%macro FE_ST 1
    mov  [%1 + 0],  r8
    mov  [%1 + 8],  r9
    mov  [%1 + 16], r10
    mov  [%1 + 24], r11
%endmacro

; ----------------------------------------------------------------------------
; FE_ADD_TAIL -- the shared reduction for every addition form.
;
; Entry: r8..r11 = the low 256 bits of s = a + b, CF = the 257th bit of s,
;        a, b canonical, rbx = C.  Exit: r8..r11 = s mod p, canonical.
;
; WHY ONE CONDITIONAL SELECT DOES BOTH STEPS
;   fe_add does this in two: fold the 257th bit (add C when CF is set), then
;   one conditional subtract of p. Written out, that is
;       v = s0 + CF1*C ; result = (v + C >= 2^256) ? v + C : v
;   With a, b < p those two steps collapse into one, because:
;     * s = a + b <= 2p - 2, so s mod p is either s or s - p; and
;     * s - p == s + C (mod 2^256) -- p = 2^256 - C; and
;     * s >= p  <=>  CF1 = 1  OR  s0 + C carries out of 2^256.
;       (CF1 = 1 means s >= 2^256 > p. CF1 = 0 means s = s0 < 2^256, and then
;        s0 + C >= 2^256 <=> s0 >= 2^256 - C = p.)
;   So: form t = s0 + C once, and take t exactly when either carry fired.
;
;   The result is the same 256 bits fe_add produces, not merely congruent:
;     CF1 = 0: t and the predicate are literally fe_add's own w and CF2, and
;              fe_add's fold added nothing, so v = s0. Identical by inspection.
;     CF1 = 1: s0 = s - 2^256 <= 2p - 2 - 2^256 = 2^256 - 2C - 2, hence
;              t = s0 + C <= 2^256 - C - 2 < p. So fe_add's second step finds
;              t < p and keeps it -- which is what this returns.
;   The ONLY inputs on which the two forms differ are non-canonical ones
;   (they need a + b >= 2^257 - 2C, impossible for a, b < p = 2^256 - C).
;   tests/test_fe_inline pins that boundary directly, including the family
;   that separates the two forms, and confirms agreement on canonical input.
;
; Cost: 14 instructions, no memory traffic, no branch (constant-time).
; ----------------------------------------------------------------------------
%macro FE_ADD_TAIL 0
    sbb  rdi, rdi           ; rdi = -CF1 (consumes the 257th bit; MOV below
                            ;             would preserve CF, but the shadow
                            ;             add would not)
    mov  rax, r8
    mov  rcx, r9
    mov  rsi, r10
    mov  rdx, r11
    add  rax, rbx           ; t = s0 + C  ( == s0 - p, mod 2^256 )
    adc  rcx, 0
    adc  rsi, 0
    adc  rdx, 0             ; CF2 = 1  <=>  s0 >= p
    adc  rdi, rdi           ; rdi = 2*(-CF1) + CF2 : ZF = 0 <=> CF1 | CF2.
                            ; CF1=0 -> rdi = CF2 ; CF1=1 -> rdi in {-2,-1}.
    cmovnz r8,  rax
    cmovnz r9,  rcx
    cmovnz r10, rsi
    cmovnz r11, rdx
%endmacro

; V := (V + [%1]) mod p
%macro FE_ADDM 1
    add  r8,  [%1 + 0]
    adc  r9,  [%1 + 8]
    adc  r10, [%1 + 16]
    adc  r11, [%1 + 24]
    FE_ADD_TAIL
%endmacro

; V := (V + V) mod p  -- the doubling form, one instruction cheaper per limb
; than FE_ADDM against a slot and with no load at all.
%macro FE_DBL 0
    add  r8,  r8
    adc  r9,  r9
    adc  r10, r10
    adc  r11, r11
    FE_ADD_TAIL
%endmacro

; ----------------------------------------------------------------------------
; V := (V - [%1]) mod p
; Instruction-for-instruction fe_sub's body with the operand loads folded into
; the sbb chain. Its correctness argument is fe_sub's, unchanged:
;   no borrow -> V >= [%1], the difference is already in [0, p);
;   borrow    -> the wrapped limbs hold V - [%1] + 2^256, which exceeds
;                2^256 - p = C, so subtracting C ("adding p") cannot borrow
;                again and lands in (0, p).
; Cost: 10 instructions. Uses only rax as scratch.
; ----------------------------------------------------------------------------
%macro FE_SUBM 1
    sub  r8,  [%1 + 0]
    sbb  r9,  [%1 + 8]
    sbb  r10, [%1 + 16]
    sbb  r11, [%1 + 24]
    sbb  rax, rax           ; rax = -borrow
    and  rax, rbx           ; rax = borrow ? C : 0
    sub  r8,  rax           ; "add p" == "subtract C"  (mod 2^256)
    sbb  r9,  0
    sbb  r10, 0
    sbb  r11, 0
%endmacro
