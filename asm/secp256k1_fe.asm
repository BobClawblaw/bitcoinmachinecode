; ============================================================================
; secp256k1 field arithmetic -- 100% AI-generated x86-64 assembly (NASM ELF64)
;
; PURPOSE
;   secp256k1 is the elliptic curve Bitcoin uses for its public-key crypto.
;   Every transaction input spends a previous output by presenting an ECDSA
;   signature, and validating that signature require scalars and points over
;   this curve. This file implements the underlying 256-bit prime field
;   arithmetic in raw x86-64 machine code -- the arithmetic every signature
;   check reduces to.
;
; FIELD
;   The coordinates of secp256k1 points live in the prime field
;       p = 2^256 - 2^32 - 977
;         = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
;   Element encoding: 4 little-endian 64-bit limbs (limb[0] = least significant).
;   A field element is an integer in [0, p). All arithmetic here is mod p.
;
; REDUCTION (verified against Python big-int arithmetic)
;   Multiplication of two 256-bit values yields a 512-bit product t.
;   Write t = t1 * 2^256 + t0. Because 2^256 = 2^32 + 977 (mod p), we fold the
;   high half in:  t == t0 + t1*(2^32+977)  (mod p).
;   Iterating this fold, the value shrinks below 2^256 quickly, then a final
;   conditional subtraction of p yields a canonical element. The fold constant
;   is  C = 2^32 + 977 = 0x1000003D1.
;
; ABI (System V AMD64): first three args in rdi, rsi, rdx; rax returns.
;   void fe_add(u64 r[4], const u64 a[4], const u64 b[4])   r = (a+b) mod p
;   void fe_sub(u64 r[4], const u64 a[4], const u64 b[4])   r = (a-b) mod p
;   void fe_mul(u64 r[4], const u64 a[4], const u64 b[4])   r = (a*b) mod p
;
; LIMB INDEXING: element limbs live in rdi/rsi/rdx as 4 consecutive u64.
;   limb0 = [x+0], limb1 = [x+8], limb2 = [x+16], limb3 = [x+24].
; ============================================================================

BITS 64
DEFAULT REL

; ----------------------------------------------------------------------------
; Read-only field constants.
; P_LIMBS holds p as 4 little-endian 64-bit limbs.
; C holds the reduction constant 2^32 + 977.
; ----------------------------------------------------------------------------
section .rodata
align 16
P_LIMBS:
    dq 0xFFFFFFFEFFFFFC2F   ; limb0 of p  (p mod 2^64)
    dq 0xFFFFFFFFFFFFFFFF   ; limb1
    dq 0xFFFFFFFFFFFFFFFF   ; limb2
    dq 0xFFFFFFFFFFFFFFFF   ; limb3
C_CONST:
    dq 0x00000001000003D1   ; C = 2^32 + 977  (fits comfortably in 64 bits)

; EXP = p - 2 = 2^256 - 2^32 - 979, as 32 little-endian bytes.
; The exponent used by fe_inv (Fermat a^(p-2)). Kept in this FIRST .rodata
; block: splitting .rodata across two blocks in the source caused a link/rip-
; relative resolution bug that made fe_inv read the wrong exponent. P_LIMBS and
; C_CONST already live here and relocate correctly.
align 16
EXP_BYTES:
    db 0x2d, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff
    db 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    db 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    db 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff

section .text

; ============================================================================
; void fe_add(u64 r[4], const u64 a[4], const u64 b[4])
;   Computes r = (a + b) mod p. Inputs a,b in [0,p); result canonical in [0,p).
;
; REWRITTEN 2026-08-22 (PERF_SCOPE.md §5). BIT-IDENTICAL to the previous
; version on EVERY 512-bit input pair, not merely on in-range ones -- see the
; identity below -- but 30 instructions with no callee-saved spills instead of
; 48 plus four push/pop pairs. A callgrind attribution of ecdsa_verify after
; the fe_mul rewrite put fe_add at 13.0 % and fe_sub at 11.3 % of ALL retired
; instructions, second only to fe_mul itself.
;
; THE IDENTITY THAT MAKES THIS SAFE
;   p = 2^256 - C with C = 2^32 + 977, so modulo 2^256:  -p == C  and  p == -C.
;   Therefore, on 4-limb wrapping arithmetic:
;     "subtract p"   ==  "add C"     (and the CARRY OUT of v + C is exactly
;                                     the predicate v >= p, since
;                                     v + C >= 2^256  <=>  v >= 2^256 - C = p)
;     "add p"        ==  "subtract C"
;   The old code loaded P_LIMBS, did a four-limb sbb against it to both
;   compare and subtract, and cmov'd. This does the same two things with one
;   four-limb add of a single 64-bit constant. Same value, same predicate,
;   same cmov -- the ONLY difference is which instructions compute them.
;
; STEPS (each mapping 1:1 onto a step of the old code)
;   1. sum = a + b, keeping the 257th bit in CF.
;   2. Fold that bit: 2^256 == C (mod p), so add C when it is set. Branch-free
;      via the -CF mask, exactly as before.
;   3. Canonicalise with ONE conditional subtract of p, as before -- valid
;      because after step 2 the value is < 2^256 and hence < 2p.
;
; Registers: rax/rcx/rsi/rdx are scratch after their operands are consumed;
;   r8..r11 hold the sum; rdi is the destination. No callee-saved register is
;   touched, so no prologue and no stack traffic at all.
; ----------------------------------------------------------------------------
global fe_add
fe_add:
    ; ---- step 1: 256-bit add, CF = the 257th bit ----
    mov r8,  [rsi + 0]
    add r8,  [rdx + 0]
    mov r9,  [rsi + 8]          ; MOV does not disturb CF, so the adc chain
    adc r9,  [rdx + 8]          ; below is unbroken by these loads
    mov r10, [rsi + 16]
    adc r10, [rdx + 16]
    mov r11, [rsi + 24]
    adc r11, [rdx + 24]

    ; ---- step 2: fold the 257th bit; 2^256 == C (mod p) ----
    sbb rax, rax                ; rax = -CF : all ones iff the sum overflowed
    and rax, [C_CONST]          ; rax = CF ? C : 0
    add r8,  rax
    adc r9,  0
    adc r10, 0
    adc r11, 0                  ; sum < 2p - 2^256 + C < 2^256 : cannot carry

    ; ---- step 3: one conditional subtract of p, written as "+ C" ----
    ; The carry out of v + C IS the predicate v >= p, and the wrapped sum IS
    ; v - p, so the comparison and the subtraction are the same four adds.
    mov rax, r8
    mov rcx, r9
    mov rsi, r10                ; a[] is fully consumed; rsi is scratch now
    mov rdx, r11                ; likewise b[]
    add rax, [C_CONST]
    adc rcx, 0
    adc rsi, 0
    adc rdx, 0                  ; CF = 1  <=>  v >= p
    cmovc r8,  rax
    cmovc r9,  rcx
    cmovc r10, rsi
    cmovc r11, rdx

    mov [rdi + 0],  r8
    mov [rdi + 8],  r9
    mov [rdi + 16], r10
    mov [rdi + 24], r11
    ret

; ============================================================================
; void fe_sub(u64 r[4], const u64 a[4], const u64 b[4])
;   Computes r = (a - b) mod p. Inputs a,b in [0,p); result canonical in [0,p).
;
; REWRITTEN 2026-08-22 (PERF_SCOPE.md §5). BIT-IDENTICAL to the previous
; version on EVERY 512-bit input pair: the old code added the four masked
; limbs of p on borrow, and modulo 2^256 adding p is *the same operation* as
; subtracting C = 2^32 + 977, because p = 2^256 - C. Both versions drop the
; out-of-range bit in the same place. 18 instructions and no callee-saved
; spills, against 36 plus three push/pop pairs.
;
; WHY ONE CORRECTION SUFFICES
;   No borrow: a >= b, so a - b is already in [0, p).
;   Borrow:    the wrapped limbs hold a - b + 2^256, and a - b > -p gives
;              a - b + 2^256 > 2^256 - p = C, so subtracting C cannot borrow
;              again and lands on a - b + p, which is in (0, p).
; ----------------------------------------------------------------------------
global fe_sub
fe_sub:
    mov r8,  [rsi + 0]
    sub r8,  [rdx + 0]
    mov r9,  [rsi + 8]          ; MOV preserves CF; the sbb chain is unbroken
    sbb r9,  [rdx + 8]
    mov r10, [rsi + 16]
    sbb r10, [rdx + 16]
    mov r11, [rsi + 24]
    sbb r11, [rdx + 24]         ; CF = borrow

    sbb rax, rax                ; rax = -borrow
    and rax, [C_CONST]          ; rax = borrow ? C : 0
    sub r8,  rax                ; "add p" == "subtract C" (mod 2^256)
    sbb r9,  0
    sbb r10, 0
    sbb r11, 0

    mov [rdi + 0],  r8
    mov [rdi + 8],  r9
    mov [rdi + 16], r10
    mov [rdi + 24], r11
    ret

; ============================================================================
; void fe_mul(u64 r[4], const u64 a[4], const u64 b[4])
;   Computes r = (a * b) mod p, result canonical in [0, p).
;
; WHY THIS WAS REWRITTEN (2026-08-22, PERF_SCOPE.md §5)
;   The previous implementation was algorithmically the same but spent ~290
;   instructions per call: it materialised each row a_i*B into its own 40-byte
;   stack buffer, merged the four buffers with memory-to-memory add/adc, and
;   then reduced through more memory, using `mul` (which forces rax/rdx) and
;   three-instruction `xor edx,edx / add / adc rdx,0` carry captures. A live
;   profile put fe_mul at 55.9 % of ALL replay cycles, so the constant factor
;   here is the single largest cost in the node.
;
;   This version keeps the identical algorithm and the identical 4x64
;   representation -- so every existing test applies unchanged -- and simply
;   stops touching memory: the whole 512-bit product and both reduction folds
;   live in registers, and every carry is captured by ADCX/ADOX rather than
;   by an add/adc pair. Measured on this box (Zen 5, tests/bench_fe):
;   10.46 -> 4.42 ns per call in the 4-independent-chains regime.
;
;   Instruction budget: 21 multiplies (16 for the product, 4 + 1 for the two
;   folds) and ~36 ADCX/ADOX. Probed on this CPU (scratch uarch harness):
;   mulx 0.67 cyc/op throughput, adcx+adox on two interleaved chains
;   0.50 cyc/op -- so ~18 cycles of carry work overlapping ~14 cycles of
;   multiply work is the floor this schedule is aiming at.
;
; ALGORITHM (unchanged; the fold constant and the two-fold structure are the
; same ones validated in Python by the previous implementation)
;   Phase 1 -- 256x256 -> 512-bit schoolbook product T[0..7]:
;       T = sum_i (a_i * b) << 64i
;     Row 0 is a plain 1x4 multiply (nothing to accumulate into yet). Rows
;     1..3 accumulate into T with TWO independent carry chains: ADCX (CF)
;     absorbs the low halves, ADOX (OF) the high halves. Two chains is not a
;     stylistic choice -- it is the only way to add both halves of a 128-bit
;     product term into adjacent limbs without serialising on a single flag.
;   Phase 2 -- reduction, 2^256 == C (mod p), C = 2^32 + 977 = 0x1000003D1:
;       fold 1:  V = T[0..3] + T[4..7]*C          -> 5 limbs (u0..u3, u4)
;       fold 2:  W = (u0..u3) + u4*C              -> 4 limbs + a carry
;       the carry out of fold 2 is worth exactly 2^256 == C, so it is folded
;       back in once more (this is the lost-carry bug fixed on 2026-08-21;
;       tests/test_mul_carry_regression.c pins the operands that expose it).
;   Canonicalise: p = 2^256 - C, so v >= p exactly when v + C >= 2^256.
;     Compute v + C once; if it carried out, that sum IS v - p. cmov it in.
;     No P_LIMBS load and no separate comparison.
;
; CARRY-TERMINATION PROOF (the part that must be right, not fast)
;   Let S_i = sum_{k<=i} a_k*b*2^(64k) be the running product after row i.
;     S_i <= (2^(64(i+1)) - 1)*(2^256 - 1) < 2^(64(i+5)),
;   so S_i always fits in limbs T[0..i+4] and NO carry can leave T[i+4].
;   Within row i the ADOX chain ends at `adox T[i+4], hi3` where T[i+4] was
;   still 0: 0 + hi3 + OF_in <= (2^64 - 2) + 1 < 2^64, so the OF chain also
;   terminates at zero rather than being dropped.
;   Fold 1: T[4..7] < 2^256 and C < 2^33, so T[4..7]*C < 2^289 and the top
;   word u4 = hi(T[7]*C) + OF + CF < 2^33 + 2 -- again no overflow.
;   Fold 2: u4*C < 2^67, so W < 2^256 + 2^67; when it does carry out, the
;   surviving low part is < 2^67 and adding C once more cannot carry again.
;   All four claims are asserted per-operation, not just on the final result,
;   in the Python model (validation/fe_mul_model.py) over 400,000 random and
;   every structured pair, including a = b = 2^256-1 and full-range
;   (non-canonical) inputs.
;
; REGISTER / FRAME plan (System V ABI) -- 15 of the 15 usable GPRs, no stack:
;   rdi = r[] (untouched until the four final stores)
;   rsi = a[] during phase 1, then reused as the fold-1 top word u4
;   rcx = b[] (mulx clobbers rdx, so b cannot live there)
;   rdx = mulx's implicit multiplicand
;   rax, rbx = mulx low/high destinations
;   rbp = a hard zero, the source operand for "add just the pending carry"
;   r8..r15 = T[0..7]
;   callee-saved used and pushed: rbx, rbp, r12, r13, r14, r15. No calls are
;   made, so no 16-byte realignment is required.
; ============================================================================
global fe_mul
fe_mul:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov  rcx, rdx               ; rcx = b[]  (rdx is about to become mulx's)

    ; ======================================================================
    ; PHASE 1, ROW 0:  T[0..4] = a0 * b   (nothing to accumulate into yet,
    ; so this is a plain add/adc chain -- MULX does not touch flags, which
    ; is what lets the multiplies sit between the adds.)
    ; ======================================================================
    mov  rdx, [rsi + 0]         ; a0
    mulx r9,  r8,  [rcx + 0]    ; T1:T0 = a0*b0
    mulx r10, rax, [rcx + 8]    ; T2:lo  = a0*b1
    add  r9,  rax
    mulx r11, rax, [rcx + 16]   ; T3:lo  = a0*b2
    adc  r10, rax
    mulx r12, rax, [rcx + 24]   ; T4:lo  = a0*b3
    adc  r11, rax
    adc  r12, 0                 ; a0*b < 2^320, so this cannot carry out

    xor  r13d, r13d             ; T5 = 0
    xor  r14d, r14d             ; T6 = 0
    xor  r15d, r15d             ; T7 = 0

    ; ======================================================================
    ; PHASE 1, ROWS 1..3:  T[i..i+4] += a_i * b
    ;
    ; Each row opens with `xor ebp, ebp`, which clears BOTH CF and OF and
    ; (re)zeroes rbp. Clearing per row is mandatory, not defensive: row i-1
    ; leaves a residual CF behind, and inheriting it would add a phantom 2^64
    ; to row i. rbp is the zero operand for the final "absorb the pending
    ; CF" -- ADCX has no immediate form.
    ; ======================================================================

    ; ---- row 1: a1 * b into T1..T5 ----
    mov  rdx, [rsi + 8]         ; a1
    xor  ebp, ebp               ; CF = OF = 0, rbp = 0
    mulx rbx, rax, [rcx + 0]    ; hi:lo = a1*b0
    adcx r9,  rax
    adox r10, rbx
    mulx rbx, rax, [rcx + 8]
    adcx r10, rax
    adox r11, rbx
    mulx rbx, rax, [rcx + 16]
    adcx r11, rax
    adox r12, rbx
    mulx rbx, rax, [rcx + 24]
    adcx r12, rax
    adox r13, rbx               ; T5 was 0; hi3 + OF < 2^64, OF chain ends
    adcx r13, rbp               ; absorb the pending CF; cannot carry out

    ; ---- row 2: a2 * b into T2..T6 ----
    mov  rdx, [rsi + 16]        ; a2
    xor  ebp, ebp
    mulx rbx, rax, [rcx + 0]
    adcx r10, rax
    adox r11, rbx
    mulx rbx, rax, [rcx + 8]
    adcx r11, rax
    adox r12, rbx
    mulx rbx, rax, [rcx + 16]
    adcx r12, rax
    adox r13, rbx
    mulx rbx, rax, [rcx + 24]
    adcx r13, rax
    adox r14, rbx               ; T6 was 0
    adcx r14, rbp

    ; ---- row 3: a3 * b into T3..T7 ----
    mov  rdx, [rsi + 24]        ; a3
    xor  ebp, ebp
    mulx rbx, rax, [rcx + 0]
    adcx r11, rax
    adox r12, rbx
    mulx rbx, rax, [rcx + 8]
    adcx r12, rax
    adox r13, rbx
    mulx rbx, rax, [rcx + 16]
    adcx r13, rax
    adox r14, rbx
    mulx rbx, rax, [rcx + 24]
    adcx r14, rax
    adox r15, rbx               ; T7 was 0
    adcx r15, rbp
    ; T[0..7] now holds the exact 512-bit product a*b. rsi and rcx are dead.

    ; ======================================================================
    ; PHASE 2, FOLD 1:  (u0..u3, u4) = T[0..3] + T[4..7] * C
    ;
    ; Same two-chain shape: ADCX takes the low halves of T[4+k]*C into
    ; T[0+k], ADOX takes the high halves into T[1+k]. The last high half has
    ; nowhere left to go inside T[0..3], so it lands in rsi (free since
    ; phase 1 finished) which becomes the 5th limb u4.
    ;
    ; fe_sqr JUMPS TO THE LABEL BELOW. That is deliberate: the reduction is
    ; the part of this file that has already produced one consensus-relevant
    ; lost-carry bug, so there is exactly ONE copy of it, exercised by every
    ; fe_mul AND every fe_sqr in the test suite, instead of two copies that
    ; can drift apart.
    ;
    ; ENTRY CONTRACT for .reduce:
    ;   r8..r15 = the exact 512-bit product T[0..7]
    ;   rbp     = 0            (the "add just the pending carry" operand)
    ;   rdi     = result pointer
    ;   rsi     = dead         (it becomes the 5th limb u4)
    ;   rbx, rbp, r12, r13, r14, r15 already pushed IN THAT ORDER, because
    ;   the epilogue at the end of this routine is what pops them.
    ; ======================================================================
.reduce:
    mov  rdx, [C_CONST]         ; rdx = C = 2^32 + 977
    xor  esi, esi               ; u4 = 0, CF = OF = 0

    mulx rbx, rax, r12          ; T4 * C
    adcx r8,  rax
    adox r9,  rbx
    mulx rbx, rax, r13          ; T5 * C
    adcx r9,  rax
    adox r10, rbx
    mulx rbx, rax, r14          ; T6 * C
    adcx r10, rax
    adox r11, rbx
    mulx rbx, rax, r15          ; T7 * C
    adcx r11, rax
    adox rsi, rbx               ; u4 = hi(T7*C) + OF < 2^33 + 1
    adcx rsi, rbp               ; u4 += pending CF ; still < 2^33 + 2

    ; ======================================================================
    ; PHASE 2, FOLD 2:  W = (u0..u3) + u4 * C, then fold W's own carry.
    ; u4 < 2^33+2 and C < 2^34, so u4*C < 2^67: a two-limb addend.
    ; ======================================================================
    mulx rbx, rax, rsi          ; rbx:rax = u4 * C   (rdx is still C)
    add  r8,  rax
    adc  r9,  rbx
    adc  r10, 0
    adc  r11, 0
    ; CF here is the 2^256 that fold 2 produced. It is worth C (mod p), and
    ; dropping it is exactly the bug fixed on 2026-08-21 -- it is reachable
    ; (e.g. squaring p - 2^31), not merely theoretical.
    sbb  rax, rax               ; rax = -CF : all ones iff the carry was 1
    and  rax, rdx               ; rax = CF ? C : 0
    add  r8,  rax
    adc  r9,  0
    adc  r10, 0
    adc  r11, 0                 ; when CF was 1 the low part is < 2^67, so
                                ; adding C once more provably cannot carry

    ; ======================================================================
    ; CANONICALISE.  p = 2^256 - C, hence  v >= p  <=>  v + C >= 2^256.
    ; Form v + C in a shadow set of registers; the carry out of that addition
    ; is the comparison result AND the shadow set is already v - p. One cmov
    ; group commits it. Branch-free, so constant-time for the signing path.
    ; ======================================================================
    mov  r12, r8
    mov  r13, r9
    mov  r14, r10
    mov  r15, r11
    add  r12, rdx               ; + C
    adc  r13, 0
    adc  r14, 0
    adc  r15, 0                 ; CF = 1  <=>  v >= p
    cmovc r8,  r12
    cmovc r9,  r13
    cmovc r10, r14
    cmovc r11, r15

    mov  [rdi + 0],  r8
    mov  [rdi + 8],  r9
    mov  [rdi + 16], r10
    mov  [rdi + 24], r11

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ============================================================================
; void fe_sqr(u64 r[4], const u64 a[4])
;   r = (a * a) mod p, result canonical in [0, p).
;
; This used to be `jmp fe_mul` with both operands equal. A dedicated square
; needs only 10 multiplies instead of 16, because the schoolbook product of a
; value with itself has just four distinct diagonal terms a_i^2 and six
; distinct off-diagonal terms a_i*a_j (i<j), each of which appears TWICE:
;
;     a^2 = 2*D + sum_i a_i^2 * 2^(128 i),
;     D   = a0a1*2^64 + a0a2*2^128 + (a0a3 + a1a2)*2^192
;           + a1a3*2^256 + a2a3*2^320
;
; So: accumulate D once (6 multiplies), double it with a single shift-left
; chain, then add the four squares (4 multiplies). Squaring is roughly 40 %
; of the field multiplies on the verify path -- fe_inv alone is 255 squares
; to 248 multiplies -- so the six saved multiplies are worth having.
;
; The reduction is NOT duplicated here: phase 1 leaves the exact 512-bit
; square in r8..r15 and jumps into fe_mul's .reduce, which also owns the
; shared epilogue. See the entry contract documented at that label.
;
; BOUNDS THAT MUST HOLD (all asserted per-step in the Python model, over
; 300,000 random values, every limb-boundary family, and the extremes
; 0, 1, 2^256-1, p, p-1, p-2^31):
;   * D < 2^448, so D occupies exactly T1..T6 and the a2a3 row cannot carry
;     out of T6. (With every limb at 2^64-1, D = 2^448 - 2^384 + ... < 2^448.)
;   * 2D < 2^449, so the doubling chain's carry out of T6 lands in T7 and
;     nothing above it.
;   * a^2 < 2^512, so the diagonal ripple cannot carry out of T7.
;   * Each ADOX chain ends on a limb that was still zero, so it terminates
;     at zero rather than dropping an overflow.
;
; Registers: rsi = a[] (live until the last diagonal load), r8..r15 = T[0..7],
;   rdx = mulx multiplicand, rax/rbx = mulx destinations, rbp = hard zero.
; ============================================================================
global fe_sqr
fe_sqr:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15                    ; same order fe_mul.reduce's epilogue pops

    xor  r8d,  r8d              ; T0 = 0 (only the diagonal writes it)
    xor  r13d, r13d             ; T5 = 0
    xor  r14d, r14d             ; T6 = 0
    xor  r15d, r15d             ; T7 = 0
    xor  ebp,  ebp              ; rbp = 0

    ; ---- D, part 1: a0*(a1,a2,a3) -> T1..T4 (nothing to accumulate yet) ----
    mov  rdx, [rsi + 0]         ; a0
    mulx r10, r9,  [rsi + 8]    ; T2:T1 = a0*a1
    mulx r11, rax, [rsi + 16]   ; T3:lo = a0*a2
    add  r10, rax
    mulx r12, rax, [rsi + 24]   ; T4:lo = a0*a3
    adc  r11, rax
    adc  r12, 0                 ; a0*(a1..a3) < 2^256, so no carry out

    ; ---- D, part 2: a1*(a2,a3) -> T3..T5 ----
    mov  rdx, [rsi + 8]         ; a1
    xor  ebp, ebp               ; CF = OF = 0, rbp = 0
    mulx rbx, rax, [rsi + 16]   ; a1*a2
    adcx r11, rax
    adox r12, rbx
    mulx rbx, rax, [rsi + 24]   ; a1*a3
    adcx r12, rax
    adox r13, rbx               ; T5 was 0: the OF chain ends here
    adcx r13, rbp

    ; ---- D, part 3: a2*a3 -> T5..T6 ----
    mov  rdx, [rsi + 16]        ; a2
    xor  ebp, ebp
    mulx rbx, rax, [rsi + 24]   ; a2*a3
    adcx r13, rax
    adox r14, rbx               ; T6 was 0
    adcx r14, rbp
    ; T1..T6 now hold D exactly, and D < 2^448.

    ; ---- 2D: one shift-left chain; the bit out of T6 becomes T7 ----
    add  r9,  r9
    adc  r10, r10
    adc  r11, r11
    adc  r12, r12
    adc  r13, r13
    adc  r14, r14
    adc  r15, 0                 ; T7 was 0, so T7 := carry out of T6

    ; ---- + the four diagonal squares, one ripple-carry chain ----
    ; a_i^2 lands on limbs (2i, 2i+1); the pairs are disjoint and processed
    ; in increasing limb order, so a single CF chain is exactly right. MOV
    ; and MULX leave the flags alone, which is what keeps the chain unbroken
    ; across the multiplies.
    mov  rdx, [rsi + 0]
    mulx rbx, rax, rdx          ; a0^2
    add  r8,  rax
    adc  r9,  rbx
    mov  rdx, [rsi + 8]
    mulx rbx, rax, rdx          ; a1^2
    adc  r10, rax
    adc  r11, rbx
    mov  rdx, [rsi + 16]
    mulx rbx, rax, rdx          ; a2^2
    adc  r12, rax
    adc  r13, rbx
    mov  rdx, [rsi + 24]
    mulx rbx, rax, rdx          ; a3^2
    adc  r14, rax
    adc  r15, rbx               ; a^2 < 2^512, so this cannot carry out

    ; r8..r15 = the exact 512-bit square; rbp is still 0; rsi is dead.
    jmp fe_mul.reduce

; ============================================================================
; void fe_inv(u64 r[4], const u64 a[4])
;   r = a^-1 mod p, computed by Fermat's little theorem: a^(p-2) == a^-1 (mod p).
;   Uses MSB->LSB square-and-multiply over the fixed exponent EXP = p-2,
;   driven only by the known constant EXP (no secret-dependent branching).
;
;   result := a
;   for each exponent bit from bit 254 down to 0:
;       result := fe_sqr(result)
;       if that exponent bit is set:  result := fe_mul(result, a)
;   r := result
;
; REGISTER plan (values that must survive the many fe_mul calls live in
; callee-saved registers, which fe_mul preserves: rbx, r12-r15; rbp too):
;   r15 = &A_i  (stack local copy of the input a, preserved across calls)
;   r14 = &R    (stack local accumulator, preserved across calls)
;   r13 = &EXP  (byte array of EXP = p-2, preserved across calls)
;   r12 = bit index (254..0), preserved across calls
;   rbx = scratch for the current exponent byte / mask, preserved across calls
; ============================================================================
global fe_inv
fe_inv:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64            ; [rsp+0..31] = A local, [rsp+32..63] = R local

    ; copy the caller's a[0..3] into the local A[] at [rsp+0]
    mov rax, [rsi + 0]
    mov [rsp + 0], rax
    mov rax, [rsi + 8]
    mov [rsp + 8], rax
    mov rax, [rsi + 16]
    mov [rsp + 16], rax
    mov rax, [rsi + 24]
    mov [rsp + 24], rax

    ; result := a   (start the accumulator at a^1)
    lea r15, [rsp + 0]
    lea r14, [rsp + 32]
    mov rax, [r15 + 0]
    mov [r14 + 0], rax
    mov rax, [r15 + 8]
    mov [r14 + 8], rax
    mov rax, [r15 + 16]
    mov [r14 + 16], rax
    mov rax, [r15 + 24]
    mov [r14 + 24], rax

    ; Preserve the caller's output pointer in rbx (callee-saved, so it
    ; survives every fe_mul call). rdi is caller-saved and is clobbered by the
    ; call argument setup inside the loop, so it CANNOT hold the output ptr.
    mov rbx, rdi            ; rbx = caller's r[] output pointer

    ; exp byte pointer
    lea r13, [EXP_BYTES]

    ; bit index (process 254 down to 0; bit 255 is the implicit leading 1)
    mov r12, 254

.inv_loop:
    ; --- square the accumulator: R := R^2 mod p ---
    mov rdi, r14
    mov rsi, r14
    mov rdx, r14
    call fe_mul

    ; --- determine the current exponent byte and bit ---
    ;   byte index b = r12 >> 3 ; bit = r12 & 7 ; mask = 1 << bit
    mov r9, r12
    shr r9, 3               ; byte index
    mov rcx, r12
    and rcx, 7              ; bit position 0..7
    mov r8, 1
    shl r8, cl              ; mask = 1 << bit

    ; --- test EXP_BYTES[b] & mask ---
    mov al, [r13 + r9]
    test al, r8b             ; test byte & mask (low 8 bits of r8 is the mask)
    jz .no_mul              ; exponent bit == 0 -> skip the multiply

    ; --- multiply: R := R * A mod p ---
    mov rdi, r14
    mov rsi, r14
    mov rdx, r15
    call fe_mul

.no_mul:
    dec r12
    jns .inv_loop           ; loop while bit index >= 0

    ; --- copy R[] out to the caller's r[] (pointer saved in rbx) ---
    mov rax, [r14 + 0]
    mov [rbx + 0], rax
    mov rax, [r14 + 8]
    mov [rbx + 8], rax
    mov rax, [r14 + 16]
    mov [rbx + 16], rax
    mov rax, [r14 + 24]
    mov [rbx + 24], rax

    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret


; ----------------------------------------------------------------------------
; Non-executable stack marker (consistent with sha256.asm hygiene).
; ----------------------------------------------------------------------------
section .note.GNU-stack noalloc noexec nowrite progbits
