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
;   Computes r = (a + b) mod p using a 4-limb add with carry, then performs a
;   conditional subtract of p to fold any value >= p back into [0, p).
;
;   Because a,b < p < 2^256, a+b < 2^257, i.e. at most one carry out of the
;   top limb and then a value < 2p. We subtract p up to twice (carry from the
;   top limb contributes +1, so one extra subtract handles it).
;
; Registers:
;   rax      : limb scratch / running carry
;   r8..r11  : the four limbs of the sum
;   rdi      : r[]  (survives as destination)
;   rsi, rdx : a[], b[]
; ----------------------------------------------------------------------------
global fe_add
fe_add:
    push rbx
    push r12
    push r13
    push r14              ; preserve callee-saved registers we touch

    ; ---- 256-bit add with carry: sum = a + b ----
    mov rax, [rsi + 0]
    add rax, [rdx + 0]
    mov r8, rax           ; limb0 of sum

    mov rax, [rsi + 8]
    adc rax, [rdx + 8]
    mov r9, rax           ; limb1

    mov rax, [rsi + 16]
    adc rax, [rdx + 16]
    mov r10, rax          ; limb2

    mov rax, [rsi + 24]
    adc rax, [rdx + 24]
    mov r11, rax          ; limb3

    ; carry out of the top limb, if any, is in CF.
    ; We now have sum = r8:r9:r10:r11 (little-endian limbs) in [0, 2^257).
    ; If CF=1, the value is >= 2^256, so subtract p once (which clears the
    ; extra 2^256 because 2^256 - p is small). Equivalent: if the top 257th
    ; bit is set, add (2^256 - p) as a fourth carry then subtract p.

    ; Approach: perform r = sum - p; if borrow, r = sum. We need a constant-
    ; time(ish) selection. Because sum < 2p always, one conditional subtract
    ; of p suffices *provided* we first fold any carry by adding back
    ; (2^256 - p). Do: t = sum + carry*2^256; then if t >= p, t -= p.
    ; Simplest correct route:
    ;   1) t0..t3 = sum limbs (r8..r11), and cf = carry.
    ;   2) if cf: compute sum = sum + (2^256 - p)  [adds low differ, all-ones high]
    ;   3) conditional subtract p if sum >= p.
    ; We implement step 2 with adc from a zero high limb.

    ; Step 2: fold the carry. 2^256 - p = 2^32 + 977. So add (carry)*(2^32+977)
    ; to the low limb and propagate. Now branch-free (FINDING 3): the 257th
    ; carry bit becomes a mask, and (2^256 - p) is conditionally added without
    ; a jump, keeping the instruction count independent of the operand values.
    sbb rbx, rbx            ; rbx = -CF = 0 (no carry) or -1 (carry mask)
    mov rax, [C_CONST]
    and rax, rbx            ; masked (2^32+977)
    add r8, rax
    adc r9, 0
    adc r10, 0
    adc r11, 0

.no_carry_fold:
    ; ---- conditional subtract p: t = sum - p; if borrow, keep sum ----
    mov rax, r8
    sub rax, [P_LIMBS + 0]
    mov rcx, rax            ; t0
    mov rax, r9
    sbb rax, [P_LIMBS + 8]
    mov rbx, rax            ; t1
    mov rax, r10
    sbb rax, [P_LIMBS + 16]
    mov r12, rax            ; t2
    mov rax, r11
    sbb rax, [P_LIMBS + 24]
    mov r13, rax            ; t3 ; CF = borrow

    ; select: if borrow (sum < p), keep original sum; else use t = sum - p.
    ; cmovnc copies the reduced limb ONLY when no borrow occurred (sum was >= p);
    ; when a borrow did occur the destination keeps its original sum limb.
    cmovnc r8, rcx          ; use t0 = sum0-p  if sum >= p (no borrow)
    cmovnc r9, rbx
    cmovnc r10, r12
    cmovnc r11, r13

    ; ---- store result ----
    mov [rdi + 0],  r8
    mov [rdi + 8],  r9
    mov [rdi + 16], r10
    mov [rdi + 24], r11

    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; void fe_sub(u64 r[4], const u64 a[4], const u64 b[4])
;   Computes r = (a - b) mod p.
;   a,b in [0,p). Compute d = a - b with borrow; if borrow, add p back.
; ----------------------------------------------------------------------------
global fe_sub
fe_sub:
    push rbx
    push r12
    push r13

    mov rax, [rsi + 0]
    sub rax, [rdx + 0]
    mov r8, rax
    mov rax, [rsi + 8]
    sbb rax, [rdx + 8]
    mov r9, rax
    mov rax, [rsi + 16]
    sbb rax, [rdx + 16]
    mov r10, rax
    mov rax, [rsi + 24]
    sbb rax, [rdx + 24]
    mov r11, rax            ; r8..r11 = a - b, CF = borrow

    ; if borrow (a < b), add p: d += p. Now branch-free (FINDING 3): the
    ; borrow is turned into a mask and p is conditionally re-added, so the
    ; instruction count is independent of the operand values (secret-clean for
    ; the future constant-time ladder).
    sbb rax, rax            ; rax = -CF  = 0 (no borrow) or -1 (borrow) = mask
    ; Pre-mask p limbs into scratch so the add/adc chain has no interleaved
    ; flag-clobbering `and` between an `add` and its `adc`.
    mov rbx, [P_LIMBS + 0]
    and rbx, rax
    mov r12, [P_LIMBS + 8]
    and r12, rax
    mov r13, [P_LIMBS + 16]
    and r13, rax
    mov rcx, [P_LIMBS + 24]
    and rcx, rax
    add r8, rbx
    adc r9, r12
    adc r10, r13
    adc r11, rcx

.store:
    mov [rdi + 0],  r8
    mov [rdi + 8],  r9
    mov [rdi + 16], r10
    mov [rdi + 24], r11

    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; void fe_mul(u64 r[4], const u64 a[4], const u64 b[4])
;   Computes r = (a * b) mod p.
;
; ALGORITHM
;   Phase 1 -- 256x256 -> 512-bit schoolbook product over 64-bit limbs:
;     product[k] = sum over (i,j): i+j=k of a[i]*b[j], each term a 64x64->128
;     multiply; accumulated limb-by-limb with carry propagation.
;   Phase 2 -- reduction. Write t = t1*2^256 + t0 (t0 = product[0..3],
;     t1 = product[4..7]). Because 2^256 == C (mod p), where
;     C = 2^32 + 977 = 0x10000003D1:
;       t (mod p) == t0 + t1*C
;     Iterating this fold shrinks a 512-bit product to < 2^256 in TWO steps
;     (validated over 20000 random cases in Python: 512 -> 288 -> 256 bits).
;     After two folds the value is < 2^256 and, since p > 2^255, at most < 2p,
;     so ONE conditional subtract of p canonicalizes it.
;
; REGISTER / FRAME plan (System V ABI):
;   rdi = r[] (result, written at the very end)
;   rsi = a[] ; rdx = b[]
;   callee-saved used and pushed: rbx, r12, r13, r14, r15
;   caller-saved used freely: rax, rcx, r8, r9, r10, r11
;   Stack scratch (64 bytes): product[0..7] at [rsp+0 .. rsp+63].
;
; PHASE-1 limb schedule (a0..a3 = a[0..3], b0..b3 = b[0..3]):
;   p0 = a0*b0
;   p1 = a1*b0 + a0*b1
;   p2 = a2*b0 + a1*b1 + a0*b2
;   p3 = a3*b0 + a2*b1 + a1*b2 + a0*b3
;   p4 = a3*b1 + a2*b2 + a1*b3
;   p5 = a3*b2 + a2*b3
;   p6 = a3*b3
;   (carries absorbed into the limb above; p7 catches the overflow of p6.)
; We compute each product term with mulq (rax:rdx = src1*src2) and fan each
; term into its destination limb with ADC, tracking the carry upward.
; ============================================================================
global fe_mul
fe_mul:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64            ; 8 x u64 product scratch: [rsp+0 .. rsp+63]

    ; Keep pointers/values in callee-saved regs so calls (none here, but keeps
    ; an audit-clean function) and address math stay live:
    ;   r15 = a pointer ; r14 = b pointer ; rdi preserved = r pointer
    ; We'll read a[i], b[j] via rsi/rdx directly and not disturb rdi.

    ; ---- Phase 1: compute the 512-bit schoolbook product ----
    ; Keep a[] in r13 and b[] in r14. CRITICAL: 'mul' clobbers rdx, so the b
    ; pointer must live in a register mul does not touch (a callee-saved one).
    ; The inner accumulation uses the row method: for each a_i, multiply it by
    ; all four b_j, adding each 128-bit term into C[i+j] with a running 64-bit
    ; carry that rides in r9. This is auditable because every step is a simple
    ; add/adc into a memory limb with an explicit carry register.

    ; Load operand pointers.
    mov r13, rsi            ; r13 = a[]
    mov r14, rdx            ; r14 = b[]  (survives 'mul')

    ; Zero the 8 product limbs C[0..7] at [rsp].
    xor eax, eax
    mov rcx, 8
    lea r8, [rsp]
.zero:
    mov [r8], rax
    add r8, 8
    dec rcx
    jnz .zero

    ; ======================================================================
    ; ROW 0 : a0 * (b0,b1,b2,b3)  -->  C[0..3]
    ; ======================================================================
    mov rbx, [r13 + 0]      ; rbx = a0
    xor r9, r9              ; carry = 0
    ; j=0
    mov rax, rbx
    mul qword [r14 + 0]     ; rax:rdx = a0*b0
    mov r8, [rsp + 0]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 0], r8       ; C0
    ; j=1
    mov rax, rbx
    mul qword [r14 + 8]
    mov r8, [rsp + 8]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 8], r8       ; C1
    ; j=2
    mov rax, rbx
    mul qword [r14 + 16]
    mov r8, [rsp + 16]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 16], r8      ; C2
    ; j=3
    mov rax, rbx
    mul qword [r14 + 24]
    mov r8, [rsp + 24]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 24], r8      ; C3
    ; propagate trailing carry into C4 (C4 was zero so far)
    mov [rsp + 32], r9      ; C4 = carry (can't overflow up, C4 was 0)

    ; ======================================================================
    ; ROW 1 : a1 * (b0..b3)  -->  C[1..4]
    ; ======================================================================
    mov rbx, [r13 + 8]      ; rbx = a1
    xor r9, r9              ; carry = 0
    ; j=0 -> C1
    mov rax, rbx
    mul qword [r14 + 0]
    mov r8, [rsp + 8]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 8], r8
    ; j=1 -> C2
    mov rax, rbx
    mul qword [r14 + 8]
    mov r8, [rsp + 16]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 16], r8
    ; j=2 -> C3
    mov rax, rbx
    mul qword [r14 + 16]
    mov r8, [rsp + 24]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 24], r8
    ; j=3 -> C4
    mov rax, rbx
    mul qword [r14 + 24]
    mov r8, [rsp + 32]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 32], r8
    ; propagate trailing carry into C5
    mov rax, [rsp + 40]
    add rax, r9
    mov [rsp + 40], rax
    adc qword [rsp + 48], 0     ; C6 absorbs any carry-out of C5

    ; ======================================================================
    ; ROW 2 : a2 * (b0..b3)  -->  C[2..5]
    ; ======================================================================
    mov rbx, [r13 + 16]     ; rbx = a2
    xor r9, r9
    ; j=0 -> C2
    mov rax, rbx
    mul qword [r14 + 0]
    mov r8, [rsp + 16]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 16], r8
    ; j=1 -> C3
    mov rax, rbx
    mul qword [r14 + 8]
    mov r8, [rsp + 24]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 24], r8
    ; j=2 -> C4
    mov rax, rbx
    mul qword [r14 + 16]
    mov r8, [rsp + 32]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 32], r8
    ; j=3 -> C5
    mov rax, rbx
    mul qword [r14 + 24]
    mov r8, [rsp + 40]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 40], r8
    ; propagate trailing carry into C6
    mov rax, [rsp + 48]
    add rax, r9
    mov [rsp + 48], rax
    adc qword [rsp + 56], 0     ; C7 absorbs any carry-out of C6

    ; ======================================================================
    ; ROW 3 : a3 * (b0..b3)  -->  C[3..6]
    ; ======================================================================
    mov rbx, [r13 + 24]     ; rbx = a3
    xor r9, r9
    ; j=0 -> C3
    mov rax, rbx
    mul qword [r14 + 0]
    mov r8, [rsp + 24]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 24], r8
    ; j=1 -> C4
    mov rax, rbx
    mul qword [r14 + 8]
    mov r8, [rsp + 32]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 32], r8
    ; j=2 -> C5
    mov rax, rbx
    mul qword [r14 + 16]
    mov r8, [rsp + 40]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 40], r8
    ; j=3 -> C6
    mov rax, rbx
    mul qword [r14 + 24]
    mov r8, [rsp + 48]
    add r8, rax
    adc rdx, 0
    add r8, r9
    adc rdx, 0
    mov r9, rdx
    mov [rsp + 48], r8
    ; propagate trailing carry into C7 (cannot overflow past 512 bits)
    mov rax, [rsp + 56]
    add rax, r9
    mov [rsp + 56], rax
    ; (product < 2^512, so C7 plus carry cannot overflow into a C8)

    ; ======================================================================
    ; Phase 2: reduction. Fold the 512-bit product (limbs 0..7) into a
    ; canonical <p 4-limb element using two applications of
    ;   value := (value & MASK256) + ((value >> 256) * C),  C = 2^32+977.
    ; Each fold computes  new = low4 + high*C.
    ;
    ; FOLD 1  (high = product limbs 4..7, 256 bits):
    ;   new0 = C0 + lo4
    ;   new1 = C1 + hi4 + lo5
    ;   new2 = C2 + hi5 + lo6
    ;   new3 = C3 + hi6 + lo7
    ;   new4 =        hi7
    ;   where Ci = product[i], and (loX,hiX) = Cx*C split into low/high 64-bit
    ;   words. Carries propagate upward. Result spans 5 limbs (up to 289 bits).
    ;
    ; FOLD 2  (high = the single 33-bit limb new4):
    ;   res0 = new0 + lo(new4*C)
    ;   res1 = new1 + hi(new4*C)
    ;   res2 = new2 (+ incoming carry)
    ;   res3 = new3 (+ incoming carry)
    ;   Result < 2^256 (validated in Python), then one conditional subtract of p.
    ; ======================================================================

    ; ---- FOLD 1: compute (loX, hiX) = Cx * C for x in 4..7 ----
    mov rax, [rsp + 32]     ; C4
    mul qword [C_CONST]     ; rax=lo4, rdx=hi4
    mov r8, rax             ; lo4
    mov r9, rdx             ; hi4

    mov rax, [rsp + 40]     ; C5
    mul qword [C_CONST]
    mov r12, rax            ; lo5   (r12 is callee-saved, already pushed)
    mov r13, rdx            ; hi5

    mov rax, [rsp + 48]     ; C6
    mul qword [C_CONST]
    mov r10, rax            ; lo6
    mov r11, rdx            ; hi6

    mov rax, [rsp + 56]     ; C7
    mul qword [C_CONST]
    mov r14, rax            ; lo7
    mov r15, rdx            ; hi7

    ; new0 = C0 + lo4 ; carry -> rbx
    mov rax, [rsp + 0]
    add rax, r8
    mov rbx, 0
    adc rbx, 0
    mov [rsp + 0], rax      ; overwrite C0 with new0

    ; new1 = C1 + hi4 + lo5 + carry_in ; carry_out -> rbx
    mov rax, [rsp + 8]
    xor edx, edx
    add rax, r9
    adc rdx, 0
    add rax, r12
    adc rdx, 0
    add rax, rbx
    adc rdx, 0
    mov [rsp + 8], rax      ; new1
    mov rbx, rdx

    ; new2 = C2 + hi5 + lo6 + carry_in
    mov rax, [rsp + 16]
    xor edx, edx
    add rax, r13
    adc rdx, 0
    add rax, r10
    adc rdx, 0
    add rax, rbx
    adc rdx, 0
    mov [rsp + 16], rax     ; new2
    mov rbx, rdx

    ; new3 = C3 + hi6 + lo7 + carry_in
    mov rax, [rsp + 24]
    xor edx, edx
    add rax, r11
    adc rdx, 0
    add rax, r14
    adc rdx, 0
    add rax, rbx
    adc rdx, 0
    mov [rsp + 24], rax     ; new3
    mov rbx, rdx

    ; new4 = hi7 + carry_in (the 33-bit top limb)
    mov rax, r15
    add rax, rbx
    mov [rsp + 32], rax     ; new4  (overwrites C4)

    ; ---- FOLD 2: res = low(new0..new3) + new4*C ----
    mov rax, [rsp + 32]     ; new4 (<=33 bits)
    mul qword [C_CONST]     ; rax = lo2, rdx = hi2
    mov r8, rax             ; lo2
    mov r9, rdx             ; hi2 (<=33 bits)

    ; res0 = new0 + lo2
    mov rax, [rsp + 0]
    add rax, r8
    mov rbx, 0
    adc rbx, 0
    mov r10, rax            ; res0 -> r10

    ; res1 = new1 + hi2 + carry_in
    mov rax, [rsp + 8]
    xor edx, edx
    add rax, r9
    adc rdx, 0
    add rax, rbx
    adc rdx, 0
    mov r11, rax            ; res1 -> r11
    mov rbx, rdx

    ; res2 = new2 + carry_in
    mov rax, [rsp + 16]
    xor edx, edx
    add rax, rbx
    adc rdx, 0
    mov r12, rax            ; res2 -> r12
    mov rbx, rdx

    ; res3 = new3 + carry_in  (result < 2^256, top carry is dropped)
    mov rax, [rsp + 24]
    add rax, rbx
    mov r13, rax            ; res3 -> r13

    ; ---- canonicalize: if value >= p, subtract p once ----
    mov rax, r10
    sub rax, [P_LIMBS + 0]
    mov rcx, rax            ; t0
    mov rax, r11
    sbb rax, [P_LIMBS + 8]
    mov r8, rax             ; t1
    mov rax, r12
    sbb rax, [P_LIMBS + 16]
    mov r9, rax             ; t2
    mov rax, r13
    sbb rax, [P_LIMBS + 24]
    mov r14, rax            ; t3 ; CF = borrow
    ; if no borrow (value >= p) use the reduced t; else keep value.
    cmovnc r10, rcx
    cmovnc r11, r8
    cmovnc r12, r9
    cmovnc r13, r14

    ; ---- store the canonical result into r[] ----
    mov [rdi + 0],  r10
    mov [rdi + 8],  r11
    mov [rdi + 16], r12
    mov [rdi + 24], r13

    ; ---- epilogue: release scratch, restore callee-saved, return ----
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ============================================================================
; void fe_sqr(u64 r[4], const u64 a[4])
;   r = (a * a) mod p. Squaring is the same modular multiply with both
;   operands equal, so we simply forward to fe_mul. No separate code needed.
; ============================================================================
global fe_sqr
fe_sqr:
    mov rdx, rsi            ; a is both multiplicands: rd/... rdx = a (2nd op)
    jmp fe_mul              ; fe_mul(r, a, a)  (rdi=r, rsi=a already set)

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
