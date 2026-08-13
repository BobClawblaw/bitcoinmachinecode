; ============================================================================
; secp256k1_scalar.asm -- scalar arithmetic mod the secp256k1 curve order n.
;   100% AI-authored x86-64 assembly (built from first principles, validated
;   against a self-written Python big-int oracle -- NOT derived from any
;   existing Bitcoin implementation).
;
; Scalars are 256-bit values reduced mod n, stored as 4 little-endian u64
; limbs (same convention as secp256k1_fe.asm / secp256k1_point.asm).
;
;   n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
;
; Exported API:
;   sc_add(r[4], a[4], b[4]) : r = (a+b) mod n
;   sc_sub(r[4], a[4], b[4]) : r = (a-b) mod n
;   sc_mul(r[4], a[4], b[4]) : r = (a*b) mod n
;   sc_sqr(r[4], a[4])       : r = (a*a) mod n
;   sc_inv(r[4], a[4])       : r = a^(n-2) mod n  (Fermat)
;
; DESIGN NOTE (correctness-first): sc_mul is implemented as MSB->LSB
; double-and-add in the scalar ring, using only sc_add (which is a simple,
; fully-tested 256-bit modular add).  This trades speed for clarity and
; verifiability: no multi-limb mulq/carry logic to get wrong.  ECDSA
; verification is not on the IBD hot path, so the constant factor cost is
; acceptable.  sc_inv uses MSB->LSB square-and-multiply over the Fermat
; exponent n-2.
;
;   System V AMD64 ABI: args rdi,rsi,rdx; preserve rbx/r12-r15. sc_mul/sc_inv
;   call sc_add/sc_sub, so they keep their own long-lived state in callee-saved
;   registers.
; ============================================================================

default rel

section .rodata

align 16
N_LIMBS:
    dq 0xBFD25E8CD0364141   ; limb0 of n
    dq 0xBAAEDCE6AF48A03B   ; limb1
    dq 0xFFFFFFFFFFFFFFFE   ; limb2
    dq 0xFFFFFFFFFFFFFFFF   ; limb3

; DELTA = 2^256 - n, 4 little-endian limbs. Folds an adc carry in sc_add
; (because 2^256 == DELTA mod n).
align 16
DELTA:
    dq 0x402DA1732FC9BEBF
    dq 0x4551231950B75FC4
    dq 0x0000000000000001
    dq 0x0000000000000000

; n - 2, the Fermat inverse exponent, as 32 little-endian bytes (sc_inv).
align 16
N_EXP:
    db 0x3f,0x41,0x36,0xd0,0x8c,0x5e,0xd2,0xbf
    db 0x3b,0xa0,0x48,0xaf,0xe6,0xdc,0xae,0xba
    db 0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    db 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
N_EXP_END:

section .text

; ----------------------------------------------------------------------------
; sc_add(r,a,b) = (a+b) mod n
;   s = a+b (adc chain). Sum in [0,2n) < 2^257, has at most one 257th bit.
;   If set (>=2^256): fold by adding DELTA (2^256 == DELTA mod n). This may
;   set a top bit again (DELTA ~2^128) once; fold again. Then one conditional
;   subtract of n canonicalizes.
; ----------------------------------------------------------------------------
global sc_add
sc_add:
    push rbx
    push r12
    push r13
    push r14

    mov rax, [rsi+0]
    add rax, [rdx+0]
    mov r8, rax
    mov rax, [rsi+8]
    adc rax, [rdx+8]
    mov r9, rax
    mov rax, [rsi+16]
    adc rax, [rdx+16]
    mov r10, rax
    mov rax, [rsi+24]
    adc rax, [rdx+24]
    mov r11, rax          ; CF = carry (257th bit)

    jnc .folded
    add r8, [DELTA+0]
    adc r9, [DELTA+8]
    adc r10, [DELTA+16]
    adc r11, [DELTA+24]
    jnc .folded
    add r8, [DELTA+0]
    adc r9, [DELTA+8]
    adc r10, [DELTA+16]
    adc r11, [DELTA+24]

.folded:
    mov rax, r8
    sub rax, [N_LIMBS+0]
    mov rcx, rax
    mov rax, r9
    sbb rax, [N_LIMBS+8]
    mov rbx, rax
    mov rax, r10
    sbb rax, [N_LIMBS+16]
    mov r12, rax
    mov rax, r11
    sbb rax, [N_LIMBS+24]
    mov r13, rax
    cmovnc r8, rcx
    cmovnc r9, rbx
    cmovnc r10, r12
    cmovnc r11, r13

    mov [rdi+0], r8
    mov [rdi+8], r9
    mov [rdi+16], r10
    mov [rdi+24], r11

    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; sc_sub(r,a,b) = (a-b) mod n  : d = a-b; if borrow add n back.
; ----------------------------------------------------------------------------
global sc_sub
sc_sub:
    push rbx
    push r12
    push r13

    mov rax, [rsi+0]
    sub rax, [rdx+0]
    mov r8, rax
    mov rax, [rsi+8]
    sbb rax, [rdx+8]
    mov r9, rax
    mov rax, [rsi+16]
    sbb rax, [rdx+16]
    mov r10, rax
    mov rax, [rsi+24]
    sbb rax, [rdx+24]
    mov r11, rax

    jnc .store
    add r8, [N_LIMBS+0]
    adc r9, [N_LIMBS+8]
    adc r10, [N_LIMBS+16]
    adc r11, [N_LIMBS+24]

.store:
    mov [rdi+0], r8
    mov [rdi+8], r9
    mov [rdi+16], r10
    mov [rdi+24], r11

    pop r13
    pop r12
    pop rbx
    ret

; ----------------------------------------------------------------------------
; sc_mul(r,a,b) = (a*b) mod n, via MSB->LSB double-and-add in the scalar ring.
;   Uses only sc_add. Long-lived values in callee-saved regs (sc_add preserves
;   rbx/r12-r15).
;     r12 = result accumulator, r13 = a (multiplicand), r14 = b copy (4 limbs
;          held on stack), r15 = running bit index (255..0)
;   Main loop per bit: result += result; if set-bit: result += a.
; ----------------------------------------------------------------------------
global sc_mul
sc_mul:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0xc8        ; layout (all BELOW save area [rbp-8..-40]):
                          ;   R contig @ [rbp-0x78, -0x70, -0x68, -0x60]
                          ;     (limb0..3; sc_add writes contiguously upward
                          ;      from its rdi, so R must be contiguous here)
                          ;   b ascending @ [-0xa8,-0xa0,-0x98,-0x90]
                          ; 0xc8==8 mod 16 so nested sc_add calls stay aligned

    ; r12 = original output pointer
    mov r12, rdi
    ; copy b (rdx) ascending: b[j] at [rbp-0xa8 + 8*j]
    mov rax, [rdx+0]
    mov [rbp-0xa8], rax
    mov rax, [rdx+8]
    mov [rbp-0xa0], rax
    mov rax, [rdx+16]
    mov [rbp-0x98], rax
    mov rax, [rdx+24]
    mov [rbp-0x90], rax
    ; r13 = a (multiplicand)
    mov r13, rsi
    ; R = 0  (contiguous)
    mov qword [rbp-0x78], 0
    mov qword [rbp-0x70], 0
    mov qword [rbp-0x68], 0
    mov qword [rbp-0x60], 0

    ; iterate bit i = 255..0 : R = 2R ; if bit i of b set: R += a
    mov r15, 255
.dbl_loop:
    lea rdi, [rbp-0x78]
    lea rsi, [rbp-0x78]
    mov rdx, rsi
    call sc_add

    mov rcx, r15
    shr rcx, 6
    shl rcx, 3
    mov rdx, r15
    and rdx, 63
    mov rax, [rbp-0xa8+rcx]
    bt rax, rdx
    jnc .next
    lea rdi, [rbp-0x78]
    lea rsi, [rbp-0x78]
    mov rdx, r13
    call sc_add
.next:
    dec r15
    jns .dbl_loop

    ; copy R (contiguous) -> output (r12)
    mov rax, [rbp-0x78]
    mov [r12+0], rax
    mov rax, [rbp-0x70]
    mov [r12+8], rax
    mov rax, [rbp-0x68]
    mov [r12+16], rax
    mov rax, [rbp-0x60]
    mov [r12+24], rax

    add rsp, 0xc8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ----------------------------------------------------------------------------
; sc_sqr(r,a) = (a*a) mod n
; ----------------------------------------------------------------------------
global sc_sqr
sc_sqr:
    ; tail-jump into sc_mul with b = a : sc_mul(r, a, a)
    mov rdx, rsi
    jmp sc_mul

; ----------------------------------------------------------------------------
; sc_inv(r,a) = a^(n-2) mod n, MSB->LSB square-and-multiply over N_EXP bytes.
;   long-lived: r12 = &resultR, r13 = &baseA, r14 = iterator index (254..0),
;               rbx = final output pointer.
; ----------------------------------------------------------------------------
global sc_inv
sc_inv:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0xa8

    mov rbx, rdi           ; output
    ; R = A local at -0x50 ; A base at -0x78
    ; copy a (rsi) -> [-0x78..-0x90] and R = a -> [-0x50..-0x68]
    mov rax, [rsi+0]
    mov [rbp-0x78], rax
    mov [rbp-0x50], rax
    mov rax, [rsi+8]
    mov [rbp-0x70], rax
    mov [rbp-0x48], rax
    mov rax, [rsi+16]
    mov [rbp-0x68], rax
    mov [rbp-0x40], rax
    mov rax, [rsi+24]
    mov [rbp-0x60], rax
    mov [rbp-0x38], rax
    lea r13, [rbp-0x78]    ; A
    lea r12, [rbp-0x50]    ; R
    lea r14, [N_EXP]       ; base pointer to the Fermat exponent bytes (load
                           ; once; index with a register is PIC-safe, whereas
                           ; a 32-bit absolute of rodata is not)

    ; iterate bits 254..0
    mov r15, 254
.inv_loop:
    ; R = R*R
    mov rdi, r12
    mov rsi, r12
    mov rdx, r12
    call sc_mul
    ; test bit r15 of N_EXP
    mov rcx, r15
    shr rcx, 3
    mov rdx, r15
    and rdx, 7
    movzx eax, byte [r14 + rcx]
    bt rax, rdx
    jnc .inv_next
    ; R = R * A
    mov rdi, r12
    mov rsi, r12
    mov rdx, r13
    call sc_mul
.inv_next:
    dec r15
    jns .inv_loop

    ; copy R (r12) -> output (rbx)
    mov rax, [r12+0]
    mov [rbx+0], rax
    mov rax, [r12+8]
    mov [rbx+8], rax
    mov rax, [r12+16]
    mov [rbx+16], rax
    mov rax, [r12+24]
    mov [rbx+24], rax

    add rsp, 0xa8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits

