; ============================================================================
; bitcoin_pubkey.asm -- secp256k1 public-key parsing / affine-limb recovery
;
;   int pubkey_parse(const u8 *pub, unsigned long publen,
;                    u64 qx[4], u64 qy[4])
;       Parse a canonical secp256k1 public key and return its affine
;       coordinates as two 4x u64 little-endian limbs (the form fe_* and
;       ecdsa_verify consume). Returns 1 on a structurally valid on-curve
;       point, 0 otherwise.
;         - compressed (33 bytes, first byte 0x02 or 0x03): x = bytes 1..32,
;           y = sqrt(x^3 + 7) with matching parity bit.
;         - uncompressed (65 bytes, first byte 0x04): x,y given; y is checked
;           to satisfy y^2 == x^3 + 7 (mod p) -- an on-curve membership probe.
;
;   static void fe_pow(u64 out[4], const u64 base[4], const u64 exp[4])
;       out = base^exp (mod p), exp a 256-bit little-endian exponent.
;       Square-and-multiply. Exported (not static) for testing via
;       tests/test_pubkey.c. EXP must be nonzero.
;
; Field arithmetic lives in secp256k1_fe.asm (u64[4] little-endian limbs):
;   fe_sqr(r,a) ; fe_mul(r,a,b) ; fe_add ; fe_sub ; fe_inv
; P_LIMBS holds the 256-bit prime p.
;
; ABI: System V AMD64. All helpers here preserve callee-saved regs and keep
; rsp 8-mod-16 at every `call` (locals live below [rbp-8..-0x28] with pushes).
; ============================================================================
    default rel
    global pubkey_parse
    global fe_pow

    extern fe_sqr
    extern fe_mul
    extern fe_sub
    extern fe_add

; ---- exponent (p+1)/4 for square-root (y = x^((p+1)/4)) as 4 LE limbs ----
section .rodata
align 16
EXP_QR:
    dq 0xFFFFFFFFBFFFFF0C
    dq 0xFFFFFFFFFFFFFFFF
    dq 0xFFFFFFFFFFFFFFFF
    dq 0x3FFFFFFFFFFFFFFF
; ---- 7 (curve constant), as 4 LE limbs ----
CURVE7:
    dq 7, 0, 0, 0

section .data
; scratch area? none needed -- all locals live on the stack.

section .text
; ============================================================================
; fe_pow(out[4], base[4], exp[4]) -- square-and-multiply, exp != 0.
; ============================================================================
fe_pow:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x198
    ; 5 pushes (0x28) + sub 0x198 = total 0x1c0 == 0 mod16,
                            ; so rsp = rbp-0x1c0 == 8mod16 at calls (rbp==8mod16).
                            ; Locals below [rbp-8..-0x28].
    ; ---- save arg pointers in callee-saved (helpers preserve them) ----
    mov   r12, rdi
    ; out
    mov   r13, rsi
    ; base
    mov   r14, rdx
    ; exp[4]
    ; ---- acc = 1 (init to field one) at [rbp-0x38+0x20]? locals below -0x28.
    ; acc at [rbp-0x40 .. -0x30]; tmp at [rbp-0xa0 .. -0x90]? Let's lay out:
    ;   acc  [rbp-0x48] x4 limbs -> [-0x48,-0x40,-0x38,-0x30]
    ;   tmp  [rbp-0xc8] x4 limbs -> [-0xc8,-0xc0,-0xb8,-0xb0]
    ; We must NOT touch [rbp-8..-0x28] (callee-saved save area).
    ; acc = 1: limb0=1, rest 0.
    mov   qword [rbp-0x48], 1
    mov   qword [rbp-0x40], 0
    mov   qword [rbp-0x38], 0
    mov   qword [rbp-0x30], 0
    ; ---- scan exponent bits from most-significant bit down (bit 255) ----
    mov   r15, 255
    ; bit index
.pow_bit:
    ; acc = acc^2
    lea   rdi, [rbp-0xc8]
    ; tmp
    lea   rsi, [rbp-0x48]
    ; acc
    call  fe_sqr
    ; copy tmp -> acc ([rbp-0x48] = tmp[0..3])
    mov   rax, [rbp-0xc8]
    mov [rbp-0x48], rax
    mov   rax, [rbp-0xc0]
    mov [rbp-0x40], rax
    mov   rax, [rbp-0xb8]
    mov [rbp-0x38], rax
    mov   rax, [rbp-0xb0]
    mov [rbp-0x30], rax
    ; ---- test exponent bit (r15) ; MSB-first: bit index == r15 directly ----
    ; byte index = r15>>3 ; bit = r15&7
    mov   rdx, r15
    shr   rdx, 3
    ; byte idx
    movzx rax, byte [r14 + rdx]
    mov   rcx, r15
    and   rcx, 7
    bt    rax, rcx
    jnc   .pow_next
    ; multiply: tmp = acc * base  (fe_mul preserves r15; do NOT push r15 here --
    ; a push would change rsp by 8 and break the 8mod16 parity at the call)
    lea   rdi, [rbp-0xc8]
    lea   rsi, [rbp-0x48]
    mov   rdx, r13
    ; base
    call  fe_mul
    mov   rax, [rbp-0xc8]
    mov [rbp-0x48], rax
    mov   rax, [rbp-0xc0]
    mov [rbp-0x40], rax
    mov   rax, [rbp-0xb8]
    mov [rbp-0x38], rax
    mov   rax, [rbp-0xb0]
    mov [rbp-0x30], rax
.pow_next:
    dec   r15
    jns   .pow_bit
    ; ---- out = acc ----
    mov   rax, [rbp-0x48]
    mov [r12+0x00], rax
    mov   rax, [rbp-0x40]
    mov [r12+0x08], rax
    mov   rax, [rbp-0x38]
    mov [r12+0x10], rax
    mov   rax, [rbp-0x30]
    mov [r12+0x18], rax
    add   rsp, 0x198
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop   rbp
    ret

; ============================================================================
; pubkey_parse(pub, publen, qx[4], qy[4])
; ============================================================================
pubkey_parse:
    push  rbp
    mov   rbp, rsp
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 0x1d8
    ; 5 pushes(0x28) + 0x1d8 = 0x200 == 0 mod16 -> rsp==8mod16.
    mov   r12, rdi
    ; pub
    mov   r13, rsi
    ; publen
    mov   r14, rdx
    ; qx
    mov   r15, rcx
    ; qy
    ; ---- dispatch on first byte / length ----
    movzx eax, byte [r12]
    cmp   r13, 33
    je    .chk_comp
    cmp   r13, 65
    je    .chk_uncomp
    xor   eax, eax
    ; bad length -> invalid
    jmp   .done

.chk_comp:
    ; first byte must be 0x02 or 0x03
    ; (note: r12[0] already in eax; but eax was clobbered? we re-read)
    movzx eax, byte [r12]
    cmp   al, 0x02
    je    .do_comp
    cmp   al, 0x03
    jne   .bad_ret
.do_comp:
    ; x = bytes 1..32 (RLE: copy pub+1 -> x local [rbp-0x50 .. -0x30])
    ; copy 32 bytes to x [rbp-0x50 .. -0x30]
    mov   rcx, 32
    lea   rdi, [rbp-0x50]
    lea   rsi, [r12+1]
.copy_x1:
    mov   al, [rsi]
    mov [rdi], al
    inc   rdi
    inc rsi
    dec rcx
    jnz .copy_x1
    ; ---- convert x (32 BE bytes at [rbp-0x50]) to 4 LE limbs at [rbp-0x118]
    ; limb j (LE) = bytes[(3-j)*8 .. +7] bswapped  (matches bitcoin_keys.asm)
    ; (we use -0x118 as x-limbs; x-bytes stay at -0x50 for nothing further)
    xor   rcx, rcx
.xlimb:
    cmp   rcx, 4
    jae   .xlimb_done
    mov   rdx, rcx
    neg   rdx
    add   rdx, 3
    mov   rax, [rbp-0x50 + rdx*8]
    bswap rax
    mov   [rbp-0x118 + rcx*8], rax
    inc   rcx
    jmp   .xlimb
.xlimb_done:
    ; y = sqrt(x^3 + 7) mod p.
    ;   x2 = sqr(x)            ; x3 = mul(x2,x) ; t = add(x3,7)
    ;   y = t^((p+1)/4)        ; verify y^2 == t
    ; locals: x-limbs -0x118, x2 -0xc8, x3 -0x90, t -0x168, y -0x1b8
    ; ---- x2 = x^2
    lea   rdi, [rbp-0xc8]
    lea   rsi, [rbp-0x118]
    call  fe_sqr
    ; ---- x3 = x2 * x
    lea   rdi, [rbp-0x90]
    lea   rsi, [rbp-0xc8]
    lea   rdx, [rbp-0x118]
    call  fe_mul
    ; ---- t = x3 + 7
    lea   rdi, [rbp-0x168]
    lea   rsi, [rbp-0x90]
    lea   rdx, [CURVE7]
    call  fe_add
    ; ---- y = t^((p+1)/4)
    lea   rdi, [rbp-0x1b8]
    lea   rsi, [rbp-0x168]
    lea   rdx, [EXP_QR]
    call  fe_pow
    ; ---- verify y^2 == t
    lea   rdi, [rbp-0xc8]
    ; reuse x2 slot as y2
    lea   rsi, [rbp-0x1b8]
    call  fe_sqr
    ; compare y2[0..3] == t[0..3]
    lea   rsi, [rbp-0x168]
    ; y2 at [rbp-0xc8]
    mov   rax,[rbp-0xc8]
    cmp rax,[rsi+  0]
    jne .bad_ret
    mov   rax,[rbp-0xc0]
    cmp rax,[rsi+  8]
    jne .bad_ret
    mov   rax,[rbp-0xb8]
    cmp rax,[rsi+ 16]
    jne .bad_ret
    mov   rax,[rbp-0xb0]
    cmp rax,[rsi+ 24]
    jne .bad_ret
    ; ---- fix parity: y should have odd/even parity matching pub[0]&1 ----
    movzx r9d, byte [r12]
    ; 0x02 or 0x03
    and   r9d, 1
    ; need y&1 == r9d
    mov   rax, [rbp-0x1b8]
    ; y limb0 = value
    ; parity = bit0
    and   eax, 1
    cmp   eax, r9d
    je    .store_y
    ; need y = -y = p - y : fe_sub(p, y, 0) ? use hand sub: y = p - y
    ; p - y mod p:
    mov   rax, [P_LIMBS+0]
    sub rax, [rbp-0x1b8]
    mov [rbp-0x1b8], rax
    mov   rax, [P_LIMBS+8]
    sbb rax, [rbp-0x1b0]
    mov [rbp-0x1b0], rax
    mov   rax, [P_LIMBS+16]
    sbb rax, [rbp-0x1a8]
    mov [rbp-0x1a8], rax
    mov   rax, [P_LIMBS+24]
    sbb rax, [rbp-0x1a0]
    mov [rbp-0x1a0], rax
.store_y:
    ; ---- qx = x (x-limbs at -0x118), qy = y ----
    mov   rax,[rbp-0x118]
    mov [r14+  0], rax
    mov   rax,[rbp-0x110]
    mov [r14+  8], rax
    mov   rax,[rbp-0x108]
    mov [r14+ 16], rax
    mov   rax,[rbp-0x100]
    mov [r14+ 24], rax
    mov   rax,[rbp-0x1b8]
    mov [r15+  0], rax
    mov   rax,[rbp-0x1b0]
    mov [r15+  8], rax
    mov   rax,[rbp-0x1a8]
    mov [r15+ 16], rax
    mov   rax,[rbp-0x1a0]
    mov [r15+ 24], rax
    mov   eax, 1
    jmp   .done

.chk_uncomp:
    movzx eax, byte [r12]
    cmp   al, 0x04
    jne   .bad_ret
    ; x = bytes 1..32, y = bytes 33..64
    ; copy x to [rbp-0x50], y to [rbp-0x90]
    mov   rcx, 32
    lea   rdi, [rbp-0x50]
    lea   rsi, [r12+1]
.cx:
    mov   al,[rsi]
    mov [rdi],al
    inc rdi
    inc rsi
    dec rcx
    jnz .cx
    mov   rcx, 32
    lea   rdi, [rbp-0x90]
    lea   rsi, [r12+33]
.cy:
    mov   al,[rsi]
    mov [rdi],al
    inc rdi
    inc rsi
    dec rcx
    jnz .cy
    ; ---- convert x (32 BE bytes @-0x50) -> limbs @-0x118 ; y (BE @-0x90) -> limbs @-0x168
    xor   rcx, rcx
.uconv:
    cmp   rcx, 4
    jae   .uconv_done
    mov   rdx, rcx
    neg   rdx
    add   rdx, 3
    mov   rax, [rbp-0x50 + rdx*8]
    bswap rax
    mov   [rbp-0x118 + rcx*8], rax
    mov   rax, [rbp-0x90 + rdx*8]
    bswap rax
    mov   [rbp-0x168 + rcx*8], rax
    inc   rcx
    jmp   .uconv
.uconv_done:
    ; check y^2 == x^3 + 7
    ; x2 = x^2 [rbp-0xc8]; x3 [rbp-0x90]; t [rbp-0x1b8]; y2 [rbp-0xc8]
    lea   rdi, [rbp-0xc8]
    lea rsi, [rbp-0x118]
    call fe_sqr
    lea   rdi, [rbp-0x90]
    lea rsi, [rbp-0xc8]
    lea rdx, [rbp-0x118]
    call fe_mul
    lea   rdi, [rbp-0x1b8]
    lea rsi, [rbp-0x90]
    lea rdx, [CURVE7]
    call fe_add
    lea   rdi, [rbp-0xc8]
    lea rsi, [rbp-0x168]
    call fe_sqr
    lea   rsi, [rbp-0x1b8]
    mov   rax,[rbp-0xc8]
    cmp rax,[rsi+  0]
    jne .bad_ret
    mov   rax,[rbp-0xc0]
    cmp rax,[rsi+  8]
    jne .bad_ret
    mov   rax,[rbp-0xb8]
    cmp rax,[rsi+ 16]
    jne .bad_ret
    mov   rax,[rbp-0xb0]
    cmp rax,[rsi+ 24]
    jne .bad_ret
    ; ---- store qx, qy (x-limbs @-0x118, y-limbs @-0x168)
    mov   rax,[rbp-0x118]
    mov [r14+  0], rax
    mov   rax,[rbp-0x110]
    mov [r14+  8], rax
    mov   rax,[rbp-0x108]
    mov [r14+ 16], rax
    mov   rax,[rbp-0x100]
    mov [r14+ 24], rax
    mov   rax,[rbp-0x168]
    mov [r15+  0], rax
    mov   rax,[rbp-0x160]
    mov [r15+  8], rax
    mov   rax,[rbp-0x158]
    mov [r15+ 16], rax
    mov   rax,[rbp-0x150]
    mov [r15+ 24], rax
    mov   eax, 1
    jmp   .done

.bad_ret:
    xor   eax, eax
.done:
    add   rsp, 0x1d8
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    pop   rbp
    ret

section .data
align 16
; exported limb copy of p for the parity-flip subtraction
P_LIMBS:
    dq 0xFFFFFFFEFFFFFC2F
    dq 0xFFFFFFFFFFFFFFFF
    dq 0xFFFFFFFFFFFFFFFF
    dq 0xFFFFFFFFFFFFFFFF

; SECURITY (audit 2026-08-29 finding 9): without this note the linker
; conservatively marks the whole program's stack EXECUTABLE (PT_GNU_STACK
; RWE). Nothing here needs a runnable stack; a single object missing the
; note is enough to turn it on for the entire binary, which is why every
; .asm file carries it.
section .note.GNU-stack noalloc noexec nowrite progbits
