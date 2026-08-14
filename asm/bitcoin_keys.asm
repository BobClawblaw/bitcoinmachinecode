; ============================================================================
; bitcoin_keys.asm -- secp256k1 key derivation helper (pure x86-64).
;   scalar_to_pubkey: scalar -> compressed secp256k1 public key (0x02/0x03 || X).
;   scalar_small_nonzero: BIP32 range check (0 < k < n).
;
; LOCAL LAYOUT (5 callee regs at [rbp-8..rbp-0x28]; locals BELOW, each disjoint):
;   prefix [rbp-0x30]
;   pub    [rbp-0x38]
;   limbs  [rbp-0x58]  (32B)
;   point  [rbp-0xc8]  (96B Jacobian XYZ, exclusive)
;   z2     [rbp-0xe8]
;   z3     [rbp-0x108]
;   inv2   [rbp-0x128]
;   inv3   [rbp-0x148]
;   ax     [rbp-0x168]
;   ay     [rbp-0x188]
;   xle    [rbp-0x1a8] (32B)
;   sub rsp, 0x1a8 -> rsp = rbp-0x1d0 (covers lowest local -0x1a8)
; ============================================================================

BITS 64
DEFAULT REL

section .rodata
align 16
G_AFF:
    dq 0x59F2815B16F81798,0x029BFCDB2DCE28D9,0x55A06295CE870B07,0x79BE667EF9DCBBAC
    dq 0x9C47D08FFB10D4B8,0xFD17B448A6855419,0x5DA4FBFC0E1108A8,0x483ADA7726A3C465
align 16
N_BE:
    db 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    db 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE
    db 0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B
    db 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41

section .text
extern fe_mul
extern fe_sqr
extern fe_inv
extern point_scalar_mul

; ============================================================================
; int scalar_small_nonzero(const u8 k[32])
; ============================================================================
global scalar_small_nonzero
scalar_small_nonzero:
    xor eax, eax
    xor rcx, rcx
.z:
    cmp rcx, 32
    jae .z_done
    or  al, byte [rdi+rcx]
    inc rcx
    jmp .z
.z_done:
    test rax, rax
    jz  .bad
    lea rdx, [N_BE]
    xor rcx, rcx
.cmp:
    cmp rcx, 32
    jae .ok
    mov al, byte [rdi+rcx]
    mov r8b, byte [rdx+rcx]
    cmp al, r8b
    jb  .ok
    ja  .bad
    inc rcx
    jmp .cmp
.ok:
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret

; ============================================================================
; void scalar_to_pubkey(u8 pub[33], const u8 k[32])
;   rdi=pub, rsi=k (32 BE bytes)
; ============================================================================
global scalar_to_pubkey
scalar_to_pubkey:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x1b0
    mov  [rbp-0x38], rdi       ; pub
    mov  r12, [rbp-0x38]       ; pub (kept in r12 too)
    mov  r13, rsi              ; k

    ; ---- convert k (32 BE bytes) to 4 LE limbs at [rbp-0x58] ----
    ; limb j (LE, j=0 low) = bytes [k + (3-j)*8 .. +7] bswapped
    lea  r14, [rbp-0x58]
    xor  rcx, rcx
.limbs:
    cmp  rcx, 4
    jae  .limbs_done
    mov  rdx, rcx
    neg  rdx
    add  rdx, 3                ; (3-rcx)
    mov  rax, [r13 + rdx*8]
    bswap rax
    mov  [r14 + rcx*8], rax
    inc  rcx
    jmp  .limbs
.limbs_done:

    ; ---- point = k*G (Jacobian) into [rbp-0xc8] ----
    lea  rdi, [rbp-0xc8]
    lea  rsi, [G_AFF]
    lea  rdx, [rbp-0x58]
    call point_scalar_mul

    ; ---- affinize ----
    ; z2 = Z^2  (Z is element at point+2 => [rbp-0xc8+64])
    lea  rdi, [rbp-0xe8]
    lea  rsi, [rbp-0x88]
    call fe_sqr
    ; z3 = Z * z2
    lea  rdi, [rbp-0x108]
    lea  rsi, [rbp-0x88]
    lea  rdx, [rbp-0xe8]
    call fe_mul
    ; inv2 = 1/z2
    lea  rdi, [rbp-0x128]
    lea  rsi, [rbp-0xe8]
    call fe_inv
    ; inv3 = 1/z3
    lea  rdi, [rbp-0x148]
    lea  rsi, [rbp-0x108]
    call fe_inv
    ; ax = X * inv2  (X at point+0 => [rbp-0xc8])
    lea  rdi, [rbp-0x168]
    lea  rsi, [rbp-0xc8]
    lea  rdx, [rbp-0x128]
    call fe_mul
    ; ay = Y * inv3  (Y at point+32 => [rbp-0xa8])
    lea  rdi, [rbp-0x188]
    lea  rsi, [rbp-0xa8]
    lea  rdx, [rbp-0x148]
    call fe_mul

    ; ---- prefix: 0x02 if ay even else 0x03 ----
    mov  rax, [rbp-0x188]
    and  rax, 1
    jnz  .odd
    mov  byte [rbp-0x30], 0x02
    jmp  .prefix_done
.odd:
    mov  byte [rbp-0x30], 0x03
.prefix_done:

    ; ---- serialize x (ax at [rbp-0x168], 4 LE limbs) to 32 LE bytes at [rbp-0x1a8] ----
    lea  r13, [rbp-0x1a8]
    xor  rbx, rbx
.bl:
    cmp  rbx, 32
    jae  .bl_done
    mov  rdx, rbx
    shr  rdx, 3                        ; limb index 0..3
    mov  rax, [rbp-0x168 + rdx*8]      ; limb value
    mov  rcx, rbx
    and  rcx, 7                        ; byte within limb
    mov  r9, rax
    ; shift = 8*(rcx&7) -- rcx is the shift count for shr using cl
    shl  rcx, 3
    shr  r9, cl
    and  r9, 0xff
    mov  byte [r13 + rbx], r9b
    inc  rbx
    jmp  .bl
.bl_done:
    ; ---- reverse 32 bytes -> big-endian pub[1..32], then pub[0]=prefix ----
    mov  rdi, r12                      ; pub
    xor  rbx, rbx
.rv:
    cmp  rbx, 32
    jae  .rv_done
    mov  al, byte [r13 + rbx]
    mov  r8, 31
    sub  r8, rbx
    mov  byte [rdi + 1 + r8], al
    inc  rbx
    jmp  .rv
.rv_done:
    mov  al, byte [rbp-0x30]
    mov  byte [rdi], al

    add  rsp, 0x1b0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
