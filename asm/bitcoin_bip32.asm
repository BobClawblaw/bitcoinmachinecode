; ============================================================================
; bitcoin_bip32.asm -- BIP32 hierarchical-deterministic key management, x86-64.
;   First wallet-derivation piece: the BIP32 MASTER key.
;
;   master = HMAC-SHA512(key = "Bitcoin seed" (12 bytes), data = seed)
;     -> first 32 bytes  = master private key k (big-endian scalar)
;     -> last  32 bytes  = master chain code c
;
;   LOCAL LAYOUT: 5 callee-regs saved at [rbp-8..rbp-0x28]; locals BELOW that.
;     k      [rbp-0x30]
;     c      [rbp-0x38]
;     digest [rbp-0x80]  (64 bytes, well below the save area, no overlap)
;
; PUBLIC ABI (System V AMD64)
;   int  bip32_master(u8 k[32], u8 c[32], const u8* seed, i64 seedlen)
;        -> 1 on success, 0 if the derived key is zero (invalid, per BIP32).
; ============================================================================

BITS 64
DEFAULT REL

section .rodata
align 8
bip32_seed_key: db "Bitcoin seed"

section .text
extern hmac_sha512

; ============================================================================
; bip32_master(k[32], c[32], seed, seedlen)
;   rdi=k, rsi=c, rdx=seed, rcx=seedlen
; ============================================================================
global bip32_master
bip32_master:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x80
    mov  [rbp-0x30], rdi       ; k
    mov  [rbp-0x38], rsi       ; c
    mov  r12, rdx              ; seed
    mov  r13, rcx              ; seedlen

    ; hmac_sha512(digest@rbp-0x80, "Bitcoin seed", 12, seed, seedlen)
    lea  rdi, [rbp-0x80]       ; digest (64B)
    lea  rsi, [bip32_seed_key]
    mov  rdx, 12
    mov  rcx, r12              ; seed
    mov  r8, r13               ; seedlen
    call hmac_sha512

    ; k = digest[0..31]
    mov  rdi, [rbp-0x30]
    lea  rsi, [rbp-0x80]
    xor  rcx, rcx
.kcp:
    cmp  rcx, 32
    jae  .kcp_done
    mov  al, byte [rsi+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .kcp
.kcp_done:
    ; c = digest[32..63]
    mov  rdi, [rbp-0x38]
    lea  rsi, [rbp-0x80+32]
    xor  rcx, rcx
.ccp:
    cmp  rcx, 32
    jae  .ccp_done
    mov  al, byte [rsi+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .ccp
.ccp_done:
    ; return 1 if k != 0, else 0
    mov  rsi, [rbp-0x30]
    xor  rax, rax
    xor  rcx, rcx
.zk:
    cmp  rcx, 32
    jae  .zk_done
    or   al, byte [rsi+rcx]
    inc  rcx
    jmp  .zk
.zk_done:
    test rax, rax
    setne al
    movzx rax, al

    add  rsp, 0x80
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
