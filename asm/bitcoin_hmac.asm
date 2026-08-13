; ============================================================================
; bitcoin_hmac.asm -- HMAC-SHA512 in x86-64 assembly.
;   The keyed message-authentication hash at the heart of the wallet stack:
;     BIP32  master/child key derivation  (HMAC-SHA512(key, data))
;     BIP39  mnemonic-to-seed PBKDF2     (repeated HMAC-SHA512)
;   Built directly on the asm SHA-512 (sha512.asm), which passes the NIST
;   vectors, so this inherits a verified compression function.
;
;   HMAC(K,m):
;     if |K| > 128: K = SHA512(K) (64 bytes)
;     K' = K right-padded with 0x00 to 128 bytes
;     inner = SHA512( (K' XOR ipad) || m )     ipad = 0x36 x 128
;     out   = SHA512( (K' XOR opad) || inner )  opad = 0x5c x 128
;
; PUBLIC ABI (System V AMD64)
;   void hmac_sha512(u8 out[64], const u8* key, i64 keylen,
;                    const u8* msg, i64 msglen)
; ============================================================================

BITS 64
DEFAULT REL

section .bss
align 16
kpad:  resb 128        ; XOR-adjusted key block (ipad/opad)
tmp:   resb (128+8+1024) ; concatenation scratch (key block + msg / inner)

section .text

extern sha512_full

; ============================================================================
; hmac_sha512(out, key, keylen, msg, msglen)
; ============================================================================
global hmac_sha512
hmac_sha512:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x80           ; local slots (below save area)
    mov  [rbp-0x48], rdi     ; out
    mov  [rbp-0x50], rsi     ; key
    mov  [rbp-0x58], rdx     ; keylen
    mov  [rbp-0x60], rcx     ; msg
    mov  [rbp-0x68], r8      ; msglen (5th arg in r8)

    ; ---- effective key: if keylen > 128, replace with SHA512(key) ----
    cmp  rdx, 128
    jle  .keyok
    ; sha512_full(tmp, key, keylen) -> 64-byte key digest in tmp
    push rdi
    push rsi
    push rcx
    push r8
    lea  rdi, [tmp]
    mov  rsi, [rbp-0x50]
    mov  rdx, [rbp-0x58]
    call sha512_full
    pop  r8
    pop  rcx
    pop  rsi
    pop  rdi
    mov  qword [rbp-0x58], 64   ; effective keylen = 64
    lea  rax, [tmp]
    mov  [rbp-0x50], rax        ; effective key = tmp (raw digest)
.keyok:

    ; ---- Build K' (key right-padded to 128) into a local key buffer ----
    ; use kpad as the key buffer first
    lea  r12, [kpad]            ; keybuf
    lea  r13, [tmp]             ; concat buffer
    mov  rcx, [rbp-0x58]        ; effective keylen
    mov  rsi, [rbp-0x50]
    xor  rdi, rdi
.kcp:
    cmp  rdi, rcx
    jae  .kcp_done
    mov  al, byte [rsi+rdi]
    mov  byte [r12+rdi], al
    inc  rdi
    jmp  .kcp
.kcp_done:
    ; zero-pad to 128
.kz:
    cmp  rdi, 128
    jae  .kz_done
    mov  byte [r12+rdi], 0
    inc  rdi
    jmp  .kz
.kz_done:

    ; ---- INNER: tmp = SHA512( (K' XOR ipad) || msg ) ----
    ; build (K' XOR ipad) into tmp[0..127]
    xor  rcx, rcx
.xip:
    cmp  rcx, 128
    jae  .xip_done
    mov  al, byte [r12+rcx]
    xor  al, 0x36
    mov  byte [r13+rcx], al
    inc  rcx
    jmp  .xip
.xip_done:
    ; copy msg into tmp[128 .. 128+msglen)
    lea  rdi, [r13+128]
    mov  rsi, [rbp-0x60]
    mov  rcx, [rbp-0x68]
    xor  r8, r8
.mcp:
    cmp  r8, rcx
    jae  .mcp_done
    mov  al, byte [rsi+r8]
    mov  byte [rdi+r8], al
    inc  r8
    jmp  .mcp
.mcp_done:
    ; inner_len = 128 + msglen
    mov  rax, [rbp-0x68]
    add  rax, 128
    ; sha512_full(tmp(inner digest out), tmp(concat), inner_len)
    push rdi
    push rsi
    push rcx
    push r8
    lea  rdi, [tmp]
    lea  rsi, [tmp]
    mov  rdx, rax
    call sha512_full
    pop  r8
    pop  rcx
    pop  rsi
    pop  rdi
    ; inner digest is now at tmp[0..63]. Move it to tmp[192..255] BEFORE the
    ; opad block overwrites tmp[0..127].
    lea  r13, [tmp]
    xor  rcx, rcx
.stash:
    cmp  rcx, 64
    jae  .stash_done
    mov  al, byte [r13+rcx]
    mov  byte [r13+192+rcx], al
    inc  rcx
    jmp  .stash
.stash_done:
    ; ---- OUTER: build (K' XOR opad) into tmp[0..127] ----
    xor  rcx, rcx
.xop:
    cmp  rcx, 128
    jae  .xop_done
    mov  al, byte [r12+rcx]
    xor  al, 0x5c
    mov  byte [r13+rcx], al
    inc  rcx
    jmp  .xop
.xop_done:
    ; copy stashed inner digest (tmp[192..255]) to tmp[128..191]
    lea  rdi, [r13+128]
    lea  rsi, [r13+192]
    xor  rcx, rcx
.icp:
    cmp  rcx, 64
    jae  .icp_done
    mov  al, byte [rsi+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .icp
.icp_done:
    ; sha512_full(out, tmp, 192)
    push rdi
    push rsi
    push rcx
    mov  rdi, [rbp-0x48]
    lea  rsi, [tmp]
    mov  rdx, 192
    call sha512_full
    pop  rcx
    pop  rsi
    pop  rdi

    add  rsp, 0x80
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
