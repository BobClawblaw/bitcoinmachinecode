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
extern scalar_to_pubkey
extern scalar_small_nonzero

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

; ============================================================================
; bip32_ckd_priv(k[32], c[32], k_par[32], c_par[32], index)
;   Child private key derivation (hardened for index >= 2^31, else normal).
;   Outputs child key k (32 BE) and child chain code c (32 BE).
;   Returns 1 on success; 0 if the derived key is invalid (>= n or zero).
;   Uses: hmac_sha512 (for I), scalar_to_pubkey (normal-case parent pubkey),
;         scalar_small_nonzero (tweak/key validation).
;
; LOCAL LAYOUT (5 saves at [rbp-8..rbp-0x28]; locals below, disjoint):
;   inp     [rbp-0x58]  (37B HMAC input)
;   I       [rbp-0x98]  (64B digest)
;   kpar    [rbp-0xb8]  (32B)
;   cpar    [rbp-0xd8]  (32B)
;   kout    [rbp-0xf8]  (32B)
;   nB      (rodata)
;   sub rsp, 0x100
; ============================================================================
global bip32_ckd_priv
bip32_ckd_priv:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x150          ; covers locals down to rbp-0x138
    mov  rbx, rdi            ; k out (kept in callee-saved rbx across calls)
    mov  r15, rsi            ; c out (kept in callee-saved r15 across calls)
    mov  r12, rdx            ; k_par
    mov  r13, rcx            ; c_par
    mov  r14d, r8d           ; index (hardened bit = top bit)

    ; build HMAC input at [rbp-0x58] (referenced directly; r15 holds c_out)
    test r14d, r14d
    js   .hardened               ; top bit set => index >= 2^31
    ; ---- NORMAL: input = ser256(K_par) || ser32(i) ----
    ; K_par = compressed pubkey of k_par
    sub  rsp, 8
    lea  rdi, [rbp-0x120]       ; 33B pub temp
    mov  rsi, r12
    call scalar_to_pubkey
    add  rsp, 8
    ; copy 33 bytes pub -> inp[0..32]
    lea  rsi, [rbp-0x120]
    lea  rdi, [rbp-0x58]
    xor  rcx, rcx
.ncp:
    cmp  rcx, 33
    jae  .ncp_done
    mov  al, byte [rsi+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .ncp
.ncp_done:
    jmp  .inp_ready
.hardened:
    ; ---- HARDENED: input = 0x00 || ser256(k_par) || ser32(i) ----
    mov  byte [rbp-0x58], 0     ; padding byte = input[0]
    mov  rsi, r12
    lea  rdi, [rbp-0x57]        ; input[1] = ser256(k_par)
    xor  rcx, rcx
.h1:
    cmp  rcx, 32
    jae  .h1_done
    mov  al, byte [rsi+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .h1
.h1_done:
    jmp  .inp_ready

.inp_ready:
    ; append ser32(i) (big-endian 4 bytes) at input[33..36]
    mov  eax, r14d
    ; input[36] = LSB ... input[33] = MSB
    mov  byte [rbp-0x58+36], al
    shr  eax, 8
    mov  byte [rbp-0x58+35], al
    shr  eax, 8
    mov  byte [rbp-0x58+34], al
    shr  eax, 8
    mov  byte [rbp-0x58+33], al    ; MSB

    ; ---- hmac_sha512(I, c_par, 32, inp, 37) ----
    lea  rdi, [rbp-0x98]
    mov  rsi, r13
    mov  rdx, 32
    lea  rcx, [rbp-0x58]
    mov  r8, 37
    call hmac_sha512

    ; ---- validate IL (first 32 bytes of I) : 0 < IL < n ----
    lea  rdi, [rbp-0x98]
    call scalar_small_nonzero
    test eax, eax
    jz   .invalid

    ; ---- copy parent k_par and c_par ----
    mov  rsi, r12
    lea  rdi, [rbp-0xb8]
    xor  rcx, rcx
.kpcp:
    cmp  rcx, 32
    jae  .kpcp_done
    mov  al, byte [rsi+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .kpcp
.kpcp_done:
    ; c_i = IR (I[32..63]) -> c_out (r15)
    lea  rsi, [rbp-0x98+32]
    mov  rdi, r15
    xor  rcx, rcx
.icp:
    cmp  rcx, 32
    jae  .icp_done
    mov  al, byte [rsi+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .icp
.icp_done:
    ; ---- k_i = (IL + k_par) mod n  (both < n; sum may exceed 2^256) ----
    ; 32-byte sum at [rbp-0x138..-0x119]; carry flag byte at [rbp-0x118]
    ; (SEPARATE slot -- [rbp-0x119] is the sum's LSB and must not be clobbered).
    lea  rdi, [rbp-0x138]
    mov  byte [rbp-0x118], 0      ; clear carry byte (separate from sum)
    clc
    mov  rcx, 32
.add:
    mov  r8, rcx
    dec  r8
    mov  al, byte [rbp-0x98+r8]       ; IL byte (r8=31 is LSB)
    mov  dl, byte [rbp-0xb8+r8]       ; kpar byte
    adc  al, dl
    mov  byte [rdi+r8], al
    loop .add
    ; capture carry (true if IL+par >= 2^256)
    setc  byte [rbp-0x118]

    ; ---- if sum >= n, subtract n. Compare the (up to 33-bit) sum against n ----
    lea  rsi, [NBYTES]               ; n as 32 BE bytes
    ; if carry byte set, sum >= 2^256 > n -> must subtract
    cmp  byte [rbp-0x118], 0
    jne  .subn                       ; carries -> definitely >= n
    ; no carry: compare 32-byte sum vs n (BE)
    xor  rdx, rdx
.cmpn:
    cmp  rdx, 32
    jae  .subn
    mov  al, byte [rdi+rdx]
    mov  r10b, byte [rsi+rdx]
    cmp  al, r10b
    jb   .store                       ; sum < n -> keep
    ja   .subn                        ; sum > n
    inc  rdx
    jmp  .cmpn
    ; (jae .subn also reached means sum == n -> subtract -> 0, then invalid)

.subn:
    ; sum >= n (or 257-bit carry): the low 32 bytes of (sum - n) are correct
    ; in both cases: with C=1, sum-n = (2^256+w)-n, whose low 32 bytes are
    ; (w-n) mod 2^256 (the 2^256 term wraps away; true result < n < 2^256).
    ; Loop uses LOOP+DEC-r8 (both preserve CF) so sbb borrows chain correctly.
    clc
    mov  rcx, 32
.sub:
    mov  r8, rcx
    dec  r8
    mov  al, byte [rdi+r8]
    mov  dl, byte [rsi+r8]
    sbb  al, dl
    mov  byte [rdi+r8], al
    loop .sub
.store:
    ; copy [rbp-0x138..-0x119] (32B) to k_out (rbx)
    mov  rdi, rbx
    lea  rsi, [rbp-0x138]
    xor  rcx, rcx
.ocp:
    cmp  rcx, 32
    jae  .ocp_done
    mov  al, byte [rsi+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .ocp
.ocp_done:
    ; validate child key: 0 < k_i < n
    mov  rdi, rbx
    call scalar_small_nonzero
    test eax, eax
    jz   .invalid

    mov  eax, 1
    jmp  .done
.invalid:
    xor  eax, eax
.done:
    add  rsp, 0x150
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .rodata
align 8
NBYTES:
    db 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    db 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE
    db 0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B
    db 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
section .note.GNU-stack noalloc noexec nowrite progbits
