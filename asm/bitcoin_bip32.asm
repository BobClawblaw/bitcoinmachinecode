; ============================================================================
; bitcoin_bip32.asm -- BIP32 hierarchical-deterministic key management, x86-64.
;   Wallet-derivation pieces built on the verified secp256k1/HMAC/SHA-512 core:
;
;   bip32_master          : HMAC-SHA512("Bitcoin seed") -> master (k, c)
;   bip32_ckd_priv        : child private key (hardened + normal)
;   bip32_derive_path     : derive a FULL path (m/44'/0'/...) from a seed
;   bip32_fingerprint     : HASH160(pub)[0..4] (BIP32 parent fingerprint)
;   bip32_extkey_serialize: build the 78-byte extended-key (xprv/xpub) payload
;
;   master     = HMAC-SHA512(key = "Bitcoin seed" (12 bytes), data = seed)
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
extern hash160

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

; ============================================================================
; bip32_derive_path(k[32], c[32], seed, seedlen, indexes[4*n], n)
;   Derive a FULL BIP32 path from a seed, on top of the verified
;   bip32_master + bip32_ckd_priv primitives:
;       node = bip32_master(k,c,seed,seedlen)
;       for i in 0..n-1: node = bip32_ckd_priv(k,c, k,c, indexes[i])
;   `indexes` is an array of n u32 child indexes (native little-endian, as
;   declared by a C unsigned[] caller; hardened indexes are already OR'd with
;   0x80000000 -- i.e. the caller resolves the path "m/44'/0'/0'/0/0" into the
;   u32 array {0x8000002c, 0x80000000, ...}). n may be 0 (master only). In-place
;   (k,c are both input and output) is safe because bip32_ckd_priv snapshots
;   k_par/c_par to stack locals before writing its outputs. Returns 1 on
;   success, 0 on an invalid derived key.
;
; PUBLIC ABI (System V AMD64)
;   int bip32_derive_path(u8 k[32], u8 c[32], const u8* seed, i64 seedlen,
;                         const u32* indexes, i64 n)
; ============================================================================
global bip32_derive_path
bip32_derive_path:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x50
    mov  rbx, rdi            ; k
    mov  r12, rsi            ; c
    mov  r13, rdx            ; seed
    mov  r14, rcx            ; seedlen
    mov  [rbp-0x30], r8      ; indexes
    mov  [rbp-0x38], r9      ; n

    ; ---- master ----
    mov  rdi, rbx            ; k
    mov  rsi, r12            ; c
    mov  rdx, r13            ; seed
    mov  rcx, r14            ; seedlen
    call bip32_master
    test eax, eax
    jz   .fail

    ; ---- walk the path ----
    xor  r15d, r15d          ; cur = 0
.loop:
    mov  rax, [rbp-0x38]     ; n
    cmp  r15, rax
    jae  .ok
    ; load index at indexes[cur]. The array is DECLARED in C as unsigned[]
    ; (native little-endian dwords), so a plain mov gives the value directly.
    mov  rax, [rbp-0x30]
    mov  ecx, r15d
    shl  ecx, 2
    mov  r8d, dword [rax+rcx]
    ; in-place child derivation: (k,c) = ckd_priv(k,c,k,c,index)
    mov  rdi, rbx            ; k out
    mov  rsi, r12            ; c out
    mov  rdx, rbx            ; k_par
    mov  rcx, r12            ; c_par
    call bip32_ckd_priv      ; r8d = index (read at callee entry)
    test eax, eax
    jz   .fail
    inc  r15d
    jmp  .loop
.ok:
    mov  eax, 1
    jmp  .done
.fail:
    xor  eax, eax
.done:
    add  rsp, 0x50
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; bip32_fingerprint(fp[4], pub[33])
;   BIP32 parent fingerprint = the first 4 bytes of HASH160(compressed pubkey).
;   Used to tie a derived node back to its parent in extended keys / HD paths.
;
; PUBLIC ABI
;   void bip32_fingerprint(u8 fp[4], const u8 pub[33])
; ============================================================================
global bip32_fingerprint
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP: the pushes precede `push rbp`, so
;   rbx/r12 are saved at [rbp+0x08]/[rbp+0x10] and the 20-byte HASH160 output
;   at [rbp-0x20 .. rbp-0x0d] is inside this function's own 0x30 reservation.
;   Previously the pushes followed `mov rbp,rsp`, putting saved r12 at rbp-0x18
;   -- only 16 bytes above the buffer, which hash160 fills with 20. The top
;   4 bytes of the digest landed on saved r12's low half, so the CALLER got a
;   corrupted r12. Confirmed with tests/bench_abi_guard.S: pre-fix,
;   bip32_fingerprint returns CLOBBERS r12.
;   ALIGNMENT IS UNCHANGED: same three pushes, same 0x30 reservation, only
;   reordered; the nested hash160 call still sees RSP == 0 mod 16.
bip32_fingerprint:
    push rbx
    push r12
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x30           ; h160 at [rbp-0x20]
    mov  rbx, rdi            ; fp
    mov  r12, rsi            ; pub
    ; hash160(h160, pub, 33)
    lea  rdi, [rbp-0x20]
    mov  rsi, r12
    mov  rdx, 33
    call hash160
    mov  eax, [rbp-0x20]
    mov  [rbx], eax
    add  rsp, 0x30
    pop  rbp
    pop  r12
    pop  rbx
    ret

; ============================================================================
; bip32_extkey_serialize(ser[78], is_priv, depth, parent_fp[4], child, c[32],
;                        key[], keylen)
;   Build the 78-byte BIP32 extended-key payload (the thing that gets
;   base58check-encoded into xprv / xpub):
;       ser[0..3]   = version   0x0488ADE4 (xprv) / 0x0488B21E (xpub)
;       ser[4]      = depth
;       ser[5..8]   = parent fingerprint (4 bytes, as given)
;       ser[9..12]  = child number (u32, big-endian)
;       ser[13..44] = chain code (32 bytes)
;       ser[45..77] = key: 0x00 || key32 (is_priv, keylen=32)
;                      or         pub33  (is_pub,  keylen=33)
;   Returns 78. key/keylen are the 7th/8th args (on the stack).
;
; PUBLIC ABI
;   int bip32_extkey_serialize(u8 ser[78], int is_priv, u8 depth,
;                              const u8 parent_fp[4], u32 child,
;                              const u8 c[32], const u8* key, i64 keylen)
; ============================================================================
global bip32_extkey_serialize
bip32_extkey_serialize:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x40
    mov  rbx, rdi            ; ser
    mov  r12d, esi           ; is_priv
    mov  r13b, dl            ; depth
    mov  r14, rcx            ; parent_fp
    mov  r15d, r8d           ; child
    mov  [rbp-0x30], r9      ; c

    ; ---- version (4 big-endian bytes: 0x0488ADE4 xprv / 0x0488B21E xpub) ----
    test r12d, r12d
    jz   .v_pub
    mov  byte [rbx+0], 0x04
    mov  byte [rbx+1], 0x88
    mov  byte [rbx+2], 0xAD
    mov  byte [rbx+3], 0xE4
    jmp  .v_done
.v_pub:
    mov  byte [rbx+0], 0x04
    mov  byte [rbx+1], 0x88
    mov  byte [rbx+2], 0xB2
    mov  byte [rbx+3], 0x1E
.v_done:
    mov  byte [rbx+4], r13b     ; depth
    mov  eax, [r14]             ; parent fingerprint (4 bytes, verbatim)
    mov  [rbx+5], eax
    ; ---- child number, big-endian ----
    mov  eax, r15d
    mov  byte [rbx+12], al
    shr  eax, 8
    mov  byte [rbx+11], al
    shr  eax, 8
    mov  byte [rbx+10], al
    shr  eax, 8
    mov  byte [rbx+9], al
    ; ---- chain code (32 bytes) ----
    mov  rax, [rbp-0x30]
    lea  rdi, [rbx+13]
    mov  rsi, rax
    mov  ecx, 32
    rep  movsb
    ; ---- key data ----
    mov  rax, [rbp+16]          ; key ptr
    mov  ecx, [rbp+24]          ; keylen
    test r12d, r12d
    jz   .k_pub
    ; priv: ser[45]=0x00, then 32-byte key at 46..77
    mov  byte [rbx+45], 0
    lea  rdi, [rbx+46]
    mov  rsi, rax
    xor  r8d, r8d
.kpriv:
    cmp  r8, rcx
    jae  .done
    mov  al, byte [rsi+r8]
    mov  byte [rdi+r8], al
    inc  r8
    jmp  .kpriv
.k_pub:
    ; pub: 33-byte compressed pubkey at 45..77
    lea  rdi, [rbx+45]
    mov  rsi, rax
    xor  r8d, r8d
.kpub:
    cmp  r8, rcx
    jae  .done
    mov  al, byte [rsi+r8]
    mov  byte [rdi+r8], al
    inc  r8
    jmp  .kpub
.done:
    mov  eax, 78
    add  rsp, 0x40
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
