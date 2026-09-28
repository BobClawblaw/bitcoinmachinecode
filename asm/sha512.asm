; ============================================================================
; SHA-512  --  100% AI-generated x86-64 assembly (NASM, ELF64 ABI)
;
; PURPOSE
;   SHA-512 (FIPS 180-4) is a wallet-building block: BIP32 and BIP39 both use
;   HMAC-SHA512. Same compression-schedule shape as SHA-256 but 64-bit words,
;   128-byte blocks, 80 rounds, 128-bit length.
;
; PUBLIC ABI (System V AMD64)
;   void sha512_init (u64 state[8])
;   void sha512_block(u64 state[8], const u8 block[128])
;   void sha512_full (u8 out[64], const void *msg, i64 len)
;
; Register plan in sha512_block:
;   r12=state  r13=block  rbx=W base          (callee-saved)
;   r14=a      r15=b                          (callee-saved working)
;   rax=c  rcx=d  rdx=e  rsi=f  rdi=g  r8=h
;   temps r9, r10 ; r11 = round/schedule index ; T1 spilled to [rbp-8]
; ============================================================================

BITS 64
DEFAULT REL

section .rodata
align 8
K512:
    dq 0x428a2f98d728ae22, 0x7137449123ef65cd
    dq 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
    dq 0x3956c25bf348b538, 0x59f111f1b605d019
    dq 0x923f82a4af194f9b, 0xab1c5ed5da6d8118
    dq 0xd807aa98a3030242, 0x12835b0145706fbe
    dq 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
    dq 0x72be5d74f27b896f, 0x80deb1fe3b1696b1
    dq 0x9bdc06a725c71235, 0xc19bf174cf692694
    dq 0xe49b69c19ef14ad2, 0xefbe4786384f25e3
    dq 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
    dq 0x2de92c6f592b0275, 0x4a7484aa6ea6e483
    dq 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
    dq 0x983e5152ee66dfab, 0xa831c66d2db43210
    dq 0xb00327c898fb213f, 0xbf597fc7beef0ee4
    dq 0xc6e00bf33da88fc2, 0xd5a79147930aa725
    dq 0x06ca6351e003826f, 0x142929670a0e6e70
    dq 0x27b70a8546d22ffc, 0x2e1b21385c26c926
    dq 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
    dq 0x650a73548baf63de, 0x766a0abb3c77b2a8
    dq 0x81c2c92e47edaee6, 0x92722c851482353b
    dq 0xa2bfe8a14cf10364, 0xa81a664bbc423001
    dq 0xc24b8b70d0f89791, 0xc76c51a30654be30
    dq 0xd192e819d6ef5218, 0xd69906245565a910
    dq 0xf40e35855771202a, 0x106aa07032bbd1b8
    dq 0x19a4c116b8d2d0c8, 0x1e376c085141ab53
    dq 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
    dq 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
    dq 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
    dq 0x748f82ee5defb2fc, 0x78a5636f43172f60
    dq 0x84c87814a1f0ab72, 0x8cc702081a6439ec
    dq 0x90befffa23631e28, 0xa4506cebde82bde9
    dq 0xbef9a3f7b2c67915, 0xc67178f2e372532b
    dq 0xca273eceea26619c, 0xd186b8c721c0c207
    dq 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
    dq 0x06f067aa72176fba, 0x0a637dc5a2c898a6
    dq 0x113f9804bef90dae, 0x1b710b35131c471b
    dq 0x28db77f523047d84, 0x32caab7b40c72493
    dq 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
    dq 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
    dq 0x5fcb6fab3ad6faec, 0x6c44198c4a475817

align 8
H512:
    dq 0x6a09e667f3bcc908, 0xbb67ae8584caa73b
    dq 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
    dq 0x510e527fade682d1, 0x9b05688c2b3e6c1f
    dq 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

section .text

; ============================================================================
; sha512_init(state[8])
; ============================================================================
global sha512_init
sha512_init:
    lea  rax, [H512]
    mov  rcx, 8
.l:
    mov  rdx, [rax]
    mov  [rdi], rdx
    add  rax, 8
    add  rdi, 8
    dec  rcx
    jnz  .l
    ret

; ============================================================================
; sha512_block(state[8], block[128])
; ============================================================================
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP.
;   The five pushes come before `push rbp`, so rbx/r12/r13/r14/r15 are saved at
;   [rbp+0x08 .. rbp+0x28] and the three round temporaries at [rbp-8],
;   [rbp-16], [rbp-24] are inside this function's own 0x20 reservation.
;   Before this change the pushes followed `mov rbp,rsp` and the comment here
;   claimed the temporaries were "below save area" -- they were not. Saved rbx
;   sat at rbp-8, r12 at rbp-16 and r13 at rbp-24, i.e. exactly on T1, tmp and
;   Maj, so the epilogue popped SHA-512 round state into the CALLER's rbx, r12
;   and r13. Verified with tests/bench_abi_guard.S: pre-fix, a direct
;   sha512_block call returns CLOBBERS rbx r12 r13.
;   This was invisible to tests/bench_abi_audit because that harness probes
;   sha512_full, whose own frame re-saves the same three registers, so the
;   damage never escaped sha512.asm. sha512_block is `global`, though, so any
;   future caller -- notably any C caller -- would have been hit. Found by
;   scripts/abi_callee_saved_audit.py, the static half of this guard.
;   ALIGNMENT IS UNCHANGED: same six pushes and the same 0x20 reservation,
;   only reordered. Entry 8 -> 5 pushes -> 0 -> push rbp -> 8 -> sub 0x20 -> 8;
;   previously 8 -> push rbp -> 0 -> 5 pushes -> 8 -> sub 0x20 -> 8. This
;   function makes no calls, so nothing downstream sees a difference either.
global sha512_block
sha512_block:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    ; ---- CRY-4 (audit 2026-09-03): the 80-word schedule lives on the STACK.
    ;
    ; It was `Wbuf: resb 80*8` in .bss -- one buffer shared by every caller in
    ; the process. Two threads hashing concurrently overwrote each other's
    ; schedule mid-round and both produced wrong digests, silently. That is
    ; exactly the class of defect behind the schnorr false-reject incident
    ; (secp256k1_schnorr.asm), and it was latent here only because every
    ; SHA-512 user -- BIP32 and BIP39 derivation, wallet_crypter, wallet_store,
    ; the RPC key paths -- happens to run under rpc_server.c's g_exec_lock.
    ; Nothing enforced that, and a future caller from a tx_verify worker or
    ; the ZMQ/i2p threads would have got wrong child keys: getnewaddress
    ; handing out an address nobody can spend.
    ;
    ; 640 bytes is a multiple of 16, so RSP keeps the residue the old
    ; reservation gave it -- entry 8 -> 5 pushes -> 0 -> push rbp -> 8 ->
    ; sub -> 8 -- and this function makes no calls in any case. The scalar
    ; locals stay where they were at [rbp-8], [rbp-16], [rbp-24]; the schedule
    ; sits BELOW them and the two regions do not overlap.
    sub  rsp, 0x2A0                ; 0x20 locals + 0x280 (80*8) schedule
    ; ---- 2026-09-28: the schedule and the 80 rounds are written out, the
    ; eight state words live in r8-r15 and rotate by NAME through the macro
    ; (after eight rounds the assignment is back where it started), T1 and T2
    ; never touch memory, and nothing branches. The 2026-09-27 benchmark had
    ; this file 1.7x behind Core's plain C++ (1.63 vs 0.955 ns/byte); the
    ; per-round chain e -> S1 -> T1 -> e' is ~6.5 cycles and that floor is
    ; where Core sits, so the win is in reaching it, not in the arithmetic.
    ; The frame is unchanged (CRY-4: the schedule stays on the stack, per
    ; call); rsp is the schedule's base (0x280 bytes), the 0x20 above it is
    ; unused.
    mov  rbx, rdi                ; state (rbx is callee-saved and pushed above)

%assign i 0
%rep 16
    mov  rax, [rsi + i*8]
    bswap rax
    mov  [rsp + i*8], rax
%assign i i+1
%endrep

; W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16]
%macro SHA512_W 1
    mov  rax, [rsp + ((%1)-2)*8]
    mov  rcx, rax
    ror  rax, 19
    ror  rcx, 61
    xor  rax, rcx
    mov  rcx, [rsp + ((%1)-2)*8]
    shr  rcx, 6
    xor  rax, rcx                        ; s1
    mov  rcx, [rsp + ((%1)-15)*8]
    mov  rdx, rcx
    ror  rcx, 1
    ror  rdx, 8
    xor  rcx, rdx
    mov  rdx, [rsp + ((%1)-15)*8]
    shr  rdx, 7
    xor  rcx, rdx                        ; s0
    add  rax, rcx
    add  rax, [rsp + ((%1)-7)*8]
    add  rax, [rsp + ((%1)-16)*8]
    mov  [rsp + (%1)*8], rax
%endmacro
%assign i 16
%rep 64
    SHA512_W i
%assign i i+1
%endrep

    mov  r8,  [rbx+0]            ; a
    mov  r9,  [rbx+8]            ; b
    mov  r10, [rbx+16]           ; c
    mov  r11, [rbx+24]           ; d
    mov  r12, [rbx+32]           ; e
    mov  r13, [rbx+40]           ; f
    mov  r14, [rbx+48]           ; g
    mov  r15, [rbx+56]           ; h

; one round: h += S1(e) + Ch(e,f,g) + K[i] + W[i]; d += h; h += S0(a) + Maj(a,b,c)
; (h then holds the new a; the caller rotates the names)
%macro SHA512_ROUND 9
    mov  rax, %5
    ror  rax, 14
    mov  rcx, %5
    ror  rcx, 18
    xor  rax, rcx
    mov  rcx, %5
    ror  rcx, 41
    xor  rax, rcx                        ; S1(e)
    mov  rcx, %6
    xor  rcx, %7
    and  rcx, %5
    xor  rcx, %7                         ; Ch = (e & (f ^ g)) ^ g
    add  %8, [rsp + (%9)*8]
    add  %8, [K512 + (%9)*8]
    add  %8, rax
    add  %8, rcx                         ; T1
    add  %4, %8                          ; d += T1
    mov  rax, %1
    ror  rax, 28
    mov  rcx, %1
    ror  rcx, 34
    xor  rax, rcx
    mov  rcx, %1
    ror  rcx, 39
    xor  rax, rcx                        ; S0(a)
    mov  rcx, %1
    or   rcx, %2
    and  rcx, %3
    mov  rdx, %1
    and  rdx, %2
    or   rcx, rdx                        ; Maj = (a & b) | (c & (a | b))
    add  %8, rax
    add  %8, rcx                         ; T1 + T2 = the new a
%endmacro
%assign i 0
%rep 10
    SHA512_ROUND r8,  r9,  r10, r11, r12, r13, r14, r15, i
    SHA512_ROUND r15, r8,  r9,  r10, r11, r12, r13, r14, i+1
    SHA512_ROUND r14, r15, r8,  r9,  r10, r11, r12, r13, i+2
    SHA512_ROUND r13, r14, r15, r8,  r9,  r10, r11, r12, i+3
    SHA512_ROUND r12, r13, r14, r15, r8,  r9,  r10, r11, i+4
    SHA512_ROUND r11, r12, r13, r14, r15, r8,  r9,  r10, i+5
    SHA512_ROUND r10, r11, r12, r13, r14, r15, r8,  r9,  i+6
    SHA512_ROUND r9,  r10, r11, r12, r13, r14, r15, r8,  i+7
%assign i i+8
%endrep

    add  [rbx+0],  r8
    add  [rbx+8],  r9
    add  [rbx+16], r10
    add  [rbx+24], r11
    add  [rbx+32], r12
    add  [rbx+40], r13
    add  [rbx+48], r14
    add  [rbx+56], r15

    add  rsp, 0x2A0                ; CRY-4: must match the reservation above
    pop  rbp                       ; save area is ABOVE rbp -- rbp pops first
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; sha512_full(out[64], msg, len)
;   Pads (0x80, zeros, 128-bit BE bit-length) and processes all 128-byte blocks
;   including final partial block. Emits digest as 8 BE qwords.
; ============================================================================
global sha512_full
sha512_full:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x240                ; pad[2] @rbp-0x200, state @rbp-0x100, loop slots @-0x228..-0x238
    ; keep out/msg/len in stack slots (don't trust callee-saved regs across calls)
    mov  [rbp-0x210], rdi          ; out
    mov  [rbp-0x218], rsi          ; msg
    mov  [rbp-0x220], rdx          ; len
    lea  r15, [rbp-0x100]          ; state (survives; every callee preserves it)
    mov  rdi, r15
    push r15
    call sha512_init
    pop  r15

    ; full 128-byte blocks: keep loop state in memory slots (no callee can clobber)
    mov  rax, [rbp-0x220]          ; len
    shr  rax, 7
    mov  [rbp-0x228], rax          ; nfull
    mov  rax, [rbp-0x218]          ; msg
    mov  [rbp-0x230], rax          ; running block pointer
    mov  qword [rbp-0x238], 0      ; counter i
.blk:
    mov  rax, [rbp-0x238]
    cmp  rax, [rbp-0x228]          ; i < nfull ?
    jae  .blk_done
    mov  rsi, [rbp-0x230]          ; block ptr
    mov  rdi, r15
    push r15
    call sha512_block
    pop  r15
    add  qword [rbp-0x230], 128
    inc  qword [rbp-0x238]
    jmp  .blk
.blk_done:

    ; pad buffer at rbp-0x200
    lea  rdi, [rbp-0x200]
    ; copy rem bytes
    mov  rax, [rbp-0x220]          ; len
    and  rax, 127                  ; rem
    mov  r8, rax
    mov  r9, [rbp-0x218]           ; msg
    add  r9, [rbp-0x220]           ; msg + len
    sub  r9, r8                    ; start of remaining bytes
    xor  rcx, rcx
.cp:
    cmp  rcx, r8
    jae  .cp_done
    mov  al, byte [r9+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .cp
.cp_done:
    mov  [rbp-0x208], r8        ; save rem across the sha512_block call (r8 is caller-saved)
    mov  byte [rdi+rcx], 0x80      ; 0x80 separator at offset rem
    ; zero-fill block 0 fully (rem+1 .. 127)
    inc  rcx
.z:
    cmp  rcx, 128
    jae  .z_done
    mov  byte [rdi+rcx], 0
    inc  rcx
    jmp  .z
.z_done:

    ; decide which block carries the 16-byte length:
    ;   rem <= 111 -> block 0 (length at its 112..127)
    ;   rem >= 112 -> block 0 has no room; block 1 (all zeros) carries it
    lea  rsi, [rbp-0x200]        ; block 0 (default length carrier)
    cmp  qword [rbp-0x208], 112
    jb   .lenone
    lea  rsi, [rbp-0x200+128]    ; block 1 becomes the length carrier
    ; block 1 must be all-zero except the length: zero it fully
    xor  rcx, rcx
.zb2:
    cmp  rcx, 128
    jae  .zb2_done
    mov  byte [rsi+rcx], 0
    inc  rcx
    jmp  .zb2
.zb2_done:
.lenone:
    mov  [rbp-0x240], rsi        ; length-carrier block pointer (survives block0 call)

    ; write 128-bit BE length = len*8 at [carrier+112..127]
    mov  rax, [rbp-0x220]
    shl  rax, 3
    mov  rcx, 16
.zlen:
    dec  rcx
    mov  byte [rsi+112+rcx], 0
    test rcx, rcx
    jnz  .zlen
    mov  rcx, 8
.lb:
    dec  rcx
    mov  rdx, rax
    and  rdx, 0xff
    mov  byte [rsi+120+rcx], dl
    shr  rax, 8
    test rcx, rcx
    jnz  .lb

    ; process padding block 0 always
    lea  rsi, [rbp-0x200]
    mov  rdi, r15
    push r15
    call sha512_block
    pop  r15

    ; if the length went into block 1, process that too
    cmp  qword [rbp-0x208], 112
    jb   .nopad2
    mov  rsi, [rbp-0x240]
    mov  rdi, r15
    push r15
    call sha512_block
    pop  r15
.nopad2:

    ; emit digest: 8 qwords BE
    mov  rdi, [rbp-0x210]          ; out
    lea  rsi, [rbp-0x100]
    mov  rcx, 8
.em:
    dec  rcx
    mov  rax, [rsi+rcx*8]
    bswap rax
    mov  [rdi+rcx*8], rax
    test rcx, rcx
    jnz  .em

    add  rsp, 0x240
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
