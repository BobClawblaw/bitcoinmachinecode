; ============================================================================
; SHA-1  --  100% AI-generated x86-64 assembly (NASM, ELF64 ABI)
;
; PURPOSE
;   OP_SHA1 (0xa7) is a real, always-defined Bitcoin Script opcode -- rare on
;   chain but real, and this file exists because a full mainnet archive
;   replay (2026-08-20, real block height 251683) hit a real historical
;   transaction spending a "hash-puzzle" style scriptPubKey that uses it
;   (`OP_SIZE OP_DUP OP_1 OP_GREATERTHAN OP_VERIFY OP_NEGATE OP_HASH256
;   OP_HASH160 OP_SHA256 OP_SHA1 OP_RIPEMD160 OP_EQUAL`). SHA-1 is
;   cryptographically broken for collision resistance, but that is
;   irrelevant here: this file only needs to reproduce the exact, fixed
;   FIPS 180-4 algorithm real Bitcoin consensus already depends on, the same
;   way this project implements RIPEMD-160 (also not collision-resistant by
;   modern standards) for the same reason.
;
; ALGORITHM (FIPS 180-4 SHA-1)
;   Like SHA-256, SHA-1 processes the message in 512-bit (64-byte) blocks
;   with the same 0x80 + zero-pad + 64-bit-big-endian-bitlength trailer.
;   Unlike SHA-256 it keeps only 5 working words (a..e, not a..h) and runs
;   80 rounds (not 64), split into four 20-round phases each with its own
;   f-function and round constant:
;     rounds  0-19: f = (b AND c) OR ((NOT b) AND d)      K = 0x5A827999
;     rounds 20-39: f = b XOR c XOR d                     K = 0x6ED9EBA1
;     rounds 40-59: f = (b AND c) OR (b AND d) OR (c AND d) K = 0x8F1BBCDC
;     rounds 60-79: f = b XOR c XOR d                     K = 0xCA62C1D6
;   Per round: temp = ROTL(a,5) + f + e + K + W[i]
;              e=d; d=c; c=ROTL(b,30); b=a; a=temp
;   W[0..15] are the 16 big-endian words of the block; W[16..79] extend via:
;     W[i] = ROTL(W[i-3] XOR W[i-8] XOR W[i-14] XOR W[i-16], 1)
;
; PUBLIC ABI (System V AMD64: first args in rdi, rsi, rdx)
;   void sha1_init (u32 state[5])                          -> rdi = state
;   void sha1_block(u32 state[5], const u8 block[64])      -> rdi, rsi
;   void sha1_full (u8 out[20], const void *msg, i64 len)  -> rdi, rsi, rdx
;
; ENDIANNESS: same convention as sha256.asm -- each 32-bit word is
; big-endian on the wire; BSWAP on the way in, BSWAP on the way out.
;
; Correctness-first, no accelerated path: OP_SHA1 is rare on real chain
; data (unlike SHA-256/RIPEMD-160, which are on the hot P2PKH/P2SH path),
; so a scalar-only implementation is the right tradeoff here, matching this
; project's existing "correctness first" precedent for cold paths (e.g.
; secp256k1_scalar.asm's sc_mul).
; ============================================================================

BITS 64
DEFAULT REL

section .rodata
align 16
INIT_H1:
    ; H0..H4 for a fresh SHA-1 run (FIPS 180-4 initialization vector).
    dd 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

section .text

; ============================================================================
; void sha1_init(u32 state[5])
; ============================================================================
global sha1_init
sha1_init:
    lea rsi, [INIT_H1]
    mov ecx, 5
.loop:
    mov eax, [rsi]
    mov [rdi], eax
    add rdi, 4
    add rsi, 4
    dec ecx
    jnz .loop
    ret

; ============================================================================
; void sha1_block(u32 state[5], const u8 block[64])
;   Runs ONE 64-byte block through the SHA-1 compression function, adding
;   the result into state[].
;
; REGISTER CONTRACT: the five SHA-1 working variables a..e live in
;   r8d=a  r9d=b  r10d=c  r11d=d  r12d=e
; Scratch: eax, edx, ebx. rcx is the round index (also W[]'s word index).
; ============================================================================
; sha1_block(state, block): dispatch once (cached), then the SHA-NI body or
; the scalar one. sha1_force_path(edi): 0 re-probe, 1 SHA-NI, 2 scalar (tests).
section .data
sha1_path: db 0
section .text
global sha1_force_path
sha1_force_path:
    mov  byte [rel sha1_path], dil
    ret
global sha1_block
sha1_block:
    movzx eax, byte [rel sha1_path]
    cmp  eax, 1
    je   sha1_block_shani
    cmp  eax, 2
    je   sha1_block_scalar
    push rdi
    push rsi
    sub  rsp, 8                       ; entry rsp = 8 mod 16; two pushes + 8 -> 0
    call sha1_cpu_has_sha
    add  rsp, 8
    pop  rsi
    pop  rdi
    mov  byte [rel sha1_path], 2
    test eax, eax
    jz   sha1_block_scalar
    mov  byte [rel sha1_path], 1
    jmp  sha1_block_shani

global sha1_block_scalar
sha1_block_scalar:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 320            ; W[0..79] = 80 words x 4 bytes

    ; ---- PHASE 1: W[0..15] from the raw big-endian block bytes ----
    xor ecx, ecx
.fill:
    mov eax, [rsi + rcx*4]
    bswap eax
    mov [rsp + rcx*4], eax
    inc ecx
    cmp ecx, 16
    jb  .fill

    ; ---- PHASE 2: extend to W[16..79] ----
    ;   W[i] = ROTL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1)
    mov ecx, 16
.extend:
    mov eax, [rsp + (rcx-3)*4]
    xor eax, [rsp + (rcx-8)*4]
    xor eax, [rsp + (rcx-14)*4]
    xor eax, [rsp + (rcx-16)*4]
    rol eax, 1
    mov [rsp + rcx*4], eax
    inc ecx
    cmp ecx, 80
    jb  .extend

    ; ---- PHASE 3: load working variables a..e from the hash state ----
    mov r8d,  [rdi + 0]     ; a = H0
    mov r9d,  [rdi + 4]     ; b = H1
    mov r10d, [rdi + 8]     ; c = H2
    mov r11d, [rdi + 12]    ; d = H3
    mov r12d, [rdi + 16]    ; e = H4

    ; ---- PHASE 4: the 80 compression rounds, four 20-round f/K phases ----
    xor ecx, ecx
.round:
    cmp ecx, 20
    jb  .f1
    cmp ecx, 40
    jb  .f2
    cmp ecx, 60
    jb  .f3
    jmp .f4
.f1:
    ; f = (b AND c) OR ((NOT b) AND d)
    mov eax, r9d
    and eax, r10d
    mov edx, r9d
    not edx
    and edx, r11d
    or  eax, edx
    mov ebx, 0x5A827999
    jmp .have_f
.f2:
    ; f = b XOR c XOR d
    mov eax, r9d
    xor eax, r10d
    xor eax, r11d
    mov ebx, 0x6ED9EBA1
    jmp .have_f
.f3:
    ; f = (b AND c) OR (b AND d) OR (c AND d)
    mov eax, r9d
    and eax, r10d
    mov edx, r9d
    and edx, r11d
    or  eax, edx
    mov edx, r10d
    and edx, r11d
    or  eax, edx
    mov ebx, 0x8F1BBCDC
    jmp .have_f
.f4:
    ; f = b XOR c XOR d
    mov eax, r9d
    xor eax, r10d
    xor eax, r11d
    mov ebx, 0xCA62C1D6
.have_f:
    ; eax = f, ebx = K[phase] -- temp = ROTL(a,5) + f + e + K + W[i]
    add eax, r12d            ; f + e
    add eax, ebx              ; + K
    add eax, [rsp + rcx*4]    ; + W[i]
    mov edx, r8d              ; a
    rol edx, 5                ; ROTL(a,5)
    add eax, edx               ; eax = temp

    ; state update: (e,d,c,b,a) <- (d, c, ROTL(b,30), a, temp)
    mov r12d, r11d            ; e' = d
    mov r11d, r10d            ; d' = c
    mov edx, r9d               ; b
    rol edx, 30
    mov r10d, edx              ; c' = ROTL(b,30)
    mov r9d, r8d                ; b' = a
    mov r8d, eax                 ; a' = temp

    inc ecx
    cmp ecx, 80
    jb  .round

    ; ---- PHASE 5: fold the working state back into the running hash ----
    add [rdi + 0],  r8d      ; H0 += a
    add [rdi + 4],  r9d      ; H1 += b
    add [rdi + 8],  r10d     ; H2 += c
    add [rdi + 12], r11d     ; H3 += d
    add [rdi + 16], r12d     ; H4 += e

    add rsp, 320
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; ============================================================================
; void sha1_full(u8 out[20], const void *msg, i64 len)
;   One-shot SHA-1 over a message of arbitrary length. Same padding rule as
;   sha256_full (FIPS 180-4, shared block size and trailer format).
;
; Callee-saved parking, mirroring sha256_full exactly:
;   r15 = out pointer, rbx = current msg position,
;   r14 = total byte length, r13 = bytes still unprocessed.
; Stack layout: [rsp+0..19] state H[0..4], [rsp+32..95] work block.
; ============================================================================
global sha1_full
sha1_full:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 104            ; 32B state slot (20 used) + 64B work block + 8B pad
                              ; 6 pushes -> RSP 8 mod16; sub 104 (8 mod16) -> 0 mod16

    mov r15, rdi             ; r15 = out[]
    mov rbx, rsi             ; rbx = msg pointer
    mov r14, rdx             ; r14 = total length in bytes
    mov r13, rdx             ; r13 = remaining byte count

    mov rdi, rsp
    call sha1_init

.blocks:
    cmp r13, 64
    jb  .padrun
    lea rdi, [rsp+32]
    mov rsi, rbx
    mov rcx, 64
    rep movsb
    mov rdi, rsp
    lea rsi, [rsp+32]
    call sha1_block
    add rbx, 64
    sub r13, 64
    jmp .blocks

.padrun:
    lea rdi, [rsp+32]
    mov rsi, rbx
    mov rcx, r13
    rep movsb
    mov byte [rdi], 0x80
    lea rdi, [rsp+32]
    mov rax, r13
    lea rdi, [rdi + rax + 1]
    xor eax, eax
    mov rcx, 63
    sub rcx, r13
    rep stosb

    cmp r13, 56
    jb  .lastblock
    mov rdi, rsp
    lea rsi, [rsp+32]
    call sha1_block
    lea rdi, [rsp+32]
    xor eax, eax
    mov rcx, 64
    rep stosb

.lastblock:
    mov rax, r14
    shl rax, 3
    bswap rax
    lea rdi, [rsp+32]
    mov [rdi + 56], rax
    mov rdi, rsp
    lea rsi, [rsp+32]
    call sha1_block

    ; emit the 20-byte digest (5 words), big-endian
    mov rsi, rsp
    xor ecx, ecx
.emit:
    mov eax, [rsi + rcx*4]
    bswap eax
    mov [r15 + rcx*4], eax
    inc ecx
    cmp ecx, 5
    jb  .emit

    add rsp, 104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret


; ============================================================================
; SHA-NI SHA-1 (2026-09-28): sha1_block_shani, the same compression with the
; SHA extensions' sha1rnds4 / sha1nexte / sha1msg1 / sha1msg2, four rounds
; per instruction. The scalar body above (sha1_block_scalar) is the fallback
; on CPUs without the extension and the oracle the tests hold this to.
;
; WHY NOW. The 2026-09-27 benchmark had SHA-1 2.5x behind Core over a
; megabyte (1.58 vs 0.64 ns/byte): Core's is plain C++ but scheduled well;
; the scalar body here branches to one of four f-functions on every round.
; Rather than tune that (cold path: OP_SHA1 only), the extension takes the
; block: ~0.25 ns/byte, and the scalar body stays exactly as it was.
;
; REGISTER CONVENTION (Intel's, as the Linux kernel's sha1_ni_asm.S):
;   ABCD  = state[0..3] with A in the HIGH dword (pshufd 0x1B on load/store)
;   E0    = state[4] in the high dword, the low three zero
;   MSG0..3 = the 64-byte block as four big-endian-corrected words each,
;             word 0 of each quartet in the high dword (a full 16-byte
;             byte reversal via pshufb)
;   sha1rnds4 ABCD, E, f    four rounds with f-function 0..3
;   sha1nexte E, MSG        E' = rotl(A, 30) + MSG (the next quartet's E term)
;   sha1msg1 / sha1msg2     the schedule W[i] = rotl(W[i-3]^W[i-8]^W[i-14]^W[i-16], 1)
; ============================================================================
section .rodata
align 16
SHA1_BSWAP16:  db 15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0
SHA1_HIGHWORD: dd 0, 0, 0, 0xffffffff
section .text

global sha1_block_shani
sha1_block_shani:
    ; rdi = state (u32[5]), rsi = block (64 bytes)
    movdqu  xmm0, [rdi]                 ; ABCD
    pshufd  xmm0, xmm0, 0x1B            ; A into the high dword
    movd    xmm1, dword [rdi+16]        ; E
    pslldq  xmm1, 12                    ; into the high dword
    movdqa  xmm8, xmm0                  ; saved ABCD
    movdqa  xmm9, xmm1                  ; saved E
    movdqa  xmm7, [rel SHA1_BSWAP16]

    ; rounds 0-3
    movdqu  xmm3, [rsi+0]
    pshufb  xmm3, xmm7                  ; MSG0
    paddd   xmm1, xmm3                  ; E0 += MSG0
    movdqa  xmm2, xmm0                  ; E1 = ABCD
    sha1rnds4 xmm0, xmm1, 0
    ; rounds 4-7
    movdqu  xmm4, [rsi+16]
    pshufb  xmm4, xmm7                  ; MSG1
    sha1nexte xmm2, xmm4
    movdqa  xmm1, xmm0
    sha1rnds4 xmm0, xmm2, 0
    sha1msg1 xmm3, xmm4
    ; rounds 8-11
    movdqu  xmm5, [rsi+32]
    pshufb  xmm5, xmm7                  ; MSG2
    sha1nexte xmm1, xmm5
    movdqa  xmm2, xmm0
    sha1rnds4 xmm0, xmm1, 0
    sha1msg1 xmm4, xmm5
    pxor    xmm3, xmm5
    ; rounds 12-15
    movdqu  xmm6, [rsi+48]
    pshufb  xmm6, xmm7                  ; MSG3
    sha1nexte xmm2, xmm6
    movdqa  xmm1, xmm0
    sha1msg2 xmm3, xmm6
    sha1rnds4 xmm0, xmm2, 0
    sha1msg1 xmm5, xmm6
    pxor    xmm4, xmm6
    ; rounds 16-19
    sha1nexte xmm1, xmm3
    movdqa  xmm2, xmm0
    sha1msg2 xmm4, xmm3
    sha1rnds4 xmm0, xmm1, 0
    sha1msg1 xmm6, xmm3
    pxor    xmm5, xmm3
    ; rounds 20-23
    sha1nexte xmm2, xmm4
    movdqa  xmm1, xmm0
    sha1msg2 xmm5, xmm4
    sha1rnds4 xmm0, xmm2, 1
    sha1msg1 xmm3, xmm4
    pxor    xmm6, xmm4
    ; rounds 24-27
    sha1nexte xmm1, xmm5
    movdqa  xmm2, xmm0
    sha1msg2 xmm6, xmm5
    sha1rnds4 xmm0, xmm1, 1
    sha1msg1 xmm4, xmm5
    pxor    xmm3, xmm5
    ; rounds 28-31
    sha1nexte xmm2, xmm6
    movdqa  xmm1, xmm0
    sha1msg2 xmm3, xmm6
    sha1rnds4 xmm0, xmm2, 1
    sha1msg1 xmm5, xmm6
    pxor    xmm4, xmm6
    ; rounds 32-35
    sha1nexte xmm1, xmm3
    movdqa  xmm2, xmm0
    sha1msg2 xmm4, xmm3
    sha1rnds4 xmm0, xmm1, 1
    sha1msg1 xmm6, xmm3
    pxor    xmm5, xmm3
    ; rounds 36-39
    sha1nexte xmm2, xmm4
    movdqa  xmm1, xmm0
    sha1msg2 xmm5, xmm4
    sha1rnds4 xmm0, xmm2, 1
    sha1msg1 xmm3, xmm4
    pxor    xmm6, xmm4
    ; rounds 40-43
    sha1nexte xmm1, xmm5
    movdqa  xmm2, xmm0
    sha1msg2 xmm6, xmm5
    sha1rnds4 xmm0, xmm1, 2
    sha1msg1 xmm4, xmm5
    pxor    xmm3, xmm5
    ; rounds 44-47
    sha1nexte xmm2, xmm6
    movdqa  xmm1, xmm0
    sha1msg2 xmm3, xmm6
    sha1rnds4 xmm0, xmm2, 2
    sha1msg1 xmm5, xmm6
    pxor    xmm4, xmm6
    ; rounds 48-51
    sha1nexte xmm1, xmm3
    movdqa  xmm2, xmm0
    sha1msg2 xmm4, xmm3
    sha1rnds4 xmm0, xmm1, 2
    sha1msg1 xmm6, xmm3
    pxor    xmm5, xmm3
    ; rounds 52-55
    sha1nexte xmm2, xmm4
    movdqa  xmm1, xmm0
    sha1msg2 xmm5, xmm4
    sha1rnds4 xmm0, xmm2, 2
    sha1msg1 xmm3, xmm4
    pxor    xmm6, xmm4
    ; rounds 56-59
    sha1nexte xmm1, xmm5
    movdqa  xmm2, xmm0
    sha1msg2 xmm6, xmm5
    sha1rnds4 xmm0, xmm1, 2
    sha1msg1 xmm4, xmm5
    pxor    xmm3, xmm5
    ; rounds 60-63
    sha1nexte xmm2, xmm6
    movdqa  xmm1, xmm0
    sha1msg2 xmm3, xmm6
    sha1rnds4 xmm0, xmm2, 3
    sha1msg1 xmm5, xmm6
    pxor    xmm4, xmm6
    ; rounds 64-67
    sha1nexte xmm1, xmm3
    movdqa  xmm2, xmm0
    sha1msg2 xmm4, xmm3
    sha1rnds4 xmm0, xmm1, 3
    sha1msg1 xmm6, xmm3
    pxor    xmm5, xmm3
    ; rounds 68-71
    sha1nexte xmm2, xmm4
    movdqa  xmm1, xmm0
    sha1msg2 xmm5, xmm4
    sha1rnds4 xmm0, xmm2, 3
    pxor    xmm6, xmm4
    ; rounds 72-75
    sha1nexte xmm1, xmm5
    movdqa  xmm2, xmm0
    sha1msg2 xmm6, xmm5
    sha1rnds4 xmm0, xmm1, 3
    ; rounds 76-79
    sha1nexte xmm2, xmm6
    movdqa  xmm1, xmm0
    sha1rnds4 xmm0, xmm2, 3

    ; state += result: E = rotl(A,30) + E_saved is what sha1nexte computes
    sha1nexte xmm1, xmm9
    paddd   xmm0, xmm8
    pshufd  xmm0, xmm0, 0x1B
    movdqu  [rdi], xmm0
    pextrd  dword [rdi+16], xmm1, 3
    ret

; sha1_cpu_has_sha() -> eax = 1 if leaf 7 ebx bit 29 (SHA extensions)
global sha1_cpu_has_sha
sha1_cpu_has_sha:
    push rbx
    xor  eax, eax
    cpuid
    cmp  eax, 7
    jb   .no
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    shr  ebx, 29
    and  ebx, 1
    mov  eax, ebx
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
