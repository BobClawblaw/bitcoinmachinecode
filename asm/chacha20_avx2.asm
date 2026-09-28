; ============================================================================
; chacha20_avx2.asm -- RFC 8439 ChaCha20 keystream, AVX2, six blocks in flight.
;
; WHY. crypto_chacha20.c is the plain-C reference and was the transport's
; cipher: 1.18 ns/byte at 64 bytes against Core's 0.77, and 0.7 against
; Core's ~0.45 on long packets (docs/devlog/BENCHMARKS.md, 2026-09-27). The
; same round function sits under bitcoin_muhash.asm's chacha20_keystream_k0,
; which is 0.65 of every 0.99 us MuHash insert. Core's is a two-way SSE/AVX2
; implementation; this is the AVX2 half of that.
;
; SHAPE. One ChaCha20 block is a 4x4 matrix of 32-bit words; a round applies
; the quarter-round to its four columns, the next round to its four
; diagonals. Holding each ROW in a 128-bit lane makes a column round four
; quarter-rounds in one instruction sequence (lane-wise adds, xors and
; rotates), and a diagonal round the same sequence after rotating rows 1, 2,
; 3 by one, two, three words (vpshufd) and back. A ymm register holds two
; such rows -- one block per 128-bit lane -- so a four-register set is two
; blocks, and three sets (ymm0-11) are six blocks whose instruction streams
; are independent and interleave in the pipeline. ymm12/13 hold the byte
; shuffles that rotate by 16 and 8 (vpshufb; 12 and 7 are shift+shift+or),
; ymm14 is the temporary.
;
; The block counter (word 12) differs per block: the initial row 3 is
; broadcast to both lanes and lane 1's counter gets +1; sets 1 and 2 start
; at +2 and +4; after six blocks the base advances by 6. Counters wrap at
; 32 bits as the RFC says and as the C does (vpaddd wraps).
;
; ENTRY POINTS (System V; the state is 16 LE u32 as crypto_chacha20.c lays
; it out: sigma, key, counter, nonce; it is read, never written):
;   void chacha20_xor_avx2(u8* out, const u8* in, const u32 state[16],
;                          unsigned long nblocks)
;       out[0 .. 64*nblocks) = keystream XOR in; in == NULL emits the raw
;       keystream (it is XORed with a zero page, so the two paths share
;       every instruction). Whole blocks only; the caller handles a tail.
;   int chacha20_cpu_has_avx2(void)
;       1 if AVX2 is present AND the OS saves the ymm state (OSXSAVE,
;       XCR0[2:1]); the C dispatcher probes once and remembers.
;
; Proof: tests/test_chacha20 -- the AVX2 path against the C block function
; on the RFC vectors and on random keys, nonces, counters (including the
; wrap at 2^32), lengths 0..1600 and 1 MB, XOR and raw, with the path forced
; each way through chacha20_force_path.
; ============================================================================
BITS 64

section .rodata
align 32
CC_SIGMA:  dd 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
           dd 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
CC_ROT16:  db 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
           db 2,3,0,1, 6,7,4,5, 10,11,8,9, 14,15,12,13
CC_ROT8:   db 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
           db 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14
CC_CTR01:  dd 0,0,0,0, 1,0,0,0          ; lane 1 is the next block
CC_CTR2:   dd 2,0,0,0, 2,0,0,0          ; a pair advances by two blocks
CC_W0MASK: dd 0xffffffff,0,0,0, 0xffffffff,0,0,0   ; the counter word of each lane
align 32
CC_ZERO:   times 384 db 0               ; "in" when the caller passed NULL

section .text

; one round on rows a b c d (ymm), T a temporary ymm; ymm12/ymm13 = rot16/rot8
%macro QROUND 5
    vpaddd  %1, %1, %2
    vpxor   %4, %4, %1
    vpshufb %4, %4, ymm12
    vpaddd  %3, %3, %4
    vpxor   %2, %2, %3
    vpslld  %5, %2, 12
    vpsrld  %2, %2, 20
    vpor    %2, %2, %5
    vpaddd  %1, %1, %2
    vpxor   %4, %4, %1
    vpshufb %4, %4, ymm13
    vpaddd  %3, %3, %4
    vpxor   %2, %2, %3
    vpslld  %5, %2, 7
    vpsrld  %2, %2, 25
    vpor    %2, %2, %5
%endmacro
; rows 1,2,3 rotated left by 1,2,3 words so the diagonals line up as columns
%macro DIAG_IN 3
    vpshufd %1, %1, 0x39
    vpshufd %2, %2, 0x4E
    vpshufd %3, %3, 0x93
%endmacro
%macro DIAG_OUT 3
    vpshufd %1, %1, 0x93
    vpshufd %2, %2, 0x4E
    vpshufd %3, %3, 0x39
%endmacro
; 20 rounds on the three sets
%macro ROUNDS3 0
    mov  eax, 10
%%r:
    QROUND ymm0, ymm1, ymm2,  ymm3,  ymm14
    QROUND ymm4, ymm5, ymm6,  ymm7,  ymm15
    QROUND ymm8, ymm9, ymm10, ymm11, ymm14
    DIAG_IN ymm1, ymm2,  ymm3
    DIAG_IN ymm5, ymm6,  ymm7
    DIAG_IN ymm9, ymm10, ymm11
    QROUND ymm0, ymm1, ymm2,  ymm3,  ymm15
    QROUND ymm4, ymm5, ymm6,  ymm7,  ymm14
    QROUND ymm8, ymm9, ymm10, ymm11, ymm15
    DIAG_OUT ymm1, ymm2,  ymm3
    DIAG_OUT ymm5, ymm6,  ymm7
    DIAG_OUT ymm9, ymm10, ymm11
    dec  eax
    jnz  %%r
%endmacro
; 20 rounds on set 0 alone
%macro ROUNDS1 0
    mov  eax, 10
%%r:
    QROUND ymm0, ymm1, ymm2, ymm3, ymm14
    DIAG_IN ymm1, ymm2, ymm3
    QROUND ymm0, ymm1, ymm2, ymm3, ymm14
    DIAG_OUT ymm1, ymm2, ymm3
    dec  eax
    jnz  %%r
%endmacro
; finalise one set: add the initial rows (row 3 from the slot given) and
; write its two blocks XORed with [rsi+%6 ..] to [rdi+%6 ..].
;   %1..%4 = rows a b c d, %5 = stack slot of this set's initial row 3,
;   %6 = byte offset of the pair within the six-block group
%macro FINISH_PAIR 6
    vpaddd  %1, %1, [rsp+0]
    vpaddd  %2, %2, [rsp+32]
    vpaddd  %3, %3, [rsp+64]
    vpaddd  %4, %4, [rsp+%5]
    ; block 0 of the pair: the low lanes
    vpxor   xmm14, %1 %+ _x, [rsi+%6+0]
    vmovdqu [rdi+%6+0], xmm14
    vpxor   xmm14, %2 %+ _x, [rsi+%6+16]
    vmovdqu [rdi+%6+16], xmm14
    vpxor   xmm14, %3 %+ _x, [rsi+%6+32]
    vmovdqu [rdi+%6+32], xmm14
    vpxor   xmm14, %4 %+ _x, [rsi+%6+48]
    vmovdqu [rdi+%6+48], xmm14
    ; block 1: the high lanes
    vextracti128 xmm14, %1, 1
    vpxor   xmm14, xmm14, [rsi+%6+64]
    vmovdqu [rdi+%6+64], xmm14
    vextracti128 xmm14, %2, 1
    vpxor   xmm14, xmm14, [rsi+%6+80]
    vmovdqu [rdi+%6+80], xmm14
    vextracti128 xmm14, %3, 1
    vpxor   xmm14, xmm14, [rsi+%6+96]
    vmovdqu [rdi+%6+96], xmm14
    vextracti128 xmm14, %4, 1
    vpxor   xmm14, xmm14, [rsi+%6+112]
    vmovdqu [rdi+%6+112], xmm14
%endmacro
; finalise one set and write only its FIRST block (the low lanes)
%macro FINISH_SINGLE 6
    vpaddd  %1, %1, [rsp+0]
    vpaddd  %2, %2, [rsp+32]
    vpaddd  %3, %3, [rsp+64]
    vpaddd  %4, %4, [rsp+%5]
    vpxor   xmm14, %1 %+ _x, [rsi+%6+0]
    vmovdqu [rdi+%6+0], xmm14
    vpxor   xmm14, %2 %+ _x, [rsi+%6+16]
    vmovdqu [rdi+%6+16], xmm14
    vpxor   xmm14, %3 %+ _x, [rsi+%6+32]
    vmovdqu [rdi+%6+32], xmm14
    vpxor   xmm14, %4 %+ _x, [rsi+%6+48]
    vmovdqu [rdi+%6+48], xmm14
%endmacro
%define ymm0_x  xmm0
%define ymm1_x  xmm1
%define ymm2_x  xmm2
%define ymm3_x  xmm3
%define ymm4_x  xmm4
%define ymm5_x  xmm5
%define ymm6_x  xmm6
%define ymm7_x  xmm7
%define ymm8_x  xmm8
%define ymm9_x  xmm9
%define ymm10_x xmm10
%define ymm11_x xmm11

; ----------------------------------------------------------------------------
; chacha20_xor_avx2(out=rdi, in=rsi, state=rdx, nblocks=rcx)
;   Stack (32-aligned): [rsp+0] row0 (sigma, both lanes), [rsp+32] row1,
;   [rsp+64] row2, [rsp+96] row3 of the current pair 0 (lane 1 = +1),
;   [rsp+128] pair 1's row3 (+2), [rsp+160] pair 2's (+4).
;   r8 = bytes to advance `in` per group (0 when in is the zero page).
; ----------------------------------------------------------------------------
global chacha20_xor_avx2
chacha20_xor_avx2:
    push rbp
    mov  rbp, rsp
    and  rsp, -32
    sub  rsp, 192
    test rsi, rsi
    setnz r8b
    movzx r8d, r8b                  ; r8 = 1 if in is real, else 0
    lea  rax, [rel CC_ZERO]
    test rsi, rsi
    cmovz rsi, rax                  ; in = the zero page when NULL

    vmovdqa ymm12, [rel CC_ROT16]
    vmovdqa ymm13, [rel CC_ROT8]
    vmovdqa ymm0, [rel CC_SIGMA]
    vmovdqa [rsp+0], ymm0
    vbroadcasti128 ymm1, [rdx+16]
    vmovdqa [rsp+32], ymm1
    vbroadcasti128 ymm2, [rdx+32]
    vmovdqa [rsp+64], ymm2
    vbroadcasti128 ymm3, [rdx+48]
    vpaddd  ymm3, ymm3, [rel CC_CTR01]
    vmovdqa [rsp+96], ymm3

    ; ---- three to six blocks per pass: the whole group is computed (it is
    ;      throughput-bound, ~120 ns for six), only the blocks asked for are
    ;      written; a pair alone is latency-bound (~90 ns for two) ----
    cmp  rcx, 3
    jb   .pairs
.six:
    vmovdqa ymm3, [rsp+96]
    vpaddd  ymm7, ymm3, [rel CC_CTR2]
    vmovdqa [rsp+128], ymm7
    vpaddd  ymm11, ymm7, [rel CC_CTR2]
    vmovdqa [rsp+160], ymm11
    vmovdqa ymm0, [rsp+0]
    vmovdqa ymm1, [rsp+32]
    vmovdqa ymm2, [rsp+64]
    vmovdqa ymm4, ymm0
    vmovdqa ymm5, ymm1
    vmovdqa ymm6, ymm2
    vmovdqa ymm8, ymm0
    vmovdqa ymm9, ymm1
    vmovdqa ymm10, ymm2
    ROUNDS3
    FINISH_PAIR ymm0, ymm1, ymm2, ymm3, 96, 0          ; blocks 0,1: always (rcx >= 3)
    cmp  rcx, 4
    jb   .six_p1_single                                ; rcx == 3
    FINISH_PAIR ymm4, ymm5, ymm6, ymm7, 128, 128       ; blocks 2,3
    cmp  rcx, 5
    jb   .six_done                                     ; rcx == 4
    je   .six_p2_single                                ; rcx == 5
    FINISH_PAIR ymm8, ymm9, ymm10, ymm11, 160, 256     ; blocks 4,5
    jmp  .six_done
.six_p1_single:
    FINISH_SINGLE ymm4, ymm5, ymm6, ymm7, 128, 128     ; block 2
    jmp  .six_done
.six_p2_single:
    FINISH_SINGLE ymm8, ymm9, ymm10, ymm11, 160, 256   ; block 4
.six_done:
    ; n = min(rcx, 6): advance out, in (if real) and the counter base by n
    mov  rax, 6
    cmp  rcx, rax
    cmovb rax, rcx
    sub  rcx, rax
    shl  rax, 6                     ; n * 64 bytes
    add  rdi, rax
    imul r9, rax, 1
    imul r9, r8                     ; 0 when in is the zero page
    add  rsi, r9
    shr  rax, 6
    vmovd   xmm14, eax
    vpbroadcastd ymm14, xmm14
    vpand   ymm14, ymm14, [rel CC_W0MASK]
    vpaddd  ymm3, ymm14, [rsp+96]
    vmovdqa [rsp+96], ymm3
    cmp  rcx, 3
    jae  .six

    ; ---- two blocks per pass ----
.pairs:
    cmp  rcx, 2
    jb   .single
    mov  r9, r8
    shl  r9, 7                      ; 128 or 0
.two:
    vmovdqa ymm0, [rsp+0]
    vmovdqa ymm1, [rsp+32]
    vmovdqa ymm2, [rsp+64]
    vmovdqa ymm3, [rsp+96]
    ROUNDS1
    FINISH_PAIR ymm0, ymm1, ymm2, ymm3, 96, 0
    vmovdqa ymm3, [rsp+96]
    vpaddd  ymm3, ymm3, [rel CC_CTR2]
    vmovdqa [rsp+96], ymm3
    add  rdi, 128
    add  rsi, r9
    sub  rcx, 2
    cmp  rcx, 2
    jae  .two

    ; ---- one block: a pair whose second block is not written ----
.single:
    test rcx, rcx
    jz   .done
    vmovdqa ymm0, [rsp+0]
    vmovdqa ymm1, [rsp+32]
    vmovdqa ymm2, [rsp+64]
    vmovdqa ymm3, [rsp+96]
    ROUNDS1
    vpaddd  ymm0, ymm0, [rsp+0]
    vpaddd  ymm1, ymm1, [rsp+32]
    vpaddd  ymm2, ymm2, [rsp+64]
    vpaddd  ymm3, ymm3, [rsp+96]
    vpxor   xmm14, xmm0, [rsi+0]
    vmovdqu [rdi+0], xmm14
    vpxor   xmm14, xmm1, [rsi+16]
    vmovdqu [rdi+16], xmm14
    vpxor   xmm14, xmm2, [rsi+32]
    vmovdqu [rdi+32], xmm14
    vpxor   xmm14, xmm3, [rsi+48]
    vmovdqu [rdi+48], xmm14
.done:
    ; the stack held key material: clear it
    vpxor   ymm0, ymm0, ymm0
    vmovdqa [rsp+32], ymm0
    vmovdqa [rsp+64], ymm0
    vmovdqa [rsp+96], ymm0
    vmovdqa [rsp+128], ymm0
    vmovdqa [rsp+160], ymm0
    vzeroupper
    mov  rsp, rbp
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; chacha20_cpu_has_avx2() -> eax = 1 if AVX2 is usable: max basic leaf >= 7,
;   AVX and OSXSAVE (leaf 1 ecx 28, 27), AVX2 (leaf 7 ebx 5), and XCR0 with
;   the XMM and YMM state bits (1 and 2) set by the OS.
; ----------------------------------------------------------------------------
global chacha20_cpu_has_avx2
chacha20_cpu_has_avx2:
    push rbx
    xor  eax, eax
    cpuid
    cmp  eax, 7
    jb   .no
    mov  eax, 1
    xor  ecx, ecx
    cpuid
    bt   ecx, 27                    ; OSXSAVE
    jnc  .no
    bt   ecx, 28                    ; AVX
    jnc  .no
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    bt   ebx, 5                     ; AVX2
    jnc  .no
    xor  ecx, ecx
    xgetbv                          ; edx:eax = XCR0
    and  eax, 6
    cmp  eax, 6
    jne  .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
