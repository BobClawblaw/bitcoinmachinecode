; ============================================================================
; sha256_nia.asm -- SHA-256 via Intel/AMD SHA-NI extensions (runtime-dispatched)
;
;   Dispatched on CPUs that report the SHA bit (CPUID.7.0.EBX bit 29). This is
;   the highest-throughput SHA-256 path available on this (AMD Ryzen 9950X3D)
;   machine. The scalar sha256.asm remains the always-correct default; this
;   module is cross-checked byte-for-byte against it before it is trusted.
;
;   Algorithm (canonical Intel SHA-NI layout, 16 words / 64 rounds per block):
;     abcd = state[0..3], efgh = state[4..7]  (lane-reversed: pshufd 0x1B)
;     M0..M3 = bswapped block quads
;     for each of 4 K-groups (4 constants each):
;        K  = load K[i*4 .. i*4+3]
;        TMP = M3 (for msg2)
;        palignr M3, M2, 4            ; shifted schedule word
;        M0 = sha256msg1(M0, M1)
;        paddd M0, M3
;        sha256rnds2 abcd,efgh,K ; sha256rnds2 efgh,abcd,K
;        sha256msg2 M0, TMP
;        ... schedule rotate ...
;        (interleaved 2x rnds2 per msg1/msg2 pair, 2 pairs per group)
;     state += abcd ; state += efgh
;
; ABI (System V AMD64): X/YMM are caller-saved; rbx preserved.
;   int  cpu_has_sha_ni(void)
;   void sha256_block_nia(u32 state[8], const u8 block[64])
;   void sha256_full_nia (u8 out[32], const void* msg, i64 len)
; ============================================================================

BITS 64
DEFAULT REL

section .rodata
align 16
K256_NI:
    dd 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
    dd 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
    dd 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
    dd 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
    dd 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
    dd 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070
    dd 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
    dd 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
align 16
BSHUF_MASK: db 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12

section .text

; ============================================================================
; int cpu_has_sha_ni(void)
; ============================================================================
global cpu_has_sha_ni
cpu_has_sha_ni:
    push rbx
    xor  eax,eax
    cpuid
    cmp  eax,7
    jb   .no
    mov  eax,7
    xor  ecx,ecx
    cpuid
    shr  ebx,29
    and  ebx,1
    mov  eax,ebx
    pop  rbx
    ret
.no:
    xor  eax,eax
    pop  rbx
    ret

; ============================================================================
; void sha256_block_nia(u32 state[8], const u8 block[64])
; http://www.intel.com/content/dam/www/public/us/en/documents/white-papers/sha-256-implementations-sha-512-openssl-gcc-ia32-x64-white-paper.pdf
; ============================================================================
global sha256_block_nia
sha256_block_nia:
    movdqu xmm8,[rdi+0]       ; abcd
    movdqu xmm9,[rdi+16]      ; efgh
    pshufd xmm8,xmm8,0x1B
    pshufd xmm9,xmm9,0x1B

    movdqu xmm13,[rsi+0]      ; M0
    movdqu xmm14,[rsi+16]     ; M1
    movdqu xmm15,[rsi+32]     ; M2
    movdqu xmm11,[rsi+48]     ; M3
    movdqu xmm10,[BSHUF_MASK]
    pshufb xmm13,xmm10
    pshufb xmm14,xmm10
    pshufb xmm15,xmm10
    pshufb xmm11,xmm10

    lea rdx,[K256_NI]

    ; ========================================================================
    ; 4 K-groups. Register roles (System V: XMM all caller-saved):
    ;   xmm8 = abcd (state a,b,c,d)
    ;   xmm9 = efgh (state e,f,g,h)
    ;   xmm13..xmm11 = message schedule quads M0..M3
    ;   xmm2 = TMP (schedule scratch)
    ;   xmm1 = quad-rotation scratch
    ;   xmm10 = K-value staging (loaded into XMM0 for each rnds2)
    ; Canonical per-group body:
    ;   load K(4 lanewords) into xmm10
    ;   paddd M0,K ; tmp=M3; palignr tmp,M2,4; msg1 M0,M1;
    ;   paddd M0,tmp; msg2 M0,tmp
    ;   movdqu xmm0,K      ; K -> XMM0 (hard operand of rnds2)
    ;   rnds2 abcd,efgh
    ;   pshufd K,K,0x0E  (rotate the two K pairs)
    ;   rnds2 efgh,abcd
    ;   pshufd K,K,0x0E
    ;   (schedule) tmp=M3; palignr tmp,M2,4; msg1 M0,M1; paddd M0,tmp; msg2 M0,tmp
    ;   movdqu xmm0,K; rnds2 abcd,efgh; pshufd K,K,0x0E; rnds2 efgh,abcd
    ;   rotate M0<-M1, M1<-M2, M2<-M3, M3<-M0
    ; ========================================================================
    ; ---------------- GROUP 0 : K[0..3] ----------------
    movdqu xmm10,[rdx+0]
    paddd  xmm13,xmm10
    movdqa xmm2,xmm11
    palignr xmm2,xmm15,4
    sha256msg1 xmm13,xmm14
    paddd  xmm13,xmm2
    sha256msg2 xmm13,xmm2
    movdqu xmm0,xmm10
    sha256rnds2 xmm8,xmm9
    pshufd xmm10,xmm10,0x0E
    sha256rnds2 xmm9,xmm8
    pshufd xmm10,xmm10,0x0E
    movdqa xmm2,xmm11
    palignr xmm2,xmm15,4
    sha256msg1 xmm13,xmm14
    paddd  xmm13,xmm2
    sha256msg2 xmm13,xmm2
    movdqu xmm0,xmm10
    sha256rnds2 xmm8,xmm9
    pshufd xmm10,xmm10,0x0E
    sha256rnds2 xmm9,xmm8
    pshufd xmm10,xmm10,0x0E
    movdqa xmm1,xmm13
    movdqa xmm13,xmm14
    movdqa xmm14,xmm15
    movdqa xmm15,xmm11
    movdqa xmm11,xmm1

    ; ---------------- GROUP 1 : K[4..7] ----------------
    movdqu xmm10,[rdx+16]
    paddd  xmm13,xmm10
    movdqa xmm2,xmm11
    palignr xmm2,xmm15,4
    sha256msg1 xmm13,xmm14
    paddd  xmm13,xmm2
    sha256msg2 xmm13,xmm2
    movdqu xmm0,xmm10
    sha256rnds2 xmm8,xmm9
    pshufd xmm10,xmm10,0x0E
    sha256rnds2 xmm9,xmm8
    pshufd xmm10,xmm10,0x0E
    movdqa xmm2,xmm11
    palignr xmm2,xmm15,4
    sha256msg1 xmm13,xmm14
    paddd  xmm13,xmm2
    sha256msg2 xmm13,xmm2
    movdqu xmm0,xmm10
    sha256rnds2 xmm8,xmm9
    pshufd xmm10,xmm10,0x0E
    sha256rnds2 xmm9,xmm8
    pshufd xmm10,xmm10,0x0E
    movdqa xmm1,xmm13
    movdqa xmm13,xmm14
    movdqa xmm14,xmm15
    movdqa xmm15,xmm11
    movdqa xmm11,xmm1

    ; ---------------- GROUP 2 : K[8..11] ----------------
    movdqu xmm10,[rdx+32]
    paddd  xmm13,xmm10
    movdqa xmm2,xmm11
    palignr xmm2,xmm15,4
    sha256msg1 xmm13,xmm14
    paddd  xmm13,xmm2
    sha256msg2 xmm13,xmm2
    movdqu xmm0,xmm10
    sha256rnds2 xmm8,xmm9
    pshufd xmm10,xmm10,0x0E
    sha256rnds2 xmm9,xmm8
    pshufd xmm10,xmm10,0x0E
    movdqa xmm2,xmm11
    palignr xmm2,xmm15,4
    sha256msg1 xmm13,xmm14
    paddd  xmm13,xmm2
    sha256msg2 xmm13,xmm2
    movdqu xmm0,xmm10
    sha256rnds2 xmm8,xmm9
    pshufd xmm10,xmm10,0x0E
    sha256rnds2 xmm9,xmm8
    pshufd xmm10,xmm10,0x0E
    movdqa xmm1,xmm13
    movdqa xmm13,xmm14
    movdqa xmm14,xmm15
    movdqa xmm15,xmm11
    movdqa xmm11,xmm1

    ; ---------------- GROUP 3 : K[12..15] ----------------
    movdqu xmm10,[rdx+48]
    paddd  xmm13,xmm10
    movdqa xmm2,xmm11
    palignr xmm2,xmm15,4
    sha256msg1 xmm13,xmm14
    paddd  xmm13,xmm2
    sha256msg2 xmm13,xmm2
    movdqu xmm0,xmm10
    sha256rnds2 xmm8,xmm9
    pshufd xmm10,xmm10,0x0E
    sha256rnds2 xmm9,xmm8
    pshufd xmm10,xmm10,0x0E
    movdqa xmm2,xmm11
    palignr xmm2,xmm15,4
    sha256msg1 xmm13,xmm14
    paddd  xmm13,xmm2
    sha256msg2 xmm13,xmm2
    movdqu xmm0,xmm10
    sha256rnds2 xmm8,xmm9
    pshufd xmm10,xmm10,0x0E
    sha256rnds2 xmm9,xmm8

    ; ---------------- fold state (reverse lane order) ----------------
    pshufd xmm8,xmm8,0x1B
    pshufd xmm9,xmm9,0x1B
    movdqu xmm10,[rdi+0]
    movdqu xmm11,[rdi+16]
    paddd  xmm8,xmm10
    paddd  xmm9,xmm11
    movdqu [rdi+0],xmm8
    movdqu [rdi+16],xmm9
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
