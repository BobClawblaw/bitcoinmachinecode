/* ============================================================================
 * sha1.S -- SHA-1 in AArch64 assembly (Apple silicon), the counterpart of
 * asm/sha1.asm. Replaces sha1_twin.c on the Mac (2026-09-26); the twin stays
 * in port/osx/test_support as the oracle.
 *
 *   void sha1_init(u32 state[5]);
 *   void sha1_block(u32 state[5], const u8 block[64]);
 *   void sha1_full(u8 out[20], const void* msg, long long len);
 *
 * FIPS 180-4 SHA-1: big-endian message words, padding as SHA-256's (0x80,
 * zeros, 64-bit big-endian bit length), digest = the 5 state words as
 * big-endian bytes.
 *
 * The compression uses the ARMv8 SHA-1 instructions (sha1c/p/m four rounds
 * each, sha1h for the next e, sha1su0/su1 for the schedule) -- the AArch64
 * counterpart of SHA-NI, present on every Apple silicon core (FEAT_SHA1 is
 * mandatory with the crypto extension Apple ships). Since 2026-09-28 (x86
 * main #332 gave sha1.asm a SHA-NI body beside its scalar one, and
 * tests/test_sha1 drives both) the same two-body shape is here:
 *   sha1_block_shani   the crypto-extension body (the one above, renamed)
 *   sha1_block_scalar  a plain FIPS 180-4 round loop, the test's second body
 *   sha1_block         dispatches: the probe once (sysctlbyname
 *                      hw.optional.arm.FEAT_SHA1, as sha256.S's), then the
 *                      cached path; sha1_force_path(0 re-probe, 1 crypto,
 *                      2 scalar) pins it for the test; sha1_cpu_has_sha.
 * The output is the same standard function, which the differential fuzz
 * against the twin and the hashlib vectors of test_sha1-using tests pin.
 *
 * The first two AArch64 attempts (2026-09-08, scalar translations of the
 * x86) loaded W[0] wrong; this one is written against the instruction
 * semantics, not the x86 register schedule, and is fuzzed across every
 * length 0..300 and random lengths up to 4 KiB.
 * ========================================================================== */
    .text

    .p2align 2
    .globl _sha1_init
_sha1_init:
    adrp  x9, Lsha1_iv@PAGE
    add   x9, x9, Lsha1_iv@PAGEOFF
    ldr   q0, [x9]
    ldr   w10, [x9, #16]
    str   q0, [x0]
    str   w10, [x0, #16]
    ret

/* sha1_block(state=x0, block=x1): the dispatcher */
    .p2align 2
    .globl _sha1_block
_sha1_block:
    adrp  x9, Lsha1_path@PAGE
    add   x9, x9, Lsha1_path@PAGEOFF
    ldrb  w10, [x9]
    cbnz  w10, 1f
    stp   x29, x30, [sp, #-32]!           /* probe once: park the arguments */
    stp   x0, x1, [sp, #16]
    bl    _sha1_cpu_has_sha
    mov   w10, #2
    cmp   w0, #1
    csel  w10, w0, w10, eq                /* 1 -> crypto, else 2 -> scalar */
    adrp  x9, Lsha1_path@PAGE
    add   x9, x9, Lsha1_path@PAGEOFF
    strb  w10, [x9]
    ldp   x0, x1, [sp, #16]
    ldp   x29, x30, [sp], #32
1:  cmp   w10, #1
    b.eq  _sha1_block_shani
    b     _sha1_block_scalar

/* sha1_force_path(p): 0 re-probe on the next call, 1 crypto, 2 scalar */
    .p2align 2
    .globl _sha1_force_path
_sha1_force_path:
    adrp  x9, Lsha1_path@PAGE
    add   x9, x9, Lsha1_path@PAGEOFF
    strb  w0, [x9]
    ret

/* int sha1_cpu_has_sha(void): sysctlbyname("hw.optional.arm.FEAT_SHA1") */
    .p2align 2
    .globl _sha1_cpu_has_sha
_sha1_cpu_has_sha:
    stp   x29, x30, [sp, #-16]!
    sub   sp, sp, #16                     /* [sp] value, [sp+8] size (in/out) */
    adrp  x0, Lsha1_feat@PAGE
    add   x0, x0, Lsha1_feat@PAGEOFF
    mov   x1, sp
    mov   x9, #4
    str   x9, [sp, #8]
    add   x2, sp, #8
    mov   x3, #0
    mov   x4, #0
    bl    _sysctlbyname
    cbnz  w0, 2f
    ldr   w9, [sp]
    cmp   w9, #1
    b.ne  2f
    mov   w0, #1
    b     3f
2:  mov   w0, #0
3:  add   sp, sp, #16
    ldp   x29, x30, [sp], #16
    ret

/* sha1_block_scalar(state=x0, block=x1): FIPS 180-4 section 6.1.2 as
 * written -- W[80] on the stack, one round per iteration, the four stages
 * as four loops. Not for speed: the crypto body is 4x faster and is what
 * the dispatcher takes on every Apple core; this is the second body the
 * test holds it to. x9..x17 only. */
    .p2align 2
    .globl _sha1_block_scalar
_sha1_block_scalar:
    sub   sp, sp, #320
    mov   x9, #0
1:  ldr   w10, [x1, x9, lsl #2]           /* W[t] = big-endian word t */
    rev   w10, w10
    str   w10, [sp, x9, lsl #2]
    add   x9, x9, #1
    cmp   x9, #16
    b.lo  1b
2:  sub   x10, x9, #3                     /* W[t] = rol(W[t-3]^W[t-8]^W[t-14]^W[t-16], 1) */
    ldr   w11, [sp, x10, lsl #2]
    sub   x10, x9, #8
    ldr   w12, [sp, x10, lsl #2]
    eor   w11, w11, w12
    sub   x10, x9, #14
    ldr   w12, [sp, x10, lsl #2]
    eor   w11, w11, w12
    sub   x10, x9, #16
    ldr   w12, [sp, x10, lsl #2]
    eor   w11, w11, w12
    ror   w11, w11, #31
    str   w11, [sp, x9, lsl #2]
    add   x9, x9, #1
    cmp   x9, #80
    b.lo  2b
    ldp   w10, w11, [x0]                  /* a b */
    ldp   w12, w13, [x0, #8]              /* c d */
    ldr   w14, [x0, #16]                  /* e */
    mov   x9, #0
    /* stage 1: t = 0..19, f = d ^ (b & (c ^ d)), K = 0x5A827999 */
    movz  w17, #0x7999
    movk  w17, #0x5A82, lsl #16
3:  eor   w15, w12, w13
    and   w15, w15, w11
    eor   w15, w15, w13
    ldr   w16, [sp, x9, lsl #2]
    add   w15, w15, w16
    add   w15, w15, w17
    add   w15, w15, w14
    ror   w16, w10, #27                   /* rol(a, 5) */
    add   w15, w15, w16
    mov   w14, w13
    mov   w13, w12
    ror   w12, w11, #2                    /* c = rol(b, 30) */
    mov   w11, w10
    mov   w10, w15
    add   x9, x9, #1
    cmp   x9, #20
    b.lo  3b
    /* stage 2: t = 20..39, f = b ^ c ^ d, K = 0x6ED9EBA1 */
    movz  w17, #0xEBA1
    movk  w17, #0x6ED9, lsl #16
4:  eor   w15, w11, w12
    eor   w15, w15, w13
    ldr   w16, [sp, x9, lsl #2]
    add   w15, w15, w16
    add   w15, w15, w17
    add   w15, w15, w14
    ror   w16, w10, #27
    add   w15, w15, w16
    mov   w14, w13
    mov   w13, w12
    ror   w12, w11, #2
    mov   w11, w10
    mov   w10, w15
    add   x9, x9, #1
    cmp   x9, #40
    b.lo  4b
    /* stage 3: t = 40..59, f = (b & c) | (d & (b | c)), K = 0x8F1BBCDC */
    movz  w17, #0xBCDC
    movk  w17, #0x8F1B, lsl #16
5:  and   w15, w11, w12
    orr   w16, w11, w12
    and   w16, w16, w13
    orr   w15, w15, w16
    ldr   w16, [sp, x9, lsl #2]
    add   w15, w15, w16
    add   w15, w15, w17
    add   w15, w15, w14
    ror   w16, w10, #27
    add   w15, w15, w16
    mov   w14, w13
    mov   w13, w12
    ror   w12, w11, #2
    mov   w11, w10
    mov   w10, w15
    add   x9, x9, #1
    cmp   x9, #60
    b.lo  5b
    /* stage 4: t = 60..79, f = b ^ c ^ d, K = 0xCA62C1D6 */
    movz  w17, #0xC1D6
    movk  w17, #0xCA62, lsl #16
6:  eor   w15, w11, w12
    eor   w15, w15, w13
    ldr   w16, [sp, x9, lsl #2]
    add   w15, w15, w16
    add   w15, w15, w17
    add   w15, w15, w14
    ror   w16, w10, #27
    add   w15, w15, w16
    mov   w14, w13
    mov   w13, w12
    ror   w12, w11, #2
    mov   w11, w10
    mov   w10, w15
    add   x9, x9, #1
    cmp   x9, #80
    b.lo  6b
    ldp   w15, w16, [x0]
    add   w10, w10, w15
    add   w11, w11, w16
    ldp   w15, w16, [x0, #8]
    add   w12, w12, w15
    add   w13, w13, w16
    ldr   w15, [x0, #16]
    add   w14, w14, w15
    stp   w10, w11, [x0]
    stp   w12, w13, [x0, #8]
    str   w14, [x0, #16]
    add   sp, sp, #320
    ret

/* sha1_block_shani(state=x0, block=x1) ; leaf, uses v0-v7, v16-v22 (no v8-v15) */
    .p2align 2
    .globl _sha1_block_shani
_sha1_block_shani:
    adrp  x9, Lsha1_k@PAGE
    add   x9, x9, Lsha1_k@PAGEOFF
    ld1r  {v16.4s}, [x9], #4
    ld1r  {v17.4s}, [x9], #4
    ld1r  {v18.4s}, [x9], #4
    ld1r  {v19.4s}, [x9]
    ldr   q0, [x0]                        /* abcd */
    ldr   s1, [x0, #16]                   /* e */
    ld1   {v4.16b, v5.16b, v6.16b, v7.16b}, [x1]
    rev32 v4.16b, v4.16b                  /* big-endian message words */
    rev32 v5.16b, v5.16b
    rev32 v6.16b, v6.16b
    rev32 v7.16b, v7.16b
    mov   v2.16b, v0.16b                  /* saved abcd, e */
    mov   v3.16b, v1.16b
    /* rounds 0..3 */
    add   v22.4s, v4.4s, v16.4s
    sha1su0 v4.4s, v5.4s, v6.4s
    sha1su1 v4.4s, v7.4s
    sha1h s20, s0
    sha1c q0, s1, v22.4s
    /* rounds 4..7 */
    add   v22.4s, v5.4s, v16.4s
    sha1su0 v5.4s, v6.4s, v7.4s
    sha1su1 v5.4s, v4.4s
    sha1h s21, s0
    sha1c q0, s20, v22.4s
    /* rounds 8..11 */
    add   v22.4s, v6.4s, v16.4s
    sha1su0 v6.4s, v7.4s, v4.4s
    sha1su1 v6.4s, v5.4s
    sha1h s20, s0
    sha1c q0, s21, v22.4s
    /* rounds 12..15 */
    add   v22.4s, v7.4s, v16.4s
    sha1su0 v7.4s, v4.4s, v5.4s
    sha1su1 v7.4s, v6.4s
    sha1h s21, s0
    sha1c q0, s20, v22.4s
    /* rounds 16..19 */
    add   v22.4s, v4.4s, v16.4s
    sha1su0 v4.4s, v5.4s, v6.4s
    sha1su1 v4.4s, v7.4s
    sha1h s20, s0
    sha1c q0, s21, v22.4s
    /* rounds 20..23 */
    add   v22.4s, v5.4s, v17.4s
    sha1su0 v5.4s, v6.4s, v7.4s
    sha1su1 v5.4s, v4.4s
    sha1h s21, s0
    sha1p q0, s20, v22.4s
    /* rounds 24..27 */
    add   v22.4s, v6.4s, v17.4s
    sha1su0 v6.4s, v7.4s, v4.4s
    sha1su1 v6.4s, v5.4s
    sha1h s20, s0
    sha1p q0, s21, v22.4s
    /* rounds 28..31 */
    add   v22.4s, v7.4s, v17.4s
    sha1su0 v7.4s, v4.4s, v5.4s
    sha1su1 v7.4s, v6.4s
    sha1h s21, s0
    sha1p q0, s20, v22.4s
    /* rounds 32..35 */
    add   v22.4s, v4.4s, v17.4s
    sha1su0 v4.4s, v5.4s, v6.4s
    sha1su1 v4.4s, v7.4s
    sha1h s20, s0
    sha1p q0, s21, v22.4s
    /* rounds 36..39 */
    add   v22.4s, v5.4s, v17.4s
    sha1su0 v5.4s, v6.4s, v7.4s
    sha1su1 v5.4s, v4.4s
    sha1h s21, s0
    sha1p q0, s20, v22.4s
    /* rounds 40..43 */
    add   v22.4s, v6.4s, v18.4s
    sha1su0 v6.4s, v7.4s, v4.4s
    sha1su1 v6.4s, v5.4s
    sha1h s20, s0
    sha1m q0, s21, v22.4s
    /* rounds 44..47 */
    add   v22.4s, v7.4s, v18.4s
    sha1su0 v7.4s, v4.4s, v5.4s
    sha1su1 v7.4s, v6.4s
    sha1h s21, s0
    sha1m q0, s20, v22.4s
    /* rounds 48..51 */
    add   v22.4s, v4.4s, v18.4s
    sha1su0 v4.4s, v5.4s, v6.4s
    sha1su1 v4.4s, v7.4s
    sha1h s20, s0
    sha1m q0, s21, v22.4s
    /* rounds 52..55 */
    add   v22.4s, v5.4s, v18.4s
    sha1su0 v5.4s, v6.4s, v7.4s
    sha1su1 v5.4s, v4.4s
    sha1h s21, s0
    sha1m q0, s20, v22.4s
    /* rounds 56..59 */
    add   v22.4s, v6.4s, v18.4s
    sha1su0 v6.4s, v7.4s, v4.4s
    sha1su1 v6.4s, v5.4s
    sha1h s20, s0
    sha1m q0, s21, v22.4s
    /* rounds 60..63 */
    add   v22.4s, v7.4s, v19.4s
    sha1su0 v7.4s, v4.4s, v5.4s
    sha1su1 v7.4s, v6.4s
    sha1h s21, s0
    sha1p q0, s20, v22.4s
    /* rounds 64..67 */
    add   v22.4s, v4.4s, v19.4s
    sha1h s20, s0
    sha1p q0, s21, v22.4s
    /* rounds 68..71 */
    add   v22.4s, v5.4s, v19.4s
    sha1h s21, s0
    sha1p q0, s20, v22.4s
    /* rounds 72..75 */
    add   v22.4s, v6.4s, v19.4s
    sha1h s20, s0
    sha1p q0, s21, v22.4s
    /* rounds 76..79 */
    add   v22.4s, v7.4s, v19.4s
    sha1h s21, s0
    sha1p q0, s20, v22.4s
    add   v0.4s, v0.4s, v2.4s
    add   v21.4s, v21.4s, v3.4s           /* e after round 79 is in s21 */
    str   q0, [x0]
    str   s21, [x0, #16]
    ret

/* ============================================================================
 * sha1_full(out=x0, msg=x1, len=x2)
 * frame: state 0 (32), block 32 (128) -> 160 ; out x19, msg x20, len x21
 * ========================================================================== */
    .p2align 2
    .globl _sha1_full
_sha1_full:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #160
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x0, sp
    bl    _sha1_init
    lsr   x22, x21, #6                    /* full blocks */
    cbz   x22, 2f
1:  mov   x0, sp
    mov   x1, x20
    bl    _sha1_block
    add   x20, x20, #64
    subs  x22, x22, #1
    b.ne  1b
2:  add   x0, sp, #32                     /* 128-byte tail block, zeroed */
    movi  v0.16b, #0
    stp   q0, q0, [x0]
    stp   q0, q0, [x0, #32]
    stp   q0, q0, [x0, #64]
    stp   q0, q0, [x0, #96]
    and   x22, x21, #63                   /* rem */
    mov   x1, x20
    mov   x2, x22
    bl    _memcpy
    add   x9, sp, #32
    mov   w10, #0x80
    strb  w10, [x9, x22]
    lsl   x10, x21, #3                    /* bit length, big-endian */
    rev   x10, x10
    cmp   x22, #56
    b.hs  3f
    str   x10, [x9, #56]
    mov   x0, sp
    add   x1, sp, #32
    bl    _sha1_block
    b     4f
3:  str   x10, [x9, #120]
    mov   x0, sp
    add   x1, sp, #32
    bl    _sha1_block
    mov   x0, sp
    add   x1, sp, #96
    bl    _sha1_block
4:  ldr   q0, [sp]                        /* digest: words big-endian */
    ldr   w10, [sp, #16]
    rev32 v0.16b, v0.16b
    rev   w10, w10
    str   q0, [x19]
    str   w10, [x19, #16]
    add   sp, sp, #160
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

    .section __DATA,__data
Lsha1_path:
    .byte 0                               /* 0 unprobed, 1 crypto, 2 scalar */
    .section __TEXT,__cstring
Lsha1_feat:
    .asciz "hw.optional.arm.FEAT_SHA1"
    .section __TEXT,__const
    .p2align 4
Lsha1_iv:
    .long 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
Lsha1_k:
    .long 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
