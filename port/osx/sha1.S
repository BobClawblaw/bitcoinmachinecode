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
 * mandatory with the crypto extension Apple ships), so there is no scalar
 * fallback or probe here. The x86 module is scalar; the output is the same
 * standard function, which the differential fuzz against the twin and the
 * hashlib vectors of test_sha1-using tests pin.
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

/* sha1_block(state=x0, block=x1) ; leaf, uses v0-v7, v16-v22 (no v8-v15) */
    .p2align 2
    .globl _sha1_block
_sha1_block:
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

    .section __TEXT,__const
    .p2align 4
Lsha1_iv:
    .long 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
Lsha1_k:
    .long 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
