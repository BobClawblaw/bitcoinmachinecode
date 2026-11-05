/* ============================================================================
 * bitcoin_muhash.S -- MuHash3072 in AArch64 assembly (Apple silicon), the
 * counterpart of asm/bitcoin_muhash.asm. Replaces muhash_twin.c on the Mac
 * (2026-09-26); the twin stays in port/osx/test_support as the oracle.
 *
 *   p = 2^3072 - 1103717 (MPD = 1103717), 48 x u64 little-endian limbs.
 *
 *   void num3072_set_one(u64 r[48]);            void muhash_init(u64 r[48]);
 *   long num3072_is_overflow(const u64 a[48]);  a in [p, 2^3072)
 *   void num3072_full_reduce(u64 a[48]);        a += MPD (mod 2^3072) = a - p
 *   void num3072_mul_generic(u64 out[48], const u64 a[48], const u64 b[48]);
 *   void num3072_mul(u64 a[48], const u64 b[48]);          a = a*b
 *   void num3072_mul_force_path(int);  int num3072_mul_current_path(void);
 *   int  num3072_cpu_has_ifma(void);   int num3072_cpu_has_adx(void);
 *   void chacha20_keystream_k0(u8* out, u64 blocks, const u8 key[32]);
 *   void muhash_to_num3072(u8 out[384], const void* data, unsigned long len);
 *   void muhash_insert(u64 acc[48], const void* data, unsigned long len);
 *   void muhash_combine(u64 acc[48], const u64 other[48]);
 *   void muhash_finalize(u8 out[32], const void* acc);
 *
 * num3072_mul_generic: the exact 6144-bit product by product scanning (one
 * column per output limb, a 192-bit accumulator), then value = L + H*2^3072
 * with 2^3072 = MPD (mod p): one pass folds H*MPD into L (the column carry
 * stays under 2^23), the leftover top word is folded again, and a last
 * carry out of 2^3072 once more (then the value is small, so it cannot
 * carry again). A final t >= p test -- t + MPD carries out of 2^3072 --
 * subtracts p. The result is the CANONICAL residue for any inputs, what the
 * twin's three bounded rounds + canonicalise produce. The whole product is
 * built on the stack before out is written, so out may alias a or b.
 *
 * x86 has ADX and IFMA bodies beside the generic one; AArch64 has neither,
 * so the path is always 2 (generic) and force_path is a no-op, as the twin.
 * Variable-time in the limb values? No: every loop count is fixed and the
 * data-dependent parts are carries; the fold loop repeats only on a carry
 * out, as the twin's rounds do. MuHash hashes public UTXO data.
 * ========================================================================== */
#define MPD 1103717

    .text

    .p2align 2
    .globl _num3072_set_one
    .globl _muhash_init
_muhash_init:
_num3072_set_one:
    mov   x9, #1
    stp   x9, xzr, [x0], #16
    mov   x10, #23                        /* 23 more pairs: limbs 2..47 */
1:  stp   xzr, xzr, [x0], #16
    subs  x10, x10, #1
    b.ne  1b
    ret

    .p2align 2
    .globl _num3072_is_overflow
_num3072_is_overflow:
    ldr   x9, [x0]
    movz  x10, #(MPD & 0xffff)
    movk  x10, #(MPD >> 16), lsl #16
    mvn   x10, x10                        /* 2^64 - 1 - MPD */
    cmp   x9, x10
    b.ls  2f
    mov   x11, #1
1:  ldr   x9, [x0, x11, lsl #3]
    cmn   x9, #1
    b.ne  2f
    add   x11, x11, #1
    cmp   x11, #48
    b.lo  1b
    mov   x0, #1
    ret
2:  mov   x0, #0
    ret

    .p2align 2
    .globl _num3072_full_reduce
_num3072_full_reduce:
    movz  x10, #(MPD & 0xffff)
    movk  x10, #(MPD >> 16), lsl #16
    ldr   x9, [x0]
    adds  x9, x9, x10
    str   x9, [x0], #8
    mov   x11, #47
1:  ldr   x9, [x0]                        /* ldr/str/sub/cbnz leave C alone */
    adcs  x9, x9, xzr
    str   x9, [x0], #8
    sub   x11, x11, #1
    cbnz  x11, 1b
    ret

/* ============================================================================
 * num3072_mul_generic(out=x0, a=x1, b=x2) ; leaf, frame t[96] at sp (768)
 * ========================================================================== */
    .p2align 2
    .globl _num3072_mul_generic
_num3072_mul_generic:
    sub   sp, sp, #768
    mov   x9, xzr                         /* column accumulator c0:c1:c2 */
    mov   x10, xzr
    mov   x11, xzr
    mov   x12, #0                         /* k: output column 0..94 */
Lcol:
    subs  x3, x12, #47                    /* i_lo = max(0, k-47) */
    csel  x3, xzr, x3, lo
    cmp   x12, #47                        /* i_hi = min(k, 47) */
    mov   x4, #47
    csel  x4, x12, x4, lo
    sub   x5, x4, x3
    add   x5, x5, #1                      /* terms in this column */
    add   x6, x1, x3, lsl #3              /* &a[i_lo] */
    sub   x7, x12, x3
    add   x7, x2, x7, lsl #3              /* &b[k - i_lo] */
1:  ldr   x13, [x6], #8
    ldr   x14, [x7], #-8
    mul   x15, x13, x14
    umulh x16, x13, x14
    adds  x9, x9, x15
    adcs  x10, x10, x16
    adc   x11, x11, xzr
    subs  x5, x5, #1
    b.ne  1b
    str   x9, [sp, x12, lsl #3]           /* t[k] */
    mov   x9, x10
    mov   x10, x11
    mov   x11, xzr
    add   x12, x12, #1
    cmp   x12, #95
    b.lo  Lcol
    str   x9, [sp, #95 * 8]               /* t[95] */

    /* fold: t[0..47] = L + H*MPD, carry word out in x9 */
    movz  x3, #(MPD & 0xffff)
    movk  x3, #(MPD >> 16), lsl #16
    mov   x9, xzr
    mov   x12, #0
2:  add   x6, sp, x12, lsl #3
    ldr   x13, [x6]                       /* L[i] */
    ldr   x14, [x6, #48 * 8]              /* H[i] */
    mul   x15, x14, x3
    umulh x16, x14, x3
    adds  x13, x13, x15
    adc   x16, x16, xzr
    adds  x13, x13, x9
    adc   x9, x16, xzr
    str   x13, [x6]
    add   x12, x12, #1
    cmp   x12, #48
    b.lo  2b
    /* top word * MPD back in at limb 0; a carry out of 2^3072 is MPD again */
    mul   x9, x9, x3                      /* < 2^23 * 2^21: one word */
3:  ldr   x13, [sp]
    adds  x13, x13, x9
    str   x13, [sp]
    add   x6, sp, #8
    mov   x12, #47
4:  ldr   x13, [x6]
    adcs  x13, x13, xzr
    str   x13, [x6], #8
    sub   x12, x12, #1
    cbnz  x12, 4b
    mov   x9, x3
    b.cs  3b                              /* carried out: fold MPD once more */

    /* canonical: t >= p  <=>  t + MPD carries out of 2^3072 */
    ldr   x13, [sp]
    adds  x13, x13, x3
    add   x6, sp, #8
    mov   x12, #47
5:  ldr   x13, [x6], #8
    adcs  x13, x13, xzr
    sub   x12, x12, #1
    cbnz  x12, 5b
    csel  x3, x3, xzr, cs                 /* add MPD (wrapping = t - p) or 0 */
    ldr   x13, [sp]
    adds  x13, x13, x3
    str   x13, [x0]
    add   x6, sp, #8
    add   x7, x0, #8
    mov   x12, #47
6:  ldr   x13, [x6], #8
    adcs  x13, x13, xzr
    str   x13, [x7], #8
    sub   x12, x12, #1
    cbnz  x12, 6b
    add   sp, sp, #768
    ret

    .p2align 2
    .globl _num3072_mul
_num3072_mul:
    mov   x2, x1                          /* a = a*b: alias-safe, see above */
    mov   x1, x0
    b     _num3072_mul_generic

    .p2align 2
    .globl _num3072_mul_force_path
_num3072_mul_force_path:
    ret                                   /* AArch64: generic only */

    .p2align 2
    .globl _num3072_mul_current_path
_num3072_mul_current_path:
    mov   w0, #2
    ret

    .p2align 2
    .globl _num3072_cpu_has_ifma
    .globl _num3072_cpu_has_adx
_num3072_cpu_has_ifma:
_num3072_cpu_has_adx:
    mov   w0, #0
    ret

/* ============================================================================
 * chacha20_keystream_k0(out=x0, blocks=x1, key=x2): ChaCha20 with sigma,
 * the 32-byte key, block counter from 0 and a zero nonce.
 * State st[16] at sp (64); working x0..x15 in w3..w17, w19 (x15);
 * round counter x20, out x21, blocks x22.
 * ========================================================================== */
.macro QR a, b, c, d
    add   \a, \a, \b
    eor   \d, \d, \a
    ror   \d, \d, #16
    add   \c, \c, \d
    eor   \b, \b, \c
    ror   \b, \b, #20
    add   \a, \a, \b
    eor   \d, \d, \a
    ror   \d, \d, #24
    add   \c, \c, \d
    eor   \b, \b, \c
    ror   \b, \b, #25
.endm
.macro OUT2 wa, wb, off                   /* out[off..] = (wa, wb) + st */
    ldp   w0, w1, [sp, #\off]
    add   \wa, \wa, w0
    add   \wb, \wb, w1
    stp   \wa, \wb, [x21, #\off]
.endm

    .p2align 2
    .globl _chacha20_keystream_k0
_chacha20_keystream_k0:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #64
    mov   x21, x0
    mov   x22, x1
    adrp  x9, Lsigma@PAGE
    add   x9, x9, Lsigma@PAGEOFF
    ldp   x10, x11, [x9]
    stp   x10, x11, [sp]                  /* st[0..3] = sigma */
    ldp   x10, x11, [x2]
    stp   x10, x11, [sp, #16]             /* st[4..11] = key */
    ldp   x10, x11, [x2, #16]
    stp   x10, x11, [sp, #32]
    stp   xzr, xzr, [sp, #48]             /* st[12..15] = counter, nonce = 0 */
    cbz   x22, Lcc_done
Lcc_block:
    ldp   w3, w4, [sp]
    ldp   w5, w6, [sp, #8]
    ldp   w7, w8, [sp, #16]
    ldp   w9, w10, [sp, #24]
    ldp   w11, w12, [sp, #32]
    ldp   w13, w14, [sp, #40]
    ldp   w15, w16, [sp, #48]
    ldp   w17, w19, [sp, #56]
    mov   x20, #10
1:  QR    w3, w7, w11, w15                /* columns */
    QR    w4, w8, w12, w16
    QR    w5, w9, w13, w17
    QR    w6, w10, w14, w19
    QR    w3, w8, w13, w19                /* diagonals */
    QR    w4, w9, w14, w15
    QR    w5, w10, w11, w16
    QR    w6, w7, w12, w17
    subs  x20, x20, #1
    b.ne  1b
    OUT2  w3, w4, 0
    OUT2  w5, w6, 8
    OUT2  w7, w8, 16
    OUT2  w9, w10, 24
    OUT2  w11, w12, 32
    OUT2  w13, w14, 40
    OUT2  w15, w16, 48
    OUT2  w17, w19, 56
    ldr   w9, [sp, #48]                   /* st[12] += 1 (u32) */
    add   w9, w9, #1
    str   w9, [sp, #48]
    add   x21, x21, #64
    subs  x22, x22, #1
    b.ne  Lcc_block
Lcc_done:
    add   sp, sp, #64
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* muhash_to_num3072(out=x0, data=x1, len=x2) ; frame digest 0 (32) */
    .p2align 2
    .globl _muhash_to_num3072
_muhash_to_num3072:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #32
    mov   x19, x0
    mov   x0, sp
    bl    _sha256_full
    mov   x0, x19
    mov   x1, #6                          /* 384 / 64 */
    mov   x2, sp
    bl    _chacha20_keystream_k0
    add   sp, sp, #32
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* muhash_insert(acc=x0, data=x1, len=x2) ; frame elem 0 (384) */
    .p2align 2
    .globl _muhash_insert
_muhash_insert:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #384
    mov   x19, x0
    mov   x0, sp
    bl    _muhash_to_num3072
    mov   x0, x19
    mov   x1, x19
    mov   x2, sp
    bl    _num3072_mul_generic
    add   sp, sp, #384
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .p2align 2
    .globl _muhash_combine
_muhash_combine:
    mov   x2, x1                          /* acc = acc*other */
    mov   x1, x0
    b     _num3072_mul_generic

/* muhash_finalize(out=x0, acc=x1) ; frame work 0 (384) ; out x19 */
    .p2align 2
    .globl _muhash_finalize
_muhash_finalize:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #384
    mov   x19, x0
    mov   x0, sp
    mov   x2, #384
    bl    _memcpy                         /* work = acc */
    mov   x0, sp
    bl    _num3072_is_overflow
    cbz   x0, 1f
    mov   x0, sp
    bl    _num3072_full_reduce
1:  mov   x0, sp                          /* work = work * 1 */
    mov   x1, sp
    adrp  x2, Lone@PAGE
    add   x2, x2, Lone@PAGEOFF
    bl    _num3072_mul_generic
    mov   x0, sp
    bl    _num3072_is_overflow
    cbz   x0, 2f
    mov   x0, sp
    bl    _num3072_full_reduce
2:  mov   x0, x19
    mov   x1, sp
    mov   x2, #384
    bl    _sha256_full
    add   sp, sp, #384
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .section __TEXT,__const
    .p2align 4
Lsigma:
    .long 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
Lone:       /* the num3072 one */
    .quad 1
    .space 47 * 8
