/* ============================================================================
 * bech32.S -- bech32 / bech32m codec in AArch64 assembly (Apple silicon),
 * the counterpart of asm/bech32.asm. Replaces bech32_twin.c on the Mac
 * (2026-09-26); the twin stays in port/osx/test_support as the oracle.
 *
 *   void      bech32_init(void);
 *   void      bech32_create_checksum(u8 out6[6], const char* hrp, i64 hrplen,
 *                                    const u8* data5, i64 datalen, i64 spec);
 *   i64       bech32_verify_checksum(const char* hrp, i64 hrplen,
 *                                    const u8* data5, i64 datalen, i64 spec);
 *   i64       bech32_convert_bits(u8* out, const u8* in, i64 inlen,
 *                                 i64 frombits, i64 tobits, i64 pad);
 *   i64       bech32_encode(char* out, const char* hrp, i64 hrplen,
 *                           const u8* data5, i64 datalen, i64 spec);
 *   i64       bech32_decode(u8* out5, char* out_hrp, i64 hrp_cap,
 *                           const char* in);          data5 count or -1
 *
 * spec 0 = bech32 (constant 1), 1 = bech32m (0x2bc830a3). Both audited
 * fixes of the x86 control flow are kept: the 90-character input cap
 * (SER-1/WAL-1), checked before any output write, and the mixed-case
 * rejection (SER-5/WAL-9). decode writes out_hrp only once the string has
 * passed the cap/case/separator checks, and out5 only on success.
 *
 * Differences in form, not in output:
 *   - the checksum polymod STREAMS the hrp expansion, the data and the zero
 *     padding, where x86 (and the twin) assemble them in a 512-byte
 *     workspace first -- so no hrplen/datalen can overrun anything here;
 *   - CHAR2IDX / the charset are constant tables, built at assembly time,
 *     so bech32_init has nothing left to do (it stays, as callers call it).
 *   - the hrp expansion's high part is (signed char)c >> 5 as a byte, the
 *     twin's C semantics (and x86's movsx/sar), so a byte >= 0x80 in the hrp
 *     expands the same way.
 * ========================================================================== */
#define BECH32M_CONST 0x2bc830a3

    .text

    .p2align 2
    .globl _bech32_init
_bech32_init:
    ret

/* PMSTEP: chk (w9) = polymod step with value w10 ; GEN in w11..w15,
 * scratch w16, w17 */
.macro PMSTEP
    lsr   w16, w9, #25
    and   w9, w9, #0x1ffffff
    eor   w9, w10, w9, lsl #5
    sbfx  w17, w16, #0, #1
    and   w17, w17, w11
    eor   w9, w9, w17
    sbfx  w17, w16, #1, #1
    and   w17, w17, w12
    eor   w9, w9, w17
    sbfx  w17, w16, #2, #1
    and   w17, w17, w13
    eor   w9, w9, w17
    sbfx  w17, w16, #3, #1
    and   w17, w17, w14
    eor   w9, w9, w17
    sbfx  w17, w16, #4, #1
    and   w17, w17, w15
    eor   w9, w9, w17
.endm

/* Lpolymod(hrp=x0, hrplen=x1, data=x2, datalen=x3, nzero=x4) -> w9 ;
 * leaf, clobbers x5, x6, w9..w17 ; lengths <= 0 contribute nothing */
    .p2align 2
Lpolymod:
    adrp  x5, Lgen@PAGE
    add   x5, x5, Lgen@PAGEOFF
    ldp   w11, w12, [x5]
    ldp   w13, w14, [x5, #8]
    ldr   w15, [x5, #16]
    mov   w9, #1
    mov   x6, #0                          /* hrp high parts */
1:  cmp   x6, x1
    b.ge  2f
    ldrsb w10, [x0, x6]
    asr   w10, w10, #5
    and   w10, w10, #0xff
    PMSTEP
    add   x6, x6, #1
    b     1b
2:  mov   w10, #0                         /* the 0 separator */
    PMSTEP
    mov   x6, #0                          /* hrp low parts */
3:  cmp   x6, x1
    b.ge  4f
    ldrb  w10, [x0, x6]
    and   w10, w10, #31
    PMSTEP
    add   x6, x6, #1
    b     3b
4:  mov   x6, #0                          /* data */
5:  cmp   x6, x3
    b.ge  6f
    ldrb  w10, [x2, x6]
    PMSTEP
    add   x6, x6, #1
    b     5b
6:  cmp   x4, #0                          /* zero padding */
    b.le  7f
    mov   w10, #0
    PMSTEP
    sub   x4, x4, #1
    b     6b
7:  ret

/* w9 ^= spec (x5) ? BECH32M_CONST : 1 ; clobbers w16 */
.macro SPECXOR spec
    movz  w16, #(BECH32M_CONST & 0xffff)
    movk  w16, #(BECH32M_CONST >> 16), lsl #16
    mov   w17, #1
    cmp   \spec, #0
    csel  w16, w16, w17, ne
    eor   w9, w9, w16
.endm

/* bech32_create_checksum(out6=x0, hrp=x1, hrplen=x2, data5=x3, datalen=x4, spec=x5) */
    .p2align 2
    .globl _bech32_create_checksum
_bech32_create_checksum:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x5
    mov   x0, x1
    mov   x1, x2
    mov   x2, x3
    mov   x3, x4
    mov   x4, #6
    bl    Lpolymod
    SPECXOR x20
    mov   x6, #0                          /* out6[i] = chk >> 5*(5-i) & 31 */
    mov   w7, #25
1:  lsr   w10, w9, w7
    and   w10, w10, #31
    strb  w10, [x19, x6]
    add   x6, x6, #1
    sub   w7, w7, #5
    cmp   x6, #6
    b.lo  1b
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* bech32_verify_checksum(hrp=x0, hrplen=x1, data5=x2, datalen=x3, spec=x4) */
    .p2align 2
    .globl _bech32_verify_checksum
_bech32_verify_checksum:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    mov   x19, x4
    mov   x4, #0
    bl    Lpolymod
    SPECXOR x19                           /* chk ^ want == 0  <=>  chk == want */
    cmp   w9, #0
    cset  x0, eq
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* bech32_convert_bits(out=x0, in=x1, inlen=x2, frombits=x3, tobits=x4, pad=x5)
 * acc w9, bits w10, ret x11, max_acc w12, tobits mask w13 ; leaf */
    .p2align 2
    .globl _bech32_convert_bits
_bech32_convert_bits:
    mov   w9, #0
    mov   w10, #0
    mov   x11, #0
    add   x12, x3, x4
    sub   x12, x12, #1
    mov   x13, #1
    lsl   x12, x13, x12
    sub   w12, w12, #1                    /* (u32)((1 << (f+t-1)) - 1) */
    mov   w13, #1
    lsl   w13, w13, w4
    sub   w13, w13, #1
    mov   x6, #0
1:  cmp   x6, x2
    b.ge  3f
    ldrb  w7, [x1, x6]
    lsl   w9, w9, w3
    orr   w9, w9, w7
    and   w9, w9, w12
    add   w10, w10, w3
2:  cmp   w10, w4
    b.lo  4f
    sub   w10, w10, w4
    lsr   w7, w9, w10
    and   w7, w7, w13
    strb  w7, [x0, x11]
    add   x11, x11, #1
    b     2b
4:  add   x6, x6, #1
    b     1b
3:  cbz   w10, 6f
    cbnz  x5, 5f
    mov   w7, #1                          /* no pad: the leftover bits must be 0 */
    lsl   w7, w7, w10
    sub   w7, w7, #1
    tst   w9, w7
    b.eq  6f
    mov   x0, #-1
    ret
5:  sub   w7, w4, w10                     /* pad the final group */
    lsl   w7, w9, w7
    and   w7, w7, w13
    strb  w7, [x0, x11]
    add   x11, x11, #1
6:  mov   x0, x11
    ret

/* bech32_encode(out=x0, hrp=x1, hrplen=x2, data5=x3, datalen=x4, spec=x5)
 * out x19, hrp x20, hrplen x21, data x22, datalen x23 */
    .p2align 2
    .globl _bech32_encode
_bech32_encode:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, x3
    mov   x23, x4
    mov   x24, x5
    mov   x0, x20
    mov   x1, x21
    mov   x2, x22
    mov   x3, x23
    mov   x4, #6
    bl    Lpolymod
    SPECXOR x24
    mov   w24, w9                         /* chk, across memcpy */
    mov   x0, x19
    mov   x1, x20
    mov   x2, x21
    bl    _memcpy
    add   x8, x19, x21
    mov   w9, #'1'
    strb  w9, [x8], #1
    adrp  x10, Lcharset@PAGE
    add   x10, x10, Lcharset@PAGEOFF
    mov   x6, #0
1:  cmp   x6, x23
    b.ge  2f
    ldrb  w9, [x22, x6]
    ldrb  w9, [x10, x9]
    strb  w9, [x8], #1
    add   x6, x6, #1
    b     1b
2:  mov   w7, #25                         /* the 6 checksum characters */
3:  lsr   w9, w24, w7
    and   w9, w9, #31
    ldrb  w9, [x10, x9]
    strb  w9, [x8], #1
    subs  w7, w7, #5
    b.pl  3b
    strb  wzr, [x8]
    add   x0, x21, x23
    add   x0, x0, #7                      /* hrplen + 1 + datalen + 6 */
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* ============================================================================
 * bech32_decode(out5=x0, out_hrp=x1, hrp_cap=x2, in=x3)
 * frame: d5 0 (96) ; out5 x19, in x20, hrplen x21, dlen x22
 * ========================================================================== */
    .p2align 2
    .globl _bech32_decode
_bech32_decode:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #96
    mov   x19, x0
    mov   x20, x3
    /* scan: length cap, case bits, last '1' */
    mov   x6, #0                          /* total */
    mov   x7, #0                          /* sep */
    mov   w8, #0                          /* casebits */
1:  ldrb  w9, [x20, x6]
    cbz   w9, 3f
    cmp   x6, #90
    b.hs  Ldec_no                         /* SER-1: the 90-character cap */
    sub   w10, w9, #'a'
    cmp   w10, #25
    b.hi  2f
    orr   w8, w8, #1
2:  sub   w10, w9, #'A'
    cmp   w10, #25
    b.hi  21f
    orr   w8, w8, #2
21: cmp   w9, #'1'
    csel  x7, x6, x7, eq
    add   x6, x6, #1
    b     1b
3:  cmp   w8, #3
    b.eq  Ldec_no                         /* SER-5: mixed case */
    cbz   x7, Ldec_no                     /* no separator / empty hrp */
    mov   x21, x7                         /* hrplen */
    cmp   x21, x2
    b.ge  Ldec_no                         /* hrplen >= hrp_cap */
    mov   x6, #0                          /* hrp: printable US-ASCII */
4:  cmp   x6, x21
    b.hs  5f
    ldrb  w9, [x20, x6]
    sub   w9, w9, #0x21
    cmp   w9, #(0x7e - 0x21)
    b.hi  Ldec_no
    add   x6, x6, #1
    b     4b
5:  mov   x6, #0                          /* out_hrp = hrp, NUL-terminated */
6:  cmp   x6, x21
    b.hs  7f
    ldrb  w9, [x20, x6]
    strb  w9, [x1, x6]
    add   x6, x6, #1
    b     6b
7:  strb  wzr, [x1, x21]
    /* data characters -> d5 */
    add   x8, x20, x21
    add   x8, x8, #1
    adrp  x10, Lchar2idx@PAGE
    add   x10, x10, Lchar2idx@PAGEOFF
    mov   x22, #0
8:  ldrb  w9, [x8], #1
    cbz   w9, 9f
    cmp   x22, #90
    b.hs  Ldec_no
    ldrb  w9, [x10, x9]
    cmp   w9, #0xff
    b.eq  Ldec_no
    strb  w9, [sp, x22]
    add   x22, x22, #1
    b     8b
9:  cmp   x22, #6
    b.lt  Ldec_no
    mov   x0, x19
    mov   x1, sp
    mov   x2, x22
    bl    _memcpy
    mov   x0, x22
    b     Ldec_ret
Ldec_no:
    mov   x0, #-1
Ldec_ret:
    add   sp, sp, #96
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

    .section __TEXT,__const
    .p2align 4
Lgen:
    .long 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
    .p2align 4
Lcharset:
    .ascii "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
Lchar2idx:  /* 0xff = not in the charset; upper case folds to lower */
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0x0f,0xff,0x0a,0x11,0x15,0x14,0x1a,0x1e,0x07,0x05,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0x1d,0xff,0x18,0x0d,0x19,0x09,0x08,0x17,0xff,0x12,0x16,0x1f,0x1b,0x13,0xff
    .byte 0x01,0x00,0x03,0x10,0x0b,0x1c,0x0c,0x0e,0x06,0x04,0x02,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0x1d,0xff,0x18,0x0d,0x19,0x09,0x08,0x17,0xff,0x12,0x16,0x1f,0x1b,0x13,0xff
    .byte 0x01,0x00,0x03,0x10,0x0b,0x1c,0x0c,0x0e,0x06,0x04,0x02,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    .byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
