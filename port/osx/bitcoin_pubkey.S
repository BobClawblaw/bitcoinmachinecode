/* ============================================================================
 * bitcoin_pubkey.S -- secp256k1 public key parsing in AArch64 assembly
 * (Apple silicon), the counterpart of asm/bitcoin_pubkey.asm. With
 * secp256k1_schnorr.S it replaces pubkey_schnorr_twin.c on the Mac
 * (2026-09-26); the twin stays in port/osx/test_support as the oracle.
 *
 *   int  pubkey_parse(const u8* pub, unsigned long publen, u64 qx[4], u64 qy[4]);
 *   void fe_pow(u64 out[4], const u64 base[4], const u64 exp[4]);
 *
 * pubkey_parse, as libsecp256k1's parse that Core's CPubKey::Verify uses:
 *   33 bytes: 0x02/0x03 || x, x < p; y = (x^3 + 7)^((p+1)/4), checked by
 *             squaring; y := p - y when its parity differs from the prefix.
 *   65 bytes: 0x04 || x || y, or the HYBRID 0x06/0x07 whose low bit must
 *             equal y's parity (CRY-2: Core rejects hybrids only under
 *             STRICTENC, a policy flag never set for block validation, so
 *             they are consensus-valid); x, y < p and y^2 == x^3 + 7.
 *   Anything else: 0. Returns 1 with qx, qy filled (little-endian limbs).
 *
 * fe_pow: out = base^exp (mod p), square-and-multiply over bits 255..0 of the
 * little-endian exponent, as the x86 (its only caller here is the square
 * root, whose result is the unique canonical value however it is reached).
 * ========================================================================== */
    .text

/* x0 = dst limbs, x1 = 32 big-endian bytes ; leaf, clobbers x9..x12 */
    .p2align 2
    .globl _bmc_load_be32
_bmc_load_be32:
    ldp   x9, x10, [x1]                   /* bytes 0..15: limbs 3, 2 */
    ldp   x11, x12, [x1, #16]             /* bytes 16..31: limbs 1, 0 */
    rev   x9, x9
    rev   x10, x10
    rev   x11, x11
    rev   x12, x12
    stp   x12, x11, [x0]
    stp   x10, x9, [x0, #16]
    ret

/* w0 = 1 iff the 4 limbs at x0 are < p ; leaf, clobbers x9..x15 */
    .p2align 2
    .globl _bmc_lt_p
_bmc_lt_p:
    ldp   x9, x10, [x0]
    ldp   x11, x12, [x0, #16]
    adrp  x15, Lp@PAGE
    add   x15, x15, Lp@PAGEOFF
    ldp   x13, x14, [x15, #16]
    cmp   x12, x14
    b.ne  1f
    cmp   x11, x13
    b.ne  1f
    ldp   x13, x14, [x15]
    cmp   x10, x14
    b.ne  1f
    cmp   x9, x13
1:  cset  w0, lo
    ret

/* ============================================================================
 * fe_pow(out=x0, base=x1, exp=x2) ; frame: acc 0 (32)
 * ========================================================================== */
    .p2align 2
    .globl _fe_pow
_fe_pow:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #32
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x9, #1
    stp   x9, xzr, [sp]
    stp   xzr, xzr, [sp, #16]             /* acc = 1 */
    mov   x22, #255
1:  mov   x0, sp
    mov   x1, sp
    bl    _fe_sqr                         /* acc = acc^2 */
    lsr   x9, x22, #6
    ldr   x9, [x21, x9, lsl #3]
    and   x10, x22, #63
    lsr   x9, x9, x10
    tbz   x9, #0, 2f
    mov   x0, sp
    mov   x1, sp
    mov   x2, x20
    bl    _fe_mul                         /* acc *= base */
2:  subs  x22, x22, #1
    b.pl  1b
    ldp   x9, x10, [sp]
    ldp   x11, x12, [sp, #16]
    stp   x9, x10, [x19]
    stp   x11, x12, [x19, #16]
    add   sp, sp, #32
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * pubkey_parse(pub=x0, publen=x1, qx=x2, qy=x3)
 * frame: x 0, rhs 32, y 64, t 96 (128) ; pub x19, qx x20, qy x21
 * ========================================================================== */
.macro EQ32 a, b                          /* Z = (sp+a == sp+b) */
    ldp   x9, x10, [sp, #\a]
    ldp   x11, x12, [sp, #\a + 16]
    ldp   x13, x14, [sp, #\b]
    ldp   x15, x16, [sp, #\b + 16]
    eor   x9, x9, x13
    eor   x10, x10, x14
    eor   x11, x11, x15
    eor   x12, x12, x16
    orr   x9, x9, x10
    orr   x11, x11, x12
    orr   x9, x9, x11
    cmp   x9, #0
.endm
/* rhs = x^3 + 7 (t is scratch) */
.macro RHS
    mov   x0, sp
    add   x0, x0, #96
    mov   x1, sp
    bl    _fe_sqr                         /* t = x^2 */
    add   x0, sp, #32
    add   x1, sp, #96
    mov   x2, sp
    bl    _fe_mul                         /* rhs = t*x */
    add   x0, sp, #32
    add   x1, sp, #32
    adrp  x2, L7@PAGE
    add   x2, x2, L7@PAGEOFF
    bl    _fe_add                         /* rhs += 7 */
.endm

    .p2align 2
    .globl _pubkey_parse
_pubkey_parse:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #128
    mov   x19, x0
    mov   x20, x2
    mov   x21, x3
    cmp   x1, #33
    b.eq  Lpk33
    cmp   x1, #65
    b.eq  Lpk65
    b     Lpk_no

Lpk33:
    ldrb  w9, [x19]
    cmp   w9, #2
    b.eq  1f
    cmp   w9, #3
    b.ne  Lpk_no
1:  mov   x0, sp
    add   x1, x19, #1
    bl    _bmc_load_be32                  /* x */
    mov   x0, sp
    bl    _bmc_lt_p
    cbz   w0, Lpk_no
    RHS
    add   x0, sp, #64                     /* y = rhs^((p+1)/4): fe_pow_sqrt's addition
                                             chain (253 sqr + 13 mul); was fe_pow over
                                             the exponent's bits, ~500 field ops (2026-09-27) */
    add   x1, sp, #32
    bl    _fe_pow_sqrt
    add   x0, sp, #96                     /* t = y^2 */
    add   x1, sp, #64
    bl    _fe_sqr
    EQ32  96, 32
    b.ne  Lpk_no                          /* not a square: not on the curve */
    ldr   x9, [sp, #64]
    ldrb  w10, [x19]
    eor   x9, x9, x10
    tbz   x9, #0, 2f                      /* parity already matches */
    adrp  x15, Lp@PAGE                    /* y = p - y */
    add   x15, x15, Lp@PAGEOFF
    ldp   x9, x10, [x15]
    ldp   x11, x12, [x15, #16]
    ldp   x13, x14, [sp, #64]
    subs  x9, x9, x13
    sbcs  x10, x10, x14
    ldp   x13, x14, [sp, #80]
    sbcs  x11, x11, x13
    sbc   x12, x12, x14
    stp   x9, x10, [sp, #64]
    stp   x11, x12, [sp, #80]
2:  b     Lpk_out

Lpk65:
    ldrb  w9, [x19]
    cmp   w9, #4
    b.eq  3f
    cmp   w9, #6
    b.eq  1f
    cmp   w9, #7
    b.ne  Lpk_no
1:  ldrb  w10, [x19, #64]                 /* hybrid: prefix parity == y parity */
    eor   w10, w10, w9
    tbnz  w10, #0, Lpk_no
3:  mov   x0, sp
    add   x1, x19, #1
    bl    _bmc_load_be32                  /* x */
    add   x0, sp, #64
    add   x1, x19, #33
    bl    _bmc_load_be32                  /* y */
    mov   x0, sp
    bl    _bmc_lt_p
    cbz   w0, Lpk_no
    add   x0, sp, #64
    bl    _bmc_lt_p
    cbz   w0, Lpk_no
    RHS
    add   x0, sp, #96                     /* t = y^2 */
    add   x1, sp, #64
    bl    _fe_sqr
    EQ32  96, 32
    b.ne  Lpk_no

Lpk_out:
    ldp   x9, x10, [sp]
    ldp   x11, x12, [sp, #16]
    stp   x9, x10, [x20]
    stp   x11, x12, [x20, #16]
    ldp   x9, x10, [sp, #64]
    ldp   x11, x12, [sp, #80]
    stp   x9, x10, [x21]
    stp   x11, x12, [x21, #16]
    mov   w0, #1
    b     Lpk_ret
Lpk_no:
    mov   w0, #0
Lpk_ret:
    add   sp, sp, #128
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

    .section __TEXT,__const
    .p2align 4
Lp:     /* p */
    .quad 0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
L7:
    .quad 7, 0, 0, 0
