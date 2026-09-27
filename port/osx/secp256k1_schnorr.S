/* ============================================================================
 * secp256k1_schnorr.S -- BIP340 Schnorr verification in AArch64 assembly
 * (Apple silicon), the counterpart of asm/secp256k1_schnorr.asm. With
 * bitcoin_pubkey.S it replaces pubkey_schnorr_twin.c on the Mac (2026-09-26).
 *
 *   int schnorr_verify(const u8 sig[64], const u8 pub_xonly[32],
 *                      const u8* msg, int msglen);                1 / 0
 *   int schnorr_x_eq_r(const u64 r[4], const u64 X[4], const u64 Z[4]);
 *
 * verify: msglen in [0, 192] (the repo's cap); P = lift_x(pk) through
 * pubkey_parse(0x02 || pk); r < p and s < n; e = H_tag(r || P.x || m) mod n
 * with H_tag = SHA256(SHA256(tag) || SHA256(tag) || .), tag
 * "BIP0340/challenge" -- SHA256(tag) is the constant below rather than
 * rehashed per call; R = s*G - e*P (GLV unless BMC_ECDSA_GLV=0); R not at
 * infinity; x(R) == r tested projectively (r*Z^2 == X); y(R) even.
 *
 * The negation of e*P tests ALL FOUR limbs of its Y, as the x86 does
 * ([EP+32] .. [EP+56]). pubkey_schnorr_twin.c tested limbs 5..7 only, so a
 * point whose Y is below 2^64 went un-negated -- ~2^-192 per signature and
 * never hit by a test, but a divergence from x86; the oracle is corrected
 * with this file.
 * ========================================================================== */
    .text

/* frame (sp-relative)
 *   keyscr 0 (48), P_aff 48 (64), rL 112, sL 144, eL 176, digest 208,
 *   buf 240 (320: th, th, r, P.x, msg <= 192), SG 560 (96), EP 656 (96),
 *   RPT 752 (96), zi 848, z3 880, yr 912    -> 944
 * sig x19, pub x20, msg x21, msglen x22 */
#define S_KEY   0
#define S_PAFF  48
#define S_RL    112
#define S_SL    144
#define S_EL    176
#define S_DIG   208
#define S_BUF   240
#define S_SG    560
#define S_EP    656
#define S_RPT   752
#define S_ZI    848
#define S_Z3    880
#define S_YR    912
#define S_SIZE  944

    .p2align 2
    .globl _schnorr_verify
_schnorr_verify:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #S_SIZE
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    sxtw  x22, w3
    tbnz  x22, #63, Lsv_no                /* msglen < 0 */
    cmp   x22, #192
    b.hi  Lsv_no                          /* msglen > 192 */

    /* P = lift_x(pk): pubkey_parse(0x02 || pk, 33) */
    mov   w9, #2
    strb  w9, [sp, #S_KEY]
    ldp   x9, x10, [x20]
    ldp   x11, x12, [x20, #16]
    add   x13, sp, #S_KEY + 1
    stp   x9, x10, [x13]                  /* unaligned store: fine on AArch64 */
    stp   x11, x12, [x13, #16]
    add   x0, sp, #S_KEY
    mov   x1, #33
    add   x2, sp, #S_PAFF
    add   x3, sp, #S_PAFF + 32
    bl    _pubkey_parse
    cbz   w0, Lsv_no

    /* r, s from the signature; r < p, s < n */
    add   x0, sp, #S_RL
    mov   x1, x19
    bl    _bmc_load_be32
    add   x0, sp, #S_SL
    add   x1, x19, #32
    bl    _bmc_load_be32
    add   x0, sp, #S_RL
    bl    _bmc_lt_p
    cbz   w0, Lsv_no
    add   x0, sp, #S_SL
    bl    Llt_n
    cbz   w0, Lsv_no

    /* buf = SHA256(tag) || SHA256(tag) || r || P.x || msg ; e = SHA256(buf) */
    adrp  x15, Ltaghash@PAGE
    add   x15, x15, Ltaghash@PAGEOFF
    ldp   x9, x10, [x15]
    ldp   x11, x12, [x15, #16]
    add   x13, sp, #S_BUF
    stp   x9, x10, [x13]
    stp   x11, x12, [x13, #16]
    stp   x9, x10, [x13, #32]
    stp   x11, x12, [x13, #48]
    ldp   x9, x10, [x19]                  /* r (big-endian, as signed) */
    ldp   x11, x12, [x19, #16]
    stp   x9, x10, [x13, #64]
    stp   x11, x12, [x13, #80]
    ldp   x9, x10, [x20]                  /* P.x (the x-only key) */
    ldp   x11, x12, [x20, #16]
    stp   x9, x10, [x13, #96]
    stp   x11, x12, [x13, #112]
    add   x0, sp, #S_BUF + 128
    mov   x1, x21
    mov   x2, x22
    bl    _memcpy                         /* msg */
    add   x0, sp, #S_DIG
    add   x1, sp, #S_BUF
    add   x2, x22, #128
    bl    _sha256_full
    add   x0, sp, #S_EL
    add   x1, sp, #S_DIG
    bl    _bmc_load_be32
    /* e mod n: one conditional subtract (e < 2^256 < 2n) */
    add   x0, sp, #S_EL
    bl    Llt_n
    cbnz  w0, 1f
    add   x13, sp, #S_EL
    adrp  x15, Lnn@PAGE
    add   x15, x15, Lnn@PAGEOFF
    ldp   x9, x10, [x13]
    ldp   x11, x12, [x15]
    subs  x9, x9, x11
    sbcs  x10, x10, x12
    stp   x9, x10, [x13]
    ldp   x9, x10, [x13, #16]
    ldp   x11, x12, [x15, #16]
    sbcs  x9, x9, x11
    sbc   x10, x10, x12
    stp   x9, x10, [x13, #16]
1:
    /* SG = s*G ; EP = e*P */
    add   x0, sp, #S_SG
    add   x1, sp, #S_SL
    bl    _point_scalar_mul_fixed
    bl    _bmc_ecdsa_glv_enabled
    add   x1, sp, #S_PAFF
    add   x2, sp, #S_EL
    cbz   w0, 2f
    add   x0, sp, #S_EP
    bl    _point_scalar_mul_glv
    b     3f
2:  add   x0, sp, #S_EP
    bl    _point_scalar_mul
3:
    /* EP.Y = p - EP.Y when any of its four limbs is set (x86: or of all four) */
    add   x13, sp, #S_EP + 32
    ldp   x9, x10, [x13]
    ldp   x11, x12, [x13, #16]
    orr   x14, x9, x10
    orr   x15, x11, x12
    orr   x14, x14, x15
    cbz   x14, 4f
    adrp  x15, Lpp@PAGE
    add   x15, x15, Lpp@PAGEOFF
    ldp   x14, x16, [x15]
    subs  x9, x14, x9
    sbcs  x10, x16, x10
    ldp   x14, x16, [x15, #16]
    sbcs  x11, x14, x11
    sbc   x12, x16, x12
    stp   x9, x10, [x13]
    stp   x11, x12, [x13, #16]
4:  add   x0, sp, #S_RPT                  /* R = sG + (-eP) */
    add   x1, sp, #S_SG
    add   x2, sp, #S_EP
    bl    _point_add
    add   x13, sp, #S_RPT + 64            /* R at infinity: invalid */
    ldp   x9, x10, [x13]
    ldp   x11, x12, [x13, #16]
    orr   x9, x9, x10
    orr   x11, x11, x12
    orr   x9, x9, x11
    cbz   x9, Lsv_no
    add   x0, sp, #S_RL                   /* x(R) == r */
    add   x1, sp, #S_RPT
    add   x2, sp, #S_RPT + 64
    bl    _schnorr_x_eq_r
    cbz   w0, Lsv_no
    /* y(R) = Y * Z^-3 must be even */
    add   x0, sp, #S_ZI
    add   x1, sp, #S_RPT + 64
    bl    _fe_inv
    add   x0, sp, #S_Z3
    add   x1, sp, #S_ZI
    bl    _fe_sqr
    add   x0, sp, #S_Z3
    add   x1, sp, #S_Z3
    add   x2, sp, #S_ZI
    bl    _fe_mul
    add   x0, sp, #S_YR
    add   x1, sp, #S_RPT + 32
    add   x2, sp, #S_Z3
    bl    _fe_mul
    ldr   x9, [sp, #S_YR]
    tbnz  x9, #0, Lsv_no
    mov   w0, #1
    b     Lsv_ret
Lsv_no:
    mov   w0, #0
Lsv_ret:
    add   sp, sp, #S_SIZE
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* w0 = 1 iff the 4 limbs at x0 are < n ; leaf */
    .p2align 2
Llt_n:
    ldp   x9, x10, [x0]
    ldp   x11, x12, [x0, #16]
    adrp  x15, Lnn@PAGE
    add   x15, x15, Lnn@PAGEOFF
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
 * schnorr_x_eq_r(r=x0, X=x1, Z=x2): r*Z^2 == X (mod p) -> 1 / 0
 * frame: t 0, lhs 32 ; r x19, X x20
 * ========================================================================== */
    .p2align 2
    .globl _schnorr_x_eq_r
_schnorr_x_eq_r:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #64
    mov   x19, x0
    mov   x20, x1
    mov   x0, sp
    mov   x1, x2
    bl    _fe_sqr                         /* t = Z^2 */
    add   x0, sp, #32
    mov   x1, x19
    mov   x2, sp
    bl    _fe_mul                         /* lhs = r*t */
    ldp   x9, x10, [sp, #32]
    ldp   x11, x12, [sp, #48]
    ldp   x13, x14, [x20]
    ldp   x15, x16, [x20, #16]
    eor   x9, x9, x13
    eor   x10, x10, x14
    eor   x11, x11, x15
    eor   x12, x12, x16
    orr   x9, x9, x10
    orr   x11, x11, x12
    orr   x9, x9, x11
    cmp   x9, #0
    cset  w0, eq
    add   sp, sp, #64
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .section __TEXT,__const
    .p2align 4
Ltaghash:   /* SHA256("BIP0340/challenge") */
    .byte 0x7b,0xb5,0x2d,0x7a,0x9f,0xef,0x58,0x32,0x3e,0xb1,0xbf,0x7a,0x40,0x7d,0xb3,0x82
    .byte 0xd2,0xf3,0xf2,0xd8,0x1b,0xb1,0x22,0x4f,0x49,0xfe,0x51,0x8f,0x6d,0x48,0xd3,0x7c
Lnn:        /* n */
    .quad 0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF
Lpp:        /* p */
    .quad 0xFFFFFFFEFFFFFC2F, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
