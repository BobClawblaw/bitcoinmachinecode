/* ============================================================================
 * secp256k1_taproot.S -- BIP341 taproot commitment/tweak layer in AArch64
 * assembly (Apple silicon), the counterpart of asm/secp256k1_taproot.asm.
 * Replaces taproot_twin.c on the Mac (2026-09-26); the twin stays in
 * port/osx/test_support as the differential oracle.
 *
 *   void tagged_hash256(u8 out[32], const char* tag, u64 taglen,
 *                       const u8* msg, u64 msglen);
 *   void tap_branch_hash(u8 out[32], const u8* a, const u8* b);
 *   long tap_leaf_hash(u8 out[32], u8 ver, const u8* script, u64 slen);
 *   long taproot_tweak_pubkey(u8 out_x[32], const u8 internal_x[32],
 *                             const u8 merkle_root[32]);      0 / 1 even / 2 odd
 *   long tap_merkle_root(u8 out[32], const u8* leaf_hashes, u64 count,
 *                        const u8* control, u64 clen);
 *
 * Rules, as the x86 module:
 *   tagged_hash256: h = SHA256(tag); out = SHA256(h || h || msg).
 *   tap_branch_hash / tap_merkle_root: TapBranch over the lexicographically
 *     sorted pair -- the first differing byte decides, all-equal puts the
 *     first operand (a / the running node) first.
 *   tap_leaf_hash: TapLeaf(ver || compactsize(slen) || script); slen above
 *     TAP_PREIMG_CAP - 70 returns 0 with out untouched.
 *   taproot_tweak_pubkey: t = TapTweak(x || [root]); rejects t >= n and
 *     x >= p; P = lift_x(x) through pubkey_parse(0x02 || x); Q = P + t*G;
 *     Q at infinity rejected; returns 1 + parity(y(Q)) with out_x = x(Q).
 *     (The x86 then negates the affine Y it is done with; nothing reads it,
 *     so that dead store is not reproduced.)
 *   tap_merkle_root: count is ignored exactly as on x86; the depth is
 *     (clen - 33) / 32 when control is non-null and clen >= 33.
 *
 * Scratch is THREAD-LOCAL, as on x86 since 2026-08-23 (tx_verify.c's worker
 * threads hash in parallel). x86 puts both buffers in .tbss; here tagh_buf
 * (32 bytes) is a Mach-O TLV of its own, and tap_preimg is a per-thread
 * POINTER to a 4 MiB buffer malloc'd on the thread's first use -- dyld
 * allocates and zeroes a TLV block eagerly for every thread that touches the
 * image's TLVs, where the ELF .tbss is demand-paged, so a 4 MiB TLV would cost
 * each thread 4 MiB of resident memory. The C twin used the same design.
 * ========================================================================== */
#define TAP_PREIMG_CAP 0x400000

    .text

/* Ltap_bufs: x0 = this thread's tap_preimg buffer (allocated on first use),
 * x1 = this thread's tagh_buf. Aborts when malloc fails, as the twin. */
    .p2align 2
Ltap_bufs:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    adrp  x0, _tap_preimg@TLVPPAGE
    ldr   x0, [x0, _tap_preimg@TLVPPAGEOFF]
    ldr   x8, [x0]
    blr   x8                              /* x0 = &tap_preimg (this thread) */
    ldr   x19, [x0]
    cbnz  x19, 1f
    str   x0, [sp, #24]
    mov   x0, #TAP_PREIMG_CAP
    bl    _malloc
    cbz   x0, Ltap_abort
    mov   x19, x0
    ldr   x1, [sp, #24]
    str   x19, [x1]
1:  adrp  x0, _tagh_buf@TLVPPAGE
    ldr   x0, [x0, _tagh_buf@TLVPPAGEOFF]
    ldr   x8, [x0]
    blr   x8                              /* x0 = tagh_buf (this thread) */
    mov   x1, x0
    mov   x0, x19
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret
Ltap_abort:
    bl    _abort

/* Lsorted_pair(msg=x0, a=x1, b=x2): msg = b||a when b < a (bytewise), else
 * a||b ; leaf, clobbers x9..x13 */
    .p2align 2
Lsorted_pair:
    mov   x13, #0
1:  ldr   x9, [x2, x13]
    ldr   x10, [x1, x13]
    rev   x9, x9
    rev   x10, x10
    cmp   x9, x10
    b.ne  2f
    add   x13, x13, #8
    cmp   x13, #32
    b.lo  1b
    b     3f                              /* equal: a first */
2:  b.lo  4f                              /* b < a: b first */
3:  ldp   x9, x10, [x1]
    ldp   x11, x12, [x1, #16]
    stp   x9, x10, [x0]
    stp   x11, x12, [x0, #16]
    ldp   x9, x10, [x2]
    ldp   x11, x12, [x2, #16]
    stp   x9, x10, [x0, #32]
    stp   x11, x12, [x0, #48]
    ret
4:  ldp   x9, x10, [x2]
    ldp   x11, x12, [x2, #16]
    stp   x9, x10, [x0]
    stp   x11, x12, [x0, #16]
    ldp   x9, x10, [x1]
    ldp   x11, x12, [x1, #16]
    stp   x9, x10, [x0, #32]
    stp   x11, x12, [x0, #48]
    ret

/* ============================================================================
 * tagged_hash256(out=x0, tag=x1, taglen=x2, msg=x3, msglen=x4)
 * out x19, tag x20, taglen x21, msg x22, msglen x23, pre x24, th x25
 * ========================================================================== */
    .p2align 2
    .globl _tagged_hash256
_tagged_hash256:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    mov   x29, sp
    str   x25, [sp, #-16]!
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, x3
    mov   x23, x4
    bl    Ltap_bufs
    mov   x24, x0
    mov   x25, x1
    mov   x0, x25                         /* th = SHA256(tag) */
    mov   x1, x20
    mov   x2, x21
    bl    _sha256_full
    ldp   x9, x10, [x25]                  /* pre = th || th || msg */
    ldp   x11, x12, [x25, #16]
    stp   x9, x10, [x24]
    stp   x11, x12, [x24, #16]
    stp   x9, x10, [x24, #32]
    stp   x11, x12, [x24, #48]
    add   x0, x24, #64                    /* memmove: tap_leaf_hash builds */
    mov   x1, x22                         /* msg in place at pre + 64 */
    mov   x2, x23
    bl    _memmove
    mov   x0, x19
    mov   x1, x24
    add   x2, x23, #64
    bl    _sha256_full
    ldr   x25, [sp], #16
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* ============================================================================
 * tap_branch_hash(out=x0, a=x1, b=x2) ; frame: msg 0 (64)
 * ========================================================================== */
    .p2align 2
    .globl _tap_branch_hash
_tap_branch_hash:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #64
    mov   x19, x0
    mov   x0, sp
    bl    Lsorted_pair
    mov   x0, x19
    adrp  x1, Ltag_branch@PAGE
    add   x1, x1, Ltag_branch@PAGEOFF
    mov   x2, #9
    mov   x3, sp
    mov   x4, #64
    bl    _tagged_hash256
    add   sp, sp, #64
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* ============================================================================
 * tap_leaf_hash(out=x0, ver=w1, script=x2, slen=x3)
 * out x19, ver -> m x20, script x21, slen x22, n x23
 * ========================================================================== */
    .p2align 2
    .globl _tap_leaf_hash
_tap_leaf_hash:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    str   x23, [sp, #48]
    mov   x29, sp
    mov   x19, x0
    and   x20, x1, #0xff
    mov   x21, x2
    mov   x22, x3
    bl    Ltap_bufs                       /* the twin allocates before the bound too */
    mov   x9, #TAP_PREIMG_CAP
    sub   x9, x9, #70
    cmp   x22, x9
    b.hi  Lleaf_no
    add   x0, x0, #64                     /* m = pre + 64 */
    strb  w20, [x0]                       /* ver */
    mov   x20, x0
    cmp   x22, #0xfd
    b.lo  1f
    cmp   x22, #0x10, lsl #12             /* 0x10000 */
    b.lo  2f
    mov   w11, #0xfe                      /* 0xfe + u32 LE (slen < 4 MiB here) */
    strb  w11, [x0, #1]
    str   w22, [x0, #2]
    mov   x23, #6                      /* n = ver + 0xfe + 4 */
    b     3f
2:  mov   w11, #0xfd                      /* 0xfd + u16 LE */
    strb  w11, [x0, #1]
    strh  w22, [x0, #2]
    mov   x23, #4
    b     3f
1:  strb  w22, [x0, #1]
    mov   x23, #2
3:  add   x0, x20, x23                    /* m + n = script */
    mov   x1, x21
    mov   x2, x22
    bl    _memcpy
    mov   x0, x19
    adrp  x1, Ltag_leaf@PAGE
    add   x1, x1, Ltag_leaf@PAGEOFF
    mov   x2, #7
    mov   x3, x20
    add   x4, x23, x22
    bl    _tagged_hash256
    mov   x0, #1
    b     Lleaf_ret
Lleaf_no:
    mov   x0, #0
Lleaf_ret:
    ldr   x23, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* ============================================================================
 * taproot_tweak_pubkey(out_x=x0, internal_x=x1, merkle_root=x2)
 * frame: msg 0 (64), digest 64, kscr 96 (48), t 144, pj 176 (96),
 *        tg 272 (96), q 368 (96), z2 464, z3 496, zi 528, xr 560 -> 592
 * out x19, ix x20, root x21
 * ========================================================================== */
#define T_MSG   0
#define T_DIG   64
#define T_KSCR  96
#define T_T     144
#define T_PJ    176
#define T_TG    272
#define T_Q     368
#define T_Z2    464
#define T_Z3    496
#define T_ZI    528
#define T_XR    560
#define T_SIZE  592

    .p2align 2
    .globl _taproot_tweak_pubkey
_taproot_tweak_pubkey:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #T_SIZE
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    /* msg = internal_x || [merkle_root] */
    ldp   x9, x10, [x20]
    ldp   x11, x12, [x20, #16]
    stp   x9, x10, [sp, #T_MSG]
    stp   x11, x12, [sp, #T_MSG + 16]
    mov   x4, #32
    cbz   x21, 1f
    ldp   x9, x10, [x21]
    ldp   x11, x12, [x21, #16]
    stp   x9, x10, [sp, #T_MSG + 32]
    stp   x11, x12, [sp, #T_MSG + 48]
    mov   x4, #64
1:  add   x0, sp, #T_DIG
    adrp  x1, Ltag_tweak@PAGE
    add   x1, x1, Ltag_tweak@PAGEOFF
    mov   x2, #8
    add   x3, sp, #T_MSG
    bl    _tagged_hash256
    add   x0, sp, #T_T                    /* t = BE digest */
    add   x1, sp, #T_DIG
    bl    _bmc_load_be32
    /* t < n, else reject */
    ldp   x9, x10, [sp, #T_T]
    ldp   x11, x12, [sp, #T_T + 16]
    adrp  x15, Ltn@PAGE
    add   x15, x15, Ltn@PAGEOFF
    ldp   x13, x14, [x15, #16]
    cmp   x12, x14
    b.ne  2f
    cmp   x11, x13
    b.ne  2f
    ldp   x13, x14, [x15]
    cmp   x10, x14
    b.ne  2f
    cmp   x9, x13
2:  b.hs  Ltw_no
    /* internal_x < p, else reject */
    add   x0, sp, #T_Z2
    mov   x1, x20
    bl    _bmc_load_be32
    add   x0, sp, #T_Z2
    bl    _bmc_lt_p
    cbz   w0, Ltw_no
    /* P = lift_x: pubkey_parse(0x02 || x) into pj (X, Y); Z = 1 */
    mov   w9, #2
    strb  w9, [sp, #T_KSCR]
    ldp   x9, x10, [x20]
    ldp   x11, x12, [x20, #16]
    add   x13, sp, #T_KSCR + 1
    stp   x9, x10, [x13]
    stp   x11, x12, [x13, #16]
    add   x0, sp, #T_KSCR
    mov   x1, #33
    add   x2, sp, #T_PJ
    add   x3, sp, #T_PJ + 32
    bl    _pubkey_parse
    cbz   w0, Ltw_no
    add   x13, sp, #T_PJ + 64
    mov   x9, #1
    stp   x9, xzr, [x13]
    stp   xzr, xzr, [x13, #16]
    /* TG = t*G ; Q = PJ + TG */
    add   x0, sp, #T_TG
    adrp  x1, Lgaff@PAGE
    add   x1, x1, Lgaff@PAGEOFF
    add   x2, sp, #T_T
    bl    _point_scalar_mul
    add   x0, sp, #T_Q
    add   x1, sp, #T_PJ
    add   x2, sp, #T_TG
    bl    _point_add
    add   x13, sp, #T_Q + 64
    ldp   x9, x10, [x13]
    ldp   x11, x12, [x13, #16]
    orr   x9, x9, x10
    orr   x11, x11, x12
    orr   x9, x9, x11
    cbz   x9, Ltw_no                      /* Q at infinity */
    /* affine, in the twin's order: z2 = Z^2, z3 = Z*z2, xr = X/z2, yr = Y/z3 */
    add   x0, sp, #T_Z2
    add   x1, sp, #T_Q + 64
    bl    _fe_sqr
    add   x0, sp, #T_Z3
    add   x1, sp, #T_Q + 64
    add   x2, sp, #T_Z2
    bl    _fe_mul
    add   x0, sp, #T_ZI
    add   x1, sp, #T_Z2
    bl    _fe_inv_var                     /* public point: safegcd */
    add   x0, sp, #T_XR
    add   x1, sp, #T_Q
    add   x2, sp, #T_ZI
    bl    _fe_mul
    add   x0, sp, #T_ZI
    add   x1, sp, #T_Z3
    bl    _fe_inv_var                     /* public point: safegcd */
    add   x0, sp, #T_Z2                   /* yr (z2 is spent) */
    add   x1, sp, #T_Q + 32
    add   x2, sp, #T_ZI
    bl    _fe_mul
    /* out_x = BE bytes of xr */
    add   x13, sp, #T_XR
    ldp   x9, x10, [x13]
    ldp   x11, x12, [x13, #16]
    rev   x9, x9
    rev   x10, x10
    rev   x11, x11
    rev   x12, x12
    stp   x12, x11, [x19]
    stp   x10, x9, [x19, #16]
    ldr   x9, [sp, #T_Z2]
    and   x0, x9, #1
    add   x0, x0, #1                      /* 1 even Y, 2 odd Y */
    b     Ltw_ret
Ltw_no:
    mov   x0, #0
Ltw_ret:
    add   sp, sp, #T_SIZE
    ldr   x21, [sp], #16
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* ============================================================================
 * tap_merkle_root(out=x0, leaf_hashes=x1, count=x2 (ignored), control=x3,
 *                 clen=x4)
 * frame: node 0 (32), msg 32 (64) -> 96 ; out x19, sibling cursor x20,
 * depth x21
 * ========================================================================== */
    .p2align 2
    .globl _tap_merkle_root
_tap_merkle_root:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #96
    mov   x19, x0
    mov   x21, #0
    cbz   x3, 1f
    cmp   x4, #33
    b.lo  1f
    sub   x21, x4, #33
    lsr   x21, x21, #5                    /* depth = (clen - 33) / 32 */
1:  add   x20, x3, #33
    ldp   x9, x10, [x1]                   /* node = leaf_hashes[0] */
    ldp   x11, x12, [x1, #16]
    stp   x9, x10, [sp]
    stp   x11, x12, [sp, #16]
    cbz   x21, 3f
2:  add   x0, sp, #32                     /* msg = sorted(node, sib) */
    mov   x1, sp
    mov   x2, x20
    bl    Lsorted_pair
    mov   x0, sp                          /* node = TapBranch(msg) */
    adrp  x1, Ltag_branch@PAGE
    add   x1, x1, Ltag_branch@PAGEOFF
    mov   x2, #9
    add   x3, sp, #32
    mov   x4, #64
    bl    _tagged_hash256
    add   x20, x20, #32
    subs  x21, x21, #1
    b.ne  2b
3:  ldp   x9, x10, [sp]
    ldp   x11, x12, [sp, #16]
    stp   x9, x10, [x19]
    stp   x11, x12, [x19, #16]
    mov   x0, #1
    add   sp, sp, #96
    ldr   x21, [sp], #16
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .section __TEXT,__const
    .p2align 4
Lgaff:      /* G, affine little-endian limbs: x, y */
    .quad 0x59F2815B16F81798, 0x029BFCDB2DCE28D9, 0x55A06295CE870B07, 0x79BE667EF9DCBBAC
    .quad 0x9C47D08FFB10D4B8, 0xFD17B448A6855419, 0x5DA4FBFC0E1108A8, 0x483ADA7726A3C465
Ltn:        /* n */
    .quad 0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF
Ltag_branch:
    .ascii "TapBranch"
Ltag_leaf:
    .ascii "TapLeaf"
Ltag_tweak:
    .ascii "TapTweak"

/* thread-local scratch (see the header) */
.tbss _tagh_buf$tlv$init, 32, 4
.tbss _tap_preimg$tlv$init, 8, 3

    .section __DATA,__thread_vars,thread_local_variables
    .p2align 3
    .globl _tagh_buf
_tagh_buf:
    .quad __tlv_bootstrap
    .quad 0
    .quad _tagh_buf$tlv$init
    .globl _tap_preimg
_tap_preimg:
    .quad __tlv_bootstrap
    .quad 0
    .quad _tap_preimg$tlv$init
