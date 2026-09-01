/* secp256k1_taproot.S -- AArch64 port of asm/secp256k1_taproot.asm (AAPCS64).
 * BIP341 Taproot helpers on the verified secp256k1 point/scalar + sha256.
 *   void tagged_hash256(out32, tag, taglen, msg, msglen)
 *      out = SHA256(SHA256(tag)||SHA256(tag)||msg)
 *   i64  taproot_tweak_pubkey(out_x32, internal_x32, merkle_root) ->1/2 (parity)
 *   void tap_leaf_hash(out32, leaf_version, script, slen) -> 1/0
 *   void tap_branch_hash(out32, a32, b32)
 *   i64  tap_merkle_root(out32, leaf_hashes, count, control, clen) -> 1/0
 * Scratch tagh_buf/tap_preimg are thread-local (.tbss) via AArch64 TLS
 * Initial-Exec (gottprel + tpidr_el0), matching the x86 thread-locality. */
    .section .rodata
    .p2align 4
P_LIMBS_TR:
    .quad 0xFFFFFFFEFFFFFC2F,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF
    .p2align 4
N_LIMBS_TR:
    .quad 0xBFD25E8CD0364141,0xBAAEDCE6AF48A03B,0xFFFFFFFFFFFFFFFE,0xFFFFFFFFFFFFFFFF
    .p2align 4
TAPTWEAK_TAG:
    .asciz "TapTweak"
    .p2align 4
TAPLEAF_TAG:
    .asciz "TapLeaf"
    .p2align 4
TAPBRANCH_TAG:
    .asciz "TapBranch"
    .p2align 4
G_AFF_TR:
    .quad 0x59F2815B16F81798,0x029BFCDB2DCE28D9,0x55A06295CE870B07,0x79BE667EF9DCBBAC
    .quad 0x9C47D08FFB10D4B8,0xFD17B448A6855419,0x5DA4FBFC0E1108A8,0x483ADA7726A3C465
    .p2align 4
P_BE:
    .byte 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    .byte 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F

#define TAP_PREIMG_CAP (4*1024*1024)

    .section .tbss,"awT",@nobits
    .p2align 4
    .global tagh_buf
tagh_buf:   .space 32
    .global tap_preimg
tap_preimg: .space TAP_PREIMG_CAP

    .text

/* AArch64 TLS Initial-Exec: dst = thread address of sym.
 * dst must be x0-x17 (caller-saved); scratch likewise. */
.macro TLS_ADDR dst, sym, scratch
    adrp \dst, :gottprel:\sym
    ldr  \dst, [\dst, #:gottprel_lo12:\sym]
    mrs  \scratch, tpidr_el0
    add  \dst, \dst, \scratch
.endm

/* ================= tagged_hash256(out=x0, tag=x1, taglen=x2, msg=x3, msglen=x4) ================= */
    .global tagged_hash256
    .type tagged_hash256,%function
tagged_hash256:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    sub  sp,sp,#0x10
    mov  x29,sp
    mov  x19,x0                /* out */
    mov  x20,x1                /* tag */
    mov  x21,x2                /* taglen */
    mov  x22,x4                /* msglen */
    str  x3,[sp]               /* preserve msg across calls (x3 caller-saved) */
    /* sha256_full(tagh_buf, tag, taglen) */
    TLS_ADDR x0, tagh_buf, x9
    mov  x1,x20
    mov  x2,x21
    bl   sha256_full
    /* copy 64 bytes: tap_preimg[0..63] = taghash||taghash */
    TLS_ADDR x0, tap_preimg, x9
    TLS_ADDR x1, tagh_buf, x9
    mov  x2,#64
    bl   __cp_tw
    /* copy msg -> tap_preimg[64..] */
    TLS_ADDR x0, tap_preimg, x9
    add  x0,x0,#64
    ldr  x1,[sp]               /* msg */
    mov  x2,x22
    bl   __cp_tw
    /* sha256_full(out, tap_preimg, msglen+64) */
    mov  x0,x19
    TLS_ADDR x1, tap_preimg, x9
    add  x2,x22,#64
    bl   sha256_full
    add  sp,sp,#0x10
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size tagged_hash256,.-tagged_hash256

/* ---------- __cp_tw(dst=x0, src=x1, n=x2) ---------- */
    .type __cp_tw,%function
__cp_tw:
    mov  x3,#0
.Lcpt_l:
    cmp  x3,x2
    b.hs .Lcpt_d
    ldrb w4,[x1,x3]
    strb w4,[x0,x3]
    add  x3,x3,#1
    b    .Lcpt_l
.Lcpt_d:
    ret
    .size __cp_tw,.-__cp_tw

/* ============ tap_branch_hash(out=x0, a=x1, b=x2) ============ */
    .global tap_branch_hash
    .type tap_branch_hash,%function
tap_branch_hash:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    sub  sp,sp,#0x10
    mov  x29,sp
    mov  x19,x0                /* out */
    mov  x20,x1                /* a */
    mov  x21,x2                /* b */
    /* msg = sorted(a,b) at tap_preimg+64 */
    mov  x0,x20                 /* a */
    mov  x1,x21                 /* b */
    bl   __tb_cmp             /* x0 = 1 if b<a (b first), 0 if a<=b (a first) */
    /* __tb_cmp returns x0 = order (0 -> a first, 1 -> b first) */
    cbnz x0,.Lbr_bfirst
    /* a first */
    TLS_ADDR x0, tap_preimg, x9
    add  x0,x0,#64
    mov  x1,x20
    mov  x2,#32
    bl   __cp_tw
    TLS_ADDR x0, tap_preimg, x9
    add  x0,x0,#96
    mov  x1,x21
    mov  x2,#32
    bl   __cp_tw
    b    .Lbr_do
.Lbr_bfirst:
    TLS_ADDR x0, tap_preimg, x9
    add  x0,x0,#64
    mov  x1,x21
    mov  x2,#32
    bl   __cp_tw
    TLS_ADDR x0, tap_preimg, x9
    add  x0,x0,#96
    mov  x1,x20
    mov  x2,#32
    bl   __cp_tw
.Lbr_do:
    mov  x0,x19
    adrp x1,TAPBRANCH_TAG
    add  x1,x1,:lo12:TAPBRANCH_TAG
    mov  x2,#9                 /* "TapBranch" len */
    TLS_ADDR x9, tap_preimg, x10
    mov  x3,x9
    add  x3,x3,#64
    mov  x4,#64
    bl   tagged_hash256
    add  sp,sp,#0x10
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size tap_branch_hash,.-tap_branch_hash

/* __tb_cmp(a=x0,b=x1) -> x0 = 1 if b<a (b first), 0 if a<=b (a first)
 * Returns in x0 (standard): the x22 return of the draft made this helper an
 * unsaved callee-saved clobber for every -O2 C or asm caller. */
    .type __tb_cmp,%function
__tb_cmp:
    mov  x3,#0
    mov  x0,#0
.Ltbc:
    cmp  x3,#32
    b.hs .Ltbc_d
    ldrb w4,[x0,x3]
    ldrb w5,[x1,x3]
    cmp  w4,w5
    b.lo .Ltbc_d
    b.hi .Ltbc_b
    add  x3,x3,#1
    b    .Ltbc
.Ltbc_b:
    mov  x0,#1
.Ltbc_d:
    ret
    .size __tb_cmp,.-__tb_cmp

/* ============ tap_leaf_hash(out=x0, leaf_version=w1, script=x2, slen=x3) -> 1/0 ============ */
    .global tap_leaf_hash
    .type tap_leaf_hash,%function
tap_leaf_hash:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    sub  sp,sp,#0x10
    mov  x29,sp
    mov  x19,x0                /* out */
    mov  x20,x2                /* script */
    mov  x21,x3                /* slen */
    /* bound: TAP_PREIMG_CAP - 70 >= slen */
    mov  w9,#0xFFBA             /* 0x003FFFBA = TAP_PREIMG_CAP-70 (4194234) */
    movk w9,#0x003F,lsl#16
    cmp  x21,x9
    b.hi .Ltl_big
    /* msg@tap_preimg+64: ver || compactsize(slen) || script */
    TLS_ADDR x9, tap_preimg, x10
    add  x22,x9,#64            /* cursor */
    strb w1,[x22]
    add  x22,x22,#1
    cmp  x21,#0xfd
    b.lo .Ltl_sm
    cmp  x21,#0x10000
    b.lo .Ltl_mid
    /* 5-byte */
    mov  w9,#0xfe
    strb w9,[x22]
    add  x22,x22,#1
    str  w21,[x22]
    add  x22,x22,#4
    b    .Ltl_cp
.Ltl_mid:
    mov  w9,#0xfd
    strb w9,[x22]
    add  x22,x22,#1
    strh w21,[x22]
    add  x22,x22,#2
    b    .Ltl_cp
.Ltl_sm:
    strb w21,[x22]
    add  x22,x22,#1
.Ltl_cp:
    mov  x0,x22
    mov  x1,x20
    mov  x2,x21
    bl   __cp_tw
    add  x22,x22,x21           /* cursor += slen (script copy doesn't advance it) */
    TLS_ADDR x9, tap_preimg, x10
    sub  x9,x22,x9             /* cursor - base */
    sub  x9,x9,#64             /* msglen = ver + compactsize + slen */
    mov  x0,x19
    adrp x1,TAPLEAF_TAG
    add  x1,x1,:lo12:TAPLEAF_TAG
    mov  x2,#7                 /* "TapLeaf" len */
    TLS_ADDR x3, tap_preimg, x10
    add  x3,x3,#64
    mov  x4,x9
    bl   tagged_hash256
    mov  w0,#1
    b    .Ltl_ret
.Ltl_big:
    mov  w0,#0
.Ltl_ret:
    add  sp,sp,#0x10
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size tap_leaf_hash,.-tap_leaf_hash

/* ============ taproot_tweak_pubkey(out_x=x0, internal_x=x1, mr=x2) -> 1/2/0 ============ */
    .global taproot_tweak_pubkey
    .type taproot_tweak_pubkey,%function
taproot_tweak_pubkey:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    sub  sp,sp,#0x2B0
    mov  x29,sp
    mov  x19,x0                /* out_x */
    mov  x20,x1                /* internal_x */
    mov  x21,x2                /* merkle_root */
    /* MSG@sp+0x00 = internal_x(32) [|| merkle_root(32)] */
    mov  x0,sp
    mov  x1,x20
    mov  x2,#32
    bl   __cp_tw
    mov  x22,#32               /* msglen */
    cbz  x21,.Ltw_nomr
    add  x0,sp,#32
    mov  x1,x21
    mov  x2,#32
    bl   __cp_tw
    mov  x22,#64
.Ltw_nomr:
    /* digest@sp+0x40 = TapTweak(MSG) */
    add  x0,sp,#0x40
    adrp x1,TAPTWEAK_TAG
    add  x1,x1,:lo12:TAPTWEAK_TAG
    mov  x2,#8
    mov  x3,sp
    mov  x4,x22
    bl   tagged_hash256
    /* T@sp+0x60 limbs = bswap of digest chunks */
    ldr  x9,[sp,#0x58]
    rev  x9,x9
    str  x9,[sp,#0x60]          /* T[0] = bswap(DIGEST+24) */
    ldr  x9,[sp,#0x50]
    rev  x9,x9
    str  x9,[sp,#0x68]
    ldr  x9,[sp,#0x48]
    rev  x9,x9
    str  x9,[sp,#0x70]
    ldr  x9,[sp,#0x40]
    rev  x9,x9
    str  x9,[sp,#0x78]          /* T[3] */
    /* reject t >= n (MSB limb first) */
    adrp x10,N_LIMBS_TR
    add  x10,x10,:lo12:N_LIMBS_TR
    ldr  x9,[sp,#0x78]
    ldr  x11,[x10,#24]
    cmp  x9,x11
    b.hi .Ltw_fail
    b.lo .Ltw_nok
    ldr  x9,[sp,#0x70]
    ldr  x11,[x10,#16]
    cmp  x9,x11
    b.hi .Ltw_fail
    b.lo .Ltw_nok
    ldr  x9,[sp,#0x68]
    ldr  x11,[x10,#8]
    cmp  x9,x11
    b.hi .Ltw_fail
    b.lo .Ltw_nok
    ldr  x9,[sp,#0x60]
    ldr  x11,[x10]
    cmp  x9,x11
    b.hs .Ltw_fail
.Ltw_nok:
    /* reject internal_x >= p (BE byte compare) */
    adrp x10,P_BE
    add  x10,x10,:lo12:P_BE
    mov  x11,#0
.Ltw_xl:
    cmp  x11,#32
    b.hs .Ltw_xok
    ldrb w12,[x20,x11]
    ldrb w13,[x10,x11]
    cmp  w12,w13
    b.lo .Ltw_xok
    b.hi .Ltw_fail
    add  x11,x11,#1
    b    .Ltw_xl
.Ltw_xok:
    /* P = lift internal via pubkey_parse([0x02||internal], 33, &x,&y) */
    mov  w9,#0x02
    strb w9,[sp,#0x280]
    add  x0,sp,#0x281
    mov  x1,x20
    mov  x2,#32
    bl   __cp_tw
    add  x0,sp,#0x280
    mov  x1,#33
    add  x2,sp,#0x80           /* PAFF.x */
    add  x3,sp,#0xA0           /* PAFF.y */
    bl   pubkey_parse
    cbz  w0,.Ltw_fail
    /* PJ@sp+0xC0 = PAFF || {1,0,0,0} */
    add  x0,sp,#0xC0
    add  x1,sp,#0x80
    mov  x2,#64
    bl   __cp_tw
    mov  x9,#1
    str  x9,[sp,#0x100]         /* PJ.z = 1 */
    str  xzr,[sp,#0x108]
    str  xzr,[sp,#0x110]
    str  xzr,[sp,#0x118]
    /* TG@sp+0x120 = t * G */
    add  x0,sp,#0x120
    adrp x1,G_AFF_TR
    add  x1,x1,:lo12:G_AFF_TR
    add  x2,sp,#0x60           /* T */
    bl   point_scalar_mul
    /* Q@sp+0x180 = PJ + TG */
    add  x0,sp,#0x180
    add  x1,sp,#0xC0
    add  x2,sp,#0x120
    bl   point_add
    /* Q infinite check (Qz zero) */
    ldr  x9,[sp,#0x1C0]
    ldr  x10,[sp,#0x1C8]
    orr  x9,x9,x10
    ldr  x10,[sp,#0x1D0]
    orr  x9,x9,x10
    ldr  x10,[sp,#0x1D8]
    orr  x9,x9,x10
    cbz  x9,.Ltw_fail
    /* affine */
    add  x0,sp,#0x1E0          /* Z2 = Qz^2 */
    add  x1,sp,#0x1C0
    bl   fe_sqr
    add  x0,sp,#0x220          /* ZI = inv(Z2) */
    add  x1,sp,#0x1E0
    bl   fe_inv
    add  x0,sp,#0x240          /* XR = Qx * ZI */
    add  x1,sp,#0x180
    add  x2,sp,#0x220
    bl   fe_mul
    add  x0,sp,#0x200          /* Z3 = Z2 * Qz */
    add  x1,sp,#0x1E0
    add  x2,sp,#0x1C0
    bl   fe_mul
    add  x0,sp,#0x220          /* ZI = inv(Z3) */
    add  x1,sp,#0x200
    bl   fe_inv
    add  x0,sp,#0x260          /* YR = Qy * ZI */
    add  x1,sp,#0x1A0
    add  x2,sp,#0x220
    bl   fe_mul
    /* parity */
    ldrb w13,[sp,#0x260]
    and  w14,w13,#1
    mov  x23,#0                 /* parity 0 (even) -> ret 1 */
    cbz  w14,.Ltw_even
    mov  x23,#1                 /* odd -> negate YR, ret 2 */
    adrp x10,P_LIMBS_TR
    add  x10,x10,:lo12:P_LIMBS_TR
    ldr  x12,[x10]
    ldr  x11,[sp,#0x260]
    subs x11,x12,x11
    str  x11,[sp,#0x260]
    ldr  x12,[x10,#8]
    ldr  x11,[sp,#0x268]
    sbcs x11,x12,x11
    str  x11,[sp,#0x268]
    ldr  x12,[x10,#16]
    ldr  x11,[sp,#0x270]
    sbcs x11,x12,x11
    str  x11,[sp,#0x270]
    ldr  x12,[x10,#24]
    ldr  x11,[sp,#0x278]
    sbcs x11,x12,x11
    str  x11,[sp,#0x278]
.Ltw_even:
    /* out_x = BE bytes of XR (bswap limbs, reverse order) */
    ldr  x9,[sp,#0x258]
    rev  x9,x9
    str  x9,[x19]               /* out[0] = bswap(XR[3]) */
    ldr  x9,[sp,#0x250]
    rev  x9,x9
    str  x9,[x19,#8]
    ldr  x9,[sp,#0x248]
    rev  x9,x9
    str  x9,[x19,#16]
    ldr  x9,[sp,#0x240]
    rev  x9,x9
    str  x9,[x19,#24]
    mov  w0,#1
    add  w0,w0,w23             /* 1 even, 2 odd */
    b    .Ltw_done
.Ltw_fail:
    mov  w0,#0
.Ltw_done:
    add  sp,sp,#0x2B0
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size taproot_tweak_pubkey,.-taproot_tweak_pubkey

/* ============ tap_merkle_root(out=x0, leaf_hashes=x1, count=x2, control=x3, clen=x4) -> 1 ============ */
    .global tap_merkle_root
    .type tap_merkle_root,%function
tap_merkle_root:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0                 /* out */
    mov  x20,x1                 /* leaf_hashes */
    mov  x21,x3                 /* control */
    mov  x24,#0                 /* depth */
    cbz  x21,.Lmr_lf
    cmp  x4,#33
    b.lo .Lmr_lf
    sub  x9,x4,#33
    lsr  x24,x9,#5              /* depth */
.Lmr_lf:
    TLS_ADDR x23, tap_preimg, x9
    add  x0,x23,#192            /* node */
    mov  x1,x20                 /* leaf_hashes[0] */
    mov  x2,#32
    bl   __cp_tw
    mov  x22,#0                 /* i */
.Lmr_ml:
    cmp  x22,x24
    b.hs .Lmr_md
    mov  x9,x22
    lsl  x9,x9,#5
    add  x9,x9,#33
    add  x11,x21,x9             /* sibling ptr */
    /* lexicographic compare node(x23+192) vs sibling: x13=0 if node<=sib */
    mov  x10,#0
    mov  x13,#0
.Lmr_lc:
    cmp  x10,#32
    b.hs .Lmr_lcd
    add  x12,x23,#192
    ldrb w4,[x12,x10]
    ldrb w5,[x11,x10]
    cmp  w4,w5
    b.lo .Lmr_lcd
    b.hi .Lmr_sib
    add  x10,x10,#1
    b    .Lmr_lc
.Lmr_sib:
    mov  x13,#1
.Lmr_lcd:
    /* msg@x23+128 ; node@x23+192 ; outtemp@x23+224 */
    cbnz x13,.Lmr_bf
    /* node first: msg = node||sib */
    add  x0,x23,#128
    add  x1,x23,#192
    mov  x2,#32
    bl   __cp_tw
    add  x0,x23,#160
    mov  x1,x11
    mov  x2,#32
    bl   __cp_tw
    b    .Lmr_do
.Lmr_bf:
    /* sibling first: msg = sib||node */
    add  x0,x23,#128
    mov  x1,x11
    mov  x2,#32
    bl   __cp_tw
    add  x0,x23,#160
    add  x1,x23,#192
    mov  x2,#32
    bl   __cp_tw
.Lmr_do:
    add  x0,x23,#224
    adrp x1,TAPBRANCH_TAG
    add  x1,x1,:lo12:TAPBRANCH_TAG
    mov  x2,#9
    add  x3,x23,#128
    mov  x4,#64
    bl   tagged_hash256
    add  x0,x23,#192
    add  x1,x23,#224
    mov  x2,#32
    bl   __cp_tw
    add  x22,x22,#1
    b    .Lmr_ml
.Lmr_md:
    mov  x0,x19
    add  x1,x23,#192
    mov  x2,#32
    bl   __cp_tw
    mov  w0,#1
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size tap_merkle_root,.-tap_merkle_root


    .section .note.GNU-stack,"",@progbits
