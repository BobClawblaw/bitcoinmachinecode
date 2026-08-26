/* bitcoin_muhash.S -- AArch64 port of asm/bitcoin_muhash.asm (AAPCS64).
 * MuHash3072 multiset hash, byte-for-byte compatible with Bitcoin Core's
 * MuHash3072/Num3072 (src/crypto/muhash.cpp). Modulus p = 2^3072 - 1103717.
 * Exports:
 *   void muhash_init(acc) / muhash_insert(acc,data,len) / muhash_combine(acc,other)
 *       / muhash_finalize(out32,acc) / muhash_to_num3072(out384,data,len)
 *   void num3072_mul(a,b) a=a*b mod p / num3072_set_one(a)
 *   long num3072_is_overflow(a) / num3072_full_reduce(a)
 *   void chacha20_keystream_k0(out, blocks, key32)
 * acc = 48 LE u64 limbs (384 B). AArch64 128-bit products via mul/umulh. */
#define MAX_PRIME_DIFF 1103717
#define NLIMBS 48

    .section .rodata
    .p2align 4
chacha_sigma:
    .word 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574

    .text

/* AArch64 QROUND on the 16-word state array whose base is held in xW,
 * using wA/wB as temps. rotate-left by k = ror by (32-k). */
.macro QR wbase, wa, wb, wc, wd, i0, i1, i2, i3
    ldr  \wa, [\wbase, #\i0*4]
    ldr  \wb, [\wbase, #\i1*4]
    add  \wa, \wa, \wb
    str  \wa, [\wbase, #\i0*4]
    ldr  \wc, [\wbase, #\i3*4]
    eor  \wc, \wc, \wa
    ror  \wc, \wc, #16
    str  \wc, [\wbase, #\i3*4]
    ldr  \wd, [\wbase, #\i2*4]
    add  \wd, \wd, \wc
    str  \wd, [\wbase, #\i2*4]
    ldr  \wa, [\wbase, #\i1*4]
    eor  \wa, \wa, \wd
    ror  \wa, \wa, #20
    str  \wa, [\wbase, #\i1*4]
    ldr  \wb, [\wbase, #\i0*4]
    add  \wb, \wb, \wa
    str  \wb, [\wbase, #\i0*4]
    ldr  \wc, [\wbase, #\i3*4]
    eor  \wc, \wc, \wb
    ror  \wc, \wc, #24
    str  \wc, [\wbase, #\i3*4]
    ldr  \wd, [\wbase, #\i2*4]
    add  \wd, \wd, \wc
    str  \wd, [\wbase, #\i2*4]
    ldr  \wa, [\wbase, #\i1*4]
    eor  \wa, \wa, \wd
    ror  \wa, \wa, #25
    str  \wa, [\wbase, #\i1*4]
.endm

/* ================= num3072_set_one(a=x0) ================= */
    .global num3072_set_one
    .type num3072_set_one,%function
num3072_set_one:
    mov  x9,#1
    str  x9,[x0]
    mov  x10,#1
.Lo1:
    cmp  x10,#NLIMBS
    b.hs .Lo1d
    str  xzr,[x0,x10,lsl#3]
    add  x10,x10,#1
    b    .Lo1
.Lo1d:
    ret
    .size num3072_set_one,.-num3072_set_one

/* ================= muhash_init(acc=x0) ================= */
    .global muhash_init
    .type muhash_init,%function
muhash_init:
    b    num3072_set_one
    .size muhash_init,.-muhash_init

/* ================= num3072_is_overflow(a=x0) -> 1/0 ================= */
    .global num3072_is_overflow
    .type num3072_is_overflow,%function
num3072_is_overflow:
    ldr  x9,[x0]
    mov  x10,#-1
    mov  w11,#0xD765
    movk w11,#0x0010,lsl#16
    sub  x10,x10,x11            /* x10 = MAX_LIMB - MAX_PRIME_DIFF */
    cmp  x9,x10
    b.ls .Lo_no
    mov  x12,#1
.Lo_loop:
    cmp  x12,#NLIMBS
    b.hs .Lo_yes
    ldr  x9,[x0,x12,lsl#3]
    cmp  x9,#-1
    b.ne .Lo_no
    add  x12,x12,#1
    b    .Lo_loop
.Lo_yes:
    mov  w0,#1
    ret
.Lo_no:
    mov  w0,#0
    ret
    .size num3072_is_overflow,.-num3072_is_overflow

/* ================= num3072_full_reduce(a=x0) ================= */
    .global num3072_full_reduce
    .type num3072_full_reduce,%function
num3072_full_reduce:
    mov  w8,#0xD765
    movk w8,#0x0010,lsl#16      /* c0 */
    mov  x9,#0                   /* c1 */
    mov  x10,#0                  /* i */
.Lfr:
    cmp  x10,#NLIMBS
    b.hs .Lfrd
    mov  x11,#0                  /* c2 */
    ldr  x12,[x0,x10,lsl#3]
    adds x8,x8,x12
    adcs x9,x9,xzr
    adc  x11,x11,xzr
    str  x8,[x0,x10,lsl#3]
    mov  x8,x9
    mov  x9,x11
    add  x10,x10,#1
    b    .Lfr
.Lfrd:
    ret
    .size num3072_full_reduce,.-num3072_full_reduce

/* ================= num3072_mul(a=x0, b=x1) : a = a*b mod p ================= */
    .global num3072_mul
    .type num3072_mul,%function
num3072_mul:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    stp  x27,x28,[sp,#-16]!
    sub  sp,sp,#0x1A0
    mov  x27,x0                  /* a_base */
    mov  x28,x1                  /* b_base */
    str  x27,[sp,#0x190]         /* a saved (reload before final calls) */
    str  x28,[sp,#0x198]         /* b saved */
    mov  x19,#0                  /* c0 */
    mov  x20,#0                  /* c1 */
    mov  x21,#0                  /* c2 */
    mov  x25,#0                  /* j */

.Lj_loop:
    cmp  x25,#NLIMBS-1
    b.hs .Lj_done
    /* ---- d = a[1+j]*b[47] ---- */
    ldr  x11,[x27, x25, lsl#3]   /* a[j]; a[j+1] at +8 */
    add  x9,x27,x25,lsl#3
    add  x9,x9,#8                /* &a[1+j] */
    ldr  x11,[x9]                /* a[1+j] */
    ldr  x12,[x28,#47*8]         /* b[47] */
    mul  x22,x11,x12             /* d0 */
    umulh x23,x11,x12            /* d1 */
    mov  x24,#0                  /* d2 */
    /* count = 46 - j  (a walks 2+j..47, b walks 46..1+j) */
    mov  x26,#46
    sub  x26,x26,x25
    add  x9,x9,#8                /* &a[2+j] */
    add  x10,x28,#46*8           /* &b[46] */
.Ld_loop:
    cbz  x26,.Ld_done
    ldr  x11,[x9]
    ldr  x12,[x10]
    mul  x13,x11,x12
    umulh x14,x11,x12
    adds x22,x22,x13
    adcs x23,x23,x14
    adc  x24,x24,xzr
    add  x9,x9,#8
    sub  x10,x10,#8
    sub  x26,x26,#1
    b    .Ld_loop
.Ld_done:
    /* ---- mulnadd3(c,d,n): c += n*[d0,d1,d2] ---- */
    mov  w9,#0xD765
    movk w9,#0x0010,lsl#16
    mul  x10,x22,x9
    umulh x11,x22,x9
    adds x19,x10,x19             /* c0 += d0n_low */
    adc  x10,x11,xzr             /* x10 = d0n_high + carry (the "carry" reg) */
    mul  x12,x23,x9
    umulh x11,x23,x9
    adds x12,x12,x10
    adc  x11,x11,xzr
    adds x20,x12,x20             /* c1 */
    adc  x11,x11,xzr             /* final carry */
    mul  x13,x24,x9              /* d2*n low */
    add  x21,x13,x11             /* c2 = d2n + finalcarry */
    /* ---- for i=0..j: c += a[i]*b[j-i] ---- */
    mov  x9,x27                  /* &a[0] */
    add  x10,x28,x25,lsl#3       /* &b[j] */
    mov  x26,x25
    add  x26,x26,#1              /* count = j+1 */
.Lc_loop:
    cbz  x26,.Lc_done
    ldr  x11,[x9]
    ldr  x12,[x10]
    mul  x13,x11,x12
    umulh x14,x11,x12
    adds x19,x19,x13
    adcs x20,x20,x14
    adc  x21,x21,xzr
    add  x9,x9,#8
    sub  x10,x10,#8
    sub  x26,x26,#1
    b    .Lc_loop
.Lc_done:
    /* extract3: tmp[j] = c0 ; shift c down */
    add  x9,sp,#16               /* &tmp[0] */
    str  x19,[x9,x25,lsl#3]
    mov  x19,x20
    mov  x20,x21
    mov  x21,#0
    add  x25,x25,#1
    b    .Lj_loop

.Lj_done:
    /* ---- top limb: for i=0..47 c += a[i]*b[47-i]; tmp[47]=c0 ---- */
    mov  x9,x27                  /* &a[0] */
    add  x10,x28,#47*8           /* &b[47] */
    mov  x26,#NLIMBS
.Lt_loop:
    ldr  x11,[x9]
    ldr  x12,[x10]
    mul  x13,x11,x12
    umulh x14,x11,x12
    adds x19,x19,x13
    adcs x20,x20,x14
    adc  x21,x21,xzr
    add  x9,x9,#8
    sub  x10,x10,#8
    sub  x26,x26,#1
    cbnz x26,.Lt_loop
    add  x9,sp,#16
    str  x19,[x9,#47*8]          /* tmp[47] = c0 */
    mov  x19,x20
    mov  x20,x21
    mov  x21,#0
    /* ---- second reduction: muln2(c0,c1,n) then fold tmp[] back into a[] ---- */
    mov  w9,#0xD765
    movk w9,#0x0010,lsl#16
    mul  x10,x19,x9
    umulh x11,x19,x9
    mov  x19,x10                 /* c0 = c0n_low */
    mov  x12,x11                 /* carry */
    mul  x13,x20,x9              /* c1*n low */
    add  x20,x13,x12             /* c1 = c1n_low + carry */
    add  x9,sp,#16               /* &tmp[0] */
    mov  x10,#0                  /* i */
.Lr_loop:
    cmp  x10,#NLIMBS
    b.hs .Lr_done
    mov  x11,#0                  /* c2 */
    ldr  x12,[x9,x10,lsl#3]      /* tmp[i] */
    adds x19,x19,x12
    adcs x20,x20,xzr
    adc  x11,x11,xzr
    str  x19,[x27,x10,lsl#3]     /* a[i] */
    mov  x19,x20
    mov  x20,x11
    add  x10,x10,#1
    b    .Lr_loop
.Lr_done:
    /* r14(x26) = c0 carry (0/1); fold overflow/carry */
    mov  x26,x19                 /* carry out of top limb */
    ldr  x0,[sp,#0x190]          /* a */
    bl   num3072_is_overflow
    cbz  w0,.Lno_ovf
    ldr  x0,[sp,#0x190]
    bl   num3072_full_reduce
.Lno_ovf:
    cbz  x26,.Lno_carry
    ldr  x0,[sp,#0x190]
    bl   num3072_full_reduce
.Lno_carry:
    add  sp,sp,#0x1A0
    ldp  x27,x28,[sp],#16
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size num3072_mul,.-num3072_mul

/* ================= chacha20_keystream_k0(out=x0, blocks=x1, key=x2) ================= */
    .global chacha20_keystream_k0
    .type chacha20_keystream_k0,%function
chacha20_keystream_k0:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    sub  sp,sp,#0x80
    mov  x29,sp
    mov  x19,x0                 /* out */
    mov  x20,x1                 /* blocks */
    mov  x21,x2                 /* key */
    add  x22,sp,#0x00           /* j[16] */
    /* sigma */
    adrp x9,chacha_sigma
    add  x9,x9,:lo12:chacha_sigma
    ldr  w10,[x9]
    str  w10,[x22,#0]
    ldr  w10,[x9,#4]
    str  w10,[x22,#4]
    ldr  w10,[x9,#8]
    str  w10,[x22,#8]
    ldr  w10,[x9,#12]
    str  w10,[x22,#12]
    /* key -> j[4..11] */
    mov  x11,#0
.Lks_kc:
    cmp  x11,#8
    b.hs .Lks_kcd
    ldr  w12,[x21,x11,lsl#2]
    add  x13,x22,#16
    str  w12,[x13,x11,lsl#2]
    add  x11,x11,#1
    b    .Lks_kc
.Lks_kcd:
    str  wzr,[x22,#48]          /* counter */
    str  wzr,[x22,#52]          /* nonce 0 */
    str  wzr,[x22,#56]
    str  wzr,[x22,#60]
.Lks_block:
    cbz  x20,.Lks_done
    add  x23,sp,#0x40           /* x[16] working */
    mov  x11,#0
.Lks_stc:
    cmp  x11,#16
    b.hs .Lks_stcd
    ldr  w12,[x22,x11,lsl#2]
    str  w12,[x23,x11,lsl#2]
    add  x11,x11,#1
    b    .Lks_stc
.Lks_stcd:
    mov  x24,#10                /* round counter */
.Lks_round:
    QR x23, w9,w10,w11,w13, 0,4,8,12
    QR x23, w9,w10,w11,w13, 1,5,9,13
    QR x23, w9,w10,w11,w13, 2,6,10,14
    QR x23, w9,w10,w11,w13, 3,7,11,15
    QR x23, w9,w10,w11,w13, 0,5,10,15
    QR x23, w9,w10,w11,w13, 1,6,11,12
    QR x23, w9,w10,w11,w13, 2,7,8,13
    QR x23, w9,w10,w11,w13, 3,4,9,14
    sub  x24,x24,#1
    cbnz x24,.Lks_round
    /* out[16] = x + j */
    mov  x11,#0
.Lks_ao:
    cmp  x11,#16
    b.hs .Lks_aod
    ldr  w12,[x23,x11,lsl#2]
    ldr  w13,[x22,x11,lsl#2]
    add  w12,w12,w13
    str  w12,[x19,x11,lsl#2]
    add  x11,x11,#1
    b    .Lks_ao
.Lks_aod:
    ldr  w12,[x22,#48]
    add  w12,w12,#1
    str  w12,[x22,#48]
    cbnz w12,.Lks_noc
    ldr  w12,[x22,#52]
    add  w12,w12,#1
    str  w12,[x22,#52]
.Lks_noc:
    add  x19,x19,#64
    sub  x20,x20,#1
    b    .Lks_block
.Lks_done:
    add  sp,sp,#0x80
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size chacha20_keystream_k0,.-chacha20_keystream_k0

/* ================= muhash_to_num3072(out384=x0, data=x1, len=x2) ================= */
    .global muhash_to_num3072
    .type muhash_to_num3072,%function
muhash_to_num3072:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    sub  sp,sp,#0x40
    mov  x29,sp
    mov  x19,x0                 /* out384 */
    add  x20,sp,#0x00           /* digest */
    mov  x0,x20
    mov  x1,x1                  /* data */
    mov  x2,x2                  /* len */
    bl   sha256_full
    mov  x0,x19
    mov  x1,#6                  /* 6 blocks = 384 bytes */
    mov  x2,x20
    bl   chacha20_keystream_k0
    add  sp,sp,#0x40
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size muhash_to_num3072,.-muhash_to_num3072

/* ================= muhash_insert(acc=x0, data=x1, len=x2) ================= */
    .global muhash_insert
    .type muhash_insert,%function
muhash_insert:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    sub  sp,sp,#0x190
    mov  x29,sp
    mov  x19,x0                 /* acc */
    mov  x0,sp                  /* element residue scratch */
    mov  x1,x1
    mov  x2,x2
    bl   muhash_to_num3072
    mov  x0,x19
    mov  x1,sp
    bl   num3072_mul
    add  sp,sp,#0x190
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size muhash_insert,.-muhash_insert

/* ================= muhash_combine(acc=x0, other=x1) ================= */
    .global muhash_combine
    .type muhash_combine,%function
muhash_combine:
    b    num3072_mul
    .size muhash_combine,.-muhash_combine

/* ================= muhash_finalize(out32=x0, acc=x1) ================= */
    .global muhash_finalize
    .type muhash_finalize,%function
muhash_finalize:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    sub  sp,sp,#0x400
    mov  x29,sp
    mov  x19,x0                 /* out32 */
    add  x20,sp,#0x000          /* work acc copy (384 B) */
    add  x21,sp,#0x180          /* const 1 (384 B) */
    mov  x11,#0
.Lmf_cp:
    cmp  x11,#48
    b.hs .Lmf_cpd
    ldr  x12,[x1,x11,lsl#3]
    str  x12,[x20,x11,lsl#3]
    add  x11,x11,#1
    b    .Lmf_cp
.Lmf_cpd:
    mov  x0,x21
    bl   num3072_set_one
    mov  x0,x20
    bl   num3072_is_overflow
    cbz  w0,.Lmf_np
    mov  x0,x20
    bl   num3072_full_reduce
.Lmf_np:
    mov  x0,x20
    mov  x1,x21
    bl   num3072_mul
    mov  x0,x20
    bl   num3072_is_overflow
    cbz  w0,.Lmf_npo
    mov  x0,x20
    bl   num3072_full_reduce
.Lmf_npo:
    mov  x0,x19
    mov  x1,x20
    mov  x2,#384
    bl   sha256_full
    add  sp,sp,#0x400
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size muhash_finalize,.-muhash_finalize

    .section .note.GNU-stack,"",@progbits
