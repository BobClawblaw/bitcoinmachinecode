/* bitcoin_keys.S -- AArch64 port of asm/bitcoin_keys.asm (AAPCS64).
 *   int  scalar_small_nonzero(const u8 k[32])   -> 1 if 0<k<=n else 0 (bug-for-bug: k==n returns 1)
 *   void scalar_to_pubkey(u8 pub[33], const u8 k[32])  -> 0x02/0x03 || X
 *
 * Uses the VERIFIED fixed-base G comb point_scalar_mul_fixed (identical k*G
 * result to the x86's deferred constant-time point_scalar_mul_ct) -- CT ladder
 * is signing/perf-only, output-deterministic. fe = 4x u64 (32 B); Jacobian 96 B.
 */
    .text
    .section .rodata
    .p2align 4
N_BE:
    .byte 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
    .byte 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE
    .byte 0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B
    .byte 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
    .text

/* ---------- scalar_small_nonzero ---------- */
    .global scalar_small_nonzero
    .type scalar_small_nonzero,%function
scalar_small_nonzero:
    mov  x9,#0
    mov  x10,#0
.sz:
    cmp  x10,#32
    b.hs .sz_done
    ldrb w8,[x0,x10]
    orr  x9,x9,x8
    add  x10,x10,#1
    b    .sz
.sz_done:
    cbz  x9,.bad                  /* all zero -> 0 */
    adrp x2, N_BE
    add  x2,x2,:lo12:N_BE
    mov  x10,#0
.scmp:
    cmp  x10,#32
    b.hs .ok                      /* all equal (k==n) -> falls through = 1 (bug-for-bug) */
    ldrb w8,[x0,x10]
    ldrb w9,[x2,x10]
    cmp  w8,w9
    b.lo .ok
    b.hi .bad
    add  x10,x10,#1
    b    .scmp
.ok:
    mov  w0,#1
    ret
.bad:
    mov  w0,#0
    ret
    .size scalar_small_nonzero,.-scalar_small_nonzero

/* ---------- scalar_to_pubkey ---------- */
    .global scalar_to_pubkey
    .type scalar_to_pubkey,%function
scalar_to_pubkey:
    /* frame 0x180. saved x29/x30@0, x19@0x10. locals:
     *   limbs @0x20(32) point @0x40(96) z2 @0xA0 z3 @0xC0 inv2 @0xE0
     *   inv3 @0x100 ax @0x120 ay @0x140 xle @0x168 prefix @0x190 */
    sub  sp,sp,#0x1A0
    stp  x29,x30,[sp,#0x00]
    str  x19,[sp,#0x10]
    add  x29,sp,#0x180
    mov  x19,x0                   /* pub */

    /* ---- k (x1, 32 BE bytes) -> 4 LE limbs at sp+0x20 ---- */
    mov  x10,#0
.kl:
    cmp  x10,#4
    b.hs .kl_done
    mov  x11,#3
    sub  x11,x11,x10              /* 3-j */
    ldr  x8,[x1,x11,lsl#3]
    rev  x8,x8
    add  x14,sp,#0x20             /* limbs base */
    str  x8,[x14,x10,lsl#3]
    add  x10,x10,#1
    b    .kl
.kl_done:

    /* ---- point = k*G : point_scalar_mul_fixed(point=sp+0x40, k=sp+0x20) ---- */
    add  x0,sp,#0x40
    add  x1,sp,#0x20
    bl   point_scalar_mul_fixed

    /* ---- affinize ---- */
    /* z2 = fe_sqr(z2, point.Z);  point.Z at sp+0x40+64 = sp+0x80 */
    add  x0,sp,#0xA0
    add  x1,sp,#0x80
    bl   fe_sqr
    /* z3 = fe_mul(z3, point.Z, z2) */
    add  x0,sp,#0xC0
    add  x1,sp,#0x80
    add  x2,sp,#0xA0
    bl   fe_mul
    /* inv2 = fe_inv(inv2, z2) */
    add  x0,sp,#0xE0
    add  x1,sp,#0xA0
    bl   fe_inv
    /* inv3 = fe_inv(inv3, z3) */
    add  x0,sp,#0x100
    add  x1,sp,#0xC0
    bl   fe_inv
    /* ax = fe_mul(ax, point.X, inv2);  point.X at sp+0x40 */
    add  x0,sp,#0x120
    add  x1,sp,#0x40
    add  x2,sp,#0xE0
    bl   fe_mul
    /* ay = fe_mul(ay, point.Y, inv3);  point.Y at sp+0x40+32 = sp+0x60 */
    add  x0,sp,#0x140
    add  x1,sp,#0x60
    add  x2,sp,#0x100
    bl   fe_mul

    /* ---- prefix: 0x02 if ay even else 0x03 (ay limb0 at sp+0x140) ---- */
    ldr  x8,[sp,#0x140]
    tbnz x8,#0,.odd
    mov  w9,#0x02
    b    .pd
.odd:
    mov  w9,#0x03
.pd:
    strb w9,[sp,#0x190]

    /* ---- serialize ax (4 LE limbs at sp+0x120) -> 32 LE bytes at sp+0x168 ---- */
    add  x12,sp,#0x120
    mov  x10,#0
.ser:
    cmp  x10,#32
    b.hs .ser_done
    mov  x11,x10
    lsr  x11,x11,#3                /* limb idx */
    ldr  x8,[x12,x11,lsl#3]
    mov  x13,x10
    and  x13,x13,#7
    lsl  x13,x13,#3
    lsrv x8,x8,x13
    and  x8,x8,#0xff
    add  x14,sp,#0x168             /* xle */
    strb w8,[x14,x10]
    add  x10,x10,#1
    b    .ser
.ser_done:

    /* ---- reverse 32 bytes -> pub[1..32] (BE), pub[0]=prefix ---- */
    mov  x10,#0
.rev:
    cmp  x10,#32
    b.hs .rev_done
    add  x14,sp,#0x168             /* xle */
    ldrb w8,[x14,x10]
    mov  x11,#31
    sub  x11,x11,x10               /* 31-i */
    add  x0,x19,#1
    strb w8,[x0,x11]
    add  x10,x10,#1
    b    .rev
.rev_done:
    ldrb w8,[sp,#0x190]            /* prefix */
    strb w8,[x19]

    ldr  x19,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x1A0
    ret
    .size scalar_to_pubkey,.-scalar_to_pubkey

    .section .note.GNU-stack,"",@progbits
