/* ============================================================================
 * bitcoin_utxo.S -- the in-memory UTXO set in AArch64 assembly (Apple
 * silicon), the counterpart of asm/bitcoin_utxo.asm. Replaces utxo_twin.c on
 * the Mac (2026-09-26); the twin stays in port/osx/test_support as the oracle.
 *
 * Layout (the x86's): u+0 count, u+8 mask (slots - 1), u+16 blob base,
 * u+24 blob cap, u+32 blob used, u+40 slots of 48 bytes:
 *   +0 blob offset, +8 txid[32], +40 index u32 (0xFFFFFFFF = empty).
 * Blob record: value u64, height | is_coinbase << 32 (one byte), slen u64,
 * script.
 *
 *   void  utxo_init(void* u, ulong slots, void* blob, ulong cap);
 *   long  utxo_put(u, txid, index, u64 value, unsigned height,
 *                  unsigned is_coinbase, script, slen);  1 / 0 dup / 2 full
 *   long  utxo_get(u, txid, index, u64* value, ulong* height,
 *                  ulong* is_coinbase, const void** script, ulong* slen);
 *   long  utxo_del(u, txid, index);                          1 / 0
 *   long  utxo_count(u);
 *   long  utxo_walk_live(u, cb, ctx);        live slots; cb != 0 stops early
 *   ulong utxo_struct_size(ulong slots);                40 + 48*slots + 8
 *   void  utxo_prefetch_n(u, txid, index, lines);  void utxo_prefetch(...)
 *
 * The home slot: FNV-1a (32-bit) over the first 8 txid bytes, xor the full
 * index, and mask. Linear probing wraps and stops back at home. A match is
 * index (low 32 bits) and all 32 txid bytes. del is backward-shift: the hole
 * pulls in any later slot of the cluster whose probe distance lets it move
 * (distance from its home to the hole < to its own slot); blob space is not
 * reclaimed (nor on x86). The walk hands the callback a copy of the txid.
 * prefetch_n warms up to 64 consecutive 64-byte lines from the home slot
 * (prfm never faults); utxo_prefetch is 6 lines, x86's 2026-09-06 value.
 * ========================================================================== */
#define SLOT     48
#define SLOTBASE 40
#define EMPTY    0xffffffff

    .text

/* Lhome(u=x0, txid=x1, index=x2) -> x9 = home slot offset from u ; leaf,
 * x10..x13 (and reads the mask into x13) */
    .p2align 2
Lhome:
    movz  w9, #0x9dc5
    movk  w9, #0x811c, lsl #16
    movz  w10, #0x0193
    movk  w10, #0x0100, lsl #16           /* 16777619 */
    mov   x11, #0
1:  ldrb  w12, [x1, x11]
    eor   w9, w9, w12
    mul   w9, w9, w10
    add   x11, x11, #1
    cmp   x11, #8
    b.lo  1b
    ldr   x13, [x0, #8]                   /* mask */
    eor   x9, x9, x2
    and   x9, x9, x13
    mov   x10, #SLOT
    mov   x11, #SLOTBASE
    madd  x9, x9, x10, x11
    ret

/* MATCH slot: Z = (slot index == w2 and slot txid == txid at x1) ; x10..x15 */
.macro MATCH sl
    ldr   w10, [\sl, #40]
    cmp   w10, w2
    ldp   x10, x11, [\sl, #8]
    ldp   x12, x13, [x1]
    ccmp  x10, x12, #0, eq
    ccmp  x11, x13, #0, eq
    ldp   x10, x11, [\sl, #24]
    ldp   x12, x13, [x1, #16]
    ccmp  x10, x12, #0, eq
    ccmp  x11, x13, #0, eq
.endm

/* NEXT: x9 (offset) to the next slot, wrapping; x14 = end offset, x16 = home */
.macro NEXTSLOT fail
    add   x9, x9, #SLOT
    cmp   x9, x14
    mov   x10, #SLOTBASE
    csel  x9, x10, x9, hs
    cmp   x9, x16
    b.eq  \fail
.endm

/* x14 = (mask + 1) * 48 + 40 (from x13 = mask) */
.macro ENDOFF
    add   x14, x13, #1
    mov   x10, #SLOT
    mul   x14, x14, x10
    add   x14, x14, #SLOTBASE
.endm

/* utxo_init(u=x0, slots=x1, blob=x2, cap=x3) ; leaf */
    .p2align 2
    .globl _utxo_init
_utxo_init:
    sub   x9, x1, #1
    stp   xzr, x9, [x0]
    stp   x2, x3, [x0, #16]
    str   xzr, [x0, #32]
    add   x10, x0, #SLOTBASE + 40
    mov   w11, #EMPTY
    cbz   x1, 2f
1:  str   w11, [x10], #SLOT
    subs  x1, x1, #1
    b.ne  1b
2:  ret

/* ============================================================================
 * utxo_put(u=x0, txid=x1, index=x2, value=x3, height=w4, cb=w5, script=x6,
 *          slen=x7) ; u x19, value x20, hc x21, script x22, slen x23, slot x24
 * ========================================================================== */
    .p2align 2
    .globl _utxo_put
_utxo_put:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x3
    and   x21, x5, #0xff                  /* height | (is_coinbase & 0xff) << 32 */
    lsl   x21, x21, #32
    mov   w4, w4                          /* height: the u32 in w4 */
    orr   x21, x21, x4
    mov   x22, x6
    mov   x23, x7
    bl    Lhome
    ENDOFF
    mov   x16, x9
1:  add   x24, x19, x9
    ldr   w10, [x24, #40]
    cmn   w10, #1
    b.eq  2f                              /* empty: insert here */
    MATCH x24
    b.eq  Lput_dup
    NEXTSLOT Lput_full
    b     1b
2:  ldp   x9, x10, [x19, #24]             /* cap, used */
    add   x11, x23, #24                   /* record length */
    add   x12, x10, x11
    cmp   x12, x9
    b.hi  Lput_full                       /* the blob is full */
    str   x12, [sp, #-16]!                /* (new used, across memcpy) */
    str   x10, [x24]                      /* slot: blob offset, txid, index */
    ldp   x12, x13, [x1]
    stp   x12, x13, [x24, #8]
    ldp   x12, x13, [x1, #16]
    stp   x12, x13, [x24, #24]
    str   w2, [x24, #40]
    ldr   x9, [x19, #16]
    add   x0, x9, x10                     /* the record */
    stp   x20, x21, [x0]
    str   x23, [x0, #16]
    add   x0, x0, #24
    mov   x1, x22
    mov   x2, x23
    bl    _memcpy
    ldr   x12, [sp], #16
    str   x12, [x19, #32]
    ldr   x9, [x19]
    add   x9, x9, #1
    str   x9, [x19]
    mov   x0, #1
    b     Lput_ret
Lput_dup:
    mov   x0, #0
    b     Lput_ret
Lput_full:
    mov   x0, #2
Lput_ret:
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* utxo_get(u=x0, txid=x1, index=x2, value=x3, height=x4, cb=x5, script=x6,
 *          slen=x7) ; leaf apart from Lhome (x30 kept in x17) */
    .p2align 2
    .globl _utxo_get
_utxo_get:
    mov   x17, x30
    bl    Lhome
    mov   x30, x17
    ENDOFF
    mov   x16, x9
1:  add   x15, x0, x9
    ldr   w10, [x15, #40]
    cmn   w10, #1
    b.eq  Lget_miss
    MATCH x15
    b.eq  2f
    NEXTSLOT Lget_miss
    b     1b
2:  ldr   x10, [x0, #16]
    ldr   x11, [x15]
    add   x10, x10, x11                   /* the record */
    ldp   x11, x12, [x10]
    str   x11, [x3]                       /* value */
    mov   w13, w12
    str   x13, [x4]                       /* height: low 32 bits */
    ubfx  x13, x12, #32, #8
    str   x13, [x5]                       /* is_coinbase: byte 4 */
    add   x11, x10, #24
    str   x11, [x6]                       /* script */
    ldr   x11, [x10, #16]
    str   x11, [x7]                       /* slen */
    mov   x0, #1
    ret
Lget_miss:
    mov   x0, #0
    ret

/* ============================================================================
 * utxo_del(u=x0, txid=x1, index=x2)
 * u x19, mask x20, i x21, j x22, sj x23 (the rest scratch)
 * ========================================================================== */
    .p2align 2
    .globl _utxo_del
_utxo_del:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    str   x23, [sp, #-16]!
    mov   x19, x0
    bl    Lhome
    mov   x20, x13
    ENDOFF
    mov   x16, x9
1:  add   x15, x19, x9
    ldr   w10, [x15, #40]
    cmn   w10, #1
    b.eq  Ldel_miss
    MATCH x15
    b.eq  2f
    NEXTSLOT Ldel_miss
    b     1b
2:  mov   w10, #EMPTY                     /* open the gap */
    str   w10, [x15, #40]
    ldr   x10, [x19]
    sub   x10, x10, #1
    str   x10, [x19]
    sub   x21, x9, #SLOTBASE
    mov   x10, #SLOT
    udiv  x21, x21, x10                   /* i = the gap's slot */
    mov   x22, x21                        /* j */
3:  add   x22, x22, #1
    and   x22, x22, x20
    mov   x10, #SLOT
    mov   x11, #SLOTBASE
    madd  x23, x22, x10, x11
    add   x23, x19, x23                   /* sj */
    ldr   w2, [x23, #40]
    cmn   w2, #1
    b.eq  Ldel_done                       /* the hole has propagated */
    mov   x0, x19
    add   x1, x23, #8
    bl    Lhome                           /* k = sj's home slot */
    sub   x9, x9, #SLOTBASE
    mov   x10, #SLOT
    udiv  x9, x9, x10
    sub   x10, x21, x9
    and   x10, x10, x20                   /* di = (i - k) & mask */
    sub   x11, x22, x9
    and   x11, x11, x20                   /* dj = (j - k) & mask */
    cmp   x10, x11
    b.hs  3b                              /* not safe to move */
    mov   x10, #SLOT
    mov   x11, #SLOTBASE
    madd  x12, x21, x10, x11
    add   x12, x19, x12                   /* si = sj; sj emptied; i = j */
    ldp   x10, x11, [x23]
    stp   x10, x11, [x12]
    ldp   x10, x11, [x23, #16]
    stp   x10, x11, [x12, #16]
    ldp   x10, x11, [x23, #32]
    stp   x10, x11, [x12, #32]
    mov   w10, #EMPTY
    str   w10, [x23, #40]
    mov   x21, x22
    b     3b
Ldel_done:
    mov   x0, #1
    b     Ldel_ret
Ldel_miss:
    mov   x0, #0
Ldel_ret:
    ldr   x23, [sp], #16
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

    .p2align 2
    .globl _utxo_count
_utxo_count:
    ldr   x0, [x0]
    ret

/* ============================================================================
 * utxo_walk_live(u=x0, cb=x1, ctx=x2)
 * u x19, cb x20, ctx x21, slot ptr x22, slots left x23, emitted x24,
 * blob x25 ; frame: txid copy 0 (32)
 * ========================================================================== */
    .p2align 2
    .globl _utxo_walk_live
_utxo_walk_live:
    stp   x29, x30, [sp, #-80]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    str   x25, [sp, #64]
    mov   x29, sp
    sub   sp, sp, #32
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    ldr   x23, [x19, #8]
    add   x23, x23, #1                    /* slots */
    ldr   x25, [x19, #16]
    add   x22, x19, #SLOTBASE
    mov   x24, #0
1:  cbz   x23, 3f
    ldr   w9, [x22, #40]
    cmn   w9, #1
    b.eq  2f
    add   x24, x24, #1
    cbz   x20, 2f                         /* no callback: count only */
    ldp   x10, x11, [x22, #8]             /* the txid, copied */
    stp   x10, x11, [sp]
    ldp   x10, x11, [x22, #24]
    stp   x10, x11, [sp, #16]
    ldr   x10, [x22]
    add   x10, x25, x10                   /* the record */
    mov   x0, x21
    mov   x1, sp
    mov   w2, w9                          /* index */
    ldp   x3, x12, [x10]                  /* value, height | cb << 32 */
    mov   w4, w12
    ubfx  x5, x12, #32, #8
    add   x6, x10, #24
    ldr   x7, [x10, #16]
    blr   x20
    cbnz  w0, 3f                          /* the callback stops the walk */
2:  add   x22, x22, #SLOT
    sub   x23, x23, #1
    b     1b
3:  mov   x0, x24
    add   sp, sp, #32
    ldr   x25, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

/* utxo_struct_size(slots=x0) ; leaf */
    .p2align 2
    .globl _utxo_struct_size
_utxo_struct_size:
    mov   x9, #SLOT
    mov   x10, #48                        /* 40 + 8 */
    madd  x0, x0, x9, x10
    ret

/* utxo_prefetch_n(u=x0, txid=x1, index=x2, lines=x3) ; leaf apart from Lhome */
    .p2align 2
    .globl _utxo_prefetch_n
_utxo_prefetch_n:
    mov   x17, x30
    bl    Lhome
    mov   x30, x17
    add   x9, x0, x9
    cmp   x3, #64
    mov   x10, #64
    csel  x3, x10, x3, hi
    cbz   x3, 2f
1:  prfm  pldl1keep, [x9]
    add   x9, x9, #64
    subs  x3, x3, #1
    b.ne  1b
2:  ret

    .p2align 2
    .globl _utxo_prefetch
_utxo_prefetch:
    mov   x3, #6                          /* UTXO_PREFETCH_LINES */
    b     _utxo_prefetch_n
