/* bitcoin_mempool.S -- AArch64 port of asm/bitcoin_mempool.asm (AAPCS64).
 * txid -> serialized-tx in-memory mempool store (open addressing + backward-
 * shift deletion, no tombstones), same shape as the UTXO.
 * Exports: mpool_struct_size, mpool_init, mpool_put(1/0/2), mpool_get(ptr/0),
 *          mpool_del(1/0), mpool_count.
 * Layout: +0 n, +8 mask, +16 blob, +24 blob_cap, +32 fill, +40 slots 48B each
 *          [+0 len][+8 txid[32]][+40 blob_off]; empty marker len = -1.
 * mpool_hash is FNV-1 (mul then xor) folded to mask -> (idx*48+40).
 */
    .text

/* ---------- mpool_struct_size(slots=x0) = 40 + slots*48 + 8 ---------- */
    .global mpool_struct_size
    .type mpool_struct_size,%function
mpool_struct_size:
    mov  x1,#48
    mul  x0,x0,x1
    add  x0,x0,#48
    ret
    .size mpool_struct_size,.-mpool_struct_size

/* ---------- mpool_init(mp=x0, slots=x1, blob=x2, blob_cap=x3) ---------- */
    .global mpool_init
    .type mpool_init,%function
mpool_init:
    str  xzr,[x0,#0]            /* n = 0 */
    sub  x9,x1,#1
    str  x9,[x0,#8]             /* mask = slots-1 */
    str  x2,[x0,#16]            /* blob */
    str  x3,[x0,#24]            /* blob_cap */
    str  xzr,[x0,#32]           /* fill = 0 */
    add  x10,x0,#40             /* first slot */
    mov  x11,x1                 /* count */
    mov  x12,#-1                /* EMPTY */
.mi_e:
    cbz  x11,.mi_d
    str  x12,[x10]
    add  x10,x10,#48
    sub  x11,x11,#1
    b    .mi_e
.mi_d:
    ret
    .size mpool_init,.-mpool_init

/* ---------- mpool_hash(txid=x0, mask=x1) -> slot byte offset ---------- */
mpool_hash:
    mov  w8,#0x9dc5
    movk w8,#0x811c,lsl#16       /* FNV offset basis */
    mov  w9,#0x0193
    movk w9,#0x0100,lsl#16       /* FNV prime */
    mov  x6,#0
.mh_l:
    cmp  x6,#8
    b.hs .mh_d
    ldrb w7,[x0,x6]
    mul  w8,w8,w9                /* hash *= prime */
    eor  w8,w8,w7                /* hash ^= byte (FNV-1, bug-for-bug) */
    add  x6,x6,#1
    b    .mh_l
.mh_d:
    and  w8,w8,w1                /* fold to mask (w write zero-extends x8) */
    mov  x9,#48
    mul  x8,x8,x9
    add  x0,x8,#40
    ret

/* ---------- memcmp32(a=x0, b=x1, n=x2) -> 0 equal / 1 diff ---------- */
memcmp32:
    mov  x3,#0
.mc_c:
    cmp  x3,x2
    b.hs .mc_eq
    ldrb w4,[x0,x3]
    ldrb w5,[x1,x3]
    cmp  w4,w5
    b.ne .mc_ne
    add  x3,x3,#1
    b    .mc_c
.mc_eq:
    mov  w0,#0
    ret
.mc_ne:
    mov  w0,#1
    ret

/* ---------- mcopy(dst=x0, src=x1, n=x2) ---------- */
mcopy:
    mov  x3,#0
.mo_c:
    cmp  x3,x2
    b.hs .mo_d
    ldrb w4,[x1,x3]
    strb w4,[x0,x3]
    add  x3,x3,#1
    b    .mo_c
.mo_d:
    ret

/* ---------- mpool_put(mp=x0, txid=x1, tx=x2, txlen=x3) -> 1/0/2 ---------- */
    .global mpool_put
    .type mpool_put,%function
mpool_put:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0               /* mp */
    mov  x20,x1               /* txid */
    mov  x21,x2               /* tx */
    mov  x22,x3               /* txlen */
    mov  x0,x20
    ldr  x1,[x19,#8]
    bl   mpool_hash
    mov  x23,x0               /* slot offset */
    mov  x24,#0               /* probe count */
    mov  x25,#-1              /* EMPTY */
.mp_probe:
    ldr  x9,[x19,#8]
    add  x9,x9,#1             /* slot_count */
    cmp  x24,x9
    b.hs .mp_full
    add  x8,x19,x23           /* &slot */
    ldr  x9,[x8]
    cmp  x9,x25
    b.eq .mp_found
    mov  x0,x20
    add  x1,x8,#8
    mov  x2,#32
    bl   memcmp32
    cbz  x0,.mp_dup
    add  x23,x23,#48
    ldr  x9,[x19,#8]
    add  x9,x9,#1
    mov  x10,#48
    mul  x9,x9,x10
    add  x9,x9,#40
    cmp  x23,x9
    b.lo .mp_nowrap
    mov  x23,#40
.mp_nowrap:
    add  x24,x24,#1
    b    .mp_probe
.mp_found:
    ldr  x9,[x19,#32]         /* fill */
    ldr  x10,[x19,#24]        /* blob_cap */
    add  x11,x9,x22           /* fill+txlen */
    cmp  x11,x10
    b.hi .mp_full
    ldr  x12,[x19,#16]        /* blob */
    add  x12,x12,x9           /* blob+fill */
    mov  x0,x12
    mov  x1,x21
    mov  x2,x22
    bl   mcopy
    add  x8,x19,x23
    str  x22,[x8]             /* slot.len = txlen */
    str  x9,[x8,#40]          /* slot.blob_off = fill */
    add  x0,x8,#8
    mov  x1,x20
    mov  x2,#32
    bl   mcopy                /* slot.txid */
    ldr  x9,[x19,#32]
    add  x9,x9,x22
    str  x9,[x19,#32]         /* fill += txlen */
    ldr  x9,[x19]
    add  x9,x9,#1
    str  x9,[x19]             /* n++ */
    mov  w0,#1
    b    .mp_ret
.mp_dup:
    mov  w0,#0
    b    .mp_ret
.mp_full:
    mov  w0,#2
.mp_ret:
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size mpool_put,.-mpool_put

/* ---------- mpool_get(mp=x0, txid=x1, out_len=x2) -> ptr / 0 ---------- */
    .global mpool_get
    .type mpool_get,%function
mpool_get:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0
    mov  x20,x1
    mov  x21,x2
    mov  x0,x20
    ldr  x1,[x19,#8]
    bl   mpool_hash
    mov  x22,x0               /* slot offset */
    mov  x23,#0               /* probe */
    mov  x24,#-1              /* EMPTY */
    ldr  x25,[x19,#8]
    add  x25,x25,#1           /* slot_count */
.mg_probe:
    cmp  x23,x25
    b.hs .mg_miss
    add  x11,x19,x22
    ldr  x9,[x11]
    cmp  x9,x24
    b.eq .mg_miss
    mov  x0,x20
    add  x1,x11,#8
    mov  x2,#32
    bl   memcmp32
    cbz  x0,.mg_hit
    add  x22,x22,#48
    ldr  x9,[x19,#8]
    add  x9,x9,#1
    mov  x10,#48
    mul  x9,x9,x10
    add  x9,x9,#40
    cmp  x22,x9
    b.lo .mg_nowrap
    mov  x22,#40
.mg_nowrap:
    add  x23,x23,#1
    b    .mg_probe
.mg_hit:
    ldr  x9,[x11]             /* len */
    str  x9,[x21]
    ldr  x9,[x11,#40]         /* blob_off */
    ldr  x10,[x19,#16]        /* blob */
    add  x0,x9,x10
    b    .mg_ret
.mg_miss:
    mov  w0,#0
.mg_ret:
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size mpool_get,.-mpool_get

/* ---------- mpool_del(mp=x0, txid=x1) -> 1/0 (backward-shift deletion) ----
 * persistents: x19 mp, x20 txid, x21 slotoff, x22 probe, x23 EMPTY,
 * x24 slot_count, x25 i (gap index), x26 j (scan index). */
    .global mpool_del
    .type mpool_del,%function
mpool_del:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    stp  x27,x28,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0
    mov  x20,x1
    mov  x0,x20
    ldr  x1,[x19,#8]
    bl   mpool_hash
    mov  x21,x0               /* slot offset */
    mov  x22,#0
    mov  x23,#-1
    ldr  x24,[x19,#8]
    add  x24,x24,#1
.md_probe:
    cmp  x22,x24
    b.hs .md_miss
    add  x11,x19,x21
    ldr  x9,[x11]
    cmp  x9,x23
    b.eq .md_miss
    mov  x0,x20
    add  x1,x11,#8
    mov  x2,#32
    bl   memcmp32
    cbz  x0,.md_hit
    add  x21,x21,#48
    ldr  x9,[x19,#8]
    add  x9,x9,#1
    mov  x10,#48
    mul  x9,x9,x10
    add  x9,x9,#40
    cmp  x21,x9
    b.lo .md_nowrap
    mov  x21,#40
.md_nowrap:
    add  x22,x22,#1
    b    .md_probe
.md_hit:
    sub  x9,x21,#40
    mov  x10,#48
    udiv x25,x9,x10           /* i = gap slot index */
    str  x23,[x11]            /* slot[i].len = EMPTY (open gap) */
    ldr  x9,[x19]
    sub  x9,x9,#1
    str  x9,[x19]             /* n-- */
    mov  x26,x25              /* j := i */
.md_bs:
    add  x26,x26,#1
    ldr  x9,[x19,#8]          /* mask */
    and  x26,x26,x9           /* j = (j+1) & mask */
    mov  x9,x26
    mov  x10,#48
    mul  x9,x9,x10
    add  x9,x9,#40
    add  x13,x19,x9           /* &slot[j] */
    ldr  x10,[x13]            /* slot[j].len */
    cmp  x10,x23
    b.eq .md_done             /* genuine empty: done */
    add  x0,x13,#8            /* txid ptr of slot[j] */
    ldr  x1,[x19,#8]          /* mask */
    bl   mpool_hash           /* x0 = slot[j] home byte offset */
    sub  x9,x0,#40
    mov  x10,#48
    udiv x27,x9,x10           /* k = slot[j] home slot index */
    ldr  x10,[x19,#8]         /* mask */
    sub  x8,x25,x27
    and  x8,x8,x10            /* d_i = (i-k)&mask */
    sub  x11,x26,x27
    and  x11,x11,x10          /* d_j = (j-k)&mask */
    cmp  x8,x11
    b.hs .md_bs               /* not safe to move */
    /* pull slot[j] back to gap i */
    mov  x9,x25
    mov  x10,#48
    mul  x9,x9,x10
    add  x9,x9,#40
    add  x0,x19,x9            /* &slot[i] */
    mov  x1,x13               /* &slot[j] */
    mov  x2,#48
    bl   mcopy
    mov  x9,x26
    mov  x10,#48
    mul  x9,x9,x10
    add  x9,x9,#40
    add  x13,x19,x9           /* recompute &slot[j] (x13 clobbered) */
    str  x23,[x13]            /* slot[j].len = EMPTY */
    mov  x25,x26              /* i := j */
    b    .md_bs
.md_done:
    mov  w0,#1
    b    .md_ret
.md_miss:
    mov  w0,#0
.md_ret:
    ldp  x27,x28,[sp],#16
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size mpool_del,.-mpool_del

/* ---------- mpool_count(mp=x0) -> n ---------- */
    .global mpool_count
    .type mpool_count,%function
mpool_count:
    ldr  x0,[x0]
    ret
    .size mpool_count,.-mpool_count

    .section .note.GNU-stack,"",@progbits
