/* bitcoin_utxo_stats.S -- AArch64 port of asm/bitcoin_utxo_stats.asm (AAPCS64).
 * Per-coin half of gettxoutsetinfo: Core's IsUnspendable filter, Core's
 * coin serialization, and running totals (txouts/amount/bogosize/muhash).
 *
 * Exports:
 *   void utxo_stats_init(st, want_muhash, exclude_genesis_coinbase)
 *   void utxo_stats_add(st, key36[36], value, code, script, slen)
 *   void utxo_stats_finalize(st)
 *   long utxo_script_unspendable(script, slen)
 *
 * st layout (496B): txouts0 amount8 bogosize16 unsp_n24 unsp_amt32 raw_n40
 *   zero_h48 want_muhash56 muhash64(32B) acc96(384B) excl_genesis480 genesis_n488.
 * code = (height << 1) | is_coinbase. muhash_init/insert/finalize are
 * bitcoin_muhash.S exports (unported); the muhash accumulation path verifies
 * once that module lands. */
    .section .rodata
    .p2align 4
genesis_coinbase_key:
    .byte 0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61
    .byte 0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a
    .word 0

    .text

/* ========= utxo_script_unspendable(script=x0, slen=x1) -> 1/0 ========= */
    .global utxo_script_unspendable
    .type utxo_script_unspendable,%function
utxo_script_unspendable:
    mov  x14,#10000
    cmp  x1,x14
    b.hi .us_yes
    cbz  x1,.us_no
    ldrb w9,[x0]
    cmp  w9,#0x6a
    b.eq .us_yes
.us_no:
    mov  w0,#0
    ret
.us_yes:
    mov  w0,#1
    ret
    .size utxo_script_unspendable,.-utxo_script_unspendable

/* ========= utxo_stats_init(st=x0, want_muhash=x1, excl=x2) ========= */
    .global utxo_stats_init
    .type utxo_stats_init,%function
utxo_stats_init:
    stp  x29,x30,[sp,#-16]!
    mov  x9,x0
    str  xzr,[x9,#0]            /* txouts */
    str  xzr,[x9,#8]            /* amount */
    str  xzr,[x9,#16]           /* bogosize */
    str  xzr,[x9,#24]           /* unsp_n */
    str  xzr,[x9,#32]           /* unsp_amt */
    str  xzr,[x9,#40]           /* raw_n */
    str  xzr,[x9,#48]           /* zero_h */
    str  x1,[x9,#56]            /* want_muhash */
    str  x2,[x9,#480]           /* excl_genesis */
    str  xzr,[x9,#488]          /* genesis_n */
    add  x10,x9,#64             /* muhash out (zero it) */
    stp  xzr,xzr,[x10]
    stp  xzr,xzr,[x10,#16]
    add  x0,x9,#96              /* acc */
    bl   muhash_init
    ldp  x29,x30,[sp],#16
    ret
    .size utxo_stats_init,.-utxo_stats_init

/* ========= utxo_stats_add(st=x0, key=x1, value=x2, code=x3, script=x4, slen=x5) ========= */
    .global utxo_stats_add
    .type utxo_stats_add,%function
utxo_stats_add:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    mov  x14,#0x2810
    sub  sp,sp,x14              /* serialization buffer base */
    mov  x29,sp
    mov  x19,x0                 /* st */
    mov  x20,x1                 /* key */
    mov  x21,x2                 /* value */
    mov  x22,x3                 /* code */
    mov  x23,x4                 /* script */
    mov  x24,x5                 /* slen */
    ldr  x9,[x19,#40]           /* raw_n++ */
    add  x9,x9,#1
    str  x9,[x19,#40]
    cmp  x22,#2
    b.hs .ua_hok
    ldr  x9,[x19,#48]           /* zero_h++ (height==0 <=> code<2) */
    add  x9,x9,#1
    str  x9,[x19,#48]
.ua_hok:
    ldr  x9,[x19,#480]          /* excl_genesis? */
    cbz  x9,.ua_not_genesis
    adrp x10,genesis_coinbase_key
    add  x10,x10,:lo12:genesis_coinbase_key
    mov  x11,#0
.ua_gcmp:
    cmp  x11,#36
    b.hs .ua_gmatch
    ldrb w12,[x20,x11]
    ldrb w13,[x10,x11]
    cmp  w12,w13
    b.ne .ua_not_genesis
    add  x11,x11,#1
    b    .ua_gcmp
.ua_gmatch:
    ldr  x9,[x19,#488]
    add  x9,x9,#1
    str  x9,[x19,#488]
    b    .ua_done
.ua_not_genesis:
    mov  x0,x23
    mov  x1,x24
    bl   utxo_script_unspendable
    cbz  w0,.ua_spendable
    ldr  x9,[x19,#24]           /* unsp_n++ */
    add  x9,x9,#1
    str  x9,[x19,#24]
    ldr  x9,[x19,#32]           /* unsp_amt += value */
    add  x9,x9,x21
    str  x9,[x19,#32]
    b    .ua_done
.ua_spendable:
    ldr  x9,[x19]               /* txouts++ */
    add  x9,x9,#1
    str  x9,[x19]
    ldr  x9,[x19,#8]            /* amount += value */
    add  x9,x9,x21
    str  x9,[x19,#8]
    add  x9,x24,#50             /* bogosize += slen+50 */
    ldr  x10,[x19,#16]
    add  x10,x10,x9
    str  x10,[x19,#16]
    ldr  x9,[x19,#56]           /* want_muhash? */
    cbz  x9,.ua_done
    /* build Core TxOutSer image at [sp] */
    mov  x9,#0
.ua_kcpy:
    cmp  x9,#36
    b.hs .ua_kcd
    ldrb w10,[x20,x9]
    strb w10,[sp,x9]
    add  x9,x9,#1
    b    .ua_kcpy
.ua_kcd:
    str  w22,[sp,#36]           /* (height<<1)|coinbase as uint32 LE */
    str  x21,[sp,#40]           /* nValue int64 LE */
    add  x8,sp,#48              /* CompactSize(slen) */
    cmp  x24,#0xfd
    b.hs .ua_cs3
    strb w24,[x8]
    add  x8,x8,#1
    b    .ua_csd
.ua_cs3:
    mov  w9,#0xfd
    strb w9,[x8]
    and  w9,w24,#0xff
    strb w9,[x8,#1]
    lsr  w9,w24,#8
    strb w9,[x8,#2]
    add  x8,x8,#3
.ua_csd:
    mov  x9,#0
.ua_scp:
    cmp  x9,x24
    b.hs .ua_scpd
    ldrb w10,[x23,x9]
    strb w10,[x8,x9]
    add  x9,x9,#1
    b    .ua_scp
.ua_scpd:
    add  x8,x8,x24              /* one past end */
    mov  x14,sp
    sub  x12,x8,x14             /* total length */
    mov  x0,x19
    add  x0,x0,#96              /* acc */
    mov  x1,sp
    mov  x2,x12
    bl   muhash_insert
.ua_done:
    mov  x14,#0x2810
    add  sp,sp,x14
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size utxo_stats_add,.-utxo_stats_add

/* ========= utxo_stats_finalize(st=x0) ========= */
    .global utxo_stats_finalize
    .type utxo_stats_finalize,%function
utxo_stats_finalize:
    stp  x29,x30,[sp,#-16]!
    ldr  x9,[x0,#56]
    cbz  x9,.uf_skip
    add  x1,x0,#96              /* acc */
    add  x0,x0,#64              /* out */
    bl   muhash_finalize
.uf_skip:
    ldp  x29,x30,[sp],#16
    ret
    .size utxo_stats_finalize,.-utxo_stats_finalize

    .section .note.GNU-stack,"",@progbits
