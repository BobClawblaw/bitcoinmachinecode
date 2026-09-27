/* ============================================================================
 * bitcoin_utxo_stats.S -- the UTXO-set statistics layer (gettxoutsetinfo) in
 * AArch64 assembly (Apple silicon), the counterpart of
 * asm/bitcoin_utxo_stats.asm. Replaces utxo_stats_twin.c on the Mac
 * (2026-09-26); the twin stays in port/osx/test_support as the oracle.
 *
 *   long utxo_script_unspendable(const u8* script, ulong slen);
 *   void utxo_stats_init(u8* st, u64 want_muhash, u64 excl_genesis);
 *   void utxo_stats_add(u8* st, const u8 key36[36], u64 value, u64 code,
 *                       const u8* script, ulong slen);
 *   void utxo_stats_finalize(u8* st);
 *
 * struct (offsets as the x86's and utxo_setinfo.c's utxo_stats_t): 0 txouts,
 * 8 amount, 16 bogosize, 24 unspendable n, 32 unspendable amount, 40 raw n,
 * 48 zero-height n, 56 want_muhash, 64 muhash digest (32), 96 accumulator
 * (num3072, 384), 480 excl_genesis, 488 genesis n -> 496 bytes.
 *
 * add: raw n += 1; code < 2 counts zero-height; the mainnet genesis coinbase
 * outpoint is set aside when excl_genesis; unspendable (> 10000 bytes or
 * OP_RETURN-led) is counted apart; else txouts/amount/bogosize (slen + 50)
 * and, when wanted, MuHash insert of txid || vout || code32 || value ||
 * compactsize(slen) || script, as Core's TxOutSer.
 *
 * init writes each field by name (the caller's struct is 496 bytes) and sets
 * the accumulator to 1 (the empty set).
 *
 * The insert buffer (up to 32+4+4+8+3+10000 bytes) lives on the stack; the
 * frame is taken in 4 KiB steps, each touched, so it cannot step over a
 * thread's guard page.
 * ========================================================================== */
#define ST_WANT   56
#define ST_MUHASH 64
#define ST_ACC    96
#define ST_EXCL   480
#define ST_GEN_N  488
#define MAXSCRIPT 10000
#define BUFSZ     10064                   /* 10051 rounded up to 16 */

    .text

/* utxo_script_unspendable(script=x0, slen=x1) ; leaf */
    .p2align 2
    .globl _utxo_script_unspendable
_utxo_script_unspendable:
    mov   x9, #MAXSCRIPT
    cmp   x1, x9
    b.hi  1f
    cbz   x1, 2f
    ldrb  w9, [x0]
    cmp   w9, #0x6a                       /* OP_RETURN */
    cset  x0, eq
    ret
1:  mov   x0, #1
    ret
2:  mov   x0, #0
    ret

/* utxo_stats_init(st=x0, want=x1, excl=x2) */
    .p2align 2
    .globl _utxo_stats_init
_utxo_stats_init:
    stp   xzr, xzr, [x0]                  /* the seven counters */
    stp   xzr, xzr, [x0, #16]
    stp   xzr, xzr, [x0, #32]
    stp   xzr, x1, [x0, #48]              /* zero-height n, want_muhash */
    stp   xzr, xzr, [x0, #ST_MUHASH]
    stp   xzr, xzr, [x0, #ST_MUHASH + 16]
    add   x9, x0, #ST_EXCL
    stp   x2, xzr, [x9]                   /* excl_genesis, genesis n */
    add   x0, x0, #ST_ACC
    b     _muhash_init                    /* accumulator = 1 */

/* ============================================================================
 * utxo_stats_add(st=x0, key=x1, value=x2, code=x3, script=x4, slen=x5)
 * st x19, key x20, value x21, code x22, script x23, slen x24
 * ========================================================================== */
    .p2align 2
    .globl _utxo_stats_add
_utxo_stats_add:
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
    ldp   x9, x10, [x19, #40]             /* raw n, zero-height n */
    add   x9, x9, #1
    cmp   x22, #2
    cinc  x10, x10, lo
    stp   x9, x10, [x19, #40]
    ldr   x9, [x19, #ST_EXCL]
    cbz   x9, 1f
    adrp  x9, Lgenesis_key@PAGE           /* the genesis coinbase outpoint? */
    add   x9, x9, Lgenesis_key@PAGEOFF
    ldp   x10, x11, [x20]
    ldp   x12, x13, [x9]
    cmp   x10, x12
    ccmp  x11, x13, #0, eq
    ldp   x10, x11, [x20, #16]
    ldp   x12, x13, [x9, #16]
    ccmp  x10, x12, #0, eq
    ccmp  x11, x13, #0, eq
    ldr   w10, [x20, #32]
    ldr   w12, [x9, #32]
    ccmp  w10, w12, #0, eq
    b.ne  1f
    ldr   x9, [x19, #ST_GEN_N]
    add   x9, x9, #1
    str   x9, [x19, #ST_GEN_N]
    b     Lsa_ret
1:  mov   x0, x23
    mov   x1, x24
    bl    _utxo_script_unspendable
    cbz   x0, 2f
    ldp   x9, x10, [x19, #24]             /* unspendable n, amount */
    add   x9, x9, #1
    add   x10, x10, x21
    stp   x9, x10, [x19, #24]
    b     Lsa_ret
2:  ldp   x9, x10, [x19]                  /* txouts, amount */
    add   x9, x9, #1
    add   x10, x10, x21
    stp   x9, x10, [x19]
    ldr   x9, [x19, #16]                  /* bogosize += slen + 50 */
    add   x9, x9, x24
    add   x9, x9, #50
    str   x9, [x19, #16]
    ldr   x9, [x19, #ST_WANT]
    cbz   x9, Lsa_ret
    /* the insert buffer: BUFSZ bytes, taken 4 KiB at a time, each touched */
    mov   x9, #BUFSZ
3:  cmp   x9, #4096
    b.ls  4f
    sub   sp, sp, #4096
    str   xzr, [sp]
    sub   x9, x9, #4096
    b     3b
4:  sub   sp, sp, x9
    str   xzr, [sp]
    ldp   x9, x10, [x20]                  /* txid (wire order) || vout */
    ldp   x11, x12, [x20, #16]
    stp   x9, x10, [sp]
    stp   x11, x12, [sp, #16]
    ldr   w9, [x20, #32]
    str   w9, [sp, #32]
    str   w22, [sp, #36]                  /* code32 */
    stur  x21, [sp, #40]                  /* value */
    add   x0, sp, #48
    cmp   x24, #0xfd
    b.hs  5f
    strb  w24, [x0], #1
    b     6f
5:  mov   w9, #0xfd
    strb  w9, [x0]
    sturh w24, [x0, #1]
    add   x0, x0, #3
6:  mov   x1, x23
    mov   x2, x24
    add   x24, x0, x24                    /* end of the serialization */
    bl    _memcpy
    add   x0, x19, #ST_ACC
    mov   x1, sp
    sub   x2, x24, x1
    bl    _muhash_insert
    mov   sp, x29                         /* drop the buffer */
Lsa_ret:
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* utxo_stats_finalize(st=x0) */
    .p2align 2
    .globl _utxo_stats_finalize
_utxo_stats_finalize:
    ldr   x9, [x0, #ST_WANT]
    cbz   x9, 1f
    add   x1, x0, #ST_ACC
    add   x0, x0, #ST_MUHASH
    b     _muhash_finalize
1:  ret

    .section __TEXT,__const
    .p2align 3
Lgenesis_key:   /* the mainnet genesis coinbase outpoint, wire order */
    .byte 0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61
    .byte 0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a
    .byte 0x00,0x00,0x00,0x00
