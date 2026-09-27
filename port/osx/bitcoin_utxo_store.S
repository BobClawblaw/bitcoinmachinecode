/* ============================================================================
 * bitcoin_utxo_store.S -- the persistent UTXO store (WAL + checkpoint) in
 * AArch64 assembly (Apple silicon), the counterpart of
 * asm/bitcoin_utxo_store.asm. Replaces utxo_store_twin.c on the Mac
 * (2026-09-26); the twin stays in port/osx/test_support as the oracle.
 *
 * Files (cwd):
 *   utxo.dat     append-only WAL. PUSH: magic "UTXO" u32, op 1, 3 pad,
 *                txid[32], index u32, value u64, height u32, is_coinbase u8,
 *                slen u16, script (59 + slen). DEL: magic, op 2, 3 pad,
 *                txid[32], index u32 (44).
 *   utxo.idx     checkpoint: magic "UTXI" u32, log_off u64, n u64, then n
 *                records txid[32] index u32 value u64 height u32 cb u8
 *                slen u16 script; published by utxo.idx.tmp + rename.
 * State (caller-zeroed): +0 log fd, +8 idx fd, +16 log_len (LOGICAL: file +
 * buffered WAL bytes), +24 checkpoint log offset, +32 checkpoint n.
 *
 *   long utxo_store_init(void* st);  long utxo_store_init_ro(void* st);
 *   long utxo_store_put(st, u, txid, u32 index, u64 value, u32 height,
 *                       u32 is_coinbase, script, u32 slen);  utxo_put's / -1
 *   long utxo_store_del(st, u, txid, u32 index);             utxo_del's / -1
 *   long utxo_store_count(st, u);
 *   long utxo_store_get(st, u, txid, u32 index, u64* value, ulong* height,
 *                       ulong* is_coinbase, const void** script, ulong* slen);
 *   void utxo_store_clear(void* u);
 *   long utxo_store_sync(st, u);           1 / -1
 *   long utxo_store_reload(st, u);         records replayed / -1 / -2 (full)
 *   long utxo_store_wal_drain(st);         0 / -1
 *   void utxo_store_close(st);
 *
 * One 1 MiB process-wide WAL buffer shared by every store and keyed by fd,
 * as the x86 .bss: appends buffer (log_len advances at once), and the
 * buffer drains on sync / reload / close / wal_drain, when another store
 * appends, and on overflow; a record larger than the buffer goes straight
 * to the file. A short write leaves the unwritten tail at the buffer's
 * front. put / del write the WAL record first, then apply to the in-memory
 * table (bitcoin_utxo.S).
 *
 * reload: drain; clear the table; log_len = the file size; load the
 * checkpoint (when utxo.idx has the magic) through utxo_put; replay the WAL
 * from the checkpoint offset; a memtable-full put -> -2. UTX-4: only a TORN
 * exit (short read, bad magic, unknown op) sets log_len to the start of the
 * failing record and truncates the file there (best effort); a clean end
 * truncates nothing.
 *
 * sync writes each checkpoint record as its 51-byte header then its script
 * (the twin wrote field by field; the bytes are the same, and any failed
 * write unlinks the tmp either way). reload's script buffer (64 KiB) is taken
 * from the stack in touched 4 KiB steps. open() is variadic: its mode goes on
 * the stack (Darwin arm64).
 * ========================================================================== */
#define MAGIC_LOG  0x5554584F
#define MAGIC_IDX  0x55545849
#define CKPT_REC   51
#define PUSH_HDR   59
#define DEL_SIZE   44
#define IDX_HDR    20
#define WALCAP     1048576
#define O_RDONLY   0x0000
#define O_WRONLY   0x0001
#define O_RDWR     0x0002
#define O_CREAT    0x0200
#define O_TRUNC    0x0400

    .text

/* x = &Lwal (fill at +0, fd at +8) */
.macro WALADDR r
    adrp  \r, Lwal@PAGE
    add   \r, \r, Lwal@PAGEOFF
.endm
.macro WALBUF r
    adrp  \r, Lwal_buf@PAGE
    add   \r, \r, Lwal_buf@PAGEOFF
.endm
.macro MOVW r, imm
    movz  \r, #((\imm) & 0xffff)
    movk  \r, #((\imm) >> 16), lsl #16
.endm

/* Lopen3(path=x0, flags=w1): open(path, flags, 0644) ; the mode on the stack */
    .p2align 2
Lopen3:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #16
    mov   x9, #0644
    str   x9, [sp]
    bl    _open
    add   sp, sp, #16
    ldp   x29, x30, [sp], #16
    ret

/* Lwrite_all(fd=w0, p=x1, n=x2) -> x0 0 / -1 ; fd x19, p x20, n x21 */
    .p2align 2
Lwrite_all:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    mov   w19, w0
    mov   x20, x1
    mov   x21, x2
1:  cbz   x21, 2f
    mov   w0, w19
    mov   x1, x20
    mov   x2, x21
    bl    _write
    cmp   x0, #0
    b.le  3f
    add   x20, x20, x0
    sub   x21, x21, x0
    b     1b
2:  mov   x0, #0
    b     4f
3:  mov   x0, #-1
4:  ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* Lwal_drain_fd(fd=x0) -> x0 0 / -1: write the whole buffer; on a short
 * write the unwritten tail moves to the front. fd x19, p x20, remain x21 */
    .p2align 2
Lwal_drain_fd:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    WALBUF x20
    WALADDR x9
    ldr   x21, [x9]
1:  cbz   x21, 2f
    mov   w0, w19
    mov   x1, x20
    mov   x2, x21
    bl    _write
    cmp   x0, #0
    b.le  3f
    add   x20, x20, x0
    sub   x21, x21, x0
    b     1b
2:  WALADDR x9
    str   xzr, [x9]
    mov   x0, #0
    b     4f
3:  WALBUF x0                             /* keep the tail */
    mov   x1, x20
    mov   x2, x21
    bl    _memmove
    WALADDR x9
    str   x21, [x9]
    mov   x0, #-1
4:  ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* utxo_store_wal_drain(st) */
    .p2align 2
    .globl _utxo_store_wal_drain
_utxo_store_wal_drain:
    WALADDR x9
    ldp   x10, x0, [x9]                   /* fill, fd */
    cbz   x10, 1f
    b     Lwal_drain_fd
1:  mov   x0, #0
    ret

/* Lwr_log(st=x0, buf=x1, len=x2) -> x0 0 / -1 ; st x19, buf x20, len x21,
 * log fd x22 */
    .p2align 2
Lwr_log:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    ldr   x22, [x19]
    WALADDR x9
    ldp   x10, x11, [x9]                  /* fill, owner fd */
    cbz   x10, 1f
    cmp   x11, x22
    b.eq  1f
    mov   x0, x11                         /* land the other store's bytes */
    bl    Lwal_drain_fd
    cbnz  x0, Lwl_no
1:  WALADDR x9
    str   x22, [x9, #8]                   /* this store owns the buffer */
    mov   x10, #WALCAP
    cmp   x21, x10
    b.ls  3f
    ldr   x10, [x9]                       /* oversize: straight through */
    cbz   x10, 2f
    mov   x0, x22
    bl    Lwal_drain_fd
    cbnz  x0, Lwl_no
2:  mov   w0, w22
    mov   x1, x20
    mov   x2, x21
    bl    Lwrite_all
    cbnz  x0, Lwl_no
    b     5f
3:  ldr   x10, [x9]
    add   x10, x10, x21
    mov   x11, #WALCAP
    cmp   x10, x11
    b.ls  4f
    mov   x0, x22                         /* it would overflow: drain first */
    bl    Lwal_drain_fd
    cbnz  x0, Lwl_no
4:  WALADDR x9
    ldr   x10, [x9]
    WALBUF x0
    add   x0, x0, x10
    mov   x1, x20
    mov   x2, x21
    bl    _memcpy
    WALADDR x9
    ldr   x10, [x9]
    add   x10, x10, x21
    str   x10, [x9]
5:  ldr   x10, [x19, #16]                 /* the LOGICAL length advances now */
    add   x10, x10, x21
    str   x10, [x19, #16]
    mov   x0, #0
    b     Lwl_ret
Lwl_no:
    mov   x0, #-1
Lwl_ret:
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* utxo_store_init(st=x0) ; st x19 */
    .p2align 2
    .globl _utxo_store_init
_utxo_store_init:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    adrp  x0, Llogname@PAGE
    add   x0, x0, Llogname@PAGEOFF
    mov   w1, #(O_RDWR | O_CREAT)
    bl    Lopen3
    tbnz  w0, #31, 2f
    sxtw  x9, w0
    str   x9, [x19]
    adrp  x0, Lidxname@PAGE
    add   x0, x0, Lidxname@PAGEOFF
    mov   w1, #(O_RDWR | O_CREAT)
    bl    Lopen3
    tbnz  w0, #31, 1f
    sxtw  x9, w0
    str   x9, [x19, #8]
    stp   xzr, xzr, [x19, #16]
    str   xzr, [x19, #32]
    mov   x0, #1
    b     3f
1:  ldr   x0, [x19]
    bl    _close
2:  mov   x0, #-1
3:  ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* utxo_store_init_ro(st=x0) ; st x19 */
    .p2align 2
    .globl _utxo_store_init_ro
_utxo_store_init_ro:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    adrp  x0, Llogname@PAGE
    add   x0, x0, Llogname@PAGEOFF
    mov   w1, #O_RDONLY                   /* no O_CREAT: a missing log is an error */
    bl    _open
    tbnz  w0, #31, 1f
    sxtw  x9, w0
    mov   x10, #-1                        /* the idx is never opened here */
    stp   x9, x10, [x19]
    stp   xzr, xzr, [x19, #16]
    str   xzr, [x19, #32]
    mov   x0, #1
    b     2f
1:  mov   x0, #-1
2:  ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* ============================================================================
 * utxo_store_put(st=x0, u=x1, txid=x2, index=w3, value=x4, height=w5,
 *                cb=w6, script=x7, slen=w[caller sp])
 * st x19, u x20, txid x21, index x22, value x23, height x24, cb x25,
 * script x26, slen x27 ; frame: hdr 0 (64)
 * ========================================================================== */
    .p2align 2
    .globl _utxo_store_put
_utxo_store_put:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    str   x27, [sp, #80]
    mov   x29, sp
    ldr   w27, [x29, #96]                 /* slen: a u32 stack argument */
    sub   sp, sp, #64
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   w22, w3
    mov   x23, x4
    mov   w24, w5
    mov   w25, w6
    mov   x26, x7
    MOVW  w9, MAGIC_LOG
    str   w9, [sp]
    mov   w9, #1                          /* op PUSH, 3 pad */
    str   w9, [sp, #4]
    ldp   x9, x10, [x21]
    stp   x9, x10, [sp, #8]
    ldp   x9, x10, [x21, #16]
    stp   x9, x10, [sp, #24]
    str   w22, [sp, #40]
    stur  x23, [sp, #44]
    str   w24, [sp, #52]
    strb  w25, [sp, #56]
    sturh w27, [sp, #57]
    mov   x0, x19
    mov   x1, sp
    mov   x2, #PUSH_HDR
    bl    Lwr_log
    cbnz  x0, Lsp_no
    cbz   w27, 1f
    mov   x0, x19
    mov   x1, x26
    mov   w2, w27
    bl    Lwr_log
    cbnz  x0, Lsp_no
1:  mov   x0, x20                         /* then the table */
    mov   x1, x21
    mov   w2, w22
    mov   x3, x23
    mov   w4, w24
    mov   w5, w25
    mov   x6, x26
    mov   w7, w27
    bl    _utxo_put
    b     Lsp_ret
Lsp_no:
    mov   x0, #-1
Lsp_ret:
    add   sp, sp, #64
    ldr   x27, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* utxo_store_del(st=x0, u=x1, txid=x2, index=w3) ; u x19, txid x20,
 * index x21 ; frame rec 0 (48) */
    .p2align 2
    .globl _utxo_store_del
_utxo_store_del:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #48
    mov   x19, x1
    mov   x20, x2
    mov   w21, w3
    MOVW  w9, MAGIC_LOG
    str   w9, [sp]
    mov   w9, #2                          /* op DEL, 3 pad */
    str   w9, [sp, #4]
    ldp   x9, x10, [x20]
    stp   x9, x10, [sp, #8]
    ldp   x9, x10, [x20, #16]
    stp   x9, x10, [sp, #24]
    str   w21, [sp, #40]
    mov   x1, sp
    mov   x2, #DEL_SIZE
    bl    Lwr_log
    cbnz  x0, 1f
    mov   x0, x19
    mov   x1, x20
    mov   w2, w21
    bl    _utxo_del
    b     2f
1:  mov   x0, #-1
2:  add   sp, sp, #48
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

    .p2align 2
    .globl _utxo_store_count
_utxo_store_count:
    ldr   x0, [x1]
    ret

/* utxo_store_get(st, u, txid, index, value, height, cb, script, slen) ->
 * utxo_get(u, txid, index, value, height, cb, script, slen): a tail call */
    .p2align 2
    .globl _utxo_store_get
_utxo_store_get:
    ldr   x9, [sp]                        /* slen*: the 9th argument */
    mov   x0, x1
    mov   x1, x2
    mov   w2, w3
    mov   x3, x4
    mov   x4, x5
    mov   x5, x6
    mov   x6, x7
    mov   x7, x9
    b     _utxo_get

/* utxo_store_clear(u=x0) ; leaf: empty table, same mask / blob */
    .p2align 2
    .globl _utxo_store_clear
_utxo_store_clear:
    str   xzr, [x0]
    str   xzr, [x0, #32]
    ldr   x9, [x0, #8]
    add   x9, x9, #1
    add   x10, x0, #80                    /* slot 0's index field (40 + 40) */
    mov   w11, #-1
1:  str   w11, [x10], #48
    subs  x9, x9, #1
    b.ne  1b
    ret

/* ============================================================================
 * utxo_store_sync(st=x0, u=x1)
 * st x19, u x20, tfd x21, slot ptr x22, slots left x23, blob x24,
 * log_off x25, n x26 ; frame: rec 0 (64)
 * ========================================================================== */
    .p2align 2
    .globl _utxo_store_sync
_utxo_store_sync:
    stp   x29, x30, [sp, #-80]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    mov   x29, sp
    sub   sp, sp, #64
    mov   x19, x0
    mov   x20, x1
    bl    _utxo_store_wal_drain
    cmn   x0, #1
    b.eq  Lsy_ret_no
    adrp  x0, Lidxtmp@PAGE
    add   x0, x0, Lidxtmp@PAGEOFF
    mov   w1, #(O_WRONLY | O_CREAT | O_TRUNC)
    bl    Lopen3
    tbnz  w0, #31, Lsy_ret_no
    mov   w21, w0
    MOVW  w9, MAGIC_IDX                   /* header: magic, log_off, n */
    str   w9, [sp]
    ldr   x25, [x19, #16]
    ldr   x26, [x20]
    stur  x25, [sp, #4]
    stur  x26, [sp, #12]
    mov   w0, w21
    mov   x1, sp
    mov   x2, #IDX_HDR
    bl    _write
    cmp   x0, #IDX_HDR
    b.ne  Lsy_fail
    ldr   x23, [x20, #8]
    add   x23, x23, #1                    /* slots */
    add   x22, x20, #40
    ldr   x24, [x20, #16]
1:  cbz   x23, 3f
    ldr   w9, [x22, #40]
    cmn   w9, #1
    b.eq  2f
    ldp   x10, x11, [x22, #8]             /* txid, index, value, height, cb, slen */
    stp   x10, x11, [sp]
    ldp   x10, x11, [x22, #24]
    stp   x10, x11, [sp, #16]
    str   w9, [sp, #32]
    ldr   x10, [x22]
    add   x10, x24, x10                   /* the record */
    ldp   x11, x12, [x10]
    stur  x11, [sp, #36]
    str   w12, [sp, #44]
    lsr   x12, x12, #32
    strb  w12, [sp, #48]
    ldr   x11, [x10, #16]
    sturh w11, [sp, #49]
    str   x10, [sp, #56]                  /* (record, across the write) */
    mov   w0, w21
    mov   x1, sp
    mov   x2, #CKPT_REC
    bl    _write
    cmp   x0, #CKPT_REC
    b.ne  Lsy_fail
    ldr   x10, [sp, #56]
    ldr   x2, [x10, #16]                  /* slen: the full u64, as the twin */
    cbz   x2, 2f
    str   x2, [sp, #48]                   /* (slen, across the write) */
    mov   w0, w21
    add   x1, x10, #24
    bl    _write
    ldr   x2, [sp, #48]
    cmp   x0, x2
    b.ne  Lsy_fail
2:  add   x22, x22, #48
    sub   x23, x23, #1
    b     1b
3:  stp   x25, x26, [x19, #24]            /* ckpt_log_off, ckpt_n */
    mov   w0, w21
    bl    _fsync
    ldr   x0, [x19]
    bl    _fsync                          /* the log too */
    adrp  x0, Lidxtmp@PAGE
    add   x0, x0, Lidxtmp@PAGEOFF
    adrp  x1, Lidxname@PAGE
    add   x1, x1, Lidxname@PAGEOFF
    bl    _rename
    tbnz  w0, #31, Lsy_fail
    mov   w0, w21
    bl    _close
    mov   x0, #1
    b     Lsy_ret
Lsy_fail:
    mov   w0, w21
    bl    _close
    adrp  x0, Lidxtmp@PAGE                /* no torn tmp left behind */
    add   x0, x0, Lidxtmp@PAGEOFF
    bl    _unlink
Lsy_ret_no:
    mov   x0, #-1
Lsy_ret:
    add   sp, sp, #64
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

/* ============================================================================
 * utxo_store_reload(st=x0, u=x1)
 * st x19, u x20, fd x21 (checkpoint, then the replay), log_end x22,
 * consumed / cursor x23, n / i x24, rec_start x25, replayed x26, torn x27,
 * script buffer x28 ; frame: fixed 0 (64), then the 64 KiB script buffer
 * ========================================================================== */
#define SCRBUF 65536

    .p2align 2
    .globl _utxo_store_reload
_utxo_store_reload:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x9, #(SCRBUF / 4096)            /* 64 KiB, 4 KiB at a time, touched */
1:  sub   sp, sp, #4096
    str   xzr, [sp]
    subs  x9, x9, #1
    b.ne  1b
    mov   x28, sp
    sub   sp, sp, #64                     /* fixed[] at sp */
    bl    _utxo_store_wal_drain
    cmn   x0, #1
    b.eq  Lrl_no
    mov   x0, x20
    bl    _utxo_store_clear
    ldr   x0, [x19]
    mov   x1, #0
    mov   w2, #2                          /* SEEK_END */
    bl    _lseek
    tbnz  x0, #63, Lrl_no
    mov   x22, x0
    str   x22, [x19, #16]                 /* log_len = the file size */
    stp   xzr, xzr, [x19, #24]
    /* the checkpoint */
    adrp  x0, Lidxname@PAGE
    add   x0, x0, Lidxname@PAGEOFF
    mov   w1, #O_RDONLY
    bl    _open
    tbnz  w0, #31, Lrl_replay
    mov   w21, w0
    mov   w0, w21
    mov   x1, sp
    mov   x2, #IDX_HDR
    mov   x3, #0
    bl    _pread
    cmp   x0, #IDX_HDR
    b.ne  Lrl_ckclose
    ldr   w9, [sp]
    MOVW  w10, MAGIC_IDX
    cmp   w9, w10
    b.ne  Lrl_ckclose
    ldur  x9, [sp, #4]
    ldur  x24, [sp, #12]
    stp   x9, x24, [x19, #24]             /* ckpt_log_off, ckpt_n */
    mov   x23, #IDX_HDR                   /* cursor */
2:  cbz   x24, Lrl_ckclose
    mov   w0, w21
    mov   x1, sp
    mov   x2, #CKPT_REC
    mov   x3, x23
    bl    _pread
    cmp   x0, #CKPT_REC
    b.ne  Lrl_ckclose
    add   x23, x23, #CKPT_REC
    ldurh w9, [sp, #49]                   /* slen */
    cbz   w9, 3f
    mov   w0, w21
    mov   x1, x28
    mov   x2, x9
    mov   x3, x23
    bl    _pread
    ldurh w9, [sp, #49]
    cmp   x0, x9
    b.ne  Lrl_ckclose
    add   x23, x23, x9
3:  bl    Lput_fixed                      /* utxo_put from fixed[] + script */
    cmp   x0, #2
    b.eq  Lrl_ckfull
    sub   x24, x24, #1
    b     2b
Lrl_ckfull:
    mov   w0, w21
    bl    _close
    mov   x0, #-2
    b     Lrl_ret
Lrl_ckclose:
    mov   w0, w21
    bl    _close
Lrl_replay:
    adrp  x0, Llogname@PAGE
    add   x0, x0, Llogname@PAGEOFF
    mov   w1, #O_RDONLY
    bl    _open
    tbnz  w0, #31, Lrl_no
    mov   w21, w0
    ldr   x23, [x19, #24]                 /* consumed = the checkpoint offset */
    mov   x25, x23                        /* rec_start */
    mov   x26, #0
    mov   x27, #0
4:  cmp   x23, x22
    b.hs  Lrl_end                         /* a clean end: nothing truncated */
    mov   x25, x23
    mov   w0, w21
    mov   x1, sp
    mov   x2, #8
    mov   x3, x23
    bl    _pread
    cmp   x0, #8
    b.ne  Lrl_torn
    add   x23, x23, #8
    ldr   w9, [sp]
    MOVW  w10, MAGIC_LOG
    cmp   w9, w10
    b.ne  Lrl_torn
    ldrb  w9, [sp, #4]
    cmp   w9, #1
    b.eq  5f
    cmp   w9, #2
    b.eq  6f
    b     Lrl_torn                        /* an unknown op */
5:  mov   w0, w21                         /* PUSH */
    mov   x1, sp
    mov   x2, #CKPT_REC
    mov   x3, x23
    bl    _pread
    cmp   x0, #CKPT_REC
    b.ne  Lrl_torn
    add   x23, x23, #CKPT_REC
    ldurh w9, [sp, #49]
    cbz   w9, 51f
    mov   w0, w21
    mov   x1, x28
    mov   x2, x9
    mov   x3, x23
    bl    _pread
    ldurh w9, [sp, #49]
    cmp   x0, x9
    b.ne  Lrl_torn
    add   x23, x23, x9
51: bl    Lput_fixed
    cmp   x0, #2
    b.eq  Lrl_full
    add   x26, x26, #1
    b     4b
6:  mov   w0, w21                         /* DEL */
    mov   x1, sp
    mov   x2, #36
    mov   x3, x23
    bl    _pread
    cmp   x0, #36
    b.ne  Lrl_torn
    add   x23, x23, #36
    mov   x0, x20
    mov   x1, sp
    ldr   w2, [sp, #32]
    bl    _utxo_del
    add   x26, x26, #1
    b     4b
Lrl_torn:
    mov   x27, #1
Lrl_end:
    cbz   x27, 7f                         /* UTX-4: only a torn exit truncates */
    cmp   x25, x22
    b.hs  7f
    str   x25, [x19, #16]                 /* log_len = the failing record's start */
    ldr   x0, [x19]
    tbnz  x0, #63, 7f
    mov   x1, x25
    bl    _ftruncate                      /* best effort, as x86 */
7:  mov   w0, w21
    bl    _close
    mov   x0, x26
    b     Lrl_ret
Lrl_full:
    mov   w0, w21
    bl    _close
    mov   x0, #-2
    b     Lrl_ret
Lrl_no:
    mov   x0, #-1
Lrl_ret:
    mov   sp, x29
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* Lput_fixed: utxo_put(u, fixed.txid, index, value, height, cb, script or
 * NULL, slen) from reload's frame -- fixed[] is at the CALLER's sp (it is
 * called with bl, so its own frame sits below), u in x20, buffer in x28 */
    .p2align 2
Lput_fixed:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    add   x9, sp, #16                     /* the caller's fixed[] */
    mov   x0, x20
    mov   x1, x9
    ldr   w2, [x9, #32]
    ldur  x3, [x9, #36]
    ldr   w4, [x9, #44]
    ldrb  w5, [x9, #48]
    ldurh w7, [x9, #49]
    cmp   w7, #0
    csel  x6, x28, xzr, ne                /* script, or NULL when slen is 0 */
    bl    _utxo_put
    ldp   x29, x30, [sp], #16
    ret

/* utxo_store_close(st=x0) ; st x19 */
    .p2align 2
    .globl _utxo_store_close
_utxo_store_close:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    ldr   x9, [x19]
    cmn   x9, #1
    b.eq  1f
    bl    _utxo_store_wal_drain
    ldr   x0, [x19]
    bl    _fsync
    ldr   x0, [x19]
    bl    _close
1:  ldr   x9, [x19, #8]
    cmn   x9, #1
    b.eq  2f
    mov   x0, x9
    bl    _fsync
    ldr   x0, [x19, #8]
    bl    _close
2:  ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .section __TEXT,__cstring
Llogname:
    .asciz "utxo.dat"
Lidxname:
    .asciz "utxo.idx"
Lidxtmp:
    .asciz "utxo.idx.tmp"

    .data
    .p2align 3
Lwal:       /* fill, owner fd */
    .quad 0, 0

.zerofill __DATA,__bss,Lwal_buf,WALCAP,4
