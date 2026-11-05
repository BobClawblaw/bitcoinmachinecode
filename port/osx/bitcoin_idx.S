/* ============================================================================
 * bitcoin_idx.S -- the persisted block hash -> height open-addressing index
 * in AArch64 assembly (Apple silicon), the counterpart of asm/bitcoin_idx.asm.
 * Replaces idx_twin.c on the Mac (2026-09-26); the twin stays in
 * port/osx/test_support as the oracle.
 *
 * Object layout (the caller's buffer; byte for byte the x86's):
 *   +0 n (live entries), +8 mask (slots - 1, slots a power of two),
 *   +16 reserved, +24 slots of 48 bytes: height (i64, -1 = empty),
 *   hash[32], pad[8].
 *
 *   void idx_init(void* idx, u64 slots);
 *   int  idx_put(void* idx, const u8 hash[32], long height);  1 new/0 dup/2 full
 *   int  idx_get(void* idx, const u8 hash[32], long* height); 1 found / 0
 *   long idx_count(void* idx);
 *   long idx_build_from_file(void* idx, const char* path);    0 / -1 no open
 *
 * The slot hash is FNV-1a (32-bit) over all 32 bytes, h ^= h >> 15, masked;
 * linear probing with a budget of mask + 1 probes; duplicates by a full
 * 32-byte compare. build_from_file reads a positional index.dat of 48-byte
 * records (present = the first 4 bytes nonzero, the hash at rec[0..31] in
 * WIRE order) through a 4096-record window, and idx_puts each present
 * record's hash unchanged with its record number as the height -- the table
 * is keyed as the p2p wire carries hashes (do not byte-reverse them: the
 * 2026-08-27 "fix" that did keyed it backwards). The window is one global
 * buffer, as the x86's .bss (build runs once, single-threaded, at startup).
 * ========================================================================== */
#define STRIDE   48
#define BUFRECS  4096
#define BUFBYTES (BUFRECS * STRIDE)

    .text

/* idx_init(idx=x0, slots=x1) ; leaf */
    .p2align 2
    .globl _idx_init
_idx_init:
    sub   x9, x1, #1
    stp   xzr, x9, [x0]                   /* n = 0, mask */
    add   x10, x0, #24
    mov   x11, #-1
    cbz   x1, 2f
1:  str   x11, [x10], #STRIDE             /* height = -1: empty */
    subs  x1, x1, #1
    b.ne  1b
2:  ret

/* Lslot(hash=x1, mask=x9) -> x10 = first slot ; leaf, x11..x13 */
    .p2align 2
Lslot:
    movz  w10, #0x9dc5
    movk  w10, #0x811c, lsl #16           /* FNV offset basis */
    movz  w12, #0x0193
    movk  w12, #0x0100, lsl #16           /* FNV prime */
    mov   x11, #0
1:  ldrb  w13, [x1, x11]
    eor   w10, w10, w13
    mul   w10, w10, w12
    add   x11, x11, #1
    cmp   x11, #32
    b.lo  1b
    eor   w10, w10, w10, lsr #15
    and   x10, x10, x9
    ret

/* EQ32 slotptr: Z = (the slot's hash == hash at x1) ; x12..x15 */
.macro EQHASH sp
    ldp   x12, x13, [\sp, #8]
    ldp   x14, x15, [x1]
    cmp   x12, x14
    ccmp  x13, x15, #0, eq
    ldp   x12, x13, [\sp, #24]
    ldp   x14, x15, [x1, #16]
    ccmp  x12, x14, #0, eq
    ccmp  x13, x15, #0, eq
.endm

/* idx_put(idx=x0, hash=x1, height=x2) ; leaf */
    .p2align 2
    .globl _idx_put
_idx_put:
    mov   x8, x30
    ldr   x9, [x0, #8]                    /* mask */
    bl    Lslot
    mov   x30, x8
    add   x16, x9, #1                     /* probe budget */
    add   x17, x0, #24
    mov   x11, #STRIDE
1:  madd  x3, x10, x11, x17               /* slot address */
    ldr   x4, [x3]
    cmn   x4, #1
    b.eq  2f                              /* empty: insert here */
    EQHASH x3
    b.eq  3f                              /* duplicate */
    subs  x16, x16, #1
    b.eq  4f                              /* full */
    add   x10, x10, #1
    and   x10, x10, x9
    b     1b
2:  str   x2, [x3]
    ldp   x12, x13, [x1]
    ldp   x14, x15, [x1, #16]
    stp   x12, x13, [x3, #8]
    stp   x14, x15, [x3, #24]
    ldr   x12, [x0]
    add   x12, x12, #1
    str   x12, [x0]
    mov   w0, #1
    ret
3:  mov   w0, #0
    ret
4:  mov   w0, #2
    ret

/* idx_get(idx=x0, hash=x1, height=x2 or NULL) ; leaf */
    .p2align 2
    .globl _idx_get
_idx_get:
    mov   x8, x30
    ldr   x9, [x0, #8]
    bl    Lslot
    mov   x30, x8
    add   x16, x9, #1
    add   x17, x0, #24
    mov   x11, #STRIDE
1:  madd  x3, x10, x11, x17
    ldr   x4, [x3]
    cmn   x4, #1
    b.eq  3f                              /* an empty slot: absent */
    EQHASH x3
    b.eq  2f
    subs  x16, x16, #1
    b.eq  3f                              /* budget spent: absent */
    add   x10, x10, #1
    and   x10, x10, x9
    b     1b
2:  cbz   x2, 21f
    str   x4, [x2]
21: mov   w0, #1
    ret
3:  mov   w0, #0
    ret

    .p2align 2
    .globl _idx_count
_idx_count:
    ldr   x0, [x0]
    ret

/* ============================================================================
 * idx_build_from_file(idx=x0, path=x1)
 * idx x19, fd x20, n x21, pos x22, full x23, i x24, buf x25
 * ========================================================================== */
    .p2align 2
    .globl _idx_build_from_file
_idx_build_from_file:
    stp   x29, x30, [sp, #-80]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    str   x25, [sp, #64]
    mov   x29, sp
    mov   x19, x0
    mov   x0, x1
    mov   w1, #0                          /* O_RDONLY (no mode: nothing variadic) */
    bl    _open
    tbnz  w0, #31, Lib_nofile
    sxtw  x20, w0
    mov   x1, #0
    mov   w2, #2                          /* SEEK_END */
    bl    _lseek
    tbnz  x0, #63, Lib_close
    mov   x9, #STRIDE
    udiv  x21, x0, x9                     /* records */
    mov   x22, #0
    adrp  x25, Lidxbuf@PAGE
    add   x25, x25, Lidxbuf@PAGEOFF
1:  cmp   x22, x21
    b.hs  Lib_close
    sub   x9, x21, x22                    /* take = min(remaining, BUFRECS) */
    mov   x10, #BUFRECS
    cmp   x9, x10
    csel  x9, x9, x10, lo
    mov   x10, #STRIDE
    mov   w0, w20
    mov   x1, x25
    mul   x2, x9, x10
    mul   x3, x22, x10
    bl    _pread
    cmp   x0, #0
    b.le  Lib_close                       /* nothing read: stop */
    mov   x9, #STRIDE
    udiv  x23, x0, x9                     /* whole records read */
    mov   x24, #0
2:  cmp   x24, x23
    b.hs  3f
    mov   x9, #STRIDE
    madd  x1, x24, x9, x25                /* rec */
    ldr   w9, [x1]
    cbz   w9, 21f                         /* a hole */
    mov   x0, x19
    add   x2, x22, x24                    /* height = record number */
    bl    _idx_put                        /* hash as stored (wire order); a dup is skipped */
21: add   x24, x24, #1
    b     2b
3:  add   x22, x22, x23
    cmp   x23, #BUFRECS
    b.lo  Lib_close                       /* a short / final read */
    b     1b
Lib_close:
    mov   w0, w20
    bl    _close
    mov   x0, #0
    b     Lib_ret
Lib_nofile:
    mov   x0, #-1
Lib_ret:
    ldr   x25, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

.zerofill __DATA,__bss,Lidxbuf,BUFBYTES,4
