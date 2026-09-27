/* ============================================================================
 * bitcoin_utxo_lsm.S -- the LSM-tree persistent UTXO store in AArch64
 * assembly (Apple silicon), the counterpart of asm/bitcoin_utxo_lsm.asm.
 * Replaces utxo_lsm_twin.c on the Mac (2026-09-26); the twin stays in
 * port/osx/test_support as the oracle.
 *
 * Tiers: the memtable + WAL are utxo_store_* over the in-memory table
 * (bitcoin_utxo_store.S / bitcoin_utxo.S) -- the state's first 40 bytes are
 * utxo_store's own, so lst doubles as its st. This module adds the flush
 * (the memtable's live entries + this generation's tombstones -> a sorted,
 * immutable run file: MAGIC_RUN3 44-byte header, 3-seed bloom, 64-record
 * sparse index), the manifest (UMAN / UMN2, tmp + fsync + rename + dir
 * fsync), the multi-run point lookup (newest first, bloom-gated, sparse-
 * accelerated; the vendored mmap fast path asm/utxo_lsm_mm.c first), and
 * the k-way merges: recount, walk, compact.
 *
 * State (lst; the caller zeroes it and sets the config fields):
 *   +0..39 utxo_store, +40 op_count, +48 op_threshold, +56 fill_threshold,
 *   +64 tomb_buf, +72 tomb_cap, +80 tomb_n, +88 total_live, +96 next_gen,
 *   +104 manifest_buf, +112 manifest_cap, +120 manifest_n, +128 scratch_buf,
 *   +136 scratch_cap, +144 next_run_no, +152 tomb hash (LSM-owned mmap),
 *   +160 tomb hash mask.
 * Descriptor (64 bytes, flush scratch): key36 @0 (txid @0, index @32),
 * type @36 (1 PUSH / 2 DEL), value @40, slen @48, height @50, cb @54,
 * script pointer @56.
 * Run file: header [magic][gen][nrec][bloom_bits][sparse_off][sparse_n],
 * the bloom, the sorted records (key36 + type [+ value8 slen2 height4 cb1
 * + script for a PUSH]), the sparse index (key36 + offset8 every 64th).
 *
 * Every rule is the twin's (each fix it carries is the x86's -- see the
 * twin for the incident behind each): the flush hook runs first; one
 * tombstone per key per generation; the flush skips tombstones whose key is
 * live again; the WAL is reset before any state is cleared (UTX-8); ties in
 * the merges go to the newest manifest index (UTX-1) and every copy of the
 * winning key is skipped in every input; a compaction's bloom covers kept
 * DELs; a v2 manifest with an empty WAL tail supplies the live count, any
 * tail forces the recount (incident #45); a missing manifest is fine, any
 * other open failure is not (UTX-6).
 *
 * The sort. utxo_lsm_sort_desc orders descriptors by their 36-byte key,
 * STABLY: mode 1 (the default) an MSD radix over 16-byte compact entries
 * (the key's first 96 bits big-endian + the descriptor index), then over key
 * bytes 12..35 read through the descriptors, with an insertion sort for
 * buckets of <= 32 (tie-break: the remaining key bytes); mode 0 a bottom-up
 * merge sort. A stable sort by key has exactly one result, so both modes and
 * the twin's radix (whose bucket widths differ: 12/8 bits against 8 here)
 * produce the same array -- which the differential test checks against both
 * twin modes. The radix keeps the twin's scratch layout: compact entries at
 * b + 32n (ping) and b + 48n (pong, where the sorted order ends), the gather
 * into b, then b back to a. Its per-level digit counts (2 KiB) live on the
 * stack, not in a shared static, so two flushes on two stores cannot collide.
 *
 * The run lookup's fallback (when the mmap fast path declines) tests the
 * three bloom bits by reading their three bytes, not the whole bloom into a
 * 4 MiB thread-local buffer as the twin: a run whose file is shorter than
 * its header's bloom is still an error (checked with fstat), so the answer
 * is the twin's. The returned script points into a 64 KiB thread-local
 * buffer (a Mach-O TLV), valid until the thread's next lookup, as the twin.
 *
 * Process-wide writer state (the flush and compaction buffers, the toggles)
 * is static, as the x86 .bss and the twin. open() and fcntl() are variadic:
 * their extra argument goes on the stack (Darwin arm64).
 * ========================================================================== */
#define MAGIC_RUN        0x4E555255
#define MAGIC_RUN2       0x32555255
#define MAGIC_RUN3       0x33555255
#define MAGIC_MANIFEST   0x4E414D55
#define MAGIC_MANIFEST2  0x324E4D55
#define BLOOM_MAX_BYTES  0x400000
#define SCRIPT_MAX       65536
#define SPARSE_STRIDE    64
#define SPARSE_ENT       44
#define COMPACT_MAX_RUNS 64
#define RDBUF            262144
#define FLBUF            1048576
#define OWBUF            1048576
#define RS_INS_MAX       32
#define RS_MAX_DEPTH     72
#define O_RDONLY         0x0000
#define O_WRONLY         0x0001
#define O_RDWR           0x0002
#define O_CREAT          0x0200
#define O_TRUNC          0x0400
#define PROT_RW          3
#define MAP_PRIV_ANON    0x1002
#define SEEK_SET         0
#define SEEK_CUR         1
#define SEEK_END         2
#define ENOENT           2
#define SEED0            0x811c9dc5
#define SEED1            0xa1b2c3d4
#define SEED2            0x5bd1e995

/* the compaction / recount input slot (internal layout) */
#define SL_FD        0
#define SL_GEN       8
#define SL_RUN       16
#define SL_REM       24
#define SL_ACTIVE    32
#define SL_V2        36
#define SL_KEY       40                   /* key36 + type at +76 */
#define SL_TYPE      76
#define SL_VALUE     80
#define SL_SLEN      88
#define SL_HEIGHT    92
#define SL_CB        96
#define SL_FILL      104
#define SL_POS       112
#define SL_SCRIPT    128
#define SL_RDBUF     (SL_SCRIPT + SCRIPT_MAX)
#define SL_SIZE      (SL_RDBUF + RDBUF)

.macro MOVW r, imm
    movz  \r, #((\imm) & 0xffff)
    movk  \r, #(((\imm) >> 16) & 0xffff), lsl #16
.endm
.macro ADR_ r, sym
    adrp  \r, \sym@PAGE
    add   \r, \r, \sym@PAGEOFF
.endm

    .text

/* ---- plain I/O -------------------------------------------------------- */

/* Lwrite_exact(fd=w0, buf=x1, len=x2) -> x0 0 / -1 */
    .p2align 2
Lwrite_exact:
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

/* Lread_exact(fd=w0, buf=x1, len=x2) -> x0 0 / -1 */
    .p2align 2
Lread_exact:
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
    bl    _read
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

/* Lopen3(path=x0, flags=w1): open(path, flags, 0644), the mode on the stack */
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

/* Lfsync_dir: fsync(".") best effort */
    .p2align 2
Lfsync_dir:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    ADR_  x0, Ldot
    mov   w1, #O_RDONLY
    bl    _open
    tbnz  w0, #31, 1f
    mov   w19, w0
    bl    _fsync
    mov   w0, w19
    bl    _close
1:  ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* Lfmt_runname(buf=x0, run_no=w1): snprintf(buf, 21, "utxo_run_%06u.dat") */
    .p2align 2
Lfmt_runname:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #16
    mov   w9, w1
    str   x9, [sp]                        /* the variadic argument */
    mov   x1, #21
    ADR_  x2, Lrunfmt
    bl    _snprintf
    add   sp, sp, #16
    ldp   x29, x30, [sp], #16
    ret

/* ---- the flush writer (buffer Lflbuf, fill Lg+FLFILL) ------------------- */
#define G_FLFILL  0
#define G_OWFD    8
#define G_OWFILL  16
#define G_DEFUNL  24
#define G_DEFPUB  32
#define G_HOOK    40
#define G_SORT    48

/* Lfl_drain(fd=w0) -> 0 / -1 */
    .p2align 2
Lfl_drain:
    ADR_  x9, Lg
    ldr   x2, [x9, #G_FLFILL]
    cbz   x2, 1f
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    str   xzr, [x9, #G_FLFILL]            /* the twin zeroes the fill either way */
    ADR_  x1, Lflbuf
    bl    Lwrite_exact
    ldp   x29, x30, [sp], #16
    ret
1:  mov   x0, #0
    ret

/* Lfl_write(fd=w0, src=x1, len=x2) -> 0 / -1 ; fd x19, src x20, len x21 */
    .p2align 2
Lfl_write:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    mov   w19, w0
    mov   x20, x1
    mov   x21, x2
    ADR_  x9, Lg
    ldr   x10, [x9, #G_FLFILL]
    add   x10, x10, x21
    mov   x11, #FLBUF
    cmp   x10, x11
    b.ls  2f
    mov   w0, w19
    bl    Lfl_drain
    cbnz  x0, 9f
    mov   x11, #FLBUF
    cmp   x21, x11
    b.ls  2f
    mov   w0, w19                         /* larger than the buffer: direct */
    mov   x1, x20
    mov   x2, x21
    bl    Lwrite_exact
    b     10f
2:  ADR_  x9, Lg
    ldr   x10, [x9, #G_FLFILL]
    ADR_  x0, Lflbuf
    add   x0, x0, x10
    mov   x1, x20
    mov   x2, x21
    bl    _memcpy
    ADR_  x9, Lg
    ldr   x10, [x9, #G_FLFILL]
    add   x10, x10, x21
    str   x10, [x9, #G_FLFILL]
    mov   x0, #0
    b     10f
9:  mov   x0, #-1
10: ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ---- the compaction output writer (Lowbuf; fd, fill in Lg) ------------ */

/* Lout_flush() -> 0 / -1 */
    .p2align 2
Lout_flush:
    ADR_  x9, Lg
    ldr   x2, [x9, #G_OWFILL]
    cbz   x2, 1f
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    ldr   x0, [x9, #G_OWFD]
    str   xzr, [x9, #G_OWFILL]
    ADR_  x1, Lowbuf
    bl    Lwrite_exact
    ldp   x29, x30, [sp], #16
    ret
1:  mov   x0, #0
    ret

/* Lout_write(src=x0, len=x1) -> 0 / -1 ; src x19, len x20 */
    .p2align 2
Lout_write:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    ADR_  x9, Lg
    ldr   x10, [x9, #G_OWFILL]
    add   x10, x10, x20
    mov   x11, #OWBUF
    cmp   x10, x11
    b.ls  2f
    bl    Lout_flush
    cbnz  x0, 9f
    mov   x11, #OWBUF
    cmp   x20, x11
    b.ls  2f
    ADR_  x9, Lg
    ldr   x0, [x9, #G_OWFD]
    mov   x1, x19
    mov   x2, x20
    bl    Lwrite_exact
    b     10f
2:  ADR_  x9, Lg
    ldr   x10, [x9, #G_OWFILL]
    ADR_  x0, Lowbuf
    add   x0, x0, x10
    mov   x1, x19
    mov   x2, x20
    bl    _memcpy
    ADR_  x9, Lg
    ldr   x10, [x9, #G_OWFILL]
    add   x10, x10, x20
    str   x10, [x9, #G_OWFILL]
    mov   x0, #0
    b     10f
9:  mov   x0, #-1
10: ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* ---- keys, blooms, the tombstone hash --------------------------------- */

/* Lcmp_key(p=x0, q=x1) -> w0 0 lt / 1 eq / 2 gt (36 bytes, unsigned) ; leaf,
 * x9..x12 */
    .p2align 2
Lcmp_key:
    ldp   x9, x10, [x0]
    ldp   x11, x12, [x1]
    rev   x9, x9
    rev   x11, x11
    cmp   x9, x11
    b.ne  1f
    rev   x10, x10
    rev   x12, x12
    cmp   x10, x12
    b.ne  1f
    ldp   x9, x10, [x0, #16]
    ldp   x11, x12, [x1, #16]
    rev   x9, x9
    rev   x11, x11
    cmp   x9, x11
    b.ne  1f
    rev   x10, x10
    rev   x12, x12
    cmp   x10, x12
    b.ne  1f
    ldr   w9, [x0, #32]
    ldr   w11, [x1, #32]
    rev   w9, w9
    rev   w11, w11
    cmp   w9, w11
    b.ne  1f
    mov   w0, #1
    ret
1:  cset  w0, hi                          /* 1 if greater ... */
    lsl   w0, w0, #1                      /* ... -> 2; less -> 0 */
    ret

/* Lbloom_bit(key=x0, seed=w1, mask=w2) -> w0 = the bit index ; leaf,
 * x9..x12 */
    .p2align 2
Lbloom_bit:
    MOVW  w10, 16777619
    mov   w9, w1
    mov   x11, #0
1:  ldrb  w12, [x0, x11]
    eor   w9, w9, w12
    mul   w9, w9, w10
    add   x11, x11, #1
    cmp   x11, #36
    b.lo  1b
    and   w0, w9, w2
    ret

/* Lbloom_set3(key=x0, bloom=x1, mask=w2): the three seeds' bits ; x13..x16 */
    .p2align 2
Lbloom_set3:
    mov   x16, x30
    mov   x13, x0
    mov   x14, x1
    mov   w15, w2
    MOVW  w1, SEED0
    bl    Lbloom_bit
    bl    91f
    mov   x0, x13
    MOVW  w1, SEED1
    mov   w2, w15
    bl    Lbloom_bit
    bl    91f
    mov   x0, x13
    MOVW  w1, SEED2
    mov   w2, w15
    bl    Lbloom_bit
    bl    91f
    mov   x30, x16
    ret
91: lsr   w9, w0, #3                      /* bloom[bit >> 3] |= 1 << (bit & 7) */
    and   w10, w0, #7
    mov   w11, #1
    lsl   w11, w11, w10
    ldrb  w12, [x14, x9]
    orr   w12, w12, w11
    strb  w12, [x14, x9]
    ret

/* Ltomb_reset(lst=x0) -> 1 / -1 ; lst x19 */
    .p2align 2
Ltomb_reset:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    ldr   x9, [x19, #152]
    cbnz  x9, 2f
    ldr   x9, [x19, #72]                  /* slots: next pow2 >= 2 * max(cap, 1) */
    cmp   x9, #1
    csinc x9, x9, xzr, hs
    lsl   x9, x9, #1
    sub   x9, x9, #1
    clz   x10, x9
    mov   x11, #1
    mov   x12, #64
    sub   x10, x12, x10
    lsl   x9, x11, x10                    /* (x - 1 == 0 cannot happen: x >= 2) */
    str   x9, [sp, #24]                   /* (slots, across mmap -- in the save area) */
    mov   x0, #0
    lsl   x1, x9, #3
    mov   w2, #PROT_RW
    mov   w3, #MAP_PRIV_ANON
    mov   w4, #-1
    mov   x5, #0
    bl    _mmap
    cmn   x0, #1
    b.eq  9f
    str   x0, [x19, #152]
    ldr   x9, [sp, #24]
    sub   x9, x9, #1
    str   x9, [x19, #160]
2:  ldr   x0, [x19, #152]                 /* every slot empty (-1) */
    mov   w1, #0xff
    ldr   x2, [x19, #160]
    add   x2, x2, #1
    lsl   x2, x2, #3
    bl    _memset
    mov   x0, #1
    b     10f
9:  mov   x0, #-1
10: ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* Ltomb_probe(lst=x0, key=x1) -> x0 = the slot's address (empty -1, or the
 * index of the tomb holding key) ; lst x19, key x20, off x21, mask x22 */
    .p2align 2
Ltomb_probe:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    MOVW  w9, SEED0                       /* FNV-1a over the txid's first 8 bytes */
    MOVW  w10, 16777619
    mov   x11, #0
1:  ldrb  w12, [x20, x11]
    eor   w9, w9, w12
    mul   w9, w9, w10
    add   x11, x11, #1
    cmp   x11, #8
    b.lo  1b
    ldr   w12, [x20, #32]
    eor   w9, w9, w12
    ldr   x22, [x19, #160]
    and   x21, x9, x22
2:  ldr   x9, [x19, #152]
    add   x9, x9, x21, lsl #3
    ldr   x10, [x9]
    cmn   x10, #1
    b.eq  3f
    ldr   x11, [x19, #64]                 /* tomb + idx * 36 */
    mov   x12, #36
    madd  x0, x10, x12, x11
    mov   x1, x20
    bl    Lcmp_key
    cmp   w0, #1
    b.eq  4f
    add   x21, x21, #1
    and   x21, x21, x22
    b     2b
4:  ldr   x9, [x19, #152]
    add   x9, x9, x21, lsl #3
3:  mov   x0, x9
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* Lread_run_header(fd=w0, out=x1) -> 0 / -1 ; out: +0 gen, +8 nrec,
 * +16 bloom bytes, +24 bits mask, +32 sparse_off, +40 sparse_n,
 * +48 header size, +56 rec_v2 ; fd x19, out x20, need x21 ; frame tmp 40 */
    .p2align 2
Lread_run_header:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #48
    mov   w19, w0
    mov   x20, x1
    mov   x1, sp
    mov   x2, #4
    bl    Lread_exact
    cbnz  x0, 9f
    ldr   w9, [sp]
    MOVW  w10, MAGIC_RUN3
    mov   x22, #1
    mov   x21, #40
    cmp   w9, w10
    b.eq  1f
    MOVW  w10, MAGIC_RUN2
    mov   x22, #0
    cmp   w9, w10
    b.eq  1f
    MOVW  w10, MAGIC_RUN
    mov   x21, #24
    cmp   w9, w10
    b.ne  9f
1:  mov   w0, w19
    mov   x1, sp
    mov   x2, x21
    bl    Lread_exact
    cbnz  x0, 9f
    ldp   x9, x10, [sp]                   /* gen, nrec */
    stp   x9, x10, [x20]
    ldr   x9, [sp, #16]                   /* bloom bits */
    lsr   x10, x9, #3
    sub   x11, x9, #1
    stp   x10, x11, [x20, #16]
    cmp   x21, #40
    b.ne  2f
    ldp   x9, x10, [sp, #24]              /* sparse_off, sparse_n */
    stp   x9, x10, [x20, #32]
    mov   x9, #44
    b     3f
2:  stp   xzr, xzr, [x20, #32]
    mov   x9, #28
3:  stp   x9, x22, [x20, #48]
    mov   x0, #0
    b     10f
9:  mov   x0, #-1
10: add   sp, sp, #48
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ---- the sorts ---------------------------------------------------------- */

/* COPY64 d, s (x9..x12) */
.macro COPY64 d, s
    ldp   x9, x10, [\s]
    ldp   x11, x12, [\s, #16]
    stp   x9, x10, [\d]
    stp   x11, x12, [\d, #16]
    ldp   x9, x10, [\s, #32]
    ldp   x11, x12, [\s, #48]
    stp   x9, x10, [\d, #32]
    stp   x11, x12, [\d, #48]
.endm

/* Lmerge_sort(a=x0, b=x1, n=x2): bottom-up stable merge of 64-byte records
 * by key ; a x19, b x20, n x21, width x22, src x23, dst x24, lo x25,
 * p x26, q x27, out x28 ; frame: mid 0, hi 8 */
    .p2align 2
Lmerge_sort:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #16
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, #1
    mov   x23, x19                        /* src = a, dst = b */
    mov   x24, x20
1:  cmp   x22, x21
    b.hs  Lms_end
    mov   x25, #0
2:  cmp   x25, x21
    b.hs  Lms_pass
    add   x9, x25, x22                    /* mid, hi */
    cmp   x9, x21
    csel  x9, x9, x21, lo
    add   x10, x25, x22, lsl #1
    cmp   x10, x21
    csel  x10, x10, x21, lo
    stp   x9, x10, [sp]
    mov   x26, x25
    mov   x27, x9
    mov   x28, x25
3:  ldp   x9, x10, [sp]
    cmp   x26, x9
    b.hs  5f
    cmp   x27, x10
    b.hs  5f
    add   x0, x23, x26, lsl #6
    add   x1, x23, x27, lsl #6
    bl    Lcmp_key
    add   x13, x24, x28, lsl #6
    cmp   w0, #2
    b.ne  4f
    add   x14, x23, x27, lsl #6           /* src[p] > src[q]: take q */
    COPY64 x13, x14
    add   x27, x27, #1
    add   x28, x28, #1
    b     3b
4:  add   x14, x23, x26, lsl #6           /* else p (stable) */
    COPY64 x13, x14
    add   x26, x26, #1
    add   x28, x28, #1
    b     3b
5:  ldr   x9, [sp]                        /* the rest of p ... */
    cmp   x26, x9
    b.hs  6f
    add   x13, x24, x28, lsl #6
    add   x14, x23, x26, lsl #6
    COPY64 x13, x14
    add   x26, x26, #1
    add   x28, x28, #1
    b     5b
6:  ldr   x10, [sp, #8]                   /* ... and of q */
    cmp   x27, x10
    b.hs  7f
    add   x13, x24, x28, lsl #6
    add   x14, x23, x27, lsl #6
    COPY64 x13, x14
    add   x27, x27, #1
    add   x28, x28, #1
    b     6b
7:  add   x25, x25, x22, lsl #1
    b     2b
Lms_pass:
    lsl   x22, x22, #1
    mov   x9, x23                         /* swap src / dst */
    mov   x23, x24
    mov   x24, x9
    b     1b
Lms_end:
    cmp   x23, x19
    b.eq  8f
    mov   x0, x19                         /* the result is in b: back to a */
    mov   x1, x20
    lsl   x2, x21, #6
    bl    _memcpy
8:  add   sp, sp, #16
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* Lrs_gt(prev=x0, hold=x1) -> w0 1 if prev > hold (compact entries: hi @0,
 * idx @8, lo @12; then key bytes 12..35 through the descriptors at x17) ;
 * leaf, x9..x15 */
    .p2align 2
Lrs_gt:
    ldr   x9, [x0]
    ldr   x10, [x1]
    cmp   x9, x10
    b.ne  1f
    ldr   w9, [x0, #12]
    ldr   w10, [x1, #12]
    cmp   w9, w10
    b.ne  1f
    ldr   w11, [x0, #8]                   /* the descriptors */
    ldr   w12, [x1, #8]
    add   x11, x17, x11, lsl #6
    add   x12, x17, x12, lsl #6
    ldur  x9, [x11, #12]
    ldur  x10, [x12, #12]
    rev   x9, x9
    rev   x10, x10
    cmp   x9, x10
    b.ne  1f
    ldur  x9, [x11, #20]
    ldur  x10, [x12, #20]
    rev   x9, x9
    rev   x10, x10
    cmp   x9, x10
    b.ne  1f
    ldur  x9, [x11, #28]
    ldur  x10, [x12, #28]
    rev   x9, x9
    rev   x10, x10
    cmp   x9, x10
1:  cset  w0, hi
    ret

/* ============================================================================
 * Lrs_rec(src=x0, dst=x1, n=x2, bitoff=x3, depth=x4): MSD radix level.
 * Invariant: the sorted entries end in the FINAL (pong) region -- when the
 * data sits in ping (src < final) at a leaf, it is copied to dst. Globals:
 * x17 = the descriptor array (preserved across the recursion; set by the
 * caller), final in Lrs_final.
 * src x19, dst x20, n x21, bitoff x22, depth x23, i / start x24, digit
 * source x25 ; frame: counts[256] (2 KiB) at sp
 * ========================================================================== */
    .p2align 2
Lrs_rec:
    stp   x29, x30, [sp, #-80]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    str   x25, [sp, #64]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, x3
    mov   x23, x4
    cmp   x22, #288
    b.hs  Lrs_leaf                        /* every key bit consumed */
    cmp   x21, #RS_INS_MAX
    b.ls  Lrs_ins
    cmp   x23, #RS_MAX_DEPTH
    b.hs  Lrs_ins
    sub   sp, sp, #2048
    mov   x0, sp                          /* counts = 0 */
    mov   x1, #0
    mov   x2, #2048
    bl    _memset
    mov   x24, #0                         /* count the digits */
1:  cmp   x24, x21
    b.hs  2f
    add   x0, x19, x24, lsl #4
    bl    Lrs_digit
    ldr   x9, [sp, x0, lsl #3]
    add   x9, x9, #1
    str   x9, [sp, x0, lsl #3]
    add   x24, x24, #1
    b     1b
2:  mov   x9, #0                          /* one shared digit: the next level */
3:  ldr   x10, [sp, x9, lsl #3]
    cmp   x10, x21
    b.eq  Lrs_shared
    add   x9, x9, #1
    cmp   x9, #256
    b.lo  3b
    mov   x9, #0                          /* counts -> bucket starts */
    mov   x11, #0
4:  ldr   x10, [sp, x9, lsl #3]
    str   x11, [sp, x9, lsl #3]
    add   x11, x11, x10
    add   x9, x9, #1
    cmp   x9, #256
    b.lo  4b
    mov   x24, #0                         /* scatter src -> dst (stable) */
5:  cmp   x24, x21
    b.hs  6f
    add   x0, x19, x24, lsl #4
    bl    Lrs_digit
    ldr   x9, [sp, x0, lsl #3]
    add   x10, x19, x24, lsl #4
    ldp   x11, x12, [x10]
    add   x13, x20, x9, lsl #4
    stp   x11, x12, [x13]
    add   x9, x9, #1                      /* pos[d] -> the bucket's end */
    str   x9, [sp, x0, lsl #3]
    add   x24, x24, #1
    b     5b
6:  mov   x24, #0                         /* recurse per bucket: dst -> src */
    mov   x25, #0                         /* d */
7:  ldr   x9, [sp, x25, lsl #3]           /* end */
    cmp   x9, x24
    b.ls  8f
    str   x9, [sp, x25, lsl #3]
    add   x0, x20, x24, lsl #4
    add   x1, x19, x24, lsl #4
    sub   x2, x9, x24
    add   x3, x22, #8
    add   x4, x23, #1
    bl    Lrs_rec
    ldr   x9, [sp, x25, lsl #3]
8:  mov   x24, x9                         /* start = end */
    add   x25, x25, #1
    cmp   x25, #256
    b.lo  7b
    add   sp, sp, #2048
    b     Lrs_ret
Lrs_shared:
    add   sp, sp, #2048
    mov   x0, x19
    mov   x1, x20
    mov   x2, x21
    add   x3, x22, #8
    add   x4, x23, #1
    bl    Lrs_rec
    b     Lrs_ret
Lrs_ins:                                  /* stable insertion sort in src */
    mov   x24, #1
1:  cmp   x24, x21
    b.hs  Lrs_leaf
    add   x9, x19, x24, lsl #4            /* hold = src[i] */
    ldp   x14, x15, [x9]
    stp   x14, x15, [sp, #-16]!
    mov   x25, x24                        /* j */
2:  cbz   x25, 3f
    sub   x9, x25, #1
    add   x0, x19, x9, lsl #4             /* prev */
    mov   x1, sp                          /* hold */
    bl    Lrs_gt
    cbz   w0, 3f
    add   x9, x19, x25, lsl #4
    ldp   x10, x11, [x9, #-16]            /* shift prev up */
    stp   x10, x11, [x9]
    sub   x25, x25, #1
    b     2b
3:  ldp   x14, x15, [sp], #16
    add   x9, x19, x25, lsl #4
    stp   x14, x15, [x9]
    add   x24, x24, #1
    b     1b
Lrs_leaf:
    ADR_  x9, Lrs_final
    ldr   x9, [x9]
    cmp   x19, x9
    b.hs  Lrs_ret                         /* already in the final region */
    mov   x0, x20
    mov   x1, x19
    lsl   x2, x21, #4
    bl    _memcpy
Lrs_ret:
    ldr   x25, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

/* Lrs_digit(entry=x0) -> x0 = the 8-bit digit at bit x22 (the caller's
 * bitoff, still in x22) ; leaf, x9, x10 -- bits 0..95 from the compact
 * entry (hi, then lo), from 96 the key byte through the descriptor */
    .p2align 2
Lrs_digit:
    cmp   x22, #64
    b.hs  1f
    ldr   x9, [x0]                        /* hi: bits 0..63 */
    mov   x10, #56
    sub   x10, x10, x22
    lsr   x9, x9, x10
    and   x0, x9, #0xff
    ret
1:  cmp   x22, #96
    b.hs  2f
    ldr   w9, [x0, #12]                   /* lo: bits 64..95 */
    mov   x10, #88
    sub   x10, x10, x22
    lsr   w9, w9, w10
    and   x0, x9, #0xff
    ret
2:  ldr   w9, [x0, #8]                    /* key byte bitoff / 8 of descriptor idx */
    add   x9, x17, x9, lsl #6
    lsr   x10, x22, #3
    ldrb  w0, [x9, x10]
    ret

/* ============================================================================
 * Lrs_top16(ping=x0, pong=x1, n=x2) -> x0 0 done / 1 declined (malloc failed,
 * or one shared digit: the caller runs the 8-bit path from bit 0): the top
 * level of a large sort on a 16-bit digit (the compact hi's top 16 bits),
 * ping -> pong, then each bucket through Lrs_rec from bit 16, pong -> ping --
 * the same ping/pong discipline as Lrs_rec. The 512 KiB count array is
 * malloc'd (too big for a stack frame). x17 (the descriptors) is preserved.
 * ping x19, pong x20, n x21, counts x22, i / start x23, d x24, x17 saved x25
 * ========================================================================== */
    .p2align 2
Lrs_top16:
    stp   x29, x30, [sp, #-80]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    str   x25, [sp, #64]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x25, x17
    mov   x0, #65536
    mov   x1, #8
    bl    _calloc
    mov   x17, x25
    cbz   x0, 9f
    mov   x22, x0
    mov   x23, #0                         /* count */
1:  cmp   x23, x21
    b.hs  2f
    add   x9, x19, x23, lsl #4
    ldrh  w9, [x9, #6]                    /* hi's top 16 bits (little-endian u64) */
    ldr   x10, [x22, x9, lsl #3]
    add   x10, x10, #1
    str   x10, [x22, x9, lsl #3]
    add   x23, x23, #1
    b     1b
2:  mov   x9, #0                          /* one shared digit: decline */
3:  ldr   x10, [x22, x9, lsl #3]
    cmp   x10, x21
    b.eq  8f
    add   x9, x9, #1
    cmp   x9, #65536
    b.lo  3b
    mov   x9, #0                          /* counts -> bucket starts */
    mov   x11, #0
4:  ldr   x10, [x22, x9, lsl #3]
    str   x11, [x22, x9, lsl #3]
    add   x11, x11, x10
    add   x9, x9, #1
    cmp   x9, #65536
    b.lo  4b
    mov   x23, #0                         /* scatter ping -> pong (stable) */
5:  cmp   x23, x21
    b.hs  6f
    add   x10, x19, x23, lsl #4
    ldrh  w9, [x10, #6]
    ldr   x11, [x22, x9, lsl #3]
    ldp   x12, x13, [x10]
    add   x14, x20, x11, lsl #4
    stp   x12, x13, [x14]
    add   x11, x11, #1
    str   x11, [x22, x9, lsl #3]
    add   x23, x23, #1
    b     5b
6:  mov   x23, #0                         /* each bucket: pong -> ping from bit 16 */
    mov   x24, #0
7:  ldr   x9, [x22, x24, lsl #3]          /* end */
    cmp   x9, x23
    b.ls  71f
    add   x0, x20, x23, lsl #4
    add   x1, x19, x23, lsl #4
    sub   x2, x9, x23
    mov   x3, #16
    mov   x4, #1
    bl    Lrs_rec
    ldr   x9, [x22, x24, lsl #3]
71: mov   x23, x9
    add   x24, x24, #1
    cmp   x24, #65536
    b.lo  7b
    mov   x0, x22
    bl    _free
    mov   x17, x25
    mov   x0, #0
    b     10f
8:  mov   x0, x22
    bl    _free
    mov   x17, x25
9:  mov   x0, #1
10: ldr   x25, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

/* Lrsort(a=x0, b=x1, n=x2) ; a x19, b x20, n x21, ping x22, pong x23 */
    .p2align 2
Lrsort:
    cmp   x2, #1
    b.ls  9f
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    str   x23, [sp, #48]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    add   x22, x20, x21, lsl #5           /* ping = b + 32n */
    add   x23, x22, x21, lsl #4           /* pong = b + 48n */
    ADR_  x9, Lrs_final
    str   x23, [x9]
    mov   x9, #0                          /* compact entries */
1:  cmp   x9, x21
    b.hs  2f
    add   x10, x19, x9, lsl #6
    ldr   x11, [x10]
    rev   x11, x11
    ldr   w12, [x10, #8]
    rev   w12, w12
    add   x13, x22, x9, lsl #4
    str   x11, [x13]
    str   w9, [x13, #8]
    str   w12, [x13, #12]
    add   x9, x9, #1
    b     1b
2:  mov   x17, x19                        /* the descriptors, for the key bytes */
    mov   x9, #0x100000
    cmp   x21, x9
    b.lo  21f
    mov   x0, x22                         /* n >= 1M: a 16-bit top level first */
    mov   x1, x23
    mov   x2, x21
    bl    Lrs_top16
    cbz   x0, 22f                         /* done (else: fall back to the 8-bit path) */
21: mov   x0, x22
    mov   x1, x23
    mov   x2, x21
    mov   x3, #0
    mov   x4, #0
    bl    Lrs_rec
22:
    mov   x9, #0                          /* gather a[order] -> b */
3:  cmp   x9, x21
    b.hs  4f
    add   x10, x23, x9, lsl #4
    ldr   w10, [x10, #8]
    add   x14, x19, x10, lsl #6
    add   x13, x20, x9, lsl #6
    mov   x15, x9
    COPY64 x13, x14
    mov   x9, x15
    add   x9, x9, #1
    b     3b
4:  mov   x0, x19                         /* b -> a */
    mov   x1, x20
    lsl   x2, x21, #6
    bl    _memcpy
    ldr   x23, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
9:  ret

/* utxo_lsm_sort_desc(a=x0, b=x1, n=x2) */
    .p2align 2
    .globl _utxo_lsm_sort_desc
_utxo_lsm_sort_desc:
    cmp   x2, #1
    b.ls  1f
    ADR_  x9, Lg
    ldr   x9, [x9, #G_SORT]
    cbnz  x9, Lrsort
    b     Lmerge_sort
1:  ret

    .p2align 2
    .globl _utxo_lsm_set_sort_mode
_utxo_lsm_set_sort_mode:
    ADR_  x9, Lg
    str   x0, [x9, #G_SORT]
    ret

    .p2align 2
    .globl _utxo_lsm_set_defer_unlink
_utxo_lsm_set_defer_unlink:
    ADR_  x9, Lg
    str   x0, [x9, #G_DEFUNL]
    ret

    .p2align 2
    .globl _utxo_lsm_set_defer_publish
_utxo_lsm_set_defer_publish:
    ADR_  x9, Lg
    str   x0, [x9, #G_DEFPUB]
    ret

    .p2align 2
    .globl _utxo_lsm_set_flush_hook
_utxo_lsm_set_flush_hook:
    ADR_  x9, Lg
    str   x0, [x9, #G_HOOK]
    ret

/* ==========================================================================
 * the public API: init, flush, put, del, count, close
 * ======================================================================== */

/* Lclear_memtable(u=x0) ; leaf: empty table, same mask / blob */
    .p2align 2
Lclear_memtable:
    str   xzr, [x0]
    str   xzr, [x0, #32]
    ldr   x9, [x0, #8]
    add   x9, x9, #1
    add   x10, x0, #80
    mov   w11, #-1
1:  str   w11, [x10], #48
    subs  x9, x9, #1
    b.ne  1b
    ret

/* utxo_lsm_init(lst=x0) ; lst x19 */
    .p2align 2
    .globl _utxo_lsm_init
_utxo_lsm_init:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    bl    _lsm_mm_invalidate_all          /* a fresh instance: stale caches */
    mov   x0, x19
    bl    _utxo_store_init
    cmp   x0, #1
    b.ne  9f
    str   xzr, [x19, #40]                 /* op_count */
    str   xzr, [x19, #80]                 /* tomb_n */
    stp   xzr, xzr, [x19, #88]            /* total_live, next_gen */
    str   xzr, [x19, #120]                /* manifest_n */
    str   xzr, [x19, #144]                /* next_run_no */
    mov   x0, x19
    bl    Ltomb_reset
    cmp   x0, #1
    b.ne  9f
    mov   x0, #1
    b     10f
9:  mov   x0, #-1
10: ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* ============================================================================
 * Lflush(lst=x0, u=x1): the memtable's live entries + this generation's
 * not-live-again tombstones -> a new MAGIC_RUN3 run; publish the manifest;
 * reset the WAL; clear the memtable and the tombstones.
 * lst x19, u x20, n_desc x21, desc (scratch) x22, desc_cap x23, i x24,
 * fd x25, bloom bits x26, sparse_n x27, sparse buffer x28 ;
 * frame: hdr 0 (48), runname 48 (32), get outputs 80 (48),
 *        manifest hdr 128 (24) -> 160
 * ========================================================================== */
#define FL_HDR    0
#define FL_NAME   48
#define FL_GET    80
#define FL_MH     128
#define FL_SIZE   160

    .p2align 2
Lflush:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #FL_SIZE
    mov   x19, x0
    mov   x20, x1
    ADR_  x9, Lg                          /* the flush hook FIRST */
    ldr   x9, [x9, #G_HOOK]
    cbz   x9, 1f
    blr   x9
1:  mov   x0, x19
    bl    _utxo_store_wal_drain
    cmn   x0, #1
    b.eq  Lfl_no
    ldr   x9, [x19, #136]                 /* desc_cap = (cap - bloom - script) / 128 */
    MOVW  x10, (BLOOM_MAX_BYTES + SCRIPT_MAX)
    mov   x23, #0
    subs  x9, x9, x10
    b.lo  2f
    lsr   x23, x9, #7
2:  ldr   x22, [x19, #128]                /* desc = scratch */
    mov   x21, #0
    /* the memtable's live slots -> PUSH descriptors */
    ldr   x24, [x20, #8]
    add   x24, x24, #1                    /* slots left */
    add   x9, x20, #40                    /* slot pointer (x9..x15 scratch below) */
    ldr   x15, [x20, #16]                 /* blob */
3:  cbz   x24, 5f
    ldr   w10, [x9, #40]
    cmn   w10, #1
    b.eq  4f
    cmp   x21, x23
    b.hs  Lfl_no                          /* out of descriptor room */
    add   x11, x22, x21, lsl #6           /* d */
    ldp   x12, x13, [x9, #8]              /* txid */
    stp   x12, x13, [x11]
    ldp   x12, x13, [x9, #24]
    stp   x12, x13, [x11, #16]
    str   w10, [x11, #32]                 /* index */
    mov   w12, #1
    strb  w12, [x11, #36]                 /* PUSH */
    ldr   x12, [x9]
    add   x12, x15, x12                   /* the record */
    ldp   x13, x14, [x12]                 /* value, height | cb << 32 */
    str   x13, [x11, #40]
    stur  w14, [x11, #50]
    lsr   x14, x14, #32
    strb  w14, [x11, #54]
    ldr   x13, [x12, #16]
    strh  w13, [x11, #48]                 /* (u16) slen */
    add   x12, x12, #24
    str   x12, [x11, #56]                 /* script pointer */
    add   x21, x21, #1
4:  add   x9, x9, #48
    sub   x24, x24, #1
    b     3b
5:  /* tombstones -> DEL descriptors, unless the key is live again */
    mov   x24, #0
6:  ldr   x9, [x19, #80]
    cmp   x24, x9
    b.hs  8f
    ldr   x9, [x19, #64]
    mov   x10, #36
    madd  x25, x24, x10, x9               /* key (x25 free until the file opens) */
    mov   x0, x20
    mov   x1, x25
    ldr   w2, [x25, #32]
    add   x3, sp, #FL_GET
    add   x4, sp, #FL_GET + 8
    add   x5, sp, #FL_GET + 16
    add   x6, sp, #FL_GET + 24
    add   x7, sp, #FL_GET + 32
    bl    _utxo_get
    cmp   x0, #1
    b.eq  7f                              /* still live: skip */
    cmp   x21, x23
    b.hs  Lfl_no
    add   x11, x22, x21, lsl #6
    ldp   x12, x13, [x25]
    stp   x12, x13, [x11]
    ldp   x12, x13, [x25, #16]
    stp   x12, x13, [x11, #16]
    ldr   w12, [x25, #32]
    str   w12, [x11, #32]
    mov   w12, #2
    strb  w12, [x11, #36]                 /* DEL */
    add   x21, x21, #1
7:  add   x24, x24, #1
    b     6b
8:  cbz   x21, Lfl_reset                  /* nothing to write */
    ldp   x9, x10, [x19, #112]            /* manifest cap, n */
    cmp   x10, x9
    b.hs  Lfl_no
    mov   x0, x22                         /* sort by key */
    add   x1, x22, x23, lsl #6
    mov   x2, x21
    bl    _utxo_lsm_sort_desc
    /* the bloom: max(64, 10n) up to a power of two, capped */
    mov   x9, #10
    mul   x9, x21, x9
    cmp   x9, #64
    mov   x10, #64
    csel  x9, x9, x10, hs
    mov   x26, #1
9:  cmp   x26, x9
    b.hs  10f
    lsl   x26, x26, #1
    b     9b
10: mov   x9, #(BLOOM_MAX_BYTES * 8)
    cmp   x26, x9
    csel  x26, x26, x9, ls
    add   x0, x22, x23, lsl #7            /* the bloom at scratch + 2 * desc_cap * 64 */
    mov   x1, #0
    lsr   x2, x26, #3
    bl    _memset
    mov   x24, #0
11: cmp   x24, x21
    b.hs  12f
    add   x0, x22, x24, lsl #6
    add   x1, x22, x23, lsl #7
    sub   w2, w26, #1
    bl    Lbloom_set3
    add   x24, x24, #1
    b     11b
12: /* the run file */
    add   x0, sp, #FL_NAME
    ldr   w1, [x19, #144]
    bl    Lfmt_runname
    add   x0, sp, #FL_NAME
    mov   w1, #(O_WRONLY | O_CREAT | O_TRUNC)
    bl    Lopen3
    tbnz  w0, #31, Lfl_no
    mov   w25, w0
    ADR_  x9, Lg
    str   xzr, [x9, #G_FLFILL]
    MOVW  w9, MAGIC_RUN3                  /* header: magic gen nrec bits 0 0 */
    str   w9, [sp, #FL_HDR]
    ldr   x9, [x19, #96]
    stur  x9, [sp, #FL_HDR + 4]
    stur  x21, [sp, #FL_HDR + 12]
    stur  x26, [sp, #FL_HDR + 20]
    stur  xzr, [sp, #FL_HDR + 28]
    stur  xzr, [sp, #FL_HDR + 36]
    mov   w0, w25
    add   x1, sp, #FL_HDR
    mov   x2, #44
    bl    Lwrite_exact
    cbnz  x0, Lfl_fail
    mov   w0, w25
    add   x1, x22, x23, lsl #7
    lsr   x2, x26, #3
    bl    Lwrite_exact
    cbnz  x0, Lfl_fail
    add   x28, x22, x23, lsl #6           /* the sparse staging: the pong slack */
    mov   x27, #0
    mov   x24, #0
13: cmp   x24, x21
    b.hs  15f
    tst   x24, #(SPARSE_STRIDE - 1)
    b.ne  14f
    mov   w0, w25                         /* the record's LOGICAL offset */
    mov   x1, #0
    mov   w2, #SEEK_CUR
    bl    _lseek
    tbnz  x0, #63, Lfl_fail
    ADR_  x9, Lg
    ldr   x9, [x9, #G_FLFILL]
#ifndef LSM_REPRO_BAD_SPARSE
    add   x0, x0, x9                      /* fd offset + bytes still buffered */
#endif
    mov   x9, #SPARSE_ENT
    madd  x10, x27, x9, x28
    add   x11, x22, x24, lsl #6
    ldp   x12, x13, [x11]
    stp   x12, x13, [x10]
    ldp   x12, x13, [x11, #16]
    stp   x12, x13, [x10, #16]
    ldr   w12, [x11, #32]
    str   w12, [x10, #32]
    stur  x0, [x10, #36]
    add   x27, x27, #1
14: mov   w0, w25                         /* key + type */
    add   x1, x22, x24, lsl #6
    mov   x2, #37
    bl    Lfl_write
    cbnz  x0, Lfl_fail
    add   x9, x22, x24, lsl #6
    ldrb  w10, [x9, #36]
    cmp   w10, #1
    b.ne  141f
    mov   w0, w25                         /* PUSH: value slen height cb */
    add   x1, x9, #40
    mov   x2, #15
    bl    Lfl_write
    cbnz  x0, Lfl_fail
    add   x9, x22, x24, lsl #6
    ldrh  w2, [x9, #48]
    cbz   w2, 141f
    mov   w0, w25
    ldr   x1, [x9, #56]
    bl    Lfl_write
    cbnz  x0, Lfl_fail
141: add  x24, x24, #1
    b     13b
15: mov   w0, w25
    bl    Lfl_drain
    cbnz  x0, Lfl_fail
    mov   w0, w25                         /* the sparse index after the records */
    mov   x1, #0
    mov   w2, #SEEK_CUR
    bl    _lseek
    tbnz  x0, #63, Lfl_fail
    stur  x0, [sp, #FL_HDR + 28]
    stur  x27, [sp, #FL_HDR + 36]
    cbz   x27, 16f
    mov   w0, w25
    mov   x1, x28
    mov   x9, #SPARSE_ENT
    mul   x2, x27, x9
    bl    Lwrite_exact
    cbnz  x0, Lfl_fail
16: mov   w0, w25                         /* patch sparse_off / sparse_n */
    mov   x1, #28
    mov   w2, #SEEK_SET
    bl    _lseek
    tbnz  x0, #63, Lfl_fail
    mov   w0, w25
    add   x1, sp, #FL_HDR + 28
    mov   x2, #16
    bl    Lwrite_exact
    cbnz  x0, Lfl_fail
    mov   w0, w25
    bl    _fsync
    mov   w0, w25
    bl    _close
    /* the manifest: append, publish */
    ldp   x9, x10, [x19, #112]
    cmp   x10, x9
    b.hs  Lfl_no
    ldr   x11, [x19, #104]
    add   x11, x11, x10, lsl #4
    ldr   x12, [x19, #96]                 /* gen */
    ldr   x13, [x19, #144]                /* run_no */
    stp   x12, x13, [x11]
    add   x10, x10, #1
    str   x10, [x19, #120]
    add   x12, x12, #1
    str   x12, [x19, #96]
    add   x13, x13, #1
    str   x13, [x19, #144]
    ADR_  x0, Lman_tmp
    mov   w1, #(O_WRONLY | O_CREAT | O_TRUNC)
    bl    Lopen3
    tbnz  w0, #31, Lfl_no
    mov   w25, w0
    MOVW  w9, MAGIC_MANIFEST2             /* runs-only live count: the memtable */
    str   w9, [sp, #FL_MH]                /* is folded, the WAL resets below */
    ldr   x9, [x19, #120]
    stur  x9, [sp, #FL_MH + 4]
    ldr   x9, [x19, #88]
    stur  x9, [sp, #FL_MH + 12]
    mov   w0, w25
    add   x1, sp, #FL_MH
    mov   x2, #20
    bl    Lwrite_exact
    cbnz  x0, 17f
    mov   w0, w25
    ldr   x1, [x19, #104]
    ldr   x2, [x19, #120]
    lsl   x2, x2, #4
    bl    Lwrite_exact
    cbz   x0, 18f
17: mov   w0, w25
    bl    _close
    b     Lfl_no
18: mov   w0, w25
    bl    _fsync
    mov   w0, w25
    bl    _close
    ADR_  x0, Lman_tmp
    ADR_  x1, Lman_name
    bl    _rename
    tbnz  w0, #31, Lfl_no
    bl    Lfsync_dir
Lfl_reset:
    ldr   x0, [x19]                       /* UTX-8: the WAL reset first */
    mov   x1, #0
    bl    _ftruncate
    tbnz  w0, #31, Lfl_no
    ldr   x0, [x19]
    mov   x1, #0
    mov   w2, #SEEK_SET
    bl    _lseek
    tbnz  x0, #63, Lfl_no
    str   xzr, [x19, #16]
    mov   x0, x20
    bl    Lclear_memtable
    str   xzr, [x19, #40]
    str   xzr, [x19, #80]
    mov   x0, x19
    bl    Ltomb_reset
    cmp   x0, #1
    b.ne  Lfl_no
    mov   x0, #1
    b     Lfl_ret
Lfl_fail:
    mov   w0, w25
    bl    _close
Lfl_no:
    mov   x0, #-1
Lfl_ret:
    add   sp, sp, #FL_SIZE
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

    .p2align 2
    .globl _utxo_lsm_flush
_utxo_lsm_flush:
    b     Lflush

/* Lmaybe_flush(lst=x0, u=x1) -> x0 0 / -1: flush when op_count >= its
 * threshold or the memtable holds >= the fill threshold */
    .p2align 2
Lmaybe_flush:
    ldr   x9, [x0, #40]
    ldr   x10, [x0, #48]
    cmp   x9, x10
    b.hs  1f
    ldr   x9, [x1]
    ldr   x10, [x0, #56]
    cmp   x9, x10
    b.hs  1f
    mov   x0, #0
    ret
1:  stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    bl    Lflush
    cmn   x0, #1
    mov   x9, #0
    csel  x0, x0, x9, eq                  /* -1 stays, 1 -> 0 */
    ldp   x29, x30, [sp], #16
    ret

/* utxo_lsm_put(lst, u, txid, index, value, height, cb, script, slen=[sp])
 * lst x19, u x20, r x21 */
    .p2align 2
    .globl _utxo_lsm_put
_utxo_lsm_put:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    ldr   w9, [x29, #48]                  /* slen: the u32 9th argument */
    sub   sp, sp, #16
    str   w9, [sp]                        /* ... passed on as the 9th again */
    bl    _utxo_store_put
    add   sp, sp, #16
    mov   x21, x0
    cmp   x21, #1
    b.ne  1f
    ldr   x9, [x19, #88]                  /* total_live++ on a new coin */
    add   x9, x9, #1
    str   x9, [x19, #88]
1:  ldr   x9, [x19, #40]                  /* op_count++ */
    add   x9, x9, #1
    str   x9, [x19, #40]
    mov   x0, x19
    mov   x1, x20
    bl    Lmaybe_flush
    cmn   x0, #1
    csel  x0, x0, x21, eq
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* utxo_lsm_del(lst, u, txid, index=w3) ; lst x19, u x20, txid x21, index x22 */
    .p2align 2
    .globl _utxo_lsm_del
_utxo_lsm_del:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   w22, w3
    bl    _utxo_store_del
    cmn   x0, #1
    b.eq  9f
    ldp   x9, x10, [x19, #72]             /* tomb cap, n */
    cmp   x10, x9
    b.hs  9f
    ldr   x11, [x19, #64]                 /* append at tomb[n] */
    mov   x12, #36
    madd  x11, x10, x12, x11
    ldp   x12, x13, [x21]
    stp   x12, x13, [x11]
    ldp   x12, x13, [x21, #16]
    stp   x12, x13, [x11, #16]
    str   w22, [x11, #32]
    mov   x0, x19                         /* one tombstone per key per generation */
    mov   x1, x11
    bl    Ltomb_probe
    ldr   x9, [x0]
    cmn   x9, #1
    b.ne  1f
    ldr   x10, [x19, #80]
    str   x10, [x0]
    add   x10, x10, #1
    str   x10, [x19, #80]
1:  ldr   x9, [x19, #40]
    add   x9, x9, #1
    str   x9, [x19, #40]
    ldr   x9, [x19, #88]
    sub   x9, x9, #1
    str   x9, [x19, #88]
    mov   x0, x19
    mov   x1, x20
    bl    Lmaybe_flush
    cmn   x0, #1
    b.eq  9f
    mov   x0, #1
    b     10f
9:  mov   x0, #-1
10: ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

    .p2align 2
    .globl _utxo_lsm_count
_utxo_lsm_count:
    ldr   x0, [x0, #88]
    ret

    .p2align 2
    .globl _utxo_lsm_close
_utxo_lsm_close:
    b     _utxo_store_close

/* ==========================================================================
 * point lookups
 * ======================================================================== */

/* ============================================================================
 * Lrun_lookup(lst=x0, run_no=w1, gen=x2, txid=x3, index=w4, out=x5)
 *   -> 1 found / 0 absent / 2 tombstone / -1 error ;
 *   out: +0 value, +8 height u32, +12 cb u32, +16 script ptr, +24 slen u32
 * lst x19, run_no x20, txid x21, index x22, out x23, fd x24, lo x25, hi x26,
 * pos x27, rec_v2 x28 ; frame (sp-relative):
 *   mm outs 0 (v 0, h 8, cb 16, script 24, slen 32) -> 48
 *   key 48 (48), hdr 96 (64), name 160 (32), rec 192 (48), vp 240 (16),
 *   ent 256 (48), stat 304 (144), byte 448 (16) -> 464
 * (the 10-argument mm call puts its 9th/10th at [sp], [sp+8] of a 16-byte
 *  outgoing area below the frame)
 * ========================================================================== */
#define RL_MM     0
#define RL_KEY    48
#define RL_HDR    96
#define RL_NAME   160
#define RL_REC    192
#define RL_VP     240
#define RL_ENT    256
#define RL_STAT   304
#define RL_BYTE   448
#define RL_SIZE   464

    .p2align 2
Lrun_lookup:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #RL_SIZE
    mov   x19, x0
    mov   w20, w1
    mov   x21, x3
    mov   w22, w4
    mov   x23, x5
    str   xzr, [sp, #RL_MM + 32]          /* msl = 0 */
    /* the vendored mmap fast path first */
    sub   sp, sp, #16
    add   x9, sp, #16 + RL_MM + 24        /* &script */
    add   x10, sp, #16 + RL_MM + 32       /* &slen */
    stp   x9, x10, [sp]
    mov   x0, x19
    mov   w1, w20                         /* run_no (u64, zero-extended) */
    mov   x3, x21
    mov   w4, w22
    add   x5, sp, #16 + RL_MM
    add   x6, sp, #16 + RL_MM + 8
    add   x7, sp, #16 + RL_MM + 16
    bl    _lsm_run_lookup_mm              /* (x2 = gen still) */
    add   sp, sp, #16
    cmn   x0, #2
    b.eq  Lrl_fallback                    /* declined: the file path */
    cmp   x0, #1
    b.ne  Lrl_ret
    ldr   x9, [sp, #RL_MM]
    str   x9, [x23]
    ldr   x9, [sp, #RL_MM + 8]
    str   w9, [x23, #8]
    ldr   x9, [sp, #RL_MM + 16]
    str   w9, [x23, #12]
    ldr   x9, [sp, #RL_MM + 24]
    str   x9, [x23, #16]
    ldr   w9, [sp, #RL_MM + 32]
    str   w9, [x23, #24]
    b     Lrl_ret
Lrl_fallback:
    add   x0, sp, #RL_NAME
    mov   w1, w20
    bl    Lfmt_runname
    add   x0, sp, #RL_NAME
    mov   w1, #O_RDONLY
    bl    _open
    tbnz  w0, #31, Lrl_err
    mov   w24, w0
    add   x1, sp, #RL_HDR
    bl    Lread_run_header
    cbnz  x0, Lrl_errc
    ldp   x9, x10, [x21]                  /* key = txid || index */
    stp   x9, x10, [sp, #RL_KEY]
    ldp   x9, x10, [x21, #16]
    stp   x9, x10, [sp, #RL_KEY + 16]
    str   w22, [sp, #RL_KEY + 32]
    ldr   x9, [sp, #RL_HDR + 16]          /* bloom bytes */
    mov   x10, #BLOOM_MAX_BYTES
    cmp   x9, x10
    b.hi  Lrl_errc
    mov   w0, w24                         /* the whole bloom must be there */
    add   x1, sp, #RL_STAT
    bl    _fstat
    tbnz  w0, #31, Lrl_errc
    ldr   x9, [sp, #RL_STAT + 96]         /* st_size */
    ldr   x10, [sp, #RL_HDR + 48]         /* header size */
    ldr   x11, [sp, #RL_HDR + 16]
    add   x10, x10, x11
    cmp   x9, x10
    b.lo  Lrl_errc
    /* the three bloom bits, one byte each */
    MOVW  w25, SEED0
    bl    Lrl_bit
    cbz   w0, Lrl_absent
    MOVW  w25, SEED1
    bl    Lrl_bit
    cbz   w0, Lrl_absent
    MOVW  w25, SEED2
    bl    Lrl_bit
    cbz   w0, Lrl_absent
    ldr   x27, [sp, #RL_HDR + 48]         /* pos = records start */
    ldr   x9, [sp, #RL_HDR + 16]
    add   x27, x27, x9
    ldr   x9, [sp, #RL_HDR + 40]          /* sparse_n */
    cbz   x9, 3f
    mov   x25, #0                         /* binary search: lo, hi */
    sub   x26, x9, #1
1:  cmp   x25, x26
    b.hi  3f
    sub   x9, x26, x25
    add   x28, x25, x9, lsr #1            /* mid (x28 until rec_v2 is set) */
    mov   w0, w24
    add   x1, sp, #RL_ENT
    mov   x2, #SPARSE_ENT
    ldr   x3, [sp, #RL_HDR + 32]
    mov   x9, #SPARSE_ENT
    madd  x3, x28, x9, x3
    bl    _pread
    cmp   x0, #SPARSE_ENT
    b.ne  Lrl_errc
    add   x0, sp, #RL_ENT
    add   x1, sp, #RL_KEY
    bl    Lcmp_key
    cmp   w0, #2
    b.ne  2f
    cbz   x28, 3f                         /* entry > key: left half */
    sub   x26, x28, #1
    b     1b
2:  add   x9, sp, #RL_ENT                 /* entry <= key: its offset, right half */
    ldur  x27, [x9, #36]
    add   x25, x28, #1
    b     1b
3:  mov   w0, w24                         /* to the scan start */
    mov   x1, x27
    mov   w2, #SEEK_SET
    bl    _lseek
    tbnz  x0, #63, Lrl_errc
    ldr   x28, [sp, #RL_HDR + 56]         /* rec_v2 */
4:  mov   w0, w24                         /* the forward scan */
    add   x1, sp, #RL_REC
    mov   x2, #37
    bl    Lread_exact
    cbnz  x0, Lrl_absent                  /* EOF: absent */
    add   x0, sp, #RL_REC
    add   x1, sp, #RL_KEY
    bl    Lcmp_key
    cmp   w0, #1
    b.eq  6f
    cmp   w0, #2
    b.eq  Lrl_absent                      /* sorted: past it */
    ldrb  w9, [sp, #RL_REC + 36]
    cmp   w9, #1
    b.ne  4b                              /* a tombstone: header only */
    bl    Lrl_vp                          /* skip a PUSH's value part + script */
    cbnz  x0, Lrl_errc
    ldrh  w1, [sp, #RL_VP + 8]
    cbz   w1, 4b
    mov   w0, w24
    mov   w2, #SEEK_CUR
    bl    _lseek
    tbnz  x0, #63, Lrl_errc
    b     4b
6:  ldrb  w9, [sp, #RL_REC + 36]
    cmp   w9, #2
    b.eq  Lrl_tomb
    bl    Lrl_vp
    cbnz  x0, Lrl_errc
    ldrh  w26, [sp, #RL_VP + 8]           /* slen */
    adrp  x0, _bmc_lsm_script_tlv@TLVPPAGE
    ldr   x0, [x0, _bmc_lsm_script_tlv@TLVPPAGEOFF]
    ldr   x8, [x0]
    blr   x8                              /* this thread's script buffer */
    mov   x25, x0
    cbz   w26, 7f
    mov   w0, w24
    mov   x1, x25
    mov   w2, w26
    bl    Lread_exact
    cbnz  x0, Lrl_errc
7:  ldr   x9, [sp, #RL_VP]
    str   x9, [x23]                       /* value */
    mov   w9, #0
    mov   w10, #0
    cbz   x28, 8f
    ldur  w9, [sp, #RL_VP + 10]           /* height, cb (v2 records only) */
    ldrb  w10, [sp, #RL_VP + 14]
8:  stp   w9, w10, [x23, #8]
    str   x25, [x23, #16]
    str   w26, [x23, #24]
    mov   w0, w24
    bl    _close
    mov   x0, #1
    b     Lrl_ret
Lrl_tomb:
    mov   w0, w24
    bl    _close
    mov   x0, #2
    b     Lrl_ret
Lrl_absent:
    mov   w0, w24
    bl    _close
    mov   x0, #0
    b     Lrl_ret
Lrl_errc:
    mov   w0, w24
    bl    _close
Lrl_err:
    mov   x0, #-1
Lrl_ret:
    add   sp, sp, #RL_SIZE
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* Lrl_bit: w0 = the bloom bit for seed w25 (Lrun_lookup's frame, fd w24),
 * 0 on a failed read too (the file length was checked) */
Lrl_bit:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    add   x0, sp, #16 + RL_KEY
    mov   w1, w25
    ldr   x2, [sp, #16 + RL_HDR + 24]     /* bits mask (u32) */
    bl    Lbloom_bit
    mov   w26, w0                         /* (x26 free before the search) */
    mov   w0, w24
    add   x1, sp, #16 + RL_BYTE
    mov   x2, #1
    ldr   x3, [sp, #16 + RL_HDR + 48]     /* header size + bit >> 3 */
    add   x3, x3, x26, lsr #3
    bl    _pread
    cmp   x0, #1
    b.ne  1f
    ldrb  w9, [sp, #16 + RL_BYTE]
    and   w10, w26, #7
    lsr   w9, w9, w10
    and   w0, w9, #1
    b     2f
1:  mov   w0, #0
2:  ldp   x29, x30, [sp], #16
    ret

/* Lrl_vp: read a PUSH's value part (15 bytes v2, 10 v1) into RL_VP ->
 * x0 0 / -1 (Lrun_lookup's frame; rec_v2 in x28, fd w24) */
Lrl_vp:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    mov   w0, w24
    add   x1, sp, #16 + RL_VP
    cmp   x28, #0
    mov   x2, #10
    mov   x9, #15
    csel  x2, x9, x2, ne
    bl    Lread_exact
    ldp   x29, x30, [sp], #16
    ret

/* ============================================================================
 * utxo_lsm_get(lst, u, txid, index=w3, value, height, cb, script, slen=[sp])
 * lst x19, txid x20, index x21, outs x22..x26, i x27 ; frame: key 0 (48),
 * run out 48 (32) -> 80
 * ========================================================================== */
    .p2align 2
    .globl _utxo_lsm_get
_utxo_lsm_get:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    str   x27, [sp, #80]
    mov   x29, sp
    ldr   x26, [x29, #96]                 /* slen*: the 9th argument */
    sub   sp, sp, #80
    mov   x19, x0
    mov   x20, x2
    mov   w21, w3
    mov   x22, x4
    mov   x23, x5
    mov   x24, x6
    mov   x25, x7
    mov   x0, x1                          /* the memtable first (outputs on a hit only) */
    mov   x1, x20
    mov   w2, w21
    mov   x3, x22
    mov   x4, x23
    mov   x5, x24
    mov   x6, x25
    mov   x7, x26
    bl    _utxo_get
    cmp   x0, #1
    b.eq  Lg_ret
    ldp   x9, x10, [x20]                  /* this generation's tombstones shadow */
    stp   x9, x10, [sp]
    ldp   x9, x10, [x20, #16]
    stp   x9, x10, [sp, #16]
    str   w21, [sp, #32]
    mov   x0, x19
    mov   x1, sp
    bl    Ltomb_probe
    ldr   x9, [x0]
    cmn   x9, #1
    b.ne  Lg_zero
    ldr   x27, [x19, #120]                /* the runs, newest manifest index first */
1:  cbz   x27, Lg_zero
    sub   x27, x27, #1
    ldr   x9, [x19, #104]
    add   x9, x9, x27, lsl #4
    ldp   x2, x10, [x9]                   /* gen, run_no */
    mov   x0, x19
    mov   w1, w10
    mov   x3, x20
    mov   w4, w21
    add   x5, sp, #48
    bl    Lrun_lookup
    cmp   x0, #1
    b.eq  2f
    cmp   x0, #2
    b.eq  Lg_zero                         /* tombstoned in this run */
    cmn   x0, #1
    b.eq  Lg_ret
    b     1b
2:  ldr   x9, [sp, #48]
    str   x9, [x22]
    ldp   w9, w10, [sp, #56]
    str   x9, [x23]                       /* (u32 -> ulong) */
    str   x10, [x24]
    ldr   x9, [sp, #64]
    str   x9, [x25]                       /* valid until this thread's next get */
    ldr   w9, [sp, #72]
    str   x9, [x26]
    mov   x0, #1
    b     Lg_ret
Lg_zero:
    mov   x0, #0
Lg_ret:
    add   sp, sp, #80
    ldr   x27, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* ==========================================================================
 * the k-way merge inputs, recount, walk
 * ======================================================================== */

/* Lslot_read(slot=x0, dst=x1, len=x2) -> 0 / -1: through the slot's 256 KiB
 * read-ahead ; slot x19, dst x20, len x21 */
    .p2align 2
Lslot_read:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
1:  cbz   x21, 3f
    ldp   x9, x10, [x19, #SL_FILL]        /* fill, pos */
    subs  x22, x9, x10                    /* avail */
    b.ne  2f
    ldr   w0, [x19, #SL_FD]               /* refill */
    add   x1, x19, #(SL_RDBUF >> 12), lsl #12
    add   x1, x1, #(SL_RDBUF & 0xfff)
    mov   x2, #RDBUF
    bl    _read
    cmp   x0, #0
    b.le  9f
    stp   x0, xzr, [x19, #SL_FILL]
    b     1b
2:  cmp   x22, x21
    csel  x22, x22, x21, lo               /* take */
    add   x1, x19, #(SL_RDBUF >> 12), lsl #12
    add   x1, x1, #(SL_RDBUF & 0xfff)
    add   x1, x1, x10
    mov   x0, x20
    mov   x2, x22
    bl    _memcpy
    ldr   x10, [x19, #SL_POS]
    add   x10, x10, x22
    str   x10, [x19, #SL_POS]
    add   x20, x20, x22
    sub   x21, x21, x22
    b     1b
3:  mov   x0, #0
    b     10f
9:  mov   x0, #-1
10: ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* Lslot_rec(slot=x0) -> 1 / -1: the next record into the slot ; slot x19 ;
 * frame vp 0 (16) */
    .p2align 2
Lslot_rec:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #16
    mov   x19, x0
    add   x1, x19, #SL_KEY
    mov   x2, #37
    bl    Lslot_read
    cbnz  x0, 9f
    ldrb  w9, [x19, #SL_TYPE]
    cmp   w9, #1
    b.ne  3f
    mov   x0, x19                         /* PUSH: the value part */
    mov   x1, sp
    ldr   w9, [x19, #SL_V2]
    cmp   w9, #0
    mov   x2, #10
    mov   x10, #15
    csel  x2, x10, x2, ne
    bl    Lslot_read
    cbnz  x0, 9f
    ldr   x9, [sp]
    str   x9, [x19, #SL_VALUE]
    ldrh  w9, [sp, #8]
    str   w9, [x19, #SL_SLEN]
    mov   w10, #0
    mov   w11, #0
    ldr   w12, [x19, #SL_V2]
    cbz   w12, 1f
    ldur  w10, [sp, #10]
    ldrb  w11, [sp, #14]
1:  str   w10, [x19, #SL_HEIGHT]
    str   w11, [x19, #SL_CB]
    cbz   w9, 3f
    mov   x0, x19
    add   x1, x19, #SL_SCRIPT
    mov   w2, w9
    bl    Lslot_read
    cbnz  x0, 9f
3:  mov   w9, #1
    str   w9, [x19, #SL_ACTIVE]
    ldr   x9, [x19, #SL_REM]
    sub   x9, x9, #1
    str   x9, [x19, #SL_REM]
    mov   x0, #1
    b     10f
9:  mov   x0, #-1
10: add   sp, sp, #16
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* Lslots_open(lst=x0, slots=x1, first=x2, count=x3) -> x0 the summed nrec,
 * or -1: open each manifest entry's run, read its header, skip the bloom,
 * prime the first record ; lst x19, slots x20, first x21, count x22, i x23,
 * sum x24, slot x25 ; frame: hdr 0 (64), name 64 (32) */
    .p2align 2
Lslots_open:
    stp   x29, x30, [sp, #-80]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    str   x25, [sp, #64]
    mov   x29, sp
    sub   sp, sp, #96
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, x3
    mov   x23, #0                         /* every fd -1 first (the cleanup closes >= 0) */
1:  cmp   x23, x22
    b.hs  2f
    MOVW  x9, SL_SIZE
    madd  x25, x23, x9, x20
    mov   w9, #-1
    str   w9, [x25, #SL_FD]
    add   x23, x23, #1
    b     1b
2:  mov   x23, #0
    mov   x24, #0
3:  cmp   x23, x22
    b.hs  5f
    MOVW  x9, SL_SIZE
    madd  x25, x23, x9, x20
    ldr   x9, [x19, #104]
    add   x10, x21, x23
    add   x9, x9, x10, lsl #4
    ldp   x10, x11, [x9]                  /* gen, run_no */
    stp   x10, x11, [x25, #SL_GEN]
    add   x0, sp, #64
    mov   w1, w11
    bl    Lfmt_runname
    add   x0, sp, #64
    mov   w1, #O_RDONLY
    bl    _open
    str   w0, [x25, #SL_FD]
    tbnz  w0, #31, 9f
    mov   x1, sp
    bl    Lread_run_header
    cbnz  x0, 9f
    ldr   x9, [sp, #8]                    /* nrec */
    str   x9, [x25, #SL_REM]
    add   x24, x24, x9
    ldr   x9, [sp, #56]
    str   w9, [x25, #SL_V2]
    ldr   w0, [x25, #SL_FD]               /* skip the bloom */
    ldr   x1, [sp, #16]
    mov   w2, #SEEK_CUR
    bl    _lseek
    tbnz  x0, #63, 9f
    ldr   x9, [x25, #SL_REM]
    cbz   x9, 4f
    mov   x0, x25
    bl    Lslot_rec
    cmn   x0, #1
    b.eq  9f
4:  add   x23, x23, #1
    b     3b
5:  mov   x0, x24
    b     10f
9:  mov   x0, #-1
10: add   sp, sp, #96
    ldr   x25, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

/* Lslots_close(slots=x0, count=x1): close every fd >= 0 ; slots x19,
 * count x20, i x21 */
    .p2align 2
Lslots_close:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, #0
1:  cmp   x21, x20
    b.hs  2f
    MOVW  x9, SL_SIZE
    madd  x9, x21, x9, x19
    ldr   w0, [x9, #SL_FD]
    tbnz  w0, #31, 11f
    bl    _close
11: add   x21, x21, #1
    b     1b
2:  ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* Lmerge_best(slots=x0, count=x1) -> x0 the winning slot or 0: the least
 * key among the active slots, ties to the HIGHER index (the newest manifest
 * entry: UTX-1) ; slots x19, count x20, i x21, best x22 */
    .p2align 2
Lmerge_best:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, #0
    mov   x22, #0
1:  cmp   x21, x20
    b.hs  3f
    MOVW  x9, SL_SIZE
    madd  x9, x21, x9, x19
    ldr   w10, [x9, #SL_ACTIVE]
    cbz   w10, 2f
    cbz   x22, 11f
    add   x0, x9, #SL_KEY                 /* this <= best: this wins */
    add   x1, x22, #SL_KEY
    str   x9, [sp, #-16]!
    bl    Lcmp_key
    ldr   x9, [sp], #16
    cmp   w0, #2
    b.eq  2f
11: mov   x22, x9
2:  add   x21, x21, #1
    b     1b
3:  mov   x0, x22
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* Lmerge_advance(slots=x0, count=x1, key=x2) -> 0 / -1: past EVERY copy of
 * key in every active slot (x86 174d7db7) ; slots x19, count x20, key x21,
 * i x22, slot x23 */
    .p2align 2
Lmerge_advance:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    str   x23, [sp, #48]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, #0
1:  cmp   x22, x20
    b.hs  4f
    MOVW  x9, SL_SIZE
    madd  x23, x22, x9, x19
2:  ldr   w9, [x23, #SL_ACTIVE]
    cbz   w9, 3f
    add   x0, x23, #SL_KEY
    mov   x1, x21
    bl    Lcmp_key
    cmp   w0, #1
    b.ne  3f
    ldr   x9, [x23, #SL_REM]
    cbnz  x9, 21f
    str   wzr, [x23, #SL_ACTIVE]          /* drained */
    b     3f
21: mov   x0, x23
    bl    Lslot_rec
    cmn   x0, #1
    b.eq  9f
    b     2b
3:  add   x22, x22, #1
    b     1b
4:  mov   x0, #0
    b     10f
9:  mov   x0, #-1
10: ldr   x23, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* ============================================================================
 * Lrecount(lst=x0, u=x1, visit=x2, ctx=x3) -> the live count / -1: the
 * memtable's count + every run-resident PUSH that no newer memtable entry
 * holds and this generation has not tombstoned; visit(ctx, key36, value,
 * height << 1 | cb, script, slen) for each when visit != 0.
 * lst x19, u x20, visit x21, ctx x22, live x23, nruns x24, slots x25,
 * winner x26 ; frame: key 0 (48), get outs 48 (48) -> 96
 * ========================================================================== */
    .p2align 2
Lrecount:
    stp   x29, x30, [sp, #-80]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    mov   x29, sp
    sub   sp, sp, #96
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, x3
    ldr   x23, [x20]                      /* the memtable first */
    ldr   x24, [x19, #120]
    cbz   x24, Lrc_done
    mov   x0, #0                          /* the slots: an anonymous mapping */
    MOVW  x9, SL_SIZE
    mul   x1, x24, x9
    mov   w2, #PROT_RW
    mov   w3, #MAP_PRIV_ANON
    mov   w4, #-1
    mov   x5, #0
    bl    _mmap
    cmn   x0, #1
    b.eq  Lrc_err
    mov   x25, x0
    mov   x0, x19
    mov   x1, x25
    mov   x2, #0
    mov   x3, x24
    bl    Lslots_open
    cmn   x0, #1
    b.eq  Lrc_cleanup
1:  mov   x0, x25                         /* the streaming k-way merge */
    mov   x1, x24
    bl    Lmerge_best
    cbz   x0, Lrc_end
    mov   x26, x0
    ldp   x9, x10, [x26, #SL_KEY]         /* key = the winner's */
    stp   x9, x10, [sp]
    ldp   x9, x10, [x26, #SL_KEY + 16]
    stp   x9, x10, [sp, #16]
    ldr   w9, [x26, #SL_KEY + 32]
    str   w9, [sp, #32]
    ldrb  w9, [x26, #SL_TYPE]
    cmp   w9, #1
    b.ne  2f
    mov   x0, x20                         /* a PUSH: live unless the memtable holds */
    mov   x1, sp                          /* it or it is tombstoned here */
    ldr   w2, [sp, #32]
    add   x3, sp, #48
    add   x4, sp, #56
    add   x5, sp, #64
    add   x6, sp, #72
    add   x7, sp, #80
    bl    _utxo_get
    cmp   x0, #1
    b.eq  2f
    mov   x0, x19
    mov   x1, sp
    bl    Ltomb_probe
    ldr   x9, [x0]
    cmn   x9, #1
    b.ne  2f
    add   x23, x23, #1
    cbz   x21, 2f
    mov   x0, x22                         /* visit(ctx, key, value, h << 1 | cb, script, slen) */
    mov   x1, sp
    ldr   x2, [x26, #SL_VALUE]
    ldr   w3, [x26, #SL_HEIGHT]
    ldr   w9, [x26, #SL_CB]
    orr   x3, x9, x3, lsl #1
    add   x4, x26, #SL_SCRIPT
    ldr   w5, [x26, #SL_SLEN]
    blr   x21
2:  mov   x0, x25                         /* every slot past the key */
    mov   x1, x24
    mov   x2, sp
    bl    Lmerge_advance
    cmn   x0, #1
    b.eq  Lrc_cleanup
    b     1b
Lrc_end:
    mov   x0, x25
    mov   x1, x24
    bl    Lslots_close
    mov   x0, x25
    MOVW  x9, SL_SIZE
    mul   x1, x24, x9
    bl    _munmap
Lrc_done:
    mov   x0, x23
    b     Lrc_ret
Lrc_cleanup:
    mov   x0, x25
    mov   x1, x24
    bl    Lslots_close
    mov   x0, x25
    MOVW  x9, SL_SIZE
    mul   x1, x24, x9
    bl    _munmap
Lrc_err:
    mov   x0, #-1
Lrc_ret:
    add   sp, sp, #96
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

/* Lwalk_bridge(ctx, txid, index, value, height, cb, script, slen): the
 * memtable walker's callback -> the visitor's (ctx, key36, value,
 * height << 1 | cb, script, slen); returns 0 (never aborts). The visitor is
 * in Lwalk_cb. ; frame key 0 (48) */
    .p2align 2
Lwalk_bridge:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #48
    ldp   x9, x10, [x1]                   /* key36 = txid || (u32) index */
    stp   x9, x10, [sp]
    ldp   x9, x10, [x1, #16]
    stp   x9, x10, [sp, #16]
    str   w2, [sp, #32]
    mov   x1, sp
    mov   x2, x3                          /* value */
    mov   w9, w4
    mov   w10, w5
    orr   x3, x10, x9, lsl #1             /* height << 1 | cb */
    mov   x4, x6                          /* script */
    mov   x5, x7                          /* slen */
    ADR_  x9, Lwalk_cb
    ldr   x9, [x9]
    blr   x9
    mov   x0, #0
    add   sp, sp, #48
    ldp   x29, x30, [sp], #16
    ret

/* utxo_lsm_walk(lst=x0, u=x1, cb=x2, ctx=x3) ; u x19, total x20, ctx x21 */
    .p2align 2
    .globl _utxo_lsm_walk
_utxo_lsm_walk:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   x19, x1
    mov   x21, x3
    mov   x22, x2
    bl    Lrecount
    cmn   x0, #1
    b.eq  9f
    mov   x20, x0
    ADR_  x9, Lwalk_cb
    str   x22, [x9]
    mov   x0, x19
    ADR_  x1, Lwalk_bridge
    mov   x2, x21
    bl    _utxo_walk_live
    ldr   x9, [x19]                       /* self-check: every memtable entry */
    cmp   x0, x9
    b.ne  9f
    mov   x0, x20
    b     10f
9:  mov   x0, #-1
10: ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * Lreload(lst=x0, u=x1, read_only=w2): the manifest -> the WAL rebuild ->
 * the tombstones rescanned from the WAL -> the live count.
 * lst x19, u x20, ro x21, fd x22, has_count x23, base x24, replayed x25,
 * pushes x26, dels x27 ; frame: mh 0 (16), base 16 (8), rec 32 (64) -> 96
 * ========================================================================== */
    .p2align 2
Lreload:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    str   x27, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #96
    mov   x19, x0
    mov   x20, x1
    mov   w21, w2
    bl    _lsm_mm_invalidate_all
    mov   x0, x19
    cbz   w21, 1f
    bl    _utxo_store_init_ro
    b     2f
1:  bl    _utxo_store_init
2:  cmp   x0, #1
    b.ne  Lre_no
    mov   x23, #0
    mov   x24, #0
    ADR_  x0, Lman_name
    mov   w1, #O_RDONLY
    bl    _open
    tbz   w0, #31, 3f
    bl    ___error                        /* no manifest: only ENOENT is fine */
    ldr   w9, [x0]
    cmp   w9, #ENOENT
    b.ne  Lre_no
    str   xzr, [x19, #120]
    str   xzr, [x19, #96]
    str   xzr, [x19, #144]
    b     Lre_wal
3:  mov   w22, w0
    mov   x1, sp                          /* magic, n */
    mov   x2, #12
    bl    Lread_exact
    cbnz  x0, Lre_noc
    ldr   w9, [sp]
    MOVW  w10, MAGIC_MANIFEST2
    cmp   w9, w10
    b.ne  4f
    mov   w0, w22
    add   x1, sp, #16
    mov   x2, #8
    bl    Lread_exact
    cbnz  x0, Lre_noc
    ldr   x24, [sp, #16]
    mov   x23, #1
    b     5f
4:  MOVW  w10, MAGIC_MANIFEST
    cmp   w9, w10
    b.ne  Lre_noc
5:  ldur  x9, [sp, #4]                    /* n <= the manifest cap */
    ldr   x10, [x19, #112]
    cmp   x9, x10
    b.hi  Lre_noc
    str   x9, [x19, #120]
    cbz   x9, 6f
    mov   w0, w22
    ldr   x1, [x19, #104]
    lsl   x2, x9, #4
    bl    Lread_exact
    cbnz  x0, Lre_noc
6:  mov   w0, w22
    bl    _close
    ldr   x9, [x19, #120]                 /* next gen / run = 1 + the maxima */
    ldr   x10, [x19, #104]
    mov   x11, #0
    mov   x12, #0
    mov   x13, #0
7:  cmp   x13, x9
    b.hs  8f
    add   x14, x10, x13, lsl #4
    ldp   x15, x16, [x14]
    cmp   x15, x11
    csel  x11, x15, x11, hi
    cmp   x16, x12
    csel  x12, x16, x12, hi
    add   x13, x13, #1
    b     7b
8:  cbz   x9, 81f
    add   x11, x11, #1
    add   x12, x12, #1
81: str   x11, [x19, #96]
    str   x12, [x19, #144]
Lre_wal:
    mov   x0, x19
    mov   x1, x20
    bl    _utxo_store_reload
    cmn   x0, #1
    b.eq  Lre_no
    mov   x25, x0
    str   xzr, [x19, #80]                 /* the tombstones + op_count from the WAL */
    str   xzr, [x19, #40]
    mov   x0, x19
    bl    Ltomb_reset
    cmp   x0, #1
    b.ne  Lre_no
    ADR_  x0, Lwal_name
    mov   w1, #O_RDONLY
    bl    _open
    tbnz  w0, #31, Lre_no
    mov   w22, w0
    mov   x26, #0
    mov   x27, #0
9:  mov   w0, w22                         /* while the offset < log_len */
    mov   x1, #0
    mov   w2, #SEEK_CUR
    bl    _lseek
    ldr   x9, [x19, #16]
    cmp   x0, x9
    b.hs  Lre_walend
    mov   w0, w22
    add   x1, sp, #32
    mov   x2, #8
    bl    Lread_exact
    cbnz  x0, Lre_walend
    ldr   x9, [x19, #40]
    add   x9, x9, #1
    str   x9, [x19, #40]
    ldrb  w9, [sp, #36]                   /* op */
    cmp   w9, #1
    b.eq  10f
    cmp   w9, #2
    b.eq  11f
    b     Lre_walend
10: add   x26, x26, #1                    /* PUSH: skip it */
    mov   w0, w22
    add   x1, sp, #32
    mov   x2, #51
    bl    Lread_exact
    cbnz  x0, Lre_walend
    ldurh w1, [sp, #32 + 49]
    cbz   w1, 9b
    mov   w0, w22
    mov   w2, #SEEK_CUR
    bl    _lseek
    tbnz  x0, #63, Lre_walend
    b     9b
11: add   x27, x27, #1                    /* DEL: a tombstone, while there is room */
    mov   w0, w22
    add   x1, sp, #32
    mov   x2, #36
    bl    Lread_exact
    cbnz  x0, Lre_walend
    ldp   x9, x10, [x19, #72]             /* cap, n */
    cmp   x10, x9
    b.hs  9b
    ldr   x11, [x19, #64]
    mov   x12, #36
    madd  x11, x10, x12, x11
    ldp   x12, x13, [sp, #32]
    stp   x12, x13, [x11]
    ldp   x12, x13, [sp, #48]
    stp   x12, x13, [x11, #16]
    ldr   w12, [sp, #64]
    str   w12, [x11, #32]
    mov   x0, x19
    mov   x1, x11
    bl    Ltomb_probe
    ldr   x10, [x19, #80]
    str   x10, [x0]
    add   x10, x10, #1
    str   x10, [x19, #80]
    b     9b
Lre_walend:
    mov   w0, w22
    bl    _close
    /* the live count: a v2 manifest with an EMPTY WAL tail supplies it; any
     * tail, or an old / absent manifest, recounts (incident #45) */
    cbz   x23, 12f
    orr   x9, x26, x27
    cbnz  x9, 12f
    str   x24, [x19, #88]
    b     13f
12: mov   x0, x19
    mov   x1, x20
    mov   x2, #0
    mov   x3, #0
    bl    Lrecount
    cmn   x0, #1
    b.eq  Lre_no
    str   x0, [x19, #88]
13: mov   x0, x25
    b     Lre_ret
Lre_noc:
    mov   w0, w22
    bl    _close
Lre_no:
    mov   x0, #-1
Lre_ret:
    add   sp, sp, #96
    ldr   x27, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

    .p2align 2
    .globl _utxo_lsm_reload
_utxo_lsm_reload:
    mov   w2, #0
    b     Lreload

    .p2align 2
    .globl _utxo_lsm_reload_ro
_utxo_lsm_reload_ro:
    mov   w2, #1
    b     Lreload

/* ============================================================================
 * utxo_lsm_compact_range(lst=x0, lo=x1, k=x2) -> 1 / 0 (nothing to do) / -1
 * k = 0: the oldest min(manifest_n, 64) runs; else runs [lo, lo + k), which
 * must be the head (lo = 0) or the tail (lo + k = manifest_n; a tail merge
 * keeps its DELs -- older runs below it may still hold the keys).
 * lst x19, lo x20, batch x21, keep_dels x22, slots x23, bloom x24,
 * sparse x25, ofd x26, true_nrec x27, sparse_n x28 ;
 * frame: bloom bits 0, sparse bytes 8, upper bound 16, manifest_n 24,
 *        winner 32, kt/vp 48 (64), ohdr 112 (48), name 160 (32),
 *        mh 192 (32), has/base 224 (16) -> 240
 * ========================================================================== */
#define CF_BITS   0
#define CF_SPB    8
#define CF_UB     16
#define CF_MN     24
#define CF_WIN    32
#define CF_KT     48
#define CF_OHDR   112
#define CF_NAME   160
#define CF_MH     192
#define CF_BASE   224
#define CF_SIZE   240

    .p2align 2
    .globl _utxo_lsm_compact
_utxo_lsm_compact:
    mov   x1, #0
    mov   x2, #0
    .globl _utxo_lsm_compact_range
_utxo_lsm_compact_range:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #CF_SIZE
    mov   x19, x0
    mov   x20, x1
    ldr   x9, [x19, #120]                 /* manifest_n */
    str   x9, [sp, #CF_MN]
    cmp   x9, #2
    b.lo  Lcf_zero
    mov   x22, #0
    cbz   x2, 1f
    cmp   x2, #2                          /* an explicit window */
    b.lo  Lcf_zero
    cmp   x2, #COMPACT_MAX_RUNS
    b.hi  Lcf_zero
    add   x10, x20, x2
    cmp   x10, x9
    b.hi  Lcf_zero
    cbz   x20, 2f
    cmp   x10, x9
    b.ne  Lcf_zero                        /* neither the head nor the tail */
    mov   x22, #1                         /* a tail merge keeps its DELs */
2:  mov   x21, x2
    b     3f
1:  mov   x10, #COMPACT_MAX_RUNS          /* (lo stays as passed, as the twin) */
    cmp   x9, x10
    csel  x21, x9, x10, lo
3:  mov   x0, #0                          /* the input slots */
    MOVW  x9, SL_SIZE
    mul   x1, x21, x9
    mov   w2, #PROT_RW
    mov   w3, #MAP_PRIV_ANON
    mov   w4, #-1
    mov   x5, #0
    bl    _mmap
    cmn   x0, #1
    b.eq  Lcf_err
    mov   x23, x0
    mov   x24, #0                         /* (no bloom / sparse mapped yet) */
    mov   x25, #0
    mov   x0, x19
    mov   x1, x23
    mov   x2, x20
    mov   x3, x21
    bl    Lslots_open
    cmn   x0, #1
    b.eq  Lcf_cleanup
    str   x0, [sp, #CF_UB]
    mov   x9, #10                         /* the bloom from the upper bound */
    mul   x9, x0, x9
    cmp   x9, #64
    mov   x10, #64
    csel  x9, x9, x10, hs
    mov   x10, #1
4:  cmp   x10, x9
    b.hs  5f
    lsl   x10, x10, #1
    b     4b
5:  mov   x9, #(BLOOM_MAX_BYTES * 8)
    cmp   x10, x9
    csel  x10, x10, x9, ls
    str   x10, [sp, #CF_BITS]
    mov   x0, #0
    lsr   x1, x10, #3
    mov   w2, #PROT_RW
    mov   w3, #MAP_PRIV_ANON
    mov   w4, #-1
    mov   x5, #0
    bl    _mmap                           /* (anonymous: already zero) */
    cmn   x0, #1
    b.eq  Lcf_cleanup
    mov   x24, x0
    ldr   x9, [sp, #CF_UB]                /* the sparse buffer */
    lsr   x9, x9, #6
    add   x9, x9, #2
    mov   x10, #SPARSE_ENT
    mul   x9, x9, x10
    str   x9, [sp, #CF_SPB]
    mov   x0, #0
    mov   x1, x9
    mov   w2, #PROT_RW
    mov   w3, #MAP_PRIV_ANON
    mov   w4, #-1
    mov   x5, #0
    bl    _mmap
    cmn   x0, #1
    b.eq  Lcf_unmap_bloom
    mov   x25, x0
    mov   x28, #0
    add   x0, sp, #CF_NAME                /* the output run */
    ldr   w1, [x19, #144]
    bl    Lfmt_runname
    add   x0, sp, #CF_NAME
    mov   w1, #(O_WRONLY | O_CREAT | O_TRUNC)
    bl    Lopen3
    tbnz  w0, #31, Lcf_unmap_both
    mov   w26, w0
    MOVW  w9, MAGIC_RUN3                  /* header: gen, nrec 0, bits, 0, 0 */
    str   w9, [sp, #CF_OHDR]
    ldr   x9, [x19, #96]
    stur  x9, [sp, #CF_OHDR + 4]
    stur  xzr, [sp, #CF_OHDR + 12]
    ldr   x9, [sp, #CF_BITS]
    stur  x9, [sp, #CF_OHDR + 20]
    stur  xzr, [sp, #CF_OHDR + 28]
    stur  xzr, [sp, #CF_OHDR + 36]
    mov   w0, w26
    add   x1, sp, #CF_OHDR
    mov   x2, #44
    bl    Lwrite_exact
    cbnz  x0, Lcf_fail
    mov   w0, w26
    mov   x1, x24
    ldr   x2, [sp, #CF_BITS]
    lsr   x2, x2, #3
    bl    Lwrite_exact
    cbnz  x0, Lcf_fail
    ADR_  x9, Lg
    str   x26, [x9, #G_OWFD]
    str   xzr, [x9, #G_OWFILL]
    mov   x27, #0
6:  mov   x0, x23                         /* the streaming k-way merge */
    mov   x1, x21
    bl    Lmerge_best
    cbz   x0, Lcf_merged
    str   x0, [sp, #CF_WIN]
    ldrb  w9, [x0, #SL_TYPE]
    cmp   w9, #1                          /* emit a PUSH, or a DEL when kept */
    b.eq  7f
    cbz   x22, Lcf_adv
    cmp   w9, #2
    b.ne  Lcf_adv
7:  tst   x27, #(SPARSE_STRIDE - 1)
    b.ne  8f
    mov   w0, w26                         /* the sparse entry: fd offset + fill */
    mov   x1, #0
    mov   w2, #SEEK_CUR
    bl    _lseek
    tbnz  x0, #63, Lcf_fail
    ADR_  x9, Lg
    ldr   x9, [x9, #G_OWFILL]
    add   x0, x0, x9
    mov   x9, #SPARSE_ENT
    madd  x10, x28, x9, x25
    ldr   x11, [sp, #CF_WIN]
    ldp   x12, x13, [x11, #SL_KEY]
    stp   x12, x13, [x10]
    ldp   x12, x13, [x11, #SL_KEY + 16]
    stp   x12, x13, [x10, #16]
    ldr   w12, [x11, #SL_KEY + 32]
    str   w12, [x10, #32]
    stur  x0, [x10, #36]
    add   x28, x28, #1
8:  ldr   x0, [sp, #CF_WIN]               /* key + type (37 contiguous bytes) */
    add   x0, x0, #SL_KEY
    mov   x1, #37
    bl    Lout_write
    cbnz  x0, Lcf_fail
    ldr   x11, [sp, #CF_WIN]
    ldrb  w9, [x11, #SL_TYPE]
    cmp   w9, #1
    b.ne  9f
    ldr   x9, [x11, #SL_VALUE]            /* value slen height cb */
    stur  x9, [sp, #CF_KT]
    ldr   w9, [x11, #SL_SLEN]
    sturh w9, [sp, #CF_KT + 8]
    ldr   w9, [x11, #SL_HEIGHT]
    stur  w9, [sp, #CF_KT + 10]
    ldr   w9, [x11, #SL_CB]
    strb  w9, [sp, #CF_KT + 14]
    add   x0, sp, #CF_KT
    mov   x1, #15
    bl    Lout_write
    cbnz  x0, Lcf_fail
    ldr   x11, [sp, #CF_WIN]
    ldr   w1, [x11, #SL_SLEN]
    cbz   w1, 9f
    add   x0, x11, #SL_SCRIPT
    bl    Lout_write
    cbnz  x0, Lcf_fail
9:  ldr   x0, [sp, #CF_WIN]               /* EVERY emitted key into the bloom */
    add   x0, x0, #SL_KEY
    mov   x1, x24
    ldr   x2, [sp, #CF_BITS]
    sub   w2, w2, #1
    bl    Lbloom_set3
    add   x27, x27, #1
Lcf_adv:
    ldr   x11, [sp, #CF_WIN]              /* the key, copied (the winner moves) */
    ldp   x12, x13, [x11, #SL_KEY]
    stp   x12, x13, [sp, #CF_KT]
    ldp   x12, x13, [x11, #SL_KEY + 16]
    stp   x12, x13, [sp, #CF_KT + 16]
    ldr   w12, [x11, #SL_KEY + 32]
    str   w12, [sp, #CF_KT + 32]
    mov   x0, x23
    mov   x1, x21
    add   x2, sp, #CF_KT
    bl    Lmerge_advance
    cmn   x0, #1
    b.eq  Lcf_fail
    b     6b
Lcf_merged:
    bl    Lout_flush                      /* every record on disk before the seeks */
    cbnz  x0, Lcf_fail
    mov   w0, w26                         /* the bloom, now filled */
    mov   x1, #44
    mov   w2, #SEEK_SET
    bl    _lseek
    tbnz  x0, #63, Lcf_fail
    mov   w0, w26
    mov   x1, x24
    ldr   x2, [sp, #CF_BITS]
    lsr   x2, x2, #3
    bl    Lwrite_exact
    cbnz  x0, Lcf_fail
    mov   w0, w26                         /* nrec */
    mov   x1, #12
    mov   w2, #SEEK_SET
    bl    _lseek
    tbnz  x0, #63, Lcf_fail
    str   x27, [sp, #CF_KT]
    mov   w0, w26
    add   x1, sp, #CF_KT
    mov   x2, #8
    bl    Lwrite_exact
    cbnz  x0, Lcf_fail
    mov   w0, w26                         /* the sparse index at the end */
    mov   x1, #0
    mov   w2, #SEEK_END
    bl    _lseek
    tbnz  x0, #63, Lcf_fail
    stur  x0, [sp, #CF_OHDR + 28]
    stur  x28, [sp, #CF_OHDR + 36]
    cbz   x28, 10f
    mov   w0, w26
    mov   x1, x25
    mov   x9, #SPARSE_ENT
    mul   x2, x28, x9
    bl    Lwrite_exact
    cbnz  x0, Lcf_fail
10: mov   w0, w26                         /* patch sparse_off / n */
    mov   x1, #28
    mov   w2, #SEEK_SET
    bl    _lseek
    tbnz  x0, #63, Lcf_fail
    mov   w0, w26
    add   x1, sp, #CF_OHDR + 28
    mov   x2, #16
    bl    Lwrite_exact
    cbnz  x0, Lcf_fail
    mov   w0, w26
    bl    _fsync
    mov   w0, w26
    bl    _close
    /* the manifest: the merged entry at lo, the survivors shifted down */
    ldr   x9, [x19, #104]
    add   x10, x9, x20, lsl #4
    ldr   x11, [x19, #96]
    ldr   x12, [x19, #144]
    stp   x11, x12, [x10]
    add   x13, x20, x21                   /* src */
    add   x14, x20, #1                    /* dst */
    ldr   x15, [sp, #CF_MN]
11: cmp   x13, x15
    b.hs  12f
    add   x10, x9, x13, lsl #4
    ldp   x11, x12, [x10]
    add   x10, x9, x14, lsl #4
    stp   x11, x12, [x10]
    add   x13, x13, #1
    add   x14, x14, #1
    b     11b
12: str   x14, [x19, #120]
    ldr   x9, [x19, #96]
    add   x9, x9, #1
    str   x9, [x19, #96]
    ldr   x9, [x19, #144]
    add   x9, x9, #1
    str   x9, [x19, #144]
    /* the live-count field: a full merge -> true_nrec; partial -> carry the
     * persisted base (or write v1 when none) */
    stp   xzr, xzr, [sp, #CF_BASE]        /* has_count, base */
    ADR_  x0, Lman_name
    mov   w1, #O_RDONLY
    bl    _open
    tbnz  w0, #31, 14f
    mov   w26, w0
    mov   w0, w26
    add   x1, sp, #CF_MH
    mov   x2, #12
    bl    Lread_exact
    cbnz  x0, 13f
    ldr   w9, [sp, #CF_MH]
    MOVW  w10, MAGIC_MANIFEST2
    cmp   w9, w10
    b.ne  13f
    mov   w0, w26
    add   x1, sp, #CF_BASE + 8
    mov   x2, #8
    bl    Lread_exact
    cbnz  x0, 13f
    mov   x9, #1
    str   x9, [sp, #CF_BASE]
13: mov   w0, w26
    bl    _close
14: ldp   x9, x10, [sp, #CF_BASE]         /* has_count, base */
    ldr   x11, [sp, #CF_MN]
    cmp   x21, x11
    b.ne  15f
    mov   x12, x27                        /* full merge: true_nrec, v2 */
    mov   x13, #1
    cbz   x9, 16f
    ldr   x14, [x19, #88]                 /* total_live - base + true_nrec */
    sub   x14, x14, x10
    add   x14, x14, x27
    str   x14, [x19, #88]
    b     16f
15: mov   x12, x10                        /* partial: the base, v2 if there was one */
    mov   x13, x9
16: stp   x12, x13, [sp, #CF_BASE]        /* (persist_count, write_v2) */
    ADR_  x9, Lg
    ldr   x9, [x9, #G_DEFPUB]
    ADR_  x0, Lman_tmp
    ADR_  x10, Lman_child
    cmp   x9, #0
    csel  x0, x10, x0, ne
    mov   w1, #(O_WRONLY | O_CREAT | O_TRUNC)
    bl    Lopen3
    tbnz  w0, #31, Lcf_cleanup_ok_files
    mov   w26, w0
    ldp   x12, x13, [sp, #CF_BASE]
    MOVW  w9, MAGIC_MANIFEST2
    MOVW  w10, MAGIC_MANIFEST
    cmp   x13, #0
    csel  w9, w9, w10, ne
    str   w9, [sp, #CF_MH]
    ldr   x9, [x19, #120]
    stur  x9, [sp, #CF_MH + 4]
    stur  x12, [sp, #CF_MH + 12]
    mov   x2, #12
    mov   x9, #20
    cmp   x13, #0
    csel  x2, x9, x2, ne
    mov   w0, w26
    add   x1, sp, #CF_MH
    bl    Lwrite_exact
    cbnz  x0, 17f
    mov   w0, w26
    ldr   x1, [x19, #104]
    ldr   x2, [x19, #120]
    lsl   x2, x2, #4
    bl    Lwrite_exact
    cbz   x0, 18f
17: mov   w0, w26
    bl    _close
    b     Lcf_cleanup_ok_files
18: mov   w0, w26
    bl    _fsync
    mov   w0, w26
    bl    _close
    ADR_  x9, Lg
    ldr   x9, [x9, #G_DEFPUB]
    cbnz  x9, 19f
    ADR_  x0, Lman_tmp
    ADR_  x1, Lman_name
    bl    _rename
    tbnz  w0, #31, Lcf_cleanup_ok_files
    bl    Lfsync_dir
19: mov   x26, #0                         /* close the inputs; unlink them */
20: cmp   x26, x21                        /* unless deferred */
    b.hs  21f
    MOVW  x9, SL_SIZE
    madd  x27, x26, x9, x23               /* (x27 is spent) */
    ldr   w0, [x27, #SL_FD]
    tbnz  w0, #31, 201f
    bl    _close
201: ADR_ x9, Lg
    ldr   x9, [x9, #G_DEFUNL]
    cbnz  x9, 202f
    add   x0, sp, #CF_NAME
    ldr   w1, [x27, #SL_RUN]
    bl    Lfmt_runname
    add   x0, sp, #CF_NAME
    bl    _unlink
202: add  x26, x26, #1
    b     20b
21: mov   x0, x23
    MOVW  x9, SL_SIZE
    mul   x1, x21, x9
    bl    _munmap
    mov   x0, x24
    ldr   x1, [sp, #CF_BITS]
    lsr   x1, x1, #3
    bl    _munmap
    mov   x0, x25
    ldr   x1, [sp, #CF_SPB]
    bl    _munmap
    mov   x0, #1
    b     Lcf_ret
/* the failure exits, as the twin: after the output file opened, close it;
 * the bloom and sparse maps stay mapped (the twin's cleanup does not unmap
 * them either); before it, what was mapped is unmapped */
Lcf_unmap_both:
    mov   x0, x25
    ldr   x1, [sp, #CF_SPB]
    bl    _munmap
Lcf_unmap_bloom:
    mov   x0, x24
    ldr   x1, [sp, #CF_BITS]
    lsr   x1, x1, #3
    bl    _munmap
    b     Lcf_cleanup
Lcf_fail:
    mov   w0, w26
    bl    _close
Lcf_cleanup:
Lcf_cleanup_ok_files:
    mov   x0, x23
    mov   x1, x21
    bl    Lslots_close
    mov   x0, x23
    MOVW  x9, SL_SIZE
    mul   x1, x21, x9
    bl    _munmap
Lcf_err:
    mov   x0, #-1
    b     Lcf_ret
Lcf_zero:
    mov   x0, #0
Lcf_ret:
    add   sp, sp, #CF_SIZE
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* ==========================================================================
 * data
 * ======================================================================== */
    .section __TEXT,__cstring
Ldot:       .asciz "."
Lrunfmt:    .asciz "utxo_run_%06u.dat"
Lman_name:  .asciz "utxo_manifest.dat"
Lman_tmp:   .asciz "utxo_manifest.tmp"
Lman_child: .asciz "utxo_manifest.child"
Lwal_name:  .asciz "utxo.dat"

    .data
    .p2align 3
Lg:         /* flush fill, compaction fd, compaction fill, defer_unlink,
               defer_publish, flush hook, sort mode (1 = radix) */
    .quad 0, 0, 0, 0, 0, 0, 1
Lrs_final:  .quad 0
Lwalk_cb:   .quad 0

.zerofill __DATA,__bss,Lflbuf,FLBUF,4
.zerofill __DATA,__bss,Lowbuf,OWBUF,4

/* the run lookup's per-thread script buffer (valid until the next lookup) */
.tbss _bmc_lsm_script_tlv$tlv$init, SCRIPT_MAX, 4
    .section __DATA,__thread_vars,thread_local_variables
    .p2align 3
    .globl _bmc_lsm_script_tlv
_bmc_lsm_script_tlv:
    .quad __tlv_bootstrap
    .quad 0
    .quad _bmc_lsm_script_tlv$tlv$init
