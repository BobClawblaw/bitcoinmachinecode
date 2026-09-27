/* ============================================================================
 * bitcoin_cons.S -- the block consensus verifier in AArch64 assembly (Apple
 * silicon), the counterpart of asm/bitcoin_cons.asm. Replaces cons_twin.c
 * on the Mac (2026-09-26); the twin stays in port/osx/test_support as the
 * oracle.
 *
 *   int cons_verify(const u8* block, u64 len, u8* txids_out, unsigned cap);
 *
 * 1 iff: len >= 82; pow_check passes; the compact-size tx count parses
 * (bounded) and is nonzero; every tx parses (tx_parse) and lies inside the
 * block; tx[0] has exactly one input; at most cap txids; each txid computes;
 * the txs fill the block exactly and number the count; the merkle root of
 * the txids matches header[36..68]; merkle_root reports no duplicate-txid
 * mutation (Core's bad-txns-duplicate).
 *
 * The txid is computed HERE, not by tx_txid, as the twin does -- the x86
 * tx_txid hashed the wrong length for segwit txs (see cons_twin.c's
 * UPSTREAM-BUG NOTE). The walk is the twin's, quirk for quirk: the witness
 * item COUNT takes 0xfd/0xfe forms only (0xff reads as 255), every other
 * compact size takes all three; a script length is read before its bound is
 * checked; the stripped serialization is capped at 1 MiB.
 *
 * Differences in form, not in result:
 *   - the stripped serialization, version || [n_in .. end of outputs) ||
 *     locktime, is HASHED IN PIECES through sha256_init/sha256_block, where
 *     the twin copies it into a 1 MiB stack buffer first: a 1 MiB frame in
 *     assembly, with no stack probe, could step over a secondary thread's
 *     guard page (Darwin gives them 512 KiB by default);
 *   - cap is read as the unsigned 32 bits every caller declares (blk_submit,
 *     archive_verify, check_chain, ibd_pipeline, reorg), not as 64 bits.
 * ========================================================================== */
#define STRIP_CAP (1 << 20)

    .text

/* ---- streaming SHA-256: ctx = state 0 (32), buf 32 (64), buflen 96,
 *      total 104 -> 112 bytes ---------------------------------------------- */
#define SH_BUF    32
#define SH_BLEN   96
#define SH_TOTAL  104
#define SH_SIZE   112

/* Lsh_feed(ctx=x0, p=x1, n=x2) ; ctx x19, p x20, n x21 */
    .p2align 2
Lsh_feed:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    ldr   x9, [x19, #SH_TOTAL]
    add   x9, x9, x21
    str   x9, [x19, #SH_TOTAL]
1:  cbz   x21, 4f
    ldr   x9, [x19, #SH_BLEN]
    cbnz  x9, 2f
    cmp   x21, #64
    b.lo  2f
    mov   x0, x19                         /* whole block straight from p */
    mov   x1, x20
    bl    _sha256_block
    add   x20, x20, #64
    sub   x21, x21, #64
    b     1b
2:  mov   x10, #64                        /* take = min(64 - buflen, n) */
    sub   x10, x10, x9
    cmp   x10, x21
    csel  x22, x10, x21, lo
    add   x0, x19, #SH_BUF
    add   x0, x0, x9
    mov   x1, x20
    mov   x2, x22
    bl    _memcpy
    ldr   x9, [x19, #SH_BLEN]
    add   x9, x9, x22
    add   x20, x20, x22
    sub   x21, x21, x22
    cmp   x9, #64
    b.ne  3f
    mov   x0, x19
    add   x1, x19, #SH_BUF
    bl    _sha256_block
    mov   x9, #0
3:  str   x9, [x19, #SH_BLEN]
    b     1b
4:  ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* Lsh_final_d(ctx=x0, out=x1): out = SHA256(SHA256(fed bytes))
 * frame: tail 0 (16: 0x80 + length), digest 16 (32) -> 48 ; ctx x19, out x20,
 * bit length x21 */
    .p2align 2
Lsh_final_d:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #48
    mov   x19, x0
    mov   x20, x1
    ldr   x21, [x19, #SH_TOTAL]
    lsl   x21, x21, #3                    /* message length in bits */
    mov   w9, #0x80
    strb  w9, [sp]
    mov   x0, x19
    mov   x1, sp
    mov   x2, #1
    bl    Lsh_feed
    ldr   x9, [x19, #SH_BLEN]             /* zeros up to byte 56 of a block */
    mov   x10, #56
    sub   x2, x10, x9
    add   x10, x2, #64
    cmp   x9, #56
    csel  x2, x10, x2, hi
    mov   x0, x19
    adrp  x1, Lzero64@PAGE
    add   x1, x1, Lzero64@PAGEOFF
    bl    Lsh_feed
    rev   x9, x21                         /* 64-bit big-endian bit length */
    str   x9, [sp, #8]
    mov   x0, x19
    add   x1, sp, #8
    mov   x2, #8
    bl    Lsh_feed
    ldp   q0, q1, [x19]                   /* digest: state words big-endian */
    rev32 v0.16b, v0.16b
    rev32 v1.16b, v1.16b
    stp   q0, q1, [sp, #16]
    mov   x0, x20                         /* the second SHA-256 */
    add   x1, sp, #16
    mov   x2, #32
    bl    _sha256_full
    add   sp, sp, #48
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * Ltxid_of_span(tx=x0, txlen=x1, out=x2) -> w0 1 / 0
 * tx x19, end x20, q x21, hdr x22, nin x23, i x24, body x25, out x26,
 * j x27 ; frame: sha ctx 0 (112) -> 112
 * ========================================================================== */

/* CS rd, allow_ff: rd = compact size at [x21], x21 advanced; the extended
 * forms bounds-checked (end - q, signed, as the twin) ; scratch x9 */
.macro CS rd, rw, allow_ff
    ldrb  \rw, [x21], #1
    cmp   \rd, #0xfd
    b.lo  90f
    sub   x9, x20, x21
    b.ne  91f
    cmp   x9, #2                          /* 0xfd: u16 */
    b.lt  Ltx_fail
    ldrh  \rw, [x21], #2
    b     90f
91: cmp   \rd, #0xfe
    b.ne  92f
    cmp   x9, #4                          /* 0xfe: u32 */
    b.lt  Ltx_fail
    ldr   \rw, [x21], #4
    b     90f
92:
    .if \allow_ff
    cmp   x9, #8                          /* 0xff: u64 */
    b.lt  Ltx_fail
    ldr   \rd, [x21], #8
    .endif
90:
.endm

    .p2align 2
Ltxid_of_span:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    str   x27, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #SH_SIZE
    cmp   x1, #10
    b.lo  Ltx_fail                        /* version + n_in + locktime minimum */
    mov   x19, x0
    add   x20, x0, x1
    mov   x26, x2
    add   x21, x19, #4                    /* p */
    mov   x22, #4                         /* hdr */
    add   x9, x21, #2                     /* BIP144 marker + nonzero flag */
    cmp   x9, x20
    b.hi  1f
    ldrb  w10, [x21]
    ldrb  w11, [x21, #1]
    cbnz  w10, 1f
    cbz   w11, 1f
    add   x21, x21, #2
    mov   x22, #6
1:  mov   x23, #0                         /* nin (0 if it is never read) */
    cmp   x21, x20
    b.hs  Ltx_body
    CS    x23, w23, 1
    mov   x24, #0
2:  cmp   x24, x23                        /* inputs */
    b.hs  3f
    sub   x9, x20, x21
    cmp   x9, #36
    b.lt  Ltx_fail
    add   x21, x21, #36                   /* outpoint */
    CS    x10, w10, 1                          /* script length: read, then bound */
    sub   x9, x20, x21
    cmp   x9, x10
    b.lo  Ltx_fail
    add   x21, x21, x10
    sub   x9, x20, x21
    cmp   x9, #4
    b.lt  Ltx_fail
    add   x21, x21, #4                    /* sequence */
    add   x24, x24, #1
    b     2b
3:  cmp   x21, x20
    b.hs  Ltx_body
    CS    x25, w25, 1                          /* nout (x25 reused as body below) */
    mov   x24, #0
4:  cmp   x24, x25                        /* outputs */
    b.hs  Ltx_body
    sub   x9, x20, x21
    cmp   x9, #8
    b.lt  Ltx_fail
    add   x21, x21, #8                    /* value */
    CS    x10, w10, 1
    sub   x9, x20, x21
    cmp   x9, x10
    b.lo  Ltx_fail
    add   x21, x21, x10
    add   x24, x24, #1
    b     4b
Ltx_body:
    sub   x25, x21, x19                   /* body = end of outputs (before the witness) */
    cmp   x22, #6
    b.ne  8f
    mov   x24, #0                         /* segwit: skip the witness stacks */
5:  cmp   x24, x23
    b.hs  7f
    cmp   x21, x20
    b.hs  Ltx_fail
    CS    x11, w11, 0                          /* item count: 0xfd/0xfe forms only */
    mov   x27, #0
6:  cmp   x27, x11
    b.hs  61f
    cmp   x21, x20
    b.hs  Ltx_fail
    CS    x10, w10, 1
    sub   x9, x20, x21
    cmp   x9, x10
    b.lo  Ltx_fail
    add   x21, x21, x10
    add   x27, x27, #1
    b     6b
61: add   x24, x24, #1
    b     5b
7:  add   x9, x21, #4                     /* the locktime must follow exactly */
    cmp   x9, x20
    b.ne  Ltx_fail
    b     9f
8:  sub   x9, x20, x21                    /* legacy: only the locktime remains */
    cmp   x9, #4
    b.ne  Ltx_fail
9:  sub   x24, x25, x22                   /* body - hdr */
    add   x9, x24, #8
    mov   x10, #STRIP_CAP
    cmp   x9, x10
    b.hi  Ltx_fail
    /* sha256d(version || tx[hdr..body) || locktime) */
    mov   x0, sp
    bl    _sha256_init
    stp   xzr, xzr, [sp, #SH_BLEN]        /* buflen, total */
    mov   x0, sp
    mov   x1, x19
    mov   x2, #4
    bl    Lsh_feed
    mov   x0, sp
    add   x1, x19, x22
    mov   x2, x24
    bl    Lsh_feed
    mov   x0, sp
    sub   x1, x20, #4
    mov   x2, #4
    bl    Lsh_feed
    mov   x0, sp
    mov   x1, x26
    bl    Lsh_final_d
    mov   w0, #1
    b     Ltx_ret
Ltx_fail:
    mov   w0, #0
Ltx_ret:
    add   sp, sp, #SH_SIZE
    ldr   x27, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* ============================================================================
 * cons_verify(block=x0, len=x1, txids=x2, cap=w3)
 * block x19, len x20, txids x21, cap x22, expect x23, off x24, count x25
 * frame: info 0 (64), root 64 (32) -> 96
 * ========================================================================== */
    .p2align 2
    .globl _cons_verify
_cons_verify:
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
    mov   w22, w3                         /* unsigned, as the callers declare */
    cmp   x20, #82
    b.lo  Lcv_no
    bl    _pow_check
    cmp   x0, #1
    b.ne  Lcv_no
    /* the tx count at block[80] */
    ldrb  w9, [x19, #80]
    cmp   w9, #0xfd
    b.hs  1f
    mov   x23, x9
    mov   x24, #81
    b     4f
1:  b.ne  2f
    cmp   x20, #83                        /* 0xfd: block[81..82] inside */
    b.lo  Lcv_no
    ldurh w23, [x19, #81]
    mov   x24, #83
    b     4f
2:  cmp   w9, #0xfe
    b.ne  3f
    cmp   x20, #85
    b.lo  Lcv_no
    ldur  w23, [x19, #81]
    mov   x24, #85
    b     4f
3:  cmp   x20, #89
    b.lo  Lcv_no
    ldur  x23, [x19, #81]
    mov   x24, #89
4:  cbz   x23, Lcv_no                     /* >= 1 tx (the coinbase) */
    mov   w25, #0
5:  cmp   x20, x24                        /* while len > off */
    b.ls  6f
    stp   xzr, xzr, [sp]                  /* info = 0 */
    stp   xzr, xzr, [sp, #16]
    stp   xzr, xzr, [sp, #32]
    stp   xzr, xzr, [sp, #48]
    mov   x0, sp
    add   x1, x19, x24
    sub   x2, x20, x24
    bl    _tx_parse
    cbz   x0, Lcv_no
    ldr   x9, [sp]                        /* txlen */
    cbz   x9, Lcv_no
    add   x10, x24, x9
    cmp   x10, x20
    b.hi  Lcv_no
    cbnz  w25, 51f
    ldr   w10, [sp, #12]                  /* the coinbase: n_in == 1 */
    cmp   w10, #1
    b.ne  Lcv_no
51: cmp   x25, x22
    b.hs  Lcv_no                          /* count >= cap */
    add   x0, x19, x24
    mov   x1, x9
    add   x2, x21, x25, lsl #5
    bl    Ltxid_of_span
    cbz   w0, Lcv_no
    ldr   x9, [sp]
    add   x24, x24, x9
    add   w25, w25, #1
    b     5b
6:  cmp   x24, x20
    b.ne  Lcv_no
    cbz   w25, Lcv_no
    cmp   x25, x23
    b.ne  Lcv_no                          /* count != expect */
    add   x0, sp, #64
    mov   x1, x21
    mov   x2, x25
    bl    _merkle_root
    mov   x23, x0                         /* mutated */
    add   x9, sp, #64                     /* root == header merkle root */
    ldp   x10, x11, [x9]
    ldp   x12, x13, [x9, #16]
    add   x9, x19, #36
    ldp   x14, x15, [x9]
    ldp   x16, x17, [x9, #16]
    cmp   x10, x14
    ccmp  x11, x15, #0, eq
    ccmp  x12, x16, #0, eq
    ccmp  x13, x17, #0, eq
    b.ne  Lcv_no
    cbnz  x23, Lcv_no                     /* bad-txns-duplicate */
    mov   w0, #1
    b     Lcv_ret
Lcv_no:
    mov   w0, #0
Lcv_ret:
    add   sp, sp, #96
    ldr   x25, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

    .section __TEXT,__const
    .p2align 4
Lzero64:
    .space 64
