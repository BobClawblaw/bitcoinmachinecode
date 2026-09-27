/* ============================================================================
 * bitcoin_sighash.S -- legacy SignatureHash builders in AArch64 assembly
 * (Apple silicon), the counterpart of asm/bitcoin_sighash.asm. Replaces
 * sighash_twin.c on the Mac (2026-09-26); the twin stays in
 * port/osx/test_support as the oracle.
 *
 *   int  sighash_all(u8 out32[32], const u8* tx, u64 txlen, u64 input_index,
 *                    const u8* script, u64 script_len, u8* preimg, u64 cap);
 *   int  legacy_sighash(u8 out32[32], const u8* tx, u64 txlen, u64 nIn,
 *                       const u8* scriptCode, u64 scLen, int32_t hashtype,
 *                       u8* preimg, u64 cap);
 *   u64  script_find_and_delete(u8* dst, u64 dstcap, const u8* src,
 *                               u64 srclen, const u8* needle, u64 needlelen);
 *   u64  script_op_len(const u8* pos, const u8* end);
 *   u64  script_push_encode(u8* dst, u64 dstcap, const u8* data, u64 datalen);
 *   __thread u8 legacy_sighash_scfbuf[20000];
 *
 * Every bound check -- and every NON-check -- of the x86 is kept, as the
 * twin keeps them: sighash_all copies the prevouts, sequences and the tail
 * without re-checking the cursors, and writes the signed script after only
 * the varint's cap check; the callers never feed it hostile txs (see the
 * x86 header). Failure is 0; find_and_delete / push_encode return
 * UINT64_MAX when the destination is too small. Every "room" test is the
 * unsigned (u64)(pend - p) < n of the twin.
 *
 * legacy_sighash strips OP_CODESEPARATOR from scriptCode into
 * legacy_sighash_scfbuf, which is THREAD-LOCAL (the x86 .tbss fix of
 * 2026-08-19 for parallel verification); here a 20000-byte Mach-O TLV.
 * SIGHASH_SINGLE with nIn >= n_out answers the "one" hash (1, 0 ... 0) before
 * anything is built, as Core. The hashtype is appended as its full 32-bit
 * pattern.
 * ========================================================================== */
#define SCFCAP 20000

    .text

/* Lpv(cur=x0, end=x1) -> x0 value, x1 new cursor ; leaf, x9..x11
 * CompactSize: 0 with the cursor unmoved at/after end; 0 with only the
 * prefix consumed when the value bytes overrun; else the value. */
    .p2align 2
Lpv:
    cmp   x0, x1
    b.hs  8f
    ldrb  w9, [x0], #1
    cmp   w9, #0xfd
    b.lo  7f
    mov   x10, #2
    mov   x11, #4
    cmp   w9, #0xfe
    csel  x10, x11, x10, eq
    mov   x11, #8
    cmp   w9, #0xff
    csel  x10, x11, x10, eq
    sub   x11, x1, x0
    cmp   x11, x10
    b.lo  6f
    cmp   x10, #4
    b.eq  4f
    b.hi  5f
    ldrh  w9, [x0]
    b     3f
4:  ldr   w9, [x0]
    b     3f
5:  ldr   x9, [x0]
3:  add   x1, x0, x10
    mov   x0, x9
    ret
6:  mov   x1, x0                          /* the prefix byte stays consumed */
    mov   x0, #0
    ret
7:  mov   x1, x0
    mov   x0, x9
    ret
8:  mov   x1, x0
    mov   x0, #0
    ret

/* Lwv(p=x0, v=x1) -> x0 advanced ; leaf, x9 -- no cap check (callers bound) */
    .p2align 2
Lwv:
    cmp   x1, #0xfc
    b.hi  1f
    strb  w1, [x0], #1
    ret
1:  mov   x9, #0xffff
    cmp   x1, x9
    b.hi  2f
    mov   w9, #0xfd
    strb  w9, [x0]
    sturh w1, [x0, #1]
    add   x0, x0, #3
    ret
2:  mov   x9, #0xffffffff
    cmp   x1, x9
    b.hi  3f
    mov   w9, #0xfe
    strb  w9, [x0]
    stur  w1, [x0, #1]
    add   x0, x0, #5
    ret
3:  mov   w9, #0xff
    strb  w9, [x0]
    stur  x1, [x0, #1]
    add   x0, x0, #9
    ret

/* COPY36 dst, src: 36 bytes, both advanced ; x9..x12 */
.macro COPY36 d, s
    ldp   x9, x10, [\s]
    ldp   x11, x12, [\s, #16]
    stp   x9, x10, [\d]
    stp   x11, x12, [\d, #16]
    ldr   w9, [\s, #32]
    str   w9, [\d, #32]
    add   \d, \d, #36
    add   \s, \s, #36
.endm

/* script_op_len(pos=x0, end=x1) ; leaf */
    .p2align 2
    .globl _script_op_len
_script_op_len:
    cmp   x0, x1
    b.hs  9f
    ldrb  w9, [x0]
    sub   x10, x1, x0                     /* available */
    cmp   w9, #0x4c
    b.hs  1f
    add   x11, x9, #1                     /* direct push */
    b     5f
1:  b.ne  2f
    cmp   x10, #2                         /* PUSHDATA1 */
    b.lo  9f
    ldrb  w12, [x0, #1]
    add   x11, x12, #2
    b     5f
2:  cmp   w9, #0x4d
    b.ne  3f
    cmp   x10, #3                         /* PUSHDATA2 */
    b.lo  9f
    ldurh w12, [x0, #1]
    add   x11, x12, #3
    b     5f
3:  cmp   w9, #0x4e
    b.ne  4f
    cmp   x10, #5                         /* PUSHDATA4 */
    b.lo  9f
    ldur  w12, [x0, #1]
    add   x11, x12, #5
    b     5f
4:  mov   x11, #1                         /* any other opcode */
5:  add   x12, x0, x11
    cmp   x12, x1
    b.hi  9f
    mov   x0, x11
    ret
9:  mov   x0, #0
    ret

/* ============================================================================
 * script_find_and_delete(dst=x0, dstcap=x1, src=x2, srclen=x3, needle=x4,
 *                        needlelen=x5)
 * dst x19, outend x20, pc x21, end x22, needle x23, nlen x24, out x25,
 * unit/rem x26
 * ========================================================================== */
    .p2align 2
    .globl _script_find_and_delete
_script_find_and_delete:
    stp   x29, x30, [sp, #-80]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    mov   x29, sp
    mov   x19, x0
    add   x20, x0, x1
    mov   x21, x2
    add   x22, x2, x3
    mov   x23, x4
    mov   x24, x5
    mov   x25, x0
Lfd_loop:
    cbz   x24, Lfd_unit                   /* delete consecutive raw needle matches */
    sub   x9, x22, x21
    cmp   x9, x24
    b.lo  Lfd_unit
    cmp   x24, #1
    b.ne  1f
    ldrb  w9, [x21]                       /* the common 1-byte needle, inline */
    ldrb  w10, [x23]
    cmp   w9, w10
    b.ne  Lfd_unit
    b     2f
1:  mov   x0, x21
    mov   x1, x23
    mov   x2, x24
    bl    _memcmp
    cbnz  w0, Lfd_unit
2:  add   x21, x21, x24
    b     Lfd_loop
Lfd_unit:
    cmp   x21, x22
    b.eq  Lfd_done
    mov   x0, x21
    mov   x1, x22
    bl    _script_op_len
    mov   x26, x0
    cbnz  x26, 3f
    sub   x26, x22, x21                   /* malformed tail: copy it verbatim */
    sub   x9, x20, x25
    cmp   x9, x26
    b.lo  Lfd_full
    mov   x0, x25
    mov   x1, x21
    mov   x2, x26
    bl    _memcpy
    add   x25, x25, x26
    b     Lfd_done
3:  sub   x9, x20, x25
    cmp   x9, x26
    b.lo  Lfd_full
    mov   x0, x25
    mov   x1, x21
    mov   x2, x26
    bl    _memcpy
    add   x25, x25, x26
    add   x21, x21, x26
    b     Lfd_loop
Lfd_full:
    mov   x0, #-1
    b     Lfd_ret
Lfd_done:
    sub   x0, x25, x19
Lfd_ret:
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

/* script_push_encode(dst=x0, dstcap=x1, data=x2, datalen=x3) ; total x19 */
    .p2align 2
    .globl _script_push_encode
_script_push_encode:
    cmp   x3, #0x4c
    b.hs  1f
    add   x9, x3, #1
    cmp   x1, x9
    b.lo  Lpe_full
    strb  w3, [x0]
    mov   x10, #1
    b     4f
1:  cmp   x3, #0xff
    b.hi  2f
    add   x9, x3, #2
    cmp   x1, x9
    b.lo  Lpe_full
    mov   w11, #0x4c
    strb  w11, [x0]
    strb  w3, [x0, #1]
    mov   x10, #2
    b     4f
2:  mov   x11, #0xffff
    cmp   x3, x11
    b.hi  3f
    add   x9, x3, #3
    cmp   x1, x9
    b.lo  Lpe_full
    mov   w11, #0x4d
    strb  w11, [x0]
    sturh w3, [x0, #1]
    mov   x10, #3
    b     4f
3:  add   x9, x3, #5
    cmp   x1, x9
    b.lo  Lpe_full
    mov   w11, #0x4e
    strb  w11, [x0]
    stur  w3, [x0, #1]                    /* the low 32 bits, as the twin */
    mov   x10, #5
4:  stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    add   x19, x10, x3                    /* header + data */
    add   x0, x0, x10
    mov   x1, x2
    mov   x2, x3
    bl    _memcpy
    mov   x0, x19
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret
Lpe_full:
    mov   x0, #-1
    ret

/* ============================================================================
 * sighash_all(out=x0, tx=x1, txlen=x2, idx=x3, script=x4, slen=x5,
 *             preimg=x6, cap=x7)
 * out x19, tx x20, txend x21, idx x22, script x23, slen x24, preimg x25,
 * pend x26, txcur x27, p x28 ; frame: n_in 0, i 8 -> 16
 * ========================================================================== */
    .p2align 2
    .globl _sighash_all
_sighash_all:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #16
    cmp   x2, #10
    b.lo  Lsa_no
    mov   x19, x0
    mov   x20, x1
    add   x21, x1, x2
    mov   x22, x3
    mov   x23, x4
    mov   x24, x5
    mov   x25, x6
    add   x26, x6, x7
    add   x0, x20, #4
    mov   x1, x21
    bl    Lpv
    mov   x27, x1
    cbz   x0, Lsa_no                      /* n_in */
    cmp   x22, x0
    b.hs  Lsa_no                          /* input_index >= n_in */
    str   x0, [sp]
    mov   x28, x25
    sub   x9, x26, x28
    cmp   x9, #4
    b.lo  Lsa_no
    ldr   w9, [x20]                       /* version */
    str   w9, [x28], #4
    mov   x0, x28
    ldr   x1, [sp]
    bl    Lwv                             /* n_in (cursor not re-checked, as x86) */
    mov   x28, x0
    str   xzr, [sp, #8]
Lsa_in:
    ldp   x9, x10, [sp]
    cmp   x10, x9
    b.hs  Lsa_tail
    COPY36 x28, x27                       /* prevout + index, raw */
    mov   x0, x27                         /* skip the scriptSig */
    mov   x1, x21
    bl    Lpv
    add   x27, x1, x0
    cmp   x27, x21
    b.hi  Lsa_no
    ldr   x10, [sp, #8]
    cmp   x10, x22
    b.ne  1f
    mov   x0, x28                         /* the signed input: the script */
    mov   x1, x24
    bl    Lwv
    mov   x28, x0
    cmp   x28, x26
    b.hi  Lsa_no                          /* FINDING 2b cap (varint only) */
    mov   x0, x28
    mov   x1, x23
    mov   x2, x24
    bl    _memcpy
    add   x28, x28, x24
    b     2f
1:  sub   x9, x26, x28
    cbz   x9, Lsa_no                      /* (u64)(pend - p) < 1 */
    strb  wzr, [x28], #1
2:  ldr   w9, [x27], #4                   /* sequence, raw */
    str   w9, [x28], #4
    ldr   x10, [sp, #8]
    add   x10, x10, #1
    str   x10, [sp, #8]
    b     Lsa_in
Lsa_tail:
    mov   x0, x28                         /* [txcur, txend) verbatim */
    mov   x1, x27
    sub   x2, x21, x27
    bl    _memcpy
    sub   x9, x21, x27
    add   x28, x28, x9
    sub   x9, x26, x28
    cmp   x9, #4
    b.lo  Lsa_no
    mov   w9, #1                          /* hashtype = SIGHASH_ALL */
    str   w9, [x28], #4
    mov   x0, x19
    mov   x1, x25
    sub   x2, x28, x25
    bl    _sha256d
    mov   w0, #1
    b     Lsa_ret
Lsa_no:
    mov   w0, #0
Lsa_ret:
    add   sp, sp, #16
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* ============================================================================
 * Llocate_nout(tx=x0, txend=x1, nIn=x2) -> x0 n_out, x1 ok (1/0)
 * Walks version, n_in and every input without writing; nIn >= n_in is not ok;
 * the n_out compact size must fit. p x19, txend x20, n_in x21, i x22
 * ========================================================================== */
    .p2align 2
Llocate_nout:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   x20, x1
    mov   x22, x2
    add   x0, x0, #4
    bl    Lpv
    mov   x19, x1
    cbz   x0, Lln_no
    cmp   x22, x0
    b.hs  Lln_no
    mov   x21, x0
    mov   x22, #0
1:  cmp   x22, x21
    b.hs  2f
    add   x19, x19, #36
    cmp   x19, x20
    b.hi  Lln_no
    mov   x0, x19
    mov   x1, x20
    bl    Lpv
    add   x19, x1, x0
    cmp   x19, x20
    b.hi  Lln_no
    add   x19, x19, #4
    cmp   x19, x20
    b.hi  Lln_no
    add   x22, x22, #1
    b     1b
2:  cmp   x19, x20
    b.hs  Lln_no
    ldrb  w9, [x19]                       /* the n_out compact size must fit */
    mov   x10, #1
    cmp   w9, #0xfd
    b.lo  3f
    mov   x10, #3
    b.eq  3f
    mov   x10, #5
    cmp   w9, #0xfe
    b.eq  3f
    mov   x10, #9
3:  sub   x11, x20, x19
    cmp   x11, x10
    b.lo  Lln_no
    mov   x0, x19
    mov   x1, x20
    bl    Lpv
    mov   x1, #1
    b     Lln_ret
Lln_no:
    mov   x0, #0
    mov   x1, #0
Lln_ret:
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * legacy_sighash(out=x0, tx=x1, txlen=x2, nIn=x3, sc=x4, scLen=x5, ht=w6,
 *                preimg=x7, cap=[caller sp])
 * out x19, tx x20, txend x21, nIn x22, preimg x23, pend x24, pcur x25,
 * walk x26, flags x27 (1 SINGLE, 2 NONE, 4 ANYONECANPAY), n_in x28
 * frame: ht 0, scf_len 8, i 16, n_out 24, j 32, scfbuf 40, prevout 48,
 *        seq 56, val 64, spk 72, spk_len 80 -> 96
 * ========================================================================== */
#define L_HT     0
#define L_SCF    8
#define L_I      16
#define L_NOUT   24
#define L_J      32
#define L_BUF    40
#define L_PREV   48
#define L_SEQ    56
#define L_VAL    64
#define L_SPK    72
#define L_SPKL   80
#define L_SIZE   96

/* ROOM n: (u64)(pend - pcur) < n -> fail ; x9 */
.macro ROOM n
    sub   x9, x24, x25
    cmp   x9, \n
    b.lo  Lls_no
.endm

    .p2align 2
    .globl _legacy_sighash
_legacy_sighash:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #L_SIZE
    ldr   x9, [x29, #96]                  /* cap: the 9th argument */
    cmp   x2, #10
    b.lo  Lls_no
    mov   x19, x0
    mov   x20, x1
    add   x21, x1, x2
    mov   x22, x3
    mov   x23, x7
    add   x24, x7, x9
    mov   w10, w6
    str   x10, [sp, #L_HT]
    and   w11, w6, #0x1f
    mov   x27, #0
    cmp   w11, #3
    cinc  x27, x27, eq                    /* SINGLE */
    cmp   w11, #2
    mov   x12, #2
    csel  x12, x12, xzr, eq
    orr   x27, x27, x12                   /* NONE */
    tst   w6, #0x80
    mov   x12, #4
    csel  x12, x12, xzr, ne
    orr   x27, x27, x12                   /* ANYONECANPAY */
    stp   x4, x5, [sp, #L_PREV]           /* scriptCode, scLen parked */
    add   x0, x20, #4
    mov   x1, x21
    bl    Lpv
    mov   x26, x1                         /* walk = txcur */
    mov   x28, x0
    cbz   x28, Lls_no
    cmp   x22, x28
    b.hs  Lls_no
    tbz   x27, #0, 1f                     /* SINGLE: out-of-range pre-check */
    mov   x0, x20
    mov   x1, x21
    mov   x2, x22
    bl    Llocate_nout
    cbz   x1, Lls_no
    cmp   x22, x0
    b.lo  1f
    mov   x9, #1                          /* the "one" hash */
    stp   x9, xzr, [x19]
    stp   xzr, xzr, [x19, #16]
    mov   w0, #1
    b     Lls_ret
1:  adrp  x0, _legacy_sighash_scfbuf@TLVPPAGE
    ldr   x0, [x0, _legacy_sighash_scfbuf@TLVPPAGEOFF]
    ldr   x8, [x0]
    blr   x8                              /* this thread's scfbuf */
    str   x0, [sp, #L_BUF]
    mov   x1, #SCFCAP                     /* strip OP_CODESEPARATOR */
    ldp   x2, x3, [sp, #L_PREV]
    adrp  x4, Lneedle_ab@PAGE
    add   x4, x4, Lneedle_ab@PAGEOFF
    mov   x5, #1
    bl    _script_find_and_delete
    cmn   x0, #1
    b.eq  Lls_no
    str   x0, [sp, #L_SCF]
    mov   x25, x23                        /* pcur = preimg */
    ROOM  #4
    ldr   w9, [x20]                       /* version */
    str   w9, [x25], #4
    mov   x0, x25                         /* n inputs: ACP ? 1 : n_in */
    mov   x1, x28
    tst   x27, #4
    mov   x9, #1
    csel  x1, x9, x1, ne
    bl    Lwv
    mov   x25, x0
    cmp   x25, x24
    b.hi  Lls_no
    str   xzr, [sp, #L_I]
Lls_in:
    ldr   x10, [sp, #L_I]
    cmp   x10, x28
    b.hs  Lls_outs
    str   x26, [sp, #L_PREV]              /* prevout */
    add   x26, x26, #36
    cmp   x26, x21
    b.hi  Lls_no
    mov   x0, x26
    mov   x1, x21
    bl    Lpv
    add   x26, x1, x0
    cmp   x26, x21
    b.hi  Lls_no
    str   x26, [sp, #L_SEQ]
    add   x26, x26, #4
    cmp   x26, x21
    b.hi  Lls_no
    ldr   x10, [sp, #L_I]
    cmp   x10, x22
    b.ne  2f
    ROOM  #36                             /* the signed input */
    ldr   x13, [sp, #L_PREV]
    COPY36 x25, x13
    mov   x0, x25
    ldr   x1, [sp, #L_SCF]
    bl    Lwv
    mov   x25, x0
    cmp   x25, x24
    b.hi  Lls_no
    ldr   x2, [sp, #L_SCF]
    ROOM  x2
    mov   x0, x25
    ldr   x1, [sp, #L_BUF]
    bl    _memcpy
    ldr   x2, [sp, #L_SCF]
    add   x25, x25, x2
    ROOM  #4
    ldr   x13, [sp, #L_SEQ]
    ldr   w9, [x13]
    str   w9, [x25], #4
    b     3f
2:  tbnz  x27, #2, 3f                     /* ACP: the others are not emitted */
    ROOM  #36
    ldr   x13, [sp, #L_PREV]
    COPY36 x25, x13
    ROOM  #1
    strb  wzr, [x25], #1                  /* empty script */
    ROOM  #4
    ldr   x13, [sp, #L_SEQ]
    ldr   w9, [x13]
    tst   x27, #3                         /* SINGLE / NONE: sequence 0 */
    csel  w9, wzr, w9, ne
    str   w9, [x25], #4
3:  ldr   x10, [sp, #L_I]
    add   x10, x10, #1
    str   x10, [sp, #L_I]
    b     Lls_in
Lls_outs:
    mov   x0, x26                         /* n_out, raw side */
    mov   x1, x21
    bl    Lpv
    mov   x26, x1
    str   x0, [sp, #L_NOUT]
    add   x1, x22, #1                     /* emitted: NONE 0, SINGLE nIn+1, else n_out */
    tst   x27, #1
    csel  x1, x1, x0, ne
    tst   x27, #2
    csel  x1, xzr, x1, ne
    mov   x0, x25
    bl    Lwv
    mov   x25, x0
    cmp   x25, x24
    b.hi  Lls_no
    str   xzr, [sp, #L_J]
Lls_out:
    ldp   x9, x10, [sp, #L_NOUT]          /* n_out, j */
    cmp   x10, x9
    b.hs  Lls_lock
    str   x26, [sp, #L_VAL]
    add   x26, x26, #8
    cmp   x26, x21
    b.hi  Lls_no
    mov   x0, x26
    mov   x1, x21
    bl    Lpv
    str   x1, [sp, #L_SPK]
    str   x0, [sp, #L_SPKL]
    add   x26, x1, x0
    cmp   x26, x21
    b.hi  Lls_no
    tbnz  x27, #1, 6f                     /* NONE: nothing */
    tbz   x27, #0, 5f
    ldr   x10, [sp, #L_J]
    cmp   x10, x22
    b.hi  6f                              /* SINGLE, j > nIn: nothing */
    b.eq  5f                              /* SINGLE, j == nIn: the real output */
    ROOM  #9                              /* SINGLE, j < nIn: (-1, empty) */
    mov   x9, #-1
    str   x9, [x25]
    strb  wzr, [x25, #8]
    add   x25, x25, #9
    b     6f
5:  ROOM  #8
    ldr   x13, [sp, #L_VAL]
    ldr   x9, [x13]
    str   x9, [x25], #8
    mov   x0, x25
    ldr   x1, [sp, #L_SPKL]
    bl    Lwv
    mov   x25, x0
    cmp   x25, x24
    b.hi  Lls_no
    ldr   x2, [sp, #L_SPKL]
    ROOM  x2
    mov   x0, x25
    ldr   x1, [sp, #L_SPK]
    bl    _memcpy
    ldr   x2, [sp, #L_SPKL]
    add   x25, x25, x2
6:  ldr   x10, [sp, #L_J]
    add   x10, x10, #1
    str   x10, [sp, #L_J]
    b     Lls_out
Lls_lock:
    add   x9, x26, #4                     /* locktime */
    cmp   x9, x21
    b.hi  Lls_no
    ROOM  #4
    ldr   w9, [x26]
    str   w9, [x25], #4
    ROOM  #4
    ldr   w9, [sp, #L_HT]                 /* the full hashtype pattern */
    str   w9, [x25], #4
    mov   x0, x19
    mov   x1, x23
    sub   x2, x25, x23
    bl    _sha256d
    mov   w0, #1
    b     Lls_ret
Lls_no:
    mov   w0, #0
Lls_ret:
    add   sp, sp, #L_SIZE
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

    .section __TEXT,__const
Lneedle_ab:
    .byte 0xab

/* the per-thread OP_CODESEPARATOR-stripped scriptCode */
.tbss _legacy_sighash_scfbuf$tlv$init, SCFCAP, 4

    .section __DATA,__thread_vars,thread_local_variables
    .p2align 3
    .globl _legacy_sighash_scfbuf
_legacy_sighash_scfbuf:
    .quad __tlv_bootstrap
    .quad 0
    .quad _legacy_sighash_scfbuf$tlv$init
