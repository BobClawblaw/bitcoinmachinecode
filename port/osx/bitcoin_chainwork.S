/* ============================================================================
 * bitcoin_chainwork.S -- the chainwork layer in AArch64 assembly (Apple
 * silicon), the counterpart of asm/bitcoin_chainwork.asm. Replaces
 * chainwork_twin.c on the Mac (2026-09-26); the twin stays in
 * port/osx/test_support as the oracle.
 *
 *   void compact_to_target_le(u8 out_le[32], u32 bits);
 *   void u256_div(u8 q_le[32], const u8 a_le[32], const u8 b_le[32]);
 *   void block_work(u64 work[2], u32 bits);
 *   void chainwork_add(u64 out[2], const u64 a[2], const u64 b[2]);
 *   long chainwork_cmp(const u64 a[2], const u64 b[2]);          -1 / 0 / 1
 *   long store_chainwork_init(void* st);                         1 / -1
 *   long store_chainwork_append(void* st, long height, const u64 work[2]);
 *   long store_chainwork_get_at(void* st, long height, u64 out[2]);
 *   long store_chainwork_get_tip(void* st, u64 out[2]);
 *   long store_chainwork_reload(void* st);               record count / -1
 *   long store_chainwork_truncate(void* st, long target_height);  1 / -1
 *
 * compact_to_target_le: exponent < 3 -> 0; the 3 mantissa bytes land at
 *   byte exp-3 (little-endian); an offset past 29 -> 0 (they would pass
 *   byte 31).
 * u256_div: restoring division, bit 255 down to 0, as the x86: R = R<<1 |
 *   a_bit (the bit shifted out of R is COUT), t = R - B with a real borrow
 *   chain, commit (R = t, quotient bit 1) iff no borrow OR COUT. The
 *   quotient is shifted in from the top instead of OR-ed at bit i -- the
 *   same bits in the same places. (The twin computed the borrow per limb
 *   as R < B+borrow, which lost the borrow when B's limb is all-ones and a
 *   borrow comes in; the x86 sbb does not, nor does this sbcs chain. Not
 *   reachable from block_work -- a compact target has at most three nonzero
 *   bytes -- but u256_div is exported; the oracle is corrected with this.)
 * block_work: target = 0 -> 0; target + 1 wrapping -> 0; else work =
 *   ~target / (target + 1) + 1, low 128 bits.
 * chainwork_add: 128-bit add saturating to all-ones on the carry out.
 *
 * The store layer keeps one process-wide chainwork.dat (cwd) of 16-byte
 * cumulative records, fd and tip in __DATA as the twin's statics (the st
 * argument is unused, as in the twin). Through libc; open() is variadic,
 * so its mode goes on the stack (Darwin arm64). Every return is a full
 * 64-bit value (-1 sign-extended), as the x86's rax.
 * ========================================================================== */
#define O_RDWR   0x0002
#define O_CREAT  0x0200
#define SEEK_END 2

    .text

/* compact_to_target_le(out=x0, bits=w1) ; leaf */
    .p2align 2
    .globl _compact_to_target_le
_compact_to_target_le:
    stp   xzr, xzr, [x0]
    stp   xzr, xzr, [x0, #16]
    lsr   w9, w1, #24                     /* exponent */
    subs  w9, w9, #3                      /* offset of the mantissa LSB */
    b.lo  1f
    cmp   w9, #29
    b.hi  1f
    add   x10, x0, x9
    strb  w1, [x10]
    lsr   w11, w1, #8
    strb  w11, [x10, #1]
    lsr   w11, w1, #16
    strb  w11, [x10, #2]
1:  ret

/* ============================================================================
 * u256_div(q=x0, a=x1, b=x2)
 * B x3..x6, R x7..x10, Q x11..x14, t x15..x17 + x19, COUT x20,
 * bit index x2, commit x21 ; q stays in x0
 * ========================================================================== */
    .p2align 2
    .globl _u256_div
_u256_div:
    stp   x19, x20, [sp, #-32]!
    str   x21, [sp, #16]
    ldp   x3, x4, [x2]
    ldp   x5, x6, [x2, #16]
    mov   x7, xzr
    mov   x8, xzr
    mov   x9, xzr
    mov   x10, xzr
    mov   x11, xzr
    mov   x12, xzr
    mov   x13, xzr
    mov   x14, xzr
    mov   x2, #255
1:  lsr   x20, x10, #63                   /* COUT */
    extr  x10, x10, x9, #63               /* R <<= 1 */
    extr  x9, x9, x8, #63
    extr  x8, x8, x7, #63
    lsr   x15, x2, #6
    ldr   x15, [x1, x15, lsl #3]          /* A[bit >> 6] */
    lsr   x15, x15, x2                    /* >> (bit & 63) */
    and   x15, x15, #1
    orr   x7, x15, x7, lsl #1             /* | a_bit */
    subs  x15, x7, x3                     /* t = R - B, real borrow chain */
    sbcs  x16, x8, x4
    sbcs  x17, x9, x5
    sbcs  x19, x10, x6
    cset  x21, cs                         /* no borrow */
    orr   x21, x21, x20                   /* ... or COUT: commit */
    extr  x14, x14, x13, #63              /* Q = Q<<1 | commit */
    extr  x13, x13, x12, #63
    extr  x12, x12, x11, #63
    orr   x11, x21, x11, lsl #1
    cbz   x21, 2f
    mov   x7, x15
    mov   x8, x16
    mov   x9, x17
    mov   x10, x19
2:  subs  x2, x2, #1
    b.pl  1b
    stp   x11, x12, [x0]
    stp   x13, x14, [x0, #16]
    ldr   x21, [sp, #16]
    ldp   x19, x20, [sp], #32
    ret

/* ============================================================================
 * block_work(work=x0, bits=w1) ; frame: target 0, num 32, den 64, q 96 -> 128
 * ========================================================================== */
    .p2align 2
    .globl _block_work
_block_work:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #128
    mov   x19, x0
    mov   x0, sp
    bl    _compact_to_target_le
    ldp   x9, x10, [sp]
    ldp   x11, x12, [sp, #16]
    orr   x13, x9, x10
    orr   x14, x11, x12
    orr   x13, x13, x14
    cbz   x13, Lbw_zero                   /* target 0: no work */
    mvn   x13, x9                         /* num = ~target */
    mvn   x14, x10
    mvn   x15, x11
    mvn   x16, x12
    stp   x13, x14, [sp, #32]
    stp   x15, x16, [sp, #48]
    adds  x9, x9, #1                      /* den = target + 1 */
    adcs  x10, x10, xzr
    adcs  x11, x11, xzr
    adcs  x12, x12, xzr
    b.cs  Lbw_zero                        /* wrapped (x86 jc .overflow) */
    stp   x9, x10, [sp, #64]
    stp   x11, x12, [sp, #80]
    add   x0, sp, #96
    add   x1, sp, #32
    add   x2, sp, #64
    bl    _u256_div
    ldp   x9, x10, [sp, #96]
    adds  x9, x9, #1                      /* + 1, low 128 bits */
    adc   x10, x10, xzr
    stp   x9, x10, [x19]
    b     Lbw_ret
Lbw_zero:
    stp   xzr, xzr, [x19]
Lbw_ret:
    add   sp, sp, #128
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* chainwork_add(out=x0, a=x1, b=x2) ; leaf, saturating */
    .p2align 2
    .globl _chainwork_add
_chainwork_add:
    ldp   x9, x10, [x1]
    ldp   x11, x12, [x2]
    adds  x9, x9, x11
    adcs  x10, x10, x12
    csinv x9, x9, xzr, cc                 /* carry out: all-ones */
    csinv x10, x10, xzr, cc
    stp   x9, x10, [x0]
    ret

/* chainwork_cmp(a=x0, b=x1) ; leaf */
    .p2align 2
    .globl _chainwork_cmp
_chainwork_cmp:
    ldp   x9, x10, [x0]
    ldp   x11, x12, [x1]
    cmp   x10, x12
    b.ne  1f
    cmp   x9, x11
1:  cset  x0, hi                          /* 1 if a > b */
    csinv x0, x0, xzr, hs                 /* -1 if a < b ; 0 if equal */
    ret

/* ---- the store layer: chainwork.dat, fd and tip in __DATA ---------------- */

/* x9 = &Lcw (fd at +0, tip at +8) */
.macro CWADDR reg
    adrp  \reg, Lcw@PAGE
    add   \reg, \reg, Lcw@PAGEOFF
.endm

/* store_chainwork_init(st) */
    .p2align 2
    .globl _store_chainwork_init
_store_chainwork_init:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #16
    CWADDR x19
    ldr   x0, [x19]
    tbnz  x0, #63, 1f                     /* an fd already open: close it */
    bl    _close
    mov   x9, #-1
    str   x9, [x19]
1:  adrp  x0, Lcw_path@PAGE
    add   x0, x0, Lcw_path@PAGEOFF
    mov   w1, #(O_RDWR | O_CREAT)
    mov   x9, #0644
    str   x9, [sp]                        /* variadic mode: on the stack */
    bl    _open
    sxtw  x0, w0
    str   x0, [x19]
    tbnz  x0, #63, 2f
    stp   xzr, xzr, [x19, #8]             /* tip = 0 */
    mov   x0, #1
    b     3f
2:  mov   x0, #-1
3:  add   sp, sp, #16
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* store_chainwork_append(st, height=x1, work=x2)
 * frame: prev 0, new 16 ; &Lcw x19, height x20, work x21 */
    .p2align 2
    .globl _store_chainwork_append
_store_chainwork_append:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #32
    CWADDR x19
    mov   x20, x1
    mov   x21, x2
    ldr   x0, [x19]
    tbnz  x0, #63, Lcwa_no
    stp   xzr, xzr, [sp]                  /* prev = 0 at height 0 */
    cbz   x20, 1f
    mov   x1, sp
    mov   x2, #16
    sub   x3, x20, #1
    lsl   x3, x3, #4
    bl    _pread
    cmp   x0, #16
    b.ne  Lcwa_no
1:  add   x0, sp, #16
    mov   x1, sp
    mov   x2, x21
    bl    _chainwork_add
    ldr   x0, [x19]
    add   x1, sp, #16
    mov   x2, #16
    lsl   x3, x20, #4
    bl    _pwrite
    cmp   x0, #16
    b.ne  Lcwa_no
    ldp   x9, x10, [sp, #16]
    stp   x9, x10, [x19, #8]              /* tip */
    mov   x0, #1
    b     Lcwa_ret
Lcwa_no:
    mov   x0, #-1
Lcwa_ret:
    add   sp, sp, #32
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* store_chainwork_get_at(st, height=x1, out=x2) */
    .p2align 2
    .globl _store_chainwork_get_at
_store_chainwork_get_at:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    CWADDR x9
    ldr   x0, [x9]
    tbnz  x0, #63, 1f
    lsl   x3, x1, #4
    mov   x1, x2
    mov   x2, #16
    bl    _pread
    cmp   x0, #16
    b.ne  1f
    mov   x0, #1
    b     2f
1:  mov   x0, #-1
2:  ldp   x29, x30, [sp], #16
    ret

/* store_chainwork_get_tip(st, out=x1) ; leaf */
    .p2align 2
    .globl _store_chainwork_get_tip
_store_chainwork_get_tip:
    CWADDR x9
    ldp   x10, x11, [x9, #8]
    stp   x10, x11, [x1]
    mov   x0, #1
    ret

/* store_chainwork_reload(st) ; &Lcw x19, n x20 */
    .p2align 2
    .globl _store_chainwork_reload
_store_chainwork_reload:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    CWADDR x19
    ldr   x0, [x19]
    tbnz  x0, #63, Lcwr_no
    mov   x1, #0
    mov   w2, #SEEK_END
    bl    _lseek
    tbnz  x0, #63, Lcwr_no
    lsr   x20, x0, #4                     /* whole records; a partial tail is ignored */
    stp   xzr, xzr, [x19, #8]
    cbz   x20, Lcwr_n
    ldr   x0, [x19]
    add   x1, x19, #8                     /* read the last record into the tip */
    mov   x2, #16
    sub   x3, x20, #1
    lsl   x3, x3, #4
    bl    _pread
    cmp   x0, #16
    b.eq  Lcwr_n
    stp   xzr, xzr, [x19, #8]             /* (the twin reads into a local) */
Lcwr_no:
    mov   x0, #-1
    b     Lcwr_ret
Lcwr_n:
    mov   x0, x20
Lcwr_ret:
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* store_chainwork_truncate(st, target_height=x1) ; target x19 */
    .p2align 2
    .globl _store_chainwork_truncate
_store_chainwork_truncate:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    mov   x19, x1
    cmn   x19, #1
    b.lt  Lcwt_no                         /* target < -1 */
    CWADDR x9
    ldr   x0, [x9]
    tbnz  x0, #63, Lcwt_no
    bl    _store_chainwork_reload
    cmn   x0, #1
    b.eq  Lcwt_no
    add   x9, x19, #1
    cmp   x9, x0
    b.ge  Lcwt_ok                         /* nothing past the target */
    CWADDR x10
    ldr   x0, [x10]
    lsl   x1, x9, #4
    bl    _ftruncate
    tbnz  w0, #31, Lcwt_no
    bl    _store_chainwork_reload
    cmn   x0, #1
    b.eq  Lcwt_no
Lcwt_ok:
    mov   x0, #1
    b     Lcwt_ret
Lcwt_no:
    mov   x0, #-1
Lcwt_ret:
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .section __TEXT,__cstring
Lcw_path:
    .asciz "chainwork.dat"

    .data
    .p2align 3
Lcw:        /* fd (-1 = closed), then the tip's two limbs */
    .quad -1, 0, 0
