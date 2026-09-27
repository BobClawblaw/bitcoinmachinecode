/* ============================================================================
 * bitcoin_cli.S -- the S6 offline store CLI in AArch64 assembly (Apple
 * silicon), the counterpart of asm/bitcoin_cli.asm. Replaces cli_twin.c on
 * the Mac (2026-09-26); the twin stays in port/osx/test_support as the
 * oracle.
 *
 *   char* cli_hex(char* out, const u8* src, u64 n);   out past 2n hex chars
 *   long  cli_atoi(const char* s);           '-' sign, stops at a non-digit
 *   long  cli_hex_to_bin(u8 out[32], const char* hex64);       1 / 0
 *   long  cli_main(void* st, long argc, void** argv, u8* out, long cap);
 *         argv[0] the command, argv[1] its argument; the text answer (or an
 *         "error: ..." line) goes to out; returns its length.
 *
 * Commands: help, getblockcount / stop, getbestblockhash, getblockhash <h>,
 * getblock <h | hash64>, gettx <txid64>, getbalance, prune <h>.
 *
 * The x86 parity the twin documents is kept: uppercase hex digits are
 * REJECTED (the asm's 'A'-'F' branch falls into .bad); the block buffers are
 * the asm's -- 0x180 bytes for getblock / gettx / getbalance, 0x800 for
 * getblockhash, 0x4000 (a static buffer) for getbestblockhash -- so a larger
 * block is "not found" / skipped / "height out of range", as on x86; cap is
 * never checked (nor on x86). The varint bounds are the twin's real ones.
 * ========================================================================== */
    .text

/* cli_hex(out=x0, src=x1, n=x2) ; leaf */
    .p2align 2
    .globl _cli_hex
_cli_hex:
    adrp  x9, Lhexd@PAGE
    add   x9, x9, Lhexd@PAGEOFF
    cbz   x2, 2f
1:  ldrb  w10, [x1], #1
    lsr   w11, w10, #4
    and   w10, w10, #15
    ldrb  w11, [x9, x11]
    ldrb  w10, [x9, x10]
    strb  w11, [x0], #1
    strb  w10, [x0], #1
    subs  x2, x2, #1
    b.ne  1b
2:  ret

/* cli_atoi(s=x0) ; leaf */
    .p2align 2
    .globl _cli_atoi
_cli_atoi:
    mov   x9, #0                          /* value */
    mov   w10, #0                         /* negative */
    ldrb  w11, [x0]
    cmp   w11, #'-'
    b.ne  1f
    mov   w10, #1
    add   x0, x0, #1
1:  ldrb  w11, [x0], #1
    sub   w11, w11, #'0'
    cmp   w11, #9
    b.hi  2f
    mov   x12, #10
    madd  x9, x9, x12, x11
    b     1b
2:  cmp   w10, #0
    cneg  x0, x9, ne
    ret

/* HEXVAL wd, ws: wd = the digit's value, or branch to \bad ; 0-9 a-f only */
.macro HEXVAL wd, ws, bad
    sub   \wd, \ws, #'0'
    cmp   \wd, #9
    b.ls  91f
    sub   \wd, \ws, #'a'
    cmp   \wd, #5
    b.hi  \bad
    add   \wd, \wd, #10
91:
.endm

/* cli_hex_to_bin(out=x0, h=x1) ; leaf */
    .p2align 2
    .globl _cli_hex_to_bin
_cli_hex_to_bin:
    mov   x9, #0
1:  add   x12, x1, x9, lsl #1
    ldrb  w10, [x12]
    HEXVAL w11, w10, 9f
    ldrb  w10, [x12, #1]
    HEXVAL w13, w10, 9f
    orr   w11, w13, w11, lsl #4
    strb  w11, [x0, x9]
    add   x9, x9, #1
    cmp   x9, #32
    b.lo  1b
    ldrb  w10, [x1, #64]                  /* and nothing after the 64 digits */
    cmp   w10, #0
    cset  x0, eq
    ret
9:  mov   x0, #0
    ret

/* Lrev32(o=x0, s=x1) ; leaf */
    .p2align 2
Lrev32:
    ldp   x9, x10, [x1]
    ldp   x11, x12, [x1, #16]
    rev   x9, x9
    rev   x10, x10
    rev   x11, x11
    rev   x12, x12
    stp   x12, x11, [x0]
    stp   x10, x9, [x0, #16]
    ret

/* Lemit_dec(o=x0, v=x1) -> x0 past the digits ; leaf, a 24-byte scratch */
    .p2align 2
Lemit_dec:
    sub   sp, sp, #32
    mov   x9, #0
    mov   x10, #10
1:  udiv  x11, x1, x10
    msub  x12, x11, x10, x1
    add   w12, w12, #'0'
    strb  w12, [sp, x9]
    add   x9, x9, #1
    mov   x1, x11
    cbnz  x1, 1b
2:  sub   x9, x9, #1
    ldrb  w12, [sp, x9]
    strb  w12, [x0], #1
    cbnz  x9, 2b
    add   sp, sp, #32
    ret

/* Lemit(o=x0, s=x1, n=x2) -> x0 = o + n */
    .p2align 2
Lemit:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x2
    bl    _memcpy
    add   x0, x19, x20
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* Lload_block(st=x0, h=x1, buf=x2, cap=x3) -> length / -1
 * st x19, buf x20, cap x21 ; frame meta 0 (32) */
    .p2align 2
Lload_block:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #32
    mov   x19, x0
    mov   x20, x2
    mov   x21, x3
    mov   x2, sp
    bl    _store_get_at
    cmp   x0, #1
    b.ne  9f
    ldr   x9, [sp, #8]
    cmp   x9, x21
    b.hi  9f                              /* larger than the buffer */
    mov   x0, x19
    ldr   w1, [sp, #16]
    bl    _store_get_file_fd
    tbnz  x0, #63, 9f
    mov   w22, w0
    ldr   x1, [sp]
    add   x1, x1, #8
    mov   w2, #0                          /* SEEK_SET */
    bl    _lseek
    tbnz  x0, #63, 9f
    mov   w0, w22
    mov   x1, x20
    ldr   x2, [sp, #8]
    bl    _read
    ldr   x9, [sp, #8]
    cmp   x0, x9
    b.ne  9f
    mov   x0, x9
    b     10f
9:  mov   x0, #-1
10: add   sp, sp, #32
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* Lread_varint(p=x0, len=x1) -> x0 bytes / -1, x1 value ; leaf */
    .p2align 2
Lread_varint:
    cmp   x1, #1
    b.lt  9f
    ldrb  w9, [x0]
    cmp   w9, #0xfd
    b.hs  1f
    mov   x1, x9
    mov   x0, #1
    ret
1:  b.ne  2f
    cmp   x1, #3
    b.lt  9f
    ldurh w1, [x0, #1]
    mov   x0, #3
    ret
2:  cmp   w9, #0xfe
    b.ne  3f
    cmp   x1, #5
    b.lt  9f
    ldur  w1, [x0, #1]
    mov   x0, #5
    ret
3:  cmp   x1, #9
    b.lt  9f
    ldur  x1, [x0, #1]
    mov   x0, #9
    ret
9:  mov   x0, #-1
    ret

/* Lhash_line(o=x0, blk=x1) -> x0 past "hash\n" (display order) ;
 * o x19 ; frame h 0, r 32 */
    .p2align 2
Lhash_line:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #64
    mov   x19, x0
    mov   x0, sp
    bl    _block_hash
    add   x0, sp, #32
    mov   x1, sp
    bl    Lrev32
    mov   x0, x19
    add   x1, sp, #32
    mov   x2, #32
    bl    _cli_hex
    mov   w9, #'\n'
    strb  w9, [x0], #1
    add   sp, sp, #64
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* ---- commands: (st, [arg,] o) -> x0 past the answer, or 0 --------------- */

/* Lcmd_count(st=x0, o=x1) */
    .p2align 2
Lcmd_count:
    ldr   w9, [x0, #24]
    cmn   w9, #1
    b.eq  9f
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    mov   x0, x1
    add   w1, w9, #1                      /* (u32)(tip + 1) */
    bl    Lemit_dec
    mov   w9, #'\n'
    strb  w9, [x0], #1
    ldp   x29, x30, [sp], #16
    ret
9:  mov   x0, #0
    ret

/* Lcmd_best(st=x0, o=x1) ; o x19 */
    .p2align 2
Lcmd_best:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    mov   x19, x1
    ldr   w1, [x0, #24]                   /* (u32) tip, zero-extended */
    cmn   w1, #1
    b.eq  9f
    adrp  x2, Lbestbuf@PAGE
    add   x2, x2, Lbestbuf@PAGEOFF
    mov   x3, #0x4000
    bl    Lload_block
    cmp   x0, #80
    b.lt  9f
    mov   x0, x19
    adrp  x1, Lbestbuf@PAGE
    add   x1, x1, Lbestbuf@PAGEOFF
    bl    Lhash_line
    b     10f
9:  mov   x0, #0
10: ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* Lcmd_bhash(st=x0, arg=x1, o=x2) ; st x19, o x20, h x21 ; frame buf 0x800 */
    .p2align 2
Lcmd_bhash:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #0x800
    mov   x19, x0
    mov   x20, x2
    mov   x0, x1
    bl    _cli_atoi
    mov   x21, x0
    ldr   w9, [x19, #24]
    cmn   w9, #1
    b.eq  9f
    cmp   x21, x9                         /* unsigned: a negative height is out */
    b.hi  9f
    mov   x0, x19
    mov   x1, x21
    mov   x2, sp
    mov   x3, #0x800
    bl    Lload_block
    cmp   x0, #80
    b.lt  9f
    mov   x0, x20
    mov   x1, sp
    bl    Lhash_line
    b     10f
9:  mov   x0, #0
10: add   sp, sp, #0x800
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * Lcmd_block(st=x0, arg=x1, o=x2)
 * st x19, arg x20, o x21, h x22, tip x23, length x24 ; frame: buf 0 (0x180),
 * bin 0x180, want 0x1a0, got 0x1c0 -> 0x1e0
 * ========================================================================== */
    .p2align 2
Lcmd_block:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    mov   x29, sp
    sub   sp, sp, #0x1e0
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    ldrsw x23, [x19, #24]
    mov   x9, x20                         /* all digits (or empty)? a height */
1:  ldrb  w10, [x9], #1
    cbz   w10, Lcb_height
    sub   w10, w10, #'0'
    cmp   w10, #9
    b.ls  1b
    add   x0, sp, #0x180                  /* else a hash */
    mov   x1, x20
    bl    _cli_hex_to_bin
    cbz   x0, Lcb_none
    add   x0, sp, #0x1a0
    add   x1, sp, #0x180
    bl    Lrev32
    cmn   x23, #1
    b.eq  Lcb_none
    mov   w22, #0
2:  cmp   w22, w23                        /* h <= (u32) tip */
    b.hi  Lcb_none
    mov   x0, x19
    mov   w1, w22
    mov   x2, sp
    mov   x3, #0x180
    bl    Lload_block
    cmp   x0, #80
    b.lt  3f
    mov   x24, x0
    add   x0, sp, #0x1c0
    mov   x1, sp
    bl    _block_hash
    add   x9, sp, #0x1c0
    add   x10, sp, #0x1a0
    ldp   x11, x12, [x9]
    ldp   x13, x14, [x10]
    cmp   x11, x13
    ccmp  x12, x14, #0, eq
    ldp   x11, x12, [x9, #16]
    ldp   x13, x14, [x10, #16]
    ccmp  x11, x13, #0, eq
    ccmp  x12, x14, #0, eq
    b.ne  3f
    mov   x0, x24
    b     Lcb_emit
3:  add   w22, w22, #1
    b     2b
Lcb_height:
    mov   x0, x20
    bl    _cli_atoi
    cmn   x23, #1
    b.eq  Lcb_none
    mov   w9, w23
    cmp   x0, x9                          /* unsigned, as the twin */
    b.hi  Lcb_none
    mov   x1, x0
    mov   x0, x19
    mov   x2, sp
    mov   x3, #0x180
    bl    Lload_block
    cmp   x0, #0
    b.le  Lcb_none
Lcb_emit:                                 /* x0 = the length */
    mov   x2, x0
    mov   x0, x21
    mov   x1, sp
    bl    _cli_hex
    mov   w9, #'\n'
    strb  w9, [x0], #1
    b     Lcb_ret
Lcb_none:
    mov   x0, #0
Lcb_ret:
    add   sp, sp, #0x1e0
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* ============================================================================
 * Lcmd_tx(st=x0, arg=x1, o=x2)
 * st x19, o x20, h x21, tip x22, p x23, rem x24, ntx x25, i x26, n x27,
 * tl x28 ; frame: buf 0 (0x180), bin 0x180, want 0x1a0, id 0x1c0,
 * info 0x1e0 (64) -> 0x220
 * ========================================================================== */
    .p2align 2
Lcmd_tx:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #0x220
    mov   x19, x0
    mov   x20, x2
    add   x0, sp, #0x180
    bl    _cli_hex_to_bin                 /* (x1 = arg still) */
    cbz   x0, Ltx_none
    add   x0, sp, #0x1a0
    add   x1, sp, #0x180
    bl    Lrev32
    ldrsw x22, [x19, #24]
    cmn   x22, #1
    b.eq  Ltx_none
    mov   w21, #0
1:  cmp   w21, w22
    b.hi  Ltx_none
    mov   x0, x19
    mov   w1, w21
    mov   x2, sp
    mov   x3, #0x180
    bl    Lload_block
    cmp   x0, #80
    b.le  5f
    mov   x27, x0
    add   x0, sp, #80
    sub   x1, x27, #80
    bl    Lread_varint
    tbnz  x0, #63, 5f
    cbz   x1, 5f
    mov   x25, x1                         /* ntx */
    add   x23, sp, #80
    add   x23, x23, x0                    /* p */
    sub   x24, x27, #80
    sub   x24, x24, x0                    /* rem */
    mov   x26, #0
2:  cmp   x26, x25
    b.hs  5f
    cmp   x24, #0
    b.le  5f
    add   x0, sp, #0x1e0
    mov   x1, x23
    mov   x2, x24
    bl    _tx_parse
    cmp   x0, #1
    b.ne  5f
    ldr   x28, [sp, #0x1e0]               /* the tx length */
    cmp   x28, #0
    b.le  5f
    cmp   x28, x24
    b.gt  5f
    add   x0, sp, #0x1c0
    mov   x1, x23
    mov   x2, x28
    bl    _sha256d
    add   x9, sp, #0x1c0
    add   x10, sp, #0x1a0
    ldp   x11, x12, [x9]
    ldp   x13, x14, [x10]
    cmp   x11, x13
    ccmp  x12, x14, #0, eq
    ldp   x11, x12, [x9, #16]
    ldp   x13, x14, [x10, #16]
    ccmp  x11, x13, #0, eq
    ccmp  x12, x14, #0, eq
    b.eq  3f
    add   x23, x23, x28
    sub   x24, x24, x28
    add   x26, x26, #1
    b     2b
3:  mov   x0, x20                         /* "found in block <h>\n<hex>\n" */
    adrp  x1, Lfound@PAGE
    add   x1, x1, Lfound@PAGEOFF
    mov   x2, #15
    bl    Lemit
    mov   w1, w21
    bl    Lemit_dec
    mov   w9, #'\n'
    strb  w9, [x0], #1
    mov   x1, x23
    mov   x2, x28
    bl    _cli_hex
    mov   w9, #'\n'
    strb  w9, [x0], #1
    b     Ltx_ret
5:  add   w21, w21, #1
    b     1b
Ltx_none:
    mov   x0, #0
Ltx_ret:
    add   sp, sp, #0x220
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* ============================================================================
 * Lcmd_balance(st=x0, o=x1)
 * st x19, o x20, h x21, tip x22, sum x23, p x24, end x25, k x26, nout x27,
 * n x28 ; frame: buf 0 (0x180), info 0x180 (64) -> 0x1c0
 * ========================================================================== */
    .p2align 2
Lcmd_balance:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    sub   sp, sp, #0x1c0
    mov   x19, x0
    mov   x20, x1
    ldrsw x22, [x19, #24]
    cmn   x22, #1
    b.eq  Lbal_none
    mov   x23, #0
    mov   w21, #0
1:  cmp   w21, w22
    b.hi  Lbal_done
    mov   x0, x19
    mov   w1, w21
    mov   x2, sp
    mov   x3, #0x180
    bl    Lload_block
    cmp   x0, #80
    b.le  5f
    mov   x28, x0
    add   x0, sp, #80
    sub   x1, x28, #80
    bl    Lread_varint
    tbnz  x0, #63, 5f
    cbz   x1, 5f
    add   x24, sp, #80
    add   x24, x24, x0                    /* the coinbase */
    sub   x2, x28, #80
    sub   x2, x2, x0
    add   x0, sp, #0x180
    mov   x1, x24
    bl    _tx_parse
    cmp   x0, #1
    b.ne  5f
    ldr   w27, [sp, #0x180 + 16]          /* n_out */
    ldr   x9, [sp, #0x180 + 40]           /* out0 value offset */
    add   x24, x24, x9
    add   x25, sp, x28                    /* end = buf + n */
    mov   w26, #0
2:  cmp   w26, w27
    b.hs  5f
    add   x9, x24, #8
    cmp   x9, x25
    b.hi  5f
    ldr   x9, [x24]
    add   x23, x23, x9                    /* sum += value */
    add   x0, x24, #8
    sub   x1, x25, x0
    bl    Lread_varint
    tbnz  x0, #63, 5f
    add   x24, x24, #8
    add   x24, x24, x0
    add   x24, x24, x1
    add   w26, w26, #1
    b     2b
5:  add   w21, w21, #1
    b     1b
Lbal_done:
    mov   x0, x20
    mov   x1, x23
    bl    Lemit_dec
    mov   w9, #'\n'
    strb  w9, [x0], #1
    b     Lbal_ret
Lbal_none:
    mov   x0, #0
Lbal_ret:
    add   sp, sp, #0x1c0
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* ============================================================================
 * cli_main(st=x0, argc=x1, argv=x2, out=x3, cap=x4)
 * st x19, cmd x20, a1 x21, out x22
 * ========================================================================== */
.macro ISCMD name, target
    mov   x0, x20
    adrp  x1, \name@PAGE
    add   x1, x1, \name@PAGEOFF
    bl    _strcmp
    cbz   w0, \target
.endm
.macro ERR msg, len
    mov   x0, x22
    adrp  x1, \msg@PAGE
    add   x1, x1, \msg@PAGEOFF
    mov   x2, #\len
    bl    Lemit
    b     Lcm_len
.endm

    .p2align 2
    .globl _cli_main
_cli_main:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x22, x3
    mov   x20, #0
    mov   x21, #0
    cmp   x1, #0
    b.le  1f
    ldr   x20, [x2]
    cmp   x1, #1
    b.le  1f
    ldr   x21, [x2, #8]
1:  cbz   x20, Lcm_usage
    ISCMD Lc_help, Lcm_help
    ISCMD Lc_count, Lcm_count
    ISCMD Lc_stop, Lcm_count
    ISCMD Lc_best, Lcm_best
    ISCMD Lc_bhash, Lcm_bhash
    ISCMD Lc_block, Lcm_block
    ISCMD Lc_tx, Lcm_tx
    ISCMD Lc_balance, Lcm_balance
    ISCMD Lc_prune, Lcm_prune
Lcm_usage:
    ERR   Le_usage, 34
Lcm_arg:
    ERR   Le_arg, 20
Lcm_range:
    ERR   Le_range, 27
Lcm_nf:
    ERR   Le_nf, 17
Lcm_help:
    mov   x0, x22
    adrp  x1, Lhelp@PAGE
    add   x1, x1, Lhelp@PAGEOFF
    adrp  x2, Lhelp_len@PAGE
    ldr   x2, [x2, Lhelp_len@PAGEOFF]
    bl    Lemit
    b     Lcm_len
Lcm_count:
    mov   x0, x19
    mov   x1, x22
    bl    Lcmd_count
    cbz   x0, Lcm_range
    b     Lcm_len
Lcm_best:
    mov   x0, x19
    mov   x1, x22
    bl    Lcmd_best
    cbz   x0, Lcm_range
    b     Lcm_len
Lcm_bhash:
    cbz   x21, Lcm_arg
    mov   x0, x19
    mov   x1, x21
    mov   x2, x22
    bl    Lcmd_bhash
    cbz   x0, Lcm_range
    b     Lcm_len
Lcm_block:
    cbz   x21, Lcm_arg
    mov   x0, x19
    mov   x1, x21
    mov   x2, x22
    bl    Lcmd_block
    cbz   x0, Lcm_nf
    b     Lcm_len
Lcm_tx:
    cbz   x21, Lcm_arg
    mov   x0, x19
    mov   x1, x21
    mov   x2, x22
    bl    Lcmd_tx
    cbz   x0, Lcm_nf
    b     Lcm_len
Lcm_balance:
    mov   x0, x19
    mov   x1, x22
    bl    Lcmd_balance
    cbz   x0, Lcm_range
    b     Lcm_len
Lcm_prune:
    cbz   x21, Lcm_arg
    mov   x0, x21
    bl    _cli_atoi
    mov   w1, w0                          /* (int) */
    mov   x0, x19
    bl    _store_prune
    tbnz  w0, #31, Lcm_range
    mov   x0, x22                         /* "pruned to height <eff>\n" */
    adrp  x1, Lpruned@PAGE
    add   x1, x1, Lpruned@PAGEOFF
    mov   x2, #17
    bl    Lemit
    ldr   w1, [x19, #48]                  /* the effective (clamped) height, u32 */
    bl    Lemit_dec
    mov   w9, #'\n'
    strb  w9, [x0], #1
Lcm_len:
    sub   x0, x0, x22
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

    .section __TEXT,__const
Lhexd:      .ascii "0123456789abcdef"
    .p2align 3
Lhelp_len:  .quad Lhelp_end - Lhelp

    .section __TEXT,__cstring
Lhelp:
    .ascii "Bitcoin node CLI (all-asm)\n"
    .ascii "  help                  this text\n"
    .ascii "  getblockcount         number of blocks in store\n"
    .ascii "  getbestblockhash      best block hash (display order)\n"
    .ascii "  getblockhash <h>      hash of block at height h\n"
    .ascii "  getblock <h|hash64>   raw block bytes as hex\n"
    .ascii "  gettx <txid64>        find + print a transaction by id\n"
    .ascii "  getbalance            total of stored coinbase outputs (sat)\n"
    .ascii "  prune <height>        delete blk data below height (Core -prune)\n"
    .ascii "  stop                  report current tip\n"
Lhelp_end:
    .byte 0
Le_usage:   .asciz "error: unknown command (try help)\n"
Le_arg:     .asciz "error: bad argument\n"
Le_range:   .asciz "error: height out of range\n"
Le_nf:      .asciz "error: not found\n"
Lfound:     .asciz "found in block "
Lpruned:    .asciz "pruned to height "
Lc_help:    .asciz "help"
Lc_count:   .asciz "getblockcount"
Lc_stop:    .asciz "stop"
Lc_best:    .asciz "getbestblockhash"
Lc_bhash:   .asciz "getblockhash"
Lc_block:   .asciz "getblock"
Lc_tx:      .asciz "gettx"
Lc_balance: .asciz "getbalance"
Lc_prune:   .asciz "prune"

.zerofill __DATA,__bss,Lbestbuf,0x4000,4
