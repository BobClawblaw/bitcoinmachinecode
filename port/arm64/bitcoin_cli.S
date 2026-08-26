/* ============================================================================
 * bitcoin_cli.S -- AArch64 (GNU as) port of asm/bitcoin_cli.asm: the all-asm
 * Bitcoin node CLI. Inspects the persistent store (blk00000.dat + index.dat)
 * and prints human-readable answers. Thin C driver passes argv/argc and
 * writes the returned output buffer to stdout.
 *
 * Exports:
 *   char* cli_hex(out, src, n)             -> advanced out  (n*2 hex chars)
 *   long  cli_atoi(str)                    -> value (0 if not a valid int)
 *   long  cli_hex_to_bin(out32, hexstr)    -> 1 ok / 0 bad (exactly 64 hex)
 *   long  cli_main(store, argc, argv, out, cap) -> byte count / -1
 *
 * Deps (all already ported): store_get_at, store_get_file_fd, store_reload,
 *   store_get_tip, store_prune, block_hash, sha256d, tx_parse, fd_write_all.
 * cli_load_block uses raw AArch64 syscalls: lseek=62 (fd,off,whence), read=63.
 *
 * BLOCK BUFFER: the command frames each carry a CLI_BLK-byte on-stack block
 * buffer so the CLI can read REAL full mainnet blocks (live_blocks fetches
 * segwit blocks of ~1.6-1.8 MB; Core MAX_BLOCK_SERIALIZED_SIZE = 4,000,000).
 * The upstream x86 CLI sized these buffers at 384B/2KB/16KB, so it could only
 * inspect synthetic/small chains -- this AArch64 port enlarges them so the
 * block-reading commands work against the real chain in data/. Must stay >=
 * MAX_BLOCK_SERIALIZED_SIZE (4,000,000); 0x400000 = 4 MiB.
 * ==========================================================================*/
    .section .text

    .equ CLI_BLK, 0x400000    /* 4 MiB block buffer per command frame */

/* LB reg: load CLI_BLK (0x400000) into a register. 0x400000 = 0x40 << 16. */
.macro LB reg
    movz \reg, #0x40, lsl #16
.endm

    .extern store_get_at
    .extern store_get_file_fd
    .extern store_get_tip
    .extern store_reload
    .extern store_prune
    .extern block_hash
    .extern sha256d
    .extern tx_parse
    .extern fd_write_all

    .section .rodata
help_text:
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
help_len = . - help_text
err_usage:    .ascii "error: unknown command (try help)\n"
err_usage_len = . - err_usage
err_arg:      .ascii "error: bad argument\n"
err_arg_len = . - err_arg
err_range:    .ascii "error: height out of range\n"
err_range_len = . - err_range
err_notfound: .ascii "error: not found\n"
err_notfound_len = . - err_notfound
hexdig:       .ascii "0123456789abcdef"

    .section .text

/* cli_hex(out=x0, src=x1, n=x2) -> x0 = advanced out (out + n*2) */
    .global cli_hex
    .type cli_hex,%function
cli_hex:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    sub  sp, sp, #16
    mov  x19, x0            /* out */
    mov  x20, x1            /* src */
    mov  x21, x2            /* n */
    adrp x22, hexdig
    add  x22, x22, :lo12:hexdig
    mov  x23, #0            /* i */
.ch_loop:
    cmp  x23, x21
    b.hs .ch_done
    ldrb w9, [x20, x23]
    lsr  w10, w9, #4
    and  w10, w10, #0xf
    ldrb w10, [x22, x10]
    add  x12, x23, x23
    strb w10, [x19, x12]
    and  w10, w9, #0xf
    ldrb w10, [x22, x10]
    add  x12, x23, x23
    add  x12, x12, #1
    strb w10, [x19, x12]
    add  x23, x23, #1
    b    .ch_loop
.ch_done:
    add  x0, x23, x23
    add  x0, x19, x0
    add  sp, sp, #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

/* cli_rev32(out=x0, src=x1) -- reverse 32 bytes (leaf, scratch regs only) */
cli_rev32:
    mov  x10, x0
    mov  x11, x1
    mov  x9,  #0
.rev_loop:
    cmp  x9,  #32
    b.hs .rev_done
    mov  x12, #31
    sub  x12, x12, x9
    ldrb w13, [x11, x12]
    strb w13, [x10, x9]
    add  x9,  x9, #1
    b    .rev_loop
.rev_done:
    ret

/* cli_atoi(str=x0) -> x0 = value (0 if not a valid integer); leaf */
    .global cli_atoi
    .type cli_atoi,%function
cli_atoi:
    mov  x9,  x0            /* ptr */
    mov  x10, #0            /* value */
    mov  x11, #0            /* sign flag */
    ldrb w12, [x9]
    cmp  w12, #'-'
    b.ne .at_digits
    mov  x11, #1
    add  x9,  x9, #1
.at_digits:
    ldrb w12, [x9]
    cbz  w12, .at_fin
    cmp  w12, #'0'
    b.lo .at_fin
    cmp  w12, #'9'
    b.hi .at_fin
    mov  x13, #10
    mul  x10, x10, x13
    sub  w12, w12, #'0'
    add  x10, x10, x12
    add  x9,  x9, #1
    b    .at_digits
.at_fin:
    mov  x0, x10
    cbz  x11, .at_pos
    neg  x0, x0
.at_pos:
    ret

/* cli_hexval(char=x0) -> w0 = 0..15 or 0xFF if invalid; leaf */
cli_hexval:
    mov  w9, w0
    cmp  w9, #'0'
    b.lo .hx_bad
    cmp  w9, #'9'
    b.hi .hx_a
    sub  w9, w9, #'0'
    mov  w0, w9
    ret
.hx_a:
    cmp  w9, #'a'
    b.lo .hx_bad
    cmp  w9, #'f'
    b.hi .hx_A
    sub  w9, w9, #'a'
    add  w9, w9, #10
    mov  w0, w9
    ret
.hx_A:
    cmp  w9, #'A'
    b.lo .hx_bad
    cmp  w9, #'F'
    b.hi .hx_bad
    sub  w9, w9, #'A'
    add  w9, w9, #10
    mov  w0, w9
    ret
.hx_bad:
    mov  w0, #0xff
    ret

/* cli_hex_to_bin(out=x0, hexstr=x1) -> x0 = 1 ok / 0 bad */
    .global cli_hex_to_bin
    .type cli_hex_to_bin,%function
cli_hex_to_bin:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    mov  x19, x0            /* out */
    mov  x20, x1            /* hexstr */
    mov  x21, #0            /* i */
.hb_loop:
    cmp  x21, #32
    b.hs .hb_check
    add  x9,  x21, x21
    ldrb w0, [x20, x9]
    bl   cli_hexval
    cmp  w0, #0xff
    b.eq .hb_bad
    lsl  w22, w0, #4
    add  x9, x21, x21
    add  x9, x9, #1
    ldrb w0, [x20, x9]
    bl   cli_hexval
    cmp  w0, #0xff
    b.eq .hb_bad
    orr  w0, w0, w22
    strb w0, [x19, x21]
    add  x21, x21, #1
    b    .hb_loop
.hb_check:
    ldrb w9, [x20, #64]
    cbnz w9, .hb_bad
    mov  w0, #1
    b    .hb_done
.hb_bad:
    mov  w0, #0
.hb_done:
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

/* cli_out(out=x0, src=x1, n=x2) -> x0 = advanced out (leaf, scratch regs) */
cli_out:
    mov  x10, x0
    mov  x11, x1
    mov  x12, x2
    mov  x13, #0
.co_loop:
    cmp  x13, x12
    b.hs .co_done
    ldrb w14, [x11, x13]
    strb w14, [x10, x13]
    add  x13, x13, #1
    b    .co_loop
.co_done:
    add  x0, x10, x13
    ret

/* cli_emit_dec(buf=x0, value=x1) -> x0 = advanced buf (leaf) */
cli_emit_dec:
    sub  sp, sp, #32
    mov  x8,  x0            /* buf */
    mov  x9,  x1            /* value */
    add  x10, sp, #16       /* boundary -> write digits downward */
    mov  x11, #10
    cbz  x9, .ed_zero
.ed_digits:
    udiv x12, x9, x11
    msub x13, x12, x11, x9  /* remainder = value - q*10 */
    mov  x9, x12
    add  x13, x13, #'0'
    sub  x10, x10, #1
    strb w13, [x10]
    cbnz x9, .ed_digits
    b    .ed_flip
.ed_zero:
    sub  x10, x10, #1
    mov  w13, #'0'
    strb w13, [x10]
.ed_flip:
    add  x11, sp, #16       /* boundary */
.ed_cp:
    ldrb w13, [x10]
    strb w13, [x8]
    add  x8,  x8, #1
    add  x10, x10, #1
    cmp  x10, x11
    b.lo .ed_cp
    mov  x0, x8
    add  sp, sp, #32
    ret

/* cmd_getblockcount(st=x0, out=x1, cap=x2) -> x0 = advanced out / -1 empty */
cmd_getblockcount:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    ldr  w9, [x0, #24]      /* tip_height */
    cmp  w9, #-1
    b.eq .gbc_empty
    add  w9, w9, #1
    mov  x19, x1            /* out */
    mov  x0, x19
    mov  w1, w9
    bl   cli_emit_dec
    mov  w9, #10
    strb w9, [x0]
    add  x0, x0, #1
    b    .gbc_done
.gbc_empty:
    mov  x0, #-1
.gbc_done:
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

/* cli_load_block(st=x0, height=x1, out=x2, cap=x3) -> x0 = len / -1
 * Raw syscalls: lseek=62(fd,off,whence), read=63(fd,buf,count). */
cli_load_block:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    stp  x25, x26, [sp, #-16]!
    sub  sp, sp, #0x30      /* meta[24]@+0, fd@+24 */
    mov  x19, x0            /* st */
    mov  x20, x1            /* height */
    mov  x21, x2            /* out */
    mov  x22, x3            /* cap */
    /* store_get_at(st, height, &meta) */
    mov  x0, x19
    mov  x1, x20
    add  x2, sp, #0
    bl   store_get_at
    cmp  w0, #1
    b.ne .lb_fail
    ldr  x23, [sp, #8]      /* meta[1] = data_size */
    cmp  x23, x22
    b.hi .lb_fail           /* cap too small */
    ldr  x24, [sp, #0]      /* meta[0] = data_pos */
    ldr  w25, [sp, #16]     /* meta[2] = file_no (low 32) */
    /* store_get_file_fd(st, file_no) */
    mov  x0, x19
    mov  w1, w25
    bl   store_get_file_fd
    cmp  x0, #0
    b.lt .lb_fail
    mov  x26, x0            /* fd */
    /* lseek(fd, pos+8, SEEK_SET) */
    mov  x8, #62
    mov  x0, x26
    add  x1, x24, #8
    mov  x2, #0
    svc  #0
    cmp  x0, #0
    b.lt .lb_fail
    /* read(fd, out, size) */
    mov  x8, #63
    mov  x0, x26
    mov  x1, x21
    mov  x2, x23
    svc  #0
    cmp  x0, x23
    b.ne .lb_fail
    mov  x0, x23
    b    .lb_done
.lb_fail:
    mov  x0, #-1
.lb_done:
    add  sp, sp, #0x30
    ldp  x25, x26, [sp], #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

/* cmd_getbestblockhash(st=x0, out=x1, cap=x2) -> x0 = advanced / -1
 * Frame: blockbuf[0x4000]@+0, hbuf[32]@+0x4000, rev[32]@+0x4020 */
cmd_getbestblockhash:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    LB x9
    add  x9, x9, #0x60
    sub  sp, sp, x9
    mov  x19, x0            /* st */
    mov  x20, x1            /* out */
    mov  x21, x2            /* cap */
    ldr  w9, [x19, #24]     /* tip */
    cmp  w9, #-1
    b.eq .gbbh_fail
    /* cli_load_block(st, tip, blockbuf, CLI_BLK) */
    mov  x0, x19
    mov  w1, w9
    add  x2, sp, #0
    LB x3
    bl   cli_load_block
    cmp  x0, #0
    b.le .gbbh_fail
    cmp  x0, #80
    b.lo .gbbh_fail
    /* hbuf = sp+CLI_BLK ; block_hash(hbuf, blockbuf) */
    LB x9
    add  x0, sp, x9
    add  x1, sp, #0
    bl   block_hash
    /* cli_rev32(rev=hbuf+0x20, hbuf) */
    LB x9
    add  x0, sp, x9
    add  x0, x0, #0x20
    sub  x1, x0, #0x20      /* hbuf = rev-0x20 */
    bl   cli_rev32
    /* cli_hex(out, rev=hbuf+0x20, 32) */
    mov  x0, x20
    LB x9
    add  x1, sp, x9
    add  x1, x1, #0x20
    mov  x2, #32
    bl   cli_hex
    mov  w9, #10
    strb w9, [x0]
    add  x0, x0, #1
    b    .gbbh_done
.gbbh_fail:
    mov  x0, #-1
.gbbh_done:
    LB x9
    add  x9, x9, #0x60
    add  sp, sp, x9
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret
.size cmd_getbestblockhash, .-cmd_getbestblockhash

/* hex_char_only(byte=x0) -> w0 = 1 if hex digit / 0; leaf */
hex_char_only:
    mov  w9, w0
    mov  w0, #0
    cmp  w9, #'0'
    b.lo .hco_no
    cmp  w9, #'9'
    b.ls .hco_yes
    orr  w9, w9, #0x20      /* lowercase */
    cmp  w9, #'a'
    b.lo .hco_no
    cmp  w9, #'f'
    b.hi .hco_no
.hco_yes:
    mov  w0, #1
.hco_no:
    ret

/* is_digit_str(str=x0) -> w0 = 1 if all digits / 0; leaf */
is_digit_str:
    mov  x9, x0
.ids_loop:
    ldrb w10, [x9]
    cbz  w10, .ids_yes
    cmp  w10, #'0'
    b.lo .ids_no
    cmp  w10, #'9'
    b.hi .ids_no
    add  x9, x9, #1
    b    .ids_loop
.ids_no:
    mov  w0, #0
    ret
.ids_yes:
    mov  w0, #1
    ret

/* str_eq(a=x0, b=x1) -> w0 = 1 if C-strings equal / 0 */
str_eq:
    mov  x9, x0
    mov  x10, x1
.se_loop:
    ldrb w11, [x9]
    ldrb w12, [x10]
    cmp  w11, w12
    b.ne .se_no
    cbz  w11, .se_yes
    add  x9,  x9, #1
    add  x10, x10, #1
    b    .se_loop
.se_no:
    mov  w0, #0
    ret
.se_yes:
    mov  w0, #1
    ret

/* cmd_getblockhash(st=x0, hstr=x1, out=x2, cap=x3) -> x0 = advanced / -1
 * Frame: blockbuf[0x800]@+0, hbuf[32]@+0x800, rev[32]@+0x820 */
cmd_getblockhash:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    LB x9
    add  x9, x9, #0x60
    sub  sp, sp, x9
    mov  x19, x0            /* st */
    mov  x20, x1            /* hstr */
    mov  x21, x2            /* out */
    mov  x22, x3            /* cap */
    mov  x0, x20
    bl   cli_atoi
    mov  x23, x0            /* height */
    ldr  w9, [x19, #24]
    cmp  w9, #-1
    b.eq .gbh2_fail
    cmp  w23, w9
    b.hi .gbh2_fail
    /* cli_load_block(st, height, blockbuf, CLI_BLK) */
    mov  x0, x19
    mov  x1, x23
    add  x2, sp, #0
    LB x3
    bl   cli_load_block
    cmp  x0, #0
    b.le .gbh2_fail
    cmp  x0, #80
    b.lo .gbh2_fail
    /* hbuf = sp+CLI_BLK ; block_hash(hbuf, blockbuf) */
    LB x9
    add  x0, sp, x9
    add  x1, sp, #0
    bl   block_hash
    /* cli_rev32(rev=hbuf+0x20, hbuf) */
    LB x9
    add  x0, sp, x9
    add  x0, x0, #0x20
    sub  x1, x0, #0x20
    bl   cli_rev32
    mov  x0, x21
    LB x9
    add  x1, sp, x9
    add  x1, x1, #0x20
    mov  x2, #32
    bl   cli_hex
    mov  w9, #10
    strb w9, [x0]
    add  x0, x0, #1
    b    .gbh2_done
.gbh2_fail:
    mov  x0, #-1
.gbh2_done:
    LB x9
    add  x9, x9, #0x60
    add  sp, sp, x9
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

/* cmd_getblock(st=x0, arg=x1, out=x2, cap=x3) -> x0 = advanced / -1
 * Frame: blockbuf[384]@+0, bin[32]@+0x1B0, rev[32]@+0x1D0, hbuf[32]@+0x1F0 */
cmd_getblock:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    LB x9
    add  x9, x9, #0x80
    sub  sp, sp, x9
    mov  x19, x0            /* st */
    mov  x20, x1            /* arg */
    mov  x21, x2            /* out */
    mov  x22, x3            /* cap */
    /* by-number or by-hash? */
    mov  x0, x20
    bl   is_digit_str
    cbz  w0, .gbk_byhash
    mov  x0, x20
    bl   cli_atoi
    mov  x23, x0            /* height */
    ldr  w9, [x19, #24]
    cmp  w9, #-1
    b.eq .gbk_fail
    cmp  w23, w9
    b.hi .gbk_fail
    mov  x0, x19
    mov  x1, x23
    add  x2, sp, #0
    LB x3
    bl   cli_load_block
    cmp  x0, #0
    b.le .gbk_fail
    mov  x23, x0            /* block length */
    mov  x0, x21
    add  x1, sp, #0
    mov  x2, x23
    bl   cli_hex
    mov  w9, #10
    strb w9, [x0]
    add  x0, x0, #1
    b    .gbk_done
.gbk_byhash:
    /* bin = sp+CLI_BLK ; parse 64 hex -> bin (display) */
    LB x9
    add  x0, sp, x9
    mov  x1, x20
    bl   cli_hex_to_bin
    cbz  w0, .gbk_fail
    /* cli_rev32(rev=bin+0x20, bin) */
    LB x9
    add  x0, sp, x9
    add  x0, x0, #0x20
    add  x1, sp, #0
    add  x1, x1, x9         /* bin = sp+CLI_BLK */
    bl   cli_rev32          /* rev = raw requested hash */
    ldr  w9, [x19, #24]
    cmp  w9, #-1
    b.eq .gbk_fail
    mov  w23, #0            /* scan height */
.gbk_scan:
    ldr  w9, [x19, #24]
    cmp  w23, w9
    b.hi .gbk_fail
    mov  x0, x19
    mov  w1, w23
    add  x2, sp, #0
    LB x3
    bl   cli_load_block
    cmp  x0, #0
    b.le .gbk_next
    cmp  x0, #80
    b.lo .gbk_next
    /* hbuf = sp+CLI_BLK+0x40 ; block_hash(hbuf, blockbuf) */
    LB x9
    add  x0, sp, x9
    add  x0, x0, #0x40
    add  x1, sp, #0
    bl   block_hash
    /* compare hbuf(base+0x40) vs rev(base+0x20), 32 bytes */
    LB x9
    add  x9, sp, x9
    add  x10, x9, #0x20     /* rev */
    add  x9, x9, #0x40      /* hbuf */
    mov  x11, #0
.gbk_cmp:
    cmp  x11, #32
    b.hs .gbk_match
    ldrb w12, [x9, x11]
    ldrb w13, [x10, x11]
    cmp  w12, w13
    b.ne .gbk_next2
    add  x11, x11, #1
    b    .gbk_cmp
.gbk_next2:
    b    .gbk_next
.gbk_match:
    /* re-load matched block for length */
    mov  x0, x19
    mov  w1, w23
    add  x2, sp, #0
    LB x3
    bl   cli_load_block
    cmp  x0, #0
    b.le .gbk_fail
    mov  x23, x0
    mov  x0, x21
    add  x1, sp, #0
    mov  x2, x23
    bl   cli_hex
    mov  w9, #10
    strb w9, [x0]
    add  x0, x0, #1
    b    .gbk_done
.gbk_next:
    add  w23, w23, #1
    b    .gbk_scan
.gbk_fail:
    mov  x0, #-1
.gbk_done:
    LB x9
    add  x9, x9, #0x80
    add  sp, sp, x9
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret
/* cli_read_varint(buf=x0, len=x1, value_out=x2) -> x0 = consumed / -1 (leaf) */
cli_read_varint:
    mov  x9,  x0            /* buf */
    mov  x10, x1            /* len */
    mov  x11, x2            /* value_out */
    cmp  x10, #1
    b.lo .rv_bad
    ldrb w12, [x9]
    cbz  x11, .rv_sk1
    str  x12, [x11]
.rv_sk1:
    cmp  w12, #0xfd
    b.lo .rv_one
    cmp  w12, #0xfd
    b.eq .rv_two
    cmp  w12, #0xfe
    b.eq .rv_four
    /* 0xff -> 8-byte */
    cmp  x10, #9
    b.lo .rv_bad
    ldr  x12, [x9, #1]
    cbz  x11, .rv_sk8
    str  x12, [x11]
.rv_sk8:
    mov  x0, #9
    ret
.rv_four:
    cmp  x10, #5
    b.lo .rv_bad
    ldr  w12, [x9, #1]
    cbz  x11, .rv_sk4
    str  x12, [x11]
.rv_sk4:
    mov  x0, #5
    ret
.rv_two:
    cmp  x10, #3
    b.lo .rv_bad
    ldrh w12, [x9, #1]
    cbz  x11, .rv_sk2
    str  x12, [x11]
.rv_sk2:
    mov  x0, #3
    ret
.rv_one:
    mov  x0, #1
    ret
.rv_bad:
    mov  x0, #-1
    ret

/* cmd_gettx(st=x0, txid_hex=x1, out=x2, cap=x3) -> x0 = advanced / -1
 * Frame locals: txbase@8 txlen@16 blen@24 ntx@28 vsize@32 txcount@36
 *   remain@40 txptr@48 txidx@56 parsed@64(32) rawreq@96(32) comp@128(32)
 *   info@160(64)->224  blockbuf@224(0x180)->0x2a0  FRAME=0x2b0 */
#define L_GTB 8
#define L_GTL 16
#define L_GBL 24
#define L_GNT 28
#define L_GVS 32
#define L_GTC 36
#define L_GRM 40
#define L_GTP 48
#define L_GTI 56
#define L_GPD 64
#define L_GRQ 96
#define L_GCP 128
#define L_GIF 160
#define L_GBB 224
#define F_TX  (0xe0 + CLI_BLK)
cmd_gettx:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    LB x9
    add  x9, x9, #0xe0        /* F_TX = 0xe0 + CLI_BLK */
    sub  sp, sp, x9
    mov  x19, x0            /* st */
    mov  x20, x1            /* txid hex */
    mov  x21, x2            /* out */
    mov  x22, x3            /* cap */
    /* parse txid -> parsed (display order), reverse -> raw req */
    add  x0, sp, #L_GPD
    mov  x1, x20
    bl   cli_hex_to_bin
    cbz  w0, .gtx_fail
    add  x0, sp, #L_GRQ
    add  x1, sp, #L_GPD
    bl   cli_rev32
    ldr  w9, [x19, #24]
    cmp  w9, #-1
    b.eq .gtx_fail
    mov  w23, #0            /* height */
.gtx_blk:
    ldr  w9, [x19, #24]
    cmp  w23, w9
    b.hi .gtx_fail
    mov  x0, x19
    mov  w1, w23
    add  x2, sp, #L_GBB
    LB x3
    bl   cli_load_block
    cmp  x0, #0
    b.le .gtx_next
    str  w0, [sp, #L_GBL]   /* blen */
    /* ntx = varint at block+80 */
    add  x0, sp, #L_GBB
    add  x0, x0, #80
    sub  w1, w0, #0
    add  x1, sp, #L_GBB
    /* remaining = blen - 80 */
    ldr  w9, [sp, #L_GBL]
    sub  w1, w9, #80
    add  x2, sp, #L_GNT
    bl   cli_read_varint    /* returns vsize (=bytes used) */
    cmp  x0, #-1
    b.eq .gtx_next
    str  w0, [sp, #L_GVS]   /* vsize */
    ldr  w9, [sp, #L_GNT]
    cbz  w9, .gtx_next
    str  w9, [sp, #L_GTC]   /* txcount */
    add  x0, sp, #L_GBB
    add  x0, x0, #80
    ldr  w10, [sp, #L_GVS]
    add  x0, x0, x10        /* txptr */
    str  x0, [sp, #L_GTP]
    ldr  w9, [sp, #L_GBL]
    sub  w9, w9, #80
    sub  w9, w9, w10        /* remaining */
    str  w9, [sp, #L_GRM]
    str  wzr, [sp, #L_GTI]  /* txidx = 0 */
.gtx_tx:
    ldr  w9, [sp, #L_GTI]
    ldr  w10, [sp, #L_GTC]
    cmp  w9, w10
    b.hs .gtx_next
    add  x0, sp, #L_GIF
    ldr  x1, [sp, #L_GTP]
    ldr  w2, [sp, #L_GRM]
    bl   tx_parse
    cmp  w0, #1
    b.ne .gtx_next
    ldr  x9, [sp, #L_GIF]   /* tx_len at info+0 */
    cmp  x9, #0
    b.le .gtx_next
    /* sha256d(comp, txptr, txlen) */
    add  x0, sp, #L_GCP
    ldr  x1, [sp, #L_GTP]
    mov  x2, x9
    bl   sha256d
    /* compare rawreq vs comp (32) */
    add  x9, sp, #L_GRQ
    add  x10, sp, #L_GCP
    mov  x11, #0
.gtx_cmp:
    cmp  x11, #32
    b.hs .gtx_found
    ldrb w12, [x9, x11]
    ldrb w13, [x10, x11]
    cmp  w12, w13
    b.ne .gtx_next2
    add  x11, x11, #1
    b    .gtx_cmp
.gtx_next2:
    b    .gtx_adv
.gtx_found:
    /* save tx ptr/len for output */
    ldr  x9, [sp, #L_GTP]
    str  x9, [sp, #L_GTB]
    ldr  x9, [sp, #L_GIF]
    str  x9, [sp, #L_GTL]
    /* cli_out(out, "found in block ", len) */
    mov  x0, x21
    adrp x1, fnd1
    add  x1, x1, :lo12:fnd1
    mov  x2, #fnd1_len
    bl   cli_out
    mov  x0, x0
    mov  w1, w23
    bl   cli_emit_dec
    mov  w9, #10
    strb w9, [x0]
    add  x0, x0, #1
    /* tx hex */
    mov  x0, x0
    ldr  x1, [sp, #L_GTB]
    ldr  x2, [sp, #L_GTL]
    bl   cli_hex
    mov  w9, #10
    strb w9, [x0]
    add  x0, x0, #1
    b    .gtx_done
.gtx_adv:
    ldr  x9, [sp, #L_GTP]
    ldr  x10, [sp, #L_GIF]
    add  x9, x9, x10
    str  x9, [sp, #L_GTP]
    ldr  w9, [sp, #L_GRM]
    ldr  w10, [sp, #L_GIF]
    sub  w9, w9, w10
    str  w9, [sp, #L_GRM]
    ldr  w9, [sp, #L_GTI]
    add  w9, w9, #1
    str  w9, [sp, #L_GTI]
    b    .gtx_tx
.gtx_next:
    add  w23, w23, #1
    b    .gtx_blk
.gtx_fail:
    mov  x0, #-1
.gtx_done:
    LB x9
    add  x9, x9, #0xe0        /* F_TX */
    add  sp, sp, x9
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret
fnd1:     .ascii "found in block "
fnd1_len = . - fnd1
    .p2align 4

/* cmd_getbalance(st=x0, out=x1, cap=x2) -> x0 = advanced / -1
 * Frame: blen@8 ntx@12 vsize@16 txbase@24 remain@32 nout@36 out0off@40
 *   sum@48 scriptlen@56 info@64(64)->128 blockbuf@128(0x180)->0x2a0 F=0x2b0 */
#define L_BBL 8
#define L_BNT 12
#define L_BVS 16
#define L_BTB 24
#define L_BRM 32
#define L_BNO 36
#define L_BOO 40
#define L_BSU 48
#define L_BSL 56
#define L_BIF 64
#define L_BBB 208
#define F_GB  (0xd0 + CLI_BLK)
cmd_getbalance:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    LB x9
    add  x9, x9, #0xd0        /* F_GB = 0xd0 + CLI_BLK */
    sub  sp, sp, x9
    mov  x19, x0            /* st */
    mov  x20, x1            /* out */
    mov  x21, x2            /* cap */
    ldr  w9, [x19, #24]
    cmp  w9, #-1
    b.eq .gb_fail
    str  xzr, [sp, #L_BSU]  /* sum = 0 */
    mov  w22, #0            /* height */
.gb_blk:
    ldr  w9, [x19, #24]
    cmp  w22, w9
    b.hi .gb_emit
    mov  x0, x19
    mov  w1, w22
    add  x2, sp, #L_BBB
    LB x3
    bl   cli_load_block
    cmp  x0, #0
    b.le .gb_next
    str  w0, [sp, #L_BBL]   /* blen */
    add  x0, sp, #L_BBB
    add  x0, x0, #80
    ldr  w9, [sp, #L_BBL]
    sub  w1, w9, #80
    add  x2, sp, #L_BNT
    bl   cli_read_varint
    cmp  x0, #-1
    b.eq .gb_next
    str  w0, [sp, #L_BVS]   /* vsize */
    ldr  w9, [sp, #L_BNT]
    cbz  w9, .gb_next
    add  x0, sp, #L_BBB
    add  x0, x0, #80
    ldr  w10, [sp, #L_BVS]
    add  x0, x0, x10        /* txbase */
    str  x0, [sp, #L_BTB]
    ldr  w9, [sp, #L_BBL]
    sub  w9, w9, #80
    sub  w9, w9, w10
    str  w9, [sp, #L_BRM]   /* remain */
    /* tx_parse(info, txbase, remain) -- coinbase */
    add  x0, sp, #L_BIF
    ldr  x1, [sp, #L_BTB]
    ldr  w2, [sp, #L_BRM]
    bl   tx_parse
    cmp  w0, #1
    b.ne .gb_next
    ldr  w9, [sp, #L_BIF+16]   /* n_out */
    str  w9, [sp, #L_BNO]
    ldr  x9, [sp, #L_BIF+40]   /* out0_value offset */
    str  x9, [sp, #L_BOO]
    ldr  x9, [sp, #L_BTB]
    ldr  x10, [sp, #L_BOO]
    add  x9, x9, x10          /* p = txbase + out0_off */
    mov  x10, #0              /* out index */
.gb_out:
    ldr  w11, [sp, #L_BNO]
    cmp  x10, x11
    b.hs .gb_next
    ldr  x12, [x9]            /* value */
    ldr  x13, [sp, #L_BSU]
    add  x13, x13, x12
    str  x13, [sp, #L_BSU]
    /* remaining = blen - (p+8 - blockbase) */
    add  x12, x9, #8
    add  x13, sp, #L_BBB
    sub  x12, x12, x13
    ldr  w13, [sp, #L_BBL]
    sub  x12, x13, x12
    mov  x0, x9
    add  x0, x0, #8
    mov  x1, x12
    add  x2, sp, #L_BSL
    bl   cli_read_varint
    cmp  x0, #-1
    b.eq .gb_next
    add  x9, x9, #8
    add  x9, x9, x0           /* + scriptlen varint size */
    ldr  x12, [sp, #L_BSL]
    add  x9, x9, x12          /* + scriptlen bytes */
    add  x10, x10, #1
    b    .gb_out
.gb_next:
    add  w22, w22, #1
    b    .gb_blk
.gb_emit:
    mov  x0, x20
    ldr  x1, [sp, #L_BSU]
    bl   cli_emit_dec
    mov  w9, #10
    strb w9, [x0]
    add  x0, x0, #1
    b    .gb_done
.gb_fail:
    mov  x0, #-1
.gb_done:
    LB x9
    add  x9, x9, #0xd0        /* F_GB */
    add  sp, sp, x9
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

/* cli_main(store=x0, argc=x1, argv=x2, out=x3, cap=x4) -> x0 = len / -1 */
    .global cli_main
    .type cli_main,%function
cli_main:
    stp  x29, x30, [sp, #-16]!
    mov  x29, sp
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x23, x24, [sp, #-16]!
    sub  sp, sp, #16
    mov  x19, x0            /* store */
    mov  x20, x1            /* argc */
    mov  x21, x2            /* argv */
    mov  x22, x3            /* out */
    mov  x23, x4            /* cap */
    cmp  x20, #0
    b.le .cm_unknown
    ldr  x24, [x21]         /* argv[0] */
    mov  x0, x24
    adrp x1, c_help
    add  x1, x1, :lo12:c_help
    bl   str_eq
    cbnz w0, .cm_help
    mov  x0, x24
    adrp x1, c_count
    add  x1, x1, :lo12:c_count
    bl   str_eq
    cbnz w0, .cm_count
    mov  x0, x24
    adrp x1, c_best
    add  x1, x1, :lo12:c_best
    bl   str_eq
    cbnz w0, .cm_best
    mov  x0, x24
    adrp x1, c_bhash
    add  x1, x1, :lo12:c_bhash
    bl   str_eq
    cbnz w0, .cm_bhash
    mov  x0, x24
    adrp x1, c_block
    add  x1, x1, :lo12:c_block
    bl   str_eq
    cbnz w0, .cm_block
    mov  x0, x24
    adrp x1, c_tx
    add  x1, x1, :lo12:c_tx
    bl   str_eq
    cbnz w0, .cm_tx
    mov  x0, x24
    adrp x1, c_balance
    add  x1, x1, :lo12:c_balance
    bl   str_eq
    cbnz w0, .cm_balance
    mov  x0, x24
    adrp x1, c_stop
    add  x1, x1, :lo12:c_stop
    bl   str_eq
    cbnz w0, .cm_count      /* stop -> report count */
    mov  x0, x24
    adrp x1, c_prune
    add  x1, x1, :lo12:c_prune
    bl   str_eq
    cbnz w0, .cm_prune
    b    .cm_unknown
.cm_help:
    mov  x0, x22
    adrp x1, help_text
    add  x1, x1, :lo12:help_text
    mov  x2, #help_len
    bl   cli_out
    b    .finish_out
.cm_count:
    mov  x0, x19
    mov  x1, x22
    mov  x2, x23
    bl   cmd_getblockcount
    cmp  x0, #-1
    b.eq .cm_erange
    b    .finish_out
.cm_best:
    mov  x0, x19
    mov  x1, x22
    mov  x2, x23
    bl   cmd_getbestblockhash
    cmp  x0, #-1
    b.eq .cm_erange
    b    .finish_out
.cm_bhash:
    cmp  x20, #2
    b.lo .cm_earg
    mov  x0, x19
    ldr  x1, [x21, #8]      /* argv[1] */
    mov  x2, x22
    mov  x3, x23
    bl   cmd_getblockhash
    cmp  x0, #-1
    b.eq .cm_erange
    b    .finish_out
.cm_block:
    cmp  x20, #2
    b.lo .cm_earg
    mov  x0, x19
    ldr  x1, [x21, #8]
    mov  x2, x22
    mov  x3, x23
    bl   cmd_getblock
    cmp  x0, #-1
    b.eq .cm_enotfound
    b    .finish_out
.cm_tx:
    cmp  x20, #2
    b.lo .cm_earg
    mov  x0, x19
    ldr  x1, [x21, #8]
    mov  x2, x22
    mov  x3, x23
    bl   cmd_gettx
    cmp  x0, #-1
    b.eq .cm_enotfound
    b    .finish_out
.cm_balance:
    mov  x0, x19
    mov  x1, x22
    mov  x2, x23
    bl   cmd_getbalance
    cmp  x0, #-1
    b.eq .cm_erange
    b    .finish_out
.cm_prune:
    cmp  x20, #2
    b.lo .cm_earg
    ldr  x0, [x21, #8]
    bl   cli_atoi
    mov  x24, x0            /* height */
    mov  x0, x19
    mov  x1, x24
    bl   store_prune
    cmp  x0, #0
    b.lt .cm_erange
    mov  x0, x22
    adrp x1, prune_msg
    add  x1, x1, :lo12:prune_msg
    mov  x2, #prune_msg_len
    bl   cli_out
    mov  x24, x0            /* advanced out */
    mov  x0, x24
    ldr  w9, [x19, #48]     /* clamped prune height at st+48 */
    mov  w1, w9
    bl   cli_emit_dec
    mov  w9, #10
    strb w9, [x0]
    add  x0, x0, #1
    b    .finish_out
.finish_out:
    mov  x9, x22
    sub  x0, x0, x9
    b    .cm_done
.cm_unknown:
    mov  x0, x22
    adrp x1, err_usage
    add  x1, x1, :lo12:err_usage
    mov  x2, #err_usage_len
    bl   cli_out
    mov  x0, x22
    add  x0, x0, #err_usage_len
    mov  x9, x22
    sub  x0, x0, x9
    b    .cm_done
.cm_earg:
    mov  x0, x22
    adrp x1, err_arg
    add  x1, x1, :lo12:err_arg
    mov  x2, #err_arg_len
    bl   cli_out
    mov  x0, x22
    add  x0, x0, #err_arg_len
    mov  x9, x22
    sub  x0, x0, x9
    b    .cm_done
.cm_erange:
    mov  x0, x22
    adrp x1, err_range
    add  x1, x1, :lo12:err_range
    mov  x2, #err_range_len
    bl   cli_out
    mov  x0, x22
    add  x0, x0, #err_range_len
    mov  x9, x22
    sub  x0, x0, x9
    b    .cm_done
.cm_enotfound:
    mov  x0, x22
    adrp x1, err_notfound
    add  x1, x1, :lo12:err_notfound
    mov  x2, #err_notfound_len
    bl   cli_out
    mov  x0, x22
    add  x0, x0, #err_notfound_len
    mov  x9, x22
    sub  x0, x0, x9
.cm_done:
    add  sp, sp, #16
    ldp  x23, x24, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ldp  x29, x30, [sp], #16
    ret

    .section .rodata
c_help:    .ascii "help\0"
c_count:   .ascii "getblockcount\0"
c_best:    .ascii "getbestblockhash\0"
c_bhash:   .ascii "getblockhash\0"
c_block:   .ascii "getblock\0"
c_tx:      .ascii "gettx\0"
c_balance: .ascii "getbalance\0"
c_stop:    .ascii "stop\0"
c_prune:   .ascii "prune\0"
prune_msg: .ascii "pruned to height "
prune_msg_len = . - prune_msg

    .section .note.GNU-stack,"",@progbits
