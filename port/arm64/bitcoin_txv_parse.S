/* ============================================================================
 * bitcoin_txv_parse.S -- AArch64 (ARMv8-A) port of asm/bitcoin_txv_parse.asm
 *
 * The daemon tx_verify transaction-parse layer, explicit-state ABI (no file
 * statics; caller passes input array + witness pool). Two entry points:
 *
 *   long txv_parse_asm(const u8* tx, u64 txlen, txv_rawin_t* in,
 *                      witpool_t* wp, u64* out_nin, const char** reason)
 *     -> 1 parsed / 0 rejected (*reason = .rodata string, byte-identical to
 *        the C twin's, which the differential strcmp()s)
 *   long txvb_parse_tx_asm(tx, txlen, tx_index, flat, base, cap,
 *                          out_nin, reason, wp [stack args]) -> 1 / 0
 *     AAPCS64: 9 args -> first 8 in x0..x7, 9th (wp) at [sp+0] on entry.
 *
 * Struct ABI (offsetof-pinned):
 *   txv_rawin_t (stride 10080): outpoint@0 scriptSig@8 sscriptSiglen@16 wit@24
 *     witlen@32 nwit@40 wit_off@44 (wprog/wproglen/wrapped/value/spk/shape
 *     are CLASSIFY's job; parse touches only the above).
 *   witpool_t: ptr@0 len@8 cap@16 used@24.
 *   txvb_in_t (stride 144): tx_index@0 local_idx@8 tx_ptr@16 tx_len@24
 *     outpoint@32 scriptSig@40 scriptSiglen@48 nwit@72 wit_off@76 tap_desc@128.
 *
 * Notes kept faithful to the x86 twin: the split `avail < sl || avail-sl < 4`
 * scriptSig bound (incident #36); wp->ptr/len re-read after every reserve
 * (it may realloc) and wit/witlen only resolved in the final pass; the block
 * path poisons tap_desc=-1 and does NOT reset wp->used or resolve wit/witlen.
 * The pool reserve is the ported txv_witpool_reserve_asm (same semantics as
 * the C it replaced).
 *
 * RDCS <fail>: inline compact-size (varint) read. p=x26, end=x27; reads at p,
 * advances p, leaves the value in x9; truncation jumps straight to <fail>.
 * Clobbers x9,x10 (and branches to fail). Mirrors the x86 RDCS macro exactly.
 * ========================================================================== */

	.text
	.global txv_parse_asm
	.type txv_parse_asm, %function
	.global txvb_parse_tx_asm
	.type txvb_parse_tx_asm, %function

	.extern txv_witpool_reserve_asm

/* --- load a symbol's address (adrp + :lo12:, range-safe) --- */
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

/* --- inline compact-size read; value in x9 --- */
	.macro RDCS fail
	cmp  x26, x27
	b.hs \fail
	ldrb w9, [x26]
	cmp  w9, #0xfd
	b.lo .Lr1\@
	b.eq .Lr2\@
	cmp  w9, #0xfe
	b.eq .Lr4\@
	/* 0xff -> 8-byte (value = p[1..8]; #1 skips the 0xff discriminator) */
	add  x10, x26, #9
	cmp  x10, x27
	b.hi \fail
	ldr  x9, [x26, #1]
	add  x26, x26, #9
	b    .Lrdone\@
.Lr4\@:
	add  x10, x26, #5
	cmp  x10, x27
	b.hi \fail
	ldr  w9, [x26, #1]
	add  x26, x26, #5
	b    .Lrdone\@
.Lr2\@:
	add  x10, x26, #3
	cmp  x10, x27
	b.hi \fail
	ldrh w9, [x26, #1]
	add  x26, x26, #3
	b    .Lrdone\@
.Lr1\@:
	ldrb w9, [x26]
	add  x26, x26, #1
.Lrdone\@:
	.endm

	.section .rodata
r_short:   .asciz "tx too short"
r_nin:     .asciz "bad n_in varint"
r_bounds:  .asciz "input count out of bounds"
r_outpt:   .asciz "truncated outpoint"
r_ssv:     .asciz "bad scriptSig varint"
r_sstrunc: .asciz "truncated scriptSig/sequence"
r_nout:    .asciz "bad n_out varint"
r_outtr:   .asciz "truncated output"
r_osv:     .asciz "bad output script varint"
r_ostrunc: .asciz "truncated output script"
r_wcv:     .asciz "bad witness item-count varint"
r_witmany: .asciz "too many witness items"
r_oom:     .asciz "out of memory"
r_wlv:     .asciz "bad witness-item-len varint"
r_wtrunc:  .asciz "truncated witness item"
r_sizing:  .asciz "block input count exceeds sizing pass"
	.text

/* ============================================================================
 * txv_parse_asm(tx, txlen, in, wp, out_nin, reason)
 *   Regs: x19=tx x20=txlen x21=out_nin x22=reason x23=in-base x24=wp
 *         x25=record-cursor x26=p x27=end
 *   Locals @sp+0 segwit, +8 nin, +0x10 i, +0x18 nitems, +0x20 woff, +0x28 j.
 * ========================================================================== */
txv_parse_asm:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #0x40
	mov  x19, x0                 /* tx */
	mov  x20, x1                 /* txlen */
	mov  x23, x2                 /* in base */
	mov  x24, x3                 /* wp */
	mov  x21, x4                 /* out_nin */
	mov  x22, x5                 /* reason */
	add  x27, x0, x1             /* end */
	mov  x26, x0                 /* p */
	cmp  x20, #10                /* txlen < 10 */
	b.lo .Tr_short
	str  xzr, [x24, #24]         /* wp->used = 0 */
	add  x26, x26, #4            /* skip version */
	/* segwit = (p+2 <= end && p[0]==0 && p[1]==1) */
	mov  x9, #0
	add  x10, x26, #2
	cmp  x10, x27
	b.hi .Tr_segdone
	ldrb w11, [x26]
	cbnz w11, .Tr_segdone
	ldrb w11, [x26, #1]
	cmp  w11, #1
	b.ne .Tr_segdone
	mov  x9, #1
	add  x26, x26, #2
.Tr_segdone:
	str  x9, [sp, #0x00]         /* segwit */
	RDCS .Tr_nin                 /* nin in x9 */
	cbz  x9, .Tr_bounds
	mov  x10, #20000
	cmp  x9, x10                     /* TXV_MAX_INPUTS */
	b.hi .Tr_bounds
	str  x9, [sp, #0x08]         /* nin */
	mov  x25, x23                /* record cursor = in[0] */
	str  xzr, [sp, #0x10]        /* i = 0 */
.Tr_inloop:
	ldr  x9, [sp, #0x10]
	ldr  x10, [sp, #0x08]
	cmp  x9, x10
	b.hs .Tr_indone
	add  x10, x26, #36
	cmp  x10, x27
	b.hi .Tr_outpt
	str  x26, [x25, #0]          /* outpoint = p */
	add  x26, x26, #36
	RDCS .Tr_ssv                 /* sl in x9 */
	mov  x28, x9                 /* sl */
	sub  x9, x27, x26            /* avail = end - p */
	cmp  x9, x28
	b.lo .Tr_sstrunc
	sub  x9, x9, x28
	cmp  x9, #4
	b.lo .Tr_sstrunc
	str  x26, [x25, #8]          /* scriptSig = p */
	str  w28, [x25, #16]         /* scriptSiglen = (u32)sl */
	add  x26, x26, x28
	add  x26, x26, #4            /* p += sl + 4 */
	str  wzr, [x25, #40]         /* nwit = 0 */
	mov  x10, #10080
	add  x25, x25, x10                 /* stride */
	ldr  x9, [sp, #0x10]
	add  x9, x9, #1
	str  x9, [sp, #0x10]
	b    .Tr_inloop
.Tr_indone:
	RDCS .Tr_nout                /* nout in x9 */
	mov  x28, x9
.Tr_outloop:
	cbz  x28, .Tr_outdone
	add  x9, x26, #8
	cmp  x9, x27
	b.hi .Tr_outtr
	add  x26, x26, #8
	RDCS .Tr_osv                 /* sl in x9 */
	sub  x10, x27, x26
	cmp  x10, x9
	b.lo .Tr_ostrunc
	add  x26, x26, x9
	sub  x28, x28, #1
	b    .Tr_outloop
.Tr_outdone:
	ldr  x9, [sp, #0x00]         /* segwit */
	cbz  x9, .Tr_resolve
	mov  x25, x23
	str  xzr, [sp, #0x10]        /* i = 0 */
.Tr_witloop:
	ldr  x9, [sp, #0x10]
	ldr  x10, [sp, #0x08]
	cmp  x9, x10
	b.hs .Tr_resolve
	RDCS .Tr_wcv                 /* nitems in x9 */
	mov  x10, #0x0900
	movk x10, #0x003D, lsl#16
	cmp  x9, x10                  /* TXV_MAX_WIT_ITEMS */
	b.hi .Tr_witmany
	str  x9, [sp, #0x18]         /* nitems */
	str  w9, [x25, #40]          /* nwit = (u32)nitems */
	mov  x0, x24                 /* wp */
	mov  x1, x9
	bl   txv_witpool_reserve_asm
	cmp  x0, #-1
	b.eq .Tr_oom
	str  x0, [sp, #0x20]         /* woff */
	str  w0, [x25, #44]          /* wit_off = (u32)woff */
	str  xzr, [sp, #0x28]        /* j = 0 */
.Tr_itemloop:
	ldr  x9, [sp, #0x28]
	ldr  x10, [sp, #0x18]
	cmp  x9, x10
	b.hs .Tr_itemsdone
	RDCS .Tr_wlv                 /* il in x9 */
	sub  x10, x27, x26
	cmp  x10, x9
	b.lo .Tr_wtrunc
	ldr  x10, [sp, #0x20]        /* woff */
	ldr  x11, [sp, #0x28]        /* j */
	add  x10, x10, x11           /* woff+j */
	ldr  x11, [x24, #0]          /* wp->ptr (re-read: reserve may have moved) */
	str  x26, [x11, x10, lsl #3] /* ptr[woff+j] = p */
	ldr  x11, [x24, #8]          /* wp->len */
	str  w9, [x11, x10, lsl #2]  /* len[woff+j] = (u32)il */
	add  x26, x26, x9            /* p += il */
	ldr  x9, [sp, #0x28]
	add  x9, x9, #1
	str  x9, [sp, #0x28]
	b    .Tr_itemloop
.Tr_itemsdone:
	mov  x10, #10080
	add  x25, x25, x10
	ldr  x9, [sp, #0x10]
	add  x9, x9, #1
	str  x9, [sp, #0x10]
	b    .Tr_witloop
.Tr_resolve:
	mov  x25, x23
	ldr  x11, [sp, #0x08]        /* nin countdown */
.Tr_resloop:
	cbz  x11, .Tr_ok
	ldr  w9, [x25, #40]          /* nwit */
	cbz  w9, .Tr_reszero
	ldr  w9, [x25, #44]          /* wit_off */
	ldr  x10, [x24, #0]          /* wp->ptr */
	add  x10, x10, x9, lsl #3
	str  x10, [x25, #24]         /* wit = ptr[woff] */
	ldr  x10, [x24, #8]          /* wp->len */
	add  x10, x10, x9, lsl #2
	str  x10, [x25, #32]         /* witlen = len[woff] */
	b    .Tr_resnext
.Tr_reszero:
	str  xzr, [x25, #24]         /* wit = 0 */
	str  xzr, [x25, #32]         /* witlen = 0 */
.Tr_resnext:
	mov  x10, #10080
	add  x25, x25, x10
	sub  x11, x11, #1
	b    .Tr_resloop
.Tr_ok:
	ldr  x9, [sp, #0x08]
	str  x9, [x21]               /* *out_nin = nin */
	mov  x0, #1
	b    .Tr_out
/* rejection tail: x9=reason string, returns 0 */
.Tr_short:   LAddr x9, r_short;   b .Tr_reject
.Tr_nin:     LAddr x9, r_nin;     b .Tr_reject
.Tr_bounds:  LAddr x9, r_bounds;  b .Tr_reject
.Tr_outpt:   LAddr x9, r_outpt;   b .Tr_reject
.Tr_ssv:     LAddr x9, r_ssv;     b .Tr_reject
.Tr_sstrunc: LAddr x9, r_sstrunc; b .Tr_reject
.Tr_nout:    LAddr x9, r_nout;    b .Tr_reject
.Tr_outtr:   LAddr x9, r_outtr;   b .Tr_reject
.Tr_osv:     LAddr x9, r_osv;     b .Tr_reject
.Tr_ostrunc: LAddr x9, r_ostrunc; b .Tr_reject
.Tr_wcv:     LAddr x9, r_wcv;     b .Tr_reject
.Tr_witmany: LAddr x9, r_witmany; b .Tr_reject
.Tr_oom:     LAddr x9, r_oom;     b .Tr_reject
.Tr_wlv:     LAddr x9, r_wlv;     b .Tr_reject
.Tr_wtrunc:  LAddr x9, r_wtrunc;  b .Tr_reject
.Tr_sizing:  LAddr x9, r_sizing;  b .Tr_reject
.Tr_reject:
	str  x9, [x22]               /* *reason = string */
	mov  x0, #0
.Tr_out:
	add  sp, sp, #0x40
	ldp  x29, x30, [sp], #16
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size txv_parse_asm, .-txv_parse_asm

/* ============================================================================
 * txvb_parse_tx_asm(tx, txlen, tx_index, flat, base, cap, out_nin, reason, wp)
 *   AAPCS64 9 args: x0..x7 then wp at [sp+0]. Does NOT reset wp->used, does
 *   NOT resolve wit/witlen; fills 144-byte txvb_in_t entries at
 *   flat + base*144; poisons tap_desc. nin bound = (base+nin > cap) -> r_sizing.
 *   Regs: x19=tx x20=txlen x21=tx_index x22=flat x23=base x24=wp x25=entry-cur
 *         x26=p x27=end x28=cap
 *   Locals: segwit@0 nitems@0x18 woff@0x20 n_wait use: nin@8 i@0x10 j@0x28
 *           out_nin@0x30 reason@0x38
 * ========================================================================== */
txvb_parse_tx_asm:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #0x40
	/* wp is the 9th arg at entry_sp+0 = sp + 0xA0 now */
	ldr  x24, [sp, #0xA0]        /* wp */
	mov  x19, x0                 /* tx */
	mov  x20, x1                 /* txlen */
	mov  x21, x2                 /* tx_index */
	mov  x22, x3                 /* flat */
	mov  x23, x4                 /* base */
	mov  x28, x5                 /* cap */
	str  x6, [sp, #0x30]         /* out_nin */
	str  x7, [sp, #0x38]         /* reason */
	/* entry0 = flat + base*144 */
	mov  x9, #144
	mul  x10, x23, x9
	add  x10, x22, x10
	mov  x25, x10                /* entry cursor */
	add  x27, x0, x1             /* end */
	mov  x26, x0                 /* p */
	cmp  x20, #10
	b.lo .Tb_short
	add  x26, x26, #4            /* version */
	mov  x9, #0
	add  x10, x26, #2
	cmp  x10, x27
	b.hi .Tb_segdone
	ldrb w11, [x26]
	cbnz w11, .Tb_segdone
	ldrb w11, [x26, #1]
	cmp  w11, #1
	b.ne .Tb_segdone
	mov  x9, #1
	add  x26, x26, #2
.Tb_segdone:
	str  x9, [sp, #0x00]         /* segwit */
	RDCS .Tb_nin                 /* nin in x9 */
	cbz  x9, .Tb_bounds
	str  x9, [sp, #0x08]         /* nin */
	add  x9, x9, x23             /* base + nin */
	cmp  x9, x28                 /* > cap ? */
	b.hi .Tb_sizing
	str  xzr, [sp, #0x10]        /* i = 0 */
.Tb_inloop:
	ldr  x9, [sp, #0x10]
	ldr  x10, [sp, #0x08]
	cmp  x9, x10
	b.hs .Tb_indone
	str  x21, [x25, #0]          /* tx_index */
	str  w9, [x25, #8]           /* local_idx = (u32)i */
	str  x19, [x25, #16]         /* tx_ptr */
	str  x20, [x25, #24]         /* tx_len */
	mov  x11, #-1
	str  x11, [x25, #128]        /* poison tap_desc */
	add  x10, x26, #36
	cmp  x10, x27
	b.hi .Tb_outpt
	str  x26, [x25, #32]         /* outpoint */
	add  x26, x26, #36
	RDCS .Tb_ssv                 /* sl */
	mov  x11, x9
	sub  x9, x27, x26
	cmp  x9, x11
	b.lo .Tb_sstrunc
	sub  x9, x9, x11
	cmp  x9, #4
	b.lo .Tb_sstrunc
	str  x26, [x25, #40]         /* scriptSig */
	str  w11, [x25, #48]         /* scriptSiglen */
	add  x26, x26, x11
	add  x26, x26, #4
	str  wzr, [x25, #72]         /* nwit = 0 */
	add  x25, x25, #144          /* stride */
	ldr  x9, [sp, #0x10]
	add  x9, x9, #1
	str  x9, [sp, #0x10]
	b    .Tb_inloop
.Tb_indone:
	RDCS .Tb_nout                /* nout */
	mov  x11, x9
.Tb_outloop:
	cbz  x11, .Tb_outdone
	add  x9, x26, #8
	cmp  x9, x27
	b.hi .Tb_outtr
	add  x26, x26, #8
	RDCS .Tb_osv
	sub  x10, x27, x26
	cmp  x10, x9
	b.lo .Tb_ostrunc
	add  x26, x26, x9
	sub  x11, x11, #1
	b    .Tb_outloop
.Tb_outdone:
	ldr  x9, [sp, #0x00]         /* segwit */
	cbz  x9, .Tb_ok
	/* recompute entry0 (x25 advanced during in_loop) */
	mov  x9, #144
	mul  x10, x23, x9
	add  x10, x22, x10
	mov  x25, x10
	str  xzr, [sp, #0x10]        /* i = 0 */
.Tb_witloop:
	ldr  x9, [sp, #0x10]
	ldr  x10, [sp, #0x08]
	cmp  x9, x10
	b.hs .Tb_ok
	RDCS .Tb_wcv                 /* nitems */
	mov  x10, #0x0900
	movk x10, #0x003D, lsl#16
	cmp  x9, x10
	b.hi .Tb_witmany
	str  x9, [sp, #0x18]         /* nitems */
	str  w9, [x25, #72]          /* nwit */
	mov  x0, x24                 /* wp */
	mov  x1, x9
	bl   txv_witpool_reserve_asm
	cmp  x0, #-1
	b.eq .Tb_oom
	str  x0, [sp, #0x20]         /* woff */
	str  w0, [x25, #76]          /* wit_off */
	str  xzr, [sp, #0x28]        /* j = 0 */
.Tb_itemloop:
	ldr  x9, [sp, #0x28]
	ldr  x10, [sp, #0x18]
	cmp  x9, x10
	b.hs .Tb_itemsdone
	RDCS .Tb_wlv                 /* il */
	sub  x10, x27, x26
	cmp  x10, x9
	b.lo .Tb_wtrunc
	ldr  x10, [sp, #0x20]
	ldr  x11, [sp, #0x28]
	add  x10, x10, x11
	ldr  x11, [x24, #0]
	str  x26, [x11, x10, lsl #3]
	ldr  x11, [x24, #8]
	str  w9, [x11, x10, lsl #2]
	add  x26, x26, x9
	ldr  x9, [sp, #0x28]
	add  x9, x9, #1
	str  x9, [sp, #0x28]
	b    .Tb_itemloop
.Tb_itemsdone:
	add  x25, x25, #144
	ldr  x9, [sp, #0x10]
	add  x9, x9, #1
	str  x9, [sp, #0x10]
	b    .Tb_witloop
.Tb_ok:
	ldr  x9, [sp, #0x08]
	ldr  x10, [sp, #0x30]        /* out_nin */
	str  x9, [x10]               /* *out_nin = nin */
	mov  x0, #1
	b    .Tb_out
.Tb_short:   LAddr x9, r_short;   b .Tb_reject
.Tb_nin:     LAddr x9, r_nin;     b .Tb_reject
.Tb_bounds:  LAddr x9, r_bounds;  b .Tb_reject
.Tb_sizing:  LAddr x9, r_sizing;  b .Tb_reject
.Tb_outpt:   LAddr x9, r_outpt;   b .Tb_reject
.Tb_ssv:     LAddr x9, r_ssv;     b .Tb_reject
.Tb_sstrunc: LAddr x9, r_sstrunc; b .Tb_reject
.Tb_nout:    LAddr x9, r_nout;    b .Tb_reject
.Tb_outtr:   LAddr x9, r_outtr;   b .Tb_reject
.Tb_osv:     LAddr x9, r_osv;     b .Tb_reject
.Tb_ostrunc: LAddr x9, r_ostrunc; b .Tb_reject
.Tb_wcv:     LAddr x9, r_wcv;     b .Tb_reject
.Tb_witmany: LAddr x9, r_witmany; b .Tb_reject
.Tb_oom:     LAddr x9, r_oom;     b .Tb_reject
.Tb_wlv:     LAddr x9, r_wlv;     b .Tb_reject
.Tb_wtrunc:  LAddr x9, r_wtrunc;  b .Tb_reject
.Tb_reject:
	ldr  x10, [sp, #0x38]        /* reason */
	str  x9, [x10]
	mov  x0, #0
.Tb_out:
	add  sp, sp, #0x40
	ldp  x29, x30, [sp], #16
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size txvb_parse_tx_asm, .-txvb_parse_tx_asm

	.section .note.GNU-stack,"",%progbits
