/* ============================================================================
 * bitcoin_txv_classify.S -- AArch64 (ARMv8-A) port of asm/bitcoin_txv_classify.asm
 *
 * Per-input consensus classification for daemon/tx_verify.c's block path:
 * coinbase maturity, prevout spk copy-out (offset discipline into the caller's
 * bytepool), the taproot gate, segwit classification (using the self-contained
 * 8-arg sv_classify_segwit port) incl. the wrapped/native wprog split, the
 * unexpected-witness rule, and the legacy fallthrough.
 *
 * ABI (SysV x64 -> AAPCS64):
 *   long txvb_classify_asm(txvb_in_t* in, long height, u64 flags, u64 value,
 *                          u64 uheight, u64 ucb,
 *                          const u8* spk, u64 spklen,
 *                          bytepool_t* spk_pool, int* has_taproot,
 *                          const char** reason) -> 1 ok / 0 reject
 *     AAPCS64: first 6 in x0..x5; args 7-11 (spk, spklen, spk_pool,
 *     has_taproot, reason) on the stack.
 *
 * txvb_in_t offsets: scriptSig@40 scriptSiglen@48 nwit@72 wprog@80 wproglen@88
 *   wrapped@92 wprog_off@96 value@104 spk_off@112 spklen@120 shape@136,
 *   stride 144. Shapes: LEGACY 0, P2TR 3, WV0 4, WPASS 5.
 *   TXV_SPK_CAP=10000 COINBASE_MATURITY=100 FLAG_WITNESS=1<<11 FLAG_TAPROOT=1<<17
 * ========================================================================== */

	.text
	.global txvb_classify_asm
	.type txvb_classify_asm, %function

	.extern sv_classify_segwit
	.extern txv_bytepool_alloc_asm

	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

	.section .rodata
c_immature: .asciz "immature coinbase spend (100-block rule)"
c_spkbig:   .asciz "prevout script too large"
c_oom:      .asciz "out of memory"
c_tapss:    .asciz "p2tr scriptSig must be empty"
c_tapwit:   .asciz "p2tr empty witness"
c_wrapss:   .asciz "p2sh-wrapped witness program: scriptSig must be exactly one push of the redeemScript"
c_wpss:     .asciz "witness program scriptSig must be empty"
c_wpkh2:    .asciz "p2wpkh needs exactly 2 witness items"
c_wsh1:     .asciz "p2wsh needs a witnessScript"
c_unexwit:  .asciz "unexpected witness on a non-witness script"
	.text

/* ============================================================================
 * txvb_classify_asm -- see header. Regs:
 *   x19=in x20=spk x21=spklen x22=flags x23=height x24=spk_pool
 *   x25=has_taproot x26=reason
 *   Locals: wver@sp+0 wplen@sp+4 wrapped@sp+8 wprog@sp+16.
 *   Stack args at [sp+0xA0..0xC0] (after 5 pairs + sub 0x20).
 * ========================================================================== */
txvb_classify_asm:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #0x20
	mov  x19, x0                 /* in */
	mov  x23, x1                 /* height */
	mov  x22, x2                 /* flags */
	mov  x20, x6                 /* spk (arg 7 = x6 on AAPCS64) */
	mov  x21, x7                 /* spklen (arg 8 = x7) */
	ldr  x24, [sp, #0x70]        /* spk_pool (arg 9 on stack) */
	ldr  x25, [sp, #0x78]        /* has_taproot (arg 10) */
	ldr  x26, [sp, #0x80]        /* reason (arg 11) */
	/* ---- coinbase maturity ---- */
	cbz  x5, .Cc_notcb           /* ucb */
	sub  x9, x23, x4             /* height - (long)uheight */
	mov  x10, #100
	cmp  x9, x10
	b.ge .Cc_notcb
	LAddr x9, c_immature
	b    .Cc_reject
.Cc_notcb:
	str  x3, [x19, #104]         /* in->value = value */
	mov  x9, #10000
	cmp  x21, x9                 /* spklen > TXV_SPK_CAP */
	b.hi .Cc_spkbig
	/* ---- spk copy-out into the bytepool ---- */
	mov  x0, x24                 /* spk_pool */
	mov  x1, x20                 /* spk */
	mov  x2, x21                 /* spklen */
	bl   txv_bytepool_alloc_asm
	cmp  x0, #-1
	b.eq .Cc_oom
	str  x0, [x19, #112]         /* spk_off */
	str  w21, [x19, #120]        /* spklen (u32) */
	/* ---- taproot gate ---- */
	cmp  x21, #34
	b.ne .Cc_nottap
	ldrb w9, [x20]
	cmp  w9, #0x51
	b.ne .Cc_nottap
	ldrb w9, [x20, #1]
	cmp  w9, #0x20
	b.ne .Cc_nottap
	tbz  x22, #17, .Cc_nottap    /* FLAG_TAPROOT */
	mov  w9, #1
	str  w9, [x25]               /* *has_taproot = 1 */
	mov  w9, #3                  /* SHAPE_P2TR */
	strb w9, [x19, #136]
	ldr  w9, [x19, #48]          /* scriptSiglen */
	cbnz w9, .Cc_tapss
	ldr  w9, [x19, #72]          /* nwit */
	cbz  w9, .Cc_tapwit
	b    .Cc_accept
.Cc_nottap:
	tbz  x22, #11, .Cc_legacy    /* FLAG_WITNESS */
	/* ---- segwit classification ---- */
	mov  x0, x20                 /* spk */
	mov  w1, w21                 /* (u32)spl */
	ldr  x2, [x19, #40]          /* scriptSig */
	ldr  w3, [x19, #48]          /* ssl */
	add  x4, sp, #0              /* &wver */
	add  x5, sp, #16             /* &wprog */
	add  x6, sp, #4              /* &wplen */
	add  x7, sp, #8              /* &wrapped */
	bl   sv_classify_segwit
	tbnz x0, #31, .Cc_wrapss     /* cls < 0 */
	cbz  x0, .Cc_notwitprog      /* cls == 0 */
	ldr  w9, [sp, #8]            /* wrapped */
	cbnz w9, .Cc_have
	ldr  w9, [x19, #48]          /* ssl (native: must be empty) */
	cbnz w9, .Cc_wpss
.Cc_have:
	ldr  w9, [sp, #0]            /* wver */
	cbnz w9, .Cc_wpass
	mov  w9, #4                  /* SHAPE_WV0 */
	strb w9, [x19, #136]
	ldr  w9, [sp, #4]            /* wplen */
	str  w9, [x19, #88]          /* wproglen */
	ldr  w9, [sp, #8]            /* wrapped */
	strb w9, [x19, #92]          /* wrapped (u8) */
	cbz  w9, .Cc_native
	ldr  x9, [sp, #16]           /* wprog = raw ptr (tx bytes) */
	str  x9, [x19, #80]
	str  wzr, [x19, #96]         /* wprog_off = 0 */
	b    .Cc_wv0
.Cc_native:
	str  xzr, [x19, #80]         /* wprog = 0 (offset form) */
	ldr  x9, [sp, #16]
	sub  x9, x9, x20             /* wprog - spk */
	str  w9, [x19, #96]          /* wprog_off */
.Cc_wv0:
	ldr  w9, [sp, #4]            /* wplen */
	cmp  w9, #20
	b.ne .Cc_chk32
	ldr  w9, [x19, #72]          /* nwit */
	cmp  w9, #2
	b.ne .Cc_wpkh2
	b    .Cc_accept
.Cc_chk32:
	cmp  w9, #32
	b.ne .Cc_accept
	ldr  w9, [x19, #72]          /* nwit */
	cbz  w9, .Cc_wsh1
	b    .Cc_accept
.Cc_wpass:
	mov  w9, #5                  /* SHAPE_WPASS */
	strb w9, [x19, #136]
	b    .Cc_accept
.Cc_notwitprog:
	ldr  w9, [x19, #72]          /* nwit */
	cbnz w9, .Cc_unexwit
.Cc_legacy:
	strb wzr, [x19, #136]        /* SHAPE_LEGACY */
.Cc_accept:
	mov  w0, #1
	b    .Cc_out
.Cc_spkbig: LAddr x9, c_spkbig;   b .Cc_reject
.Cc_oom:    LAddr x9, c_oom;      b .Cc_reject
.Cc_tapss:  LAddr x9, c_tapss;    b .Cc_reject
.Cc_tapwit: LAddr x9, c_tapwit;   b .Cc_reject
.Cc_wrapss: LAddr x9, c_wrapss;   b .Cc_reject
.Cc_wpss:   LAddr x9, c_wpss;     b .Cc_reject
.Cc_wpkh2:  LAddr x9, c_wpkh2;    b .Cc_reject
.Cc_wsh1:   LAddr x9, c_wsh1;     b .Cc_reject
.Cc_unexwit:LAddr x9, c_unexwit;  b .Cc_reject
.Cc_reject:
	str  x9, [x26]               /* *reason = string */
	mov  w0, #0
.Cc_out:
	add  sp, sp, #0x20
	ldp  x29, x30, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size txvb_classify_asm, .-txvb_classify_asm

	.section .note.GNU-stack,"",%progbits
