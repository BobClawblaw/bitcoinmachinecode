/* ============================================================================
 * bitcoin_strip_witness.S -- AArch64 (ARMv8-A) port of asm/bitcoin_strip_witness.asm
 *
 * Canonical witness stripping: SERIALIZE_TRANSACTION_NO_WITNESS.
 * Consumers: legacy sighash on mixed (segwit-carrying) txs and BIP341's
 * stripped-tx commitment -- one divergent byte is a wrong sighash, silently.
 *
 *   long strip_witness_asm(const u8* tx, i64 txlen, u8* out, long cap)
 *     -> stripped length (> 0) or 0 on malformed / cap exceeded
 *
 * AAPCS64: x0=tx, x1=txlen, x2=out, x3=cap ; returns dsz in x0.
 * Faithful transcription of the x86 original: the compactsize reader here is
 * bitcoin_segwit.c's read_cs, which REJECTS non-canonical encodings (v < min
 * for its width); the walk-phase scriptSig bound uses the split (incident #38)
 * form; nin/scriptSig varints are RE-ENCODED minimally on output while the
 * outputs section is copied verbatim (the C's asymmetry); on failure partial
 * bytes already written are left behind, same as the C.
 *
 * Register map (all callee-saved are pushed before use):
 *   x19=tx   x20=end   x21=read cursor / `it`   x22=write cursor d
 *   x23=dsz  x24=cap   x25=segwit flag          x26=nin
 *   x27=i    x28=nitems
 * Locals below the save area ([sp,#0..]): outs_start/outs_end/lock/in0.
 * ========================================================================== */

	.text

/* RDCSC <fail>: canonical compact-size at x21 (end = x20) -> x9, x21 advanced.
 * Jumps to <fail> on truncation OR non-canonical encoding. Clobbers x9,w13,
 * x14,x15. Numeric-local labels 100/101/102 are self-contained per expansion.
 */
.macro RDCSC fail_label
	cmp  x21, x20
	b.hs \fail_label
	ldrb w9, [x21]
	add  x21, x21, #1
	cmp  w9, #0xfd
	b.lo 100f                 /* 1-byte: done, x9 = value */
	beq  101f                 /* 0xfd: 2-byte  */
	cmp  w9, #0xfe
	beq  102f                 /* 0xfe: 4-byte  */
	/* 0xff: 8 bytes, value must be >= 2^32 (canonical) */
	sub  x14, x20, x21
	cmp  x14, #8
	b.lo \fail_label
	ldr  x9, [x21]
	add  x21, x21, #8
	movz x15, #1, lsl #32
	cmp  x9, x15
	b.lo \fail_label
	b    100f
101:
	sub  x14, x20, x21
	cmp  x14, #2
	b.lo \fail_label
	ldrh w9, [x21]
	add  x21, x21, #2
	mov  w15, #0xfd
	cmp  w9, w15
	b.lo \fail_label
	b    100f
102:
	sub  x14, x20, x21
	cmp  x14, #4
	b.lo \fail_label
	ldr  w9, [x21]
	add  x21, x21, #4
	movz w15, #1, lsl #16
	cmp  w9, w15
	b.lo \fail_label
100:
.endm

/* CSSIZE <out>: out = cs_size(x9). Clobbers x15. */
.macro CSSIZE outreg
	mov  \outreg, #1
	cmp  x9, #0xfd
	b.lo 133f
	mov  \outreg, #3
	mov  x15, #0xffff
	cmp  x9, x15
	b.ls 133f
	lsr  x15, x9, #32
	cbnz x15, 131f
	mov  \outreg, #5
	b    133f
131:
	mov  \outreg, #9
133:
.endm

/* PUTCS: write x9 as a minimal compactsize at x22, advance x22 and add the
 * width to x23 (dsz). Clobbers x13, x15. Caller has bounds-checked. */
.macro PUTCS
	cmp  x9, #0xfd
	b.hs 140f
	strb w9, [x22]
	add  x22, x22, #1
	add  x23, x23, #1
	b    143f
140:
	mov  x15, #0xffff
	cmp  x9, x15
	b.hi 141f
	mov  w13, #0xfd
	strb w13, [x22]
	strh w9, [x22, #1]
	add  x22, x22, #3
	add  x23, x23, #3
	b    143f
141:
	lsr  x15, x9, #32
	cbnz x15, 142f
	mov  w13, #0xfe
	strb w13, [x22]
	str  w9, [x22, #1]
	add  x22, x22, #5
	add  x23, x23, #5
	b    143f
142:
	mov  w13, #0xff
	strb w13, [x22]
	str  x9, [x22, #1]
	add  x22, x22, #9
	add  x23, x23, #9
143:
.endm

	.global strip_witness_asm
	.type strip_witness_asm, %function
strip_witness_asm:
	/* save callee-saved + fp/lr: 6 pairs = 96B, then locals 0x40 */
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	sub  sp, sp, #0x40         /* locals: [0]=outs_start [8]=outs_end [16]=lock [24]=in0 */

	mov  x19, x0              /* tx */
	mov  x22, x2              /* d = out */
	mov  x24, x3              /* cap */
	mov  x23, xzr             /* dsz = 0 */
	cmp  x1, #10
	b.lt .fail
	add  x20, x19, x1         /* end = tx + txlen */
	add  x21, x19, #4         /* p = tx + 4 */

	/* segwit = (p[0]==0x00 && p[1]==0x01); txlen>=10 covers the reads */
	mov  x25, xzr
	ldrb w14, [x21]
	cmp  w14, #0x00
	b.ne 200f
	ldrb w14, [x21, #1]
	cmp  w14, #0x01
	b.ne 200f
	mov  x25, #1
	add  x21, x21, #2
200:
	RDCSC .fail               /* x9 = nin */
	cbz  x9, .fail            /* nin == 0 */
	mov  x26, x9              /* nin */
	str  x21, [sp, #24]       /* in0 = input section start (post nin varint) */

	/* ---- walk 1: inputs ---- */
	mov  x27, xzr             /* i = 0 */
.Lw_in:
	cmp  x27, x26
	b.hs .Lw_in_done
	sub  x14, x20, x21        /* avail */
	cmp  x14, #36
	b.lo .fail
	add  x21, x21, #36
	RDCSC .fail               /* x9 = sl */
	sub  x14, x20, x21        /* avail */
	cmp  x14, x9              /* avail < sl ? */
	b.lo .fail
	sub  x14, x14, x9         /* avail - sl */
	cmp  x14, #4
	b.lo .fail
	add  x21, x21, x9
	add  x21, x21, #4
	add  x27, x27, #1
	b    .Lw_in
.Lw_in_done:
	str  x21, [sp, #0]        /* outs_start (nout varint included) */
	RDCSC .fail               /* x9 = nout */
	mov  x27, x9              /* nout countdown */
.Lw_out:
	cbz  x27, .Lw_out_done
	sub  x14, x20, x21
	cmp  x14, #8
	b.lo .fail
	add  x21, x21, #8
	RDCSC .fail               /* x9 = sl */
	sub  x14, x20, x21
	cmp  x14, x9
	b.lo .fail
	add  x21, x21, x9
	sub  x27, x27, #1
	b    .Lw_out
.Lw_out_done:
	str  x21, [sp, #8]        /* outs_end == witness start */
	str  x21, [sp, #16]       /* lock = q (legacy default) */
	cbz  x25, .Lw_lock

	/* ---- walk 2: witness stacks (segwit only) ---- */
	mov  x27, xzr             /* i = 0 */
.Lw_wit:
	cmp  x27, x26
	b.hs .Lw_wit_done
	RDCSC .fail               /* x9 = nitems */
	mov  x28, x9
.Lw_item:
	cbz  x28, .Lw_item_done
	RDCSC .fail               /* x9 = il */
	sub  x14, x20, x21
	cmp  x14, x9
	b.lo .fail
	add  x21, x21, x9
	sub  x28, x28, #1
	b    .Lw_item
.Lw_item_done:
	add  x27, x27, #1
	b    .Lw_wit
.Lw_wit_done:
	str  x21, [sp, #16]       /* lock = q */
.Lw_lock:
	ldr  x16, [sp, #16]
	sub  x14, x20, x16        /* avail(lock) */
	cmp  x14, #4
	b.lo .fail

	/* ================= emit ================= */
	/* version: dsz + 4 > cap ? (signed) */
	add  x14, x23, #4
	cmp  x14, x24
	b.gt .fail
	ldr  w14, [x19]
	str  w14, [x22]
	add  x22, x22, #4
	add  x23, x23, #4
	/* nin varint, re-encoded minimally */
	mov  x9, x26
	CSSIZE x14                /* x14 = cs_size(nin) */
	add  x15, x23, x14
	cmp  x15, x24             /* dsz + csn > cap ? (signed) */
	b.gt .fail
	PUTCS                     /* writes nin */

	/* ---- inputs: copy outpoint+sequence, re-encode scriptSig varint ---- */
	ldr  x21, [sp, #24]       /* it = input section start */
	mov  x27, xzr             /* i = 0 */
.Le_in:
	cmp  x27, x26
	b.hs .Le_in_done
	add  x14, x23, #36
	cmp  x14, x24             /* dsz + 36 > cap ? (signed) */
	b.gt .fail
	ldp  x15, x16, [x21]
	stp  x15, x16, [x22]
	ldp  x15, x16, [x21, #16]
	stp  x15, x16, [x22, #16]
	ldr  w15, [x21, #32]
	str  w15, [x22, #32]
	add  x21, x21, #36
	add  x22, x22, #36
	add  x23, x23, #36
	RDCSC .fail               /* x9 = sl (re-read; walk 1 validated it) */
	/* C bound: cap < 0 || (u64)(cap - dsz) < cs_size(sl)+sl+4 */
	tbnz x24, #63, .fail      /* cap < 0 */
	CSSIZE x14                /* x14 = cs_size(sl) */
	add  x14, x14, x9         /* + sl */
	add  x14, x14, #4         /* + 4 */
	sub  x15, x24, x23        /* cap - dsz */
	cmp  x15, x14             /* unsigned < */
	b.lo .fail
	PUTCS                     /* scriptSig varint (x9 = sl) */
	mov  x14, x9              /* sl bytes to copy */
	add  x23, x23, x14        /* dsz += sl */
.Lcpy:
	cbz  x14, .Lcpy_done
	ldrb w15, [x21]
	strb w15, [x22]
	add  x21, x21, #1
	add  x22, x22, #1
	sub  x14, x14, #1
	b    .Lcpy
.Lcpy_done:
	ldr  w15, [x21]           /* sequence */
	str  w15, [x22]
	add  x21, x21, #4
	add  x22, x22, #4
	add  x23, x23, #4
	add  x27, x27, #1
	b    .Le_in
.Le_in_done:

	/* ---- outputs section, verbatim ---- */
	ldr  x14, [sp, #8]        /* outs_end */
	ldr  x15, [sp, #0]        /* outs_start */
	sub  x14, x14, x15        /* olen */
	cmp  x14, #1
	b.lt .fail                /* olen < 1 */
	add  x16, x23, x14
	cmp  x16, x24             /* dsz + olen > cap ? (signed) */
	b.gt .fail
	mov  x15, x14             /* count */
	ldr  x16, [sp, #0]
.Locpy:
	cbz  x15, .Locpy_done
	ldrb w17, [x16]
	strb w17, [x22]
	add  x16, x16, #1
	add  x22, x22, #1
	sub  x15, x15, #1
	b    .Locpy
.Locpy_done:
	add  x23, x23, x14        /* dsz += olen */

	/* ---- locktime ---- */
	add  x14, x23, #4
	cmp  x14, x24             /* dsz + 4 > cap ? (signed) */
	b.gt .fail
	ldr  x16, [sp, #16]       /* lock */
	ldr  w17, [x16]
	str  w17, [x22]
	add  x23, x23, #4
	mov  x0, x23              /* return dsz */
	b    .out

.fail:
	mov  x0, xzr
.out:
	add  sp, sp, #0x40
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size strip_witness_asm, .-strip_witness_asm

/* ----------------------------------------------------------------------------
 * hash160(u8 out[20], const void* in, i64 len)  (x0,x1,x2)
 * h = SHA-256(in); out = RIPEMD-160(h). Exact ABI twin of asm/bitcoin_addr.asm.
 * Needed by the C segwit path (p2wpkh/p2wsh) that the differential links.
 * -------------------------------------------------------------------------- */
	.global hash160
	.type hash160, %function
hash160:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	sub  sp, sp, #0x30        /* 32-byte scratch + pad; 0x10+0x10+0x30=0x50, 0 mod 16 */
	mov  x19, x0              /* out */
	mov  x20, x2              /* len */
	/* h = sha256_full(sp+0, in, len) */
	add  x0, sp, #0
	mov  x1, x1               /* in (unchanged) */
	mov  x2, x20
	bl   sha256_full
	/* out = ripemd160(out, sp+0, 32) */
	mov  x0, x19
	mov  x1, sp
	mov  x2, #32
	bl   ripemd160
	add  sp, sp, #0x30
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size hash160, .-hash160

	.section .note.GNU-stack,"",@progbits
