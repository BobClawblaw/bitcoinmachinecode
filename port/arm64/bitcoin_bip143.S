/* ============================================================================
 * bitcoin_bip143.S -- AArch64 port of asm/bitcoin_bip143.asm (BIP143 / segwit
 * v0 sighash): swtx_parse_asm + segwit_v0_sighash_asm.
 *
 *   long swtx_parse_asm(swtx_t* t, u32* off)       -> w0 1/0
 *   long segwit_v0_sighash_asm(u8 out32[32], const u8* tx, i64 txlen,
 *                              i64 n_in, u32 nHashType, u64 amount,
 *                       (stack args) const u8* scriptCode, u64 sclen,
 *                              u8* pre, long cap)  -> x0 prelen or 0
 *
 * swtx_t (offsetof-pinned): tx@0 txlen@8 end@16 version@24 locktime@32
 *   nin@40 nout@48 inputs@56 in_off@64 out_off@72, size 80.
 * Static buffers (single-threaded; -> .tbss before threaded daemon):
 * bip143_mbuf (4 MiB), bip143_soff (600000 u32). sha256d from bitcoin_hash.S.
 * ========================================================================== */

	.text
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

	/* canonical compact-size reader: RA = value; cur advanced; bad on
	   truncation or non-minimal encoding. Clobbers x0,x1,x2. */
	.macro RDCSC RA, cur, end, bad
	cmp  \cur, \end
	b.hs \bad
	ldrb w1, [\cur]
	add  \cur, \cur, #1
	cmp  w1, #0xfd
	b.lo 97f
	b.eq 96f
	cmp  w1, #0xfe
	b.eq 95f
	sub  x0, \end, \cur
	cmp  x0, #8
	b.lo \bad
	ldr  x1, [\cur]
	add  \cur, \cur, #8
	movz x2, #1, lsl #32
	cmp  x1, x2
	b.hs 97f
	b    \bad
95:	sub  x0, \end, \cur
	cmp  x0, #4
	b.lo \bad
	ldr  w1, [\cur]
	add  \cur, \cur, #4
	movz x2, #1, lsl #16
	cmp  x1, x2
	b.hs 97f
	b    \bad
96:	sub  x0, \end, \cur
	cmp  x0, #2
	b.lo \bad
	ldrh w1, [\cur]
	add  \cur, \cur, #2
	cmp  w1, #0xfd
	b.lo \bad
97:	mov  \RA, x1
	.endm

	.section .bss
	.balign 16
	.global bip143_mbuf
bip143_mbuf:
	.space (4 << 20)
	.global bip143_soff
bip143_soff:
	.space (600000 * 4)
	.text

/* Local byte copy: x0=dst x1=src x2=n. clobbers x0-x3; preserves x19-x28. */
	.type bip_copy, %function
bip_copy:
	cbz  x2, 1f
0:	ldrb w3, [x1]
	strb w3, [x0]
	add  x0, x0, #1
	add  x1, x1, #1
	sub  x2, x2, #1
	cbnz x2, 0b
1:	ret
	.size bip_copy, .-bip_copy

/* ============================================================================
 * swtx_parse_asm(x0=t, x1=off) -> w0 1/0
 * x19=cursor x20=end x21=t x22=off x23=nin x24=i x25=nout x26=out_off
 * ========================================================================== */
	.global swtx_parse_asm
	.type swtx_parse_asm, %function
swtx_parse_asm:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	mov  x21, x0                 /* t */
	mov  x22, x1                 /* off */
	ldr  x19, [x21, #0]          /* cursor = t.tx */
	ldr  x6,  [x21, #8]          /* txlen */
	cmp  x6, #10
	b.lt .sw_no
	movz x7, #0xffff, lsl #16
	movk x7, #0xffff
	cmp  x6, x7
	b.hi .sw_no
	add  x20, x19, x6            /* end */
	str  x20, [x21, #16]
	ldrsw x6, [x19]              /* version sign-ext */
	str  x6, [x21, #24]
	add  x19, x19, #4
	ldrb w6, [x19]
	cmp  w6, #0
	b.ne .sw_nin
	ldrb w7, [x19, #1]
	cmp  w7, #1
	b.ne .sw_nin
	add  x19, x19, #2
.sw_nin:
	RDCSC x8, x19, x20, .sw_no
	cmp  x8, #0
	b.le .sw_no
	str  x8, [x21, #40]          /* nin */
	mov  x23, x8
	add  x6, x8, #1
	movz x7, #0x27c0
	movk x7, #0x9, lsl #16
	cmp  x6, x7
	b.hi .sw_no
	str  x19, [x21, #56]         /* t.inputs */
	mov  x24, #0
.sw_in_loop:
	cmp  x24, x23
	b.hs .sw_in_done
	ldr  x7, [x21, #0]
	sub  x6, x19, x7
	str  w6, [x22, x24, lsl #2]  /* in_off[i] */
	sub  x6, x20, x19
	cmp  x6, #36
	b.lo .sw_no
	add  x19, x19, #36
	RDCSC x8, x19, x20, .sw_no   /* sl */
	sub  x6, x20, x19
	cmp  x6, x8
	b.lo .sw_no
	sub  x6, x6, x8
	cmp  x6, #4
	b.lo .sw_no
	add  x19, x19, x8
	add  x19, x19, #4
	add  x24, x24, #1
	b    .sw_in_loop
.sw_in_done:
	ldr  x7, [x21, #0]
	sub  x6, x19, x7
	str  w6, [x22, x23, lsl #2]  /* in_off[nin] */
	str  x22, [x21, #64]
	RDCSC x8, x19, x20, .sw_no   /* nout */
	cmp  x8, #0
	b.lt .sw_no
	str  x8, [x21, #48]          /* nout */
	mov  x25, x8
	add  x6, x23, #1
	add  x6, x6, x25
	add  x6, x6, #1
	movz x7, #0x27c0
	movk x7, #0x9, lsl #16
	cmp  x6, x7
	b.hi .sw_no
	add  x26, x22, x23, lsl #2
	add  x26, x26, #4            /* out_off = off+(nin+1) */
	mov  x24, #0
.sw_out_loop:
	cmp  x24, x25
	b.hs .sw_out_done
	ldr  x7, [x21, #0]
	sub  x6, x19, x7
	str  w6, [x26, x24, lsl #2]  /* out_off[i] */
	sub  x6, x20, x19
	cmp  x6, #8
	b.lo .sw_no
	add  x19, x19, #8
	RDCSC x8, x19, x20, .sw_no   /* sl */
	sub  x6, x20, x19
	cmp  x6, x8
	b.lo .sw_no
	add  x19, x19, x8
	add  x24, x24, #1
	b    .sw_out_loop
.sw_out_done:
	ldr  x7, [x21, #0]
	sub  x6, x19, x7
	str  w6, [x26, x25, lsl #2]  /* out_off[nout] */
	str  x26, [x21, #72]
	ldr  x7, [x21, #0]
	ldrb w6, [x7, #4]
	cmp  w6, #0
	b.ne .sw_lock
	ldrb w7, [x7, #5]
	cmp  w7, #1
	b.ne .sw_lock
	mov  x24, #0
.sw_wit_loop:
	cmp  x24, x23
	b.hs .sw_lock
	RDCSC x25, x19, x20, .sw_no  /* nitems */
.sw_item_loop:
	cbz  x25, .sw_item_done
	RDCSC x8, x19, x20, .sw_no   /* il */
	sub  x6, x20, x19
	cmp  x6, x8
	b.lo .sw_no
	add  x19, x19, x8
	sub  x25, x25, #1
	b    .sw_item_loop
.sw_item_done:
	add  x24, x24, #1
	b    .sw_wit_loop
.sw_lock:
	sub  x6, x20, x19
	cmp  x6, #4
	b.lo .sw_no
	ldr  w6, [x19]
	str  w6, [x21, #32]          /* locktime */
	mov  w0, #1
	b    .sw_out
.sw_no:
	mov  w0, #0
.sw_out:
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size swtx_parse_asm, .-swtx_parse_asm

/* ============================================================================
 * segwit_v0_sighash_asm
 * Args: x0=out32 x1=tx x2=txlen x3=n_in w4=nHashType x5=amount x6=scriptCode
 *       x7=sclen  [sp]=pre [sp+8]=cap
 * Frame base x28 (sp), 288 bytes. Locals:
 *   out32@0 n_in@8 nHashType@16 amount@24 htype@32 acp@40 p@48 pend@56 mbuf@64
 *   t(80B)@80 hashPrevouts@160 hashSequence@192 hashOutputs@224 n@256
 *   scriptCode@272 sclen@280
 * Registers: x19=p x20=&t x21=mbuf x22=nin x23=i x24=n x25=pend x26/27=scratch
 * ========================================================================== */
	.global segwit_v0_sighash_asm
	.type segwit_v0_sighash_asm, %function
segwit_v0_sighash_asm:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	sub  sp, sp, #288
	mov  x28, sp
	/* stack args at CALLER's sp; after 6 stp (96)+288 = 384 */
	ldr  x9, [sp, #384]          /* pre */
	str  x9,  [x28, #48]
	ldr  x9, [sp, #392]          /* cap */
	str  x9,  [x28, #56]
	str  x0, [x28, #0]           /* out32 */
	str  x3, [x28, #8]           /* n_in */
	str  x4, [x28, #16]          /* nHashType */
	mov  x9, x5
	str  x9, [x28, #24]          /* amount */
	str  x6, [x28, #272]         /* scriptCode */
	mov  x9, x7
	str  x9, [x28, #280]         /* sclen */
	add  x20, x28, #80           /* &t */
	str  x1, [x20, #0]           /* t.tx */
	str  x2, [x20, #8]           /* t.txlen */
	LAddr x21, bip143_mbuf
	str  x21, [x28, #64]
	LAddr x26, bip143_soff
	add  x0, x20, #0
	mov  x1, x26
	bl   swtx_parse_asm
	cbz  w0, .swv_fail
	ldr  x9, [x28, #8]
	cmp  x9, #0
	b.lt .swv_fail
	ldr  x22, [x20, #40]         /* nin */
	cmp  x9, x22
	b.ge .swv_fail
	ldr  x9, [x28, #16]
	and  w10, w9, #0x1f
	str  x10, [x28, #32]         /* htype */
	and  w10, w9, #0x80
	str  x10, [x28, #40]         /* acp */
	add  x9, x28, #160
	stp  xzr, xzr, [x9, #0]
	stp  xzr, xzr, [x9, #16]
	stp  xzr, xzr, [x9, #32]
	stp  xzr, xzr, [x9, #48]
	stp  xzr, xzr, [x9, #64]
	stp  xzr, xzr, [x9, #80]
	ldr  x19, [x28, #48]         /* p = pre */
	ldr  x9,  [x28, #56]
	add  x25, x19, x9            /* pend */
	ldr  x9, [x28, #40]          /* acp */
	cbnz x9, .swv_outputs
	/* ---- hashPrevouts ---- */
	mov  x7, #36
	mul  x6, x22, x7
	movz x7, #0x40, lsl #16
	cmp  x6, x7
	b.hi .swv_fail
	mov  x23, #0
	mov  x24, #0
.swv_hp_loop:
	cmp  x23, x22
	b.hs .swv_hp_done
	ldr  x9, [x20, #64]
	ldr  w9, [x9, x23, lsl #2]
	ldr  x10, [x20, #0]
	add  x9, x9, x10
	add  x13, x21, x24
	ldp  x11, x12, [x9]
	stp  x11, x12, [x13]
	ldp  x11, x12, [x9, #16]
	stp  x11, x12, [x13, #16]
	ldr  w11, [x9, #32]
	str  w11, [x13, #32]
	add  x24, x24, #36
	add  x23, x23, #1
	b    .swv_hp_loop
.swv_hp_done:
	str  x24, [x28, #256]
	add  x0, x28, #160
	mov  x1, x21
	mov  x2, x24
	bl   sha256d
	/* ---- hashSequence ---- */
	ldr  x9, [x28, #32]
	cmp  x9, #3
	b.eq .swv_outputs
	cmp  x9, #2
	b.eq .swv_outputs
	lsl  x6, x22, #2
	movz x7, #0x40, lsl #16
	cmp  x6, x7
	b.hi .swv_fail
	mov  x23, #0
	mov  x24, #0
.swv_hs_loop:
	cmp  x23, x22
	b.hs .swv_hs_done
	ldr  x9, [x20, #64]
	add  x7, x23, #1
	ldr  w9, [x9, x7, lsl #2]
	ldr  x10, [x20, #0]
	add  x9, x9, x10
	ldr  w11, [x9, #-4]
	add  x13, x21, x24
	str  w11, [x13]
	add  x24, x24, #4
	add  x23, x23, #1
	b    .swv_hs_loop
.swv_hs_done:
	str  x24, [x28, #256]
	add  x0, x28, #192
	mov  x1, x21
	mov  x2, x24
	bl   sha256d
.swv_outputs:
	ldr  x9, [x28, #32]
	cmp  x9, #3
	b.eq .swv_single
	cmp  x9, #2
	b.eq .swv_preimage
	/* ALL: hash over [out_off[0], out_off[nout]) */
	ldr  x9,  [x20, #72]
	ldr  x10, [x20, #48]
	ldr  w8, [x9, x10, lsl #2]
	ldr  w7, [x9]
	sub  x6, x8, x7
	movz x10, #0x40, lsl #16
	cmp  x6, x10
	b.hi .swv_fail
	ldr  x10, [x20, #0]
	add  x1, x7, x10
	add  x0, x28, #224
	mov  x2, x6
	bl   sha256d
	b    .swv_preimage
.swv_single:
	ldr  x9, [x28, #8]
	ldr  x10, [x20, #48]
	cmp  x9, x10
	b.ge .swv_preimage
	ldr  x7, [x20, #72]
	add  x8, x9, #1
	ldr  w8, [x7, x8, lsl #2]    /* out_off[n_in+1] */
	ldr  w6, [x7, x9, lsl #2]    /* out_off[n_in] */
	sub  x2, x8, x6
	movz x10, #0x40, lsl #16
	cmp  x2, x10
	b.hi .swv_fail
	ldr  x10, [x20, #0]
	add  x1, x10, x6             /* obytes */
	add  x0, x28, #224
	bl   sha256d
	/* fall through */
.swv_preimage:
	/* ---- version ---- */
	add  x9, x19, #4
	cmp  x9, x25
	b.hi .swv_fail
	ldr  w10, [x20, #24]
	str  w10, [x19]
	add  x19, x19, #4
	/* ---- hashPrevouts || hashSequence (64) ---- */
	add  x9, x19, #64
	cmp  x9, x25
	b.hi .swv_fail
	add  x0, x19, #0
	add  x1, x28, #160
	mov  x2, #64
	bl   bip_copy
	add  x19, x19, #64
	/* ---- outpoint[n_in] 36 bytes ---- */
	add  x9, x19, #36
	cmp  x9, x25
	b.hi .swv_fail
	ldr  x9, [x20, #64]
	ldr  x10, [x28, #8]
	ldr  w10, [x9, x10, lsl #2]
	ldr  x11, [x20, #0]
	add  x0, x19, #0
	add  x1, x11, x10
	mov  x2, #36
	bl   bip_copy
	add  x19, x19, #36
	/* ---- scriptCode: compute cs_size(sclen), check cap, write cs then bytes ---- */
	ldr  x7, [x28, #280]         /* sclen */
	mov  x8, #1                  /* cs_size */
	cmp  x7, #0xfd
	b.lo .swv_cs_have
	mov  x8, #3
	movz x13, #0xffff
	cmp  x7, x13
	b.ls .swv_cs_have
	mov  x8, #5
	movz x9, #0xffff, lsl #16
	movk x9, #0xffff
	cmp  x7, x9
	b.ls .swv_cs_have
	mov  x8, #9
.swv_cs_have:
	/* (p-pre) + cs_size + sclen <= cap ? */
	ldr  x10, [x28, #48]         /* pre */
	sub  x9, x19, x10            /* p - pre */
	add  x9, x9, x8              /* + cs_size */
	add  x9, x9, x7              /* + sclen */
	ldr  x12, [x28, #56]         /* cap */
	cmp  x9, x12
	b.hi .swv_fail
	/* write cs prefix */
	cmp  x7, #0xfd
	b.lo .swv_cs1
	movz x13, #0xffff
	cmp  x7, x13
	b.hi .swv_cs4
	mov  w10, #0xfd
	strb w10, [x19]
	strh w7, [x19, #1]
	add  x19, x19, #3
	b    .swv_cs_data
.swv_cs4:
	movz x10, #0xffff, lsl #16
	movk x10, #0xffff
	cmp  x7, x10
	b.hi .swv_cs8
	mov  w10, #0xfe
	strb w10, [x19]
	str  w7, [x19, #1]
	add  x19, x19, #5
	b    .swv_cs_data
.swv_cs8:
	mov  w10, #0xff
	strb w10, [x19]
	str  x7, [x19, #1]
	add  x19, x19, #9
	b    .swv_cs_data
.swv_cs1:
	strb w7, [x19]
	add  x19, x19, #1
.swv_cs_data:
	ldr  x10, [x28, #272]        /* scriptCode */
	ldr  x7,  [x28, #280]        /* sclen */
	add  x0, x19, #0
	mov  x1, x10
	mov  x2, x7
	bl   bip_copy
	add  x19, x19, x7
	/* ---- amount ---- */
	add  x9, x19, #8
	cmp  x9, x25
	b.hi .swv_fail
	ldr  x10, [x28, #24]
	str  x10, [x19]
	add  x19, x19, #8
	/* ---- nSequence[n_in] ---- */
	add  x9, x19, #4
	cmp  x9, x25
	b.hi .swv_fail
	ldr  x9, [x20, #64]
	ldr  x10, [x28, #8]
	add  x10, x10, #1
	ldr  w10, [x9, x10, lsl #2]
	ldr  x11, [x20, #0]
	add  x9, x11, x10
	ldr  w10, [x9, #-4]
	str  w10, [x19]
	add  x19, x19, #4
	/* ---- hashOutputs ---- */
	add  x9, x19, #32
	cmp  x9, x25
	b.hi .swv_fail
	add  x0, x19, #0
	add  x1, x28, #224
	mov  x2, #32
	bl   bip_copy
	add  x19, x19, #32
	/* ---- locktime ---- */
	add  x9, x19, #4
	cmp  x9, x25
	b.hi .swv_fail
	ldr  w10, [x20, #32]
	str  w10, [x19]
	add  x19, x19, #4
	/* ---- nHashType ---- */
	add  x9, x19, #4
	cmp  x9, x25
	b.hi .swv_fail
	ldr  x9, [x28, #16]
	str  w9, [x19]
	add  x19, x19, #4
	/* ---- prelen + sha256d ---- */
	ldr  x9, [x28, #48]          /* pre */
	sub  x2, x19, x9
	ldr  x0, [x28, #0]           /* out32 */
	mov  x1, x9
	mov  x24, x2                 /* prelen */
	bl   sha256d
	mov  x0, x24
	b    .swv_out
.swv_fail:
	mov  x0, #0
.swv_out:
	add  sp, sp, #288
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size segwit_v0_sighash_asm, .-segwit_v0_sighash_asm

	.section .note.GNU-stack,"",%progbits
