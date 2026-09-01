/* ============================================================================
 * bitcoin_sighash.S -- AArch64 port of asm/bitcoin_sighash.asm
 *
 * int legacy_sighash(u8 out32[32], const u8* tx, u64 txlen, u64 nIn,
 *                    const u8* scriptCode, u64 scLen, int32 hashtype,
 *                    u8* preimg, u64 cap)  -> w0 1/0
 *   Legacy (SigVersion::BASE) SignatureHash for every hashtype
 *   (ALL/NONE/SINGLE x ANYONECANPAY) incl. the SIGHASH_SINGLE out-of-range
 *   uint256(1) quirk. Serializes version + inputs (scriptCode for the signed
 *   input, empty elsewhere, zeroed seq for SINGLE/NONE, inputs omitted under
 *   ANYONECANPAY) + outputs + locktime + hashtype into `preimg` (cap bytes)
 *   then sha256d into out32. Returns 0 on malformed tx / out-of-range /
 *   overflow -- never a silent wrong hash.
 *
 * Module-internal helper ABIs (called only within this file):
 *   copy_bytes(x0=dst,x1=src,x2=n)              -> x0=dst+n, x1=src+n
 *   parse_varint(x0=ptr,x1=end)                 -> x0=value, x1=newptr
 *   write_varint(x0=cursor,x1=value,x2=end)     -> x0=newcursor
 *   script_op_len(x0=pos,x1=end)                -> x0=unit len (0 malformed)
 *   script_find_and_delete(x0=dst,x1=dstcap,x2=src,x3=srclen,x4=needle,
 *                          x5=needlelen)        -> x0=outlen or 0xFFFF..
 *   script_push_encode(x0=dst,x1=dstcap,x2=data,x3=datalen) -> x0=outlen/-1
 *   legacy_locate_nout(x0=tx,x1=txend,x2=nIn)   -> x0=nOut, x1=ok
 * All helpers preserve x19-x28.
 *
 * TLS NOTE: x86 uses per-thread legacy_sighash_scfbuf via TLS_ADDR. This port
 * uses one static 20000-byte buffer (ls_scfbuf) -- fine single-threaded;
 * convert to .tbss/__thread before the threaded daemon.
 * ========================================================================== */
	.text
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

	.macro CMd rd, off
	ldr  x16, [x28, \off]
	cmp  \rd, x16
	.endm

/* TLS Initial-Exec address of a .tbss symbol into d (clobbers x10). x86
 * parity: the scriptCode scratch below is PER-THREAD; the threaded verify
 * workers must each get their own buffer or they race on the shared one. */
	.macro TLS_ADDR d, sym
	adrp \d, :gottprel:\sym
	ldr  \d, [\d, #:gottprel_lo12:\sym]
	mrs  x10, tpidr_el0
	add  \d, \d, x10
	.endm

	.section .tbss,"awT",@nobits
	.balign 16
	.global ls_scfbuf
ls_scfbuf:
	.space 20000
	.text

/* ============================================================================
 * copy_bytes(x0=dst, x1=src, x2=n) -> x0=dst+n, x1=src+n. Byte loop.
 * ========================================================================== */
copy_bytes:
	cbz  x2, 1f
0:	ldrb w3, [x1]
	strb w3, [x0]
	add  x0, x0, #1
	add  x1, x1, #1
	sub  x2, x2, #1
	cbnz x2, 0b
1:	ret

/* ============================================================================
 * parse_varint(x0=ptr, x1=end) -> x0=value, x1=newptr
 * ========================================================================== */
parse_varint:
	cmp  x0, x1
	b.hs .pv_fail
	mov  x3, x0                 /* newptr */
	ldrb w2, [x3]
	add  x3, x3, #1
	cmp  w2, #0xfd
	b.hs .pv_wide
	mov  x0, x2                 /* value = prefix byte */
	mov  x1, x3
	ret
.pv_wide:
	mov  x4, #2
	cmp  w2, #0xfd
	b.eq .pv_load            /* 0xfd: 2-byte value */
	mov  x4, #4
	cmp  w2, #0xfe
	b.eq .pv_load            /* 0xfe: 4-byte value */
	mov  x4, #8              /* 0xff: 8-byte value */
.pv_load:
	add  x5, x3, x4
	cmp  x5, x1
	b.hi .pv_fail
	mov  x2, #0
	mov  x6, #0                 /* shift */
.pv_b:
	ldrb w7, [x3]
	lsl  x7, x7, x6
	orr  x2, x2, x7
	add  x3, x3, #1
	add  x6, x6, #8
	sub  x4, x4, #1
	cbnz x4, .pv_b
	mov  x0, x2
	mov  x1, x3
	ret
.pv_fail:
	mov  x0, #0
	mov  x1, #-1                /* sentinel cursor -> any downstream bounds
	                               check fails (never dereferenced) */
	ret

/* ============================================================================
 * write_varint(x0=cursor, x1=value, x2=end) -> x0=newcursor (caller bounds)
 * ========================================================================== */
write_varint:
	cmp  x1, #0xfc
	b.ls .wv_1
	mov  x15, #0xffff
	cmp  x1, x15
	b.hi .wv_ge64k
	mov  w3, #0xfd
	strb w3, [x0]
	strh w1, [x0, #1]
	add  x0, x0, #3
	ret
.wv_ge64k:
	lsr  x15, x1, #32
	cbz  x15, .wv_4
	mov  w3, #0xff
	strb w3, [x0]
	str  x1, [x0, #1]
	add  x0, x0, #9
	ret
.wv_4:
	mov  w3, #0xfe
	strb w3, [x0]
	str  w1, [x0, #1]
	add  x0, x0, #5
	ret
.wv_1:
	strb w1, [x0]
	add  x0, x0, #1
	ret

/* ============================================================================
 * script_op_len(x0=pos, x1=end) -> x0 = byte length of one script unit, 0 if
 * malformed / would overrun. Mirrors Core GetScriptOp.
 * ========================================================================== */
	.global script_op_len
	.type script_op_len, %function
script_op_len:
	cmp  x0, x1
	b.hs 3f
	ldrb w2, [x0]
	cmp  w2, #0x4c
	b.lo 1f
	cmp  w2, #0x4c
	b.eq 4f
	cmp  w2, #0x4d
	b.eq 5f
	cmp  w2, #0x4e
	b.eq 6f
	mov  x0, #1                 /* regular opcode: unit length 1 */
	ret
1:	/* direct push: len = 1 + opcode */
	add  x2, x2, #1
	add  x3, x0, x2
	cmp  x3, x1
	b.hi 3f
	mov  x0, x2
	ret
4:	/* PUSHDATA1: len = 2 + n */
	add  x3, x0, #2
	cmp  x3, x1
	b.hi 3f
	ldrb w4, [x0, #1]
	add  x2, x4, #2
	add  x3, x0, x2
	cmp  x3, x1
	b.hi 3f
	mov  x0, x2
	ret
5:	/* PUSHDATA2: len = 3 + n */
	add  x3, x0, #3
	cmp  x3, x1
	b.hi 3f
	ldrh w4, [x0, #1]
	add  x2, x4, #3
	add  x3, x0, x2
	cmp  x3, x1
	b.hi 3f
	mov  x0, x2
	ret
6:	/* PUSHDATA4: len = 5 + n */
	add  x3, x0, #5
	cmp  x3, x1
	b.hi 3f
	ldr  w4, [x0, #1]
	add  x2, x4, #5
	add  x3, x0, x2
	cmp  x3, x1
	b.hi 3f
	mov  x0, x2
	ret
3:	mov  x0, #0
	ret

/* ============================================================================
 * script_find_and_delete(x0=dst,x1=dstcap,x2=src,x3=srclen,x4=needle,
 *                        x5=needlelen) -> x0=outlen or 0xFFFFFFFFFFFFFFFF
 * ========================================================================== */
	.global script_find_and_delete
	.type script_find_and_delete, %function
script_find_and_delete:
		/* locals BELOW saved regs in a separate 0x40 frame (was overlapping the x19/x20
		 * saved slots at +48/+56 with out@48/outend@56, corrupting the caller's x19/x20 on
		 * return: x20 got restored to outend == cms_scstrip0+dstcap == cms_scstrip1). */
		stp  x29, x30, [sp, #-16]!
		mov  x29, sp
		stp  x19, x20, [sp, #-16]!
		stp  x21, x22, [sp, #-16]!
		stp  x23, x24, [sp, #-16]!
		stp  x25, x26, [sp, #-16]!
		sub  sp, sp, #0x40
		mov  x26, sp                 /* locals base (saved regs live above at +0x40..) */
	/* store args: dst@0 dstcap@8 needle@16 needlelen@24 end@32 pc@40 out@48 outend@56 */
	str  x0, [x26, #0]
	str  x1, [x26, #8]
	str  x4, [x26, #16]
	str  x5, [x26, #24]
	add  x3, x2, x3
	str  x3, [x26, #32]          /* end */
	str  x2, [x26, #40]          /* pc */
	str  x0, [x26, #48]          /* out */
	add  x0, x0, x1
	str  x0, [x26, #56]          /* outend */
	/* off+64 for scfbuf addr not needed here */

.fad_mc:
	ldr  x8, [x26, #24]          /* needlelen */
	cbz  x8, .fad_decode
	ldr  x9, [x26, #32]          /* end */
	ldr  x10, [x26, #40]         /* pc */
	sub  x9, x9, x10
	cmp  x9, x8
	b.lo .fad_decode
	ldr  x0, [x26, #40]          /* pc */
	ldr  x1, [x26, #16]          /* needle */
	mov  x2, x8
0:	cbz  x2, .fad_matched
	ldrb w3, [x0]
	ldrb w4, [x1]
	cmp  w3, w4
	b.ne .fad_decode
	add  x0, x0, #1
	add  x1, x1, #1
	sub  x2, x2, #1
	b    0b
.fad_matched:
	ldr  x10, [x26, #40]
	ldr  x8, [x26, #24]
	add  x10, x10, x8            /* pc += needlelen */
	str  x10, [x26, #40]
	b    .fad_mc
.fad_decode:
	ldr  x10, [x26, #40]
	ldr  x9, [x26, #32]
	cmp  x10, x9
	b.eq .fad_done
	mov  x0, x10
	mov  x1, x9
	bl   script_op_len
	cbnz x0, .fad_copy_unit
	/* malformed trailing: copy remainder verbatim */
	ldr  x10, [x26, #40]
	ldr  x9, [x26, #32]
	sub  x2, x9, x10
	ldr  x8, [x26, #48]          /* out */
	add  x8, x8, x2
	ldr  x9, [x26, #56]          /* outend */
	cmp  x8, x9
	b.hi .fad_overflow
	mov  x0, x8
	sub  x0, x0, x2               /* out (start) */
	ldr  x1, [x26, #40]           /* pc */
	bl   copy_bytes               /* x0=dst+n */
	str  x0, [x26, #48]
	b    .fad_done
.fad_copy_unit:
	mov  x2, x0                   /* unit len */
	ldr  x8, [x26, #48]
	add  x8, x8, x2
	ldr  x9, [x26, #56]
	cmp  x8, x9
	b.hi .fad_overflow
	ldr  x0, [x26, #48]
	ldr  x1, [x26, #40]
	bl   copy_bytes
	str  x0, [x26, #48]
	str  x1, [x26, #40]
	b    .fad_mc                  /* re-check needle at new unit boundary */
.fad_done:
	/* result = out - dst */
	ldr  x0, [x26, #48]
	ldr  x1, [x26, #0]
	sub  x0, x0, x1
	b    .fad_ret
.fad_overflow:
	mov  x0, #-1
.fad_ret:
	add  sp, sp, #0x40
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret

/* ============================================================================
 * script_push_encode(x0=dst,x1=dstcap,x2=data,x3=datalen) -> x0=outlen/-1
 * ========================================================================== */
	.global script_push_encode
	.type script_push_encode, %function
script_push_encode:
	cmp  x3, #0x4c
	b.hs .spe_pd1
	add  x4, x3, #1
	cmp  x4, x1
	b.hi .spe_ov
	strb w3, [x0]
	add  x4, x0, #1
	b    .spe_copy
.spe_pd1:
	cmp  x3, #0xff
	b.hi .spe_pd2
	add  x4, x3, #2
	cmp  x4, x1
	b.hi .spe_ov
	mov  w5, #0x4c
	strb w5, [x0]
	strb w3, [x0, #1]
	add  x4, x0, #2
	b    .spe_copy
.spe_pd2:
	mov  x15, #0xffff
	cmp  x3, x15
	b.hi .spe_pd4
	add  x4, x3, #3
	cmp  x4, x1
	b.hi .spe_ov
	mov  w5, #0x4d
	strb w5, [x0]
	strh w3, [x0, #1]
	add  x4, x0, #3
	b    .spe_copy
.spe_pd4:
	add  x4, x3, #5
	cmp  x4, x1
	b.hi .spe_ov
	mov  w5, #0x4e
	strb w5, [x0]
	str  w3, [x0, #1]
	add  x4, x0, #5
.spe_copy:
	/* copy datalen bytes from x2 to x4 */
	mov  x5, x3
0:	cbz  x5, 1f
	ldrb w6, [x2]
	strb w6, [x4]
	add  x2, x2, #1
	add  x4, x4, #1
	sub  x5, x5, #1
	b    0b
1:	/* outlen = (x4 + datalen?) - x0 ; x4 already advanced by datalen */
	sub  x0, x4, x0
	ret
.spe_ov:
	mov  x0, #-1
	ret

/* ============================================================================
 * legacy_locate_nout(x0=tx, x1=txend, x2=nIn) -> x0=nOut, x1=ok(0/1)
 * ========================================================================== */
legacy_locate_nout:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	mov  x19, x0                 /* tx */
	mov  x20, x1                 /* txend */
	mov  x21, x2                 /* nIn */
	add  x0, x19, #4
	mov  x1, x20
	bl   parse_varint
	cbz  x0, .lln_fail
	cmp  x21, x0
	b.hs .lln_fail
	mov  x22, x0                 /* n_in */
	mov  x24, x1                 /* cursor */
	mov  x23, #0                 /* i */
.lln_loop:
	cmp  x23, x22
	b.hs .lln_outvarint
	add  x24, x24, #36
	cmp  x24, x20
	b.hi .lln_fail
	mov  x0, x24
	mov  x1, x20
	bl   parse_varint
	mov  x24, x1                 /* advanced past varint */
	add  x24, x24, x0            /* += scriptSig len */
	cmp  x24, x20
	b.hi .lln_fail
	add  x24, x24, #4            /* sequence */
	cmp  x24, x20
	b.hi .lln_fail
	add  x23, x23, #1
	b    .lln_loop
.lln_outvarint:
	cmp  x24, x20
	b.hs .lln_fail
	ldrb w8, [x24]
	cmp  w8, #0xfd
	b.lo .lln_ovcall
	cmp  w8, #0xfe
	b.eq .lln_ovw4
	cmp  w8, #0xff
	b.eq .lln_ovw8
	add  x8, x24, #3
	b    .lln_ovcheck
.lln_ovw4:
	add  x8, x24, #5
	b    .lln_ovcheck
.lln_ovw8:
	add  x8, x24, #9
.lln_ovcheck:
	cmp  x8, x20
	b.hi .lln_fail
.lln_ovcall:
	mov  x0, x24
	mov  x1, x20
	bl   parse_varint            /* x0 = n_out, x1 = cursor past varint */
	cmn  x1, #1                  /* parse_varint failure sentinel */
	b.eq .lln_fail
	mov  x24, x1
	mov  x25, x0                 /* n_out */
	mov  x23, #0                 /* j */
.lln_outloop:
	cmp  x23, x25
	b.hs .lln_lock
	add  x24, x24, #8            /* output value */
	cmp  x24, x20
	b.hi .lln_fail
	mov  x0, x24
	mov  x1, x20
	bl   parse_varint            /* spk_len */
	mov  x24, x1
	add  x24, x24, x0            /* += scriptPubKey len */
	cmp  x24, x20
	b.hi .lln_fail
	add  x23, x23, #1
	b    .lln_outloop
.lln_lock:
	add  x24, x24, #4            /* locktime */
	cmp  x24, x20
	b.hi .lln_fail
	/* tx fully well-formed */
	mov  x0, x25                 /* n_out */
	mov  x1, #1                  /* ok */
	b    .lln_ret
.lln_fail:
	mov  x0, #0
	mov  x1, #0
.lln_ret:
	ldp  x19, x20, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x29, x30, [sp], #16
	ret

	/* ============================================================================
	 * legacy_sighash(x0=out32, x1=tx, x2=txlen, x3=nIn, x4=scriptCode, x5=scLen,
	 *                w6=hashtype, x7=preimg, [sp]=cap)  -> w0 1/0
	 *
	 * AAPCS64 arg note: this is a 9-arg function; out..preimg use x0-x7 and
	 * `cap` is the 9th argument at [sp] on entry (sp+0 in the CALLER's frame).
	 * ========================================================================== */
		.section .rodata
		.p2align 4
	cs_needle:
		.byte 0xab
		.text
		.balign 4
		.global legacy_sighash
		.type legacy_sighash, %function
	legacy_sighash:
		stp  x29, x30, [sp, #-16]!
		mov  x29, sp
		stp  x19, x20, [sp, #-16]!
		stp  x21, x22, [sp, #-16]!
		stp  x23, x24, [sp, #-16]!
		stp  x25, x26, [sp, #-16]!
		stp  x27, x28, [sp, #-16]!
		sub  sp, sp, #224
		mov  x28, sp                  /* locals base (callee-saved, stable) */
		/* ---- arg capture ---- */
		str  x0, [x28, #0]            /* out */
		str  x1, [x28, #8]            /* tx */
		str  x2, [x28, #16]           /* txlen */
		str  x3, [x28, #24]           /* nIn */
		str  x4, [x28, #32]           /* scriptCode */
		str  x5, [x28, #40]           /* scLen */
		mov  x9, x6
		str  x9, [x28, #48]           /* hashtype (low 32 used) */
		str  x7, [x28, #56]           /* preimg */
		/* cap was 9th arg at CALLER's [sp]; after 6 stp (96) + sub 224 = 320 */
		ldr  x9, [sp, #320]
		str  x9, [x28, #64]           /* cap */
		/* ---- hashtype flags ---- */
		ldr  x9, [x28, #48]
		and  w10, w9, #0x1f
		cmp  w10, #3
		cset x11, eq
		str  x11, [x28, #72]          /* fSingle */
		cmp  w10, #2
		cset x11, eq
		str  x11, [x28, #80]          /* fNone */
		and  w10, w9, #0x80
		cmp  w10, #0
		cset x11, ne
		str  x11, [x28, #88]          /* fACP */
		/* ---- txend, txlen>=10 ---- */
		ldr  x9, [x28, #8]
		ldr  x10, [x28, #16]
		add  x11, x9, x10
		str  x11, [x28, #96]          /* txend */
		cmp  x10, #10
		b.lo .ls_fail
		/* ---- n_in / txcur ---- */
		add  x0, x9, #4
		ldr  x1, [x28, #96]
		bl   parse_varint
		cbz  x0, .ls_fail
		str  x0, [x28, #104]          /* n_in */
		ldr  x9, [x28, #24]           /* nIn */
		cmp  x9, x0
		b.hs .ls_fail
		str  x1, [x28, #112]          /* txcur */
		/* ---- SIGHASH_SINGLE out-of-range pre-check ---- */
		ldr  x9, [x28, #72]           /* fSingle */
		cbz  x9, .ls_no_single_check
		ldr  x0, [x28, #8]            /* tx */
		ldr  x1, [x28, #96]           /* txend */
		ldr  x2, [x28, #24]           /* nIn */
		bl   legacy_locate_nout
		cbz  x1, .ls_fail             /* x1 = ok (my ABI) */
		ldr  x9, [x28, #24]           /* nIn */
		cmp  x9, x0                   /* nIn vs nOut */
		b.lo .ls_no_single_check      /* nIn < nOut: normal SINGLE */
		/* quirk: out = uint256(1) */
		ldr  x9, [x28, #0]
		mov  w10, #1
		strb w10, [x9]
		add  x10, x9, #1
		mov  x11, #31
	0:	cbz  x11, 1f
		strb wzr, [x10]
		add  x10, x10, #1
		sub  x11, x11, #1
		b    0b
	1:	mov  w0, #1
		b    .ls_done
	.ls_no_single_check:
		/* ---- codeseparator-strip scriptCode into scratch buffer ---- */
		TLS_ADDR x0, ls_scfbuf     /* per-thread (parallel verify: no sharing) */
		str  x0, [x28, #208]          /* scfbuf_addr */
		mov  x1, #20000
		ldr  x2, [x28, #32]           /* scriptCode */
		ldr  x3, [x28, #40]           /* scLen */
		LAddr x4, cs_needle
		mov  x5, #1
		bl   script_find_and_delete
		cmn  x0, #1
		b.eq .ls_fail
		str  x0, [x28, #136]          /* scF_len */
		/* ---- preimg cursor init ---- */
		ldr  x9, [x28, #56]           /* preimg */
		str  x9, [x28, #120]          /* pcur */
		ldr  x10, [x28, #64]          /* cap */
		add  x11, x9, x10
		str  x11, [x28, #128]         /* pend */
		/* ---- version(4) raw ---- */
		ldr  x9, [x28, #120]
		add  x9, x9, #4
			CMd x9, #128
		b.hi .ls_fail
		ldr  x10, [x28, #8]
		ldr  w11, [x10]               /* LE version */
		ldr  x12, [x28, #120]
		str  w11, [x12]
		add  x9, x12, #4
		str  x9, [x28, #120]
		/* ---- nInputs varint: fACP ? 1 : n_in ---- */
		ldr  x9, [x28, #104]
		ldr  x10, [x28, #88]
		cbz  x10, .ls_ni_have
		mov  x9, #1
	.ls_ni_have:
		ldr  x0, [x28, #120]
		mov  x1, x9
		ldr  x2, [x28, #128]
		bl   write_varint
		str  x0, [x28, #120]
			CMd x0, #128
		b.hi .ls_fail
		/* ---- input loop i=0..n_in-1 ---- */
		str  xzr, [x28, #152]          /* i=0 */
	.ls_in_loop:
		ldr  x9, [x28, #152]
		ldr  x10, [x28, #104]          /* n_in */
		cmp  x9, x10
		b.hs .ls_in_done
		ldr  x9, [x28, #112]
		str  x9, [x28, #160]           /* prevout_ptr */
		add  x9, x9, #36
		str  x9, [x28, #112]
			CMd x9, #96
		b.hi .ls_fail
		ldr  x0, [x28, #112]
		ldr  x1, [x28, #96]
		bl   parse_varint
		str  x1, [x28, #112]
		add  x1, x1, x0
			CMd x1, #96
		b.hi .ls_fail
		str  x1, [x28, #112]
		str  x1, [x28, #168]           /* seq_ptr */
		add  x1, x1, #4
		str  x1, [x28, #112]
			CMd x1, #96
		b.hi .ls_fail
		ldr  x9, [x28, #152]           /* i */
		ldr  x10, [x28, #24]           /* nIn */
		cmp  x9, x10
		b.ne .ls_in_other
		/* --- signed input: prevout36 + scF varint+bytes + seq4 --- */
		ldr  x9, [x28, #120]
		add  x9, x9, #36
			CMd x9, #128
		b.hi .ls_fail
		ldr  x0, [x28, #120]
		ldr  x1, [x28, #160]
		mov  x2, #36
		bl   copy_bytes
		str  x0, [x28, #120]
		ldr  x1, [x28, #136]           /* scF_len */
		ldr  x0, [x28, #120]
		ldr  x2, [x28, #128]
		bl   write_varint
		str  x0, [x28, #120]
			CMd x0, #128
		b.hi .ls_fail
		ldr  x10, [x28, #136]
		ldr  x9, [x28, #120]
		add  x9, x9, x10
			CMd x9, #128
		b.hi .ls_fail
		ldr  x0, [x28, #120]
		ldr  x1, [x28, #208]           /* scfbuf_addr */
		mov  x2, x10
		bl   copy_bytes
		str  x0, [x28, #120]
		ldr  x9, [x28, #120]
		add  x9, x9, #4
			CMd x9, #128
		b.hi .ls_fail
		ldr  x0, [x28, #120]
		ldr  x1, [x28, #168]           /* seq_ptr */
		mov  x2, #4
		bl   copy_bytes
		str  x0, [x28, #120]
		b    .ls_in_next
	.ls_in_other:
		ldr  x9, [x28, #88]            /* fACP */
		cbnz x9, .ls_in_next           /* fACP: other inputs not emitted */
		ldr  x9, [x28, #120]
		add  x9, x9, #36
			CMd x9, #128
		b.hi .ls_fail
		ldr  x0, [x28, #120]
		ldr  x1, [x28, #160]
		mov  x2, #36
		bl   copy_bytes
		str  x0, [x28, #120]
		ldr  x9, [x28, #120]
		add  x9, x9, #1
			CMd x9, #128
		b.hi .ls_fail
		ldr  x10, [x28, #120]
		strb wzr, [x10]
		add  x9, x10, #1
		str  x9, [x28, #120]
		add  x9, x9, #4
			CMd x9, #128
		b.hi .ls_fail
		ldr  x9, [x28, #72]            /* fSingle */
		ldr  x10, [x28, #80]           /* fNone */
		orr  x9, x9, x10
		cbz  x9, .ls_other_realseq
		ldr  x10, [x28, #120]
		str  wzr, [x10]
		add  x9, x10, #4
		str  x9, [x28, #120]
		b    .ls_in_next
	.ls_other_realseq:
		ldr  x0, [x28, #120]
		ldr  x1, [x28, #168]
		mov  x2, #4
		bl   copy_bytes
		str  x0, [x28, #120]
	.ls_in_next:
		ldr  x9, [x28, #152]
		add  x9, x9, #1
		str  x9, [x28, #152]
		b    .ls_in_loop
	.ls_in_done:
		/* ---- n_out (raw side) ---- */
		ldr  x0, [x28, #112]
		ldr  x1, [x28, #96]
		bl   parse_varint
		cmn  x1, #1                 /* parse_varint failure -> sentinel -1 */
		b.eq .ls_fail
		str  x1, [x28, #112]
		str  x0, [x28, #144]           /* n_out */
		/* ---- nOutputs varint to emit ---- */
		ldr  x9, [x28, #80]            /* fNone */
		cbnz x9, .ls_nout_none
		ldr  x9, [x28, #72]            /* fSingle */
		cbnz x9, .ls_nout_single
		ldr  x9, [x28, #144]
		b    .ls_nout_have
	.ls_nout_none:
		mov  x9, #0
		b    .ls_nout_have
	.ls_nout_single:
		ldr  x9, [x28, #24]            /* nIn */
		add  x9, x9, #1
	.ls_nout_have:
		ldr  x0, [x28, #120]
		mov  x1, x9
		ldr  x2, [x28, #128]
		bl   write_varint
		str  x0, [x28, #120]
			CMd x0, #128
		b.hi .ls_fail
		/* ---- output loop j=0..n_out-1 ---- */
		str  xzr, [x28, #176]          /* j=0 */
	.ls_out_loop:
		ldr  x9, [x28, #176]
		ldr  x10, [x28, #144]          /* n_out */
		cmp  x9, x10
		b.hs .ls_out_done
		ldr  x9, [x28, #112]
		str  x9, [x28, #184]           /* val_ptr */
		add  x9, x9, #8
		str  x9, [x28, #112]
			CMd x9, #96
		b.hi .ls_fail
		ldr  x0, [x28, #112]
		ldr  x1, [x28, #96]
		bl   parse_varint
		str  x1, [x28, #112]
		str  x0, [x28, #200]           /* spk_len */
		str  x1, [x28, #192]           /* spk_ptr */
		add  x1, x1, x0
			CMd x1, #96
		b.hi .ls_fail
		str  x1, [x28, #112]
		ldr  x9, [x28, #80]            /* fNone */
		cbnz x9, .ls_out_next
		ldr  x9, [x28, #72]            /* fSingle */
		cbz  x9, .ls_out_real
		ldr  x9, [x28, #176]           /* j */
		ldr  x10, [x28, #24]           /* nIn */
		cmp  x9, x10
		b.hs .ls_out_maybe_real
		ldr  x9, [x28, #120]
		add  x9, x9, #9
			CMd x9, #128
		b.hi .ls_fail
		ldr  x10, [x28, #120]
		mov  x11, #-1
		str  x11, [x10]
		strb wzr, [x10, #8]
		add  x9, x10, #9
		str  x9, [x28, #120]
		b    .ls_out_next
	.ls_out_maybe_real:
		ldr  x9, [x28, #176]
		ldr  x10, [x28, #24]
		cmp  x9, x10
		b.ne .ls_out_next
	.ls_out_real:
		ldr  x9, [x28, #120]
		add  x9, x9, #8
			CMd x9, #128
		b.hi .ls_fail
		ldr  x0, [x28, #120]
		ldr  x1, [x28, #184]           /* val_ptr */
		mov  x2, #8
		bl   copy_bytes
		str  x0, [x28, #120]
		ldr  x1, [x28, #200]           /* spk_len */
		ldr  x0, [x28, #120]
		ldr  x2, [x28, #128]
		bl   write_varint
		str  x0, [x28, #120]
			CMd x0, #128
		b.hi .ls_fail
		ldr  x10, [x28, #200]
		ldr  x9, [x28, #120]
		add  x9, x9, x10
			CMd x9, #128
		b.hi .ls_fail
		ldr  x0, [x28, #120]
		ldr  x1, [x28, #192]           /* spk_ptr */
		mov  x2, x10
		bl   copy_bytes
		str  x0, [x28, #120]
	.ls_out_next:
		ldr  x9, [x28, #176]
		add  x9, x9, #1
		str  x9, [x28, #176]
		b    .ls_out_loop
	.ls_out_done:
		/* ---- locktime(4) raw ---- */
		ldr  x9, [x28, #112]
		add  x9, x9, #4
			CMd x9, #96
		b.hi .ls_fail
		ldr  x9, [x28, #120]
		add  x9, x9, #4
			CMd x9, #128
		b.hi .ls_fail
		ldr  x0, [x28, #120]
		ldr  x1, [x28, #112]
		mov  x2, #4
		bl   copy_bytes
		str  x0, [x28, #120]
		/* ---- hashtype(4) raw LE ---- */
		ldr  x9, [x28, #120]
		add  x9, x9, #4
			CMd x9, #128
		b.hi .ls_fail
		ldr  w10, [x28, #48]
		ldr  x11, [x28, #120]
		str  w10, [x11]
		add  x9, x11, #4
		str  x9, [x28, #120]
		/* ---- sha256d(out32, preimg, pcur-preimg) ---- */
		ldr  x9, [x28, #120]
		ldr  x10, [x28, #56]           /* preimg */
		sub  x2, x9, x10
		ldr  x0, [x28, #0]             /* out */
		mov  x1, x10
		bl   sha256d
		mov  w0, #1
		b    .ls_done
	.ls_fail:
		mov  w0, #0
	.ls_done:
		add  sp, sp, #224
		ldp  x27, x28, [sp], #16
		ldp  x25, x26, [sp], #16
		ldp  x23, x24, [sp], #16
		ldp  x21, x22, [sp], #16
		ldp  x19, x20, [sp], #16
		ldp  x29, x30, [sp], #16
		ret
	.size legacy_sighash, .-legacy_sighash

	.section .note.GNU-stack,"",%progbits
