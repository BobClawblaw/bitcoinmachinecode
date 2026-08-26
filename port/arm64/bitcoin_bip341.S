/* ============================================================================
 * bitcoin_bip341.S -- AArch64 (ARMv8-A) port of asm/bitcoin_bip341.asm
 *
 * The BIP341/342 TapSighash builder (twins of bitcoin_taproot_sighash.c's
 * ts_agg_hashes / taproot_sighash). Byte-for-byte, preserving the two
 * consensus fixes: hash_type validity (reject unless <=0x03 or 0x81..0x83)
 * and SIGHASH_SINGLE with n_in>=nout FAILS (BIP341, not the BIP143 zero hash).
 *
 *   long ts_agg_hashes_asm   (tapctx_t* c, txview_t* t, u8 h_prev[32],
 *                             u8 h_amt[32], u8 h_spk[32], u8 h_seq[32],
 *                             const u8** spk_at_nin, u64* spk_at_nin_len)
 *                             -> 1 / 0      (8 args: x0..x7, ALL registers)
 *   long taproot_sighash_asm (u8 out32[32], tapctx_t* c, u8* pre, long cap)
 *                             -> preimage length (>0) or 0
 *
 * AArch64 TLS-IE lazy scratch (.tbss): b341_off (u32* tx_parse table),
 * b341_seq (u8* seq gather), b341_abuf (u8* annex staging).
 *
 * Structs (offsetof-pinned):
 *   tapctx_t: tx@0 txlen@8 n_in@16 hash_type@24 prevouts@32 amounts@40
 *     spks@48 num_inputs@56 ext_flag@64 tapleaf@72 codesep_pos@80 annex@88
 *     annexlen@96, size 104.
 *   txview_t: tx@0 txlen@8 end@16 version@24 locktime@28 nin@32 nout@40
 *     in_off@48 out_off@56, size 64.
 * ========================================================================== */

	.text
	.global ts_agg_hashes_asm
	.type ts_agg_hashes_asm, %function
	.global taproot_sighash_asm
	.type taproot_sighash_asm, %function

	.extern sha256_full
	.extern tagged_hash256
	.extern ts_tx_parse_export
	.extern ts_tx_seq_export
	.extern malloc
	.extern abort

	.section .tbss,"awT",@nobits
	.align 3
b341_off:  .space 8
b341_seq:  .space 8
b341_abuf: .space 8

	.section .rodata
tag_tapsighash: .asciz "TapSighash"

	.text

/* ---- tapctx / txview offsets ---- */
	.equ C_TX,0
	.equ C_TXLEN,8
	.equ C_NIN,16
	.equ C_HASHTYPE,24
	.equ C_PREVOUTS,32
	.equ C_AMOUNTS,40
	.equ C_SPKS,48
	.equ C_NUMIN,56
	.equ C_EXTFLAG,64
	.equ C_TAPLEAF,72
	.equ C_CODESEP,80
	.equ C_ANNEX,88
	.equ C_ANNEXLEN,96
	.equ V_TX,0
	.equ V_TXLEN,8
	.equ V_END,16
	.equ V_VERSION,24
	.equ V_LOCKTIME,28
	.equ V_NIN,32
	.equ V_NOUT,40
	.equ V_INOFF,48
	.equ V_OUTOFF,56
	.equ TS_SPK_RUN_CAP, 0x400000            /* 4<<20 */
	.equ TS_SEQ_CAP, 2400000                /* 4*600000 = 0x249F00 */
	.equ TS_OFF_BYTES, 2400000
	.equ TS_ANNEX_CAP, 0x400009             /* (4<<20)+9 */

/* ---- load symbol address (adrp + :lo12:) ---- */
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

/* ---- lazy TLS scratch alloc (AArch64 TLS-Initial-Exec) ---- */
	.macro TLS_LAZY rd, sym, lo, hi
	adrp x9, :gottprel:\sym
	ldr  x9, [x9, #:gottprel_lo12:\sym]
	mrs  x10, tpidr_el0
	add  x9, x9, x10                /* x9 = &sym */
	ldr  \rd, [x9]                  /* \rd = *&sym (0 or buf) */
	cbnz \rd, 98f
	stp  x9, x30, [sp, #-16]!       /* save &sym and lr across libc call */
	mov  w0, #\lo
	movk w0, #\hi, lsl #16
	bl   malloc
	cbz  x0, 97f
	ldr  x9, [sp]                   /* &sym */
	str  x0, [x9]
	ldp  x9, x30, [sp], #16
	mov  \rd, x0
	b    98f
97:
	bl   abort
98:
	.endm

/* ---- compactsize size of x9 -> size-bytes in x10 (clobbers x11) ---- */
	.macro CSSIZE_R
	mov  x10, #1
	cmp  x9, #0xfd
	b.lo 99f
	mov  x10, #3
	mov  x11, #0xffff
	cmp  x9, x11
	b.ls 99f
	mov  x11, #0xffff
	movk x11, #0xffff, lsl #16        /* 0xffffffff */
	cmp  x9, x11
	b.ls .Pcs_d
	mov  x10, #9
.Pcs_d:
99:
	.endm

/* ---- write x9 as minimal compactsize at [\rd]; advances \rd. Clobbers x10. ---- */
	.macro PUTCS_AT rd
	cmp  x9, #0xfd
	b.hs .Ppb\@_big
	strb w9, [\rd]
	add  \rd, \rd, #1
	b    95f
.Ppb\@_big:
	mov  x10, #0xffff
	cmp  x9, x10
	b.hi .Ppb\@_b4
	mov  w10, #0xfd
	strb w10, [\rd]
	strh w9, [\rd, #1]
	add  \rd, \rd, #3
	b    95f
.Ppb\@_b4:
	mov  x10, #0xffff
	movk x10, #0xffff, lsl #16        /* 0xffffffff */
	cmp  x9, x10
	b.hi .Ppb\@_b8
	mov  w10, #0xfe
	strb w10, [\rd]
	str  w9, [\rd, #1]
	add  \rd, \rd, #5
	b    95f
.Ppb\@_b8:
	mov  w10, #0xff
	strb w10, [\rd]
	str  x9, [\rd, #1]
	add  \rd, \rd, #9
95:
	.endm

/* ---- canonical compactsize read; cursor=x22, ceiling=x23; value in x9 ---- */
	.macro RDCS_RUN fail
	cmp  x22, x23
	b.hs \fail
	ldrb w9, [x22]
	add  x22, x22, #1
	cmp  w9, #0xfd
	b.lo 96f
	b.eq .Rr2\@
	cmp  w9, #0xfe
	b.eq .Rr4\@
	sub  x10, x23, x22
	cmp  x10, #8
	b.lo \fail
	ldr  x9, [x22]
	add  x22, x22, #8
	mov  x10, #0
	movk x10, #0x1, lsl #32         /* 0x100000000 */
	cmp  x9, x10
	b.lo \fail
	b    96f
.Rr4\@:
	sub  x10, x23, x22
	cmp  x10, #4
	b.lo \fail
	ldr  w9, [x22]
	add  x22, x22, #4
	mov  w10, #0x10000
	cmp  w9, w10
	b.lo \fail
	b    96f
.Rr2\@:
	sub  x10, x23, x22
	cmp  x10, #2
	b.lo \fail
	ldrh w9, [x22]
	add  x22, x22, #2
	mov  w10, #0xfd
	cmp  w9, w10
	b.lo \fail
96:
	.endm

/* ---- copy fixed 32 bytes [x11] -> [x9] ---- */
	.macro CP32
	ldp  x12, x13, [x11]
	stp  x12, x13, [x9]
	ldp  x12, x13, [x11, #16]
	stp  x12, x13, [x9, #16]
	add  x9, x9, #32
	.endm

/* ============================================================================
 * ts_agg_hashes_asm(c=x0, t=x1, h_prev=x2, h_amt=x3, h_spk=x4, h_seq=x5,
 *                   spk_at_nin=x6, spk_at_nin_len=x7) -> 1/0
 *   Regs: x19=c x20=t x21=n x22=cursor x23=ceiling x24=seqbase
 *   Locals: h_* @sp+0..0x28, seqbase@0x30, spks_base@0x38, i@0x40, k@0x48.
 * ========================================================================== */
ts_agg_hashes_asm:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #0x60
	str  x2, [sp, #0x00]             /* h_prev */
	str  x3, [sp, #0x08]             /* h_amt */
	str  x4, [sp, #0x10]             /* h_spk */
	str  x5, [sp, #0x18]             /* h_seq */
	str  x6, [sp, #0x20]             /* spk_at_nin */
	str  x7, [sp, #0x28]             /* spk_at_nin_len */
	mov  x19, x0                     /* c */
	mov  x20, x1                     /* t */
	ldr  x21, [x19, #C_NUMIN]        /* n */
	cbz  x21, .Sh_no
	ldr  x9, [x20, #V_NIN]
	cmp  x21, x9
	b.ne .Sh_no
	/* sha_prevouts(h_prev, c->prevouts, n*36) */
	ldr  x0, [sp, #0x00]
	ldr  x1, [x19, #C_PREVOUTS]
	mov  x9, #36
	mul  x2, x9, x21
	bl   sha256_full
	/* sha_amounts(h_amt, c->amounts, n*8) */
	ldr  x0, [sp, #0x08]
	ldr  x1, [x19, #C_AMOUNTS]
	lsl  x2, x21, #3
	bl   sha256_full
	/* ---- scriptpubkeys run walk (own ceiling; no length param) ---- */
	ldr  x22, [x19, #C_SPKS]         /* cursor */
	str  x22, [sp, #0x38]            /* spks_base */
	mov  w9, #0x0000
	movk w9, #0x0040, lsl #16        /* 0x400000 = TS_SPK_RUN_CAP */
	add  x23, x22, x9                /* ceiling = cursor + cap */
	mov  x28, #0x00000000
	str  xzr, [sp, #0x40]            /* i = 0 */
.Spk_loop:
	ldr  x9, [sp, #0x40]
	cmp  x9, x21
	b.hs .Spk_done
	RDCS_RUN .Sh_no                  /* sl in x9 */
	sub  x10, x23, x22               /* avail */
	cmp  x10, x9
	b.lo .Sh_no
	ldr  x10, [sp, #0x40]
	ldr  x11, [x19, #C_NIN]          /* c->n_in */
	cmp  x10, x11
	b.ne .Spk_next
	ldr  x11, [sp, #0x20]
	str  x22, [x11]                  /* *spk_at_nin = cursor */
	ldr  x11, [sp, #0x28]
	str  x9, [x11]                   /* *spk_at_nin_len = sl */
.Spk_next:
	add  x22, x22, x9
	ldr  x9, [sp, #0x40]
	add  x9, x9, #1
	str  x9, [sp, #0x40]
	b    .Spk_loop
.Spk_done:
	/* sha_scriptpubkeys(h_spk, spks_base, cursor-spks_base) */
	ldr  x0, [sp, #0x10]
	ldr  x1, [sp, #0x38]
	sub  x2, x22, x1
	bl   sha256_full
	/* ---- sequences gather (4 bytes/input) ---- */
	lsl  x9, x21, #2
	mov  w10, #0x9F00
	movk w10, #0x24, lsl #16          /* 2400000 = TS_SEQ_CAP */
	cmp  x9, x10
	b.hi .Sh_no
	TLS_LAZY x24, b341_seq, 0x9F00, 0x24
	str  x24, [sp, #0x30]            /* seqbase */
	str  xzr, [sp, #0x40]            /* i */
	str  xzr, [sp, #0x48]            /* k */
.Seq_loop:
	ldr  x9, [sp, #0x40]
	cmp  x9, x21
	b.hs .Seq_done
	mov  x0, x20                     /* t */
	mov  x1, x9                      /* i */
	bl   ts_tx_seq_export
	ldr  x10, [sp, #0x30]            /* seqbase */
	ldr  x11, [sp, #0x48]            /* k */
	str  w0, [x10, x11]
	add  x11, x11, #4
	str  x11, [sp, #0x48]
	ldr  x9, [sp, #0x40]
	add  x9, x9, #1
	str  x9, [sp, #0x40]
	b    .Seq_loop
.Seq_done:
	ldr  x0, [sp, #0x18]             /* h_seq */
	ldr  x1, [sp, #0x30]
	ldr  x2, [sp, #0x48]
	bl   sha256_full
	mov  w0, #1
	b    .Sh_ret
.Sh_no:
	mov  w0, #0
.Sh_ret:
	add  sp, sp, #0x60
	ldp  x29, x30, [sp], #16
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size ts_agg_hashes_asm, .-ts_agg_hashes_asm

/* ============================================================================
 * taproot_sighash_asm(out32=x0, c=x1, pre=x2, cap=x3) -> prelen / 0
 *   Regs: x19=c x20=p(write cursor) x21=&t
 *   Frame (sub 0x180): out32@0x00 c@0x08 pre@0x10 cap@0x18 pend@0x20
 *     spk_nin@0x28 spk_nin_len@0x30 ht@0x34 acp@0x38 is_single@0x40
 *     is_none@0x48 annex_p@0x50 h_prev[32]@0x60 h_amt[32]@0x80
 *     h_spk[32]@0xA0 h_seq[32]@0xC0 ho[32]@0xE0 t(80B)@0x100.
 * ========================================================================== */
taproot_sighash_asm:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #0x180
	str  x0, [sp, #0x00]             /* out32 */
	str  x1, [sp, #0x08]             /* c */
	str  x2, [sp, #0x10]             /* pre */
	str  x3, [sp, #0x18]             /* cap */
	mov  x19, x1                     /* c */
	add  x21, sp, #0x100             /* &t */
	mov  x20, x2                     /* p = pre */
	add  x9, x2, x3
	str  x9, [sp, #0x20]             /* pend */
	/* t->tx, t->txlen from c */
	ldr  x9, [x19, #C_TX]
	str  x9, [x21, #V_TX]
	ldr  x9, [x19, #C_TXLEN]
	str  x9, [x21, #V_TXLEN]
	/* tx_parse into this thread's table (C seam) */
	TLS_LAZY x22, b341_off, 0x9F00, 0x24
	mov  x0, x21                     /* t */
	mov  x1, x22                     /* off table (2nd arg of ts_tx_parse_export) */
	bl   ts_tx_parse_export
	cbz  w0, .Tf_fail
	/* n_in bounds */
	ldr  x9, [x19, #C_NIN]
	tbnz x9, #63, .Tf_fail
	ldr  x10, [x21, #V_NIN]
	cmp  x9, x10
	b.ge .Tf_fail
	ldr  x10, [x19, #C_NUMIN]
	cmp  x9, x10
	b.ge .Tf_fail
	/* ---- aggregates ---- */
	str  xzr, [sp, #0x28]            /* spk_nin = NULL */
	str  xzr, [sp, #0x30]
	mov  x0, x19                     /* c */
	mov  x1, x21                     /* t */
	add  x2, sp, #0x60               /* h_prev */
	add  x3, sp, #0x80               /* h_amt */
	add  x4, sp, #0xA0               /* h_spk */
	add  x5, sp, #0xC0               /* h_seq */
	add  x6, sp, #0x28               /* &spk_nin (7th arg) */
	add  x7, sp, #0x30               /* &spk_nin_len (8th arg) */
	bl   ts_agg_hashes_asm
	cbz  w0, .Tf_fail
	ldr  x9, [sp, #0x28]             /* spk_nin */
	cbz  x9, .Tf_fail
	/* ---- hash_type validity ---- */
	ldrb w9, [x19, #C_HASHTYPE]       /* byte field, like the C's movzx */
	str  w9, [sp, #0x58]             /* ht */
	cmp  w9, #0x03
	b.ls .Tht_ok
	cmp  w9, #0x81
	b.lo .Tf_fail
	cmp  w9, #0x83
	b.hi .Tf_fail
.Tht_ok:
	/* eff = ht ? ht : 1 */
	mov  w11, w9
	cbnz w9, .Teff_set
	mov  w11, #1
.Teff_set:
	/* acp = eff & 0x80 */
	and  w12, w11, #0x80
	str  w12, [sp, #0x38]            /* acp */
	/* single = (eff&3)==3 ; none = (eff&3)==2 */
	and  w13, w11, #3
	mov  w14, #0
	cmp  w13, #3
	cset w14, eq
	str  w14, [sp, #0x40]            /* is_single */
	mov  w14, #0
	cmp  w13, #2
	cset w14, eq
	str  w14, [sp, #0x48]            /* is_none */
	/* annex_present = (c->annex != 0) */
	ldr  x10, [x19, #C_ANNEX]
	cmp  x10, #0
	cset w10, ne
	str  w10, [sp, #0x50]            /* annex_present */
	/* ---- epoch 0x00 + hash_type + nVersion + nLockTime ---- */
	ldr  x8, [sp, #0x20]
	cmp  x20, x8
	b.hs .Tf_fail                      /* p >= pend -> fail (need 1) */
	mov  w9, #0
	strb w9, [x20]
	add  x20, x20, #1
	add  x9, x20, #1
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	ldr  w9, [sp, #0x58]
	strb w9, [x20]
	add  x20, x20, #1
	add  x9, x20, #4
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	ldr  w9, [x21, #V_VERSION]
	str  w9, [x20]
	add  x20, x20, #4
	add  x9, x20, #4
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	ldr  w9, [x21, #V_LOCKTIME]
	str  w9, [x20]
	add  x20, x20, #4
	/* ---- the four aggregates (non-ACP) ---- */
	ldr  w9, [sp, #0x38]
	cbnz w9, .Tafter_aggs
	add  x9, x20, #128
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	mov  x9, x20
	add  x11, sp, #0x60
	CP32                              /* h_prev */
	add  x11, sp, #0x80
	CP32                              /* h_amt */
	add  x11, sp, #0xA0
	CP32                              /* h_spk */
	add  x11, sp, #0xC0
	CP32                              /* h_seq -> x9 now p+128 */
	mov  x20, x9
.Tafter_aggs:
	/* ---- sha_outputs (not NONE, not SINGLE), in place ---- */
	ldr  w9, [sp, #0x48]             /* is_none */
	cbnz w9, .Tspend_type
	ldr  w9, [sp, #0x40]             /* is_single */
	cbnz w9, .Tspend_type
	ldr  x9, [x21, #V_OUTOFF]        /* out_off[] */
	ldr  w10, [x21, #V_NOUT]
	ldr  w11, [x9, x10, lsl #2]      /* out_off[nout] */
	ldr  w12, [x9]                   /* out_off[0] */
	sub  x2, x11, x12
	ldr  x0, [x21, #V_TX]
	add  x1, x0, x12
	add  x0, sp, #0xE0               /* ho */
	bl   sha256_full
	add  x9, x20, #32
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	mov  x9, x20
	add  x11, sp, #0xE0
	CP32
	mov  x20, x9
.Tspend_type:
	/* spend_type = ext_flag*2 + annex_present */
	add  x9, x20, #1
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	ldr  w9, [x19, #C_EXTFLAG]
	add  w9, w9, w9
	ldr  w10, [sp, #0x50]
	add  w9, w9, w10
	strb w9, [x20]
	add  x20, x20, #1
	ldr  w9, [sp, #0x38]             /* acp */
	cbz  w9, .Tinput_index
	/* ---- ACP: outpoint || amount || cs+spk || nSequence ---- */
	add  x9, x20, #36
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	ldr  x9, [x21, #V_INOFF]         /* in_off[] */
	ldr  w10, [x19, #C_NIN]
	ldr  w10, [x9, x10, lsl #2]
	ldr  x9, [x21, #V_TX]
	add  x9, x9, x10
	add  x10, x20, #0
	add  x11, x9, #0
	/* copy 36 bytes [x11] -> [x10] */
	ldp  x12, x13, [x11]
	stp  x12, x13, [x10]
	ldp  x12, x13, [x11, #16]
	stp  x12, x13, [x10, #16]
	ldr  w12, [x11, #32]
	str  w12, [x10, #32]
	add  x20, x20, #36
	/* amount = c->amounts[n_in] (8B) */
	add  x9, x20, #8
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	ldr  x9, [x19, #C_AMOUNTS]
	ldr  w10, [x19, #C_NIN]
	ldr  x9, [x9, x10, lsl #3]
	str  x9, [x20]
	add  x20, x20, #8
	/* cs+spk bounded the C's overflow-safe way */
	ldr  x9, [sp, #0x30]             /* sl */
	CSSIZE_R                         /* cs_size in x10 */
	ldr  x11, [sp, #0x18]            /* cap */
	tbnz x11, #63, .Tf_fail
	ldr  x8, [sp, #0x10]
	sub  x12, x20, x8       /* p - pre */
	sub  x11, x11, x12               /* cap - (p-pre) */
	add  x13, x10, x9                /* cs_size + sl */
	cmp  x11, x13
	b.lo .Tf_fail
	PUTCS_AT x20
	ldr  x11, [sp, #0x28]            /* spk_nin */
	ldr  x9,  [sp, #0x30]            /* sl */
	/* copy sl bytes [x11] -> [x20] */
	add  x10, x20, #0
	add  x14, x11, x9                /* end */
.Tcp_spk:
	cmp  x11, x14
	b.hs .Tcp_spk_d
	ldrb w15, [x11], #1
	strb w15, [x10], #1
	b    .Tcp_spk
.Tcp_spk_d:
	add  x20, x20, x9
	/* nSequence */
	add  x9, x20, #4
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	mov  x0, x21                     /* t */
	ldr  x1, [x19, #C_NIN]
	bl   ts_tx_seq_export
	str  w0, [x20]
	add  x20, x20, #4
	b    .Tannex
.Tinput_index:
	add  x9, x20, #4
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	ldr  w9, [x19, #C_NIN]
	str  w9, [x20]
	add  x20, x20, #4
.Tannex:
	ldr  w9, [sp, #0x50]             /* annex_present */
	cbz  w9, .Tsingle
	/* sha256(compactsize(len) || annex), overflow-safe */
	ldr  x9, [x19, #C_ANNEXLEN]
	mov  w10, #0x0000
	movk w10, #0x0040, lsl #16         /* 0x400000 = TS_ANNEX_CAP-9 */
	cmp  x9, x10
	b.hi .Tf_fail
	TLS_LAZY x24, b341_abuf, 0x0009, 0x0040
	mov  x11, x24                      /* abuf base */
	mov  x22, x11                      /* annex write cursor */
	ldr  x9, [x19, #C_ANNEXLEN]
	PUTCS_AT x22                       /* compactsize(annexlen) */
	ldr  x9, [x19, #C_ANNEX]           /* annex src */
	ldr  x13, [x19, #C_ANNEXLEN]
.Tcp_ax:
	cbz  x13, .Tcp_ax_d
	ldrb w14, [x9], #1
	strb w14, [x22], #1
	sub  x13, x13, #1
	b    .Tcp_ax
.Tcp_ax_d:
	add  x0, sp, #0xE0                 /* ho reuse */
	mov  x1, x11
	sub  x2, x22, x11
	bl   sha256_full
	add  x9, x20, #32
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	mov  x9, x20
	add  x11, sp, #0xE0
	CP32
	mov  x20, x9

.Tsingle:
	ldr  w9, [sp, #0x40]             /* is_single */
	cbz  w9, .Text
	/* BIP341: n_in >= nout FAILS */
	ldr  x9, [x19, #C_NIN]
	ldr  x10, [x21, #V_NOUT]
	cmp  x9, x10
	b.ge .Tf_fail
	ldr  x11, [x21, #V_OUTOFF]
	add  x10, x9, #1
	ldr  w12, [x11, x10, lsl #2]     /* out_off[n_in+1] */
	ldr  w13, [x11, x9, lsl #2]      /* out_off[n_in] */
	sub  x2, x12, x13
	ldr  x0, [x21, #V_TX]
	add  x1, x0, x13
	add  x0, sp, #0xE0               /* hs (reuse ho) */
	bl   sha256_full
	add  x9, x20, #32
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	mov  x9, x20
	add  x11, sp, #0xE0
	CP32
	mov  x20, x9
.Text:
	ldr  w9, [x19, #C_EXTFLAG]
	cmp  w9, #1
	b.ne .Tfinish
	ldr  x9, [x19, #C_TAPLEAF]
	cbz  x9, .Tf_fail
	add  x10, x20, #32
	ldr  x8, [sp, #0x20]
	cmp  x10, x8
	b.hi .Tf_fail
	mov  x9, x20
	ldr  x11, [x19, #C_TAPLEAF]
	CP32
	mov  x20, x9
	add  x9, x20, #1
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	mov  w9, #0                       /* key_version */
	strb w9, [x20]
	add  x20, x20, #1
	add  x9, x20, #4
	ldr  x8, [sp, #0x20]
	cmp  x9, x8
	b.hi .Tf_fail
	ldr  w9, [x19, #C_CODESEP]
	str  w9, [x20]
	add  x20, x20, #4
.Tfinish:
	ldr  x8, [sp, #0x10]
	sub  x14, x20, x8       /* prelen */
	/* tagged_hash256(out32, "TapSighash", 10, pre, prelen) */
	ldr  x0, [sp, #0x00]
	LAddr x1, tag_tapsighash
	mov  w2, #10
	ldr  x3, [sp, #0x10]
	mov  x4, x14
	bl   tagged_hash256
	mov  x0, x14
	b    .Tf_ret
.Tf_fail:
	mov  w0, #0
.Tf_ret:
	add  sp, sp, #0x180
	ldp  x29, x30, [sp], #16
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size taproot_sighash_asm, .-taproot_sighash_asm

	.section .note.GNU-stack,"",%progbits
