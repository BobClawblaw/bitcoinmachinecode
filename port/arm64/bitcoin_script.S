/* ============================================================================
 * bitcoin_script.S -- AArch64 port of asm/bitcoin_script.asm: P2PKH spend
 * validation (wallet / tx-validation layer). Same exported symbols:
 *
 *   int der_parse_sig(const u8* sig, u64 slen, u64 r[4], u64 s[4], u32* ht)
 *       Parse a DER ECDSA signature TOLERANT of non-minimal INTEGER
 *       encoding (pre-BIP66 mainnet history): 0x30 len 0x02 rlen rbytes
 *       0x02 slen sbytes [0x01 htype]; r/s may carry ANY number of
 *       redundant leading 0x00 padding bytes, stripped down to <=32
 *       significant bytes (genuinely-too-large values are rejected).
 *       Returns 1 ok / 0 malformed. (x86 BUG FIX 2026-08-19 carried over.)
 *
 *   void be_to_limbs(u64 out[4], const u8* bytes, u64 len)
 *       Big-endian integer bytes (1..32) -> 4 LE limbs, zero-padded left,
 *       limb j = bswap of the j-th 8-byte group.
 *
 *   int verify_p2pkh(const u8* tx, u64 txlen, u64 input_index,
 *                    const u8* prevout_script, u64 prevout_len,
 *                    u8* work, u64 work_cap)
 *       1. sighash_all with prevout_script as the signing script
 *       2. walk the raw tx to input_index, locate its scriptSig, parse the
 *          two pushes: sig and pubkey
 *       3. der_parse_sig(sig) -> r,s,htype (require htype==1)
 *       4. z = be_to_limbs(sighash 32 BE)
 *       5. pubkey_parse -> Qx,Qy
 *       6. ecdsa_verify(z,r,s,Qx,Qy)   -> 1 verify / 0 otherwise
 *
 * AAPCS64: sighash_all's 8 args fit x0..x7 (the x86 needed 2 stack slots).
 * All callees (sighash_all, pubkey_parse, ecdsa_verify, be_to_limbs) preserve
 * x19-x28. Frame layout (sp-relative after the save area; the x86 map is
 * rbp-relative -- offsets re-derived: arm = 0x200 - N):
 *   tx@0x1d0 txlen@0x1c8 idx@0x1c0 pvscript@0x1b8 pvlen@0x1b0 work@0x1a8
 *   cap@0x1a0 htype@0x198 sigstart@0x188 siglen@0x180 sigbytes@0x170
 *   publen@0x168 pubbytes@0x160 Qy@0x140 Qx@0x100 z@0x0c0 s@0x080
 *   r@0x040 out32@0x010
 * ========================================================================== */

	.text

/* ----------------------------------------------------------------------------
 * .Lparse_varint -- COMPACTSIZE (this file's own local helper; the x86 file
 * carries the same one). x0=cursor, x1=end.
 * returns x0=value (0 on over-run -- callers treat 0 as error where n>0),
 *         x1=cursor advanced past the varint (on success).
 * clobbers x2-x7. preserves everything else.
 * -------------------------------------------------------------------------- */
	.type .Lparse_varint, %function
.Lparse_varint:
	/* x0=cursor, x1=end -> x0=value (0 on over-run), x1=cursor advanced past
	 * the varint on success (callers treat value 0 as the error and never
	 * reuse the cursor then; the x86 helper behaves the same way). */
	cmp  x0, x1
	b.hs .Lpv_fail
	ldrb w2, [x0], #1
	cmp  w2, #0xfd
	b.hs .Lpv_wide
	mov  x1, x0                       /* advanced cursor */
	mov  x0, x2                       /* value */
	ret
.Lpv_wide:
	/* value bytes follow, little-endian */
	cmp  w2, #0xfe
	b.eq 1f
	cmp  w2, #0xff
	b.eq 2f
	mov  x3, #2
	b    .Lpv_read
1:	mov  x3, #4
	b    .Lpv_read
2:	mov  x3, #8
.Lpv_read:
	add  x4, x0, x3
	cmp  x4, x1
	b.hi .Lpv_fail
	mov  x5, #0                       /* value */
	mov  x6, #0                       /* shift bits */
.Lpv_b:
	ldrb w7, [x0], #1
	lsl  x7, x7, x6
	orr  x5, x5, x7
	add  x6, x6, #8
	subs x3, x3, #1
	b.ne .Lpv_b
	mov  x1, x0                       /* advanced cursor */
	mov  x0, x5
	ret
.Lpv_fail:
	mov  x0, #0
	ret

/* ----------------------------------------------------------------------------
 * be_to_limbs(x0=out u64[4], x1=bytes, x2=len) -- big-endian -> 4 LE limbs.
 * clobbers x0-x11. preserves x19+.
 * -------------------------------------------------------------------------- */
	.global be_to_limbs
	.type   be_to_limbs, %function
be_to_limbs:
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #48                  /* 32-byte right-justified temp at sp+8 */
	mov  x3, sp
	add  x3, x3, #8
	mov  x4, #0
	str  x4, [x3, #0]
	str  x4, [x3, #8]
	str  x4, [x3, #16]
	str  x4, [x3, #24]
	/* copy len bytes to temp+(32-len) (right-justified) */
	sub  x5, x3, x2
	add  x5, x5, #32                  /* dst start */
	mov  x6, x1
	mov  x7, x2
.Lbl_copy:
	cbz  x7, .Lbl_copied
	ldrb w8, [x6], #1
	strb w8, [x5], #1
	sub  x7, x7, #1
	b    .Lbl_copy
.Lbl_copied:
	/* limb j = bswap(temp[8*(3-j)..]) ; temp[0] is MSB */
	mov  x9, #0                       /* j */
.Lbl_loop:
	cmp  x9, #4
	b.hs .Lbl_done
	mov  x10, #3
	sub  x10, x10, x9
	lsl  x10, x10, #3
	add  x11, x3, x10
	ldr  x4, [x11]
	rev  x4, x4
	str  x4, [x0, x9, lsl #3]
	add  x9, x9, #1
	b    .Lbl_loop
.Lbl_done:
	add  sp, sp, #48
	ldp  x29, x30, [sp], #16
	ret
	.size be_to_limbs, .-be_to_limbs

/* ----------------------------------------------------------------------------
 * der_parse_sig(x0=sig, x1=slen, x2=r_out, x3=s_out, x4=hashtype*)
 * -> w0 = 1 ok / 0 malformed.
 * persistents: x19=sig x20=slen x21=r_out x22=s_out x23=ht_ptr
 *              x24=r base(original) x25=r len(stripped) x26=end-of-s(orig)
 * -------------------------------------------------------------------------- */
	.global der_parse_sig
	.type   der_parse_sig, %function
der_parse_sig:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	mov  x19, x0                      /* sig */
	mov  x20, x1                      /* slen */
	mov  x21, x2                      /* r_out */
	mov  x22, x3                      /* s_out */
	mov  x23, x4                      /* hashtype* */
	/* need at least 0x30 len 0x02 rlen(+1) 0x02 slen(+1) = 8 */
	cmp  x1, #8
	b.lo .Ldp_fail
	ldrb w2, [x19]
	cmp  w2, #0x30
	b.ne .Ldp_fail
	/* r: expect 0x02 rlen */
	ldrb w2, [x19, #2]
	cmp  w2, #0x02
	b.ne .Ldp_fail
	ldrb w25, [x19, #3]               /* rlen */
	cbz  w25, .Ldp_fail
	add  x24, x19, #4                 /* r value base (original) */
	add  x4, x24, x25
	add  x5, x19, x20
	cmp  x4, x5
	b.hi .Ldp_fail
	/* strip ANY number of redundant leading 0x00 down to <=32 significant
	 * bytes (x86 BUG FIX 2026-08-19; non-minimal DER INTEGER encodings are
	 * real pre-BIP66 mainnet history). base+len stay invariant as a pair. */
.Ldp_rstrip:
	cmp  x25, #32
	b.ls .Ldp_rnorm
	ldrb w2, [x24]
	cbz  w2, 1f
	b    .Ldp_fail
1:	add  x24, x24, #1
	sub  x25, x25, #1
	b    .Ldp_rstrip
.Ldp_rnorm:
	/* r -> limbs (be_to_limbs preserves x19-x28) */
	mov  x0, x21
	mov  x1, x24
	mov  x2, x25
	bl   be_to_limbs
	/* s: 0x02 slen at [r base + r len] -- base+len is INVARIANT across the
	 * strip (base moved up exactly as len moved down), so stripped_base +
	 * stripped_len == original end of r. */
	add  x4, x24, x25                  /* s marker */
	ldrb w2, [x4]
	cmp  w2, #0x02
	b.ne .Ldp_fail
	ldrb w25, [x4, #1]                /* slen (reuse the reg) */
	cbz  w25, .Ldp_fail
	add  x24, x4, #2                  /* s value base (moves while stripping) */
	add  x26, x24, x25                /* end of s (ORIGINAL, unstripped --
	                                   * the hashtype lookup needs this) */
	add  x5, x19, x20
	cmp  x26, x5
	b.hi .Ldp_fail
	/* strip s's redundant leading zeros; only base/len move, end stays */
.Ldp_sstrip:
	cmp  x25, #32
	b.ls .Ldp_snorm
	ldrb w2, [x24]
	cbz  w2, 2f
	b    .Ldp_fail
2:	add  x24, x24, #1
	sub  x25, x25, #1
	b    .Ldp_sstrip
.Ldp_snorm:
	/* s -> limbs */
	mov  x0, x22
	mov  x1, x24
	mov  x2, x25
	bl   be_to_limbs
	/* ---- hashtype: optional 0x01 right after s (end-of-s is original) ---- */
	add  x5, x19, x20                 /* sig end */
	cmp  x26, x5
	b.hs .Ldp_htzero
	ldrb w2, [x26]
	cmp  w2, #1
	b.ne .Ldp_htzero
	mov  x9, #1
	b    .Ldp_htdone
.Ldp_htzero:
	mov  x9, #0
.Ldp_htdone:
	str  w9, [x23]                    /* u32: the x86 stores r9d (4 bytes);
	                                   * the 8-byte store smashed 4 bytes of
	                                   * the caller's data after htype -- in
	                                   * test_script.c that is r[0]'s low half,
	                                   * in script_eval's state a word of live
	                                   * interpreter state (the whole CHECKSIG
	                                   * cluster) */
	mov  w0, #1
	b    .Ldp_done
.Ldp_fail:
	mov  w0, #0
.Ldp_done:
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size der_parse_sig, .-der_parse_sig

/* ============================================================================
 * verify_p2pkh(x0=tx, x1=txlen, x2=idx, x3=pvscript, x4=pvlen, x5=work,
 *              x6=cap) -> w0 = 1 verified / 0 otherwise.
 * Frame: 5 callee-saved pairs + sub 0x200; every local sp-relative (map in
 * the header). Callees: sighash_all, .Lparse_varint, der_parse_sig,
 * be_to_limbs, pubkey_parse, ecdsa_verify -- all preserve x19-x28.
 * ========================================================================== */
	.global verify_p2pkh
	.type   verify_p2pkh, %function
verify_p2pkh:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	sub  sp, sp, #0x200

	/* ---- args to slots ---- */
	str  x0, [sp, #0x1d0]             /* tx */
	str  x1, [sp, #0x1c8]             /* txlen */
	str  x2, [sp, #0x1c0]             /* idx */
	str  x3, [sp, #0x1b8]             /* pvscript */
	str  x4, [sp, #0x1b0]             /* pvlen */
	str  x5, [sp, #0x1a8]             /* work */
	str  x6, [sp, #0x1a0]             /* cap */

	/* ---- step 1: sighash_all(out32@0x010, tx, txlen, idx, pv, pvlen,
	 *      work, cap) -- all 8 args in registers on AAPCS64 ---- */
	add  x0, sp, #0x010
	ldr  x1, [sp, #0x1d0]
	ldr  x2, [sp, #0x1c8]
	ldr  x3, [sp, #0x1c0]
	ldr  x4, [sp, #0x1b8]
	ldr  x5, [sp, #0x1b0]
	ldr  x6, [sp, #0x1a8]
	ldr  x7, [sp, #0x1a0]
	bl   sighash_all
	cbz  w0, .Lvp_fail

	/* ---- step 2: locate input_index's scriptSig in the raw tx ---- */
	ldr  x19, [sp, #0x1d0]            /* tx */
	ldr  x20, [sp, #0x1c8]            /* txlen */
	add  x21, x19, x20                /* end */
	add  x0, x19, #4
	mov  x1, x21
	bl   .Lparse_varint               /* n_in; x0=value x1=cursor */
	cbz  x0, .Lvp_fail
	ldr  x22, [sp, #0x1c0]            /* idx */
	cmp  x22, x0
	b.hs .Lvp_fail
	mov  x23, x1                      /* cursor at first input's prevout */
	mov  x24, #0
.Lvp_walk:
	cmp  x24, x22
	b.hs .Lvp_found
	add  x23, x23, #36                /* prevout+index */
	mov  x0, x23
	mov  x1, x21
	bl   .Lparse_varint               /* scriptSig len */
	add  x23, x1, x0                  /* skip scriptSig bytes */
	add  x23, x23, #4                 /* sequence */
	add  x24, x24, #1
	b    .Lvp_walk
.Lvp_found:
	add  x23, x23, #36                /* -> target scriptSig varint */
	mov  x0, x23
	mov  x1, x21
	bl   .Lparse_varint               /* scriptSig len; x1 = script bytes */
	str  x1, [sp, #0x188]             /* script bytes start */
	str  x0, [sp, #0x180]             /* scriptSig len */
	/* push0 (sig): <len> sig */
	ldrb w2, [x1]
	str  x2, [sp, #0x178]             /* sig len */
	add  x3, x1, #1
	str  x3, [sp, #0x170]             /* sig bytes */
	add  x1, x1, x2
	add  x1, x1, #1
	/* push1 (pubkey): <len> pub */
	ldrb w2, [x1]
	str  x2, [sp, #0x168]             /* pub len */
	add  x3, x1, #1
	str  x3, [sp, #0x160]             /* pub bytes */

	/* ---- step 3: der_parse_sig(sig, siglen, r@0x040, s@0x080, ht@0x198) */
	ldr  x0, [sp, #0x170]
	ldr  x1, [sp, #0x178]
	add  x2, sp, #0x040
	add  x3, sp, #0x080
	add  x4, sp, #0x198
	bl   der_parse_sig
	cbz  w0, .Lvp_fail
	ldr  w2, [sp, #0x198]
	cmp  w2, #1
	b.ne .Lvp_fail

	/* ---- step 4: z = be_to_limbs(sighash 32 BE) ---- */
	add  x0, sp, #0x0c0
	add  x1, sp, #0x010
	mov  x2, #32
	bl   be_to_limbs

	/* ---- step 5: pubkey_parse(pub, publen, &Qx@0x100, &Qy@0x140) ---- */
	ldr  x0, [sp, #0x160]
	ldr  x1, [sp, #0x168]
	add  x2, sp, #0x100
	add  x3, sp, #0x140
	bl   pubkey_parse
	cbz  w0, .Lvp_fail

	/* ---- step 6: ecdsa_verify(z@0x0c0, r@0x040, s@0x080, Qx@0x100,
	 *      Qy@0x140) ---- */
	add  x0, sp, #0x0c0
	add  x1, sp, #0x040
	add  x2, sp, #0x080
	add  x3, sp, #0x100
	add  x4, sp, #0x140
	bl   ecdsa_verify
	cbz  w0, .Lvp_fail
	mov  w0, #1
	b    .Lvp_done
.Lvp_fail:
	mov  w0, #0
.Lvp_done:
	add  sp, sp, #0x200
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size verify_p2pkh, .-verify_p2pkh

/* SECURITY (audit 2026-08-29 finding 9): every object carries the note or the
 * linker marks the whole program's stack executable. */
	.section .note.GNU-stack,"",%progbits
