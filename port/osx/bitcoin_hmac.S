/* ============================================================================
 * bitcoin_hmac.S -- macOS (Darwin/Mach-O) AArch64 port of
 * asm/bitcoin_hmac.asm   (branch bmc_osx)
 *
 * Public ABI (AAPCS64):
 *   void hmac_sha512(u8 out[64], const u8* key, i64 keylen,
 *                    const u8* msg, i64 msglen)
 *     x0=out  x1=key  x2=keylen  x3=msg  x4=msglen
 *
 * HMAC(K,m) per RFC 2104:
 *   if |K| > 128: K = SHA512(K) (64 bytes)
 *   K' = K right-padded with 0x00 to 128 bytes
 *   inner = SHA512( (K' XOR ipad) || m )     ipad = 0x36 x 128
 *   out   = SHA512( (K' XOR opad) || inner )  opad = 0x5c x 128
 *
 * Built on the native port/osx/sha512.o (sha512_full), which passes the
 * NIST vectors, so this inherits a verified compression function.
 *
 * CRY-4 (audit 2026-09-03): kpad and tmp live in THIS frame (no .bss) so
 * concurrent callers cannot alias each other's key block.  WAL-3: kpad and
 * the key-block prefix of tmp are zeroised before return -- kpad holds the
 * padded HMAC key (a BIP32 chain code or the BIP39 mnemonic), tmp[192..255]
 * holds the inner digest.
 * ============================================================================ */

	.text
	.align	2
	.globl	_hmac_sha512
_hmac_sha512:
	stp	x29, x30, [sp, #-16]!
	mov	x29, sp
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	stp	x25, x26, [sp, #-16]!	/* x25 = tmp base below -- callee-saved;
	                                   main's GOT anchor died on it in the
	                                   dbip32 differential driver 2026-09-10 */
	sub	sp, sp, #1296			/* kpad(128) @sp+0 .. @sp+127,
						   tmp(1160) @sp+128 .. @sp+1287 */

	mov	x19, x0				/* out */
	mov	x20, x1				/* key */
	mov	x21, x2				/* keylen */
	mov	x22, x3				/* msg */
	mov	x23, x4				/* msglen */
	add	x24, sp, #0			/* x24 = kpad   (key buffer)  */
	add	x25, sp, #128			/* x25 = tmp    (concat buf)  */

	/* ---- effective key: if keylen > 128, replace with SHA512(key) ---- */
	cmp	x21, #128
	b.le	.Lhmac_keyok
	/* sha512_full(tmp, key, keylen) -> 64-byte key digest in tmp */
	mov	x0, x25
	mov	x1, x20
	mov	x2, x21
	bl	_sha512_full
	mov	x21, #64			/* effective keylen = 64 */
	mov	x20, x25			/* effective key = tmp (raw digest) */
.Lhmac_keyok:

	/* ---- Build K' (key right-padded to 128) into kpad ---- */
	mov	x9, xzr				/* i */
.Lhmac_kcp:
	cmp	x9, x21
	b.hs	.Lhmac_kcp_done
	ldrb	w10, [x20, x9]
	strb	w10, [x24, x9]
	add	x9, x9, #1
	b	.Lhmac_kcp
.Lhmac_kcp_done:
.Lhmac_kz:
	cmp	x9, #128
	b.hs	.Lhmac_kz_done
	strb	wzr, [x24, x9]
	add	x9, x9, #1
	b	.Lhmac_kz
.Lhmac_kz_done:

	/* ---- INNER: tmp = SHA512( (K' XOR ipad) || msg ) ----
	 * build (K' XOR ipad) into tmp[0..127] */
	mov	x9, xzr
.Lhmac_xip:
	cmp	x9, #128
	b.hs	.Lhmac_xip_done
	ldrb	w10, [x24, x9]
	mov	w11, #0x36
	eor	w10, w10, w11
	strb	w10, [x25, x9]
	add	x9, x9, #1
	b	.Lhmac_xip
.Lhmac_xip_done:
	/* copy msg into tmp[128 .. 128+msglen) */
	add	x11, x25, #128			/* dst */
	mov	x12, x22			/* src */
	mov	x13, x23			/* remaining */
.Lhmac_mcp:
	cmp	x13, #0
	b.eq	.Lhmac_mcp_done
	ldrb	w10, [x12], #1
	strb	w10, [x11], #1
	sub	x13, x13, #1
	b	.Lhmac_mcp
.Lhmac_mcp_done:
	/* inner_len = 128 + msglen; sha512_full(tmp+192, tmp, inner_len):
	 * write the inner digest DIRECTLY to tmp[192..255] (out != msg is fine
	 * for sha512_full), eliminating the x86's copy-then-stash dance. */
	add	x2, x23, #128
	add	x0, x25, #192
	mov	x1, x25
	bl	_sha512_full

	/* ---- OUTER: build (K' XOR opad) into tmp[0..127] ---- */
	mov	x9, xzr
.Lhmac_xop:
	cmp	x9, #128
	b.hs	.Lhmac_xop_done
	ldrb	w10, [x24, x9]
	mov	w11, #0x5c
	eor	w10, w10, w11
	strb	w10, [x25, x9]
	add	x9, x9, #1
	b	.Lhmac_xop
.Lhmac_xop_done:
	/* copy stashed inner digest (tmp[192..255]) to tmp[128..191] */
	add	x11, x25, #128
	add	x12, x25, #192
	mov	x9, xzr
.Lhmac_icp:
	cmp	x9, #64
	b.hs	.Lhmac_icp_done
	ldrb	w10, [x12, x9]
	strb	w10, [x11, x9]
	add	x9, x9, #1
	b	.Lhmac_icp
.Lhmac_icp_done:
	/* sha512_full(out, tmp, 192) */
	mov	x0, x19
	mov	x1, x25
	mov	x2, #192
	bl	_sha512_full

	/* ---- CRY-4/WAL-3: zeroise kpad and tmp[0..255] ---- */
	mov	x9, xzr
.Lhmac_zk:
	strb	wzr, [x24, x9]
	add	x9, x9, #1
	cmp	x9, #128
	b.lo	.Lhmac_zk
	mov	x9, xzr
.Lhmac_zt:
	strb	wzr, [x25, x9]
	add	x9, x9, #1
	cmp	x9, #256
	b.lo	.Lhmac_zt

	add	sp, sp, #1296
	ldp	x25, x26, [sp], #16
	ldp	x23, x24, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret
