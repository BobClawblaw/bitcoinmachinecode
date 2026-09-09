/* ============================================================================
 * bitcoin_bip39.S -- macOS (Darwin/Mach-O) AArch64 port of
 * asm/bitcoin_bip39.asm   (branch bmc_osx)
 *
 * Public ABI (AAPCS64):
 *   int bip39_generate(char* out, const u8* entropy, i64 ent_bits)
 *        x0=out       x1=entropy    x2=ent_bits     -> 1 / 0
 *   int bip39_validate(const char* mnemonic)
 *        x0=mnemonic                                  -> 12/15/18/21/24 or -1
 *   int bip39_mnemonic_to_entropy(u8 out[32], const char* mnemonic)
 *        x0=out       x1=mnemonic                   -> ent_bits or -1
 *   int bip39_mnemonic_to_seed(u8 seed[64], const char* mnemonic,
 *                              const char* passphrase, i64 passlen)
 *        x0=seed      x1=mnemonic   x2=pass  x3=passlen -> 1 / 0
 *
 * DEPENDENCIES: sha256_full (checksum), hmac_sha512 (PBKDF2 PRF) -- both
 * from the native port/osx objects.
 *
 * BSS state mirrors the x86 layout (CRY-4/WAL-11/WAL-3 notes preserved):
 *   m39_bits(40) m39_idx(96) m39_salt(512) m39_msg(520)
 *   m39_prev(64) m39_cur(64) m39_acc(64) m39_nw(8) m39_guard(512)
 * m39_guard is the WAL-11 canary: tests assert it stays zero.
 * ============================================================================ */

#include "wordlist_gnu.inc"

	.text
	.globl	_m39_guard
	.globl	_bip39_generate
	.globl	_bip39_validate
	.globl	_bip39_mnemonic_to_entropy
	.globl	_bip39_mnemonic_to_seed

	.bss
	.balign	16
m39_bits:	.space	40			/* entropy||cs bit stream (264 bits) */
m39_idx:	.space	96			/* 24 dword word indices */
m39_salt:	.space	512			/* "mnemonic"||pass / scratch digest */
m39_msg:	.space	520			/* salt||INT(1) */
m39_prev:	.space	64
m39_cur:	.space	64
m39_acc:	.space	64
m39_nw:		.space	8			/* parsed word count */
_m39_guard:
	.space	512			/* WAL-11 canary */

	.section	__TEXT,__cstring
m39_seed_salt:
	.ascii	"mnemonic"

	.text
	.align	2
/* ----------------------------------------------------------------------------
 * bip39_bit_at(rdi=buf, rsi=bitpos) -> w0 = bit.  MSB-first.
 * -------------------------------------------------------------------------- */
bip39_bit_at:
	lsr	x8, x1, #3			/* byte index */
	and	x9, x1, #7			/* bit offset in byte */
	ldrb	w10, [x0, x8]
	neg	w9, w9
	add	w9, w9, #7			/* shift = 7 - offset */
	lsr	w0, w10, w9
	and	w0, w0, #1
	ret

/* ----------------------------------------------------------------------------
 * bip39_set_bit(rdi=buf, rsi=bitpos, rdx=0/1)  (buffer pre-zeroed)
 * -------------------------------------------------------------------------- */
bip39_set_bit:
	cbz	x2, .Lsbit_zero
	lsr	x8, x1, #3
	and	w9, w1, #7
	mov	w10, #1
	neg	w11, w9
	add	w11, w11, #7			/* shift = 7 - offset */
	lsl	w10, w10, w11
	ldrb	w11, [x0, x8]
	orr	w11, w11, w10
	strb	w11, [x0, x8]
.Lsbit_zero:
	ret

/* ----------------------------------------------------------------------------
 * bip39_read11(rdi=buf, rsi=bitpos) -> x0 = 11-bit group, BE bit order.
 * -------------------------------------------------------------------------- */
bip39_read11:
	stp	x29, x30, [sp, #-16]!
	mov	x12, x0
	mov	x13, x1
	mov	w2, wzr				/* result */
	mov	x3, xzr				/* counter */
.Lr11:
	cmp	x3, #11
	b.hs	.Lr11_done
	add	x1, x13, x3
	mov	x0, x12
	stp	x2, x3, [sp, #-16]!
	bl	bip39_bit_at
	ldp	x2, x3, [sp], #16
	lsl	w2, w2, #1
	orr	w2, w2, w0
	add	x3, x3, #1
	b	.Lr11
.Lr11_done:
	mov	x0, x2
	ldp	x29, x30, [sp], #16
	ret

/* ----------------------------------------------------------------------------
 * find_word_index(rdi=token, rsi=toklen) -> w0 = index or -1.
 * -------------------------------------------------------------------------- */
find_word_index:
	stp	x29, x30, [sp, #-16]!
	mov	x14, x0				/* token */
	mov	x15, x1				/* toklen */
	adrp	x16, _bip39_words@PAGE
	add	x16, x16, _bip39_words@PAGEOFF
	mov	w17, wzr			/* index */
.Lfwi:
	cmp	x17, #(BIP39_WORD_COUNT)
	b.hs	.Lfwi_nf
	mov	x8, x17
	lsl	x8, x8, #3
	add	x8, x8, x17			/* index*9 */
	add	x8, x8, x16			/* &record */
	mov	x9, xzr				/* byte offset */
.Lfwi_cmp:
	cmp	x9, x15
	b.hs	.Lfwi_lenchk
	ldrb	w10, [x14, x9]
	ldrb	w11, [x8, x9]
	cmp	w10, w11
	b.ne	.Lfwi_next
	add	x9, x9, #1
	b	.Lfwi_cmp
.Lfwi_lenchk:
	ldrb	w10, [x8, x15]
	cbz	w10, .Lfwi_found
.Lfwi_next:
	add	x17, x17, #1
	b	.Lfwi
.Lfwi_found:
	mov	x0, x17
	b	.Lfwi_ret
.Lfwi_nf:
	mov	x0, #-1
.Lfwi_ret:
	ldp	x29, x30, [sp], #16
	ret

/* ----------------------------------------------------------------------------
 * bip39_strlen(rdi=str) -> x0 = length.
 * -------------------------------------------------------------------------- */
bip39_strlen:
	mov	x1, x0
	mov	x0, xzr
.Lbsl:
	ldrb	w8, [x1, x0]
	cbz	w8, .Lbsl_done
	add	x0, x0, #1
	b	.Lbsl
.Lbsl_done:
	ret

/* ----------------------------------------------------------------------------
 * int bip39_generate(char* out, const u8* entropy, i64 ent_bits)
 * -------------------------------------------------------------------------- */
	.align	2
_bip39_generate:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	stp	x25, x26, [sp, #-16]!
	sub	sp, sp, #48			/* out@0 ent@8 entbits@16 cs@24 nw@32 */

	mov	x19, x0				/* out */
	mov	x20, x1				/* entropy */
	mov	x21, x2				/* ent_bits */

	/* valid ent_bits: 128,160,192,224,256 */
	cmp	x21, #128
	b.eq	.Lgen_ok
	cmp	x21, #160
	b.eq	.Lgen_ok
	cmp	x21, #192
	b.eq	.Lgen_ok
	cmp	x21, #224
	b.eq	.Lgen_ok
	cmp	x21, #256
	b.eq	.Lgen_ok
	mov	w0, #0
	b	.Lgen_ret
.Lgen_ok:
	str	x21, [sp, #16]
	lsr	x8, x21, #5			/* cs_bits */
	str	x8, [sp, #24]
	add	x8, x8, x8, lsl #1		/* cs*3 = nwords */
	str	x8, [sp, #32]			/* nwords */

	/* zero the 40-byte bit buffer */
	adrp	x22, m39_bits@PAGE
	add	x22, x22, m39_bits@PAGEOFF
	mov	x9, xzr
.Lgen_zbt:
	strb	wzr, [x22, x9]
	add	x9, x9, #1
	cmp	x9, #40
	b.lo	.Lgen_zbt

	/* copy entropy bytes into the bit buffer */
	lsr	x23, x21, #3			/* ent_bytes */
	mov	x9, xzr
.Lgen_ec:
	cmp	x9, x23
	b.hs	.Lgen_ec_done
	ldrb	w10, [x20, x9]
	strb	w10, [x22, x9]
	add	x9, x9, #1
	b	.Lgen_ec
.Lgen_ec_done:

	/* checksum digest = SHA256(entropy) into m39_salt scratch */
	adrp	x24, m39_salt@PAGE
	add	x24, x24, m39_salt@PAGEOFF
	mov	x0, x24
	mov	x1, x20
	mov	x2, x23
	bl	_sha256_full

	/* append cs_bits (<=8) bits of digest[0] at bitpos ent_bits */
	mov	x25, x21			/* bitpos */
	mov	x9, xzr				/* cs index */
.Lgen_cs:
	ldr	x10, [sp, #24]
	cmp	x9, x10
	b.hs	.Lgen_cs_done
	ldrb	w11, [x24]			/* digest[0] */
	mov	w12, #7
	sub	w12, w12, w9			/* bit index = 7 - i */
	lsr	w11, w11, w12
	and	w11, w11, #1			/* val */
	mov	x0, x22
	mov	x1, x25
	mov	x2, x11
	stp	x9, x25, [sp, #-16]!
	bl	bip39_set_bit
	ldp	x9, x25, [sp], #16
	add	x9, x9, #1
	add	x25, x25, #1
	b	.Lgen_cs
.Lgen_cs_done:

	/* extract 11-bit groups -> words */
	mov	x22, x22			/* m39_bits (already) */
	ldr	x23, [sp, #32]			/* nwords */
	mov	x24, xzr			/* bitpos */
	mov	x25, x19			/* out cursor */
	mov	x20, xzr			/* word counter */
	adrp	x26, _bip39_words@PAGE
	add	x26, x26, _bip39_words@PAGEOFF
.Lgen_wloop:
	cmp	x20, x23
	b.hs	.Lgen_wloop_done
	mov	x0, x22				/* buf */
	mov	x1, x24				/* bitpos */
	stp	x20, x23, [sp, #-16]!
	stp	x24, x25, [sp, #-16]!
	bl	bip39_read11
	ldp	x24, x25, [sp], #16
	ldp	x20, x23, [sp], #16
	/* record = words + index*9 ; copy chars up to NUL */
	madd	x8, x0, x26, xzr		/* unused; compute properly below */
	lsl	x8, x0, #3
	add	x8, x8, x0
	add	x8, x8, x26			/* &record */
	mov	x9, xzr				/* char counter */
.Lgen_cpw:
	ldrb	w10, [x8, x9]
	cbz	w10, .Lgen_cpw_done
	strb	w10, [x25, x9]
	add	x9, x9, #1
	b	.Lgen_cpw
.Lgen_cpw_done:
	add	x25, x25, x9
	/* separator: space unless last word */
	add	x8, x20, #1
	cmp	x8, x23
	b.hs	.Lgen_nospace
	mov	w10, #0x20
	strb	w10, [x25]
	add	x25, x25, #1
.Lgen_nospace:
	add	x24, x24, #11
	add	x20, x20, #1
	b	.Lgen_wloop
.Lgen_wloop_done:
	strb	wzr, [x25]
	mov	w0, #1
.Lgen_ret:
	add	sp, sp, #48
	ldp	x25, x26, [sp], #16
	ldp	x23, x24, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret

/* ----------------------------------------------------------------------------
 * bip39_parse(rdi=mnemonic) -> w0 = nwords (12/15/18/21/24) or -1.
 * Internal. Rebuilds m39_bits / m39_idx, verifies the SHA-256 checksum,
 * leaves entropy in m39_salt (then overwritten by the digest) and the
 * word count in m39_nw.
 * -------------------------------------------------------------------------- */
	.align	2
bip39_parse:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	stp	x25, x26, [sp, #-16]!
	sub	sp, sp, #32			/* mnemonic@0 ent_bits@8 cs@16 */

	mov	x19, x0				/* mnemonic */
	mov	x20, xzr			/* word count */
	mov	x21, x19			/* scan ptr */
.Lprs_tokloop:
.Lprs_skipsp:
	ldrb	w8, [x21]
	cmp	w8, #0x20
	b.ne	.Lprs_have_tok
	add	x21, x21, #1
	b	.Lprs_skipsp
.Lprs_have_tok:
	cbz	w8, .Lprs_tok_done
	mov	x22, x21			/* token start */
.Lprs_tlok:
	ldrb	w8, [x22]
	cbz	w8, .Lprs_tok_end
	cmp	w8, #0x20
	b.eq	.Lprs_tok_end
	add	x22, x22, #1
	b	.Lprs_tlok
.Lprs_tok_end:
	mov	x0, x21				/* token start */
	sub	x1, x22, x21			/* token length */
	stp	x20, x21, [sp, #-16]!
	bl	find_word_index
	ldp	x20, x21, [sp], #16
	cmn	w0, #1
	b.eq	.Lprs_invalid
	/* WAL-11: bound the index array (max 24 words) */
	cmp	x20, #24
	b.hs	.Lprs_invalid
	adrp	x23, m39_idx@PAGE
	add	x23, x23, m39_idx@PAGEOFF
	str	w0, [x23, x20, lsl #2]
	add	x20, x20, #1
	mov	x21, x22
	b	.Lprs_tokloop
.Lprs_tok_done:
	/* word count must be 12/15/18/21/24 */
	cmp	x20, #12
	b.eq	.Lprs_nok
	cmp	x20, #15
	b.eq	.Lprs_nok
	cmp	x20, #18
	b.eq	.Lprs_nok
	cmp	x20, #21
	b.eq	.Lprs_nok
	cmp	x20, #24
	b.eq	.Lprs_nok
	b	.Lprs_invalid
.Lprs_nok:
	adrp	x22, m39_nw@PAGE
	add	x22, x22, m39_nw@PAGEOFF
	str	x20, [x22]
	/* ent_bits = nwords*32/3 ; cs_bits = ent_bits/32 */
	lsl	x8, x20, #5
	mov	x9, #3
	udiv	x8, x8, x9			/* ent_bits */
	str	x8, [sp, #8]
	lsr	x9, x8, #5
	str	x9, [sp, #16]

	/* zero the bit buffer */
	adrp	x23, m39_bits@PAGE
	add	x23, x23, m39_bits@PAGEOFF
	mov	x9, xzr
.Lprs_zb:
	strb	wzr, [x23, x9]
	add	x9, x9, #1
	cmp	x9, #40
	b.lo	.Lprs_zb

	/* write each index's 11 bits at i*11 */
	adrp	x24, m39_idx@PAGE
	add	x24, x24, m39_idx@PAGEOFF
	mov	x25, xzr			/* word counter */
.Lprs_wbin:
	cmp	x25, x20
	b.hs	.Lprs_wbin_done
	ldr	w8, [x24, x25, lsl #2]		/* word index value */
	/* bitpos = x25*11 */
	mov	x9, #11
	madd	x10, x25, x9, xzr
	mov	x11, xzr			/* bit within the 11 */
.Lprs_bilin:
	cmp	x11, #11
	b.hs	.Lprs_bilin_done
	mov	w12, #10
	sub	w12, w12, w11			/* shift = 10 - bit */
	lsr	w13, w8, w12
	and	w13, w13, #1			/* val */
	mov	x0, x23				/* m39_bits */
	add	x1, x10, x11			/* bitpos */
	mov	x2, x13
	stp	x8, x10, [sp, #-16]!
	stp	x11, x25, [sp, #-16]!
	bl	bip39_set_bit
	ldp	x11, x25, [sp], #16
	ldp	x8, x10, [sp], #16
	add	x11, x11, #1
	b	.Lprs_bilin
.Lprs_bilin_done:
	add	x25, x25, #1
	b	.Lprs_wbin
.Lprs_wbin_done:
	/* ---- extract entropy bytes (first ent_bits bits) into m39_salt ---- */
	mov	x25, xzr			/* byte index */
	mov	x26, xzr			/* bitpos */
.Lprs_entb:
	ldr	x8, [sp, #8]
	lsr	x8, x8, #3			/* ent_bytes */
	cmp	x25, x8
	b.hs	.Lprs_entb_done
	mov	w9, wzr				/* byte accumulator */
	mov	x10, xzr			/* bit within byte */
.Lprs_bybit:
	cmp	x10, #8
	b.hs	.Lprs_bybit_done
	mov	x0, x23				/* m39_bits */
	mov	x1, x26				/* bitpos */
	stp	x9, x10, [sp, #-16]!
	stp	x25, x26, [sp, #-16]!
	bl	bip39_bit_at
	ldp	x25, x26, [sp], #16
	ldp	x9, x10, [sp], #16
	lsl	w9, w9, #1
	orr	w9, w9, w0
	add	x26, x26, #1
	add	x10, x10, #1
	b	.Lprs_bybit
.Lprs_bybit_done:
	adrp	x8, m39_salt@PAGE
	add	x8, x8, m39_salt@PAGEOFF
	add	x8, x8, x25
	strb	w9, [x8]
	add	x25, x25, #1
	b	.Lprs_entb
.Lprs_entb_done:

	/* ---- checksum: SHA256(entropy); compare vs stream bits ent_bits.. ---- */
	adrp	x0, m39_salt@PAGE
	add	x0, x0, m39_salt@PAGEOFF
	mov	x1, x0
	ldr	x2, [sp, #8]
	lsr	x2, x2, #3
	stp	x25, x26, [sp, #-16]!
	bl	_sha256_full
	ldp	x25, x26, [sp], #16
	adrp	x24, m39_salt@PAGE
	add	x24, x24, m39_salt@PAGEOFF
	ldr	x10, [sp, #8]			/* ent_bits */
	mov	x11, xzr				/* cs index */
.Lprs_csloop:
	ldr	x12, [sp, #16]
	cmp	x11, x12
	b.hs	.Lprs_valid
	mov	x0, x23				/* m39_bits */
	mov	x1, x10				/* bitpos = ent_bits + cs */
	stp	x10, x11, [sp, #-16]!
	bl	bip39_bit_at
	ldp	x10, x11, [sp], #16
	mov	x13, x0				/* stream bit */
	ldrb	w8, [x24]			/* digest[0] */
	mov	w9, #7
	sub	w9, w9, w11
	lsr	w8, w8, w9
	and	w8, w8, #1
	cmp	w8, w13
	b.ne	.Lprs_invalid
	add	x10, x10, #1
	add	x11, x11, #1
	b	.Lprs_csloop
.Lprs_valid:
	adrp	x8, m39_nw@PAGE
	add	x8, x8, m39_nw@PAGEOFF
	ldr	x0, [x8]
	b	.Lprs_pret
.Lprs_invalid:
	mov	w0, #-1
	b	.Lprs_pret
.Lprs_pret:
	add	sp, sp, #32
	ldp	x25, x26, [sp], #16
	ldp	x23, x24, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret

/* ----------------------------------------------------------------------------
 * int bip39_validate(const char* mnemonic)
 * -------------------------------------------------------------------------- */
	.align	2
_bip39_validate:
	stp	x29, x30, [sp, #-16]!
	bl	bip39_parse
	ldp	x29, x30, [sp], #16
	ret

/* ----------------------------------------------------------------------------
 * int bip39_mnemonic_to_entropy(u8 out[32], const char* mnemonic)
 * -------------------------------------------------------------------------- */
	.align	2
_bip39_mnemonic_to_entropy:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	sub	sp, sp, #32			/* out@0 mnemonic@8 ent_bits@16 */

	mov	x19, x0				/* out */
	mov	x20, x1				/* mnemonic */
	mov	x0, x20
	bl	bip39_parse
	cmn	w0, #1
	b.eq	.Lm2e_bad
	lsl	x8, x0, #5			/* nwords*32 */
	mov	x9, #3
	udiv	x8, x8, x9			/* ent_bits */
	str	x8, [sp, #16]

	/* rebuild entropy from the (intact) bit stream */
	mov	x21, xzr			/* byte index */
	adrp	x22, m39_bits@PAGE
	add	x22, x22, m39_bits@PAGEOFF
	mov	x23, xzr			/* bitpos */
.Lm2e_eb:
	ldr	x8, [sp, #16]
	lsr	x8, x8, #3
	cmp	x21, x8
	b.hs	.Lm2e_eb_done
	mov	w9, wzr				/* accumulator */
	mov	x10, xzr			/* bit within byte */
.Lm2e_bit:
	cmp	x10, #8
	b.hs	.Lm2e_bit_done
	mov	x0, x22
	mov	x1, x23
	stp	x9, x10, [sp, #-16]!
	stp	x21, x23, [sp, #-16]!
	bl	bip39_bit_at
	ldp	x21, x23, [sp], #16
	ldp	x9, x10, [sp], #16
	lsl	w9, w9, #1
	orr	w9, w9, w0
	add	x23, x23, #1
	add	x10, x10, #1
	b	.Lm2e_bit
.Lm2e_bit_done:
	strb	w9, [x19, x21]
	add	x21, x21, #1
	b	.Lm2e_eb
.Lm2e_eb_done:
	ldr	x0, [sp, #16]
	b	.Lm2e_ret
.Lm2e_bad:
	mov	x0, #-1
.Lm2e_ret:
	add	sp, sp, #32
	ldp	x23, x24, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret

/* ----------------------------------------------------------------------------
 * int bip39_mnemonic_to_seed(u8 seed[64], const char* mnemonic,
 *                            const char* passphrase, i64 passlen)
 * PBKDF2-HMAC-SHA512(P=mnemonic, S="mnemonic"||pass, c=2048, dkLen=64).
 * -------------------------------------------------------------------------- */
	.align	2
_bip39_mnemonic_to_seed:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	stp	x25, x26, [sp, #-16]!
	sub	sp, sp, #64
	/* seed@0 mnemonic@8 pass@16 passlen@24 mnlen@32 msg1_len@40 saltlen@48 iter@56 */

	mov	x19, x0				/* seed */
	mov	x20, x1				/* mnemonic */
	mov	x21, x2				/* passphrase */
	mov	x22, x3				/* passlen */

	/* CRY-4: bound the passphrase to m39_salt capacity (504) */
	cmp	x22, #0
	b.lt	.Lseed_toolong
	cmp	x22, #504
	b.gt	.Lseed_toolong

	/* mnemonic length */
	mov	x0, x20
	bl	bip39_strlen
	str	x0, [sp, #32]			/* mnlen */

	/* salt = "mnemonic" || passphrase into m39_salt */
	adrp	x23, m39_salt@PAGE
	add	x23, x23, m39_salt@PAGEOFF
	adrp	x24, m39_seed_salt@PAGE
	add	x24, x24, m39_seed_salt@PAGEOFF
	mov	x9, xzr
.Lseed_cs:
	ldrb	w10, [x24, x9]
	strb	w10, [x23, x9]
	add	x9, x9, #1
	cmp	x9, #8
	b.lo	.Lseed_cs
	mov	x25, #8				/* saltlen */
	cbz	x21, .Lseed_salt_done
	mov	x9, xzr
.Lseed_pc:
	cmp	x9, x22
	b.hs	.Lseed_salt_done
	ldrb	w10, [x21, x9]
	add	x8, x23, x25
	strb	w10, [x8]
	add	x25, x25, #1
	add	x9, x9, #1
	b	.Lseed_pc
.Lseed_salt_done:
	str	x25, [sp, #48]			/* saltlen */

	/* first message = salt || INT(1) into m39_msg */
	adrp	x24, m39_msg@PAGE
	add	x24, x24, m39_msg@PAGEOFF
	mov	x9, xzr
.Lseed_fm:
	cmp	x9, x25
	b.hs	.Lseed_fm_done
	ldrb	w10, [x23, x9]
	strb	w10, [x24, x9]
	add	x9, x9, #1
	b	.Lseed_fm
.Lseed_fm_done:
	add	x8, x24, x25
	mov	w10, #1
	strb	wzr, [x8]
	strb	wzr, [x8, #1]
	strb	wzr, [x8, #2]
	strb	w10, [x8, #3]
	add	x8, x25, #4
	str	x8, [sp, #40]			/* msg1_len */

	/* U1 = HMAC-SHA512(key=mnemonic, msg=salt||1) -> m39_prev */
	adrp	x24, m39_prev@PAGE
	add	x24, x24, m39_prev@PAGEOFF
	mov	x0, x24
	mov	x1, x20
	ldr	x2, [sp, #32]
	adrp	x3, m39_msg@PAGE
	add	x3, x3, m39_msg@PAGEOFF
	ldr	x4, [sp, #40]
	bl	_hmac_sha512

	/* acc = U1 */
	adrp	x23, m39_acc@PAGE
	add	x23, x23, m39_acc@PAGEOFF
	mov	x0, x23
	mov	x1, x24
	mov	x2, #64
	bl	_memcpy

	/* loop 2047 times: cur = HMAC(mn, prev) ; acc ^= cur ; prev = cur */
	mov	x25, #2047
	adrp	x22, m39_cur@PAGE
	add	x22, x22, m39_cur@PAGEOFF
.Lseed_pbloop:
	cbz	x25, .Lseed_pbdone
	mov	x0, x22
	mov	x1, x20
	ldr	x2, [sp, #32]
	mov	x3, x24
	mov	x4, #64
	stp	x25, x24, [sp, #-16]!
	bl	_hmac_sha512
	ldp	x25, x24, [sp], #16
	/* acc ^= cur */
	mov	x0, x23
	mov	x1, x22
	mov	x2, #64
	bl	_memcpy_xor1
	/* prev = cur */
	mov	x0, x24
	mov	x1, x22
	mov	x2, #64
	bl	_memcpy
	sub	x25, x25, #1
	b	.Lseed_pbloop
.Lseed_pbdone:

	/* seed = acc */
	mov	x0, x19
	mov	x1, x23
	mov	x2, #64
	bl	_memcpy
	mov	w0, #1
	b	.Lseed_wipe
.Lseed_toolong:
	mov	w0, #0
.Lseed_wipe:
	/* WAL-3/CRY-4: wipe salt/msg/prev/cur/acc unconditionally */
	stp	x0, x1, [sp, #-16]!
	mov	x9, xzr
	mov	w10, wzr
	adrp	x11, m39_salt@PAGE
	add	x11, x11, m39_salt@PAGEOFF
	mov	x12, #512
.Lseed_zs1:
	strb	w10, [x11], #1
	sub	x12, x12, #1
	cbnz	x12, .Lseed_zs1
	adrp	x11, m39_msg@PAGE
	add	x11, x11, m39_msg@PAGEOFF
	mov	x12, #520
.Lseed_zs2:
	strb	w10, [x11], #1
	sub	x12, x12, #1
	cbnz	x12, .Lseed_zs2
	adrp	x11, m39_prev@PAGE
	add	x11, x11, m39_prev@PAGEOFF
	mov	x12, #64
.Lseed_zs3:
	strb	w10, [x11], #1
	sub	x12, x12, #1
	cbnz	x12, .Lseed_zs3
	adrp	x11, m39_cur@PAGE
	add	x11, x11, m39_cur@PAGEOFF
	mov	x12, #64
.Lseed_zs4:
	strb	w10, [x11], #1
	sub	x12, x12, #1
	cbnz	x12, .Lseed_zs4
	adrp	x11, m39_acc@PAGE
	add	x11, x11, m39_acc@PAGEOFF
	mov	x12, #64
.Lseed_zs5:
	strb	w10, [x11], #1
	sub	x12, x12, #1
	cbnz	x12, .Lseed_zs5
	ldp	x0, x1, [sp], #16
.Lseed_ret:
	add	sp, sp, #64
	ldp	x25, x26, [sp], #16
	ldp	x23, x24, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret

/* ----------------------------------------------------------------------------
 * _memcpy_xor1: r0 ^= [x1] for x2 bytes (used for the PBKDF2 accumulator).
 * -------------------------------------------------------------------------- */
	.align	2
_memcpy_xor1:
.Lcx:
	cbz	x2, .Lcx_done
	ldrb	w8, [x0]
	ldrb	w9, [x1]
	eor	w8, w8, w9
	strb	w8, [x0], #1
	add	x1, x1, #1
	sub	x2, x2, #1
	b	.Lcx
.Lcx_done:
	ret
