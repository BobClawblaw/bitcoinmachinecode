/* ============================================================================
 * sha512.S -- macOS (Darwin/Mach-O) AArch64 port of asm/sha512.asm
 *
 * Public symbols (Mach-O `_`-prefixed), identical contracts:
 *   void sha512_init (u64 state[8])                       // x0
 *   void sha512_block(u64 state[8], const u8 block[128])  // x0, x1
 *   void sha512_full (u8 out[64], const void *msg, i64 len) // x0, x1, x2
 *
 * Semantics preserved from the x86 original:
 *   - CRY-4: the 80-word W schedule is a PER-CALL stack buffer, never .bss
 *     (shared .bss corrupted concurrent digests silently).
 *   - The sha512_block callee-saved save area sits above the frame pointer
 *     so the three round temporaries (T1/S1/Maj slots) never overlay saves.
 *     On AArch64 the callee-saved set (x19-x28) is stored by stp pairs and
 *     the temporaries live at sp offsets computed to not overlap them; there
 *     are no calls from sha512_block, so alignment is trivially kept.
 *
 * Darwin notes: adrp+@PAGEOFF for K512/H512; temps x9-x15; no x18/x28.
 * ========================================================================== */

	.section	__TEXT,__text

	.balign 8
K512:
	.quad 0x428a2f98d728ae22, 0x7137449123ef65cd
	.quad 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
	.quad 0x3956c25bf348b538, 0x59f111f1b605d019
	.quad 0x923f82a4af194f9b, 0xab1c5ed5da6d8118
	.quad 0xd807aa98a3030242, 0x12835b0145706fbe
	.quad 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
	.quad 0x72be5d74f27b896f, 0x80deb1fe3b1696b1
	.quad 0x9bdc06a725c71235, 0xc19bf174cf692694
	.quad 0xe49b69c19ef14ad2, 0xefbe4786384f25e3
	.quad 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
	.quad 0x2de92c6f592b0275, 0x4a7484aa6ea6e483
	.quad 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
	.quad 0x983e5152ee66dfab, 0xa831c66d2db43210
	.quad 0xb00327c898fb213f, 0xbf597fc7beef0ee4
	.quad 0xc6e00bf33da88fc2, 0xd5a79147930aa725
	.quad 0x06ca6351e003826f, 0x142929670a0e6e70
	.quad 0x27b70a8546d22ffc, 0x2e1b21385c26c926
	.quad 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
	.quad 0x650a73548baf63de, 0x766a0abb3c77b2a8
	.quad 0x81c2c92e47edaee6, 0x92722c851482353b
	.quad 0xa2bfe8a14cf10364, 0xa81a664bbc423001
	.quad 0xc24b8b70d0f89791, 0xc76c51a30654be30
	.quad 0xd192e819d6ef5218, 0xd69906245565a910
	.quad 0xf40e35855771202a, 0x106aa07032bbd1b8
	.quad 0x19a4c116b8d2d0c8, 0x1e376c085141ab53
	.quad 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
	.quad 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
	.quad 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
	.quad 0x748f82ee5defb2fc, 0x78a5636f43172f60
	.quad 0x84c87814a1f0ab72, 0x8cc702081a6439ec
	.quad 0x90befffa23631e28, 0xa4506cebde82bde9
	.quad 0xbef9a3f7b2c67915, 0xc67178f2e372532b
	.quad 0xca273eceea26619c, 0xd186b8c721c0c207
	.quad 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
	.quad 0x06f067aa72176fba, 0x0a637dc5a2c898a6
	.quad 0x113f9804bef90dae, 0x1b710b35131c471b
	.quad 0x28db77f523047d84, 0x32caab7b40c72493
	.quad 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
	.quad 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
	.quad 0x5fcb6fab3ad6faec, 0x6c44198c4a475817

	.balign 8
H512:
	.quad 0x6a09e667f3bcc908, 0xbb67ae8584caa73b
	.quad 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
	.quad 0x510e527fade682d1, 0x9b05688c2b3e6c1f
	.quad 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

	.section	__TEXT,__text

/* ==========================================================================
 * sha512_init(state[8])
 * ========================================================================== */
	.globl _sha512_init
_sha512_init:
	adrp x1, H512@PAGE
	add  x1, x1, H512@PAGEOFF
	ldp  x2, x3, [x1, #0]
	ldp  x4, x5, [x1, #16]
	ldp  x6, x7, [x1, #32]
	ldp  x8, x9, [x1, #48]
	stp  x2, x3, [x0, #0]
	stp  x4, x5, [x0, #16]
	stp  x6, x7, [x0, #32]
	stp  x8, x9, [x0, #48]
	ret

/* ==========================================================================
 * sha512_block(state[8], block[128])
 *   x19=state, x20=block.  W[0..79] (640 bytes) at sp+0.
 *   a..h in x21..x28? NO -- x28 is platform-reserved on macOS.  Use:
 *   a=x21 b=x22 c=x23 d=x24 e=x25 f=x26 g=x27 h=x19 (h folded into the
 *   parked state reg after it is reloaded? no -- state parked in x0 works:
 *   x0 is caller-saved but nothing calls out).  Simplest safe split:
 *   x0=state (kept, no calls), x1=block, x21..x27 = a..g, h in x9 -- but x9
 *   is a temp.  Final layout: state=x19, block=x20, a..h = x21,x22,x23,x24,
 *   x25,x26,x27,x28-forbidden -> h lives in x10 (temp) only inside rounds?
 *   x86 keeps h in r8 the whole time; do the same with x28 REPLACED by x15:
 *   a=x21 b=x22 c=x23 d=x24 e=x25 f=x26 g=x27 h=x15, temps x9..x14,
 *   W base = sp.  No calls -> no alignment or clobber concerns.
 * ========================================================================== */
	.globl _sha512_block
_sha512_block:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!		/* MUST save x28 even though unused */
	sub  sp, sp, #640			/* W[0..79] = 80 words x 8 bytes */

	mov  x19, x0				/* state */
	mov  x20, x1				/* block */

	/* ---- W[0..15] = big-endian words (rev = bswap) ---- */
	mov  x9, #0
1:
	ldr  x10, [x20, x9, lsl #3]
	rev  x10, x10
	str  x10, [sp, x9, lsl #3]
	add  x9, x9, #1
	cmp  x9, #16
	b.lt 1b

	/* ---- W[16..79] ----
	 * s1(x) = ROR19 ^ ROR61 ^ SHR6 ; s0(x) = ROR1 ^ ROR8 ^ SHR7 */
	mov  x9, #16
2:
	sub  x10, x9, #2
	ldr  x11, [sp, x10, lsl #3]		/* W[t-2] */
	ror  x12, x11, #19
	ror  x13, x11, #61
	eor  x12, x12, x13
	lsr  x13, x11, #6
	eor  x12, x12, x13			/* s1 */
	sub  x10, x9, #7
	ldr  x13, [sp, x10, lsl #3]		/* W[t-7] */
	add  x12, x12, x13
	sub  x10, x9, #15
	ldr  x11, [sp, x10, lsl #3]		/* W[t-15] */
	ror  x13, x11, #1
	ror  x14, x11, #8
	eor  x13, x13, x14
	lsr  x14, x11, #7
	eor  x13, x13, x14			/* s0 */
	add  x12, x12, x13
	sub  x10, x9, #16
	ldr  x13, [sp, x10, lsl #3]		/* W[t-16] */
	add  x12, x12, x13
	str  x12, [sp, x9, lsl #3]
	add  x9, x9, #1
	cmp  x9, #80
	b.lt 2b

	/* ---- a..h = state ---- */
	ldp  x21, x22, [x19, #0]		/* a, b */
	ldp  x23, x24, [x19, #16]		/* c, d */
	ldp  x25, x26, [x19, #32]		/* e, f */
	ldp  x27, x15, [x19, #48]		/* g, h  (x15 = h) */

	/* ---- 80 rounds ---- */
	adrp x11, K512@PAGE
	add  x11, x11, K512@PAGEOFF
	mov  x9, #0				/* round index */
3:
	/* S1(e) = ROR14 ^ ROR18 ^ ROR41 */
	ror  x12, x25, #14
	ror  x13, x25, #18
	eor  x12, x12, x13
	ror  x13, x25, #41
	eor  x12, x12, x13			/* S1 */
	add  x12, x12, x15			/* + h */
	/* Ch = (e&f) ^ (~e&g) */
	and  x13, x25, x26
	bic  x14, x27, x25			/* ~e & g */
	eor  x13, x13, x14			/* Ch */
	add  x12, x12, x13
	/* + K[i] + W[i]  -> T1 in x12 */
	ldr  x13, [x11, x9, lsl #3]
	add  x12, x12, x13
	ldr  x13, [sp, x9, lsl #3]
	add  x12, x12, x13			/* T1 */
	/* S0(a) = ROR28 ^ ROR34 ^ ROR39 */
	ror  x13, x21, #28
	ror  x14, x21, #34
	eor  x13, x13, x14
	ror  x14, x21, #39
	eor  x13, x13, x14			/* S0 */
	/* Maj = (a&b) ^ (a&c) ^ (b&c) */
	and  x14, x21, x22
	and  x10, x21, x23
	eor  x14, x14, x10
	and  x10, x22, x23
	eor  x14, x14, x10			/* Maj */
	add  x13, x13, x14			/* T2 */
	/* shift window: h=g g=f f=e e=d+T1 d=c c=b b=a a=T1+T2 */
	mov  x14, x27				/* new h = g */
	mov  x27, x26				/* g = f */
	mov  x26, x25				/* f = e */
	add  x25, x24, x12			/* e = d + T1 */
	mov  x24, x23				/* d = c */
	mov  x23, x22				/* c = b */
	mov  x22, x21				/* b = a */
	add  x21, x12, x13			/* a = T1 + T2 */
	mov  x15, x14				/* h */

	add  x9, x9, #1
	cmp  x9, #80
	b.lt 3b

	/* ---- H[i] += working[i] ---- */
	ldr  x10, [x19, #0]
	add  x10, x10, x21
	str  x10, [x19, #0]
	ldr  x10, [x19, #8]
	add  x10, x10, x22
	str  x10, [x19, #8]
	ldr  x10, [x19, #16]
	add  x10, x10, x23
	str  x10, [x19, #16]
	ldr  x10, [x19, #24]
	add  x10, x10, x24
	str  x10, [x19, #24]
	ldr  x10, [x19, #32]
	add  x10, x10, x25
	str  x10, [x19, #32]
	ldr  x10, [x19, #40]
	add  x10, x10, x26
	str  x10, [x19, #40]
	ldr  x10, [x19, #48]
	add  x10, x10, x27
	str  x10, [x19, #48]
	ldr  x10, [x19, #56]
	add  x10, x10, x15
	str  x10, [x19, #56]

	add  sp, sp, #640
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret

/* ==========================================================================
 * sha512_full(out[64], msg, len)
 *   state[64] + pad[2][128] on the stack; loop state in callee-saved regs.
 *   Padding: 0x80 at rem, zeros, 128-bit BE bit-length at bytes 112..127 of
 *   the carrier block (block 0 if rem<=111 else an all-zero block 1).
 * ========================================================================== */
	.globl _sha512_full
_sha512_full:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #336			/* state@0 (64) pad0@64 (128) pad1@192
						 (128) = 320; +16 keeps 16-align:
						 5 pushes (80) + 336 = 416 = 26x16 */

	mov  x19, x0				/* out */
	mov  x20, x1				/* msg */
	mov  x21, x2				/* len */

	mov  x0, sp				/* state */
	bl   _sha512_init

	/* full 128-byte blocks */
	lsr  x22, x21, #7			/* nfull */
	mov  x23, x20				/* running block ptr */
	mov  x24, #0				/* i */
1:
	cmp  x24, x22
	b.ge 2f
	mov  x0, sp
	mov  x1, x23
	bl   _sha512_block
	add  x23, x23, #128
	add  x24, x24, #1
	b    1b

2:
	/* build padded block(s) */
	and  x25, x21, #127			/* rem = len & 127 */
	/* pad0 = remaining bytes || 0x80 || zeros (pad0 at sp+64) */
	add  x9, x20, x21			/* msg + len */
	sub  x9, x9, x25			/* start of remaining */
	mov  x10, #0
3:
	cmp  x10, x25
	b.ge 4f
	ldrb w11, [x9, x10]
	add  x14, sp, #64
	strb w11, [x14, x10]			/* pad0[i] = remaining[i] */
	add  x10, x10, #1
	b    3b
4:
	mov  w11, #0x80
	add  x13, sp, #64
	strb w11, [x13, x10]			/* 0x80 at pad0[rem] */
5:						/* zero pad0[rem+1..127] */
	add  x10, x10, #1
	cmp  x10, #128
	b.ge 6f
	strb wzr, [x13, x10]
	b    5b
6:
	/* carrier: pad0 if rem <= 111 else pad1 (all-zero + length) */
	cmp  x25, #112
	b.lt 7f
	/* zero pad1 fully */
	mov  x10, #0
61:
	add  x14, sp, #192
	strb wzr, [x14, x10]
	add  x10, x10, #1
	cmp  x10, #128
	b.lt 61b
	mov  x12, #192				/* carrier offset = pad1 */
	b    8f
7:
	mov  x12, #64				/* carrier offset = pad0 */
8:
	/* 128-bit BE length = len*8 at carrier[112..127]: zero all 16 bytes,
	 * then write the low 8 bytes of len*8 BE at carrier[120..127]
	 * (any realistic len < 2^61 keeps the upper 8 bytes zero) */
	add  x13, sp, x12			/* carrier base */
	add  x13, x13, #120			/* -> carrier[120] (length low end) */
	mov  x9, #-8				/* zero carrier[112..127] = [x13-8..x13+7] */
81:
	strb wzr, [x13, x9]
	add  x9, x9, #1
	cmp  x9, #8
	b.lt 81b
	lsl  x10, x21, #3			/* bits = len*8 */
	mov  x9, #8				/* 8 bytes BE at [x13..x13+7] */
82:
	sub  x9, x9, #1
	strb w10, [x13, x9]			/* low byte first (matches x86 .lb) */
	lsr  x10, x10, #8
	cbnz x9, 82b

	/* process pad0 always */
	mov  x0, sp				/* state */
	add  x1, sp, #64
	bl   _sha512_block
	/* process pad1 if it carries the length */
	cmp  x25, #112
	b.lt 9f
	mov  x0, sp
	add  x1, sp, #192
	bl   _sha512_block
9:
	/* emit digest: 8 qwords BE */
	mov  x9, #0
91:
	ldr  x10, [sp, x9, lsl #3]
	rev  x10, x10
	str  x10, [x19, x9, lsl #3]
	add  x9, x9, #1
	cmp  x9, #8
	b.lt 91b

	add  sp, sp, #336
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
