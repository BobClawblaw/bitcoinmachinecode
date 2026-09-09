/* ============================================================================
 * bitcoin_hash.S -- macOS (Darwin/Mach-O) AArch64 port of asm/bitcoin_hash.asm
 *
 * Branch: bmc_osx.  Public symbols (Mach-O `_`-prefixed), identical contracts:
 *   void sha256d(u8 out[32], const void *msg, i64 len)   // x0, x1, x2
 *   void block_hash(u8 out[32], const u8 hdr[80])        // x0, x1
 *   void diff_target(u8 target[32], u32 bits)            // x0, w1
 *   int  pow_check(const u8 hdr[80])                     // x0 -> w0 0/1
 *   u32  pow_pow_limit_bits                              // data, armed by C
 *   void sha256d64(u8 *out, const u8 *in, u64 pairs)     // x0, x1, x2
 *   int  merkle_root(u8 out[32], void *hashes, u64 n)    // x0, x1, x2 -> w0
 *
 * Calls sha256_init/block/full from port/osx/sha256.S (proven in p0).
 * Everything is pure compute; the only external data reference is
 * pow_pow_limit_bits, which C arm via chainparams_select exactly as on x86.
 *
 * Darwin notes:
 *   - extern calls are `bl _sha256_full` etc. (ld64 resolves stubs);
 *     sp is 16-byte aligned at every bl site.
 *   - x18/x28 untouched.  Temps: x9-x15 only.
 *   - pow_pow_limit_bits lives in __DATA so C can write it; read via
 *     adrp+@PAGEOFF (same object, no GOT needed).
 *
 * Semantics preserved from the x86 original, including the audited fixes:
 *   VAL-11 (diff_target/pow_check clamping + Core SetCompact range checks),
 *   VAL-6 (merkle mutation flag, CVE-2012-2459), and the sha256d64 2-way
 *   interleave (PERF_SCOPE 13.2 -- two independent sha256_block chains,
 *   constant .rodata padding blocks).
 * ========================================================================== */

	.section	__TEXT,__text

/* ---- D64 constants (fixed by the shape of a 64-byte double-SHA256) ---- */
	.balign 16
D64_IV:					/* FIPS 180-4 H0..H7, host word order */
	.word 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a
	.word 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
	.balign 16
D64_PAD_512:				/* block 2 of SHA-256 over 64 bytes */
	.byte 0x80
	.space 55
	.byte 0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00
	.balign 16
D64_PAD_256:				/* bytes 32..63 of the block over 32 bytes */
	.byte 0x80
	.space 23
	.byte 0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00
	.balign 16
D64_BSWAP32:				/* reverse bytes within each 32-bit lane */
	.byte 0x03,0x02,0x01,0x00,0x07,0x06,0x05,0x04
	.byte 0x0b,0x0a,0x09,0x08,0x0f,0x0e,0x0d,0x0c

	.section	__DATA,__data
	.balign 4
	.globl _pow_pow_limit_bits
_pow_pow_limit_bits:
	.long 0

	.section	__TEXT,__text

/* ==========================================================================
 * sha256d(out, msg, len): SHA256(SHA256(msg))
 *   x19=out, x20=msg, x21=len parked in callee-saved across the two calls.
 *   [sp..sp+31] holds hash1.  5 pushes (80 bytes) + 32 = 112, 16-aligned.
 * ========================================================================== */
	.globl _sha256d
_sha256d:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	sub  sp, sp, #32			/* hash1[32] */

	mov  x19, x0				/* out */
	mov  x20, x1				/* msg */
	mov  x21, x2				/* len */

	mov  x0, sp
	mov  x1, x20
	mov  x2, x21
	bl   _sha256_full			/* hash1 = sha256(msg, len) */

	mov  x0, x19
	mov  x1, sp
	mov  x2, #32
	bl   _sha256_full			/* out = sha256(hash1, 32) */

	add  sp, sp, #32
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret

/* ==========================================================================
 * block_hash(out[32], hdr[80]): sha256d(hdr, 80)
 * ========================================================================== */
	.globl _block_hash
_block_hash:
	mov  x2, #80
	b    _sha256d

/* ==========================================================================
 * diff_target(target[32], bits): 256-bit big-endian target from compact nBits.
 *   VAL-11 semantics verbatim: exponent<3 -> zero target; write up to 3
 *   mantissa bytes ending at index 31-e3, stopping at the buffer top edge.
 * ========================================================================== */
	.globl _diff_target
_diff_target:
	lsr  w8, w1, #24			/* exponent */
	and  w9, w1, #0x00ffffff		/* mantissa */

	/* zero all 32 bytes (x10 = pointer walk, w11 = count) */
	mov  x10, x0
	mov  w11, #32
1:
	strb wzr, [x10], #1
	sub  w11, w11, #1
	cbnz w11, 1b

	sub  w11, w8, #3			/* e3 = exponent - 3 */
	tbz  w11, #31, 2f			/* e3 >= 0 ? */
	ret					/* negative: target stays zero */
2:
	cmp  w11, #31
	b.gt 3f					/* e3 > 31: VAL-11 clamp, write nothing */

	/* LSB lands at target[31 - e3]; write up to 3 mantissa bytes LE upward */
	mov  w12, w9				/* remaining mantissa */
	add  x13, x0, #31
	sub  x13, x13, x11			/* x13 = &target[31-e3] */
	mov  w14, #3				/* byte budget */
4:
	cbz  w12, 3f				/* mantissa exhausted */
	cmp  x13, x0
	b.lt 3f					/* VAL-11: below buffer top -> stop */
	strb w12, [x13]				/* low byte (LE order) */
	lsr  w12, w12, #8
	sub  x13, x13, #1			/* next more-significant byte */
	sub  w14, w14, #1
	cbnz w14, 4b
3:
	ret

/* ==========================================================================
 * pow_check(hdr[80]) -> w0 = 1 if PoW holds.
 *   Locals: hash[32]@sp+0, hash_be[32]@sp+32, target_be[32]@sp+64,
 *           powLimit target[32]@sp+96.  5 pushes + 128 = 208, 16-aligned.
 *   Core SetCompact range checks (VAL-11) and the armed powLimit comparison
 *   mirrored exactly from the x86 body.
 * ========================================================================== */
	.globl _pow_check
_pow_check:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #128

	mov  x20, x0				/* hdr */

	/* hash = block_hash(hdr) */
	mov  x0, sp				/* hash[32] at sp+0 */
	mov  x1, x20
	bl   _block_hash

	/* bits = *(u32 LE)(hdr+72) */
	ldr  w21, [x20, #72]

	/* ---- VAL-11: Core's SetCompact range checks ---- */
	lsr  w22, w21, #24			/* nSize */
	mov  w9, #0x007fffff
	and  w23, w21, w9			/* nWord */
	cbz  w23, .Lpc_invalid			/* mantissa 0 -> target 0 */
	tbnz w21, #23, .Lpc_invalid		/* fNegative (bit 23 = 0x00800000) */
	mov  w9, #34
	cmp  w22, w9
	b.gt .Lpc_invalid			/* nSize > 34 */
	mov  w9, #33
	cmp  w22, w9
	b.ls 5f
	mov  w9, #0xff
	cmp  w23, w9
	b.gt .Lpc_invalid			/* nSize > 33 && nWord > 0xff */
5:
	mov  w9, #32
	cmp  w22, w9
	b.ls 6f
	mov  w9, #0xffff
	cmp  w23, w9
	b.gt .Lpc_invalid			/* nSize > 32 && nWord > 0xffff */
6:
	/* target_be[32] = diff_target(bits)  (at sp+64) */
	add  x0, sp, #64
	mov  w1, w21
	bl   _diff_target

	/* target == 0 -> invalid (exponent<3 case; Core rejects bnTarget==0) */
	add  x8, sp, #64
	ldr  x9,  [x8, #0]
	ldr  x10, [x8, #8]
	orr  x9, x9, x10
	ldr  x10, [x8, #16]
	orr  x9, x9, x10
	ldr  x10, [x8, #24]
	orr  x9, x9, x10
	cbz  x9, .Lpc_invalid

	/* powLimit comparison, ARMED only (pow_pow_limit_bits != 0) */
	adrp x10, _pow_pow_limit_bits@PAGE
	add  x10, x10, _pow_pow_limit_bits@PAGEOFF
	ldr  w11, [x10]
	cbz  w11, .Lpc_lmend
	add  x0, sp, #96
	mov  w1, w11
	bl   _diff_target			/* powLimit target at sp+96 */
	add  x8, sp, #64			/* claimed target */
	add  x9, sp, #96			/* powLimit target */
	mov  w12, #0
.Lpc_lcmp:
	ldrb w13, [x8, x12]
	ldrb w14, [x9, x12]
	cmp  w13, w14
	b.lt .Lpc_lmend			/* target < powLimit: in range */
	b.gt .Lpc_invalid			/* target > powLimit */
	add  w12, w12, #1
	cmp  w12, #32
	b.ne .Lpc_lcmp				/* fully equal == in range */
.Lpc_lmend:

	/* hash_be[32] = reverse(hash[32])  (sp+32) */
	add  x8, sp, #31			/* src = hash + 31 */
	add  x9, sp, #32			/* dst = hash_be */
	mov  w11, #32
.Lpc_rev:
	ldrb w12, [x8], #-1
	strb w12, [x9], #1
	sub  w11, w11, #1
	cbnz w11, .Lpc_rev

	/* MSB-first compare hash_be vs target_be: 1 if hash_be <= target_be */
	add  x8, sp, #32			/* hash_be */
	add  x9, sp, #64			/* target_be */
	mov  w11, #0
.Lpc_cmp:
	ldrb w12, [x8, x11]
	ldrb w13, [x9, x11]
	cmp  w12, w13
	b.lt .Lpc_valid
	b.gt .Lpc_invalid
	add  w11, w11, #1
	cmp  w11, #32
	b.ne .Lpc_cmp
	b    .Lpc_valid			/* all equal -> valid */

.Lpc_valid:
	mov  w0, #1
	b    .Lpc_out
.Lpc_invalid:
	mov  w0, #0
.Lpc_out:
	add  sp, sp, #128
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret

/* ==========================================================================
 * sha256d64(out, in, pairs): 2-way interleaved 64-byte double-SHA256.
 *   out[32i..] = SHA256(SHA256(in[64i..])), the merkle inner-node op.
 *   Two independent sha256_block chains (lanes A/B) overlap; padding blocks
 *   are .rodata constants.  Odd tail finished 1-way.
 *
 *   Frame (Mach-O): stp pairs of pushes keep sp aligned.  Locals above sp
 *   after prologue: SA@+0(32) SB@+32(32) BA@+64(64) BB@+128(64); then
 *   x19=out, x20=in, x21=pairs parked BELOW those in callee-saved regs.
 *   Prologue: 5x16 push (80) + sub 224 = 304 bytes of locals region.
 *   Layout inside: [sp+0..31]=SA [32..63]=SB [64..127]=BA [128..191]=BB
 *                  [192..223]=spill pad (keeps 16-align: 80+224=304,
 *                  304%16=0 -- wait, 80+224=304, 304%16 = 0? 304=19*16 yes)
 * ========================================================================== */
	.globl _sha256d64
_sha256d64:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #224			/* SA@0 SB@32 BA@64 BB@128, tail slots at
						 96/160; 5 pushes (80) + 224 = 304 =
						 19x16, sp aligned at the bl sites */

	mov  x19, x0				/* out */
	mov  x20, x1				/* in */
	mov  x21, x2				/* pairs remaining */
	cbz  x21, .Ld64_out

	/* both second-hash blocks keep a constant 32-byte tail */
	adrp x9,  D64_PAD_256@PAGE
	add  x9,  x9, D64_PAD_256@PAGEOFF
	ldp  q0, q1, [x9]
	add  x10, sp, #96			/* BA@64 +32 = 96: PAD_256 tail */
	stp  q0, q1, [x10]
	add  x10, sp, #160			/* BB@128 +32 = 160 */
	stp  q0, q1, [x10]

.Ld64_two:
	cmp  x21, #2
	b.lt .Ld64_one

	/* SA = SB = IV */
	bl   .Ld64_setiv_ab
	/* first hash, data block, both lanes */
	mov  x0, sp				/* SA */
	mov  x1, x20				/* inA */
	bl   _sha256_block
	add  x0, sp, #32			/* SB */
	add  x1, x20, #64			/* inB */
	bl   _sha256_block
	/* first hash, padding block (constant), both lanes */
	mov  x0, sp
	adrp x1, D64_PAD_512@PAGE
	add  x1, x1, D64_PAD_512@PAGEOFF
	bl   _sha256_block
	add  x0, sp, #32
	adrp x1, D64_PAD_512@PAGE
	add  x1, x1, D64_PAD_512@PAGEOFF
	bl   _sha256_block
	/* build both second-hash blocks: BE(SA)||PAD_256, BE(SB)||PAD_256 */
	/* NOTE: dst BA is at sp+64 (NOT sp+0) -- BA overlaps SA/SB by design on
	 * the x86 side too (BA@-0xb0 vs SA@-0x50), but there D64_STORE_BE reads
	 * its source BEFORE the first write lands on the same bytes.  Here the
	 * write offset differs from the read offset, so no overlap occurs:
	 * dst=sp+64, src=sp+0. */
	mov  x0, sp
	add  x0, x0, #64			/* dst BA at sp+64 */
	mov  x1, sp				/* src SA */
	bl   .Ld64_store_be			/* writes 32 BE bytes at BA[0..31];
						 tail BA[32..63] holds PAD_256 */
	mov  x0, sp
	add  x0, x0, #128			/* dst BB at sp+128 */
	add  x1, sp, #32			/* src SB */
	bl   .Ld64_store_be
	/* second hash, both lanes: SA=IV compress BA; SB=IV compress BB */
	bl   .Ld64_setiv_ab
	mov  x0, sp
	mov  x1, sp
	add  x1, x1, #64			/* BA at sp+64 */
	bl   _sha256_block
	add  x0, sp, #32
	add  x1, sp, #128			/* BB at sp+128 */
	bl   _sha256_block
	/* emit: out[0..31]=BE(SA), out[32..63]=BE(SB) */
	mov  x0, x19
	mov  x1, sp
	bl   .Ld64_store_be
	add  x0, x19, #32
	add  x1, sp, #32
	bl   .Ld64_store_be

	add  x19, x19, #64
	add  x20, x20, #128
	sub  x21, x21, #2
	b    .Ld64_two

.Ld64_one:
	cbz  x21, .Ld64_out
	/* SA = IV */
	adrp x9,  D64_IV@PAGE
	add  x9,  x9, D64_IV@PAGEOFF
	ldp  q0, q1, [x9]
	stp  q0, q1, [sp]
	mov  x0, sp
	mov  x1, x20
	bl   _sha256_block
	mov  x0, sp
	adrp x1, D64_PAD_512@PAGE
	add  x1, x1, D64_PAD_512@PAGEOFF
	bl   _sha256_block
	/* BA tail already holds PAD_256; store BE(SA) into BA head */
	mov  x0, sp
	add  x0, x0, #64			/* BA */
	mov  x1, sp				/* SA */
	bl   .Ld64_store_be
	/* SA = IV, compress BA */
	adrp x9,  D64_IV@PAGE
	add  x9,  x9, D64_IV@PAGEOFF
	ldp  q0, q1, [x9]
	stp  q0, q1, [sp]
	mov  x0, sp
	add  x1, sp, #64
	bl   _sha256_block
	/* emit */
	mov  x0, x19
	mov  x1, sp
	bl   .Ld64_store_be

.Ld64_out:
	add  sp, sp, #224
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret

/* helper: SA=IV, SB=IV (clobbers x9, q0/q1) */
.Ld64_setiv_ab:
	adrp x9,  D64_IV@PAGE
	add  x9,  x9, D64_IV@PAGEOFF
	ldp  q0, q1, [x9]
	stp  q0, q1, [sp]			/* SA */
	stp  q0, q1, [sp, #32]			/* SB */
	ret

/* helper: [x0..x0+31] = big-endian bytes of the 8 host words at [x1..x1+31]
 * (pshufb-with-mask equivalent: rev32 per 32-bit lane)
 * NOTE: x0/x1 are READ-ONLY args -- the x86 macro took them as %1/%2 operands
 * where "%1 + 0" was an addressing mode, not an increment.  x9 is the loop
 * index; x0/x1 are never modified here.  Clobbers x9/x10 only.
 * THIS HELPER IS NOT A CALLEE-SAVED FUNCTION; but it IS called with bl, so
 * x30 must be preserved -- it is (bl sets x30, ret consumes it). */
.Ld64_store_be:
	mov  x9, #0
1:
	ldr  w10, [x1, x9]
	rev  w10, w10
	str  w10, [x0, x9]
	add  x9, x9, #4
	cmp  x9, #32
	b.lt 1b
	ret

/* ==========================================================================
 * merkle_root(out[32], hashes, n) -> w0 = mutation flag (VAL-6).
 *   In-place level-by-level; inner nodes through sha256d64 in batches of 16
 *   pairs (MK_STAGE) staged in a 1024-byte buffer; odd tail duplicates the
 *   last node; a REAL identical sibling pair anywhere sets the flag.
 *
 *   Locals: stage[1024] at sp+0..1023, write offset at sp+1024,
 *           staged count at sp+1032.  Prologue: 5x16 + 1040 = 1120 bytes.
 *   x19=hashes, x20=n, x21=out, x22=level nodes, x23=read byte offset.
 * ========================================================================== */
	.globl _merkle_root
_merkle_root:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #1056			/* stage[1024] + write_off(8) + staged(8)
						 + flag(8), all 16-aligned */

	mov  x19, x1				/* hashes */
	mov  x20, x2				/* n */
	mov  x21, x0				/* out */
	str  xzr, [sp, #1040]			/* VAL-6 mutation flag = 0 */

.Lmk_level:
	cmp  x20, #1
	b.ls .Lmk_finish

	mov  x22, x20				/* nodes at this level */
	mov  x23, #0				/* read byte offset */
	str  xzr, [sp, #1024]			/* write byte offset = 0 */

.Lmk_batch:
	str  xzr, [sp, #1032]			/* staged pairs = 0 */
.Lmk_fill:
	/* r9 equivalent: x9 = &stage[staged] */
	ldr  x9,  [sp, #1032]
	lsl  x9,  x9, #6
	add  x9,  sp, x9			/* dest slot */
	/* stage hashes[x23] + sibling (or duplicate), set flag on real dups */
	mov  x10, x19
	add  x10, x10, x23			/* &hashes[i] */
	ldr  x11, [x10, #0]
	str  x11, [x9, #0]
	ldr  x11, [x10, #8]
	str  x11, [x9, #8]
	ldr  x11, [x10, #16]
	str  x11, [x9, #16]
	ldr  x11, [x10, #24]
	str  x11, [x9, #24]
	/* sibling index = i+1 */
	lsr  x11, x23, #5
	add  x11, x11, #1
	cmp  x11, x22
	b.hs .Lmk_dup				/* no sibling -> duplicate left */
	add  x10, x10, #32			/* &sibling */
	/* VAL-6: real sibling identical to left -> mutation */
	ldr  x11, [x10, #0]
	ldr  x12, [x10, #-32]
	cmp  x11, x12
	b.ne .Lmk_nomut
	ldr  x11, [x10, #8]
	ldr  x12, [x10, #-24]
	cmp  x11, x12
	b.ne .Lmk_nomut
	ldr  x11, [x10, #16]
	ldr  x12, [x10, #-16]
	cmp  x11, x12
	b.ne .Lmk_nomut
	ldr  x11, [x10, #24]
	ldr  x12, [x10, #-8]
	cmp  x11, x12
	b.ne .Lmk_nomut
	mov  w11, #1
	strb w11, [sp, #1040]
.Lmk_nomut:
.Lmk_dup:
	ldr  x11, [x10, #0]
	str  x11, [x9, #32]
	ldr  x11, [x10, #8]
	str  x11, [x9, #40]
	ldr  x11, [x10, #16]
	str  x11, [x9, #48]
	ldr  x11, [x10, #24]
	str  x11, [x9, #56]
	add  x23, x23, #64

	/* staged++ ; flush at 16 pairs or level end */
	ldr  x11, [sp, #1032]
	add  x11, x11, #1
	str  x11, [sp, #1032]
	lsr  x12, x23, #5
	cmp  x12, x22
	b.hs .Lmk_flush
	cmp  x11, #16
	b.lt .Lmk_fill
.Lmk_flush:
	/* sha256d64(hashes + write_off, stage, staged) */
	mov  x0, x19
	ldr  x10, [sp, #1024]
	add  x0, x0, x10
	mov  x1, sp
	mov  x2, x11				/* staged pairs */
	bl   _sha256d64
	ldr  x10, [sp, #1032]
	lsl  x10, x10, #5			/* 32 bytes per pair */
	ldr  x11, [sp, #1024]
	add  x10, x10, x11
	str  x10, [sp, #1024]
	lsr  x11, x23, #5
	cmp  x11, x22
	b.lt .Lmk_batch

	/* n = (n+1)/2 for the next level */
	add  x20, x20, #1
	lsr  x20, x20, #1
	b    .Lmk_level

.Lmk_finish:
	/* out = hashes[0] (the last remaining node) */
	ldr  x9,  [x19, #0]
	str  x9,  [x21, #0]
	ldr  x9,  [x19, #8]
	str  x9,  [x21, #8]
	ldr  x9,  [x19, #16]
	str  x9,  [x21, #16]
	ldr  x9,  [x19, #24]
	str  x9,  [x21, #24]
	ldrb w0, [sp, #1040]			/* VAL-6 mutation flag in w0 */

	add  sp, sp, #1056
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
