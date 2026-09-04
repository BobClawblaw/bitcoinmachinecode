/* ============================================================================
 * bitcoin_hash.S -- AArch64 (ARMv8-A) port of asm/bitcoin_hash.asm
 *
 * Bitcoin blockchain hashing + PoW primitives, built on the ported sha256.S
 * (which provides the canonical SHA-256). AAPCS64 (SysV x64 -> AArch64):
 *   void sha256d   (u8 out[32], const void *msg, i64 len)   // x0,x1,x2
 *   void block_hash(u8 out[32], const u8 hdr[80])           // x0,x1
 *   void diff_target(u8 target[32], u32 bits)               // x0,w1
 *   int  pow_check (const u8 hdr[80])                       // x0 -> w0
 *   void sha256d64 (u8 *out, const u8 *in, u64 pairs)       // x0,x1,x2
 *   void merkle_root(u8 out[32], u8 *hashes, u64 n)         // x0,x1,x2
 * Byte order matches the x86 original (sha256_full emits big-endian digests).
 * ========================================================================== */

	.extern sha256_full

	.text

/* ============================================================================
 * void sha256d(u8 out[32], const void *msg, i64 len)
 *   out = SHA256( SHA256( msg ) ). buf[32] on the stack.
 * ========================================================================== */
	.global sha256d
	.type sha256d, %function
sha256d:
	stp x29, x30, [sp, #-16]!
	stp x19, xzr, [sp, #-16]!
	sub sp, sp, #48                 /* buf at sp+0..31 ; sp stays 16-aligned */
	mov x19, x0                     /* out (survives the two calls) */

	/* buf = sha256(msg, len) */
	mov x0, sp
	bl sha256_full
	/* out = sha256(buf, 32) */
	mov x0, x19
	mov x1, sp
	mov x2, #32
	bl sha256_full

	add sp, sp, #48
	ldp x19, xzr, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size sha256d, .-sha256d

/* ============================================================================
 * void block_hash(u8 out[32], const u8 hdr[80])   =  sha256d(hdr, 80)
 * ========================================================================== */
	.global block_hash
	.type block_hash, %function
block_hash:
	mov x2, #80
	b sha256d
	.size block_hash, .-block_hash

/* ============================================================================
 * void diff_target(u8 target[32], u32 bits)
 *   Convert compact nBits (bits) to a 256-bit big-endian target:
 *   target = mantissa * 256^(exponent-3); exponent = bits>>24,
 *   mantissa = bits & 0xffffff.  Replicates the x86 byte placement exactly.
 * ========================================================================== */
	.data
	.balign 16
	.global pow_pow_limit_bits
pow_pow_limit_bits:
	.word 0
	.text
	.global diff_target
	.type diff_target, %function
diff_target:
	lsr w3, w1, #24                 /* exponent */
	and w2, w1, #0x00ffffff         /* mantissa */
	/* zero the 32-byte target */
	str xzr, [x0, #0]
	str xzr, [x0, #8]
	str xzr, [x0, #16]
	str xzr, [x0, #24]
	sub w3, w3, #3                  /* exponent-3 */
	cmn w3, #0
	b.mi .Ldone                     /* exponent-3 < 0 -> leave zeroed */
	/* VAL-11 (audit 2026-09-03): with e3 >= 32 the LSB position 31-e3 lands
	 * BELOW the buffer -- the old code wrote 1-3 bytes below target_be (~220
	 * bytes below the frame for exponents near 0xff: a stack scribble driven
	 * by an attacker-chosen nBits, and the enabler for VAL-7/VAL-8's free
	 * bogus headers). Core's big-uint shift DISCARDS bits past 256, so the
	 * clamped behaviour writes nothing: the stored target stays 0. The
	 * overflow itself is rejected by pow_check's range checks. */
	cmp w3, #31
	b.gt .Ldone
	/* LSB position: index = 31 - (exponent-3) */
	mov w4, #31
	sub w4, w4, w3
	add x5, x0, x4
	mov w6, #3                      /* up to 3 bytes of mantissa */
	mov w7, w2
.Lw:
	cbz w7, .Ldone
	/* VAL-11 continued: stop at the buffer's top edge. Core's 256-bit shift
	 * discards bits past bit 256 (that IS the overflow pow_check now
	 * rejects); writing them below x0 is what corrupted the frame. */
	cmp x5, x0
	b.lo .Ldone
	strb w7, [x5]
	lsr w7, w7, #8
	sub x5, x5, #1
	sub w6, w6, #1
	cbnz w6, .Lw
.Ldone:
	ret
	.size diff_target, .-diff_target

/* ============================================================================
 * int pow_check(const u8 hdr[80])  ->  1 if header PoW holds (hash <= target)
 *   hash = block_hash(hdr); bits = LE u32 at hdr+72; target = diff_target(bits);
 *   hash_be = reverse(hash); result = (hash_be <= target) big-endian compare.
 * Frame: hash[0..31], hash_be[32..63], target[64..95].
 * ========================================================================== */
	.global pow_check
	.type pow_check, %function
pow_check:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	sub sp, sp, #128                /* hash[0..31], hash_be[32..63],
	                                * target[64..95], powLimit[96..127] (VAL-11);
	                                * sp stays 16-aligned */

	mov x19, x0                     /* hdr */
	/* hash = block_hash(sp+0, hdr) */
	mov x0, sp
	mov x1, x19
	bl block_hash
	/* bits = u32 LE at hdr+72 ; target = diff_target(sp+64, bits) */
	ldr w2, [x19, #72]
	/* ---- VAL-11 (audit 2026-09-03): Core's CheckProofOfWorkImpl range
	 * checks, mirrored from arith_uint256::SetCompact's flags. Previously
	 * the hash was compared against a target derived from WHATEVER nBits
	 * claimed, with no fNegative / ==0 / fOverflow tests -- so
	 * nBits=0x207fffff made PoW free (VAL-7's zero-cost bogus tip) and a
	 * negative or overflowing compact was "valid" math rather than invalid
	 * PoW.
	 *   nWord = bits & 0x007fffff ; nSize = bits >> 24
	 *   fNegative = nWord != 0 && (bits & 0x00800000)
	 *   fOverflow = nWord != 0 && (nSize > 34 ||
	 *               (nSize > 33 && nWord > 0xff) ||
	 *               (nSize > 32 && nWord > 0xffff))
	 * plus Core's bnTarget == 0 rejection. */
	lsr w3, w2, #24                 /* nSize */
	ubfx w4, w2, #0, #23            /* nWord */
	cbz w4, .Linvalid               /* mantissa 0 -> target 0 -> badPoW */
	tst w2, #0x00800000
	b.ne .Linvalid                  /* fNegative (nWord != 0 proven above) */
	cmp w3, #34
	b.gt .Linvalid                  /* fOverflow: nSize > 34 */
	cmp w3, #33
	b.ls 1f
	cmp w4, #0xff
	b.gt .Linvalid                  /* nSize > 33 && nWord > 0xff */
1:
	cmp w3, #32
	b.ls 2f
	mov w5, #0xffff
	cmp w4, w5
	b.gt .Linvalid                  /* nSize > 32 && nWord > 0xffff */
2:
	mov x0, sp
	add x0, x0, #64
	mov w1, w2
	bl diff_target
	/* target == 0? (exponent < 3 zeroes the stored target even with a
	 * nonzero mantissa; Core rejects bnTarget == 0). */
	add x6, sp, #64
	ldp x8, x9, [x6]
	ldp x10, x11, [x6, #16]
	orr x8, x8, x9
	orr x8, x8, x10
	orr x8, x8, x11
	cbz x8, .Linvalid
	/* powLimit comparison, ARMED only: pow_pow_limit_bits is set by
	 * chainparams_select from the chain's pow_limit_bits and defaults to 0
	 * (off), so harnesses that mine trivial PoW without selecting a chain
	 * keep working; the daemon arms it at boot and the live chain can never
	 * accept a target above its powLimit (Core: bnTarget > powLimit ->
	 * invalid). */
	adrp x8, pow_pow_limit_bits
	add x8, x8, :lo12:pow_pow_limit_bits
	ldr w9, [x8]
	cbz w9, .Llmdone
	add x0, sp, #96
	mov w1, w9
	bl diff_target                  /* powLimit target at sp+96 */
	add x5, sp, #64                 /* claimed target */
	add x6, sp, #96                 /* powLimit target */
	mov w7, #0
.Llmcmp:
	add x8, x5, x7
	add x9, x6, x7
	ldrb w10, [x8]
	ldrb w11, [x9]
	cmp w10, w11
	b.lo .Llmdone                   /* target < powLimit: in range */
	b.hi .Linvalid                  /* target > powLimit */
	add w7, w7, #1
	cmp w7, #32
	b.ne .Llmcmp                    /* fully equal == in range (Core: >) */
.Llmdone:
	/* hash_be[i] = hash[31-i]  (byte-reverse the digest) */
	mov x4, #31                     /* src index */
	mov x5, sp
	mov x6, sp
	add x6, x6, #32                 /* hash_be base */
	mov w7, #0                      /* dst index */
.Lrev:
	add x8, x5, x4
	ldrb w9, [x8]
	add x10, x6, x7
	strb w9, [x10]
	sub x4, x4, #1
	add x7, x7, #1
	cmp w7, #32
	b.lt .Lrev
	/* compare hash_be (sp+32) vs target (sp+64), index 0 = MSB first */
	mov x5, sp
	add x5, x5, #32                 /* hash_be */
	add x6, sp, #64                 /* target */
	mov w7, #0
.Lcmp:
	add x8, x5, x7
	add x9, x6, x7
	ldrb w10, [x8]
	ldrb w11, [x9]
	cmp w10, w11
	b.lo .Lvalid                     /* hash byte < target byte -> valid */
	b.hi .Linvalid                   /* hash byte > target byte -> invalid */
	add x7, x7, #1
	cmp w7, #32
	b.ne .Lcmp
.Lvalid:                            /* equal -> valid */
	mov w0, #1
	b .Lout
.Linvalid:
	mov w0, #0
.Lout:
	add sp, sp, #128
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size pow_check, .-pow_check

/* ============================================================================
 * void sha256d64(u8 *out, const u8 *in, u64 pairs)
 *   out[i] = SHA256(SHA256(in+64i, 64)) for i < pairs (big-endian digest).
 *   Simple correct version (per-pair via sha256_full); the x86 2-way
 *   pipelined SHA-NI version is an optimization, not a semantic difference.
 * ========================================================================== */
	.global sha256d64
	.type sha256d64, %function
sha256d64:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, xzr, [sp, #-16]!
	mov x19, x0                     /* out */
	mov x20, x1                     /* in */
	mov x21, x2                     /* pairs */
	cbz x21, .Lout64
.Lloop:
	mov x0, x19
	mov x1, x20
	mov x2, #64
	bl sha256d
	add x19, x19, #32
	add x20, x20, #64
	subs x21, x21, #1
	b.ne .Lloop
.Lout64:
	ldp x21, xzr, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size sha256d64, .-sha256d64

/* ============================================================================
 * void merkle_root(u8 out[32], u8 *hashes, u64 n)
 *   Bitcoin tx-merkle root.  Level loop, operating IN PLACE on `hashes`
 *   (caller provides n*32 bytes of mutable storage).  Each level pairs nodes,
 *   double-SHA256(left||right), odd count duplicates the last; stops at n<=1
 *   and copies hashes[0..31] to out.  Writes at index i stay strictly below
 *   the reads at 2i / 2i+1, so in-place is safe ascending.
 * ========================================================================== */
	.global merkle_root
	.type merkle_root, %function
merkle_root:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	sub sp, sp, #96                 /* concat[64] at sp+0..63, VAL-6 mutation
	                                * flag at sp+64 (+pad) */

	mov x19, x0                     /* out */
	mov x20, x1                     /* hashes */
	mov x21, x2                     /* n */
	strb wzr, [sp, #64]             /* VAL-6 mutation flag (stack-local:
	                                * thread-safe; Core ComputeMerkleRoot's
	                                * `mutated`) */

.Llevel:
	cmp x21, #1
	b.ls .Lfinish
	/* new_n = (n+1)/2 ; produce nodes into hashes[0 .. new_n) */
	mov x22, #0                     /* out-index i = 0 */
	add x23, x21, #1
	lsr x23, x23, #1                /* new_n */
.Lnode:
	/* write offset = 32*i ; left read offset = (2i)*32 = 64*i */
	lsl x4, x22, #5                 /* 32*i (write offset) */
	lsl x5, x22, #6                 /* 64*i = (2i)*32 */
	add x5, x20, x5                 /* left pointer */
	/* concat[0..31] = left */
	add x6, sp, #0
	mov x3, #0
12:	ldr x7, [x5, x3]
	str x7, [x6, x3]
	add x3, x3, #8
	cmp x3, #32
	b.lt 12b
	/* sibling = hashes + (2i+1)*32  if (2i+1) < n else duplicate left */
	lsl x9, x22, #6
	add x9, x9, #32                 /* (2i+1)*32 byte offset */
	lsl x10, x21, #5                /* n*32 bytes */
	cmp x9, x10
	b.lo 13f
	mov x8, x5                      /* duplicate left (odd count, last node) */
	b 14f
13:
	add x8, x5, #32                 /* sibling = left + 32 */
	/* VAL-6 (CVE-2012-2459): a REAL sibling pair that is byte-identical at
	 * any level flags the tree as mutated -- the duplicate-tail fold means
	 * such a tree can be rebuilt from a DIFFERENT tx list with the same root
	 * and the same block hash. Only the real-sibling path counts (the
	 * odd-tail duplicate below is legitimate). Core: ComputeMerkleRoot's
	 * `mutated` flag. */
	ldp x11, x12, [x5]
	ldp x13, x14, [x8]
	eor x11, x11, x13
	eor x12, x12, x14
	orr x11, x11, x12
	cbnz x11, 14f                   /* differ: not mutated */
	mov w11, #1
	strb w11, [sp, #64]             /* identical real sibling: mutated */
14:
	/* concat[32..63] = sibling */
	add x6, sp, #32
	mov x3, #0
15:	ldr x7, [x8, x3]
	str x7, [x6, x3]
	add x3, x3, #8
	cmp x3, #32
	b.lt 15b
	/* node = sha256d(hashes + i*32, concat, 64) */
	add x0, x20, x4
	add x1, sp, #0
	mov x2, #64
	bl sha256d
	add x22, x22, #1
	cmp x22, x23
	b.lt .Lnode
	/* n = new_n */
	mov x21, x23
	b .Llevel

.Lfinish:
	/* out = hashes[0..31] */
	mov x1, x20
	mov x0, x19
	ldp x2, x3, [x1, #0]
	stp x2, x3, [x0, #0]
	ldp x2, x3, [x1, #16]
	stp x2, x3, [x0, #16]
	/* VAL-6: return the mutation flag in w0. C callers declared `void`
	 * ignore it; cons_verify reads it to reject a mutated block. */
	ldrb w0, [sp, #64]

	add sp, sp, #96
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size merkle_root, .-merkle_root

	.section .note.GNU-stack,"",%progbits
