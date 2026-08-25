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
	/* LSB position: index = 31 - (exponent-3) */
	mov w4, #31
	sub w4, w4, w3
	add x5, x0, x4
	mov w6, #3                      /* up to 3 bytes of mantissa */
	mov w7, w2
.Lw:
	cbz w7, .Ldone
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
	sub sp, sp, #96                 /* 3x32B locals; sp stays 16-aligned */

	mov x19, x0                     /* hdr */
	/* hash = block_hash(sp+0, hdr) */
	mov x0, sp
	mov x1, x19
	bl block_hash
	/* bits = u32 LE at hdr+72 ; target = diff_target(sp+64, bits) */
	ldr w2, [x19, #72]
	mov x0, sp
	add x0, x0, #64
	mov w1, w2
	bl diff_target
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
	add sp, sp, #96
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
	sub sp, sp, #80                 /* concat[64] at sp+0..63 (+pad) */

	mov x19, x0                     /* out */
	mov x20, x1                     /* hashes */
	mov x21, x2                     /* n */

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

	add sp, sp, #80
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size merkle_root, .-merkle_root

	.section .note.GNU-stack,"",%progbits
