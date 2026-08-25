/* ============================================================================
 * sha512.S -- AArch64 (ARMv8-A) port of asm/sha512.asm
 * ABI: AAPCS64.  Same public symbols / output as the x86-64 original:
 *   void sha512_init (u64 state[8])                 // x0
 *   void sha512_block(u64 state[8], const u8 block[128])  // x0, x1
 *   void sha512_full (u8 out[64], const void *msg, i64 len)  // x0, x1, x2
 * Words are u64 native little-endian; `rev x` swaps to big-endian on I/O,
 * exactly the x86 `bswap r64` behaviour. Scalar FIPS 180-4.
 * ========================================================================== */

	.section .rodata
	.balign 16
K512:
	.xword 0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
	.xword 0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118
	.xword 0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
	.xword 0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694
	.xword 0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
	.xword 0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5
	.xword 0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4
	.xword 0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70
	.xword 0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df
	.xword 0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b
	.xword 0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30
	.xword 0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8
	.xword 0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
	.xword 0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
	.xword 0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec
	.xword 0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b
	.xword 0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
	.xword 0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b
	.xword 0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
	.xword 0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817

	.balign 16
INIT_H512:
	.xword 0x6a09e667f3bcc908,0xbb67ae8584caa73b,0x3c6ef372fe94f82b,0xa54ff53a5f1d36f1
	.xword 0x510e527fade682d1,0x9b05688c2b3e6c1f,0x1f83d9abfb41bd6b,0x5be0cd19137e2179

	.text

	.global sha512_init
	.type sha512_init, %function
sha512_init:
	adrp x1, INIT_H512
	add  x1, x1, :lo12:INIT_H512
	ldp  x2, x3, [x1, #0]
	ldp  x4, x5, [x1, #16]
	ldp  x6, x7, [x1, #32]
	ldp  x8, x9, [x1, #48]
	stp  x2, x3, [x0, #0]
	stp  x4, x5, [x0, #16]
	stp  x6, x7, [x0, #32]
	stp  x8, x9, [x0, #48]
	ret
	.size sha512_init, .-sha512_init

	.global sha512_block
	.type sha512_block, %function
sha512_block:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	sub sp, sp, #640            /* W[0..79] u64 at sp */

	/* W[0..15] from 128-byte big-endian block */
	mov x2, #0
1:
	ldr x3, [x1, x2, lsl #3]
	rev x3, x3
	str x3, [sp, x2, lsl #3]
	add x2, x2, #1
	cmp x2, #16
	b.lt 1b

	/* extend W[16..79] */
	mov w27, #16
2:
	/* s1(W[i-2]) = ROTR19 ^ ROTR61 ^ SHR6 */
	sub x3, x27, #2
	ldr x4, [sp, x3, lsl #3]
	ror x5, x4, #19
	ror x6, x4, #61
	eor x5, x5, x6
	lsr x6, x4, #6
	eor x5, x5, x6
	sub x3, x27, #7
	ldr x6, [sp, x3, lsl #3]
	add x5, x5, x6
	/* s0(W[i-15]) = ROTR1 ^ ROTR8 ^ SHR7 */
	sub x3, x27, #15
	ldr x4, [sp, x3, lsl #3]
	ror x7, x4, #1
	ror x8, x4, #8
	eor x7, x7, x8
	lsr x8, x4, #7
	eor x7, x7, x8
	add x5, x5, x7
	sub x3, x27, #16
	ldr x6, [sp, x3, lsl #3]
	add x5, x5, x6
	str x5, [sp, x27, lsl #3]
	add w27, w27, #1
	cmp w27, #80
	b.lt 2b

	/* a..h = state */
	ldr x19, [x0, #0]
	ldr x20, [x0, #8]
	ldr x21, [x0, #16]
	ldr x22, [x0, #24]
	ldr x23, [x0, #32]
	ldr x24, [x0, #40]
	ldr x25, [x0, #48]
	ldr x26, [x0, #56]

	/* 80 rounds */
	mov w28, #0
3:
	/* T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i] */
	ror x4, x23, #14
	ror x5, x23, #18
	eor x4, x4, x5
	ror x5, x23, #41
	eor x4, x4, x5
	add x4, x4, x26
	and x6, x23, x24
	mvn x5, x23
	and x5, x5, x25
	eor x6, x6, x5
	add x4, x4, x6
	adrp x2, K512
	add x2, x2, :lo12:K512
	ldr x6, [x2, w28, uxtw #3]
	add x4, x4, x6
	ldr x6, [sp, w28, uxtw #3]
	add x4, x4, x6               /* x4 = T1 */

	/* T2 = S0(a) + Maj(a,b,c) */
	ror x5, x19, #28
	ror x6, x19, #34
	eor x5, x5, x6
	ror x6, x19, #39
	eor x5, x5, x6
	and x6, x19, x20
	and x7, x19, x21
	eor x6, x6, x7
	and x7, x20, x21
	eor x6, x6, x7
	add x5, x5, x6               /* x5 = T2 */

	/* state update */
	add x2, x22, x4              /* e' = d + T1 */
	mov x26, x25
	mov x25, x24
	mov x24, x23
	mov x23, x2
	mov x22, x21
	mov x21, x20
	mov x20, x19
	add x19, x4, x5              /* a' = T1 + T2 */

	add w28, w28, #1
	cmp w28, #80
	b.lt 3b

	/* H[i] += working[i] */
	ldr x3, [x0, #0]
	add x3, x3, x19
	str x3, [x0, #0]
	ldr x3, [x0, #8]
	add x3, x3, x20
	str x3, [x0, #8]
	ldr x3, [x0, #16]
	add x3, x3, x21
	str x3, [x0, #16]
	ldr x3, [x0, #24]
	add x3, x3, x22
	str x3, [x0, #24]
	ldr x3, [x0, #32]
	add x3, x3, x23
	str x3, [x0, #32]
	ldr x3, [x0, #40]
	add x3, x3, x24
	str x3, [x0, #40]
	ldr x3, [x0, #48]
	add x3, x3, x25
	str x3, [x0, #48]
	ldr x3, [x0, #56]
	add x3, x3, x26
	str x3, [x0, #56]

	add sp, sp, #640
	ldp x27, x28, [sp], #16
	ldp x25, x26, [sp], #16
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size sha512_block, .-sha512_block

	.global sha512_full
	.type sha512_full, %function
sha512_full:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	sub sp, sp, #192             /* [sp+0..63] state, [sp+64..191] work block */

	mov x19, x0                  /* out */
	mov x20, x1                  /* msg */
	mov x21, x2                  /* remaining */
	mov x22, x2                  /* total length bytes */

	mov x0, sp
	bl sha512_init

4:                               /* consume full 128-byte blocks */
	cmp x21, #128
	b.lt 5f
	add x2, sp, #64
	mov x3, #0
41:
	ldr x5, [x20, x3]
	str x5, [x2, x3]
	add x3, x3, #8
	cmp x3, #128
	b.lt 41b
	mov x0, sp
	add x1, sp, #64
	bl sha512_block
	add x20, x20, #128
	sub x21, x21, #128
	b 4b

5:                               /* final padded block(s) */
	add x2, sp, #64
	mov x3, #0
51:
	str xzr, [x2, x3]
	add x3, x3, #8
	cmp x3, #128
	b.lt 51b
	mov x3, #0
52:
	cmp x3, x21
	b.ge 53f
	ldrb w5, [x20, x3]
	strb w5, [x2, x3]
	add x3, x3, #1
	b 52b
53:
	mov w5, #0x80
	strb w5, [x2, x3]
	cmp x21, #112
	b.lt 54f
	mov x0, sp
	add x1, sp, #64
	bl sha512_block
	add x2, sp, #64
	mov x3, #0
55:
	str xzr, [x2, x3]
	add x3, x3, #8
	cmp x3, #128
	b.lt 55b
54:
	/* 128-bit big-endian bit-length field at bytes 112..127; top 64b = 0 */
	lsl x6, x22, #3
	rev x6, x6
	str xzr, [x2, #112]
	str x6, [x2, #120]
	mov x0, sp
	add x1, sp, #64
	bl sha512_block

	/* emit digest big-endian into out[] (x19) */
	mov x3, #0
6:
	add x1, sp, x3
	ldr x5, [x1]
	rev x5, x5
	add x2, x19, x3
	str x5, [x2]
	add x3, x3, #8
	cmp x3, #64
	b.lt 6b

	add sp, sp, #192
	ldp x27, x28, [sp], #16
	ldp x25, x26, [sp], #16
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size sha512_full, .-sha512_full

	.section .note.GNU-stack,"",%progbits
