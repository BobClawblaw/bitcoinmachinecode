/* ============================================================================
 * sha1.S -- AArch64 (ARMv8-A) port of asm/sha1.asm
 * ABI: AAPCS64.  Same public symbols / output as the x86-64 original:
 *   void sha1_init (u32 state[5])                 // x0
 *   void sha1_block(u32 state[5], const u8 block[64])  // x0, x1
 *   void sha1_full (u8 out[20], const void *msg, i64 len)  // x0, x1, x2
 * Scalar FIPS 180-1/180-4 SHA-1. `ror` implements rotates; ROTL(k)=ror(32-k).
 * ========================================================================== */

	.section .rodata
	.balign 16
INIT_H1:
	.word 0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0

	.text

	.global sha1_init
	.type sha1_init, %function
sha1_init:
	adrp x1, INIT_H1
	add  x1, x1, :lo12:INIT_H1
	ldp  w2, w3, [x1, #0]
	ldp  w4, w5, [x1, #8]
	ldr  w6, [x1, #16]
	stp  w2, w3, [x0, #0]
	stp  w4, w5, [x0, #8]
	str  w6, [x0, #16]
	ret
	.size sha1_init, .-sha1_init

	.global sha1_block
	.type sha1_block, %function
sha1_block:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	sub sp, sp, #320            /* W[0..79] u32 at sp */

	/* W[0..15] from 64-byte big-endian block */
	mov x2, #0
1:
	ldr w3, [x1, x2, lsl #2]
	rev w3, w3
	str w3, [sp, x2, lsl #2]
	add x2, x2, #1
	cmp x2, #16
	b.lt 1b

	/* extend W[16..79]: W[i]=ROTL1(W[i-3]^W[i-8]^W[i-14]^W[i-16]) */
	mov w27, #16
2:
	sub x3, x27, #3
	ldr w8, [sp, x3, lsl #2]
	sub x3, x27, #8
	ldr w9, [sp, x3, lsl #2]
	eor w8, w8, w9
	sub x3, x27, #14
	ldr w9, [sp, x3, lsl #2]
	eor w8, w8, w9
	sub x3, x27, #16
	ldr w9, [sp, x3, lsl #2]
	eor w8, w8, w9
	ror w8, w8, #31            /* ROTL1 */
	str w8, [sp, x27, lsl #2]
	add w27, w27, #1
	cmp w27, #80
	b.lt 2b

	/* a..e = state */
	ldr w19, [x0, #0]           /* a */
	ldr w20, [x0, #4]           /* b */
	ldr w21, [x0, #8]           /* c */
	ldr w22, [x0, #12]          /* d */
	ldr w23, [x0, #16]          /* e */

	/* 80 rounds; w24 = i */
	mov w24, #0
3:
	/* TEMP = ROTL5(a) + f + e + K + W[i] */
	ror w3, w19, #27            /* ROTL5(a) */
	add w3, w3, w23             /* + e */
	cmp w24, #20
	b.ge 4f
	/* f = (b&c)|(~b&d) ; K=0x5a827999 */
	and w5, w20, w21
	mvn w6, w20
	and w6, w6, w22
	orr w5, w5, w6
	mov w7, #0x7999
	movk w7, #0x5a82, lsl #16
	b 5f
4:	cmp w24, #40
	b.ge 6f
	/* f = b^c^d ; K=0x6ed9eba1 */
	eor w5, w20, w21
	eor w5, w5, w22
	mov w7, #0xeba1
	movk w7, #0x6ed9, lsl #16
	b 5f
6:	cmp w24, #60
	b.ge 7f
	/* f = (b&c)|(b&d)|(c&d) ; K=0x8f1bbcdc */
	and w5, w20, w21
	and w6, w20, w22
	orr w5, w5, w6
	and w6, w21, w22
	orr w5, w5, w6
	mov w7, #0xbcdc
	movk w7, #0x8f1b, lsl #16
	b 5f
7:                              /* f = b^c^d ; K=0xca62c1d6 */
	eor w5, w20, w21
	eor w5, w5, w22
	mov w7, #0xc1d6
	movk w7, #0xca62, lsl #16
5:
	add w3, w3, w5              /* + f */
	add w3, w3, w7              /* + K */
	ldr w6, [sp, w24, uxtw #2]
	add w3, w3, w6              /* + W[i] ; w3 = TEMP */

	/* e = d ; d = c ; c = ROTL30(b) ; b = a ; a = TEMP */
	mov w23, w22
	mov w22, w21
	ror w21, w20, #2            /* ROTL30(b) */
	mov w20, w19
	mov w19, w3

	add w24, w24, #1
	cmp w24, #80
	b.lt 3b

	/* H[i] += working[i] */
	ldr w3, [x0, #0]
	add w3, w3, w19
	str w3, [x0, #0]
	ldr w3, [x0, #4]
	add w3, w3, w20
	str w3, [x0, #4]
	ldr w3, [x0, #8]
	add w3, w3, w21
	str w3, [x0, #8]
	ldr w3, [x0, #12]
	add w3, w3, w22
	str w3, [x0, #12]
	ldr w3, [x0, #16]
	add w3, w3, w23
	str w3, [x0, #16]

	add sp, sp, #320
	ldp x27, x28, [sp], #16
	ldp x25, x26, [sp], #16
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size sha1_block, .-sha1_block

	.global sha1_full
	.type sha1_full, %function
sha1_full:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	sub sp, sp, #96             /* [sp+0..31] state, [sp+32..95] work block */

	mov x19, x0                 /* out */
	mov x20, x1                 /* msg */
	mov x21, x2                 /* remaining */
	mov x22, x2                 /* total length */

	mov x0, sp
	bl sha1_init

8:
	cmp x21, #64
	b.lt 9f
	add x2, sp, #32
	mov x3, #0
81:
	ldr x5, [x20, x3]
	str x5, [x2, x3]
	add x3, x3, #8
	cmp x3, #64
	b.lt 81b
	mov x0, sp
	add x1, sp, #32
	bl sha1_block
	add x20, x20, #64
	sub x21, x21, #64
	b 8b

9:
	add x2, sp, #32
	mov x3, #0
91:
	str xzr, [x2, x3]
	add x3, x3, #8
	cmp x3, #64
	b.lt 91b
	mov x3, #0
92:
	cmp x3, x21
	b.ge 93f
	ldrb w5, [x20, x3]
	strb w5, [x2, x3]
	add x3, x3, #1
	b 92b
93:
	mov w5, #0x80
	strb w5, [x2, x3]
	cmp x21, #56
	b.lt 94f
	mov x0, sp
	add x1, sp, #32
	bl sha1_block
	add x2, sp, #32
	mov x3, #0
95:
	str xzr, [x2, x3]
	add x3, x3, #8
	cmp x3, #64
	b.lt 95b
94:
	lsl x6, x22, #3
	rev x6, x6
	str x6, [x2, #56]
	mov x0, sp
	add x1, sp, #32
	bl sha1_block

	mov x3, #0
10:
	add x1, sp, x3
	ldr w5, [x1]
	rev w5, w5
	add x2, x19, x3
	str w5, [x2]
	add x3, x3, #4
	cmp x3, #20
	b.lt 10b

	add sp, sp, #96
	ldp x27, x28, [sp], #16
	ldp x25, x26, [sp], #16
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size sha1_full, .-sha1_full

	.section .note.GNU-stack,"",%progbits
