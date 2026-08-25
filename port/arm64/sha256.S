/* ============================================================================
 * sha256.S -- AArch64 (ARMv8-A) port of asm/sha256.asm
 *
 * ABI: AAPCS64 (first args in x0, x1, x2; callee-saved x19-x28)
 *
 *   void sha256_init (u32 state[8])                 // x0 = state
 *   void sha256_block(u32 state[8], const u8 block[64])  // x0, x1
 *   void sha256_full (u8 out[32], const void *msg, i64 len) // x0, x1, x2
 *
 * Bit-for-bit same interface and output as the x86-64 original. Words are
 * kept in host little-endian registers; `rev` does the same byte-reverse that
 * x86 `bswap` does. Scalar (portable) implementation -- correct by
 * construction; an ARMv8 SHA2-extension accelerated path can be added later
 * exactly as the x86 file's SHA-NI path complements its scalar body.
 * ========================================================================== */

	.section .rodata
	.balign 16
K256:
	.word 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
	.word 0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
	.word 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
	.word 0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
	.word 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
	.word 0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
	.word 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
	.word 0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
	.word 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
	.word 0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
	.word 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
	.word 0xd192e819,0xd6990624,0xf40e3585,0x106aa070
	.word 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
	.word 0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
	.word 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
	.word 0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2

	.balign 16
INIT_H:
	.word 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a
	.word 0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19

	.text

/* ============================================================================
 * void sha256_init(u32 state[8])
 *   Load H0..H7 into the caller's 32-byte state buffer (native u32 words).
 * ========================================================================== */
	.global sha256_init
	.type sha256_init, %function
sha256_init:
	adrp x1, INIT_H
	add  x1, x1, :lo12:INIT_H
	ldp  w2, w3, [x1, #0]
	ldp  w4, w5, [x1, #8]
	ldp  w6, w7, [x1, #16]
	ldp  w8, w9, [x1, #24]
	stp  w2, w3, [x0, #0]
	stp  w4, w5, [x0, #8]
	stp  w6, w7, [x0, #16]
	stp  w8, w9, [x0, #24]
	ret
	.size sha256_init, .-sha256_init

/* ============================================================================
 * void sha256_block(u32 state[8], const u8 block[64])
 *   One 64-byte block compression, added into state[].
 *
 * Frame: 6 stp pushes (x29/x30 + x19..x28) then a 256-byte W[64] slot.
 * Registers: w19..w26 = a..h ; w27 = schedule index ; w28 = round index.
 * w2..w10 caller-saved scratch.
 * ========================================================================== */
	.global sha256_block
	.type sha256_block, %function
sha256_block:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	sub sp, sp, #256                /* W[0..63] = 64 words x 4 bytes at sp */

	/* ---- PHASE 1: W[0..15] from big-endian block bytes (rev = bswap) ---- */
	mov x2, #0
1:
	ldr w3, [x1, x2, lsl #2]
	rev w3, w3
	str w3, [sp, x2, lsl #2]
	add x2, x2, #1
	cmp x2, #16
	b.lt 1b

	/* ---- PHASE 2: extend W[16..63] ------------------------------------- */
	mov w27, #16
2:
	/* s1(W[i-2]) = ROR17 ^ ROR19 ^ SHR10 */
	sub x3, x27, #2
	ldr w4, [sp, x3, lsl #2]
	ror w5, w4, #17
	ror w6, w4, #19
	eor w5, w5, w6
	lsr w6, w4, #10
	eor w5, w5, w6
	/* + W[i-7] */
	sub x3, x27, #7
	ldr w6, [sp, x3, lsl #2]
	add w5, w5, w6
	/* s0(W[i-15]) = ROR7 ^ ROR18 ^ SHR3 */
	sub x3, x27, #15
	ldr w4, [sp, x3, lsl #2]
	ror w7, w4, #7
	ror w8, w4, #18
	eor w7, w7, w8
	lsr w8, w4, #3
	eor w7, w7, w8
	add w5, w5, w7
	/* + W[i-16] */
	sub x3, x27, #16
	ldr w6, [sp, x3, lsl #2]
	add w5, w5, w6
	str w5, [sp, x27, lsl #2]
	add w27, w27, #1
	cmp w27, #64
	b.lt 2b

	/* ---- PHASE 3: a..h = state ---------------------------------------- */
	ldr w19, [x0, #0]
	ldr w20, [x0, #4]
	ldr w21, [x0, #8]
	ldr w22, [x0, #12]
	ldr w23, [x0, #16]
	ldr w24, [x0, #20]
	ldr w25, [x0, #24]
	ldr w26, [x0, #28]

	/* ---- PHASE 4: 64 compression rounds -------------------------------- */
	mov w28, #0
3:
	/* T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i] */
	ror w4, w23, #6
	ror w5, w23, #11
	eor w4, w4, w5
	ror w5, w23, #25
	eor w4, w4, w5              /* S1(e) */
	add w4, w4, w26             /* + h */
	and w6, w23, w24            /* e&f */
	mvn w5, w23
	and w5, w5, w25             /* !e & g */
	eor w6, w6, w5              /* Ch(e,f,g) */
	add w4, w4, w6
	adrp x2, K256
	add x2, x2, :lo12:K256
	ldr w6, [x2, w28, uxtw #2]
	add w4, w4, w6              /* + K[i] */
	ldr w6, [sp, w28, uxtw #2]
	add w4, w4, w6              /* + W[i] ; w4 = T1 */

	/* T2 = S0(a) + Maj(a,b,c) */
	ror w5, w19, #2
	ror w6, w19, #13
	eor w5, w5, w6
	ror w6, w19, #22
	eor w5, w5, w6              /* S0(a) */
	and w6, w19, w20            /* a&b */
	and w7, w19, w21            /* a&c */
	eor w6, w6, w7
	and w7, w20, w21            /* b&c */
	eor w6, w6, w7              /* Maj(a,b,c) */
	add w5, w5, w6              /* w5 = T2 */

	/* slide working window right by one, set head/tail */
	add w2, w22, w4             /* tmp = d + T1   (new e) */
	mov w26, w25                /* h = g */
	mov w25, w24                /* g = f */
	mov w24, w23                /* f = e */
	mov w23, w2                 /* e = d + T1 */
	mov w22, w21                /* d = c */
	mov w21, w20                /* c = b */
	mov w20, w19                /* b = a */
	add w19, w4, w5             /* a = T1 + T2 */

	add w28, w28, #1
	cmp w28, #64
	b.lt 3b

	/* ---- PHASE 5: H[i] += working[i] ----------------------------------- */
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
	ldr w3, [x0, #20]
	add w3, w3, w24
	str w3, [x0, #20]
	ldr w3, [x0, #24]
	add w3, w3, w25
	str w3, [x0, #24]
	ldr w3, [x0, #28]
	add w3, w3, w26
	str w3, [x0, #28]

	add sp, sp, #256
	ldp x27, x28, [sp], #16
	ldp x25, x26, [sp], #16
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size sha256_block, .-sha256_block

/* ============================================================================
 * void sha256_full(u8 out[32], const void *msg, i64 len)
 *   One-shot SHA-256 with FIPS 180-4 padding; digest emitted big-endian.
 * Frame: state[8] at [sp+0..31], work block at [sp+32..95].
 *   x19=out  x20=msg(cur)  x21=remaining  x22=total byte length
 * ========================================================================== */
	.global sha256_full
	.type sha256_full, %function
sha256_full:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	sub sp, sp, #96              /* 32B state + 64B work block; 96 % 16 == 0 */

	mov x19, x0                  /* out */
	mov x20, x1                  /* msg */
	mov x21, x2                  /* remaining */
	mov x22, x2                  /* total length in bytes */

	mov x0, sp
	bl sha256_init

	/* STEP A: consume full 64-byte blocks */
4:
	cmp x21, #64
	b.lt 5f
	add x2, sp, #32              /* dst work block */
	mov x3, #0
41:
	ldr x5, [x20, x3]
	str x5, [x2, x3]
	add x3, x3, #8
	cmp x3, #64
	b.lt 41b
	mov x0, sp
	add x1, sp, #32
	bl sha256_block
	add x20, x20, #64
	sub x21, x21, #64
	b 4b

	/* STEP B: final padded block(s) */
5:
	add x2, sp, #32
	mov x3, #0
51:                              /* zero the 64-byte block */
	str xzr, [x2, x3]
	add x3, x3, #8
	cmp x3, #64
	b.lt 51b
	mov x3, #0
52:                              /* copy remaining x21 bytes */
	cmp x3, x21
	b.ge 53f
	ldrb w5, [x20, x3]
	strb w5, [x2, x3]
	add x3, x3, #1
	b 52b
53:
	mov w5, #0x80                /* 0x80 right after the data (byte x3) */
	strb w5, [x2, x3]
	cmp x21, #56                 /* does the 8-byte length fit in this block? */
	b.lt 54f
	mov x0, sp                   /* no: compress this padded block, */
	add x1, sp, #32
	bl sha256_block
	add x2, sp, #32
	mov x3, #0
55:
	str xzr, [x2, x3]            /* fresh all-zero block for the length */
	add x3, x3, #8
	cmp x3, #64
	b.lt 55b
54:
	lsl x6, x22, #3              /* bytes -> bits */
	rev x6, x6                   /* little-endian reg -> big-endian wire bytes */
	str x6, [x2, #56]            /* 64-bit BE length at bytes 56..63 */
	mov x0, sp
	add x1, sp, #32
	bl sha256_block

	/* STEP C: emit digest big-endian into out[] (x19) */
	mov x3, #0
6:
	add x1, sp, x3
	ldr w5, [x1]
	rev w5, w5
	add x2, x19, x3
	str w5, [x2]
	add x3, x3, #4
	cmp x3, #32
	b.lt 6b

	add sp, sp, #96
	ldp x27, x28, [sp], #16
	ldp x25, x26, [sp], #16
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size sha256_full, .-sha256_full

	.section .note.GNU-stack,"",%progbits
