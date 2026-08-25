/* ============================================================================
 * ripemd160.S -- AArch64 (ARMv8-A) port of asm/ripemd160.asm
 * ABI: AAPCS64.  Same public symbol / output as the x86-64 original:
 *   void ripemd160(u8 out[20], const void *in, i64 len)   // x0, x1, x2
 * Scalar RIPEMD-160 (Bosselaers/Dobbertin/Preneel). Message words and digest
 * are LITTLE-endian. Step tables were parsed programmatically from the
 * canonical reference rmd160.c so the message-order / rotation / function
 * schedules are byte-exact (no hand transcription).
 *
 * Registers: the 5-word tuple lives in w7..w11 (caller-saved). line_80 runs
 * one line's 80 steps; table bases are passed in x14..x17, X base in x20.
 * ========================================================================== */

	.section .rodata
	.balign 4
RMD_IV:
	.word 0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0
	.balign 4
RMD_rL:
	.word 0,1,2,3,4,5,6,7,8,9
	.word 10,11,12,13,14,15,7,4,13,1
	.word 10,6,15,3,12,0,9,5,2,14
	.word 11,8,3,10,14,4,9,15,8,1
	.word 2,7,0,6,13,11,5,12,1,9
	.word 11,10,0,8,12,4,13,3,7,15
	.word 14,5,6,2,4,0,5,9,7,12
	.word 2,10,14,1,3,8,11,6,15,13
	.balign 4
RMD_sL:                            /* ROR amounts = 32 - rotation */
	.word 21,18,17,20,27,24,25,23,21,19
	.word 18,17,26,25,23,24,25,26,24,19
	.word 21,23,25,17,25,20,17,23,21,25
	.word 19,20,21,19,26,25,18,23,19,17
	.word 18,24,19,26,27,20,25,27,21,20
	.word 18,17,18,17,23,24,23,18,27,26
	.word 24,26,27,20,23,17,27,21,26,24
	.word 19,20,27,20,19,18,21,24,27,26
	.balign 4
RMD_fL:                            /* function selector 0..4 */
	.word 0,0,0,0,0,0,0,0,0,0
	.word 0,0,0,0,0,0,1,1,1,1
	.word 1,1,1,1,1,1,1,1,1,1
	.word 1,1,2,2,2,2,2,2,2,2
	.word 2,2,2,2,2,2,2,2,3,3
	.word 3,3,3,3,3,3,3,3,3,3
	.word 3,3,3,3,4,4,4,4,4,4
	.word 4,4,4,4,4,4,4,4,4,4
	.balign 4
RMD_rR:
	.word 5,14,7,0,9,2,11,4,13,6
	.word 15,8,1,10,3,12,6,11,3,7
	.word 0,13,5,10,14,15,8,12,4,9
	.word 1,2,15,5,1,3,7,14,6,9
	.word 11,8,12,2,10,0,4,13,8,6
	.word 4,1,3,11,15,0,5,12,2,13
	.word 9,7,10,14,12,15,10,4,1,5
	.word 8,7,6,2,13,14,0,3,9,11
	.balign 4
RMD_sR:
	.word 24,23,23,21,19,17,17,27,25,25
	.word 24,21,18,18,20,26,23,19,17,25
	.word 20,24,23,21,25,25,20,25,26,17
	.word 19,21,23,25,17,21,24,26,26,18
	.word 20,19,27,18,19,19,25,27,17,27
	.word 24,21,18,18,26,18,26,23,20,23
	.word 20,27,17,24,24,27,20,23,20,27
	.word 18,26,24,19,26,27,17,19,21,21
	.balign 4
RMD_fR:
	.word 4,4,4,4,4,4,4,4,4,4
	.word 4,4,4,4,4,4,3,3,3,3
	.word 3,3,3,3,3,3,3,3,3,3
	.word 3,3,2,2,2,2,2,2,2,2
	.word 2,2,2,2,2,2,2,2,1,1
	.word 1,1,1,1,1,1,1,1,1,1
	.word 1,1,1,1,0,0,0,0,0,0
	.word 0,0,0,0,0,0,0,0,0,0
	.balign 4
RMD_KL:
	.word 0x00000000,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e
RMD_KR:
	.word 0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0x00000000

	.text

/* ============================================================================
 * line_80: run one line (80 steps) on tuple w7..w11.
 *   x14=r-tab  x15=ror-tab  x16=f-tab  x17=K-tab  x20=X base
 * Leaf (uses only caller-saved x13,x14..x17,x18,w0..w6 + x1).
 * Step: tt = ROL(A + f(B,C,D) + W[r] + K, s) + E ; C = ROL10(C) ; then
 * (A,B,C,D,E) <- (E, tt, A, C', B).
 * ========================================================================== */
	.type line_80, %function
line_80:
	mov w13, #0                     /* step index 0..79 */
.Lstep:
	ldr w0, [x14, w13, uxtw #2]     /* r  = r_tab[j] */
	ldr w6, [x20, w0, uxtw #2]     /* W[r] (X little-endian words) */
	ldr w1, [x15, w13, uxtw #2]     /* ror amount */
	ldr w2, [x16, w13, uxtw #2]     /* fn */
	/* ---- f(w8,w9,w10) by fn -> w4 ---- */
	cmp w2, #1
	b.eq .Lf1
	cmp w2, #2
	b.eq .Lf2
	cmp w2, #3
	b.eq .Lf3
	cmp w2, #4
	b.eq .Lf4
	/* fn=0 : F(x,y,z)=x^y^z */
	eor w4, w8, w9
	eor w4, w4, w10
	b   .Lfdone
.Lf1:                               /* G=(x&y)|(~x&z) */
	and w4, w8, w9
	mvn w3, w8
	and w3, w3, w10
	orr w4, w4, w3
	b   .Lfdone
.Lf2:                               /* H=(x|~y)^z */
	mvn w3, w9
	orr w4, w8, w3
	eor w4, w4, w10
	b   .Lfdone
.Lf3:                               /* I=(x&z)|(y&~z) */
	and w4, w8, w10
	mvn w3, w10
	and w3, w3, w9
	orr w4, w4, w3
	b   .Lfdone
.Lf4:                               /* J=x^(y|~z) */
	mvn w3, w10
	orr w3, w3, w9
	eor w4, w8, w3
.Lfdone:
	lsr w3, w13, #4                 /* round */
	ldr w5, [x17, w3, uxtw #2]      /* K[round] */
	add w4, w7, w4                  /* A + f */
	add w4, w4, w6                  /* + W[r] */
	add w4, w4, w5                  /* + K */
	ror w4, w4, w1                  /* ROL s */
	add w4, w4, w11                 /* + E -> tt */
	ror w3, w9, #22                 /* C' = ROL10(C) */
	/* rotate tuple: (w7,w8,w9,w10,w11) = (E, tt, B, C', D) */
	mov w18, w11                    /* old E -> new A */
	mov w0, w8                      /* old B -> new C */
	mov w1, w10                     /* old D -> new E */
	mov w7, w18                     /* A = E */
	mov w8, w4                      /* B = tt */
	mov w9, w0                      /* C = old B */
	mov w10, w3                     /* D = C' */
	mov w11, w1                     /* E = old D */
	add w13, w13, #1
	cmp w13, #80
	b.lt .Lstep
	ret
	.size line_80, .-line_80

/* ============================================================================
 * rmd_compress(state=x0[5], X=x1[16])  -- internal, one 64-byte block
 * ========================================================================== */
	.type rmd_compress, %function
rmd_compress:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	sub sp, sp, #48
	mov x19, x0                     /* state */
	mov x20, x1                     /* X */
	/* save original state to [sp+0..19] */
	ldr w7, [x0, #0]
	ldr w8, [x0, #4]
	ldr w9, [x0, #8]
	ldr w10, [x0, #12]
	ldr w11, [x0, #16]
	str w7, [sp, #0]
	str w8, [sp, #4]
	str w9, [sp, #8]
	str w10, [sp, #12]
	str w11, [sp, #16]
	/* ---- LEFT line (tuple already w7..w11) ---- */
	adrp x14, RMD_rL
	add  x14, x14, :lo12:RMD_rL
	adrp x15, RMD_sL
	add  x15, x15, :lo12:RMD_sL
	adrp x16, RMD_fL
	add  x16, x16, :lo12:RMD_fL
	adrp x17, RMD_KL
	add  x17, x17, :lo12:RMD_KL
	bl line_80
	/* save left result (A,B,C,D,E) to [sp+20..39] */
	str w7, [sp, #20]
	str w8, [sp, #24]
	str w9, [sp, #28]
	str w10, [sp, #32]
	str w11, [sp, #36]
	/* ---- RIGHT line: reload state, repoint tables ---- */
	ldr w7, [sp, #0]
	ldr w8, [sp, #4]
	ldr w9, [sp, #8]
	ldr w10, [sp, #12]
	ldr w11, [sp, #16]
	adrp x14, RMD_rR
	add  x14, x14, :lo12:RMD_rR
	adrp x15, RMD_sR
	add  x15, x15, :lo12:RMD_sR
	adrp x16, RMD_fR
	add  x16, x16, :lo12:RMD_fR
	adrp x17, RMD_KR
	add  x17, x17, :lo12:RMD_KR
	bl line_80
	/* ---- combine results ----
	   left  stored A,B,C,D,E = [sp+20..39]  ; right A',B',C',D',E' in w7..w11
	   new h0 = h1 + C  + D' ; h1 = h2 + D  + E'
	   new h2 = h3 + E  + A' ; h3 = h4 + A  + B' ; h4 = h0 + B + C'  */
	ldr w0, [sp, #20]               /* left A */
	ldr w1, [sp, #24]               /* left B */
	ldr w2, [sp, #28]               /* left C */
	ldr w3, [sp, #32]               /* left D */
	ldr w4, [sp, #36]               /* left E */
	/* h0' = h1 + C + D' (w10) */
	ldr w5, [sp, #4]
	add w5, w5, w2
	add w5, w5, w10
	str w5, [x19, #0]
	/* h1' = h2 + D + E' (w11) */
	ldr w5, [sp, #8]
	add w5, w5, w3
	add w5, w5, w11
	str w5, [x19, #4]
	/* h2' = h3 + E + A' (w7) */
	ldr w5, [sp, #12]
	add w5, w5, w4
	add w5, w5, w7
	str w5, [x19, #8]
	/* h3' = h4 + A + B' (w8) */
	ldr w5, [sp, #16]
	add w5, w5, w0
	add w5, w5, w8
	str w5, [x19, #12]
	/* h4' = h0 + B + C' (w9) */
	ldr w5, [sp, #0]
	add w5, w5, w1
	add w5, w5, w9
	str w5, [x19, #16]

	add sp, sp, #48
	ldp x27, x28, [sp], #16
	ldp x25, x26, [sp], #16
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size rmd_compress, .-rmd_compress

/* ============================================================================
 * void ripemd160(u8 out[20], const void *in, i64 len)   // x0,x1,x2
 * ========================================================================== */
	.global ripemd160
	.type ripemd160, %function
ripemd160:
	stp x29, x30, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	sub sp, sp, #96                 /* [sp+0..15] state, [sp+32..95] block */

	mov x19, x0                     /* out */
	mov x20, x1                     /* in */
	mov x21, x2                     /* remaining */
	mov x22, x2                     /* total length */

	/* state = IV */
	adrp x1, RMD_IV
	add  x1, x1, :lo12:RMD_IV
	ldp  w2, w3, [x1, #0]
	ldr  w4, [x1, #8]
	stp  w2, w3, [sp, #0]
	str  w4, [sp, #8]
	ldr  w5, [x1, #12]
	ldr  w6, [x1, #16]
	str  w5, [sp, #12]
	str  w6, [sp, #16]

	/* consume full 64-byte blocks */
.Lfull:
	cmp x21, #64
	b.lt .Lfinal
	add x2, sp, #32
	mov x3, #0
.Lcp64:
	ldr x5, [x20, x3]
	str x5, [x2, x3]
	add x3, x3, #8
	cmp x3, #64
	b.lt .Lcp64
	mov x0, sp
	add x1, sp, #32
	bl rmd_compress
	add x20, x20, #64
	sub x21, x21, #64
	b .Lfull

.Lfinal:                            /* build final padded block at [sp+32..95] */
	add x2, sp, #32
	mov x3, #0
.Lzero:
	str xzr, [x2, x3]
	add x3, x3, #8
	cmp x3, #64
	b.lt .Lzero
	mov x3, #0
.Lcpr:
	cmp x3, x21
	b.ge .Ldonecopy
	ldrb w5, [x20, x3]
	strb w5, [x2, x3]
	add x3, x3, #1
	b .Lcpr
.Ldonecopy:
	mov w5, #0x80
	strb w5, [x2, x3]
	cmp x21, #55
	b.ls .Lonepad
	mov x0, sp
	add x1, sp, #32
	bl rmd_compress
	add x2, sp, #32
	mov x3, #0
.Lzero2:
	str xzr, [x2, x3]
	add x3, x3, #8
	cmp x3, #64
	b.lt .Lzero2
.Lonepad:
	/* 64-bit bit-length, LITTLE-endian: word14 = bits low32, word15 = bits>>32 */
	lsl x3, x22, #3
	lsr x4, x22, #29
	str w3, [x2, #56]
	str w4, [x2, #60]
	mov x0, sp
	add x1, sp, #32
	bl rmd_compress

	/* emit 5 words little-endian into out[] */
	mov x3, #0
.Lemit:
	add x1, sp, x3
	ldr w5, [x1]
	add x2, x19, x3
	str w5, [x2]
	add x3, x3, #4
	cmp x3, #20
	b.lt .Lemit

	add sp, sp, #96
	ldp x27, x28, [sp], #16
	ldp x25, x26, [sp], #16
	ldp x23, x24, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ldp x29, x30, [sp], #16
	ret
	.size ripemd160, .-ripemd160

	.section .note.GNU-stack,"",%progbits
