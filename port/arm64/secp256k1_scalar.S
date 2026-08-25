/* ============================================================================
 * secp256k1_scalar.S -- AArch64 (ARMv8-A) port of asm/secp256k1_scalar.asm
 *
 * Scalar arithmetic mod the secp256k1 curve order
 *   n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 * Element = 4 little-endian u64 limbs. AAPCS64:
 *   void sc_add(r[4],a[4],b[4])   r=(a+b) mod n
 *   void sc_sub(r[4],a[4],b[4])   r=(a-b) mod n
 *   void sc_mul(r[4],a[4],b[4])   r=(a*b) mod n
 *   void sc_sqr(r[4],a[4])        r=(a*a) mod n
 *   void sc_inv(r[4],a[4])        r=a^(n-2) mod n (Fermat)
 *
 * Reduction: DELTA = 2^256 - n, so 2^256 == DELTA (mod n).
 * sc_mul: 10-limb product cur[0..9]; 8 FOLD rounds (tmp=cur[4..8]*DELTA,
 *   cur = tmp + cur[0..3]); then 3 conditional n-subtractions.
 * Every multi-limb add is a proper adc carry chain.
 * ========================================================================== */
	.text

	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

/* helper for sc_mul: array[base] += (hi,lo) at column k, carry through k+2..9.
 * NOTE: each propagate step must LOAD the limb and adc it -- `adcs x6,xzr,xzr`
 * would discard the limb's value and store just the carry (real bug fixed). */
	.macro SCA_ADD b, k, lo, hi
	ldr  x6, [\b, #((\k))*8]
	adds x6, x6, \lo
	str  x6, [\b, #((\k))*8]
	ldr  x6, [\b, #((\k)+1)*8]
	adcs x6, x6, \hi
	str  x6, [\b, #((\k)+1)*8]
	.if (\k)+2 <= 9
	ldr  x6, [\b, #((\k)+2)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+2)*8]
	.endif
	.if (\k)+3 <= 9
	ldr  x6, [\b, #((\k)+3)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+3)*8]
	.endif
	.if (\k)+4 <= 9
	ldr  x6, [\b, #((\k)+4)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+4)*8]
	.endif
	.if (\k)+5 <= 9
	ldr  x6, [\b, #((\k)+5)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+5)*8]
	.endif
	.if (\k)+6 <= 9
	ldr  x6, [\b, #((\k)+6)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+6)*8]
	.endif
	.if (\k)+7 <= 9
	ldr  x6, [\b, #((\k)+7)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+7)*8]
	.endif
	.if (\k)+8 <= 9
	ldr  x6, [\b, #((\k)+8)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+8)*8]
	.endif
	.if (\k)+9 <= 9
	ldr  x6, [\b, #((\k)+9)*8]
	adcs x6, x6, xzr
	str  x6, [\b, #((\k)+9)*8]
	.endif
	.endm

/* ============================================================================
 * sc_add(r,a,b)  r=(a+b) mod n
 * ========================================================================== */
	.global sc_add
	.type sc_add, %function
sc_add:
	ldr x4, [x1, #0]
	ldr x5, [x2, #0]
	ldr x6, [x1, #8]
	ldr x7, [x2, #8]
	ldr x8, [x1, #16]
	ldr x9, [x2, #16]
	ldr x10, [x1, #24]
	ldr x11, [x2, #24]
	adds x12, x4, x5
	adcs x13, x6, x7
	adcs x14, x8, x9
	adcs x15, x10, x11          /* C = 257th bit (ADD: carry-out = bit) */
	cset x4, cs
	neg  x4, x4
	LAddr x16, DELTA
	ldr x5, [x16, #0];  and x5, x5, x4
	ldr x6, [x16, #8];  and x6, x6, x4
	ldr x7, [x16, #16]; and x7, x7, x4
	ldr x8, [x16, #24]; and x8, x8, x4
	adds x12, x12, x5
	adcs x13, x13, x6
	adcs x14, x14, x7
	adcs x15, x15, x8
	LAddr x16, N_LIMBS
	ldr x4, [x16, #0];  subs x4, x12, x4
	ldr x5, [x16, #8];  sbcs x5, x13, x5
	ldr x6, [x16, #16]; sbcs x6, x14, x6
	ldr x7, [x16, #24]; sbcs x7, x15, x7  /* C=1 iff no borrow (>=n) */
	csel x12, x12, x4, cc
	csel x13, x13, x5, cc
	csel x14, x14, x6, cc
	csel x15, x15, x7, cc
	str x12, [x0, #0]
	str x13, [x0, #8]
	str x14, [x0, #16]
	str x15, [x0, #24]
	ret
	.size sc_add, .-sc_add

/* ============================================================================
 * sc_sub(r,a,b)  r=(a-b) mod n   (add n back on borrow)
 * ========================================================================== */
	.global sc_sub
	.type sc_sub, %function
sc_sub:
	ldr x4, [x1, #0]
	ldr x5, [x2, #0]
	ldr x6, [x1, #8]
	ldr x7, [x2, #8]
	ldr x8, [x1, #16]
	ldr x9, [x2, #16]
	ldr x10, [x1, #24]
	ldr x11, [x2, #24]
	subs x12, x4, x5
	sbcs x13, x6, x7
	sbcs x14, x8, x9
	sbcs x15, x10, x11          /* after sbcs: C=1 iff no borrow */
	cset x4, cc                 /* borrow */
	neg  x4, x4
	LAddr x16, N_LIMBS
	ldr x5, [x16, #0];  and x5, x5, x4
	ldr x6, [x16, #8];  and x6, x6, x4
	ldr x7, [x16, #16]; and x7, x7, x4
	ldr x8, [x16, #24]; and x8, x8, x4
	adds x12, x12, x5
	adcs x13, x13, x6
	adcs x14, x14, x7
	adcs x15, x15, x8
	str x12, [x0, #0]
	str x13, [x0, #8]
	str x14, [x0, #16]
	str x15, [x0, #24]
	ret
	.size sc_sub, .-sc_sub

/* ============================================================================
 * sc_sqr(r,a)  r=(a*a) mod n == sc_mul(r,a,a)
 * ========================================================================== */
	.global sc_sqr
	.type sc_sqr, %function
sc_sqr:
	mov x2, x1
	b   sc_mul
	.size sc_sqr, .-sc_sqr

/* ============================================================================
 * sc_mul(r,a,b)  r=(a*b) mod n
 * Frame (sp-relative): cur@0 (80B)  tmp@80 (80B)  r-save@160.
 *   x20=cur x21=tmp x22=DELTA/N scratch ; a x18, b x19. Original r saved.
 * ========================================================================== */
	.global sc_mul
	.type sc_mul, %function
sc_mul:
	stp x22, x30, [sp, #-16]!
	stp x18, x19, [sp, #-16]!
	stp x20, x21, [sp, #-16]!
	sub sp, sp, #288            /* cur@0 tmp@80 (80B each), stack slack to 288 */
	mov x18, x1                 /* a */
	mov x19, x2                 /* b */
	add x20, sp, #0             /* cur */
	add x21, sp, #80            /* tmp */
	str x0, [sp, #160]          /* save r */
	/* zero cur[0..9] */
	mov x6, xzr
	add x7, x20, #0
	mov x8, #10
1:	str x6, [x7], #8
	subs x8, x8, #1
	b.ne 1b

	/* ---- PHASE 1: 16 products into cur ---- */
	ldr x0, [x18, #0]
	ldr x1, [x19, #0]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 0, x4, x5
	ldr x1, [x19, #8]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 1, x4, x5
	ldr x1, [x19, #16]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 2, x4, x5
	ldr x1, [x19, #24]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 3, x4, x5
	ldr x0, [x18, #8]
	ldr x1, [x19, #0]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 1, x4, x5
	ldr x1, [x19, #8]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 2, x4, x5
	ldr x1, [x19, #16]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 3, x4, x5
	ldr x1, [x19, #24]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 4, x4, x5
	ldr x0, [x18, #16]
	ldr x1, [x19, #0]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 2, x4, x5
	ldr x1, [x19, #8]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 3, x4, x5
	ldr x1, [x19, #16]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 4, x4, x5
	ldr x1, [x19, #24]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 5, x4, x5
	ldr x0, [x18, #24]
	ldr x1, [x19, #0]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 3, x4, x5
	ldr x1, [x19, #8]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 4, x4, x5
	ldr x1, [x19, #16]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 5, x4, x5
	ldr x1, [x19, #24]
	mul x4, x0, x1
	umulh x5, x0, x1
	SCA_ADD x20, 6, x4, x5

	/* ---- PHASE 2: 8 FOLD rounds ---- */
	LAddr x22, DELTA
	mov x16, #8
.Lfold:
	/* zero tmp[0..9] */
	mov x7, xzr
	add x8, x21, #0
	mov x9, #10
1:	str x7, [x8], #8
	subs x9, x9, #1
	b.ne 1b
	/* tmp += cur[4+hh] * DELTA[dj] */
	mov x10, #0                  /* hh */
.Lhh:
	add x11, x20, #32            /* cur+4 */
	ldr x0, [x11, x10, lsl #3]   /* cur[4+hh] */
	mov x12, #0                  /* dj */
.Ldj:
	ldr x1, [x22, x12, lsl #3]   /* DELTA[dj] */
	mul x4, x0, x1
	umulh x5, x0, x1
	add x13, x10, x12            /* k = hh+dj */
	/* tmp[k] += lo */
	ldr x6, [x21, x13, lsl #3]
	adds x6, x6, x4
	str x6, [x21, x13, lsl #3]
	/* tmp[k+1] += hi */
	add x13, x13, #1
	ldr x6, [x21, x13, lsl #3]
	adcs x6, x6, x5
	str x6, [x21, x13, lsl #3]
	/* propagate carry to tmp[9] -- MUST NOT clobber the C flag between
	 * adcs steps (a cmp would destroy the carry and drop it at tmp[k+2]).
	 * Drive the loop with cbnz + plain sub, neither of which touch NZCV. */
	add x14, x13, #1          /* x14 = k+2 (first index to propagate) */
	mov x15, #10
	sub x15, x15, x14          /* x15 = 8-k iterations: indices k+2..9 */
.Lcar:
	ldr x6, [x21, x14, lsl #3]
	adcs x6, x6, xzr
	str x6, [x21, x14, lsl #3]
	add x14, x14, #1
	sub x15, x15, #1
	cbnz x15, .Lcar
.Lcar_done:
	add x12, x12, #1
	cmp x12, #4
	b.ne .Ldj
	add x10, x10, #1
	cmp x10, #5
	b.ne .Lhh
	/* cur[i] = tmp[i] + cur[i]  (i=0..3), carry into cur[4..9]=tmp[4..9] */
	ldr x6, [x21, #0]
	ldr x7, [x20, #0]
	adds x7, x7, x6
	str x7, [x20, #0]
	ldr x6, [x21, #8]
	ldr x7, [x20, #8]
	adcs x7, x7, x6
	str x7, [x20, #8]
	ldr x6, [x21, #16]
	ldr x7, [x20, #16]
	adcs x7, x7, x6
	str x7, [x20, #16]
	ldr x6, [x21, #24]
	ldr x7, [x20, #24]
	adcs x7, x7, x6
	str x7, [x20, #24]
	add x8, x20, #32             /* cur+4 */
	mov x9, #4
.Lup:
	ldr x6, [x21, x9, lsl #3]
	adcs x6, x6, xzr             /* tmp[i] + carry */
	str x6, [x8], #8
	add x9, x9, #1
	cmp x9, #10
	b.ne .Lup
	/* one round done */
	subs x16, x16, #1
	b.ne .Lfold

	/* ---- PHASE 3: 3 conditional n-subtractions ---- */
	LAddr x22, N_LIMBS
	mov x16, #3
.Lconds:
	ldr x4, [x20, #0]
	ldr x5, [x22, #0]
	subs x4, x4, x5
	ldr x5, [x20, #8]
	ldr x6, [x22, #8]
	sbcs x5, x5, x6
	ldr x6, [x20, #16]
	ldr x7, [x22, #16]
	sbcs x6, x6, x7
	ldr x7, [x20, #24]
	ldr x8, [x22, #24]
	sbcs x7, x7, x8              /* C=1 iff no borrow (>=n) */
	ldr x9, [x20, #0]
	csel x4, x9,  x4, cc         /* keep cur if borrow (<n) */
	ldr x9, [x20, #8]
	csel x5, x9,  x5, cc
	ldr x9, [x20, #16]
	csel x6, x9,  x6, cc
	ldr x9, [x20, #24]
	csel x7, x9,  x7, cc
	str x4, [x20, #0]
	str x5, [x20, #8]
	str x6, [x20, #16]
	str x7, [x20, #24]
	subs x16, x16, #1
	b.ne .Lconds

	/* ---- store result into r (restore saved pointer) ---- */
	ldr x0, [sp, #160]
	ldr x4, [x20, #0]
	str x4, [x0, #0]
	ldr x4, [x20, #8]
	str x4, [x0, #8]
	ldr x4, [x20, #16]
	str x4, [x0, #16]
	ldr x4, [x20, #24]
	str x4, [x0, #24]

	add sp, sp, #288
	ldp x20, x21, [sp], #16
	ldp x18, x19, [sp], #16
	ldp x22, x30, [sp], #16
	ret
	.size sc_mul, .-sc_mul

/* ============================================================================
 * sc_inv(r,a)  r = a^(n-2) mod n  (Fermat, MSB->LSB square-and-multiply over
 * the N_EXP bytes). R@sp+0 A@sp+32 ; bit counter x23, Nexp base x24 (sc_mul/
 * sc_sqr preserve x19-x28 and restore sp, and never touch x23/x24).
 * ========================================================================== */
	.global sc_inv
	.type sc_inv, %function
sc_inv:
	stp x19, x23, [sp, #-16]!
	stp x24, x30, [sp, #-16]!
	sub sp, sp, #80             /* R@0 A@32 ; 32 pushed + 80 = 112 %16==0 */
	mov x19, x0                 /* r */
	/* copy a -> R and A */
	ldr x4, [x1, #0];  str x4, [sp, #0];  str x4, [sp, #32]
	ldr x4, [x1, #8];  str x4, [sp, #8];  str x4, [sp, #40]
	ldr x4, [x1, #16]; str x4, [sp, #16]; str x4, [sp, #48]
	ldr x4, [x1, #24]; str x4, [sp, #24]; str x4, [sp, #56]
	LAddr x24, N_EXP
	mov x23, #254               /* start at bit 254 (bit 255 is the MSB, handled by R=a) */
.Linv_loop:
	/* R = R*R */
	mov x0, sp
	mov x1, sp
	bl  sc_sqr
	/* test bit x23 of N_EXP */
	lsr x13, x23, #3
	and x14, x23, #7
	ldrb w12, [x24, x13]
	lsr w12, w12, w14
	tst x12, #1
	b.eq .Linv_next
	/* R = R*A */
	mov x0, sp
	mov x1, sp
	add x2, sp, #32
	bl  sc_mul
.Linv_next:
	subs x23, x23, #1
	b.ge .Linv_loop              /* iterate 254..0 */
	/* copy R -> r */
	ldr x4, [sp, #0];  str x4, [x19, #0]
	ldr x4, [sp, #8];  str x4, [x19, #8]
	ldr x4, [sp, #16]; str x4, [x19, #16]
	ldr x4, [sp, #24]; str x4, [x19, #24]
	add sp, sp, #80
	ldp x24, x30, [sp], #16
	ldp x19, x23, [sp], #16
	ret
	.size sc_inv, .-sc_inv

	.section .rodata
	.p2align 4
N_LIMBS:
	.quad 0xBFD25E8CD0364141
	.quad 0xBAAEDCE6AF48A03B
	.quad 0xFFFFFFFFFFFFFFFE
	.quad 0xFFFFFFFFFFFFFFFF
	.p2align 4
DELTA:
	.quad 0x402DA1732FC9BEBF
	.quad 0x4551231950B75FC4
	.quad 0x0000000000000001
	.quad 0x0000000000000000
	.p2align 4
N_EXP:
	.byte 0x3f,0x41,0x36,0xd0,0x8c,0x5e,0xd2,0xbf
	.byte 0x3b,0xa0,0x48,0xaf,0xe6,0xdc,0xae,0xba
	.byte 0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	.byte 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff

/* ============================================================================
 * int sc_inv_var(r[4]=x0, a[4]=x1) : r = a^{-1} mod n  -- VARIABLE-TIME
 *   Binary extended GCD (Stein): invariants bx1*a==u, bx2*a==v mod n.
 *   Start u=a, v=n, bx1=1, bx2=0. Strip powers of 2 (halving u/bx1 then
 *   v/bx2 mod n); both odd -> subtract smaller from larger (and x's mod n via
 *   sc_sub); difference is even -> next strip. Ends u==1 (ans bx1) or v==1
 *   (ans bx2). Returns w0=1 (r written) or w0=0 (a==0). PUBLIC-scalar only
 *   (signing uses sc_inv, the constant-time Fermat). Calls sc_sub (leaf,
 *   preserves x19+). Frame: u@sp+0 v@sp+32 bx1@sp+64 bx2@sp+96.
 *   Helpers .Lf_shr1 and .Lf_halve are reachable only via bl.
 * ========================================================================== */
	.global sc_inv_var
	.type   sc_inv_var, %function
sc_inv_var:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	sub  sp, sp, #128
	mov  x19, x0                 /* out (persistent across sc_sub) */

	/* a == 0 -> fail */
	ldr  x4, [x1, #0]
	ldr  x5, [x1, #8]
	orr  x4, x4, x5
	ldr  x5, [x1, #16]
	orr  x4, x4, x5
	ldr  x5, [x1, #24]
	orr  x4, x4, x5
	cbz  x4, .Lf_fail

	/* u=a v=n bx1=1 bx2=0 */
	ldr  x4, [x1, #0]
	ldr  x5, [x1, #8]
	ldr  x6, [x1, #16]
	ldr  x7, [x1, #24]
	str  x4, [sp, #0]
	str  x5, [sp, #8]
	str  x6, [sp, #16]
	str  x7, [sp, #24]
	LAddr x4, N_LIMBS
	ldr  x5, [x4, #0]
	ldr  x6, [x4, #8]
	ldr  x7, [x4, #16]
	ldr  x8, [x4, #24]
	str  x5, [sp, #32]
	str  x6, [sp, #40]
	str  x7, [sp, #48]
	str  x8, [sp, #56]
	mov  x5, #1
	str  x5, [sp, #64]
	str  xzr, [sp, #72]
	str  xzr, [sp, #80]
	str  xzr, [sp, #88]
	str  xzr, [sp, #96]
	str  xzr, [sp, #104]
	str  xzr, [sp, #112]
	str  xzr, [sp, #120]

.Lf_loop:
	/* u == 1 ? (u0==1, u1..u3==0) -> ret bx1 */
	ldr  x4, [sp, #0]
	cmp  x4, #1
	b.ne .Lf_chkv
	ldr  x5, [sp, #8]
	ldr  x6, [sp, #16]
	orr  x5, x5, x6
	ldr  x6, [sp, #24]
	orr  x5, x5, x6
	cbz  x5, .Lf_retx1
.Lf_chkv:
	/* v == 1 ? -> ret bx2 */
	ldr  x4, [sp, #32]
	cmp  x4, #1
	b.ne .Lf_stripu
	ldr  x5, [sp, #40]
	ldr  x6, [sp, #48]
	orr  x5, x5, x6
	ldr  x6, [sp, #56]
	orr  x5, x5, x6
	cbz  x5, .Lf_retx2
.Lf_stripu:
	ldr  x4, [sp, #0]
	tst  x4, #1
	b.ne .Lf_stripv
	mov  x0, sp
	bl   .Lf_shr1
	add  x0, sp, #64
	bl   .Lf_halve
	b    .Lf_stripu
.Lf_stripv:
	ldr  x4, [sp, #32]
	tst  x4, #1
	b.ne .Lf_cmp
	add  x0, sp, #32
	bl   .Lf_shr1
	add  x0, sp, #96
	bl   .Lf_halve
	b    .Lf_stripv

.Lf_cmp:
	/* u >= v ? (compare top limb down); v remaining when u < v */
	ldr  x4, [sp, #24]
	ldr  x5, [sp, #56]
	cmp  x4, x5
	b.lo .Lf_vbig
	b.hi .Lf_ubig
	ldr  x4, [sp, #16]
	ldr  x5, [sp, #48]
	cmp  x4, x5
	b.lo .Lf_vbig
	b.hi .Lf_ubig
	ldr  x4, [sp, #8]
	ldr  x5, [sp, #40]
	cmp  x4, x5
	b.lo .Lf_vbig
	b.hi .Lf_ubig
	ldr  x4, [sp, #0]
	ldr  x5, [sp, #32]
	cmp  x4, x5
	b.lo .Lf_vbig
.Lf_ubig:
	/* u -= v */
	ldr  x4, [sp, #0]
	ldr  x5, [sp, #32]
	subs x4, x4, x5
	str  x4, [sp, #0]
	ldr  x5, [sp, #40]
	ldr  x6, [sp, #8]
	sbcs x6, x6, x5
	str  x6, [sp, #8]
	ldr  x5, [sp, #48]
	ldr  x6, [sp, #16]
	sbcs x6, x6, x5
	str  x6, [sp, #16]
	ldr  x5, [sp, #56]
	ldr  x6, [sp, #24]
	sbcs x6, x6, x5
	str  x6, [sp, #24]
	/* bx1 = sc_sub(bx1, bx2) */
	add  x0, sp, #64
	mov  x1, x0
	add  x2, sp, #96
	bl   sc_sub
	b    .Lf_loop
.Lf_vbig:
	/* v -= u */
	ldr  x4, [sp, #32]
	ldr  x5, [sp, #0]
	subs x4, x4, x5
	str  x4, [sp, #32]
	ldr  x5, [sp, #8]
	ldr  x6, [sp, #40]
	sbcs x6, x6, x5
	str  x6, [sp, #40]
	ldr  x5, [sp, #16]
	ldr  x6, [sp, #48]
	sbcs x6, x6, x5
	str  x6, [sp, #48]
	ldr  x5, [sp, #24]
	ldr  x6, [sp, #56]
	sbcs x6, x6, x5
	str  x6, [sp, #56]
	/* bx2 = sc_sub(bx2, bx1) */
	add  x0, sp, #96
	mov  x1, x0
	add  x2, sp, #64
	bl   sc_sub
	b    .Lf_loop

.Lf_retx1:
	add  x0, sp, #64
	b    .Lf_store
.Lf_retx2:
	add  x0, sp, #96
.Lf_store:
	mov  x2, x19
	ldp  x4, x5,  [x0]
	ldp  x6, x7,  [x0, #16]
	stp  x4, x5,  [x2]
	stp  x6, x7,  [x2, #16]
	mov  w0, #1
	b    .Lf_out
.Lf_fail:
	mov  w0, #0
.Lf_out:
	add  sp, sp, #128
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size sc_inv_var, .-sc_inv_var

/* .Lf_shr1(x0)  : [x0] 4 limbs >>= 1 (plain). Uses x4-x13 only. */
.Lf_shr1:
	ldr  x4, [x0, #0]
	ldr  x5, [x0, #8]
	ldr  x6, [x0, #16]
	ldr  x7, [x0, #24]
	lsr  x8, x4, #1
	lsl  x9, x5, #63
	orr  x8, x8, x9
	lsr  x9, x5, #1
	lsl  x10, x6, #63
	orr  x9, x9, x10
	lsr  x10, x6, #1
	lsl  x11, x7, #63
	orr  x10, x10, x11
	lsr  x11, x7, #1
	str  x8,  [x0, #0]
	str  x9,  [x0, #8]
	str  x10, [x0, #16]
	str  x11, [x0, #24]
	ret

/* .Lf_halve(x0) : [x0] (in [0,n)) /= 2 mod n. odd: (x+n)>>1 w/ carry-in bit.
   Uses x4-x13 only. */
.Lf_halve:
	ldr  x4, [x0, #0]
	ldr  x5, [x0, #8]
	ldr  x6, [x0, #16]
	ldr  x7, [x0, #24]
	tst  x4, #1
	b.eq .Lf_hm
	LAddr x9, N_LIMBS
	ldr  x10, [x9, #0]
	ldr  x11, [x9, #8]
	ldr  x12, [x9, #16]
	ldr  x13, [x9, #24]
	adds x4, x4, x10
	adcs x5, x5, x11
	adcs x6, x6, x12
	adcs x7, x7, x13
	adc  x8, xzr, xzr          /* x8 = bit 256 of x+n */
	lsr  x9, x4, #1
	lsl  x10, x5, #63
	orr  x9, x9, x10
	lsr  x10, x5, #1
	lsl  x11, x6, #63
	orr  x10, x10, x11
	lsr  x11, x6, #1
	lsl  x12, x7, #63
	orr  x11, x11, x12
	lsr  x12, x7, #1
	lsl  x13, x8, #63
	orr  x12, x12, x13
	str  x9,  [x0, #0]
	str  x10, [x0, #8]
	str  x11, [x0, #16]
	str  x12, [x0, #24]
	ret
.Lf_hm:
	lsr  x8, x4, #1
	lsl  x9, x5, #63
	orr  x8, x8, x9
	lsr  x9, x5, #1
	lsl  x10, x6, #63
	orr  x9, x9, x10
	lsr  x10, x6, #1
	lsl  x11, x7, #63
	orr  x10, x10, x11
	lsr  x11, x7, #1
	str  x8,  [x0, #0]
	str  x9,  [x0, #8]
	str  x10, [x0, #16]
	str  x11, [x0, #24]
	ret

	.section .note.GNU-stack,"",%progbits
