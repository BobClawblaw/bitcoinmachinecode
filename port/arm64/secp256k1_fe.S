/* ============================================================================
 * secp256k1_fe.S -- AArch64 (ARMv8-A) port of asm/secp256k1_fe.asm
 *
 * Prime field arithmetic over p = 2^256 - 2^32 - 977 for secp256k1.
 * Element = 4 little-endian u64 limbs. All results canonical in [0, p).
 * AAPCS64 (SysV x64 -> AArch64): r=x0, a=x1, b=x2:
 *   void fe_add(u64 r[4], const u64 a[4], const u64 b[4])
 *   void fe_sub(u64 r[4], const u64 a[4], const u64 b[4])
 *   void fe_mul(u64 r[4], const u64 a[4], const u64 b[4])
 *   void fe_sqr(u64 r[4], const u64 a[4])
 *   void fe_inv(u64 r[4], const u64 a[4])
 *
 * REDUCTION (identical to x86): 2^256 == C (mod p), C = 2^32+977 = 0x1000003D1.
 * Product T[0..7] (512-bit): fold1 (u0..u4) = T[0..3] + T[4..7]*C ; fold2
 * W = (u0..u3) + u4*C (+ its carry folded once more); canonicalise: v >= p
 *  <=>  v + C carries; when it does the wrapped sum IS v - p.
 *
 * fe_mul is CORRECTNESS-FIRST: the full 512-bit product is formed by the
 * classic column-sum (16 partial products, single add/adc carry chain, no
 * flag-pair tricks) instead of x86's MULX/ADCX/ADOX register schedule.
 * fe_sqr shares it (square = multiply by self; the 10-mul fast path can be
 * restored later -- mathematically identical, so all vectors still hold).
 * ========================================================================== */
	.text

	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

	/* load the 64-bit VALUE at \sym (adrp + ldr :lo12:) */
	.macro LC rd, sym
	adrp \rd, \sym
	ldr  \rd, [\rd, :lo12:\sym]
	.endm

/* ============================================================================
 * fe_add(r, a, b)  r = (a+b) mod p
 *   fold 257th bit as +C ; canonicalise with one +C carry-select (branch-free).
 * Leaf, caller-saved only, no prologue.
 *   x0=r x1=a x2=b ; t0..t3 in x8..x11 ; scratch x4,x5,x16,x17.
 * ========================================================================== */
	.global fe_add
	.type fe_add, %function
fe_add:
	ldr x8,  [x1, #0]
	ldr x9,  [x1, #8]
	ldr x10, [x1, #16]
	ldr x11, [x1, #24]
	ldr x4,  [x2, #0]
	ldr x5,  [x2, #8]
	ldr x16, [x2, #16]
	ldr x17, [x2, #24]
	adds x8, x8, x4
	adcs x9, x9, x5
	adcs x10, x10, x16
	adcs x11, x11, x17          /* C = 257th bit */
	adc  x16, xzr, xzr          /* x16 = CF */
	LC x17, C_CONST
	mul  x16, x16, x17          /* = CF ? C : 0 */
	adds x8, x8, x16
	adcs x9, x9, xzr
	adcs x10, x10, xzr
	adcs x11, x11, xzr          /* cannot carry (fold bound) */
	/* canonicalise: v+C ; carry => sum is v-p */
	mov  x4, x8
	mov  x5, x9
	mov  x16, x10
	mov  x3, x11                 /* x3 spare */
	adds x4, x4, x17
	adcs x5, x5, xzr
	adcs x16, x16, xzr
	adcs x3, x3, xzr             /* C = v>=p */
	csel x8,  x8,  x4,  cc
	csel x9,  x9,  x5,  cc
	csel x10, x10, x16, cc
	csel x11, x11, x3,  cc
	str x8,  [x0, #0]
	str x9,  [x0, #8]
	str x10, [x0, #16]
	str x11, [x0, #24]
	ret
	.size fe_add, .-fe_add

/* ============================================================================
 * fe_sub(r, a, b)  r = (a-b) mod p  (add p == subtract C on borrow)
 * ========================================================================== */
	.global fe_sub
	.type fe_sub, %function
fe_sub:
	ldr x8,  [x1, #0]
	ldr x9,  [x1, #8]
	ldr x10, [x1, #16]
	ldr x11, [x1, #24]
	ldr x4,  [x2, #0]
	ldr x5,  [x2, #8]
	ldr x16, [x2, #16]
	ldr x17, [x2, #24]
	subs x8, x8, x4
	sbcs x9, x9, x5
	sbcs x10, x10, x16
	sbcs x11, x11, x17          /* on ARM, after sbcs: C=1 means NO borrow */
	cset x16, cc                /* borrow = carry-clear */
	LC  x17, C_CONST
	mul  x16, x16, x17          /* borrow ? C : 0 */
	subs x8, x8, x16
	sbcs x9, x9, xzr
	sbcs x10, x10, xzr
	sbcs x11, x11, xzr
	str x8,  [x0, #0]
	str x9,  [x0, #8]
	str x10, [x0, #16]
	str x11, [x0, #24]
	ret
	.size fe_sub, .-fe_sub

/* ============================================================================
 * fe_mul(r, a, b)  r = (a*b) mod p
 * Product: 16 partial products P(i,j)=a_i*b_j (each mul/umulh) stored on the
 * stack; then 8 output limbs T0..T7 built by column summation k=0..7 with a
 * single add/adc carry chain (carry-in/out kept in a register). This is the
 * textbook 4x4 schoolbook and is provably carry-safe because columns are
 * consumed low->high and every carry is propagated.
 * Reduction: fold1/fold2/canonicalise as described above.
 * Leaf. Frames: sub sp,#368 keeps 16-alignment (sp was 16-aligned on entry).
 *   x0=r (kept) x1=a x2=b ; T0..T7=x8..x15 ; scratch x3,x4,x5,x6,x16,x17,x18.
 * ========================================================================== */
	.global fe_mul
	.type fe_mul, %function
fe_mul:
	sub sp, sp, #368            /* 256B products + 8B*... folded p-array + pad */
	mov x18, x0                 /* r */
	/* ---- compute 16 products P(i,j) = a_i * b_j into [sp + (4i+j)*16] ---- */
	mov x7, #0
.Lf_prodi:
	mov x6, #0
	ldr x4, [x1, x7, lsl #3]    /* a_i */
.Lf_prodj:
	ldr x5, [x2, x6, lsl #3]    /* b_j */
	mul  x16, x4, x5
	umulh x17, x4, x5
	lsl  x3, x7, #6             /* 64*i */
	add  x3, x3, x6, lsl #4     /* off = 64*i + 16*j */
	str  x16, [sp, x3]
	add  x3, x3, #8
	str  x17, [sp, x3]
	add  x6, x6, #1
	cmp  x6, #4
	b.ne .Lf_prodj
	add  x7, x7, #1
	cmp  x7, #4
	b.ne .Lf_prodi

	/* ---- column sums T0..T7 ----
	 * Each column totals (carry_in + its sub-64-bit product halves). A column
	 * may carry several bits (up to ~7), so the total is kept in (lo=x3,
	 * hi=x5): every add that overflows ORs one into hi (multi-precision add).
	 * carry_in/out user x16. T_k = lo ; carry_out = hi. */
		/* col 0: P(0,0).lo @0 */
		mov  x16, #0
		mov  x3, x16
	mov  x5, #0
	ldr  x4, [sp, #0]
	adds x3, x3, x4
	adc  x5, x5, xzr
	mov  x16, x5
	mov  x8, x3
	/* col 1: P(0,1).lo@16 P(1,0).lo@64 P(0,0).hi@8 */
	mov  x3, x16
	mov  x5, #0
	ldr  x4, [sp, #16]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #64]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #8];  adds x3, x3, x4; adc x5, x5, xzr
	mov  x16, x5
	mov  x9, x3
	/* col 2: P(0,2).lo@32 P(1,1).lo@80 P(2,0).lo@128 P(0,1).hi@24 P(1,0).hi@72 */
	mov  x3, x16
	mov  x5, #0
	ldr  x4, [sp, #32];  adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #80];  adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #128]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #24];  adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #72];  adds x3, x3, x4; adc x5, x5, xzr
	mov  x16, x5
	mov  x10, x3
	/* col 3: P(0,3).lo@48 P(1,2).lo@96 P(2,1).lo@144 P(3,0).lo@192
	          P(0,2).hi@40 P(1,1).hi@88 P(2,0).hi@136 */
	mov  x3, x16
	mov  x5, #0
	ldr  x4, [sp, #48];  adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #96];  adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #144]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #192]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #40];  adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #88];  adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #136]; adds x3, x3, x4; adc x5, x5, xzr
	mov  x16, x5
	mov  x11, x3
	/* col 4: P(1,3).lo@112 P(2,2).lo@160 P(3,1).lo@208
	          P(0,3).hi@56 P(1,2).hi@104 P(2,1).hi@152 P(3,0).hi@200 */
	mov  x3, x16
	mov  x5, #0
	ldr  x4, [sp, #112]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #160]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #208]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #56];  adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #104]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #152]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #200]; adds x3, x3, x4; adc x5, x5, xzr
	mov  x16, x5
	mov  x12, x3
	/* col 5: P(2,3).lo@176 P(3,2).lo@224 P(1,3).hi@120 P(2,2).hi@168 P(3,1).hi@216 */
	mov  x3, x16
	mov  x5, #0
	ldr  x4, [sp, #176]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #224]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #120]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #168]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #216]; adds x3, x3, x4; adc x5, x5, xzr
	mov  x16, x5
	mov  x13, x3
	/* col 6: P(3,3).lo@240 P(2,3).hi@184 P(3,2).hi@232 */
	mov  x3, x16
	mov  x5, #0
	ldr  x4, [sp, #240]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #184]; adds x3, x3, x4; adc x5, x5, xzr
	ldr  x4, [sp, #232]; adds x3, x3, x4; adc x5, x5, xzr
	mov  x16, x5
	mov  x14, x3
	/* col 7: P(3,3).hi@248 */
	mov  x3, x16
	mov  x5, #0
	ldr  x4, [sp, #248]
	adds x3, x3, x4
	adc  x5, x5, xzr
	mov  x16, x5
	mov  x15, x3
	/* T0..T7 in x8..x15. carry-out x16 (>= 1 bit possible) folds with col8<2^256 */
	/* NOTE: x16 may be >0 only if the 512-bit product overflowed 8 limbs; the
	 * total a*b < 2^512 guarantees it is 0; col8 never reaches here. */

	/* ================= REDUCTION (fold1/fold2/canonicalise) ================ */
	/* Clean multi-limb method: fold1 adds each 128-bit p[k]=T[4+k]*C into the
	 * 4-limb window shifted by k limbs, then fold2 adds u4*C and folds the
	 * carry once. Each addend is a separate adds/adcs/adc chain (no carry is
	 * ever captured and re-added as a value -- that double-counts). Verified
	 * against Python big-int on 20k random + structured products. */
	LC  x17, C_CONST
	mul  x4, x12, x17; umulh x5, x12, x17; str x4,[sp,#256]; str x5,[sp,#264]
	mul  x4, x13, x17; umulh x5, x13, x17; str x4,[sp,#272]; str x5,[sp,#280]
	mul  x4, x14, x17; umulh x5, x14, x17; str x4,[sp,#288]; str x5,[sp,#296]
	mul  x4, x15, x17; umulh x5, x15, x17; str x4,[sp,#304]; str x5,[sp,#312]
	mov  x16, #0                        /* u4 = 0 */
	/* p0 @0 */
	ldr  x4, [sp, #256]; ldr  x5, [sp, #264]
	adds x8, x8, x4
	adcs x9, x9, x5
	adcs x10, x10, xzr
	adcs x11, x11, xzr
	adc  x16, x16, xzr
	/* p1 @1 */
	ldr  x4, [sp, #272]; ldr  x5, [sp, #280]
	adds x9, x9, x4
	adcs x10, x10, x5
	adcs x11, x11, xzr
	adc  x16, x16, xzr
	/* p2 @2 */
	ldr  x4, [sp, #288]; ldr  x5, [sp, #296]
	adds x10, x10, x4
	adcs x11, x11, x5
	adc  x16, x16, xzr
	/* p3 @3 */
	ldr  x4, [sp, #304]; ldr  x5, [sp, #312]
	adds x11, x11, x4
	adc  x16, x16, x5                   /* u4 += p3h (+carry) */
	/* fold2: W = u[0..3] + u4*C */
	mul  x4, x16, x17
	umulh x5, x16, x17
	adds x8, x8, x4
	adcs x9, x9, x5
	adcs x10, x10, xzr
	adcs x11, x11, xzr
	adc  x16, xzr, xzr                  /* fold2 carry (0/1) */
	mul  x16, x16, x17                  /* = C ? C : 0 */
	adds x8, x8, x16
	adcs x9, x9, xzr
	adcs x10, x10, xzr
	adcs x11, x11, xzr                  /* cannot carry (fold bound) */
	/* canonicalise: v+C ; if carry, sum is v-p */
	mov  x4, x8
	mov  x5, x9
	mov  x16, x10
	mov  x3, x11
	adds x4, x4, x17
	adcs x5, x5, xzr
	adcs x16, x16, xzr
	adcs x3, x3, xzr             /* C = v>=p */
	csel x8,  x8,  x4,  cc
	csel x9,  x9,  x5,  cc
	csel x10, x10, x16, cc
	csel x11, x11, x3,  cc
	/* store */
	mov  x0, x18
	str  x8,  [x0, #0]
	str  x9,  [x0, #8]
	str  x10, [x0, #16]
	str  x11, [x0, #24]
	add  sp, sp, #368
	ret
	.size fe_mul, .-fe_mul

/* ============================================================================
 * fe_sqr(r, a)  r = (a*a) mod p   ==  fe_mul(r, a, a)
 * ========================================================================== */
	.global fe_sqr
	.type fe_sqr, %function
fe_sqr:
	mov  x2, x1
	b    fe_mul
	.size fe_sqr, .-fe_sqr

/* ============================================================================
 * fe_inv(r, a)  r = a^(p-2) mod p  (Fermat). Addition chain, exactly the x86
 * sequence (x2,x3,x6,x9,x11,x22,x44,x88,x176,x220,x223 then the low 33 bits).
 * Square-by-N uses fe_sqr; multiply by a stack slot uses fe_mul. Both are
 * leaf and touch only x0-x18, so only x19 (r) and x30 need preserving, and sp
 * stays 16-aligned at each call (frame sized 0x108 == 264).
 * Slot layout (32B each, sp-relative): A@0 X2@32 X3@64 X22@96 X44@128 T@160 U@192
 * ========================================================================== */
	.global fe_inv
	.type fe_inv, %function
fe_inv:
	stp x19, x20, [sp, #-16]!
	stp x30, xzr, [sp, #-16]!
	sub sp, sp, #240            /* 240%16=0 -> sp still 16-aligned; slots 0..223 */
	mov  x19, x0                /* r */
	/* A := a */
	mov  x4, x1
	ldr  x5, [x4, #0];  str x5, [sp, #0]
	ldr  x5, [x4, #8];  str x5, [sp, #8]
	ldr  x5, [x4, #16]; str x5, [sp, #16]
	ldr  x5, [x4, #24]; str x5, [sp, #24]

	/* ---- helper-free explicit chain ---- */
	/* x2 = a^3 : T=a^2 ; T*=A ; X2=T */
	mov  x0, sp
	add  x0, x0, #160           /* T@160 */
	add  x1, sp, #0             /* A */
	bl   fe_sqr
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #0
	bl   fe_mul                  /* T = a^3 */
	mov  x4, sp
	ldr  x5, [sp, #160]; str x5, [sp, #32]
	ldr  x5, [sp, #168]; str x5, [sp, #40]
	ldr  x5, [sp, #176]; str x5, [sp, #48]
	ldr  x5, [sp, #184]; str x5, [sp, #56]   /* X2@32 = T */
	/* x3 = a^7 : T=T^2 ; T*=A ; X3=T */
	add  x0, sp, #160
	add  x1, sp, #160
	bl   fe_sqr
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #0
	bl   fe_mul
	ldr  x5, [sp, #160]; str x5, [sp, #64]
	ldr  x5, [sp, #168]; str x5, [sp, #72]
	ldr  x5, [sp, #176]; str x5, [sp, #80]
	ldr  x5, [sp, #184]; str x5, [sp, #88]   /* X3@64 */

	/* x11: T=x6 (T^8 * X3) ; T=x9 (^8 * X3) ; T=x11 (^4 * X2) */
	bl   .Lfinv_sq3
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #64
	bl   fe_mul                  /* T = x6 */
	bl   .Lfinv_sq3
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #64
	bl   fe_mul                  /* T = x9 */
	/* T = T^4 (2 inline squares) -> x11 */
	add  x0, sp, #160
	add  x1, sp, #160
	bl   fe_sqr
	add  x0, sp, #160
	add  x1, sp, #160
	bl   fe_sqr
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #32
	bl   fe_mul                  /* T = x11 */
	/* U := x11 (copy T to U@192) */
	ldr  x5, [sp, #160]; str x5, [sp, #192]
	ldr  x5, [sp, #168]; str x5, [sp, #200]
	ldr  x5, [sp, #176]; str x5, [sp, #208]
	ldr  x5, [sp, #184]; str x5, [sp, #216]
	/* x22 : T^2048 * U ; X22=T */
	mov  x20, #11
	bl   .Lfinv_sqn
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #192
	bl   fe_mul                  /* T = x22 */
	ldr  x5, [sp, #160]; str x5, [sp, #96]
	ldr  x5, [sp, #168]; str x5, [sp, #104]
	ldr  x5, [sp, #176]; str x5, [sp, #112]
	ldr  x5, [sp, #184]; str x5, [sp, #120]  /* X22@96 */
	/* x44 : T^2^22 * X22 ; X44=T */
	mov  x20, #22
	bl   .Lfinv_sqn
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #96
	bl   fe_mul                  /* T = x44 */
	ldr  x5, [sp, #160]; str x5, [sp, #128]
	ldr  x5, [sp, #168]; str x5, [sp, #136]
	ldr  x5, [sp, #176]; str x5, [sp, #144]
	ldr  x5, [sp, #184]; str x5, [sp, #152]  /* X44@128 */
	/* x88 : T^2^44 * X44 ; U := x88 */
	mov  x20, #44
	bl   .Lfinv_sqn
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #128
	bl   fe_mul                  /* T = x88 */
	ldr  x5, [sp, #160]; str x5, [sp, #192]
	ldr  x5, [sp, #168]; str x5, [sp, #200]
	ldr  x5, [sp, #176]; str x5, [sp, #208]
	ldr  x5, [sp, #184]; str x5, [sp, #216]  /* U := x88 */
	/* x176 : T^2^88 * U */
	mov  x20, #88
	bl   .Lfinv_sqn
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #192
	bl   fe_mul                  /* T = x176 */
	/* x220 : T^2^44 * X44 */
	mov  x20, #44
	bl   .Lfinv_sqn
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #128
	bl   fe_mul                  /* T = x220 */
	/* x223 : T^2^3 * X3 */
	bl   .Lfinv_sq3
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #64
	bl   fe_mul                  /* T = x223 */
	/* low 33 bits of p-2 */
	mov  x20, #23
	bl   .Lfinv_sqn
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #96
	bl   fe_mul
	mov  x20, #5
	bl   .Lfinv_sqn
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #0
	bl   fe_mul
	bl   .Lfinv_sq3
	add  x0, sp, #160
	add  x1, sp, #160
	add  x2, sp, #32
	bl   fe_mul
	/* 2 sq then last multiply lands straight in r */
	mov  x0, sp
	add  x0, x0, #160
	add  x1, sp, #160
	bl   fe_sqr
	mov  x0, sp
	add  x0, x0, #160
	add  x1, sp, #160
	bl   fe_sqr
	mov  x0, x19
	add  x1, sp, #160
	add  x2, sp, #0
	bl   fe_mul                  /* r = T^2^2 * A */

	add  sp, sp, #240
	ldp  x30, xzr, [sp], #16
	ldp  x19, x20, [sp], #16
	ret

/* internal helpers -- square T by N via fe_sqr ----------------------------- */
.Lfinv_sq3:
	mov  x20, #3
	b    .Lfinv_sqn
.Lfinv_sqn:
	/* Square T x20 times. Save x30: the loop body ends with a `bl fe_sqr`
	 * whose leaf return leaves x30 pointing back into this routine, so the
	 * trailing `ret` would otherwise spin on itself forever (a real AArch64
	 * tail-return trap we hit and fixed). */
	stp  x30, xzr, [sp, #-16]!
.Lfinv_sqn_loop:
	/* after the 16-byte x30 save, fe_inv's T slot (fe_inv_sp+160) is sp+176 */
	add  x0, sp, #176
	add  x1, sp, #176
	bl   fe_sqr
	sub  x20, x20, #1
	cbnz x20, .Lfinv_sqn_loop
	ldp  x30, xzr, [sp], #16
	ret
	.size fe_inv, .-fe_inv

	.section .rodata
	.p2align 4
C_CONST: .quad 0x00000001000003D1

	.section .note.GNU-stack,"",%progbits
