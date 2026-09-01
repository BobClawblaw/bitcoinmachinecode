/* ============================================================================
 * secp256k1_ecdsa.S -- AArch64 (ARMv8-A) port of asm/secp256k1_ecdsa.asm
 *
 * ECDSA verification (verify-only) over secp256k1, identical exported symbols:
 *   int ecdsa_x_eq_mod_n(const u64 r[4], const u64 X[4], const u64 Z[4])
 *       1 iff x(X:Z) == r (mod n), decided PROJJECTIVELY (no fe_inv):
 *       t = r*Z^2 (mod p); t==X -> 1; if r>=p-n -> 0; t=(r+n)*Z^2; t==X -> 1
 *   int ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
 *                     const u64 Qx[4], const u64 Qy[4])
 *   returns 1 iff (r,s) valid ECDSA sig of hash z under pubkey Q=(Qx,Qy).
 *       1<=r,s<n ; w=s^{-1} mod n (sc_inv_var, variable-time; s is public);
 *       u1=z*w u2=r*w mod n ; P=u1*G+u2*Q ; !inf ; x(P)==r mod n.
 *
 * GLV (matches x86): u2*Q goes through bmc_ecdsa_glv_enabled() and
 * point_scalar_mul_glv when GLV is on (the default; BMC_ECDSA_GLV=0 routes
 * to point_scalar_mul). GLV is a VARIABLE-TIME PERFORMANCE path that itself
 * falls back to point_scalar_mul when its split's identity check fails. The
 * port deferred this until point_scalar_mul_glv was gated natively
 * (secp256k1_glv_mul.S: test_glv_pointmul 102056/102056 differential vs
 * point_scalar_mul, x 3 seeds); the dispatch is now byte-for-byte the x86's.
 *
 * AAPCS64: args x0..x4. Calls sc_inv_var/sc_mul (scalar.S),
 * point_scalar_mul/point_scalar_mul_fixed/point_add (point.S),
 * point_scalar_mul_glv (glv_mul.S), bmc_ecdsa_glv_enabled (glv_c.c),
 * fe_mul/fe_sqr (fe.S) -- all preserve x19+ (the C call preserves by ABI). Frame (sp-relative): s@+0 w@+32 u1@+64 u2@+96 Q@+128(8)
 * P1@+192(12) P2@+288(12) P@+384(12); sub 480.
 * ========================================================================== */
	.text
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

	.section .rodata
	.balign 16
N_LIMBS:
	.quad 0xBFD25E8CD0364141
	.quad 0xBAAEDCE6AF48A03B
	.quad 0xFFFFFFFFFFFFFFFE
	.quad 0xFFFFFFFFFFFFFFFF
	.balign 16
/* p - n = 0x14551231950b75fc4402da1722fc9baee */
PMN_LIMBS:
	.quad 0x402DA1722FC9BAEE
	.quad 0x4551231950B75FC4
	.quad 0x0000000000000001
	.quad 0x0000000000000000
	.text

/* ---- ecdsa_in_range(x0) : w0 = 1 iff x[0..3] strictly in (0, N). Local. */
ecdsa_in_range:
	ldr  x3, [x0, #0]
	ldr  x4, [x0, #8]
	orr  x3, x3, x4
	ldr  x4, [x0, #16]
	orr  x3, x3, x4
	ldr  x4, [x0, #24]
	orr  x3, x3, x4
	cbz  x3, .Lr_no
	LAddr x5, N_LIMBS
	ldr  x4, [x0, #24]
	ldr  x6, [x5, #24]
	cmp  x4, x6
	b.hi .Lr_no
	b.lo .Lr_yes
	ldr  x4, [x0, #16]
	ldr  x6, [x5, #16]
	cmp  x4, x6
	b.hi .Lr_no
	b.lo .Lr_yes
	ldr  x4, [x0, #8]
	ldr  x6, [x5, #8]
	cmp  x4, x6
	b.hi .Lr_no
	b.lo .Lr_yes
	ldr  x4, [x0, #0]
	ldr  x6, [x5, #0]
	cmp  x4, x6
	b.hi .Lr_no
.Lr_no:
	mov  w0, #0
	ret
.Lr_yes:
	mov  w0, #1
	ret

/* ============================================================================
 * ecdsa_x_eq_mod_n(x0=r, x1=X, x2=Z)
 * ========================================================================== */
	.global ecdsa_x_eq_mod_n
	.type   ecdsa_x_eq_mod_n, %function
ecdsa_x_eq_mod_n:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #96            /* z2@+0 t@+32 rn@+64 */
	mov  x19, x0                /* r */
	mov  x20, x1                /* X */
	mov  x21, x2                /* Z */
	/* z2 = Z*Z -> sp+0 */
	mov  x0, sp
	mov  x1, x21
	bl   fe_sqr
	/* t = r * z2 -> sp+32 */
	add  x0, sp, #32
	mov  x1, x19
	mov  x2, sp
	bl   fe_mul
	/* ---- compare t(@sp+32) vs X (x20) ---- */
	add  x3, sp, #32
	ldr  x4, [x3, #0]
	ldr  x5, [x20, #0]
	cmp  x4, x5
	b.ne .Lx_second
	ldr  x4, [x3, #8]
	ldr  x5, [x20, #8]
	cmp  x4, x5
	b.ne .Lx_second
	ldr  x4, [x3, #16]
	ldr  x5, [x20, #16]
	cmp  x4, x5
	b.ne .Lx_second
	ldr  x4, [x3, #24]
	ldr  x5, [x20, #24]
	cmp  x4, x5
	b.ne .Lx_second
	mov  w0, #1
	b    .Lx_out
.Lx_second:
	/* r < p-n ? (strict) */
	LAddr x5, PMN_LIMBS
	ldr  x4, [x19, #24]
	ldr  x6, [x5, #24]
	cmp  x4, x6
	b.hi .Lx_no
	b.lo .Lx_lt
	ldr  x4, [x19, #16]
	ldr  x6, [x5, #16]
	cmp  x4, x6
	b.hi .Lx_no
	b.lo .Lx_lt
	ldr  x4, [x19, #8]
	ldr  x6, [x5, #8]
	cmp  x4, x6
	b.hi .Lx_no
	b.lo .Lx_lt
	ldr  x4, [x19, #0]
	ldr  x6, [x5, #0]
	cmp  x4, x6
	b.hs .Lx_no
.Lx_lt:
	/* rn = r + n -> sp+64  (no carry out: r+n < p < 2^256) */
	LAddr x5, N_LIMBS
	ldr  x4, [x19, #0]
	ldr  x6, [x5, #0]
	adds x4, x4, x6
	add  x3, sp, #64
	str  x4, [x3, #0]
	ldr  x4, [x19, #8]
	ldr  x6, [x5, #8]
	adcs x4, x4, x6
	str  x4, [x3, #8]
	ldr  x4, [x19, #16]
	ldr  x6, [x5, #16]
	adcs x4, x4, x6
	str  x4, [x3, #16]
	ldr  x4, [x19, #24]
	ldr  x6, [x5, #24]
	adcs x4, x4, x6
	str  x4, [x3, #24]
	/* t = rn * z2 -> sp+32 */
	add  x0, sp, #32
	add  x1, sp, #64
	mov  x2, sp
	bl   fe_mul
	/* t == X ? -> yes else no */
	add  x3, sp, #32
	ldr  x4, [x3, #0]
	ldr  x5, [x20, #0]
	cmp  x4, x5
	b.ne .Lx_no
	ldr  x4, [x3, #8]
	ldr  x5, [x20, #8]
	cmp  x4, x5
	b.ne .Lx_no
	ldr  x4, [x3, #16]
	ldr  x5, [x20, #16]
	cmp  x4, x5
	b.ne .Lx_no
	ldr  x4, [x3, #24]
	ldr  x5, [x20, #24]
	cmp  x4, x5
	b.ne .Lx_no
	mov  w0, #1
	b    .Lx_out
.Lx_no:
	mov  w0, #0
.Lx_out:
	add  sp, sp, #96
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size ecdsa_x_eq_mod_n, .-ecdsa_x_eq_mod_n

/* ============================================================================
 * int ecdsa_verify(x0=z, x1=r, x2=s, x3=Qx, x4=Qy)
 * Frame (sp-relative): s@+0 w@+32 u1@+64 u2@+96 Q@+128(8) P1@+192(12)
 * P2@+288(12) P@+384(12); sub 480.
 * Persistent x19=z x20=r x21=Qx x22=Qy (preserved by all callees incl. asm).
 * ========================================================================== */
	.global ecdsa_verify
	.type   ecdsa_verify, %function
ecdsa_verify:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	sub  sp, sp, #480
	mov  x19, x0                 /* z */
	mov  x20, x1                 /* r */
	mov  x21, x3                 /* Qx */
	mov  x22, x4                 /* Qy */

	/* copy s(x2) -> sp+0 */
	ldr  x4, [x2, #0]
	ldr  x5, [x2, #8]
	ldr  x6, [x2, #16]
	ldr  x7, [x2, #24]
	str  x4, [sp, #0]
	str  x5, [sp, #8]
	str  x6, [sp, #16]
	str  x7, [sp, #24]
	/* s in (0,n)? */
	mov  x0, sp
	bl   ecdsa_in_range
	cbz  w0, .Lv_inv
	/* r in (0,n)? */
	mov  x0, x20
	bl   ecdsa_in_range
	cbz  w0, .Lv_inv

	/* w = sc_inv_var(w@+32, s@+0) */
	add  x0, sp, #32
	mov  x1, sp
	bl   sc_inv_var
	cbz  w0, .Lv_inv             /* s==0 impossible here; belt & braces */

	/* u1 = sc_mul(u1@+64, z, w) */
	add  x0, sp, #64
	mov  x1, x19                 /* z */
	add  x2, sp, #32             /* w */
	bl   sc_mul
	/* build Q affine @ sp+128: Qx(x21)->+128, Qy(x22)->+160 */
	ldr  x4, [x21, #0]
	ldr  x5, [x21, #8]
	ldr  x6, [x21, #16]
	ldr  x7, [x21, #24]
	str  x4, [sp, #128]
	str  x5, [sp, #136]
	str  x6, [sp, #144]
	str  x7, [sp, #152]
	ldr  x4, [x22, #0]
	ldr  x5, [x22, #8]
	ldr  x6, [x22, #16]
	ldr  x7, [x22, #24]
	str  x4, [sp, #160]
	str  x5, [sp, #168]
	str  x6, [sp, #176]
	str  x7, [sp, #184]
	/* u2 = sc_mul(u2@+96, r, w) */
	add  x0, sp, #96
	mov  x1, x20                 /* r */
	add  x2, sp, #32             /* w */
	bl   sc_mul
	/* P1 = u1*G : point_scalar_mul_fixed(P1@+192, u1@+64) */
	add  x0, sp, #192
	add  x1, sp, #64
	bl   point_scalar_mul_fixed
	/* P2 = u2*Q : GLV endomorphism + wNAF ladder (PERF_SCOPE.md 4.3) unless
	 * the BMC_ECDSA_GLV=0 kill switch is set; point_scalar_mul_glv itself
	 * falls back to point_scalar_mul if the split's identity check fails.
	 * u2 is public, so a variable-time multiply is within policy
	 * (secp256k1_point_ct.S header). The C call clobbers only caller-saved
	 * registers; x19-x22 (z, r, Qx, Qy) are callee-saved and every operand
	 * below is sp-relative, like the x86 which re-derives from rbp. */
	bl   bmc_ecdsa_glv_enabled
	cbz  w0, .Lp2_plain
	add  x0, sp, #288
	add  x1, sp, #128
	add  x2, sp, #96
	bl   point_scalar_mul_glv
	b    .Lp2_done
.Lp2_plain:
	add  x0, sp, #288
	add  x1, sp, #128
	add  x2, sp, #96
	bl   point_scalar_mul
.Lp2_done:
	/* P = point_add(P@+384, P1@+192, P2@+288) */
	add  x0, sp, #384
	add  x1, sp, #192
	add  x2, sp, #288
	bl   point_add
	/* P infinite? (Z @ sp+448.. all zero) -> invalid */
	ldr  x4, [sp, #448]
	ldr  x5, [sp, #456]
	orr  x4, x4, x5
	ldr  x5, [sp, #464]
	orr  x4, x4, x5
	ldr  x5, [sp, #472]
	orr  x4, x4, x5
	cbz  x4, .Lv_inv
	/* x(P)==r mod n : ecdsa_x_eq_mod_n(r, X=P@+384, Z=sp+448) */
	mov  x0, x20
	add  x1, sp, #384
	add  x2, sp, #448
	bl   ecdsa_x_eq_mod_n
	cbz  w0, .Lv_inv
	mov  w0, #1
	b    .Lv_done
.Lv_inv:
	mov  w0, #0
.Lv_done:
	add  sp, sp, #480
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size ecdsa_verify, .-ecdsa_verify

	.section .note.GNU-stack,"",%progbits
