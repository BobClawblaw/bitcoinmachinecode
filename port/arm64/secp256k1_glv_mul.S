/* ============================================================================
 * secp256k1_glv_mul.S -- AArch64 port of asm/secp256k1_point.asm's
 * point_scalar_mul_glv (PERF_SCOPE.md 4.3, libsecp256k1's
 * secp256k1_ecmult_strauss_wnaf for a single point).
 *
 *   point_scalar_mul_glv(out[12], xy[8], k[4])   -- out = k*affine(xy),
 *   Jacobian, VARIABLE-TIME (verification only).
 *
 * Algorithm (limb-for-limb the x86 @point_scalar_mul_glv):
 *   1. k = r1 + lambda*r2 (mod n), halves < 2^128 up to sign
 *      (sc_split_lambda, secp256k1_glv.S; its permanent identity check makes
 *      the caller fall back on failure).
 *   2. Width-5 wNAF of each half into 129 signed-char slots (glv_wnaf,
 *      secp256k1_glv_c.c); BITS = max of the two lengths.
 *   3. Odd-multiples table TAB[i] = (2i+1)*Q built on the isomorphic curve
 *      with C := z(2Q) so every step is a mixed add, then brought to one
 *      common Z with the captured z-ratios ZR[] (no inversion anywhere).
 *      ZG := AI.z * C is that common Z. AUXX[i] = TAB[i].x * beta is the
 *      lambda-table: lambda*(x,y) == (beta*x, y), which a shared Z keeps
 *      true.
 *   4. One ladder over both digit streams: ~128 doublings instead of 252,
 *      one mixed add per non-zero digit (TAB[idx] for stream 0,
 *      (AUXX[idx], TAB[idx].y) for stream 1, y negated for a negative digit).
 *   5. Leave the isomorphic curve: R.z *= ZG (Z == 0 stays 0).
 * Fallbacks (mirroring the x86): the split's identity check fails, the wNAF
 * encoder rejects a half (magnitude >= 2^129), or k == 0 -> plain
 * point_scalar_mul / Jacobian infinity. Slow-and-correct, never an abort.
 * The accumulator starts at infinity, so the Z1 == 0 guards in
 * point_add_mixed / point_add_mixed_zr (2026-08-22) are load-bearing here.
 *
 * AAPCS64: out = x0, xy = x1, k = x2.
 *
 * Frame -- push fp/lr pair (16 B), then 5 callee-saved pairs x19-x28 (80 B),
 *   = 96 B of save area; then `sub sp, sp, #FRAME` (FRAME = 0x6c0) and an
 *   `and #-16` of sp (round-tripped through x9 -- AArch64 has no AND that
 *   takes sp as a destination), and x28 = sp = the frame base every slot
 *   below is offset from. AAPCS64 already requires SP to be quadword-aligned
 *   at all times (unlike SysV AMD64, where the ABI only demands it at the call
 *   instruction), so this snap is expected to be a NO-OP for any caller that
 *   obeys the ABI -- it is kept as the cheap defensive copy of the x86's
 *   `and rsp, -16`, which the all-asm interpreter -> sv_checksig ->
 *   ecdsa_verify chain genuinely needs on the CHECKMULTISIG path (incident
 *   #20, docs/ABI_STACK_ALIGNMENT.md), and it costs one instruction.
 *   The 0x6c0 reservation is already a multiple of 16, so the
 *   AND only ever moves sp DOWNWARD by 0..15 bytes -- it rounds down from the
 *   reservation, never up into the save area -- which is what makes sp
 *   16-byte aligned at the C call `glv_wnaf` (same defence as the x86's
 *   `and rsp, -16`, which exists because the all-asm interpreter can arrive
 *   with rsp == 8 mod 16 on the CHECKMULTISIG path). The epilogue takes sp
 *   back from the fp (`sub sp, x29, #80`, the 5 pairs) rather than adding
 *   FRAME, because FRAME+rounding is not a constant.
 *   EVERY slot below is disjoint: the end offset of each row is the start of
 *   the next (or the frame end). Nothing here shares a byte with anything
 *   else, and no slot grows past its row -- the sizes are the call widths of
 *   the callees (fe_* write 32 B, point_double/point_add_mixed* write 96 B,
 *   glv_wnaf writes 129 B).
 *   (The x86 frame is rbp-relative with W2 BELOW W1 at -0x1b0; this one is
 *   x28-relative with W2 ABOVE W1. The two maps are isomorphic, not byte-
 *   identical -- re-derive offsets from this table, not from the x86.)
 *     +0x000 W1   129 B signed char (wNAF of r1), padded to 0x090
 *     +0x090 W2   129 B signed char (wNAF of r2), padded to 0x120
 *     +0x120 TAB  8 x 64 B = 0x200  odd multiples, x @ +0, y @ +32  -> 0x320
 *     +0x320 AUXX 8 x 32 B = 0x100  TAB[i].x * beta                 -> 0x420
 *     +0x420 ZR   8 x 32 B = 0x100  per-add z-ratios (H, or 2*Y1)   -> 0x520
 *     +0x520 AI   96 B  running table point (Jacobian x,y,z)        -> 0x580
 *     +0x580 DGE  96 B  D = 2*AI; +0/+32 are the affine d_ge,       -> 0x5E0
 *                          +64 is C = z(2Q)
 *     +0x5E0 ZS   32 B  running common-Z factor (C^2, C^3, then     -> 0x600
 *                          ZR[j+1]*..*ZR[7] in globalz)
 *     +0x600 TMP  64 B  affine operand for the ladder add (x,y);    -> 0x640
 *                          low 32 B double as the ZS^2 / ZS^3 scratch
 *     +0x640 ZG   32 B  table common Z = AI.z * C                   -> 0x660
 *     +0x660 R1   32 B  split half 1                                -> 0x680
 *     +0x680 R2   32 B  split half 2                                -> 0x6A0
 *     +0x6A0 KC   32 B  local copy of k                             -> 0x6C0 = frame end
 *   Total frame 0x6c0 (1728 B), on top of the 96 B save area.
 *
 * Register saves -- x19-x28 are all pushed above, one pair per `stp` (the
 *   project convention: secp256k1_point.S / bitcoin_sighash.S / sha256.S all
 *   push exactly the callee-saved block they use, pair by pair, with no
 *   sub-frame). x19/x20 are pushed but never used here -- they are the fifth
 *   pair that makes the save area a round 96 B, and the epilogue's
 *   `sub sp, x29, #80` counts all 5 pairs, so they are load-bearing for the
 *   epilogue even though nothing reads them.
 *   Every callee here PRESERVES x19-x28, so the values below are held across
 *   `bl` and never re-loaded. That was re-derived (2026-09-01) by walking the
 *   TRANSITIVE call closure out of this function in objdump and, per function,
 *   listing (a) every x19-x28 written as a destination and (b) every x19-x28
 *   pushed to the [sp]/[x29] save area -- the two sets are equal or the
 *   written set is a subset, for every function in the closure, direct or
 *   nested (a cached value survives a callee's callee):
 *     fe_mul / fe_sqr / fe_sub / fe_add / point_add_mixed
 *                                           leaf, x0-x18 only, no writes
 *     point_double                          writes == saves x19-x20
 *                                           (calls fe_add/fe_mul/fe_sqr/fe_sub)
 *     point_add_mixed_zr                    writes == saves x19-x22
 *                                           (calls fe_*, point_double)
 *     sc_split_lambda                       writes x19-x21,x23-x25; saves
 *                                           x19-x26 (x22/x26 pushed as pair
 *                                           padding, never written)
 *                                           (calls sc_mul_512/sc_mul/sc_add/
 *                                            sc_sub, which save what they
 *                                            write: x19-x22 each)
 *     point_scalar_mul (fallback)           writes == saves x23-x28
 *                                           (calls point_add/point_add_mixed/
 *                                            point_double; point_add saves
 *                                            x19-x22)
 *     glv_wnaf                              AAPCS64 C (gcc) -- x19-x28 are
 *                                           callee-saved by the ABI
 *   so the values below are held across `bl` and never re-loaded:
 *     x23 = out (= R, the accumulator)  live across every call here
 *     x24 = xy (affine base)            live across every call here
 *     x28 = frame base                  live across every call here
 *     x25 = BITS                        live across the 2nd glv_wnaf and the
 *                                       whole ladder
 *     x26 = loop index                  live across point_double, fe_sub and
 *                                       point_add_mixed
 *     x27 = stream index                ditto
 *     x21 = wNAF digit -> table index, x22 = digit sign mask: both die
 *         inside one stream step (the last read is the `tbnz` that picks the
 *         y-negation branch, before the fe_sub), but being callee-saved they
 *         also survive it.
 *   Scratch that is NOT trusted across a call: x4-x17 are re-materialised
 *   after every bl (see the x14 recomputation in the table/globalz loops).
 *
 * Calls: sc_split_lambda, glv_wnaf (C), fe_mul, fe_sqr, fe_sub, point_double,
 *   point_add_mixed_zr, point_add_mixed, point_scalar_mul (fallback).
 *   (Exactly the bl targets in the object -- 10 fe_mul, 2 fe_sqr, 1 fe_sub,
 *   2 glv_wnaf, 2 point_double, 1 point_add_mixed_zr, 1 point_add_mixed,
 *   1 sc_split_lambda, 1 point_scalar_mul.)
 *
 * Gate: asm/tests/test_glv_pointmul on aarch64 -- 102056 cases, 0 failures
 *   (native gcc -no-pie -O2 build of the port/arm64 objects, /tmp scratch
 *   link of secp256k1_glv_mul.o + secp256k1_glv.o + the point/scalar/fe
 *   objects + asm/secp256k1_{scalar,glv}_c.c), plus
 *   test_scalarmul / test_point / test_add / test_addm / test_point_inf /
 *   stress_pointmul / test_glv_wnaf unchanged and passing, and
 *   stress_pointmul.py (pure-python oracle) 0 failures. The GLV path was also
 *   cross-checked against that same python oracle rather than only against
 *   point_scalar_mul (edge k incl. 1, 2, n-1, n//2, 2^128+-1, 2^255, lambda,
 *   n-lambda over Q = G, -G, lambda*G and random points): 0 failures -- so a
 *   shared bug in both asm multipliers could not have hidden behind the
 *   differential.
 * ========================================================================== */

	.section .rodata
	.balign 16
/* beta = 2^((p-1)/3) root matching LAMBDA in secp256k1_scalar.S / the test's
 * BETA[]; same constant as asm/secp256k1_point.asm's BETA_LIMBS. */
BETA_LIMBS_PGM: .quad 0xC1396C28719501EE, 0x9CF0497512F58995, 0x6E64479EAC3434E9, 0x7AE96A2B657C0710
FE_ZERO_PGM:    .quad 0, 0, 0, 0
	.text

/* frame slot macros (base x28 = sp after the sub) -- see the map above */
	.equ W1,    0x000
	.equ W2,    0x090
	.equ TAB,   0x120
	.equ AUXX,  0x320
	.equ ZR,    0x420
	.equ AI,    0x520
	.equ DGE,   0x580
	.equ ZS,    0x5E0
	.equ TMP,   0x600
	.equ ZG,    0x640
	.equ R1,    0x660
	.equ R2,    0x680
	.equ KC,    0x6A0
	.equ FRAME, 0x6C0

	.global point_scalar_mul_glv
	.type   point_scalar_mul_glv, %function
point_scalar_mul_glv:
	stp x29, x30, [sp, #-16]!
	mov  x29, sp
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	sub  sp, sp, #FRAME
	mov  x9, sp                   /* glv_wnaf is gcc-compiled C: guarantee 16-byte
	                               * sp at its call no matter how the caller was
	                               * aligned (same defence as the x86's 'and rsp,
	                               * -16'). Every local is x28-relative and the
	                               * epilogue restores sp from x29, so rounding
	                               * down is safe. AArch64 cannot AND the SP
	                               * directly, hence the x9 round-trip. */
	and  x9, x9, #-16
	mov  sp, x9
	mov  x28, sp                  /* frame base */
	mov  x23, x0                  /* out (= R, the accumulator) */
	mov  x24, x1                  /* xy (affine base point) */

	/* ---- k -> KC; k == 0 -> infinity ---- */
	add  x27, x28, #KC
	ldp  x4, x5,  [x2, #0]
	ldp  x6, x7,  [x2, #16]
	stp  x4, x5,  [x27, #0]
	stp  x6, x7,  [x27, #16]
	orr  x4, x4, x5
	orr  x6, x6, x7
	orr  x4, x4, x6
	cbz  x4, .zero

	/* ---- 1. split ---- */
	add  x0, x28, #R1
	add  x1, x28, #R2
	mov  x2, x27
	bl   sc_split_lambda
	cbz  w0, .fallback

	/* ---- 2. wNAF both halves; BITS = max ---- */
	add  x0, x28, #W1
	add  x1, x28, #R1
	bl   glv_wnaf
	tbnz w0, #31, .fallback       /* -1: this half is >= 2^129 */
	sxtw x25, w0                  /* bits1 (glv_wnaf returns int) */
	add  x0, x28, #W2
	add  x1, x28, #R2
	bl   glv_wnaf
	tbnz w0, #31, .fallback
	sxtw x0, w0
	cmp  x0, x25
	csel x25, x0, x25, hi         /* BITS = max(bits1, bits2) */
	cbz  x25, .zero               /* both halves zero <=> k == 0 */

	/* ---- 3a. table on the isomorphic curve ----
	 * AI := (Qx, Qy, 1); D := 2*AI (DGE); C := D.z (kept as DGE+64). */
	add  x12, x28, #AI
	ldp  x4, x5,  [x24, #0]
	ldp  x6, x7,  [x24, #16]
	ldp  x8, x9,  [x24, #32]
	ldp  x10, x11,[x24, #48]
	stp  x4, x5,  [x12, #0]
	stp  x6, x7,  [x12, #16]
	stp  x8, x9,  [x12, #32]
	stp  x10,x11, [x12, #48]
	mov  x13, #1
	str  x13, [x12, #64]
	str  xzr, [x12, #72]
	str  xzr, [x12, #80]
	str  xzr, [x12, #88]
	add  x0, x28, #DGE
	mov  x1, x12
	bl   point_double
	/* TAB[0] = (Qx*C^2, Qy*C^3)   (ZS scratch = C^2, then C^3) */
	add  x0, x28, #ZS
	add  x1, x28, #DGE+64
	bl   fe_sqr                   /* ZS = C^2 */
	add  x0, x28, #TAB
	mov  x1, x24                  /* Qx */
	add  x2, x28, #ZS
	bl   fe_mul
	add  x0, x28, #ZS
	mov  x1, x0
	add  x2, x28, #DGE+64
	bl   fe_mul                   /* ZS = C^3 (x86 does this after TAB0.x) */
	add  x0, x28, #TAB+32
	add  x1, x24, #32             /* Qy */
	add  x2, x28, #ZS
	bl   fe_mul
	/* AI := (TAB[0].x, TAB[0].y, 1) -- phi(Q) with z = 1 */
	add  x12, x28, #AI
	add  x13, x28, #TAB
	ldp  x4, x5,  [x13, #0]
	ldp  x6, x7,  [x13, #16]
	ldp  x8, x9,  [x13, #32]
	ldp  x10, x11,[x13, #48]
	stp  x4, x5,  [x12, #0]
	stp  x6, x7,  [x12, #16]
	stp  x8, x9,  [x12, #32]
	stp  x10,x11, [x12, #48]
	mov  x13, #1
	str  x13, [x12, #64]
	str  xzr, [x12, #72]
	str  xzr, [x12, #80]
	str  xzr, [x12, #88]
	/* ZR[0] := C */
	add  x12, x28, #ZR
	add  x13, x28, #DGE+64
	ldp  x4, x5,  [x13, #0]
	ldp  x6, x7,  [x13, #16]
	stp  x4, x5,  [x12, #0]
	stp  x6, x7,  [x12, #16]
	/* TAB[i] = AI += d_ge  (i = 1..7), ZR[i] = the z-ratio of that add */
	mov  x26, #1
.tab_loop:
	add  x0, x28, #AI
	mov  x1, x0                   /* r == p, in place */
	add  x2, x28, #DGE            /* d_ge = (D.x, D.y) */
	add  x3, x28, #ZR
	lsl  x14, x26, #5
	add  x3, x3, x14              /* &ZR[i] */
	bl   point_add_mixed_zr
	/* TAB[i] := AI (x,y; the z limb is the running one, not part of the table) */
	lsl  x14, x26, #6
	add  x12, x28, #TAB
	add  x12, x12, x14
	add  x13, x28, #AI
	ldp  x4, x5,  [x13, #0]
	ldp  x6, x7,  [x13, #16]
	ldp  x8, x9,  [x13, #32]
	ldp  x10, x11,[x13, #48]
	stp  x4, x5,  [x12, #0]
	stp  x6, x7,  [x12, #16]
	stp  x8, x9,  [x12, #32]
	stp  x10,x11, [x12, #48]
	add  x26, x26, #1
	cmp  x26, #8
	b.lt .tab_loop
	/* ZG := AI.z * C  (the table's common Z once globalz has run) */
	add  x0, x28, #ZG
	add  x1, x28, #AI+64
	add  x2, x28, #DGE+64
	bl   fe_mul

	/* ---- 3b. globalz: scale TAB[j] (j = 6..0) by zs = ZR[j+1]*...*ZR[7] ---- */
	add  x12, x28, #ZS
	add  x13, x28, #ZR+7*32       /* ZS := ZR[7] */
	ldp  x4, x5,  [x13, #0]
	ldp  x6, x7,  [x13, #16]
	stp  x4, x5,  [x12, #0]
	stp  x6, x7,  [x12, #16]
	mov  x26, #6
.gz_loop:
	cmp  x26, #6
	b.eq .gz_scale
	add  x14, x26, #1
	lsl  x14, x14, #5
	add  x0, x28, #ZS
	mov  x1, x0
	add  x2, x28, #ZR
	add  x2, x2, x14              /* &ZR[j+1] */
	bl   fe_mul                   /* ZS *= ZR[j+1] */
.gz_scale:
	add  x0, x28, #TMP
	add  x1, x28, #ZS
	bl   fe_sqr                   /* TMP = ZS^2 */
	lsl  x14, x26, #6
	add  x0, x28, #TAB
	add  x0, x0, x14              /* &TAB[j].x (x14 recomputed after each bl:
	                               * x9-x18 are caller-saved) */
	mov  x1, x0
	add  x2, x28, #TMP
	bl   fe_mul                   /* TAB[j].x *= ZS^2 */
	add  x0, x28, #TMP
	mov  x1, x0
	add  x2, x28, #ZS
	bl   fe_mul                   /* TMP = ZS^3 */
	lsl  x14, x26, #6
	add  x0, x28, #TAB
	add  x0, x0, x14
	add  x0, x0, #32              /* &TAB[j].y */
	mov  x1, x0
	add  x2, x28, #TMP
	bl   fe_mul                   /* TAB[j].y *= ZS^3 */
	subs x26, x26, #1
	b.pl .gz_loop

	/* ---- 3c. lambda-table: AUXX[i] = TAB[i].x * beta ---- */
	mov  x26, #0
.aux_loop:
	lsl  x14, x26, #5
	add  x0, x28, #AUXX
	add  x0, x0, x14              /* &AUXX[i] */
	lsl  x15, x26, #6
	add  x1, x28, #TAB
	add  x1, x1, x15              /* &TAB[i].x */
	adrp x2, BETA_LIMBS_PGM
	add  x2, x2, :lo12:BETA_LIMBS_PGM
	bl   fe_mul
	add  x26, x26, #1
	cmp  x26, #8
	b.lt .aux_loop

	/* ---- 4. ladder: R = inf; for i = BITS-1..0: R = 2R (+ digit adds) ---- */
	mov  x13, #1
	str  x13, [x23, #0]
	str  xzr, [x23, #8]
	str  xzr, [x23, #16]
	str  xzr, [x23, #24]
	str  x13, [x23, #32]
	str  xzr, [x23, #40]
	str  xzr, [x23, #48]
	str  xzr, [x23, #56]
	str  xzr, [x23, #64]
	str  xzr, [x23, #72]
	str  xzr, [x23, #80]
	str  xzr, [x23, #88]
	mov  x26, x25
.ladder:
	subs x26, x26, #1
	b.lt .finish
	mov  x0, x23
	mov  x1, x23
	bl   point_double
	mov  x27, #0                  /* stream 0 = W1/TAB.x, 1 = W2/AUXX.x */
.stream:
	cbnz x27, .stream_w2
	add  x15, x28, #W1
	b    .stream_w
.stream_w2:
	add  x15, x28, #W2
.stream_w:
	ldrsb x21, [x15, x26]         /* digit in {0, +-1, +-3, ..., +-15} */
	cbz  x21, .next_stream
	asr  x22, x21, #63            /* sign mask: -1 (d<0) or 0 */
	eor  x21, x21, x22
	sub  x21, x21, x22            /* |d| */
	sub  x21, x21, #1
	lsr  x21, x21, #1             /* idx = (|d|-1)/2, 0..7 */
	/* TMP.x = (stream ? AUXX : TAB)[idx].x */
	cbnz x27, .xsrc_aux
	lsl  x14, x21, #6
	add  x13, x28, #TAB
	add  x13, x13, x14
	b    .xsrc_ok
.xsrc_aux:
	lsl  x14, x21, #5
	add  x13, x28, #AUXX
	add  x13, x13, x14
.xsrc_ok:
	add  x0, x28, #TMP
	ldp  x4, x5,  [x13, #0]
	ldp  x6, x7,  [x13, #16]
	stp  x4, x5,  [x0, #0]
	stp  x6, x7,  [x0, #16]
	/* TMP.y = TAB[idx].y (shared Z: both streams read the same y), negated
	 * for a negative digit */
	lsl  x14, x21, #6
	add  x13, x28, #TAB+32
	add  x13, x13, x14            /* &TAB[idx].y */
	add  x0, x28, #TMP+32
	tbnz x22, #63, .negy
	ldp  x4, x5,  [x13, #0]
	ldp  x6, x7,  [x13, #16]
	stp  x4, x5,  [x0, #0]
	stp  x6, x7,  [x0, #16]
	b    .addit
.negy:
	adrp x1, FE_ZERO_PGM
	add  x1, x1, :lo12:FE_ZERO_PGM
	mov  x2, x13
	bl   fe_sub                   /* TMP.y = 0 - TAB[idx].y */
.addit:
	mov  x0, x23
	mov  x1, x23
	add  x2, x28, #TMP
	bl   point_add_mixed          /* R += TMP (R == inf handled by its guard) */
.next_stream:
	add  x27, x27, #1
	cmp  x27, #2
	b.lt .stream
	b    .ladder

.finish:
	/* ---- 5. leave the isomorphic curve: R.z *= ZG (Z == 0 stays 0) ---- */
	add  x0, x23, #64
	mov  x1, x0
	add  x2, x28, #ZG
	bl   fe_mul
	b    .done

.fallback:
	mov  x0, x23
	mov  x1, x24
	add  x2, x28, #KC
	bl   point_scalar_mul
	b    .done

.zero:
	mov  x13, #1
	str  x13, [x23, #0]
	str  xzr, [x23, #8]
	str  xzr, [x23, #16]
	str  xzr, [x23, #24]
	str  x13, [x23, #32]
	str  xzr, [x23, #40]
	str  xzr, [x23, #48]
	str  xzr, [x23, #56]
	str  xzr, [x23, #64]
	str  xzr, [x23, #72]
	str  xzr, [x23, #80]
	str  xzr, [x23, #88]

.done:
	sub  sp, x29, #80             /* the x19-x28 save area (5 pairs) below the fp */
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size point_scalar_mul_glv, .-point_scalar_mul_glv

	.section .note.GNU-stack,"",%progbits
