/* ============================================================================
 * sha256.S -- macOS (Darwin/Mach-O) AArch64 port of asm/sha256.asm
 *
 * Branch: bmc_osx.  Algorithm reference: port/arm64/sha256.S on the arm-port
 * branch (differential-verified on Linux); every Darwin-ism redone from
 * scratch here.  Public symbols are identical to the x86 tree apart from the
 * Mach-O leading underscore the linker mandates, so the C harnesses and the
 * daemon link unchanged:
 *
 *   void sha256_init (u32 state[8])                      -> x0
 *   void sha256_block(u32 state[8], const u8 block[64])  -> x0, x1
 *   void sha256_full (u8 out[32], const void *msg, i64 len) -> x0, x1, x2
 *   void sha256_force_path(int p)                        -> w0   (CRY-6 pin)
 *   int  sha256_current_path(void)
 *   int  sha256_cpu_has_sha(void)
 *   void sha256_block_shani(u32 state[8], const u8 block[64])  (accelerator)
 *
 * Darwin deltas vs the arm-port .S (each one is a real porting constraint):
 *   - Mach-O: every global carries a leading underscore; no .type/.size/
 *     .note.GNU-stack; sections are __TEXT/__DATA; page-relative addressing
 *     via adrp+@PAGEOFF (same-file data needs no GOT).
 *   - x18 is platform-reserved and x28 is the platform register on macOS --
 *     the arm-port used w27/w28 as round temps; here all temps live in
 *     x9-x15 (caller-saved, leaf-safe).
 *   - ID_AA64ISAR0_EL1 is not readable at EL0 on macOS (the MRS traps), so
 *     the crypto-extension probe asks sysctlbyname for
 *     hw.optional.arm.FEAT_SHA256 instead.  The probe stays inside this
 *     module (exported, as on x86) so dispatcher and CRY-6 test can never
 *     disagree.
 *   - Stack discipline: 16-byte aligned at every bl site, x29/x30 saved (the
 *     arm-port's 8-byte x30 push left sp misaligned at a call site -- legal
 *     nowhere, fatal under guardmalloc on macOS).
 *
 * sha256_block lazily probes for the ARMv8 SHA-2 crypto extension and, when
 * present, tail-calls sha256_block_shani (bit-identical output, much faster,
 * same contract as x86's SHA-NI path).  shani_ready is the same tri-state
 * cache: 0 = unprobed, 1 = extension present, 2 = absent/forced-scalar.
 * Assemble with -march=armv8.2-a+sha2 so the sha256h/256h2/su0/su1
 * mnemonics assemble; the scalar body needs nothing beyond armv8-a.
 * ========================================================================== */

	.section	__TEXT,__text

/* ---------------------------------------------------------------------------
 * K256 -- FIPS 180-4 round constants (host word order; loads are 32-bit).
 * ------------------------------------------------------------------------- */
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
KSHA256:			/* same table, loaded by the crypto block */
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

	.section	__DATA,__data
	.balign 8
shani_ready:
	.byte 0			/* 0 unprobed / 1 sha2 ext / 2 scalar */

	.section	__TEXT,__cstring
_sha256_feat_name:
	.asciz "hw.optional.arm.FEAT_SHA256"

	.section	__TEXT,__text

/* ==========================================================================
 * void sha256_init(u32 state[8])
 *   Copy the FIPS 180-4 initial hash values into the caller's buffer.
 * ========================================================================== */
	.globl _sha256_init
_sha256_init:
	adrp x1, INIT_H@PAGE
	add  x1, x1, INIT_H@PAGEOFF
	ldp  w2, w3, [x1, #0]
	ldp  w4, w5, [x1, #8]
	ldp  w6, w7, [x1, #16]
	ldp  w8, w9, [x1, #24]
	stp  w2, w3, [x0, #0]
	stp  w4, w5, [x0, #8]
	stp  w6, w7, [x0, #16]
	stp  w8, w9, [x0, #24]
	ret

/* ==========================================================================
 * void sha256_block(u32 state[8], const u8 block[64])
 *   Lazy crypto-extension probe, then tail-call the accelerator or fall
 *   back to the scalar body.  Dispatcher contract mirrors asm/sha256.asm:
 *   shani_ready tri-state, probe through the shared exported
 *   _sha256_cpu_has_sha so dispatcher and test can never disagree (CRY-6).
 *   The probe call clobbers x0/x1/x2-x4 (sysctlbyname), so the caller's
 *   arguments are parked on the stack across it -- the ARM counterpart of
 *   the x86 push rbx around CPUID.
 * ========================================================================== */
	.globl _sha256_block
_sha256_block:
	adrp  x2, shani_ready@PAGE
	add   x2, x2, shani_ready@PAGEOFF
	ldrb  w3, [x2]
	cbnz  w3, .Lsh_probed
	/* park state ptr, block ptr, and LR; keep sp 16-aligned (2 slots) */
	stp   x0, x1, [sp, #-32]!
	stp   x30, xzr, [sp, #16]
	bl    _sha256_cpu_has_sha
	ldp   x30, xzr, [sp, #16]
	ldp   x0, x1, [sp], #32
	adrp  x2, shani_ready@PAGE	/* recompute: probe clobbers x2 */
	add   x2, x2, shani_ready@PAGEOFF
	mov   w5, #2			/* default: absent (cached) */
	cbz   w0, .Lsh_probe_done
	mov   w5, #1
.Lsh_probe_done:
	strb  w5, [x2]
	mov   w3, w5
.Lsh_probed:
	cmp   w3, #1
	b.ne  .Lsh_scalar		/* 2 (or anything else) -> scalar */
	b     _sha256_block_shani	/* tail-call; x0/x1 already set */

/* --------------------------------------------------------------------------
 * Scalar body.  REGISTER CONTRACT (mirrors asm/sha256.asm):
 *   a..h live in w19..w26 across the whole compression;
 *   temps are w4-w8 and x9 (index), x10 (K base) -- all leaf-safe; the
 *   arm-port's w27/w28 temps are FORBIDDEN here (x28 is the platform
 *   register on macOS).
 *   sp holds W[0..63] (256 bytes) for the schedule.
 * ------------------------------------------------------------------------- */
.Lsh_scalar:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #256		/* W[0..63] = 64 words x 4 bytes at sp */

	/* ---- PHASE 1: W[0..15] from big-endian block bytes (rev = bswap) ---- */
	mov  x9, #0
1:
	ldr  w4, [x1, x9, lsl #2]
	rev  w4, w4
	str  w4, [sp, x9, lsl #2]
	add  x9, x9, #1
	cmp  x9, #16
	b.lt 1b
	mov  x9, #16			/* i = 16..63 */
.Lsh_extend_loop:
	/* s1(W[i-2]) = ROR17 ^ ROR19 ^ SHR10 */
	sub  x4, x9, #2
	ldr  w5, [sp, x4, lsl #2]
	ror  w6, w5, #17
	ror  w7, w5, #19
	eor  w6, w6, w7
	lsr  w7, w5, #10
	eor  w6, w6, w7			/* w6 = s1(W[i-2]) */
	/* + W[i-7] */
	sub  x4, x9, #7
	ldr  w7, [sp, x4, lsl #2]
	add  w6, w6, w7
	/* s0(W[i-15]) = ROR7 ^ ROR18 ^ SHR3 */
	sub  x4, x9, #15
	ldr  w5, [sp, x4, lsl #2]
	ror  w7, w5, #7
	ror  w8, w5, #18
	eor  w7, w7, w8
	lsr  w8, w5, #3
	eor  w7, w7, w8
	add  w6, w6, w7
	/* + W[i-16], store W[i] */
	sub  x4, x9, #16
	ldr  w7, [sp, x4, lsl #2]
	add  w6, w6, w7
	str  w6, [sp, x9, lsl #2]
	add  x9, x9, #1
	cmp  x9, #64
	b.lt .Lsh_extend_loop

	/* ---- PHASE 3: a..h = state ------------------------------------------ */
	ldr  w19, [x0, #0]
	ldr  w20, [x0, #4]
	ldr  w21, [x0, #8]
	ldr  w22, [x0, #12]
	ldr  w23, [x0, #16]
	ldr  w24, [x0, #20]
	ldr  w25, [x0, #24]
	ldr  w26, [x0, #28]

	/* ---- PHASE 4: 64 compression rounds ---------------------------------- */
	adrp x10, K256@PAGE
	add  x10, x10, K256@PAGEOFF
	mov  x9, #0			/* round index i */
.Lsh_round:
	/* T1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i] */
	ror  w4, w23, #6
	ror  w5, w23, #11
	eor  w4, w4, w5
	ror  w5, w23, #25
	eor  w4, w4, w5			/* S1(e) */
	add  w4, w4, w26		/* + h */
	and  w6, w23, w24		/* e & f */
	mvn  w5, w23
	and  w5, w5, w25		/* !e & g */
	eor  w6, w6, w5			/* Ch(e,f,g) */
	add  w4, w4, w6
	ldr  w6, [x10, x9, lsl #2]
	add  w4, w4, w6			/* + K[i] */
	ldr  w6, [sp, x9, lsl #2]
	add  w4, w4, w6			/* + W[i]  -> w4 = T1 */

	/* T2 = S0(a) + Maj(a,b,c) */
	ror  w5, w19, #2
	ror  w6, w19, #13
	eor  w5, w5, w6
	ror  w6, w19, #22
	eor  w5, w5, w6			/* S0(a) */
	and  w6, w19, w20		/* a & b */
	and  w7, w19, w21		/* a & c */
	eor  w6, w6, w7
	and  w7, w20, w21		/* b & c */
	eor  w6, w6, w7			/* Maj(a,b,c) */
	add  w5, w5, w6			/* w5 = T2 */

	/* slide the working window right by one, set head/tail */
	add  w8, w22, w4		/* tmp = d + T1  (new e) */
	mov  w26, w25			/* h = g */
	mov  w25, w24			/* g = f */
	mov  w24, w23			/* f = e */
	mov  w23, w8			/* e = d + T1 */
	mov  w22, w21			/* d = c */
	mov  w21, w20			/* c = b */
	mov  w20, w19			/* b = a */
	add  w19, w4, w5		/* a = T1 + T2 */

	add  x9, x9, #1
	cmp  x9, #64
	b.lt .Lsh_round

	/* ---- PHASE 5: H[i] += working[i] ------------------------------------- */
	ldr  w4, [x0, #0]
	add  w4, w4, w19
	str  w4, [x0, #0]
	ldr  w4, [x0, #4]
	add  w4, w4, w20
	str  w4, [x0, #4]
	ldr  w4, [x0, #8]
	add  w4, w4, w21
	str  w4, [x0, #8]
	ldr  w4, [x0, #12]
	add  w4, w4, w22
	str  w4, [x0, #12]
	ldr  w4, [x0, #16]
	add  w4, w4, w23
	str  w4, [x0, #16]
	ldr  w4, [x0, #20]
	add  w4, w4, w24
	str  w4, [x0, #20]
	ldr  w4, [x0, #24]
	add  w4, w4, w25
	str  w4, [x0, #24]
	ldr  w4, [x0, #28]
	add  w4, w4, w26
	str  w4, [x0, #28]

	add  sp, sp, #256
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret

/* ==========================================================================
 * sha256_force_path(int p) -- CRY-6: pin the dispatcher.
 *   p = 0 -> re-probe on the next call; 1 -> crypto extension; 2 -> scalar.
 *   Test-only; lets the gate run BOTH bodies over the same vectors.
 * ========================================================================== */
	.globl _sha256_force_path
_sha256_force_path:
	adrp  x9, shani_ready@PAGE
	add   x9, x9, shani_ready@PAGEOFF
	strb  w0, [x9]
	ret

/* int sha256_current_path(void) -- report the dispatcher byte. */
	.globl _sha256_current_path
_sha256_current_path:
	adrp  x9, shani_ready@PAGE
	add   x9, x9, shani_ready@PAGEOFF
	ldrb  w0, [x9]
	ret

/* ==========================================================================
 * int sha256_cpu_has_sha(void) -> 1 if the ARMv8 SHA-2 crypto extension is
 * present.  On macOS the ID_AA64ISAR0_EL1 MRS traps at EL0, so the probe
 * reads sysctlbyname("hw.optional.arm.FEAT_SHA256").  A normal AAPCS64
 * leaf: answers in w0, may clobber caller-saved regs (the dispatcher parks
 * its live state around the call).
 * ========================================================================== */
	.globl _sha256_cpu_has_sha
_sha256_cpu_has_sha:
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #16		/* [sp]=value, [sp+8]=size */
	adrp x0, _sha256_feat_name@PAGE
	add  x0, x0, _sha256_feat_name@PAGEOFF
	mov  x1, sp			/* int value out */
	add  x2, sp, #8			/* size_t size out */
	mov  x3, #0
	mov  x4, #0
	bl   _sysctlbyname
	cbnz w0, .Lshcp_no		/* sysctl failed -> treat as absent */
	ldr  w9, [sp]			/* value: 1 if FEAT_SHA256 */
	cmp  w9, #1
	b.ne .Lshcp_no
	mov  w0, #1
	b    .Lshcp_done
.Lshcp_no:
	mov  w0, #0
.Lshcp_done:
	add  sp, sp, #16
	ldp  x29, x30, [sp], #16
	ret

/* ==========================================================================
 * void sha256_block_shani(u32 state[8], const u8 block[64])
 *   ARMv8 SHA-2 crypto-extension single-block compression, adds into
 *   state[].  CRYPTOGAMS/Polyakov ARMv8 core shape (the arm-port's
 *   differential-verified body, verbatim): state kept as {a,b,c,d}/
 *   {e,f,g,h} in v0/v1, SHA256H/H2 handle the interleave.  Caller-saved
 *   regs only -> no prologue.  Needs -march=armv8.2-a+sha2.
 * ========================================================================== */
	.globl _sha256_block_shani
_sha256_block_shani:
	mov     x4, #12
	ld1     {v0.4s, v1.4s}, [x0]		/* ABCD, EFGH */
	adrp    x3, KSHA256@PAGE
	add     x3, x3, KSHA256@PAGEOFF
	ld1     {v2.4s, v3.4s}, [x1]
	add     x5, x1, #32
	ld1     {v4.4s, v5.4s}, [x5]
	rev32   v2.16b, v2.16b
	rev32   v3.16b, v3.16b
	rev32   v4.16b, v4.16b
	rev32   v5.16b, v5.16b
	mov     v18.16b, v0.16b			/* ABCD_SAVE */
	mov     v19.16b, v1.16b			/* EFGH_SAVE */
	ld1     {v6.4s}, [x3], #16		/* W0 = K[0..3] */
.Lshx_loop:
	ld1     {v7.4s}, [x3], #16		/* W1 = next K group */
	add     v6.4s, v6.4s, v2.4s		/* W0 += MSG[0] */
	sha256su0 v2.4s, v3.4s
	mov     v16.16b, v0.16b
	sha256h  q0, q1, v6.4s
	sha256h2 q1, q16, v6.4s
	sha256su1 v2.4s, v4.4s, v5.4s
	mov     v6.16b, v7.16b			/* W0 = W1 */
	mov     v17.16b, v2.16b
	mov     v2.16b, v3.16b
	mov     v3.16b, v4.16b
	mov     v4.16b, v5.16b
	mov     v5.16b, v17.16b
	sub     x4, x4, #1
	cbnz    x4, .Lshx_loop
	/* tail: 4 more groups = 16 rounds */
	ld1     {v7.4s}, [x3], #16
	add     v6.4s, v6.4s, v2.4s
	mov     v16.16b, v0.16b
	sha256h  q0, q1, v6.4s
	sha256h2 q1, q16, v6.4s
	ld1     {v6.4s}, [x3], #16
	add     v7.4s, v7.4s, v3.4s
	mov     v16.16b, v0.16b
	sha256h  q0, q1, v7.4s
	sha256h2 q1, q16, v7.4s
	ld1     {v7.4s}, [x3], #16
	add     v6.4s, v6.4s, v4.4s
	mov     v16.16b, v0.16b
	sha256h  q0, q1, v6.4s
	sha256h2 q1, q16, v6.4s
	add     v7.4s, v7.4s, v5.4s
	mov     v16.16b, v0.16b
	sha256h  q0, q1, v7.4s
	sha256h2 q1, q16, v7.4s
	add     v0.4s, v0.4s, v18.4s		/* fold saved state */
	add     v1.4s, v1.4s, v19.4s
	st1     {v0.4s, v1.4s}, [x0]
	ret

/* ==========================================================================
 * void sha256_full(u8 out[32], const void *msg, i64 len)
 *   One-shot SHA-256 with FIPS 180-4 padding; digest emitted big-endian.
 *   Parked in callee-saved: x19=out, x20=msg, x21=remaining, x22=total.
 *   Stack: [sp..sp+31]=state H[0..7], [sp+32..sp+95]=64B work block
 *   (6 pushes = 96 bytes + 96 = 192, sp stays 16-aligned at the bl sites).
 * ========================================================================== */
	.globl _sha256_full
_sha256_full:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	sub  sp, sp, #96

	mov  x19, x0			/* out */
	mov  x20, x1			/* msg */
	mov  x21, x2			/* remaining */
	mov  x22, x2			/* total length in bytes */

	mov  x0, sp
	bl   _sha256_init

	/* STEP A: consume full 64-byte blocks */
.Lshf_blocks:
	cmp  x21, #64
	b.lt .Lshf_pad
	add  x2, sp, #32		/* dst work block */
	mov  x3, #0
.Lshf_copy:
	ldr  x5, [x20, x3]
	str  x5, [x2, x3]
	add  x3, x3, #8
	cmp  x3, #64
	b.lt .Lshf_copy
	mov  x0, sp
	add  x1, sp, #32
	bl   _sha256_block
	add  x20, x20, #64
	sub  x21, x21, #64
	b    .Lshf_blocks

	/* STEP B: final padded block(s) */
.Lshf_pad:
	add  x2, sp, #32
	mov  x3, #0
.Lshf_zero:
	str  xzr, [x2, x3]		/* zero the 64-byte block */
	add  x3, x3, #8
	cmp  x3, #64
	b.lt .Lshf_zero
	mov  x3, #0
.Lshf_cpytail:				/* copy remaining x21 bytes */
	cmp  x3, x21
	b.ge .Lshf_term
	ldrb w5, [x20, x3]
	strb w5, [x2, x3]
	add  x3, x3, #1
	b    .Lshf_cpytail
.Lshf_term:
	mov  w5, #0x80			/* 0x80 right after the data */
	strb w5, [x2, x3]
	cmp  x21, #56			/* does the 8-byte length fit here? */
	b.lt .Lshf_last
	mov  x0, sp			/* no: compress this padded block, */
	add  x1, sp, #32
	bl   _sha256_block
	add  x2, sp, #32
	mov  x3, #0
.Lshf_zero2:
	str  xzr, [x2, x3]		/* fresh all-zero block for the length */
	add  x3, x3, #8
	cmp  x3, #64
	b.lt .Lshf_zero2
.Lshf_last:
	lsl  x6, x22, #3		/* bytes -> bits */
	rev  x6, x6			/* -> big-endian wire bytes */
	str  x6, [x2, #56]		/* 64-bit BE length at bytes 56..63 */
	mov  x0, sp
	add  x1, sp, #32
	bl   _sha256_block

	/* STEP C: emit digest big-endian into out[] (x19) */
	mov  x3, #0
.Lshf_emit:
	add  x1, sp, x3
	ldr  w5, [x1]
	rev  w5, w5
	add  x2, x19, x3
	str  w5, [x2]
	add  x3, x3, #4
	cmp  x3, #32
	b.lt .Lshf_emit

	add  sp, sp, #96
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
