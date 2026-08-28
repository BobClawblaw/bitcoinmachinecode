/* ============================================================================
 * bitcoin_checksig.S -- AArch64 port of asm/bitcoin_checksig.asm: the two
 * script-interpreter checksig hooks.
 *
 *   u64 sv_checksig_asm(void* ctx, const u8* sig, u64 siglen,
 *                       const u8* pub, u64 publen, const void* slice) -> w0
 *   u64 sv_checksig_witness_v0_asm(... same signature ...)
 *
 * sv_ctx: tx@0 txlen@8 nIn@16 work@24 workcap@32 amount@56.
 * scriptCode slice { const u8* p @0; size_t n @8 }.
 * BASE does Core FindAndDelete (encode sig as a push, delete from scriptCode)
 * before legacy_sighash; WITNESS_V0 uses BIP143 over the slice verbatim.
 * Static per-thread-style scratch buffers: cks_needle[600], cks_scf[20000],
 * cks_pre[65536] (single-threaded ok; -> .tbss before the threaded daemon).
 * ========================================================================== */

	.text
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

/* TLS Initial-Exec address of a .tbss symbol into d (clobbers x17 -- never
 * used in this file). Scratch buffers are PER-THREAD (x86 parity): the
 * threaded daemon verifies many inputs across worker threads concurrently. */
	.macro TLS_ADDR d, sym
	adrp \d, :gottprel:\sym
	ldr  \d, [\d, #:gottprel_lo12:\sym]
	mrs  x17, tpidr_el0
	add  \d, \d, x17
	.endm

	.section .tbss,"awT",@nobits
	.balign 16
	.global cks_needle
cks_needle:
	.space 600
	.global cks_scf
cks_scf:
	.space 20000
	.global cks_pre
cks_pre:
	.space 65536
	.text

/* Frame (x28 = sp), 288 bytes:
 *   ctx@0 sig@8 siglen@16 pub@24 publen@32 slice@40 scF@48 scflen@56
 *   ht@64 nlen@72 dht@80 r@96 s@128 z@160 zl@192 qx@224 qy@256
 */
#define K_CTX    0
#define K_SIG    8
#define K_SIGLEN 16
#define K_PUB    24
#define K_PUBLEN 32
#define K_SLICE  40
#define K_SCF    48
#define K_SCFLEN 56
#define K_HT     64
#define K_NLEN   72
#define K_DHT    80
#define K_R      96
#define K_S      128
#define K_Z      160
#define K_ZL     192
#define K_QX     224
#define K_QY     256

	.global sv_checksig_asm
	.type sv_checksig_asm, %function
sv_checksig_asm:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	sub  sp, sp, #288
	mov  x28, sp
	str  x0, [x28, #K_CTX]
	str  x1, [x28, #K_SIG]
	str  x2, [x28, #K_SIGLEN]
	str  x3, [x28, #K_PUB]
	str  x4, [x28, #K_PUBLEN]
	str  x5, [x28, #K_SLICE]
	cbz  x2, .cs_zero
	ldr  x9, [x28, #K_SIG]
	ldr  x10, [x28, #K_SIGLEN]
	add  x11, x9, x10
	ldrb w12, [x11, #-1]
	str  w12, [x28, #K_HT]
	/* der_parse_sig */
	mov  x0, x9
	mov  x1, x10
	add  x2, x28, #K_R
	add  x3, x28, #K_S
	add  x4, x28, #K_DHT
	bl   der_parse_sig
	cbz  w0, .cs_zero
	/* script_push_encode(needle, 600, sig, siglen) -> nlen */
	TLS_ADDR x0, cks_needle
	mov  x1, #600
	ldr  x2, [x28, #K_SIG]
	ldr  x3, [x28, #K_SIGLEN]
	bl   script_push_encode
	cmp  x0, #0
	b.lt .cs_zero
	str  x0, [x28, #K_NLEN]
	/* script_find_and_delete(scF, 20000, slice.p, slice.n, needle, nlen) */
	TLS_ADDR x0, cks_scf
	str  x0, [x28, #K_SCF]
	mov  x1, #20000
	ldr  x9, [x28, #K_SLICE]
	ldr  x2, [x9, #0]
	ldr  x3, [x9, #8]
	TLS_ADDR x4, cks_needle
	ldr  x5, [x28, #K_NLEN]
	bl   script_find_and_delete
	cmp  x0, #0
	b.lt .cs_zero
	str  x0, [x28, #K_SCFLEN]
	/* legacy_sighash(z, ctx.tx, ctx.txlen, ctx.nIn, scF, scflen, ht,
	 *                ctx.work, ctx.workcap)  [9 args, cap on stack] */
	ldr  x9, [x28, #K_CTX]
	add  x0, x28, #K_Z
	ldr  x1, [x9, #0]           /* tx */
	ldr  x2, [x9, #8]           /* txlen */
	ldr  x3, [x9, #16]          /* nIn */
	ldr  x4, [x28, #K_SCF]
	ldr  x5, [x28, #K_SCFLEN]
	ldr  w6, [x28, #K_HT]
	ldr  x7, [x9, #24]          /* work (preimg) */
	ldr  x10, [x9, #32]         /* workcap */
	sub  sp, sp, #16
	str  x10, [sp]
	bl   legacy_sighash
	add  sp, sp, #16
	cbz  w0, .cs_zero
	/* be_to_limbs(zl, z, 32) */
	add  x0, x28, #K_ZL
	add  x1, x28, #K_Z
	mov  x2, #32
	bl   be_to_limbs
	/* pubkey_parse(pub, publen, qx, qy) */
	ldr  x0, [x28, #K_PUB]
	ldr  x1, [x28, #K_PUBLEN]
	add  x2, x28, #K_QX
	add  x3, x28, #K_QY
	bl   pubkey_parse
	cbz  w0, .cs_zero
	/* ecdsa_verify(zl, r, s, qx, qy) */
	add  x0, x28, #K_ZL
	add  x1, x28, #K_R
	add  x2, x28, #K_S
	add  x3, x28, #K_QX
	add  x4, x28, #K_QY
	bl   ecdsa_verify
	b    .cs_out
.cs_zero:
	mov  w0, #0
.cs_out:
	add  sp, sp, #288
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size sv_checksig_asm, .-sv_checksig_asm

	.global sv_checksig_witness_v0_asm
	.type sv_checksig_witness_v0_asm, %function
sv_checksig_witness_v0_asm:
	stp  x29, x30, [sp, #-16]!
	mov  x29, sp
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x25, x26, [sp, #-16]!
	stp  x27, x28, [sp, #-16]!
	sub  sp, sp, #288
	mov  x28, sp
	str  x0, [x28, #K_CTX]
	str  x1, [x28, #K_SIG]
	str  x2, [x28, #K_SIGLEN]
	str  x3, [x28, #K_PUB]
	str  x4, [x28, #K_PUBLEN]
	str  x5, [x28, #K_SLICE]
	cbz  x2, .cw_zero
	ldr  x9, [x28, #K_SIG]
	ldr  x10, [x28, #K_SIGLEN]
	add  x11, x9, x10
	ldrb w12, [x11, #-1]
	str  w12, [x28, #K_HT]
	/* der_parse_sig */
	mov  x0, x9
	mov  x1, x10
	add  x2, x28, #K_R
	add  x3, x28, #K_S
	add  x4, x28, #K_DHT
	bl   der_parse_sig
	cbz  w0, .cw_zero
	/* segwit_v0_sighash(z, ctx.tx, ctx.txlen, ctx.nIn, ht, ctx.amount,
	 *                    slice.p, slice.n, [sp]=pre, [sp+8]=cap) */
	ldr  x9, [x28, #K_CTX]
	add  x0, x28, #K_Z
	ldr  x1, [x9, #0]
	ldr  x2, [x9, #8]
	ldr  x3, [x9, #16]
	ldr  w4, [x28, #K_HT]
	ldr  x5, [x9, #56]          /* amount */
	ldr  x10, [x28, #K_SLICE]
	ldr  x6, [x10, #0]          /* slice.p */
	ldr  x7, [x10, #8]          /* slice.n */
	TLS_ADDR x11, cks_pre
	mov  x12, #0x10000
	sub  sp, sp, #16
	str  x11, [sp]              /* pre */
	str  x12, [sp, #8]          /* cap */
	bl   segwit_v0_sighash_asm
	add  sp, sp, #16
	cmp  x0, #0
	b.le .cw_zero
	/* be_to_limbs(zl, z, 32) */
	add  x0, x28, #K_ZL
	add  x1, x28, #K_Z
	mov  x2, #32
	bl   be_to_limbs
	/* pubkey_parse */
	ldr  x0, [x28, #K_PUB]
	ldr  x1, [x28, #K_PUBLEN]
	add  x2, x28, #K_QX
	add  x3, x28, #K_QY
	bl   pubkey_parse
	cbz  w0, .cw_zero
	/* ecdsa_verify */
	add  x0, x28, #K_ZL
	add  x1, x28, #K_R
	add  x2, x28, #K_S
	add  x3, x28, #K_QX
	add  x4, x28, #K_QY
	bl   ecdsa_verify
	b    .cw_out
.cw_zero:
	mov  w0, #0
.cw_out:
	add  sp, sp, #288
	ldp  x27, x28, [sp], #16
	ldp  x25, x26, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size sv_checksig_witness_v0_asm, .-sv_checksig_witness_v0_asm

	.section .note.GNU-stack,"",%progbits
