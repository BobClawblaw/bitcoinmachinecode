/* ============================================================================
 * sha256_nia.S -- AArch64 port of asm/sha256_nia.asm
 *
 * The x86 module is an Intel/AMD SHA-NI (CPUID-dispatch) SHA-256 accelerator.
 * AArch64 has no SHA-NI instruction set or CPUID, so the honest AArch64
 * mapping is:
 *   - cpu_has_sha_ni() always returns 0 (correct: no SHA-NI on this ISA), so
 *     any x86-style "sha_ni ? NIA : scalar" dispatcher falls back to scalar.
 *   - sha256_block_nia / sha256_full_nia delegate by tail-call to the already
 *     verified scalar port (bitcoin/sha256.S) -- byte-identical to the x86
 *     "SHA-NI absent" fallback the original guarantees.
 *
 * ABI (x64 -> AAPCS64): identical for these signatures:
 *   int  cpu_has_sha_ni(void)                    // -> 0
 *   void sha256_block_nia(u32 state[8], const u8 block[64])  // x0, x1
 *   void sha256_full_nia (u8 out[32], const void *msg, i64 len) // x0, x1, x2
 * ========================================================================== */

	.text
	.global cpu_has_sha_ni
	.type cpu_has_sha_ni, %function
	.global sha256_block_nia
	.type sha256_block_nia, %function
	.global sha256_full_nia
	.type sha256_full_nia, %function

	.extern sha256_block
	.extern sha256_full

cpu_has_sha_ni:
	mov  w0, #0                 /* no SHA-NI on AArch64 -> 0 */
	ret
	.size cpu_has_sha_ni, .-cpu_has_sha_ni

/* Tail-call the scalar block/compression routine (identical ABI x0,x1). */
sha256_block_nia:
	b    sha256_block
	.size sha256_block_nia, .-sha256_block_nia

/* Tail-call the scalar full-message hasher (identical ABI x0,x1,x2). */
sha256_full_nia:
	b    sha256_full
	.size sha256_full_nia, .-sha256_full_nia

	.section .note.GNU-stack,"",%progbits
