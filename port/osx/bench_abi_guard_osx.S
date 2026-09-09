/* bench_abi_guard_osx.S -- AAPCS64/Mach-O replacement for asm's x86
 * tests/bench_abi_guard.S so bench_hash_core.c links UNCHANGED on macOS.
 *
 * On x86 the guard exists because ripemd160/hash160 violate SysV by
 * clobbering callee-saved registers. The bmc_osx ports preserve x19-x28
 * and x29/x30 (stp/ldp pairs, verified by the module gates), so here the
 * "guard" is a plain call passthrough:
 *   long bench_call_guarded(void *fn, const unsigned long args[6]);
 *   x0 = fn, x1 = args -> loads args[0..5] into x0..x5, blr fn, returns x0.
 */
	.text
	.globl	_bench_call_guarded
	.align	2
_bench_call_guarded:
	stp	x29, x30, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	mov	x19, x0			/* fn */
	mov	x20, x1			/* args */
	ldr	x5, [x20, #40]
	ldr	x4, [x20, #32]
	ldr	x3, [x20, #24]
	ldr	x2, [x20, #16]
	ldr	x1, [x20, #8]
	ldr	x0, [x20, #0]
	blr	x19
	ldp	x19, x20, [sp], #16
	ldp	x29, x30, [sp], #16
	ret
