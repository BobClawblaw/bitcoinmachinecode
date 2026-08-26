/* ============================================================================
 * bitcoin_txv_pools.S -- AArch64 (ARMv8-A) port of asm/bitcoin_txv_pools.asm
 *
 * The tx_verify allocation arenas. Growth uses libc realloc like the x86
 * original (this layer's discipline; "no-libc" is only bitcoin_store's rule).
 * Includes the witpool/bytepool struct offsets and the C twin's exact
 * commit-order quirk (ptr then len; commit whichever succeeded before the
 * OOM check) so a half-grown pool after OOM matches the C exactly.
 *
 * Struct offsets (offsetof-pinned): witpool_t ptr@0 len@8 cap@16 used@24;
 * bytepool_t buf@0 cap@8 used@16.
 *
 * ABI (x64 -> AAPCS64):
 *   u64   txv_witpool_reserve_asm (witpool_t*, u64 n) -> off / ~0
 *   u64   txv_bytepool_reserve_asm(bytepool_t*, u64 n) -> off / ~0
 *   u64   txv_bytepool_alloc_asm (bytepool_t*, const u8* src, u64 n) -> off / ~0
 *   void* txv_grow_arena_asm     (void** buf, u64* cap, u64 need) -> ptr / 0
 * ========================================================================== */

	.text
	.global txv_witpool_reserve_asm
	.type txv_witpool_reserve_asm, %function
	.global txv_bytepool_reserve_asm
	.type txv_bytepool_reserve_asm, %function
	.global txv_bytepool_alloc_asm
	.type txv_bytepool_alloc_asm, %function
	.global txv_grow_arena_asm
	.type txv_grow_arena_asm, %function

	.extern realloc

/* ============================================================================
 * txv_witpool_reserve_asm(wp, n) -> off / ~0
 *   Regs: x19=wp x20=n x21=newcap x22=np (callee-saved across realloc).
 * ========================================================================== */
txv_witpool_reserve_asm:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	mov  x19, x0                 /* wp */
	mov  x20, x1                 /* n */
	ldr  x9, [x19, #24]          /* used */
	add  x9, x9, x20
	ldr  x10, [x19, #16]         /* cap */
	cmp  x9, x10
	b.ls .Tw_fit
	mov  x21, x10
	cbnz x21, .Tw_dbl
	mov  x21, #4096
.Tw_dbl:
	ldr  x9, [x19, #24]
	add  x9, x9, x20
	cmp  x21, x9
	b.hs .Tw_grown
	lsl  x21, x21, #1
	b    .Tw_dbl
.Tw_grown:
	ldr  x0, [x19, #0]           /* wp->ptr */
	lsl  x1, x21, #3             /* newcap*8 */
	bl   realloc
	mov  x22, x0                 /* np */
	ldr  x0, [x19, #8]           /* wp->len */
	lsl  x1, x21, #2             /* newcap*4 */
	bl   realloc                 /* nl in x0 */
	cbz  x22, .Tw_skip_ptr
	str  x22, [x19, #0]
.Tw_skip_ptr:
	cbz  x0, .Tw_skip_len
	str  x0, [x19, #8]
.Tw_skip_len:
	cbz  x22, .Tw_oom
	cbz  x0, .Tw_oom
	str  x21, [x19, #16]         /* cap = newcap */
.Tw_fit:
	ldr  x9, [x19, #24]          /* used */
	add  x10, x9, x20
	str  x10, [x19, #24]         /* used += n */
	mov  x0, x9                  /* off = old used */
	b    .Tw_out
.Tw_oom:
	mov  x0, #-1
.Tw_out:
	ldp  x29, x30, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size txv_witpool_reserve_asm, .-txv_witpool_reserve_asm

/* ============================================================================
 * txv_bytepool_reserve_asm(pool, n) -> off / ~0   (doubling from 65536)
 *   Regs: x19=pool x20=n x21=newcap.
 * ========================================================================== */
txv_bytepool_reserve_asm:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x29, [sp, #-16]!
	stp  x30, xzr, [sp, #-16]!
	mov  x19, x0                 /* pool */
	mov  x20, x1                 /* n */
	ldr  x9, [x19, #16]          /* used */
	add  x9, x9, x20
	ldr  x10, [x19, #8]          /* cap */
	cmp  x9, x10
	b.ls .Tb_fit
	mov  x21, x10
	cbnz x21, .Tb_dbl
	movz w21, #0x1, lsl #16      /* 65536 = 0x10000 */
.Tb_dbl:
	ldr  x9, [x19, #16]
	add  x9, x9, x20
	cmp  x21, x9
	b.hs .Tb_grown
	lsl  x21, x21, #1
	b    .Tb_dbl
.Tb_grown:
	ldr  x0, [x19, #0]           /* buf */
	mov  x1, x21
	bl   realloc
	cbz  x0, .Tb_oom
	str  x0, [x19, #0]
	str  x21, [x19, #8]
.Tb_fit:
	ldr  x9, [x19, #16]
	add  x10, x9, x20
	str  x10, [x19, #16]         /* used += n */
	mov  x0, x9                  /* off */
	b    .Tb_out
.Tb_oom:
	mov  x0, #-1
.Tb_out:
	ldp  x30, xzr, [sp], #16
	ldp  x21, x29, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size txv_bytepool_reserve_asm, .-txv_bytepool_reserve_asm

/* ============================================================================
 * txv_bytepool_alloc_asm(pool, src, n) -> off / ~0
 *   reserve + inline bump-copy (no libc memcpy needed, mirrors rep movsb).
 *   Regs: x19=pool x20=src x21=n x22=off.
 * ========================================================================== */
txv_bytepool_alloc_asm:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	mov  x19, x0                 /* pool */
	mov  x20, x1                 /* src */
	mov  x21, x2                 /* n */
	mov  x0, x19
	mov  x1, x21
	bl   txv_bytepool_reserve_asm
	cmp  x0, #-1
	b.eq .Ta_out
	mov  x22, x0                 /* off */
	ldr  x9, [x19, #0]           /* buf */
	add  x9, x9, x22             /* dst */
	mov  x10, x20                /* src */
	add  x11, x10, x21           /* src_end */
	cbz  x21, .Ta_ret
.Ta_copy:
	cmp  x10, x11
	b.hs .Ta_ret
	ldrb w12, [x10], #1
	strb w12, [x9], #1
	b    .Ta_copy
.Ta_ret:
	mov  x0, x22
.Ta_out:
	ldp  x29, x30, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size txv_bytepool_alloc_asm, .-txv_bytepool_alloc_asm

/* ============================================================================
 * txv_grow_arena_asm(&buf, &cap, need) -> ptr / 0  (*buf/*cap untouched on 0)
 *   Regs: x19=&buf x20=&cap x21=need.
 * ========================================================================== */
txv_grow_arena_asm:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x29, [sp, #-16]!
	stp  x30, xzr, [sp, #-16]!
	mov  x19, x0                 /* &buf */
	mov  x20, x1                 /* &cap */
	mov  x21, x2                 /* need */
	ldr  x9, [x20]               /* *cap */
	cmp  x21, x9
	b.ls .Tg_have
	ldr  x0, [x19]
	mov  x1, x21
	bl   realloc
	cbz  x0, .Tg_out
	str  x0, [x19]               /* *buf = p */
	str  x21, [x20]              /* *cap = need */
	b    .Tg_out
.Tg_have:
	ldr  x0, [x19]
.Tg_out:
	ldp  x30, xzr, [sp], #16
	ldp  x21, x29, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size txv_grow_arena_asm, .-txv_grow_arena_asm

	.section .note.GNU-stack,"",%progbits
