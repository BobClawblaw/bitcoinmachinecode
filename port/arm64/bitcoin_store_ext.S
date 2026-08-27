/* ============================================================================
 * bitcoin_store_ext.S -- AArch64 port of the asm/bitcoin_store.asm exported
 * functions that the already-ported port/arm64/bitcoin_store.S does not
 * provide, but which the daemon C requires (main.c, daemon/reorg.c,
 * daemon/archive_verify.c): store_get_tip_hash, store_validates_prevhash,
 * store_layout_monotonic, store_truncate_to, store_truncate_index_only.
 *
 * The store struct offsets mirror the x86 ABI: st+0 cur_blk_fd, st+8 idx_fd,
 * st+16 idx_len, st+24 tip_height (dword), st+28 cur_file_no (dword),
 * st+32 cur_file_pos (dword).
 *
 * AArch64 syscalls used: pread64=67 ftruncate=46 unlinkat=35 openat=56.
 * ========================================================================== */

	.extern fmt_blkname
	.extern store_get_file_fd

	.text

/* local blk-file unlink: unlink_blk(st, file_no). Builds blk%05d.dat via
   fmt_blkname(buf, file_no), then unlinkat(AT_FDCWD, buf, 0). */
	.type .Lext_unlink_blk, %function
.Lext_unlink_blk:
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #32
	/* stack buf for blkname */
	add  x0, sp, #0
	mov  x1, x1                       /* file_no */
	bl   fmt_blkname
	/* unlinkat(AT_FDCWD=-100, pathname, 0) */
	mov  x0, #-100
	add  x1, sp, #0
	mov  x2, #0
	mov  x8, #35
	svc  #0
	add  sp, sp, #32
	ldp  x29, x30, [sp], #16
	ret
	.size .Lext_unlink_blk, .-.Lext_unlink_blk

/* ============================================================================
 * store_get_tip_hash(st, out_hash[32]) -> 1 ok / -1 (empty store)
 * ========================================================================== */
	.global store_get_tip_hash
	.type store_get_tip_hash, %function
store_get_tip_hash:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	mov  x19, x0                       /* st */
	mov  x20, x1                       /* out_hash */
	ldr  w9, [x19, #24]                /* tip_height */
	cmp  w9, #-1
	b.eq 1f
	/* pread64(idx_fd, out_hash, 32, tip_height*48) */
	mov  x0, x19
	ldr  x0, [x19, #8]                 /* idx_fd */
	mov  x1, x20
	mov  x2, #32
	sxtw x3, w9                        /* height */
	mov  x4, #48
	mul  x3, x3, x4
	mov  x8, #67                       /* pread64 */
	svc  #0
	cmp  x0, #32
	b.ne 1f
	mov  x0, #1
	b    2f
1:	mov  x0, #-1
2:	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size store_get_tip_hash, .-store_get_tip_hash

/* ============================================================================
 * store_validates_prevhash(st, block_header[80]) -> 1 match / 0 / -1
 * ========================================================================== */
	.global store_validates_prevhash
	.type store_validates_prevhash, %function
store_validates_prevhash:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	sub  sp, sp, #48
	mov  x19, x0                       /* st */
	mov  x20, x1                       /* header */
	mov  x0, x19
	add  x1, sp, #0                    /* tip_hash[32] */
	bl   store_get_tip_hash
	cmp  x0, #1
	b.ne 1f
	/* compare header+4 vs tip_hash, 32 bytes */
	add  x0, x20, #4
	add  x1, sp, #0
	mov  x2, #32
	bl   .Lext_cmpeq
	cbnz x0, 2f
	mov  w0, #0
	b    3f
2:	mov  w0, #1
	b    3f
1:	mov  x0, #-1
3:	add  sp, sp, #48
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size store_validates_prevhash, .-store_validates_prevhash

/* cmpeq(a=x0, b=x1, n=x2) -> x0 1/0. Leaf. */
	.type .Lext_cmpeq, %function
.Lext_cmpeq:
	mov  x3, #0
5:	cmp  x3, x2
	b.hs 6f
	ldrb w4, [x0, x3]
	ldrb w5, [x1, x3]
	cmp  w4, w5
	b.ne 7f
	add  x3, x3, #1
	b    5b
6:	mov  x0, #1
	ret
7:	mov  x0, #0
	ret
	.size .Lext_cmpeq, .-.Lext_cmpeq

/* ============================================================================
 * store_layout_monotonic(st, upto_height) -> 1 monotonic / 0 NOT
 * ========================================================================== */
	.global store_layout_monotonic
	.type store_layout_monotonic, %function
store_layout_monotonic:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	sub  sp, sp, #64
	mov  x19, x0                       /* st */
	mov  x20, x1                       /* upto_height */
	mov  x21, #0                       /* h = 0 */
	mov  x22, #0                       /* prev_file_no */
	mov  x23, #0                       /* prev_data_pos */
	mov  x24, #0                       /* seen */
.Lslm_loop:
	cmp  x21, x20
	b.gt .Lslm_ok
	/* pread64(idx_fd, rec@sp, 48, h*48) */
	mov  x0, x19
	ldr  x0, [x19, #8]                 /* idx_fd */
	add  x1, sp, #16                   /* rec (sp+16..+63) */
	mov  x2, #48
	mov  x3, x21
	mov  x4, #48
	mul  x3, x3, x4
	mov  x8, #67
	svc  #0
	cmp  x0, #48
	b.ne .Lslm_ok
	ldr  w9, [sp, #16]                 /* rec.hash prefix (dword) */
	cbz  w9, .Lslm_next
	ldr  w10, [sp, #48]                /* rec.file_no (u32) */
	ldr  x11, [sp, #52]                /* rec.data_pos (u64) */
	cbnz x24, .Lslm_cmp
	b    .Lslm_store
.Lslm_cmp:
	cmp  x10, x22
	b.lo .Lslm_bad
	b.hi .Lslm_store
	cmp  x11, x23
	b.lo .Lslm_bad
.Lslm_store:
	mov  x22, x10
	mov  x23, x11
	mov  x24, #1
.Lslm_next:
	add  x21, x21, #1
	b    .Lslm_loop
.Lslm_bad:
	mov  x0, #0
	b    .Lslm_ret
.Lslm_ok:
	mov  x0, #1
.Lslm_ret:
	add  sp, sp, #64
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size store_layout_monotonic, .-store_layout_monotonic

/* ============================================================================
 * store_truncate_to(st, target_height) -> 1 ok / -1 err
 * ========================================================================== */
	.global store_truncate_to
	.type store_truncate_to, %function
store_truncate_to:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	sub  sp, sp, #80
	mov  x19, x0                       /* st */
	mov  x20, x1                       /* target_height */
	ldr  w9, [x19, #24]                /* tip */
	cmp  w9, #-1
	b.eq .Ltt_noop
	sxtw x9, w9
	cmp  x20, x9
	b.ge .Ltt_noop
	cmp  x20, #-1
	b.eq .Ltt_full
	/* safety gate: layout_monotonic(st, target+1) */
	mov  x1, x20
	add  x1, x1, #1
	mov  x0, x19
	bl   store_layout_monotonic
	cbz  x0, .Ltt_err
	/* read index record at (target+1)*48 -> boundary (file_no,data_pos) */
	add  x1, sp, #0                    /* rec[48] */
	mov  x0, x19
	ldr  x0, [x19, #8]                 /* idx_fd */
	mov  x2, #48
	add  x3, x20, #1
	mov  x4, #48
	mul  x3, x3, x4
	mov  x8, #67
	svc  #0
	cmp  x0, #48
	b.ne .Ltt_err
	ldr  w21, [sp, #32]                /* boundary_file_no */
	ldr  x22, [sp, #36]                /* boundary_data_pos */
	/* ftruncate(index.dat, (target+1)*48) */
	mov  x0, x19
	ldr  x0, [x19, #8]
	add  x1, x20, #1
	mov  x2, #48
	mul  x1, x1, x2
	mov  x8, #46                       /* ftruncate */
	svc  #0
	tbnz x0, #63, .Ltt_err
	/* open boundary blk file via store_get_file_fd(st, file_no) */
	mov  x0, x19
	mov  x1, x21
	bl   store_get_file_fd
	cmp  x0, #0
	b.lt .Ltt_err
	mov  x23, x0                       /* boundary fd */
	/* ftruncate(fd, boundary_data_pos) */
	mov  x0, x23
	mov  x1, x22
	mov  x8, #46
	svc  #0
	tbnz x0, #63, .Ltt_err
	/* delete later blk files (file_no > boundary) */
	ldr  w24, [x19, #28]               /* orig cur_file_no */
	cmp  w24, w21
	b.ls .Ltt_no_later
	mov  x9, x21
	add  x9, x9, #1                    /* first to delete */
.Ltt_dellater:
	cmp  w9, w24
	b.hi .Ltt_no_later
	mov  x0, x19
	mov  x1, x9
	bl   .Lext_unlink_blk
	add  x9, x9, #1
	b    .Ltt_dellater
.Ltt_no_later:
	/* update in-memory state */
	str  w21, [x19, #28]               /* cur_file_no */
	str  w22, [x19, #32]               /* cur_file_pos (w) */
	add  x9, x20, #1
	mov  x10, #48
	mul  x9, x9, x10
	str  x9, [x19, #16]                /* idx_len */
	str  w20, [x19, #24]               /* tip_height */
	mov  x0, #1
	b    .Ltt_ret
.Ltt_noop:
	mov  x0, #1
	b    .Ltt_ret
.Ltt_full:
	/* ftruncate(index.dat, 0) */
	mov  x0, x19
	ldr  x0, [x19, #8]
	mov  x1, #0
	mov  x8, #46
	svc  #0
	tbnz x0, #63, .Ltt_err
	/* delete all blk files */
	mov  x23, #0
12:	ldr  w24, [x19, #28]
	cmp  w23, w24
	b.hi 13f
	mov  x0, x19
	mov  x1, x23
	bl   .Lext_unlink_blk
	add  x23, x23, #1
	b    12b
13:	mov  x9, #0
	str  x9, [x19, #16]                /* idx_len = 0 */
	mov  w9, #-1
	str  w9, [x19, #24]                /* tip = -1 */
	mov  w9, #0
	str  w9, [x19, #28]
	str  w9, [x19, #32]
	mov  x9, #-1
	str  x9, [x19, #0]                 /* cur_blk_fd = none */
	mov  x0, #1
	b    .Ltt_ret
.Ltt_err:
	mov  x0, #-1
.Ltt_ret:
	add  sp, sp, #80
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret
	.size store_truncate_to, .-store_truncate_to

/* ============================================================================
 * store_truncate_index_only(st, target_height) -> 1 ok / -1 err
 * ========================================================================== */
	.global store_truncate_index_only
	.type store_truncate_index_only, %function
store_truncate_index_only:
	stp  x29, x30, [sp, #-16]!
	mov  x19, x0                       /* st */
	mov  x20, x1                       /* target_height */
	ldr  w9, [x19, #24]
	cmp  w9, #-1
	b.eq .Ltio_noop
	sxtw x9, w9
	cmp  x20, x9
	b.ge .Ltio_noop
	cmp  x20, #-1
	b.eq .Ltio_full
	/* ftruncate(index.dat, (target+1)*48) */
	mov  x21, x20
	add  x21, x21, #1
	mov  x22, #48
	mul  x21, x21, x22
	ldr  x0, [x19, #8]
	mov  x1, x21
	mov  x8, #46
	svc  #0
	tbnz x0, #63, .Ltio_err
	str  x21, [x19, #16]               /* idx_len */
	str  w20, [x19, #24]
	mov  x0, #1
	b    .Ltio_ret
.Ltio_full:
	ldr  x0, [x19, #8]
	mov  x1, #0
	mov  x8, #46
	svc  #0
	tbnz x0, #63, .Ltio_err
	str  xzr, [x19, #16]
	mov  w9, #-1
	str  w9, [x19, #24]
	mov  x0, #1
	b    .Ltio_ret
.Ltio_noop:
	mov  x0, #1
	b    .Ltio_ret
.Ltio_err:
	mov  x0, #-1
.Ltio_ret:
	ldp  x29, x30, [sp], #16
	ret
	.size store_truncate_index_only, .-store_truncate_index_only

	.section .note.GNU-stack,"",%progbits
