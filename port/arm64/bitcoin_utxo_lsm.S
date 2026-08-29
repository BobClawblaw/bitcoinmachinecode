/* bitcoin_utxo_lsm.S -- AArch64 port of asm/bitcoin_utxo_lsm.asm.
 * LSM-tree-style persistent UTXO store layered on bitcoin_utxo.asm
 * (memtable+WAL) and bitcoin_utxo_store.asm (utxo_store_init/put/del/
 * reload/close). Adds: per-generation sorted immutable "runs" on disk
 * with a 3-seed FNV bloom filter + sparse index, a crash-safe manifest
 * (tmp+fsync+rename), tombstones, multi-run point lookup, k-way merge
 * compaction, and a per-thread TLS scratch for get()'s bloom/script.
 *
 * Same exported symbols as the x86 original: utxo_lsm_init/put/del/count/
 * get/flush/reload/reload_ro/walk/compact/close + lsm_get_scratch (TLS).
 *
 * lst struct byte offsets (168 bytes total):
 *   +0 log_fd +8 idx_fd +16 log_len +24 ckpt_log_off +32 ckpt_n
 *   +40 op_count +48 op_threshold +56 fill_threshold
 *   +64 tomb_buf +72 tomb_cap +80 tomb_n
 *   +88 total_live +96 next_gen +104 manifest_buf +112 manifest_cap +120 manifest_n
 *   +128 scratch_buf +136 scratch_cap +144 next_run_no
 *   +152 tomb_hash_buf +160 tomb_hash_mask
 *
 * AArch64 syscalls: openat=56 read=63 write=64 close=57 lseek=62 fsync=82
 * ftruncate=46 mmap=222 munmap=215 unlinkat=35 renameat=38. AT_FDCWD=-100.
 * NOTE: there is no rename/unlink on AArch64 -- rename -> renameat(d,-100...),
 * unlink -> unlinkat(d,-100,path,0).
 */
	.section .text
	.balign 4

MAGIC_RUN       = 0x4E555255
MAGIC_RUN2      = 0x32555255
MAGIC_RUN3      = 0x33555255
MAGIC_MANIFEST  = 0x4E414D55
MAGIC_MANIFEST2 = 0x324E4D55
BLOOM_MAX_BYTES = 4194304
SCRIPT_MAX_BYTES= 65536
SPARSE_STRIDE   = 256
SPARSE_ENT_SIZE = 44
COMPACT_MAX_RUNS  = 64
COMPACT_SLOT_SIZE = 65640          /* 104 + SCRIPT_MAX_BYTES */
COMPACT_SLOTS_BYTES  = 4200960     /* 64 * 65640 */
COMPACT_SCRATCH_BYTES = 8395264    /* + BLOOM_MAX_BYTES */
O_RDONLY = 0
O_WRONLY = 1
O_RDWR   = 2
O_CREAT  = 0x40
O_TRUNC  = 0x200
AT_FDCWD = -100
SYS_read    = 63
SYS_write   = 64
SYS_close   = 57
SYS_lseek   = 62
SYS_fsync   = 82
SYS_openat  = 56
SYS_mmap    = 222
SYS_munmap  = 215
SYS_ftruncate= 46
SYS_unlinkat= 35
SYS_renameat= 38

/* TLS Initial-Exec: load the base of lsm_get_scratch into \dst. */
.macro TLS_BASE dst
	adrp \dst, :gottprel:lsm_get_scratch
	ldr  \dst, [\dst, #:gottprel_lo12:lsm_get_scratch]
	mrs  x16, tpidr_el0
	add  \dst, \dst, x16
.endm

	.section .tbss,"awT",@nobits
	.balign 16
	.global lsm_get_scratch
	.type   lsm_get_scratch,%object
lsm_get_scratch:
	.zero BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES
	.size lsm_get_scratch, BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES
	.section .text

/* ---------------------------------------------------------------------------
 * small local helpers
 * ------------------------------------------------------------------------- */

/* mac_memcpy(dst=x0, src=x1, n=x2) -- preserves x0..x6; clobbers x7+ only. */
mac_memcpy:
	mov  x7, #0
.mm_l:
	cmp  x7, x2
	b.hs .mm_d
	ldrb w8, [x1, x7]
	strb w8, [x0, x7]
	add  x7, x7, #1
	b    .mm_l
.mm_d:
	ret

/* mac_read_exact2(fd=x0, buf=x1, len=x2) -> 0 ok / -1. caller-saved only. */
mac_read_exact2:
	mov  x11, x0
	mov  x10, x1
	mov  x9, x2
.mre_l:
	cbz  x9, .mre_ok
	mov  x0, x11
	mov  x1, x10
	mov  x2, x9
	mov  x8, #SYS_read
	svc  #0
	cbz  x0, .mre_bad
	tbnz x0, #63, .mre_bad
	add  x10, x10, x0
	sub  x9, x9, x0
	b    .mre_l
.mre_bad:
	mov  x0, #-1
	ret
.mre_ok:
	mov  x0, #0
	ret

/* mac_write_exact(fd=x0, buf=x1, len=x2) -> 0 ok / -1. caller-saved only. */
mac_write_exact:
	mov  x11, x0
	mov  x10, x1
	mov  x9, x2
.mwe_l:
	cbz  x9, .mwe_ok
	mov  x0, x11
	mov  x1, x10
	mov  x2, x9
	mov  x8, #SYS_write
	svc  #0
	cbz  x0, .mwe_bad
	tbnz x0, #63, .mwe_bad
	add  x10, x10, x0
	sub  x9, x9, x0
	b    .mwe_l
.mwe_bad:
	mov  x0, #-1
	ret
.mwe_ok:
	mov  x0, #0
	ret

/* mac_fsync2(fd=x0) -> rax (0 ok) */
mac_fsync2:
	mov  x8, #SYS_fsync
	svc  #0
	ret

/* mac_cmp_key(p=x0, q=x1) -> w0: 0=p<q 1=p==q 2=p>q (36-byte unsigned, BE chunks)
 * Clobbers x0-x5 only. */
mac_cmp_key:
	ldr  x2, [x0]
	ldr  x3, [x1]
	rev  x2, x2
	rev  x3, x3
	cmp  x2, x3
	b.ne .ck_diff
	ldr  x2, [x0, #8]
	ldr  x3, [x1, #8]
	rev  x2, x2
	rev  x3, x3
	cmp  x2, x3
	b.ne .ck_diff
	ldr  x2, [x0, #16]
	ldr  x3, [x1, #16]
	rev  x2, x2
	rev  x3, x3
	cmp  x2, x3
	b.ne .ck_diff
	ldr  x2, [x0, #24]
	ldr  x3, [x1, #24]
	rev  x2, x2
	rev  x3, x3
	cmp  x2, x3
	b.ne .ck_diff
	ldr  w2, [x0, #32]
	ldr  w3, [x1, #32]
	rev  w2, w2
	rev  w3, w3
	cmp  w2, w3
	b.ne .ck_diff
	mov  w0, #1
	ret
.ck_diff:
	b.cc .ck_lt
	mov  w0, #2
	ret
.ck_lt:
	mov  w0, #0
	ret

/* mac_bloom_h(key=x0 (36B), seed=w1) -> w0 FNV-1a 32-bit hash. clobbers x9-x12. */
mac_bloom_h:
	mov  w9, w1
	mov  x10, #0
.bh_l:
	cmp  x10, #36
	b.hs .bh_d
	ldrb w11, [x0, x10]
	eor  w9, w9, w11
	mov  w12, #0x0193
	movk w12, #0x0100, lsl #16       /* 16777619 */
	mul  w9, w9, w12
	add  x10, x10, #1
	b    .bh_l
.bh_d:
	mov  w0, w9
	ret

/* mac_bloom_setbit(key=x0, seed=w1, bloom_base=x2, bits_mask=w3). clobbers x9+ */
mac_bloom_setbit:
	stp  x29,x30,[sp,#-16]!
	bl   mac_bloom_h
	and  w4, w0, w3
	lsr  w5, w4, #3
	and  w4, w4, #7
	mov  w6, #1
	lsl  w6, w6, w4
	add  x5, x2, x5
	ldrb w9, [x5]
	orr  w9, w9, w6
	strb w9, [x5]
	ldp  x29,x30,[sp],#16
	ret

/* mac_bloom_testbit(key=x0, seed=w1, bloom_base=x2, bits_mask=w3) -> w0 1/0 */
mac_bloom_testbit:
	stp  x29,x30,[sp,#-16]!
	bl   mac_bloom_h
	and  w4, w0, w3
	lsr  w5, w4, #3
	and  w4, w4, #7
	mov  w6, #1
	lsl  w6, w6, w4
	add  x5, x2, x5
	ldrb w9, [x5]
	lsr  w9, w9, w4
	and  w0, w9, #1
	ldp  x29,x30,[sp],#16
	ret

/* mac_clear_memtable(u=x0) -- reset in-memory table, reuse mask/blob/blob_cap */
mac_clear_memtable:
	mov  x9, x0
	str  xzr, [x9]
	str  xzr, [x9, #32]
	ldr  x10, [x9, #8]
	add  x10, x10, #1
	add  x11, x9, #40
.cm_l:
	cbz  x10, .cm_d
	mov  w12, #-1
	str  w12, [x11, #40]
	add  x11, x11, #48
	sub  x10, x10, #1
	b    .cm_l
.cm_d:
	ret

/* mac_calc_desc_cap(lst=x0) -> (scratch_cap - BLOOM_MAX_BYTES - SCRIPT_MAX_BYTES)/128 */
mac_calc_desc_cap:
	ldr  x1, [x0, #136]
	movz x2, #0x40, lsl #16
	sub  x1, x1, x2                /* - BLOOM_MAX_BYTES (4MiB) */
	movz x2, #1, lsl #16
	sub  x1, x1, x2                /* - SCRIPT_MAX_BYTES (64KiB) */
	lsr  x0, x1, #7                /* /128 */
	ret

/* fmt_runname(buf=x0, run_no=w1) -- "utxo_run_%06u.dat\0" (20 bytes) */
fmt_runname:
	mov  w9, #'u' ; strb w9, [x0, #0]
	mov  w9, #'t' ; strb w9, [x0, #1]
	mov  w9, #'x' ; strb w9, [x0, #2]
	mov  w9, #'o' ; strb w9, [x0, #3]
	mov  w9, #'_' ; strb w9, [x0, #4]
	mov  w9, #'r' ; strb w9, [x0, #5]
	mov  w9, #'u' ; strb w9, [x0, #6]
	mov  w9, #'n' ; strb w9, [x0, #7]
	mov  w9, #'_' ; strb w9, [x0, #8]
	mov  w2, w1
	mov  w3, #0x86a0
	movk w3, #0x0001, lsl #16       /* 100000 */
	udiv w4, w2, w3
	add  w5, w4, #'0'
	strb w5, [x0, #9]
	msub w2, w4, w3, w2
	mov  w3, #10000
	udiv w4, w2, w3
	add  w5, w4, #'0'
	strb w5, [x0, #10]
	msub w2, w4, w3, w2
	mov  w3, #1000
	udiv w4, w2, w3
	add  w5, w4, #'0'
	strb w5, [x0, #11]
	msub w2, w4, w3, w2
	mov  w3, #100
	udiv w4, w2, w3
	add  w5, w4, #'0'
	strb w5, [x0, #12]
	msub w2, w4, w3, w2
	mov  w3, #10
	udiv w4, w2, w3
	add  w5, w4, #'0'
	strb w5, [x0, #13]
	msub w2, w4, w3, w2
	add  w5, w2, #'0'
	strb w5, [x0, #14]
	mov  w9, #0x642E              /* ".d" LE */
	movk w9, #0x7461, lsl #16     /* 0x7461642E = 'a','t','.','d' */
	str  w9, [x0, #15]
	strb wzr, [x0, #19]
	ret

/* mac_copy_rec(dst=x0, src=x1) - copy fixed 64-byte descriptor. clobbers x7+ */
mac_copy_rec:
	mov  x7, #0
.cp_l:
	cmp  x7, #64
	b.hs .cp_d
	ldrb w8, [x1, x7]
	strb w8, [x0, x7]
	add  x7, x7, #1
	b    .cp_l
.cp_d:
	ret

/* mac_tomb_hash_reset(lst=x0) -> 1 ok / -1 err */
	.type mac_tomb_hash_reset,%function
mac_tomb_hash_reset:
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	mov  x19, x0
	ldr  x20, [x19, #152]
	cbnz x20, .thr_fill
	ldr  x21, [x19, #72]           /* tomb_cap */
	cmp  x21, #1
	b.hs .thr_min_ok
	mov  x21, #1
.thr_min_ok:
	lsl  x21, x21, #1
	sub  x21, x21, #1
	lsr  x22, x21, #1
	orr  x21, x21, x22
	lsr  x22, x21, #2
	orr  x21, x21, x22
	lsr  x22, x21, #4
	orr  x21, x21, x22
	lsr  x22, x21, #8
	orr  x21, x21, x22
	lsr  x22, x21, #16
	orr  x21, x21, x22
	lsr  x22, x21, #32
	orr  x21, x21, x22
	add  x21, x21, #1              /* x21 = cap_pow2 */
	mov  x22, x21
	lsl  x21, x21, #3              /* bytes */
	mov  x0, #0
	mov  x1, x21
	mov  x2, #3                    /* PROT_READ|PROT_WRITE */
	mov  x3, #0x22                 /* MAP_PRIVATE|MAP_ANONYMOUS */
	mov  x4, #-1
	mov  x5, #0
	mov  x8, #SYS_mmap
	svc  #0
	mov  x23, #-1
	cmp  x0, x23
	b.eq .thr_err
	str  x0, [x19, #152]
	sub  x22, x22, #1
	str  x22, [x19, #160]
	mov  x20, x0
.thr_fill:
	ldr  x20, [x19, #152]
	ldr  x21, [x19, #160]
	add  x21, x21, #1              /* slot count = mask+1 */
	mov  x22, #-1
.thr_fl:
	cbz  x21, .thr_done
	str  x22, [x20]
	add  x20, x20, #8
	sub  x21, x21, #1
	b    .thr_fl
.thr_done:
	mov  x0, #1
	b    .thr_out
.thr_err:
	mov  x0, #-1
.thr_out:
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ret
	.size mac_tomb_hash_reset,.-mac_tomb_hash_reset

/* mac_tomb_hash_probe(lst=x0, key=x1) -> x0 = &slot (open-addressing find/insert).
 * Preserves x1 (key); clobbers no callee-saved other than pushed. */
	.type mac_tomb_hash_probe,%function
mac_tomb_hash_probe:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	mov  x19, x0                    /* lst */
	mov  x20, x1                    /* key */
	/* FNV-1a over first 8 key bytes */
	mov  w9, #0x9dc5
	movk w9, #0x811c, lsl #16
	mov  x10, #0
.hp_hl:
	cmp  x10, #8
	b.hs .hp_hdone
	ldrb w11, [x20, x10]
	eor  w9, w9, w11
	mov  w12, #0x0193
	movk w12, #0x0100, lsl #16       /* 16777619 */
	mul  w9, w9, w12
	add  x10, x10, #1
	b    .hp_hl
.hp_hdone:
	ldr  w11, [x20, #32]           /* vout index */
	eor  x9, x9, x11
	ldr  x24, [x19, #160]          /* mask */
	and  x22, x9, x24              /* starting probe index */
	ldr  x21, [x19, #152]          /* tomb_hash_buf base */
	ldr  x23, [x19, #64]           /* tomb_buf base */
.hp_probe:
	add  x12, x21, x22, lsl #3     /* &slot */
	ldr  x13, [x12]
	mov  x14, #-1
	cmp  x13, x14
	b.eq .hp_ret
	mov  x15, #36
	mul  x14, x13, x15
	add  x14, x14, x23             /* &tomb_buf[slot] */
	mov  x0, x14
	mov  x1, x20
	bl   mac_cmp_key
	cmp  w0, #1
	b.eq .hp_ret
	add  x22, x22, #1
	and  x22, x22, x24
	b    .hp_probe
.hp_ret:
	add  x0, x21, x22, lsl #3
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size mac_tomb_hash_probe,.-mac_tomb_hash_probe

/* ---------------------------------------------------------------------------
 * mac_read_run_header(fd=x0, out=x1) -> 0 ok / -1 err.
 * out (64-byte buf): +0 gen +8 nrec +16 bloom_bytes +24 bits_mask
 *   +32 header_size (28/44) +40 sparse_off +48 sparse_n +56 rec_v2
 * ------------------------------------------------------------------------- */
	.type mac_read_run_header,%function
mac_read_run_header:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	mov  x19, x0                    /* fd */
	mov  x20, x1                    /* out */
	sub  sp, sp, #0x40
	/* read magic (4 bytes) into [sp] */
	mov  x0, x19
	add  x1, sp, #0x00
	mov  x2, #4
	bl   mac_read_exact2
	cbnz x0, .rh_err
	ldr  w9, [sp, #0x00]
	mov  w10, #0x5255
	movk w10, #0x3355, lsl #16       /* MAGIC_RUN3 */
	cmp  w9, w10
	b.eq .rh_new3
	mov  w10, #0x5255
	movk w10, #0x3255, lsl #16       /* MAGIC_RUN2 */
	cmp  w9, w10
	b.eq .rh_new2
	mov  w10, #0x5255
	movk w10, #0x4e55, lsl #16       /* MAGIC_RUN */
	cmp  w9, w10
	b.ne .rh_err
	/* ---- old format: read 24 bytes gen+nrec+bloom_bits ---- */
	mov  x0, x19
	add  x1, sp, #0x08
	mov  x2, #24
	bl   mac_read_exact2
	cbnz x0, .rh_err
	ldr  x9, [sp, #0x08]
	str  x9, [x20, #0]              /* gen */
	ldr  x9, [sp, #0x10]
	str  x9, [x20, #8]              /* nrec */
	ldr  x9, [sp, #0x18]
	mov  x10, x9
	sub  x10, x10, #1
	str  x10, [x20, #24]            /* bits_mask */
	lsr  x9, x9, #3
	str  x9, [x20, #16]             /* bloom_bytes */
	str  xzr, [x20, #40]            /* sparse_off */
	str  xzr, [x20, #48]            /* sparse_n */
	str  xzr, [x20, #56]            /* rec_v2 */
	mov  x9, #28
	str  x9, [x20, #32]             /* header_size */
	b    .rh_ret_ok
.rh_new2:
	mov  x9, #0
	b    .rh_new_common
.rh_new3:
	mov  x9, #1
.rh_new_common:
	/* x9 = rec_v2. read 40 bytes gen+nrec+bloom_bits+sparse_off+sparse_n */
	str  x9, [sp, #0x38]
	mov  x0, x19
	add  x1, sp, #0x08
	mov  x2, #40
	bl   mac_read_exact2
	cbnz x0, .rh_err
	ldr  x9, [sp, #0x08]
	str  x9, [x20, #0]              /* gen */
	ldr  x9, [sp, #0x10]
	str  x9, [x20, #8]              /* nrec */
	ldr  x9, [sp, #0x18]
	mov  x10, x9
	sub  x10, x10, #1
	str  x10, [x20, #24]            /* bits_mask */
	lsr  x9, x9, #3
	str  x9, [x20, #16]             /* bloom_bytes */
	ldr  x9, [sp, #0x20]
	str  x9, [x20, #40]             /* sparse_off */
	ldr  x9, [sp, #0x28]
	str  x9, [x20, #48]             /* sparse_n */
	mov  x9, #44
	str  x9, [x20, #32]             /* header_size */
	ldr  x9, [sp, #0x38]
	str  x9, [x20, #56]             /* rec_v2 */
.rh_ret_ok:
	mov  x0, #0
	b    .rh_ret
.rh_err:
	mov  x0, #-1
.rh_ret:
	add  sp, sp, #0x40
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size mac_read_run_header,.-mac_read_run_header

/* ---------------------------------------------------------------------------
 * mac_sort_desc(a=x0, b=x1, n=x2) -- bottom-up iterative merge sort of fixed
 * 64-byte records, comparing first 36 bytes; b is equal-size scratch. Result
 * always ends up in a.
 * ------------------------------------------------------------------------- */
	.type mac_sort_desc,%function
mac_sort_desc:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp, sp, #0x40
	mov  x19, x0                    /* a */
	mov  x20, x1                    /* b */
	mov  x21, x2                    /* n */
	cmp  x21, #1
	b.ls .sd_done
	mov  x22, #1                    /* width */
	mov  x23, #1                    /* cur_src_is_a */
.sd_pass:
	cmp  x22, x21
	b.hs .sd_maybe_copy
	cmp  x23, #1
	b.ne .sd_src_b
	mov  x24, x19                   /* src = a */
	mov  x25, x20                   /* dst = b */
	b    .sd_bases_set
.sd_src_b:
	mov  x24, x20                   /* src = b */
	mov  x25, x19                   /* dst = a */
.sd_bases_set:
	mov  x9, #0                     /* lo */
.sd_outer:
	cmp  x9, x21
	b.hs .sd_pass_done
	/* lo in x9; compute mid, hi */
	mov  x10, x9
	add  x10, x10, x22              /* lo+width */
	cmp  x10, x21
	b.ls .sd_mid_ok
	mov  x10, x21
.sd_mid_ok:
	/* x10 = mid */
	mov  x11, x22
	lsl  x11, x11, #1
	add  x11, x11, x9               /* lo+2*width */
	cmp  x11, x21
	b.ls .sd_hi_ok
	mov  x11, x21
.sd_hi_ok:
	/* x11 = hi */
	/* setup cursors: p=src+lo*64 q=src+mid*64 out=dst+lo*64 */
	mov  x12, x9
	lsl  x12, x12, #6
	add  x26, x24, x12              /* p */
	mov  x13, x10
	lsl  x13, x13, #6
	add  x27, x24, x13              /* q */
	mov  x14, x10                   /* p_end = src + MID*64 (end of left run) */
	lsl  x14, x14, #6
	add  x15, x24, x14
	mov  x12, x9
	lsl  x12, x12, #6
	add  x28, x25, x12              /* out */
	str  x15, [sp, #0x08]           /* p_end */
	mov  x16, x11
	lsl  x16, x16, #6
	add  x16, x24, x16
	str  x16, [sp, #0x18]           /* q_end = src + hi*64 */
.sd_inner:
	ldr  x15, [sp, #0x08]           /* p_end */
	cmp  x26, x15
	b.hs .sd_drain_q
	ldr  x16, [sp, #0x18]           /* q_end */
	cmp  x27, x16
	b.hs .sd_drain_p
	mov  x0, x26
	mov  x1, x27
	bl   mac_cmp_key
	cmp  w0, #2
	b.eq .sd_take_q
	mov  x0, x28
	mov  x1, x26
	bl   mac_copy_rec
	add  x26, x26, #64
	add  x28, x28, #64
	b    .sd_inner
.sd_take_q:
	mov  x0, x28
	mov  x1, x27
	bl   mac_copy_rec
	add  x27, x27, #64
	add  x28, x28, #64
	b    .sd_inner
.sd_drain_p:
	ldr  x15, [sp, #0x08]
	cmp  x26, x15
	b.hs .sd_drain_done
	mov  x0, x28
	mov  x1, x26
	bl   mac_copy_rec
	add  x26, x26, #64
	add  x28, x28, #64
	b    .sd_drain_p
.sd_drain_q:
	ldr  x16, [sp, #0x18]
	cmp  x27, x16
	b.hs .sd_drain_done
	mov  x0, x28
	mov  x1, x27
	bl   mac_copy_rec
	add  x27, x27, #64
	add  x28, x28, #64
	b    .sd_drain_q
.sd_drain_done:
	/* lo = hi */
	mov  x9, x11
	b    .sd_outer
.sd_pass_done:
	lsl  x22, x22, #1
	eor  x23, x23, #1
	b    .sd_pass
.sd_maybe_copy:
	cmp  x23, #1
	b.eq .sd_done
	/* result in b -> copy all n to a */
	mov  x9, #0
.sd_copyall:
	cmp  x9, x21
	b.hs .sd_done
	mov  x10, x9
	lsl  x10, x10, #6
	add  x0, x19, x10
	add  x1, x20, x10
	bl   mac_copy_rec
	add  x9, x9, #1
	b    .sd_copyall
.sd_done:
	add  sp, sp, #0x40
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size mac_sort_desc,.-mac_sort_desc

/* ============================================================================
 * utxo_lsm_init(lst=x0) -> 1 ok / -1 err
 * ========================================================================== */
	.global utxo_lsm_init
	.type utxo_lsm_init,%function
utxo_lsm_init:
	stp  x29,x30,[sp,#-16]!
	mov  x29, sp
	stp  x19,x20,[sp,#-16]!
	sub  sp, sp, #0x20
	mov  x19, x0
	bl   lsm_mm_invalidate_all
	mov  x0, x19
	bl   utxo_store_init
	cmp  x0, #1
	b.ne .li_fail
	str  xzr, [x19, #40]
	str  xzr, [x19, #80]
	str  xzr, [x19, #88]
	str  xzr, [x19, #96]
	str  xzr, [x19, #120]
	str  xzr, [x19, #144]
	mov  x0, x19
	bl   mac_tomb_hash_reset
	cmp  x0, #1
	b.ne .li_fail
	mov  x0, #1
	b    .li_done
.li_fail:
	mov  x0, #-1
.li_done:
	add  sp, sp, #0x20
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_lsm_init,.-utxo_lsm_init

/* ============================================================================
 * utxo_lsm_put(lst=x0,u=x1,txid=x2,index=x3,value=x4,height=x5,is_coinbase=x6,
 *              script=x7,slen=[sp]) -> 1/0/2/-1
 * ========================================================================== */
	.global utxo_lsm_put
	.type utxo_lsm_put,%function
utxo_lsm_put:
	stp  x29,x30,[sp,#-16]!
	mov  x29, sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	sub  sp, sp, #0x20
	mov  x19, x0                    /* lst */
	mov  x20, x1                    /* u */
	mov  x21, x2                    /* txid */
	mov  w22, w3                    /* index */
	mov  x23, x4                    /* value */
	/* slen (u32) = [x29+16] */
	ldr  w9, [x29, #16]
	/* call utxo_store_put(lst,u,txid,index,value,height,cb,script,slen) */
	mov  x0, x19
	mov  x1, x20
	mov  x2, x21
	uxtw x3, w22
	mov  x4, x23
	uxtw x5, w5
	mov  x6, x6
	mov  x7, x7
	sub  sp, sp, #0x10
	str  w9, [sp]
	bl   utxo_store_put
	add  sp, sp, #0x10
	str  w0, [sp, #0x00]            /* save result r */
	cmp  w0, #1
	b.ne .lp_no_live_inc
	ldr  x9, [x19, #88]
	add  x9, x9, #1
	str  x9, [x19, #88]
.lp_no_live_inc:
	ldr  x9, [x19, #40]
	add  x9, x9, #1
	str  x9, [x19, #40]
	mov  w24, #0                    /* err flag */
	ldr  x9, [x19, #40]
	ldr  x10, [x19, #48]
	cmp  x9, x10
	b.hs .lp_do_flush
	ldr  x10, [x20]
	ldr  x11, [x19, #56]
	cmp  x10, x11
	b.lo .lp_skip_flush
.lp_do_flush:
	mov  x0, x19
	mov  x1, x20
	bl   mac_flush
	mov  x9, #-1
	cmp  x0, x9
	b.ne .lp_skip_flush
	mov  w24, #1
.lp_skip_flush:
	cmp  w24, #1
	b.eq .lp_err
	ldr  w0, [sp, #0x00]
	b    .lp_done
.lp_err:
	mov  x0, #-1
.lp_done:
	add  sp, sp, #0x20
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_lsm_put,.-utxo_lsm_put

/* ============================================================================
 * utxo_lsm_del(lst=x0,u=x1,txid=x2,index=x3) -> 1 recorded / -1 err
 * ========================================================================== */
	.global utxo_lsm_del
	.type utxo_lsm_del,%function
utxo_lsm_del:
	stp  x29,x30,[sp,#-16]!
	mov  x29, sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	sub  sp, sp, #0x30
	mov  x19, x0                    /* lst */
	mov  x20, x1                    /* u */
	mov  x21, x2                    /* txid */
	mov  w22, w3                    /* index */
	/* utxo_store_del(lst,u,txid,index) */
	mov  x0, x19
	mov  x1, x20
	mov  x2, x21
	uxtw x3, w22
	bl   utxo_store_del
	mov  x9, #-1
	cmp  x0, x9
	b.eq .ld_err
	/* tomb list append: check tomb_n < tomb_cap */
	ldr  x9, [x19, #80]
	ldr  x10, [x19, #72]
	cmp  x9, x10
	b.hs .ld_err
	/* dst = tomb_buf + tomb_n*36 ; memcpy 32 bytes of txid ; store index */
	ldr  x11, [x19, #64]
	mov  x12, #36
	mul  x12, x9, x12
	add  x11, x11, x12              /* dst */
	mov  x0, x11
	mov  x1, x21
	mov  x2, #32
	bl   mac_memcpy
	str  w22, [x11, #32]
	/* mac_tomb_hash_probe(lst, dst) -> slot ; *slot = old_index */
	mov  x0, x19
	mov  x1, x11
	bl   mac_tomb_hash_probe
	ldr  x9, [x19, #80]
	str  x9, [x0]
	ldr  x9, [x19, #80]
	add  x9, x9, #1
	str  x9, [x19, #80]
	ldr  x9, [x19, #40]
	add  x9, x9, #1
	str  x9, [x19, #40]
	ldr  x9, [x19, #88]
	sub  x9, x9, #1
	str  x9, [x19, #88]
	mov  w23, #0                    /* err flag */
	ldr  x9, [x19, #40]
	ldr  x10, [x19, #48]
	cmp  x9, x10
	b.hs .ld_do_flush
	ldr  x10, [x20]
	ldr  x11, [x19, #56]
	cmp  x10, x11
	b.lo .ld_skip_flush
.ld_do_flush:
	mov  x0, x19
	mov  x1, x20
	bl   mac_flush
	mov  x9, #-1
	cmp  x0, x9
	b.ne .ld_skip_flush
	mov  w23, #1
.ld_skip_flush:
	cmp  w23, #1
	b.eq .ld_err
	mov  x0, #1
	b    .ld_done
.ld_err:
	mov  x0, #-1
.ld_done:
	add  sp, sp, #0x30
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_lsm_del,.-utxo_lsm_del

/* utxo_lsm_count(lst=x0) -> total_live */
	.global utxo_lsm_count
	.type utxo_lsm_count,%function
utxo_lsm_count:
	ldr  x0, [x0, #88]
	ret
	.size utxo_lsm_count,.-utxo_lsm_count

/* utxo_lsm_close(lst=x0) -> utxo_store_close(lst=x0) (same struct layout) */
	.global utxo_lsm_close
	.type utxo_lsm_close,%function
utxo_lsm_close:
	b    utxo_store_close
	.size utxo_lsm_close,.-utxo_lsm_close

/* ============================================================================
 * mac_run_lookup(lst=x0, run_no=w1, txid=x2, index=w3, &value=x4, &height=x5,
 *                &is_coinbase=x6, &script=x7, &slen=[sp], gen=[sp+8]) ->
 *   1 found-push / 0 absent / 2 tombstone / -1 err
 * ========================================================================== */
	.type mac_run_lookup,%function
mac_run_lookup:
	stp  x29,x30,[sp,#-16]!
	mov  x29, sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp, sp, #0x180
	mov  x19, x0                    /* lst */
	uxtw x20, w1                    /* run_no */
	mov  x21, x2                    /* txid */
	uxtw x22, w3                    /* index */
	mov  x23, x4                    /* &value */
	mov  x24, x5                    /* &height */
	mov  x25, x6                    /* &is_coinbase */
	mov  x26, x7                    /* &script */
	ldr  x27, [x29, #16]            /* &slen */
	/* persist inputs to locals */
	str  x21, [sp, #0x00]
	str  x22, [sp, #0x08]
	str  x23, [sp, #0x10]
	str  x24, [sp, #0x18]
	str  x25, [sp, #0x20]
	str  x26, [sp, #0x28]
	str  x27, [sp, #0x30]
	ldr  x9, [x29, #24]             /* gen */
	str  x9, [sp, #0x38]
	/* ---- mmap-cached fast path ---- */
	mov  x0, x19
	mov  x1, x20
	ldr  x2, [sp, #0x38]            /* gen */
	mov  x3, x21
	uxtw x4, w22
	mov  x5, x23
	mov  x6, x24
	mov  x7, x25
	sub  sp, sp, #0x10
	str  x26, [sp]                  /* &script */
	str  x27, [sp, #8]              /* &slen */
	bl   lsm_run_lookup_mm
	add  sp, sp, #0x10
	cmp  w0, #-2
	b.ne .ml_ret
	/* ---- fallback disk path ---- */
	add  x0, sp, #0x70              /* runname buf */
	mov  w1, w20
	bl   fmt_runname
	mov  x0, #AT_FDCWD
	add  x1, sp, #0x70
	mov  x2, #O_RDONLY
	mov  x3, #0
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .ml_err
	mov  x28, x0                    /* fd */
	mov  x0, x28
	add  x1, sp, #0x90              /* header out */
	bl   mac_read_run_header
	cbnz x0, .ml_err_close
	ldr  x9, [sp, #0x90+24]
	str  x9, [sp, #0x40]            /* bits_mask */
	ldr  x9, [sp, #0x90+56]
	str  x9, [sp, #0x48]            /* rec_v2 */
	/* read bloom into TLS scratch */
	mov  x0, x28
	TLS_BASE x1
	ldr  x2, [sp, #0x90+16]         /* bloom_bytes */
	bl   mac_read_exact2
	cbnz x0, .ml_err_close
	/* build keybuf */
	add  x0, sp, #0xd0
	mov  x1, x21
	mov  x2, #32
	bl   mac_memcpy
	ldr  w9, [sp, #0x08]
	str  w9, [sp, #0xd0+32]
	/* bloom test: 3 seeds */
	add  x0, sp, #0xd0
	mov  w1, #0x9dc5
	movk w1, #0x811c, lsl #16
	TLS_BASE x2
	ldr  w3, [sp, #0x40]
	bl   mac_bloom_testbit
	cbz  w0, .ml_absent_close
	add  x0, sp, #0xd0
	mov  w1, #0xc3d4
	movk w1, #0xa1b2, lsl #16
	TLS_BASE x2
	ldr  w3, [sp, #0x40]
	bl   mac_bloom_testbit
	cbz  w0, .ml_absent_close
	add  x0, sp, #0xd0
	mov  w1, #0xe995
	movk w1, #0x5bd1, lsl #16
	TLS_BASE x2
	ldr  w3, [sp, #0x40]
	bl   mac_bloom_testbit
	cbz  w0, .ml_absent_close
	/* ---- sparse index ---- */
	ldr  x9, [sp, #0x90+32]         /* header_size */
	ldr  x10, [sp, #0x90+16]        /* bloom_bytes */
	add  x9, x9, x10
	str  x9, [sp, #0x50]            /* records_start */
	ldr  x9, [sp, #0x90+48]         /* sparse_n */
	cbnz x9, .ml_sp_search
	ldr  x15, [sp, #0x50]
	str  x15, [sp, #0x110]          /* best_offset = records_start */
	b    .ml_sp_seek
.ml_sp_search:
	str  xzr, [sp, #0x100]          /* lo = 0 */
	sub  x9, x9, #1
	str  x9, [sp, #0x108]           /* hi = sparse_n-1 */
	ldr  x15, [sp, #0x50]
	str  x15, [sp, #0x110]          /* best_offset default */
.ml_sp_loop:
	ldr  x9, [sp, #0x100]           /* lo */
	ldr  x10, [sp, #0x108]          /* hi */
	cmp  x9, x10
	b.gt .ml_sp_seek
	add  x9, x9, x10
	lsr  x9, x9, #1                 /* mid */
	str  x9, [sp, #0x118]
	/* entry file offset = sparse_off + mid*44 */
	ldr  x10, [sp, #0x90+40]        /* sparse_off */
	mov  x11, #44
	mul  x11, x9, x11
	add  x10, x10, x11
	/* lseek(fd, off, SEEK_SET) */
	mov  x0, x28
	mov  x1, x10
	mov  x2, #0
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .ml_err_close
	/* read SPARSE_ENT_SIZE bytes into +0x130 */
	mov  x0, x28
	add  x1, sp, #0x130
	mov  x2, #SPARSE_ENT_SIZE
	bl   mac_read_exact2
	cbnz x0, .ml_err_close
	add  x0, sp, #0x130             /* sampled key */
	add  x1, sp, #0xd0              /* target key */
	bl   mac_cmp_key
	cmp  w0, #2
	b.eq .ml_sp_hi
	add  x15, sp, #0x130+36          /* (packed file_offset) */
	ldr  x15, [x15]                 /* this entry's file_offset */
	str  x15, [sp, #0x110]          /* best_offset */
	ldr  x9, [sp, #0x118]
	add  x9, x9, #1
	str  x9, [sp, #0x100]           /* lo = mid+1 */
	b    .ml_sp_loop
.ml_sp_hi:
	ldr  x9, [sp, #0x118]
	cbz  x9, .ml_sp_seek            /* mid==0 */
	sub  x9, x9, #1
	str  x9, [sp, #0x108]           /* hi = mid-1 */
	b    .ml_sp_loop
.ml_sp_seek:
	ldr  x1, [sp, #0x110]           /* best_offset */
	mov  x0, x28
	mov  x2, #0
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .ml_err_close
	/* ---- scan records ---- */
.ml_scan_loop:
	mov  x0, x28
	add  x1, sp, #0xf8              /* recbuf */
	mov  x2, #37
	bl   mac_read_exact2
	cbnz x0, .ml_absent_close
	add  x0, sp, #0xf8
	add  x1, sp, #0xd0
	bl   mac_cmp_key
	cmp  w0, #1
	b.eq .ml_key_match
	cmp  w0, #2
	b.eq .ml_absent_close
	ldrb w9, [sp, #0xf8+36]         /* type */
	cmp  w9, #1
	b.ne .ml_scan_loop              /* tombstone: header only */
	/* non-matching PUSH: skip value portion+slen */
	ldr  x9, [sp, #0x48]            /* rec_v2 */
	cbnz x9, .ml_skip_new
	mov  x0, x28
	add  x1, sp, #0xf8
	mov  x2, #10
	bl   mac_read_exact2
	cbnz x0, .ml_absent_close
	ldrh w9, [sp, #0xf8+8]
	b    .ml_skip_have_slen
.ml_skip_new:
	mov  x0, x28
	add  x1, sp, #0xf8
	mov  x2, #15
	bl   mac_read_exact2
	cbnz x0, .ml_absent_close
	ldrh w9, [sp, #0xf8+8]
.ml_skip_have_slen:
	cbz  w9, .ml_scan_loop
	/* lseek(fd, slen, SEEK_CUR) */
	uxtw x10, w9
	mov  x0, x28
	mov  x1, x10
	mov  x2, #1
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .ml_err_close
	b    .ml_scan_loop
.ml_key_match:
	ldrb w9, [sp, #0xf8+36]
	cmp  w9, #2
	b.eq .ml_tombstone_close
	ldr  x9, [sp, #0x48]            /* rec_v2 */
	cbnz x9, .ml_read_new
	/* old shape: value(8)+slen(2)=10; height/cb = 0 */
	mov  x0, x28
	add  x1, sp, #0xf8
	mov  x2, #10
	bl   mac_read_exact2
	cbnz x0, .ml_err_close
	ldrh w9, [sp, #0xf8+8]
	ldr  x15, [sp, #0xf8]           /* value */
	ldr  x10, [sp, #0x10]           /* &value */
	str  x15, [x10]
	str  xzr, [sp, #0x140]          /* height scratch = 0 */
	ldr  x10, [sp, #0x18]
	str  xzr, [x10]                 /* *height = 0 */
	ldr  x10, [sp, #0x20]
	str  xzr, [x10]                 /* *is_coinbase = 0 */
	b    .ml_have_value_fields
.ml_read_new:
	/* new shape: value(8)+slen(2)+height(4)+is_coinbase(1)=15 */
	mov  x0, x28
	add  x1, sp, #0xf8
	mov  x2, #15
	bl   mac_read_exact2
	cbnz x0, .ml_err_close
	ldrh w9, [sp, #0xf8+8]          /* slen */
	ldr  x15, [sp, #0xf8]           /* value */
	ldr  x10, [sp, #0x10]
	str  x15, [x10]
	add  x11, sp, #0xf8+10           /* (packed height) */
	ldr  w11, [x11]
	ldr  x10, [sp, #0x18]
	uxtw x11, w11
	str  x11, [x10]
	ldrb w11, [sp, #0xf8+14]        /* is_coinbase */
	ldr  x10, [sp, #0x20]
	str  x11, [x10]
.ml_have_value_fields:
	uxtw x13, w9                     /* slen (caller-saved ok, no call after) */
	ldr  x10, [sp, #0x30]            /* &slen (u32* internally) */
	str  w9, [x10]                   /* *slen (4 bytes) */
	cbz  x13, .ml_push_noscript
	mov  x0, x28
	TLS_BASE x1
	movz x2, #1, lsl #16            /* +SCRIPT_MAX_BYTES */
	add  x1, x1, x2
	mov  x2, x13
	bl   mac_read_exact2
	cbnz x0, .ml_err_close
.ml_push_noscript:
	/* close fd */
	mov  x0, x28
	mov  x8, #SYS_close
	svc  #0
	/* script ptr */
	ldr  x10, [sp, #0x28]            /* &script */
	TLS_BASE x9
	movz x11, #1, lsl #16
	add  x9, x9, x11                /* TLS + SCRIPT_MAX_BYTES */
	str  x9, [x10]
	mov  x0, #1
	b    .ml_ret
.ml_tombstone_close:
	mov  x0, x28
	mov  x8, #SYS_close
	svc  #0
	mov  x0, #2
	b    .ml_ret
.ml_absent_close:
	mov  x0, x28
	mov  x8, #SYS_close
	svc  #0
	mov  x0, #0
	b    .ml_ret
.ml_err_close:
	mov  x0, x28
	mov  x8, #SYS_close
	svc  #0
.ml_err:
	mov  x0, #-1
.ml_ret:
	add  sp, sp, #0x180
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size mac_run_lookup,.-mac_run_lookup

/* ============================================================================

/* ============================================================================
 * utxo_lsm_get(lst=x0,u=x1,txid=x2,index=x3,&value=x4,&height=x5,
 *              &is_coinbase=x6,&script=x7,&slen=[sp]) -> 1/0/-1
 * ========================================================================== */
	.global utxo_lsm_get
	.type utxo_lsm_get,%function
utxo_lsm_get:
	stp  x29,x30,[sp,#-16]!
	mov  x29, sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp, sp, #0x60
	mov  x28, sp
	mov  x19, x0                    /* lst */
	mov  x20, x1                    /* u */
	mov  x21, x2                    /* txid */
	uxtw x22, w3                    /* index */
	mov  x23, x4                    /* &value */
	mov  x24, x5                    /* &height */
	mov  x25, x6                    /* &is_coinbase */
	mov  x26, x7                    /* &script */
	ldr  x27, [x29, #16]            /* &slen */
	str  xzr, [x28, #0x30]          /* tmp_slen */
	/* utxo_get(u,txid,index,&value,&height,&cb,&script,&slen8) */
	mov  x0, x20
	mov  x1, x21
	uxtw x2, w22
	mov  x3, x23
	mov  x4, x24
	mov  x5, x25
	mov  x6, x26
	add  x7, x28, #0x30
	bl   utxo_get
	cmp  w0, #1
	b.eq .lg_found
	/* tombstone check this generation */
	add  x0, x28, #0x00             /* keybuf */
	mov  x1, x21
	mov  x2, #32
	bl   mac_memcpy
	str  w22, [x28, #0x20]          /* index at keybuf+32 */
	mov  x0, x19
	add  x1, x28, #0x00
	bl   mac_tomb_hash_probe
	ldr  x9, [x0]
	mov  x10, #-1
	cmp  x9, x10
	b.ne .lg_not_found
	ldr  x9, [x19, #120]            /* manifest_n */
	str  x9, [x28, #0x38]
.lg_run_loop:
	ldr  x9, [x28, #0x38]
	cbz  x9, .lg_not_found
	sub  x9, x9, #1
	str  x9, [x28, #0x38]
	mov  x10, #16
	mul  x10, x9, x10
	ldr  x11, [x19, #104]           /* manifest_buf */
	add  x11, x11, x10
	ldr  x10, [x11]                 /* gen */
	str  x10, [x28, #0x50]
	ldr  x1, [x11, #8]              /* run_no */
	mov  x0, x19
	mov  x2, x21
	uxtw x3, w22
	mov  x4, x23
	mov  x5, x24
	mov  x6, x25
	mov  x7, x26
	sub  sp, sp, #0x10
	add  x9, x28, #0x30
	str  x9, [sp]                   /* &slen scratch */
	ldr  x9, [x28, #0x50]
	str  x9, [sp, #8]               /* gen */
	bl   mac_run_lookup
	add  sp, sp, #0x10
	cmp  w0, #1
	b.eq .lg_found
	cmp  w0, #2
	b.eq .lg_not_found
	cmp  w0, #-1
	b.eq .lg_err
	b    .lg_run_loop
.lg_found:
	ldr  w0, [x28, #0x30]           /* tmp_slen zero-extend */
	str  x0, [x27]                  /* *caller_slen full width */
	mov  x0, #1
	b    .lg_done
.lg_not_found:
	mov  x0, #0
	b    .lg_done
.lg_err:
	mov  x0, #-1
.lg_done:
	add  sp, sp, #0x60
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_lsm_get,.-utxo_lsm_get

/* utxo_lsm_flush(lst=x0,u=x1) -> mac_flush (tail) */
	.global utxo_lsm_flush
	.type utxo_lsm_flush,%function
utxo_lsm_flush:
	b    mac_flush
	.size utxo_lsm_flush,.-utxo_lsm_flush

/* ============================================================================
 * mac_flush(lst=x0,u=x1) -> 1 ok / -1 err
 * ========================================================================== */
	.type mac_flush,%function
mac_flush:
	stp  x29,x30,[sp,#-16]!
	mov  x29, sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp, sp, #0x110
	mov  x28, sp
	mov  x19, x0                    /* lst */
	mov  x20, x1                    /* u */
	/* desc_cap/off_desc_b/off_bloom */
	mov  x0, x19
	bl   mac_calc_desc_cap
	str  x0, [x28, #0x00]           /* desc_cap */
	lsl  x9, x0, #6
	str  x9, [x28, #0x10]           /* off_desc_b */
	lsl  x9, x9, #1
	str  x9, [x28, #0x18]           /* off_bloom */
	str  xzr, [x28, #0x08]          /* n_desc */
	/* ---- walk memtable live slots -> PUSH descriptors ---- */
	ldr  x9, [x20, #8]
	str  x9, [x28, #0x28]           /* mask */
	mov  x21, #0                    /* slot cursor i */
.fl_slot_loop:
	ldr  x9, [x28, #0x28]
	cmp  x21, x9
	b.hi .fl_slots_done
	mov  x10, #48
	mul  x10, x21, x10
	add  x22, x20, x10              /* slot_ptr = u + i*48 */
	add  x22, x22, #40              /* slots base is u+40 */
	ldr  w11, [x22, #40]
	mov  w12, #-1
	cmp  w11, w12
	b.eq .fl_slot_next
	/* n_desc cap check */
	ldr  x11, [x28, #0x08]
	ldr  x12, [x28, #0x00]
	cmp  x11, x12
	b.hs .fl_err
	/* dest descriptor = scratch_buf + n_desc*64 */
	ldr  x12, [x19, #128]
	lsl  x11, x11, #6
	add  x23, x12, x11              /* dest descriptor */
	mov  x0, x23
	add  x1, x22, #8
	mov  x2, #32
	bl   mac_memcpy
	ldr  w11, [x22, #40]
	str  w11, [x23, #32]            /* index */
	mov  w11, #1
	strb w11, [x23, #36]            /* type = PUSH */
	/* record = u->blob + slot.blob_off */
	ldr  x11, [x22]                  /* blob_off */
	ldr  x12, [x20, #16]             /* blob base */
	add  x24, x11, x12               /* record */
	ldr  x11, [x24]
	str  x11, [x23, #40]             /* value */
	ldr  x11, [x24, #8]
	str  w11, [x23, #50]             /* height (low32) */
	lsr  x11, x11, #32
	and  w11, w11, #0xFF
	strb w11, [x23, #54]             /* is_coinbase */
	ldrh w11, [x24, #16]
	strh w11, [x23, #48]             /* slen */
	add  x11, x24, #24
	str  x11, [x23, #56]             /* script_ptr */
	ldr  x11, [x28, #0x08]
	add  x11, x11, #1
	str  x11, [x28, #0x08]           /* n_desc++ */
.fl_slot_next:
	add  x21, x21, #1
	b    .fl_slot_loop
.fl_slots_done:
	/* ---- walk tombstones -> DEL descriptors where not currently live ---- */
	mov  x21, #0                    /* tomb cursor */
.fl_tomb_loop:
	ldr  x9, [x19, #80]             /* tomb_n */
	cmp  x21, x9
	b.hs .fl_tomb_done
	ldr  x9, [x19, #64]             /* tomb_buf */
	mov  x10, #36
	mul  x10, x21, x10
	add  x22, x9, x10                /* tomb entry ptr */
	/* utxo_get(u, tombkey, index, ...discard) */
	mov  x0, x20
	mov  x1, x22
	ldr  w2, [x22, #32]
	add  x3, x28, #0x80              /* &value discard */
	add  x4, x28, #0x88              /* &height */
	add  x5, x28, #0x90              /* &cb */
	add  x6, x28, #0x98              /* &script */
	add  x7, x28, #0xa0              /* &slen */
	bl   utxo_get
	cmp  w0, #1
	b.eq .fl_tomb_skip
	/* reload tomb ptr (utxo_get may clobber x22) */
	ldr  x9, [x19, #64]
	mov  x10, #36
	mul  x10, x21, x10
	add  x22, x9, x10
	/* add DEL descriptor */
	ldr  x9, [x28, #0x08]
	ldr  x10, [x28, #0x00]
	cmp  x9, x10
	b.hs .fl_err
	ldr  x10, [x19, #128]
	lsl  x9, x9, #6
	add  x23, x10, x9                /* dest */
	mov  x0, x23
	mov  x1, x22
	mov  x2, #36
	bl   mac_memcpy
	mov  w9, #2
	strb w9, [x23, #36]              /* type = DEL */
	ldr  x9, [x28, #0x08]
	add  x9, x9, #1
	str  x9, [x28, #0x08]
.fl_tomb_skip:
	add  x21, x21, #1
	b    .fl_tomb_loop
.fl_tomb_done:
	ldr  x9, [x28, #0x08]
	cbz  x9, .fl_finish_reset
	/* manifest capacity check */
	ldr  x9, [x19, #120]
	ldr  x10, [x19, #112]
	cmp  x9, x10
	b.hs .fl_err
	/* ---- sort descriptors ---- */
	ldr  x0, [x19, #128]
	mov  x1, x0
	ldr  x2, [x28, #0x10]
	add  x1, x1, x2                  /* b = scratch + off_desc_b */
	ldr  x2, [x28, #0x08]
	bl   mac_sort_desc
	/* ---- bloom sizing ---- */
	ldr  x9, [x28, #0x08]
	mov  x10, #10
	mul  x9, x9, x10
	cmp  x9, #64
	b.hs .fl_bb1
	mov  x9, #64
.fl_bb1:
	mov  x10, #1
.fl_bb_loop:
	cmp  x10, x9
	b.hs .fl_bb2
	lsl  x10, x10, #1
	b    .fl_bb_loop
.fl_bb2:
	movz x11, #0x4000, lsl #16       /* BLOOM_MAX_BYTES*8 = 0x2000000 */
	cmp  x10, x11
	b.ls .fl_bb3
	mov  x10, x11
.fl_bb3:
	str  x10, [x28, #0x38]           /* bloom_bits */
	lsr  x9, x10, #3
	str  x9, [x28, #0x40]            /* bloom_bytes */
	sub  x10, x10, #1
	str  x10, [x28, #0x48]           /* bits_mask */
	/* ---- zero bloom region ---- */
	ldr  x9, [x19, #128]
	ldr  x10, [x28, #0x18]
	add  x12, x9, x10                /* bloom base */
	ldr  x11, [x28, #0x40]           /* bloom_bytes */
	mov  x9, #0
.fl_bz:
	cbz  x11, .fl_bz_done
	strb wzr, [x12, x9]
	add  x9, x9, #1
	sub  x11, x11, #1
	b    .fl_bz
.fl_bz_done:
	/* ---- set 3 bloom bits per descriptor ---- */
	mov  x21, #0                    /* i */
.fl_bloom_loop:
	ldr  x9, [x28, #0x08]
	cmp  x21, x9
	b.hs .fl_bloom_done
	ldr  x9, [x19, #128]
	lsl  x10, x21, #6
	add  x22, x9, x10                /* key ptr (descriptor) */
	ldr  x9, [x19, #128]
	ldr  x10, [x28, #0x18]
	add  x23, x9, x10                /* bloom base */
	ldr  x24, [x28, #0x48]           /* bits_mask */
	mov  x0, x22
	mov  w1, #0x9dc5
	movk w1, #0x811c, lsl #16
	mov  x2, x23
	mov  w3, w24
	bl   mac_bloom_setbit
	mov  x0, x22
	mov  w1, #0xc3d4
	movk w1, #0xa1b2, lsl #16
	mov  x2, x23
	mov  w3, w24
	bl   mac_bloom_setbit
	mov  x0, x22
	mov  w1, #0xe995
	movk w1, #0x5bd1, lsl #16
	mov  x2, x23
	mov  w3, w24
	bl   mac_bloom_setbit
	add  x21, x21, #1
	b    .fl_bloom_loop
.fl_bloom_done:
	/* ---- write run file ---- */
	add  x0, x28, #0x70              /* runname */
	ldr  w1, [x19, #144]             /* next_run_no */
	bl   fmt_runname
	mov  x0, #AT_FDCWD
	add  x1, x28, #0x70
	mov  x2, #(O_WRONLY|O_CREAT|O_TRUNC)
	mov  x3, #0644
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .fl_err
	mov  x21, x0                     /* fd */
	/* header (44B) at x28+0xc0 (packed: unaligned 64-bit fields) */
	mov  w9, #0x5255
	movk w9, #0x3355, lsl #16        /* MAGIC_RUN3 */
	str  w9, [x28, #0xc0]
	add  x10, x28, #0xc4
	ldr  x9, [x19, #96]              /* next_gen */
	str  x9, [x10]
	add  x10, x28, #0xcc
	ldr  x9, [x28, #0x08]            /* n_desc */
	str  x9, [x10]
	add  x10, x28, #0xd4
	ldr  x9, [x28, #0x38]            /* bloom_bits */
	str  x9, [x10]
	add  x10, x28, #0xdc
	str  xzr, [x10]                  /* sparse_off placeholder */
	add  x10, x28, #0xe4
	str  xzr, [x10]                  /* sparse_n placeholder */
	mov  x0, x21
	add  x1, x28, #0xc0
	mov  x2, #44
	bl   mac_write_exact
	cbnz x0, .fl_err_close
	/* write bloom */
	mov  x0, x21
	ldr  x9, [x19, #128]
	ldr  x10, [x28, #0x18]
	add  x1, x9, x10
	ldr  x2, [x28, #0x40]
	bl   mac_write_exact
	cbnz x0, .fl_err_close
	str  xzr, [x28, #0x60]           /* sparse_n */
	/* ---- write records ---- */
	mov  x22, #0                    /* i */
.fl_wr_loop:
	ldr  x9, [x28, #0x08]
	cmp  x22, x9
	b.hs .fl_wr_done
	ldr  x9, [x19, #128]
	lsl  x10, x22, #6
	add  x23, x9, x10                /* record descriptor ptr */
	/* sparse sampling: every SPARSE_STRIDEth record */
	tst  x22, #(SPARSE_STRIDE-1)
	b.ne .fl_wr_nosample
	/* lseek(fd, 0, SEEK_CUR) to get offset */
	mov  x0, x21
	mov  x1, #0
	mov  x2, #1
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .fl_err_close
	mov  x24, x0                    /* this record's file offset */
	/* sparse dest = scratch + off_desc_b + sparse_n*44 */
	ldr  x9, [x28, #0x60]            /* sparse_n */
	mov  x10, #44
	mul  x10, x9, x10
	ldr  x11, [x19, #128]
	ldr  x12, [x28, #0x10]
	add  x11, x11, x12
	add  x0, x11, x10                /* dest */
	mov  x1, x23
	mov  x2, #36
	bl   mac_memcpy
	str  x24, [x0, #36]             /* file_offset */
	ldr  x9, [x28, #0x60]
	add  x9, x9, #1
	str  x9, [x28, #0x60]            /* sparse_n++ */
	mov  x0, x21
	mov  x1, x23
	mov  x2, #37
	bl   mac_write_exact
	cbnz x0, .fl_err_close
	ldrb w9, [x23, #36]
	cmp  w9, #1
	b.ne .fl_wr_next
	/* PUSH: write value(8)+slen(2)+height(4)+cb(1) = 15 bytes at desc+40 */
	mov  x0, x21
	add  x1, x23, #40
	mov  x2, #15
	bl   mac_write_exact
	cbnz x0, .fl_err_close
	ldrh w9, [x23, #48]              /* slen */
	cbz  w9, .fl_wr_next
	mov  x0, x21
	ldr  x1, [x23, #56]              /* script_ptr */
	uxtw x2, w9
	bl   mac_write_exact
	cbnz x0, .fl_err_close
	b    .fl_wr_next
.fl_wr_nosample:
	/* not a sample: restore n_desc/bloom_bytes for reloaded consistency */
	mov  x0, x21
	mov  x1, x23
	mov  x2, #37
	bl   mac_write_exact
	cbnz x0, .fl_err_close
	ldrb w9, [x23, #36]
	cmp  w9, #1
	b.ne .fl_wr_next
	mov  x0, x21
	add  x1, x23, #40
	mov  x2, #15
	bl   mac_write_exact
	cbnz x0, .fl_err_close
	ldrh w9, [x23, #48]
	cbz  w9, .fl_wr_next
	mov  x0, x21
	ldr  x1, [x23, #56]
	uxtw x2, w9
	bl   mac_write_exact
	cbnz x0, .fl_err_close
.fl_wr_next:
	add  x22, x22, #1
	b    .fl_wr_loop
.fl_wr_done:
	/* ---- capture sparse_off (SEEK_CUR) then write sparse index, patch header ---- */
	mov  x0, x21
	mov  x1, #0
	mov  x2, #1
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .fl_err_close
	mov  x22, x0                    /* sparse_off */
	ldr  x23, [x28, #0x60]           /* sparse_n */
	cbz  x23, .fl_sp_written
	mov  x0, x21
	ldr  x9, [x19, #128]
	ldr  x10, [x28, #0x10]
	add  x1, x9, x10
	mov  x10, #44
	mul  x2, x23, x10
	bl   mac_write_exact
	cbnz x0, .fl_err_close
.fl_sp_written:
	/* patch sparse_off/sparse_n into header at offset 28 (2 qwords at +0xdc) */
	mov  x0, x21
	mov  x1, #28
	mov  x2, #0
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .fl_err_close
	add  x9, x28, #0xdc
	str  x22, [x9]
	add  x9, x28, #0xe4
	str  x23, [x9]
	mov  x0, x21
	add  x1, x28, #0xdc
	mov  x2, #16
	bl   mac_write_exact
	cbnz x0, .fl_err_close
	mov  x0, x21
	bl   mac_fsync2
	mov  x0, x21
	mov  x8, #SYS_close
	svc  #0
	/* ---- append to in-memory manifest, advance next_gen/next_run_no ---- */
	ldr  x9, [x19, #120]
	ldr  x10, [x19, #112]
	cmp  x9, x10
	b.hs .fl_err
	ldr  x11, [x19, #104]
	mov  x10, #16
	mul  x10, x9, x10
	add  x11, x11, x10
	ldr  x12, [x19, #96]
	str  x12, [x11]                 /* gen */
	ldr  x12, [x19, #144]
	str  x12, [x11, #8]             /* run_no */
	ldr  x12, [x19, #120]
	add  x12, x12, #1
	str  x12, [x19, #120]
	ldr  x12, [x19, #96]
	add  x12, x12, #1
	str  x12, [x19, #96]
	ldr  x12, [x19, #144]
	add  x12, x12, #1
	str  x12, [x19, #144]
	/* ---- publish manifest ---- */
	mov  x0, #AT_FDCWD
	adr  x1, manifest_tmp_name
	mov  x2, #(O_WRONLY|O_CREAT|O_TRUNC)
	mov  x3, #0644
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .fl_err
	mov  x23, x0                    /* tmp fd */
	/* header 20B: magic(4) manifest_n(8) total_live(8) */
	mov  w9, #0x4d55
	movk w9, #0x324e, lsl #16        /* MAGIC_MANIFEST2 */
	str  w9, [x28, #0xc0]
	add  x10, x28, #0xc4
	ldr  x9, [x19, #120]
	str  x9, [x10]
	add  x10, x28, #0xcc
	ldr  x9, [x19, #88]              /* total_live (runs-only now) */
	str  x9, [x10]
	mov  x0, x23
	add  x1, x28, #0xc0
	mov  x2, #20
	bl   mac_write_exact
	cbnz x0, .fl_merr_close
	mov  x0, x23
	ldr  x1, [x19, #104]
	ldr  x2, [x19, #120]
	lsl  x2, x2, #4
	bl   mac_write_exact
	cbnz x0, .fl_merr_close
	mov  x0, x23
	bl   mac_fsync2
	mov  x0, x23
	mov  x8, #SYS_close
	svc  #0
	/* renameat(AT_FDCWD, tmp, AT_FDCWD, manifest) */
	mov  x0, #AT_FDCWD
	adr  x1, manifest_tmp_name
	mov  x2, #AT_FDCWD
	adr  x3, manifest_name
	mov  x8, #SYS_renameat
	svc  #0
	tbnz x0, #63, .fl_err
	/* dir fsync on "." */
	mov  x0, #AT_FDCWD
	adr  x1, dot_name
	mov  x2, #O_RDONLY
	mov  x3, #0
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .fl_finish_reset
	mov  x23, x0
	mov  x0, x23
	bl   mac_fsync2
	mov  x0, x23
	mov  x8, #SYS_close
	svc  #0
.fl_finish_reset:
	/* ftruncate(log_fd, 0) */
	ldr  x0, [x19, #0]
	mov  x1, #0
	mov  x8, #SYS_ftruncate
	svc  #0
	/* lseek(log_fd, 0, SEEK_SET) */
	ldr  x0, [x19, #0]
	mov  x1, #0
	mov  x2, #0
	mov  x8, #SYS_lseek
	svc  #0
	str  xzr, [x19, #16]             /* log_len = 0 */
	mov  x0, x20
	bl   mac_clear_memtable
	str  xzr, [x19, #40]             /* op_count = 0 */
	str  xzr, [x19, #80]             /* tomb_n = 0 */
	mov  x0, x19
	bl   mac_tomb_hash_reset
	cmp  x0, #1
	b.ne .fl_err
	mov  x0, #1
	b    .fl_ret
.fl_merr_close:
	mov  x0, x23
	mov  x8, #SYS_close
	svc  #0
	b    .fl_err
.fl_err_close:
	mov  x0, x21
	mov  x8, #SYS_close
	svc  #0
.fl_err:
	mov  x0, #-1
.fl_ret:
	add  sp, sp, #0x110
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size mac_flush,.-mac_flush

/* ============================================================================

/* ============================================================================
 * utxo_lsm_reload_ro / utxo_lsm_reload / mac_lsm_reload_impl
 * ========================================================================== */
	.global utxo_lsm_reload_ro
	.type utxo_lsm_reload_ro,%function
utxo_lsm_reload_ro:
	mov  x2, #1
	b    mac_lsm_reload_impl
	.size utxo_lsm_reload_ro,.-utxo_lsm_reload_ro
	.global utxo_lsm_reload
	.type utxo_lsm_reload,%function
utxo_lsm_reload:
	mov  x2, #0
	b    mac_lsm_reload_impl
	.size utxo_lsm_reload,.-utxo_lsm_reload

	.type mac_lsm_reload_impl,%function
mac_lsm_reload_impl:
	stp  x29,x30,[sp,#-16]!
	mov  x29, sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp, sp, #0x80
	mov  x28, sp
	mov  x19, x0                    /* lst */
	mov  x20, x1                    /* u */
	mov  x21, x2                    /* ro flag */
	str  xzr, [x28, #0x00]          /* has_count */
	str  xzr, [x28, #0x08]          /* base */
	str  xzr, [x28, #0x10]          /* npush */
	str  xzr, [x28, #0x18]          /* ndel */
	bl   lsm_mm_invalidate_all
	mov  x0, x19
	cbnz x21, .rl_init_ro
	bl   utxo_store_init
	b    .rl_init_done
.rl_init_ro:
	bl   utxo_store_init_ro
.rl_init_done:
	cmp  x0, #1
	b.ne .rl_fail
	/* open manifest read-only */
	mov  x0, #AT_FDCWD
	adr  x1, manifest_name
	mov  x2, #O_RDONLY
	mov  x3, #0
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .rl_no_manifest
	mov  x22, x0                    /* manifest fd */
	mov  x0, x22
	add  x1, x28, #0x40
	mov  x2, #12
	bl   mac_read_exact2
	cbnz x0, .rl_manifest_bad
	ldr  w9, [x28, #0x40]
	mov  w10, #0x4d55
	movk w10, #0x324e, lsl #16      /* MAGIC_MANIFEST2 */
	cmp  w9, w10
	b.eq .rl_manifest_v2
	mov  w10, #0x4d55
	movk w10, #0x4e41, lsl #16      /* MAGIC_MANIFEST */
	cmp  w9, w10
	b.ne .rl_manifest_bad
	b    .rl_manifest_haveN
.rl_manifest_v2:
	mov  x0, x22
	add  x1, x28, #0x08
	mov  x2, #8
	bl   mac_read_exact2
	cbnz x0, .rl_manifest_bad
	mov  x9, #1
	str  x9, [x28, #0x00]           /* has_count = 1 */
.rl_manifest_haveN:
	add  x9, x28, #0x44             /* (packed manifest_n) */
	ldr  x9, [x9]
	ldr  x10, [x19, #112]           /* manifest_cap */
	cmp  x9, x10
	b.hi .rl_manifest_bad
	str  x9, [x19, #120]            /* manifest_n */
	cbz  x9, .rl_manifest_close
	mov  x0, x22
	ldr  x1, [x19, #104]            /* manifest_buf */
	lsl  x2, x9, #4
	bl   mac_read_exact2
	cbnz x0, .rl_manifest_bad
.rl_manifest_close:
	mov  x0, x22
	mov  x8, #SYS_close
	svc  #0
	str  xzr, [x19, #96]
	str  xzr, [x19, #144]
	mov  x25, #0                    /* scan cursor */
.rl_mscan:
	ldr  x9, [x19, #120]
	cmp  x25, x9
	b.hs .rl_mscan_done
	mov  x10, #16
	mul  x10, x25, x10
	ldr  x11, [x19, #104]
	add  x11, x11, x10
	ldr  x9, [x11]                  /* gen */
	ldr  x10, [x19, #96]
	cmp  x9, x10
	b.ls .rl_mscan_g
	str  x9, [x19, #96]
.rl_mscan_g:
	ldr  x9, [x11, #8]              /* run_no */
	ldr  x10, [x19, #144]
	cmp  x9, x10
	b.ls .rl_mscan_r
	str  x9, [x19, #144]
.rl_mscan_r:
	add  x25, x25, #1
	b    .rl_mscan
.rl_mscan_done:
	ldr  x9, [x19, #120]
	cbz  x9, .rl_manifest_done
	ldr  x9, [x19, #96]
	add  x9, x9, #1
	str  x9, [x19, #96]
	ldr  x9, [x19, #144]
	add  x9, x9, #1
	str  x9, [x19, #144]
	b    .rl_manifest_done
.rl_manifest_bad:
	mov  x0, x22
	mov  x8, #SYS_close
	svc  #0
	str  xzr, [x19, #120]
	str  xzr, [x19, #96]
	str  xzr, [x19, #144]
	b    .rl_manifest_done
.rl_no_manifest:
	str  xzr, [x19, #120]
	str  xzr, [x19, #96]
	str  xzr, [x19, #144]
.rl_manifest_done:
	mov  x0, x19
	mov  x1, x20
	bl   utxo_store_reload
	mov  x9, #-1
	cmp  x0, x9
	b.eq .rl_fail
	mov  x22, x0                    /* replayed count */
	str  xzr, [x19, #80]
	str  xzr, [x19, #40]
	mov  x0, x19
	bl   mac_tomb_hash_reset
	cmp  x0, #1
	b.ne .rl_fail
	mov  x0, #AT_FDCWD
	adr  x1, wal_name
	mov  x2, #O_RDONLY
	mov  x3, #0
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .rl_fail
	mov  x24, x0                    /* wal fd */
	mov  x25, #0                    /* cursor */
.rl_wal_loop:
	ldr  x9, [x19, #16]             /* log_len */
	cmp  x25, x9
	b.hs .rl_wal_close
	mov  x0, x24
	add  x1, x28, #0x60
	mov  x2, #8
	bl   mac_read_exact2
	cbnz x0, .rl_wal_close
	add  x25, x25, #8
	ldr  x9, [x19, #40]
	add  x9, x9, #1
	str  x9, [x19, #40]             /* op_count++ */
	ldrb w9, [x28, #0x64]           /* op at +0x60+4 */
	cmp  w9, #1
	b.eq .rl_wal_push
	cmp  w9, #2
	b.eq .rl_wal_del
	b    .rl_wal_close
.rl_wal_push:
	ldr  x9, [x28, #0x10]
	add  x9, x9, #1
	str  x9, [x28, #0x10]           /* npush++ */
	mov  x0, x24
	add  x1, x28, #0x60
	mov  x2, #51
	bl   mac_read_exact2
	cbnz x0, .rl_wal_close
	add  x25, x25, #51
	add  x9, x28, #0x60+49          /* (packed slen) */
	ldrh w9, [x9]
	uxtw x10, w9
	add  x25, x25, x10
	cbz  w9, .rl_wal_loop
	mov  x0, x24
	mov  x1, x10
	mov  x2, #1
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .rl_wal_close
	b    .rl_wal_loop
.rl_wal_del:
	ldr  x9, [x28, #0x18]
	add  x9, x9, #1
	str  x9, [x28, #0x18]           /* ndel++ */
	mov  x0, x24
	add  x1, x28, #0x60
	mov  x2, #36
	bl   mac_read_exact2
	cbnz x0, .rl_wal_close
	add  x25, x25, #36
	ldr  x9, [x19, #80]
	ldr  x10, [x19, #72]
	cmp  x9, x10
	b.hs .rl_wal_close
	ldr  x11, [x19, #64]
	mov  x12, #36
	mul  x12, x9, x12
	add  x11, x11, x12
	mov  x0, x11
	add  x1, x28, #0x60
	mov  x2, #36
	bl   mac_memcpy
	mov  x0, x19
	mov  x1, x11
	bl   mac_tomb_hash_probe
	ldr  x9, [x19, #80]
	str  x9, [x0]
	ldr  x9, [x19, #80]
	add  x9, x9, #1
	str  x9, [x19, #80]
	b    .rl_wal_loop
.rl_wal_close:
	mov  x0, x24
	mov  x8, #SYS_close
	svc  #0
	ldr  x9, [x28, #0x00]           /* has_count */
	cbz  x9, .rl_recount
	ldr  x9, [x28, #0x10]           /* npush */
	ldr  x10, [x28, #0x18]          /* ndel */
	orr  x9, x9, x10
	cbnz x9, .rl_recount
	ldr  x9, [x28, #0x08]           /* base */
	str  x9, [x19, #88]
	mov  x0, x22
	b    .rl_ret
.rl_recount:
	mov  x0, x19
	mov  x1, x20
	mov  x2, #0
	mov  x3, #0
	bl   mac_lsm_recount
	mov  x9, #-1
	cmp  x0, x9
	b.eq .rl_fail
	str  x0, [x19, #88]
	mov  x0, x22
	b    .rl_ret
.rl_fail:
	mov  x0, #-1
.rl_ret:
	add  sp, sp, #0x80
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size mac_lsm_reload_impl,.-mac_lsm_reload_impl

/* ============================================================================
 * mac_compact_read_rec(slot=x0) -> 1 ok / -1 err
 * ========================================================================== */
	.type mac_compact_read_rec,%function
mac_compact_read_rec:
	stp  x29,x30,[sp,#-16]!
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	mov  x19, x0                    /* slot */
	ldr  x0, [x19]                  /* fd */
	add  x1, x19, #40
	mov  x2, #37                    /* key(36)+type(1) */
	bl   mac_read_exact2
	cbnz x0, .cpr_err
	bl   g_utxo_prog_bump          /* +1 record consumed (boot progress) */
	ldrb w9, [x19, #76]             /* type */
	cmp  w9, #1
	b.ne .cpr_dec
	ldr  x9, [x19, #96]             /* rec_v2 */
	cbnz x9, .cpr_read_new
	/* old shape: value(8)+slen(2)=10 */
	ldr  x0, [x19]
	add  x1, x19, #80
	mov  x2, #10
	bl   mac_read_exact2
	cbnz x0, .cpr_err
	add  x9, x19, #90
	str  xzr, [x9]                  /* height=0 */
	strb wzr, [x19, #94]            /* is_coinbase=0 */
	b    .cpr_have_slen
.cpr_read_new:
	ldr  x0, [x19]
	add  x1, x19, #80
	mov  x2, #15
	bl   mac_read_exact2
	cbnz x0, .cpr_err
.cpr_have_slen:
	ldrh w9, [x19, #88]             /* slen */
	cbz  w9, .cpr_dec
	uxtw x10, w9
	ldr  x0, [x19]
	add  x1, x19, #104
	mov  x2, x10
	bl   mac_read_exact2
	cbnz x0, .cpr_err
.cpr_dec:
	mov  x9, #1
	str  x9, [x19, #32]             /* active = 1 */
	ldr  x9, [x19, #24]
	sub  x9, x9, #1
	str  x9, [x19, #24]             /* remaining-- */
	mov  x0, #1
	b    .cpr_ret
.cpr_err:
	mov  x0, #-1
.cpr_ret:
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size mac_compact_read_rec,.-mac_compact_read_rec

/* ============================================================================
 * mac_lsm_recount(lst=x0, u=x1, cb=x2, ctx=x3) -> exact live count / -1
 * ========================================================================== */
	.type mac_lsm_recount,%function
mac_lsm_recount:
	stp  x29,x30,[sp,#-16]!
	mov  x29, sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp, sp, #0x100
	mov  x28, sp
	mov  x19, x0                    /* lst */
	mov  x20, x1                    /* u */
	mov  x21, x2                    /* cb */
	mov  x22, x3                    /* ctx */
	ldr  x9, [x20]
	str  x9, [x28, #0x00]           /* live = u->n */
	ldr  x23, [x19, #120]           /* manifest_n */
	str  xzr, [x28, #0x08]          /* mmap_size */
	cbz  x23, .rc_ret_live
	mov  x9, x23
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16      /* COMPACT_SLOT_SIZE */
	mul  x9, x9, x10
	str  x9, [x28, #0x08]           /* mmap_size */
	mov  x0, #0
	mov  x1, x9
	mov  x2, #3
	mov  x3, #0x22
	mov  x4, #-1
	mov  x5, #0
	mov  x8, #SYS_mmap
	svc  #0
	mov  x10, #-1
	cmp  x0, x10
	b.eq .rc_err_nomap
	mov  x24, x0                    /* slots base */
	mov  x25, #0
.rc_init_loop:
	cmp  x25, x23
	b.hs .rc_init_done
	mov  x9, x25
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16
	mul  x9, x9, x10
	add  x9, x9, x24
	mov  x10, #-1
	str  x10, [x9]                  /* slot.fd = -1 */
	str  xzr, [x9, #32]             /* active = 0 */
	add  x25, x25, #1
	b    .rc_init_loop
.rc_init_done:
	mov  x25, #0
.rc_open_loop:
	cmp  x25, x23
	b.hs .rc_open_done
	mov  x10, #16
	mul  x10, x25, x10
	ldr  x11, [x19, #104]
	add  x11, x11, x10
	ldr  x9, [x11]                  /* gen */
	ldr  x10, [x11, #8]             /* run_no */
	mov  x11, x25
	movz x12, #0x0068
	movk x12, #0x0001, lsl #16
	mul  x11, x11, x12
	add  x26, x11, x24              /* slot base (callee-saved) */
	str  x9, [x26, #8]              /* slot.gen */
	str  x10, [x26, #16]            /* slot.run_no */
	add  x0, x28, #0x80
	mov  w1, w10
	bl   fmt_runname
	mov  x0, #AT_FDCWD
	add  x1, x28, #0x80
	mov  x2, #O_RDONLY
	mov  x3, #0
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .rc_err_cleanup
	str  x0, [x26]                  /* slot.fd */
	add  x1, x28, #0x30
	bl   mac_read_run_header
	cbnz x0, .rc_err_cleanup
	add  x9, x28, #0x30+8           /* nrec (aligned +0x38) */
	ldr  x9, [x9]
	str  x9, [x26, #24]             /* slot.remaining */
	add  x9, x28, #0x30+56          /* rec_v2 */
	ldr  x9, [x9]
	str  x9, [x26, #96]             /* slot.rec_v2 */
	add  x9, x28, #0x30+16          /* bloom_bytes */
	ldr  x9, [x9]
	ldr  x0, [x26]                  /* fd */
	mov  x1, x9
	mov  x2, #1
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .rc_err_cleanup
	ldr  x9, [x26, #24]             /* remaining */
	cbz  x9, .rc_open_next
	mov  x0, x26
	bl   mac_compact_read_rec
	mov  x9, #-1
	cmp  x0, x9
	b.eq .rc_err_cleanup
.rc_open_next:
	add  x25, x25, #1
	b    .rc_open_loop
.rc_open_done:
	/* boot-progress hooks: phase=1 (recount active), reset done, and total =
	 * sum of the runs' nrec so a monitor can report % as records are read. */
	mov  x10, #1
	adrp x9, :got:g_utxo_prog_phase
	ldr  x9, [x9, :got_lo12:g_utxo_prog_phase]
	str  x10, [x9]
	adrp x9, :got:g_utxo_prog_done
	ldr  x9, [x9, :got_lo12:g_utxo_prog_done]
	str  xzr, [x9]
	adrp x9, :got:g_utxo_prog_total
	ldr  x9, [x9, :got_lo12:g_utxo_prog_total]
	str  xzr, [x9]
	mov  x25, #0
.rc_prg_loop:
	cmp  x25, x23
	b.hs .rc_prg_done
	mov  x10, x25
	movz x11, #0x0068
	movk x11, #0x0001, lsl #16
	mul  x10, x10, x11
	add  x10, x10, x24
	ldr  x11, [x10, #24]           /* slot.remaining = nrec */
	adrp x9, :got:g_utxo_prog_total
	ldr  x9, [x9, :got_lo12:g_utxo_prog_total]
	ldr  x12, [x9]
	add  x12, x12, x11
	str  x12, [x9]
	add  x25, x25, #1
	b    .rc_prg_loop
.rc_prg_done:
	/* streaming k-way merge, count only */
.rc_merge:
	mov  x9, #-1
	str  x9, [x28, #0x18]           /* best_idx = -1 */
	mov  x25, #0
.rc_find:
	cmp  x25, x23
	b.hs .rc_find_done
	mov  x9, x25
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16
	mul  x9, x9, x10
	add  x26, x9, x24                /* this slot (callee-saved) */
	ldr  x10, [x26, #32]
	cbz  x10, .rc_find_next
	ldr  x10, [x28, #0x18]
	mov  x11, #-1
	cmp  x10, x11
	b.eq .rc_find_setbest
	ldr  x10, [x28, #0x18]
	movz x11, #0x0068
	movk x11, #0x0001, lsl #16
	mul  x10, x10, x11
	add  x27, x10, x24               /* best slot (callee-saved) */
	add  x0, x26, #40
	add  x1, x27, #40
	bl   mac_cmp_key
	cmp  w0, #0
	b.eq .rc_find_setbest
	cmp  w0, #1
	b.ne .rc_find_next
	ldr  x0, [x26, #8]              /* this.gen */
	ldr  x1, [x27, #8]              /* best.gen */
	cmp  x0, x1
	b.ls .rc_find_next
.rc_find_setbest:
	str  x25, [x28, #0x18]
.rc_find_next:
	add  x25, x25, #1
	b    .rc_find
.rc_find_done:
	ldr  x9, [x28, #0x18]
	mov  x10, #-1
	cmp  x9, x10
	b.eq .rc_merge_done
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16
	mul  x9, x9, x10
	add  x27, x9, x24                /* winner slot (callee-saved) */
	add  x0, x28, #0xa0
	add  x1, x27, #40
	mov  x2, #36
	bl   mac_memcpy
	ldrb w9, [x27, #76]             /* type */
	cmp  w9, #1
	b.ne .rc_advance
	add  x9, x28, #0xa0
	mov  x0, x20
	mov  x1, x9
	ldr  w2, [x9, #32]
	add  x3, x28, #0xd0
	add  x4, x28, #0xd8
	add  x5, x28, #0xe0
	add  x6, x28, #0xe8
	add  x7, x28, #0xf0
	bl   utxo_get
	cmp  w0, #1
	b.eq .rc_advance
	mov  x0, x19
	add  x1, x28, #0xa0
	bl   mac_tomb_hash_probe
	ldr  x9, [x0]
	mov  x10, #-1
	cmp  x9, x10
	b.ne .rc_advance
	ldr  x9, [x28, #0x00]
	add  x9, x9, #1
	str  x9, [x28, #0x00]           /* live++ */
	cbz  x21, .rc_advance
	mov  x0, x22                     /* ctx */
	add  x1, x28, #0xa0              /* key36 */
	ldr  x2, [x27, #80]              /* value */
	add  x3, x27, #90
	ldr  w3, [x3]                    /* height */
	lsl  x3, x3, #1
	ldrb w4, [x27, #94]              /* is_coinbase */
	orr  x3, x3, x4                   /* code = (height<<1)|cb */
	add  x4, x27, #104                /* script (arg5) */
	ldrh w5, [x27, #88]               /* slen (arg6) */
	blr  x21
.rc_advance:
	mov  x25, #0
.rc_adv_loop:
	cmp  x25, x23
	b.hs .rc_adv_done
	mov  x9, x25
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16
	mul  x9, x9, x10
	add  x26, x9, x24                /* this slot (callee-saved) */
	ldr  x10, [x26, #32]
	cbz  x10, .rc_adv_next
	add  x0, x26, #40
	add  x1, x28, #0xa0
	bl   mac_cmp_key
	cmp  w0, #1
	b.ne .rc_adv_next
	ldr  x10, [x26, #24]            /* remaining */
	cbnz x10, .rc_adv_reread
	str  xzr, [x26, #32]            /* active = 0 */
	b    .rc_adv_next
.rc_adv_reread:
	mov  x0, x26
	bl   mac_compact_read_rec
	cmp  x0, #-1
	b.eq .rc_err_cleanup
.rc_adv_next:
	add  x25, x25, #1
	b    .rc_adv_loop
.rc_adv_done:
	b    .rc_merge
.rc_merge_done:
	mov  x25, #0
.rc_close_loop:
	cmp  x25, x23
	b.hs .rc_close_done
	mov  x9, x25
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16
	mul  x9, x9, x10
	add  x26, x9, x24
	ldr  x0, [x26]
	mov  x10, #-1
	cmp  x0, x10
	b.eq .rc_close_next
	mov  x8, #SYS_close
	svc  #0
.rc_close_next:
	add  x25, x25, #1
	b    .rc_close_loop
.rc_close_done:
	mov  x0, x24
	ldr  x1, [x28, #0x08]
	mov  x8, #SYS_munmap
	svc  #0
.rc_ret_live:
	ldr  x0, [x28, #0x00]
	b    .rc_ret
.rc_err_cleanup:
	mov  x25, #0
.rc_errc_loop:
	cmp  x25, x23
	b.hs .rc_errc_done
	mov  x9, x25
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16
	mul  x9, x9, x10
	add  x26, x9, x24
	ldr  x0, [x26]
	mov  x10, #-1
	cmp  x0, x10
	b.eq .rc_errc_next
	mov  x8, #SYS_close
	svc  #0
.rc_errc_next:
	add  x25, x25, #1
	b    .rc_errc_loop
.rc_errc_done:
	mov  x0, x24
	ldr  x1, [x28, #0x08]
	mov  x8, #SYS_munmap
	svc  #0
.rc_err_nomap:
	mov  x0, #-1
.rc_ret:
	mov  x10, #2
	adrp x9, :got:g_utxo_prog_phase
	ldr  x9, [x9, :got_lo12:g_utxo_prog_phase]
	str  x10, [x9]                   /* phase=2: recount finished */
	add  sp, sp, #0x100
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size mac_lsm_recount,.-mac_lsm_recount

/* ============================================================================
 * utxo_lsm_walk(lst=x0, u=x1, cb=x2, ctx=x3) -> live count / -1
 * ========================================================================== */
	.global utxo_lsm_walk
	.type utxo_lsm_walk,%function
utxo_lsm_walk:
	stp  x29,x30,[sp,#-16]!
	mov  x29, sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	mov  x19, x0
	mov  x20, x1
	mov  x21, x2
	mov  x22, x3
	bl   mac_lsm_recount
	mov  x9, #-1
	cmp  x0, x9
	b.eq .w_err
	mov  x23, x0                    /* total live */
	mov  x0, x20
	mov  x1, x21
	mov  x2, x22
	bl   utxo_walk_live
	ldr  x9, [x20]
	cmp  x0, x9
	b.ne .w_err
	mov  x0, x23
	b    .w_ret
.w_err:
	mov  x0, #-1
.w_ret:
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_lsm_walk,.-utxo_lsm_walk

/* ============================================================================
 * utxo_lsm_compact(lst=x0) -> 1 ok / 0 nothing-to-do / -1 err
 * ========================================================================== */
	.global utxo_lsm_compact
	.type utxo_lsm_compact,%function
utxo_lsm_compact:
	stp  x29,x30,[sp,#-16]!
	mov  x29, sp
	stp  x19,x20,[sp,#-16]!
	stp  x21,x22,[sp,#-16]!
	stp  x23,x24,[sp,#-16]!
	stp  x25,x26,[sp,#-16]!
	stp  x27,x28,[sp,#-16]!
	sub  sp, sp, #0x240
	mov  x28, sp
	mov  x19, x0                    /* lst */
	ldr  x9, [x19, #120]            /* manifest_n */
	cmp  x9, #2
	b.lo .cc_noop
	str  x9, [x28, #0x00]           /* original manifest_n */
	mov  x21, #COMPACT_MAX_RUNS     /* 64 */
	cmp  x9, x21
	b.ls .cc_bs_ok
	mov  x9, x21
.cc_bs_ok:
	mov  x21, x9                    /* batch_size */
	/* mmap COMPACT_SCRATCH_BYTES */
	mov  x0, #0
	movz x1, #0x1a00
	movk x1, #0x0080, lsl #16       /* 0x801A00 */
	mov  x2, #3
	mov  x3, #0x22
	mov  x4, #-1
	mov  x5, #0
	mov  x8, #SYS_mmap
	svc  #0
	mov  x9, #-1
	cmp  x0, x9
	b.eq .cc_err_noscratch
	mov  x20, x0                    /* scratch base */
	str  xzr, [x28, #0x08]          /* upper_bound */
	/* ---- open + prime each run ---- */
	mov  x25, #0                    /* i */
.cc_open_loop:
	cmp  x25, x21
	b.hs .cc_open_done
	mov  x10, #16
	mul  x10, x25, x10
	ldr  x11, [x19, #104]           /* manifest_buf */
	add  x11, x11, x10
	ldr  x9, [x11]                  /* gen */
	str  x9, [x28, #0x68]
	ldr  x9, [x11, #8]              /* run_no */
	str  x9, [x28, #0x70]
	/* slot base = scratch + i*COMPACT_SLOT_SIZE */
	mov  x11, x25
	movz x12, #0x0068
	movk x12, #0x0001, lsl #16
	mul  x11, x11, x12
	add  x26, x11, x20              /* slot base (callee-saved) */
	ldr  x9, [x28, #0x68]
	str  x9, [x26, #8]              /* slot.gen */
	ldr  x9, [x28, #0x70]
	str  x9, [x26, #16]             /* slot.run_no */
	str  xzr, [x26, #32]            /* active=0 */
	/* fmt_runname(buf, run_no); open read-only */
	add  x0, x28, #0xa0
	ldr  w1, [x28, #0x70]
	bl   fmt_runname
	mov  x0, #AT_FDCWD
	add  x1, x28, #0xa0
	mov  x2, #O_RDONLY
	mov  x3, #0
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .cc_err
	str  x0, [x26]                  /* slot.fd */
	add  x1, x28, #0xc0
	bl   mac_read_run_header
	cbnz x0, .cc_err
	add  x9, x28, #0xc0+8           /* nrec */
	ldr  x9, [x9]
	str  x9, [x26, #24]             /* slot.remaining */
	/* upper_bound += nrec */
	ldr  x10, [x26, #24]
	ldr  x9, [x28, #0x08]
	add  x9, x9, x10
	str  x9, [x28, #0x08]           /* upper_bound += nrec */
	add  x9, x28, #0xc0+56          /* rec_v2 */
	ldr  x9, [x9]
	str  x9, [x26, #96]             /* slot.rec_v2 */
	/* skip bloom: lseek(fd, bloom_bytes, SEEK_CUR) */
	add  x9, x28, #0xc0+16          /* bloom_bytes */
	ldr  x9, [x9]
	ldr  x0, [x26]
	mov  x1, x9
	mov  x2, #1
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .cc_err
	ldr  x9, [x26, #24]             /* remaining */
	cbz  x9, .cc_open_next
	mov  x0, x26
	bl   mac_compact_read_rec
	cmp  x0, #-1
	b.eq .cc_err
.cc_open_next:
	add  x25, x25, #1
	b    .cc_open_loop
.cc_open_done:
	/* ---- bloom sizing from upper_bound ---- */
	ldr  x9, [x28, #0x08]
	mov  x10, #10
	mul  x9, x9, x10
	cmp  x9, #64
	b.hs .cc_bb1
	mov  x9, #64
.cc_bb1:
	mov  x10, #1
.cc_bb_loop:
	cmp  x10, x9
	b.hs .cc_bb2
	lsl  x10, x10, #1
	b    .cc_bb_loop
.cc_bb2:
	movz x11, #0x4000, lsl #16       /* BLOOM_MAX_BYTES*8 */
	cmp  x10, x11
	b.ls .cc_bb3
	mov  x10, x11
.cc_bb3:
	str  x10, [x28, #0x10]           /* bloom_bits */
	lsr  x9, x10, #3
	str  x9, [x28, #0x18]            /* bloom_bytes */
	sub  x10, x10, #1
	str  x10, [x28, #0x20]           /* bits_mask */
	/* zero bloom region at scratch + COMPACT_SLOTS_BYTES */
	movz x9, #0x1a00
	movk x9, #0x0040, lsl #16        /* COMPACT_SLOTS_BYTES */
	add  x12, x20, x9                /* bloom base */
	ldr  x11, [x28, #0x18]
	mov  x9, #0
.cc_bz:
	cbz  x11, .cc_bz_done
	strb wzr, [x12, x9]
	add  x9, x9, #1
	sub  x11, x11, #1
	b    .cc_bz
.cc_bz_done:
	/* ---- mmap sparse scratch: (upper_bound/256+2)*44 ---- */
	ldr  x9, [x28, #0x08]
	mov  x10, #SPARSE_STRIDE
	udiv x9, x9, x10
	add  x9, x9, #2
	mov  x10, #44
	mul  x9, x9, x10
	str  x9, [x28, #0xf8]            /* sparse_scratch_bytes */
	mov  x0, #0
	mov  x1, x9
	mov  x2, #3
	mov  x3, #0x22
	mov  x4, #-1
	mov  x5, #0
	mov  x8, #SYS_mmap
	svc  #0
	mov  x10, #-1
	cmp  x0, x10
	b.eq .cc_err
	mov  x23, x0                    /* sparse scratch base */
	str  xzr, [x28, #0x40]          /* sparse_n */
	/* ---- open output run, write placeholder header+bloom ---- */
	ldr  x9, [x19, #96]             /* next_gen */
	str  x9, [x28, #0x28]           /* out_gen */
	ldr  x9, [x19, #144]            /* next_run_no */
	str  x9, [x28, #0x30]           /* out_run_no */
	add  x0, x28, #0xa0
	ldr  w1, [x28, #0x30]
	bl   fmt_runname
	mov  x0, #AT_FDCWD
	add  x1, x28, #0xa0
	mov  x2, #(O_WRONLY|O_CREAT|O_TRUNC)
	mov  x3, #0644
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .cc_err
	mov  x22, x0                     /* out_fd */
	/* placeholder header at x28+0xc0 */
	mov  w9, #0x5255
	movk w9, #0x3355, lsl #16        /* MAGIC_RUN3 */
	str  w9, [x28, #0xc0]
	add  x9, x28, #0xc4
	ldr  x10, [x28, #0x28]
	str  x10, [x9]                   /* out_gen */
	add  x9, x28, #0xcc
	str  xzr, [x9]                   /* nrec placeholder */
	add  x9, x28, #0xd4
	ldr  x10, [x28, #0x10]
	str  x10, [x9]                   /* bloom_bits */
	add  x9, x28, #0xdc
	str  xzr, [x9]                   /* sparse_off placeholder */
	add  x9, x28, #0xe4
	str  xzr, [x9]                   /* sparse_n placeholder */
	mov  x0, x22
	add  x1, x28, #0xc0
	mov  x2, #44
	bl   mac_write_exact
	cbnz x0, .cc_err_close
	/* write placeholder bloom */
	mov  x0, x22
	movz x1, #0x1a00
	movk x1, #0x0040, lsl #16        /* +COMPACT_SLOTS_BYTES */
	add  x1, x20, x1
	ldr  x2, [x28, #0x18]
	bl   mac_write_exact
	cbnz x0, .cc_err_close
	str  xzr, [x28, #0x38]           /* true_nrec = 0 */
	/* ================= streaming k-way merge ================= */
.cc_merge_loop:
	mov  x9, #-1
	str  x9, [x28, #0x58]            /* best_idx = -1 */
	mov  x25, #0
.cc_find_loop:
	cmp  x25, x21
	b.hs .cc_find_done
	mov  x9, x25
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16
	mul  x9, x9, x10
	add  x26, x9, x20                /* this slot (callee-saved) */
	ldr  x10, [x26, #32]
	cbz  x10, .cc_find_next
	ldr  x10, [x28, #0x58]
	mov  x11, #-1
	cmp  x10, x11
	b.eq .cc_find_setbest
	ldr  x10, [x28, #0x58]
	movz x11, #0x0068
	movk x11, #0x0001, lsl #16
	mul  x10, x10, x11
	add  x27, x10, x20                /* best slot (callee-saved) */
	add  x0, x26, #40
	add  x1, x27, #40
	bl   mac_cmp_key
	cmp  w0, #0
	b.eq .cc_find_setbest
	cmp  w0, #1
	b.ne .cc_find_next
	ldr  x0, [x26, #8]               /* this.gen */
	ldr  x1, [x27, #8]               /* best.gen */
	cmp  x0, x1
	b.ls .cc_find_next
.cc_find_setbest:
	str  x25, [x28, #0x58]
.cc_find_next:
	add  x25, x25, #1
	b    .cc_find_loop
.cc_find_done:
	ldr  x9, [x28, #0x58]
	mov  x10, #-1
	cmp  x9, x10
	b.eq .cc_merge_done
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16
	mul  x9, x9, x10
	add  x27, x9, x20                 /* winning slot */
	add  x0, x28, #0x80
	add  x1, x27, #40
	mov  x2, #36
	bl   mac_memcpy                   /* snapshot winning key */
	ldrb w9, [x27, #76]              /* type */
	cmp  w9, #1
	b.ne .cc_wr_skip
	/* sparse sampling by true_nrec */
	ldr  x9, [x28, #0x38]
	tst  x9, #(SPARSE_STRIDE-1)
	b.ne .cc_sp_nosample
	mov  x0, x22
	mov  x1, #0
	mov  x2, #1
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .cc_err_close
	mov  x26, x0                      /* file offset */
	/* dest = sparse_base + sparse_n*44 */
	ldr  x9, [x28, #0x40]
	mov  x10, #44
	mul  x10, x9, x10
	add  x0, x23, x10
	add  x1, x27, #40
	mov  x2, #36
	bl   mac_memcpy
	str  x26, [x0, #36]              /* file_offset */
	ldr  x9, [x28, #0x40]
	add  x9, x9, #1
	str  x9, [x28, #0x40]            /* sparse_n++ */
.cc_sp_nosample:
	/* write key+type (37 bytes) */
	mov  x0, x22
	add  x1, x27, #40
	mov  x2, #37
	bl   mac_write_exact
	cbnz x0, .cc_err_close
	/* write value(8)+slen(2)+height(4)+cb(1) = 15 bytes */
	mov  x0, x22
	add  x1, x27, #80
	mov  x2, #15
	bl   mac_write_exact
	cbnz x0, .cc_err_close
	ldrh w9, [x27, #88]              /* slen */
	cbz  w9, .cc_wr_bloom
	mov  x0, x22
	add  x1, x27, #104
	uxtw x2, w9
	bl   mac_write_exact
	cbnz x0, .cc_err_close
.cc_wr_bloom:
	/* set 3 bloom bits */
	mov  x0, x27
	add  x0, x0, #40                 /* key ptr */
	movz x1, #0x1a00
	movk x1, #0x0040, lsl #16
	add  x2, x20, x1                 /* bloom base */
	ldr  w3, [x28, #0x20]            /* bits_mask */
	mov  w4, #0x9dc5
	movk w4, #0x811c, lsl #16
	mov  w1, w4
	bl   mac_bloom_setbit
	mov  x0, x27
	add  x0, x0, #40
	movz x1, #0x1a00
	movk x1, #0x0040, lsl #16
	add  x2, x20, x1
	ldr  w3, [x28, #0x20]
	mov  w4, #0xc3d4
	movk w4, #0xa1b2, lsl #16
	mov  w1, w4
	bl   mac_bloom_setbit
	mov  x0, x27
	add  x0, x0, #40
	movz x1, #0x1a00
	movk x1, #0x0040, lsl #16
	add  x2, x20, x1
	ldr  w3, [x28, #0x20]
	mov  w4, #0xe995
	movk w4, #0x5bd1, lsl #16
	mov  w1, w4
	bl   mac_bloom_setbit
	ldr  x9, [x28, #0x38]
	add  x9, x9, #1
	str  x9, [x28, #0x38]            /* true_nrec++ */
.cc_wr_skip:
	/* advance all slots with key == winning key */
	mov  x25, #0
.cc_adv_loop:
	cmp  x25, x21
	b.hs .cc_adv_done
	mov  x9, x25
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16
	mul  x9, x9, x10
	add  x26, x9, x20                /* this slot (callee-saved) */
	ldr  x10, [x26, #32]
	cbz  x10, .cc_adv_next
	add  x0, x26, #40
	add  x1, x28, #0x80
	bl   mac_cmp_key
	cmp  w0, #1
	b.ne .cc_adv_next
	ldr  x10, [x26, #24]
	cbnz x10, .cc_adv_reread
	str  xzr, [x26, #32]            /* active=0 */
	b    .cc_adv_next
.cc_adv_reread:
	mov  x0, x26
	bl   mac_compact_read_rec
	cmp  x0, #-1
	b.eq .cc_err_close
.cc_adv_next:
	add  x25, x25, #1
	b    .cc_adv_loop
.cc_adv_done:
	b    .cc_merge_loop
.cc_merge_done:
	/* ---- patch bloom (offset 44) and nrec (offset 12) ---- */
	mov  x0, x22
	mov  x1, #44
	mov  x2, #0
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .cc_err_close
	mov  x0, x22
	movz x1, #0x1a00
	movk x1, #0x0040, lsl #16
	add  x1, x20, x1
	ldr  x2, [x28, #0x18]
	bl   mac_write_exact
	cbnz x0, .cc_err_close
	mov  x0, x22
	mov  x1, #12
	mov  x2, #0
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .cc_err_close
	ldr  x9, [x28, #0x38]
	str  x9, [x28, #0xc0]            /* patch nrec (full 64-bit qword at 8-aligned +0xc0) */
	mov  x0, x22
	add  x1, x28, #0xc0
	mov  x2, #8
	bl   mac_write_exact
	cbnz x0, .cc_err_close
	/* ---- append sparse index (SEEK_END), then patch header at 28 ---- */
	mov  x0, x22
	mov  x1, #0
	mov  x2, #2
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .cc_err_close
	mov  x26, x0                      /* sparse_off */
	ldr  x9, [x28, #0x40]             /* sparse_n */
	cbz  x9, .cc_sp_wr_done
	mov  x0, x22
	mov  x1, x23
	mov  x10, #44
	mul  x2, x9, x10
	bl   mac_write_exact
	cbnz x0, .cc_err_close
.cc_sp_wr_done:
	mov  x0, x22
	mov  x1, #28
	mov  x2, #0
	mov  x8, #SYS_lseek
	svc  #0
	tbnz x0, #63, .cc_err_close
	add  x9, x28, #0xdc
	str  x26, [x9]                    /* sparse_off */
	add  x10, x28, #0xe4
	ldr  x9, [x28, #0x40]
	str  x9, [x10]                    /* sparse_n */
	mov  x0, x22
	add  x1, x28, #0xdc
	mov  x2, #16
	bl   mac_write_exact
	cbnz x0, .cc_err_close
	mov  x0, x22
	bl   mac_fsync2
	mov  x0, x22
	mov  x8, #SYS_close
	svc  #0
	/* ---- manifest: merged entry at index 0, shift survivors ---- */
	ldr  x11, [x19, #104]            /* manifest_buf */
	ldr  x9, [x28, #0x28]
	str  x9, [x11]                    /* gen */
	ldr  x9, [x28, #0x30]
	str  x9, [x11, #8]               /* run_no */
	mov  x25, x21                     /* src = batch_size */
	mov  x26, #1                      /* dst = 1 */
	ldr  x27, [x19, #120]             /* manifest_n */
.cc_shift_loop:
	cmp  x25, x27
	b.hs .cc_shift_done
	ldr  x11, [x19, #104]
	mov  x10, #16
	mul  x10, x25, x10
	add  x11, x11, x10                /* src ptr */
	ldr  x12, [x19, #104]
	mov  x10, #16
	mul  x10, x26, x10
	add  x12, x12, x10                 /* dst ptr */
	ldr  x9, [x11]
	str  x9, [x12]
	ldr  x9, [x11, #8]
	str  x9, [x12, #8]
	add  x25, x25, #1
	add  x26, x26, #1
	b    .cc_shift_loop
.cc_shift_done:
	str  x26, [x19, #120]             /* manifest_n = new count */
	ldr  x9, [x19, #96]
	add  x9, x9, #1
	str  x9, [x19, #96]               /* next_gen++ */
	ldr  x9, [x19, #144]
	add  x9, x9, #1
	str  x9, [x19, #144]              /* next_run_no++ */
	/* ---- decide live-count field for new manifest ---- */
	str  xzr, [x28, #0x200]           /* has_count = 0 */
	mov  x0, #AT_FDCWD
	adr  x1, manifest_name
	mov  x2, #O_RDONLY
	mov  x3, #0
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .cc_pl_decide
	str  x0, [x28, #0x208]            /* read fd */
	mov  x0, x0
	add  x1, x28, #0xc0
	mov  x2, #12
	bl   mac_read_exact2
	cbnz x0, .cc_pl_close
	ldr  w9, [x28, #0xc0]
	mov  w10, #0x4d55
	movk w10, #0x324e, lsl #16        /* MAGIC_MANIFEST2 */
	cmp  w9, w10
	b.ne .cc_pl_close
	ldr  x0, [x28, #0x208]
	add  x1, x28, #0x210              /* P_old */
	mov  x2, #8
	bl   mac_read_exact2
	cbnz x0, .cc_pl_close
	mov  x9, #1
	str  x9, [x28, #0x200]            /* has_count = 1 */
.cc_pl_close:
	ldr  x0, [x28, #0x208]
	mov  x8, #SYS_close
	svc  #0
.cc_pl_decide:
	mov  x9, x21
	ldr  x10, [x28, #0x00]
	cmp  x9, x10
	b.ne .cc_pl_partial
	/* full merge: persist_count = true_nrec */
	ldr  x9, [x28, #0x38]
	str  x9, [x28, #0x218]            /* persist_count */
	mov  x9, #1
	str  x9, [x28, #0x220]            /* write_v2 = 1 */
	ldr  x9, [x28, #0x200]            /* has_count */
	cbz  x9, .cc_pl_have
	ldr  x9, [x19, #88]
	ldr  x10, [x28, #0x210]           /* P_old */
	sub  x9, x9, x10
	ldr  x10, [x28, #0x38]
	add  x9, x9, x10
	str  x9, [x19, #88]
	b    .cc_pl_have
.cc_pl_partial:
	ldr  x9, [x28, #0x200]
	cbz  x9, .cc_pl_v1
	ldr  x9, [x28, #0x210]
	str  x9, [x28, #0x218]
	mov  x9, #1
	str  x9, [x28, #0x220]
	b    .cc_pl_have
.cc_pl_v1:
	str  xzr, [x28, #0x220]           /* write_v1 */
.cc_pl_have:
	/* ---- publish manifest ---- */
	mov  x0, #AT_FDCWD
	adr  x1, manifest_tmp_name
	mov  x2, #(O_WRONLY|O_CREAT|O_TRUNC)
	mov  x3, #0644
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .cc_err_close
	mov  x24, x0                      /* tmp fd */
	ldr  x9, [x19, #120]              /* manifest_n */
	add  x11, x28, #0xc4
	str  x9, [x11]                    /* manifest_n in header */
	ldr  x9, [x28, #0x220]            /* write_v2 */
	cbz  x9, .cc_hdr_v1
	mov  w9, #0x4d55
	movk w9, #0x324e, lsl #16         /* MAGIC_MANIFEST2 */
	str  w9, [x28, #0xc0]
	add  x11, x28, #0xcc
	ldr  x9, [x28, #0x218]
	str  x9, [x11]                    /* total_live */
	mov  x2, #20
	b    .cc_hdr_wr
.cc_hdr_v1:
	mov  w9, #0x4d55
	movk w9, #0x4e41, lsl #16         /* MAGIC_MANIFEST */
	str  w9, [x28, #0xc0]
	mov  x2, #12
.cc_hdr_wr:
	mov  x0, x24
	add  x1, x28, #0xc0
	bl   mac_write_exact
	cbnz x0, .cc_merr_close
	mov  x0, x24
	ldr  x1, [x19, #104]
	ldr  x2, [x19, #120]
	lsl  x2, x2, #4
	bl   mac_write_exact
	cbnz x0, .cc_merr_close
	mov  x0, x24
	bl   mac_fsync2
	mov  x0, x24
	mov  x8, #SYS_close
	svc  #0
	mov  x0, #AT_FDCWD
	adr  x1, manifest_tmp_name
	mov  x2, #AT_FDCWD
	adr  x3, manifest_name
	mov  x8, #SYS_renameat
	svc  #0
	tbnz x0, #63, .cc_err_close
	/* dir fsync */
	mov  x0, #AT_FDCWD
	adr  x1, dot_name
	mov  x2, #O_RDONLY
	mov  x3, #0
	mov  x8, #SYS_openat
	svc  #0
	tbnz x0, #63, .cc_dirsync_skip
	mov  x24, x0
	mov  x0, x24
	bl   mac_fsync2
	mov  x0, x24
	mov  x8, #SYS_close
	svc  #0
.cc_dirsync_skip:
	/* close output, unlink old runs */
	mov  x0, x22
	mov  x8, #SYS_close
	svc  #0
	mov  x25, #0
.cc_unlink_loop:
	cmp  x25, x21
	b.hs .cc_unlink_done
	mov  x9, x25
	movz x10, #0x0068
	movk x10, #0x0001, lsl #16
	mul  x9, x9, x10
	add  x9, x9, x20
	ldr  x0, [x9]
	mov  x8, #SYS_close
	svc  #0
	ldr  w1, [x9, #16]               /* run_no */
	add  x0, x28, #0xa0
	bl   fmt_runname
	mov  x0, #AT_FDCWD
	add  x1, x28, #0xa0
	mov  x2, #0
	mov  x8, #SYS_unlinkat
	svc  #0
	add  x25, x25, #1
	b    .cc_unlink_loop
.cc_unlink_done:
	/* munmap scratch + sparse scratch */
	mov  x0, x20
	movz x1, #0x1a00
	movk x1, #0x0080, lsl #16        /* COMPACT_SCRATCH_BYTES */
	mov  x8, #SYS_munmap
	svc  #0
	mov  x0, x23
	ldr  x1, [x28, #0xf8]
	mov  x8, #SYS_munmap
	svc  #0
	mov  x0, #1
	b    .cc_ret
.cc_merr_close:
	mov  x0, x24
	mov  x8, #SYS_close
	svc  #0
	b    .cc_err_close
.cc_err_close:
	mov  x0, x22
	mov  x8, #SYS_close
	svc  #0
.cc_err:
	mov  x0, #-1
	b    .cc_ret
.cc_noop:
	mov  x0, #0
	b    .cc_ret
.cc_err_noscratch:
	mov  x0, #-1
	b    .cc_ret
.cc_ret:
	add  sp, sp, #0x240
	ldp  x27,x28,[sp],#16
	ldp  x25,x26,[sp],#16
	ldp  x23,x24,[sp],#16
	ldp  x21,x22,[sp],#16
	ldp  x19,x20,[sp],#16
	ldp  x29,x30,[sp],#16
	ret
	.size utxo_lsm_compact,.-utxo_lsm_compact

	.section .rodata
manifest_name:
	.asciz "utxo_manifest.dat"
manifest_tmp_name:
	.asciz "utxo_manifest.tmp"
dot_name:
	.asciz "."
wal_name:
	.asciz "utxo.dat"
	.section .text

	.section .note.GNU-stack,"",@progbits

	.bss
	.balign 8
	.globl g_utxo_prog_phase
	.type  g_utxo_prog_phase, @object
g_utxo_prog_phase: .zero 8
	.globl g_utxo_prog_done
	.type  g_utxo_prog_done, @object
g_utxo_prog_done:  .zero 8
	.globl g_utxo_prog_total
	.type  g_utxo_prog_total, @object
g_utxo_prog_total: .zero 8
	.text
	.balign 4
	.globl g_utxo_prog_bump
	.type  g_utxo_prog_bump, @function
g_utxo_prog_bump:
	adrp x9, :got:g_utxo_prog_done
	ldr  x9, [x9, :got_lo12:g_utxo_prog_done]
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	ret
