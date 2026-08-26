/* ============================================================================
 * bitcoin_store_fast.S -- AArch64 (ARMv8-A) port of asm/bitcoin_store_fast.asm
 *
 * Fast block READ path for bitcoin_store: a direct-mapped cache of read-only
 * block fds (pread-based, no shared offset -> thread-safe) and an mmap-backed
 * ZERO-COPY map cache for serving/hashing blocks straight out of the page
 * cache. The write path (store_append/open_file/cur_blk_fd) is untouched.
 *
 * ABI (SysV x64 -> AAPCS64): rdi/rsi/rdx/rcx/r8 -> x0/x1/x2/x3/x4.
 *   void store_rd_init   (void *st)
 *   void store_rd_close  (void *st)      (= tail store_rd_init)
 *   int  store_rd_fd     (void *st, u32 file_no) -> fd / -errno
 *   long store_read_meta (void *st, u64 height, u64 meta[3], void *buf, u64 cap)
 *   long store_read_at   (void *st, u64 height, void *buf, u64 cap)
 *   void store_rd_advise (void *st, u64 height, u64 nblocks)
 *   void store_map_init  (void *st)
 *   void store_map_close (void *st)     (= tail store_map_init)
 *   const u8 *store_map_at (void *st, u64 height, u64 out[2])
 *   void store_map_advise(void *st, u64 height, u64 nblocks)
 *   int  store_prune_safe(void *st, u32 prune_height)
 *
 * FD cache : +56 magic(8) +64 +slot*8 : dword file_no, dword fd. 8 slots.
 *           slot = file_no & 7.  FDC_MAGIC = 0x52444643_00000001 ("RDFC").
 * MAP cache: +120 magic(8) +128 +slot*32 : dword file_no, dword fd,
 *           qword addr, qword maplen, qword reserved. 4 slots.
 *           slot = file_no & 3.  MAP_MAGIC = 0x4d415000_00000001 ("MAP").
 *
 * AArch64 syscall deltas (differ from the x86 constants in the asm header):
 *   openat=56 (no plain open) close=57 pread64=67 (offset in x3) fstat=80
 *   fadvise64=223 (fd,off,len,advice in x0..x3) mmap=222 (6 args x0..x5)
 *   munmap=215  madvise=233.  O_CLOEXEC=0x80000.  st_size at statbuf+48.
 *   svc does NOT set NZCV -> use tbnz x0,#63 for negative return checks and
 *   mmap-failure (user mappings always have bit63 clear).
 * ========================================================================== */

	.text
	.global store_rd_init
	.type store_rd_init, %function
	.global store_rd_close
	.type store_rd_close, %function
	.global store_rd_fd
	.type store_rd_fd, %function
	.global store_read_meta
	.type store_read_meta, %function
	.global store_read_at
	.type store_read_at, %function
	.global store_rd_advise
	.type store_rd_advise, %function
	.global store_map_init
	.type store_map_init, %function
	.global store_map_close
	.type store_map_close, %function
	.global store_map_at
	.type store_map_at, %function
	.global store_map_advise
	.type store_map_advise, %function
	.global store_prune_safe
	.type store_prune_safe, %function

	.extern fmt_blkname
	.extern store_get_at
	.extern store_prune

/* ============================================================================
 * store_rd_init(st)  -- reset the read-fd cache, closing anything cached.
 * ========================================================================== */
store_rd_init:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x29, [sp, #-16]!
	stp  x30, xzr, [sp, #-16]!
	mov  x19, x0                 /* st */
	/* FDC_MAGIC = 0x52444643_00000001 */
	movz x10, #0x0001
	movk x10, #0x4446, lsl #32
	movk x10, #0x5243, lsl #48
	ldr  x11, [x19, #56]
	cmp  x11, x10
	b.ne .Sf_rd_fresh
	/* magic present -> slots hold real fds: close them */
	add  x20, x19, #64           /* slot base */
	mov  x21, #0
.Sf_rd_closeloop:
	cmp  x21, #8
	b.hs .Sf_rd_fresh
	add  x11, x20, x21, lsl #3
	ldr  w9, [x11, #4]           /* fd */
	cmp  w9, #0
	b.lt .Sf_rd_next
	mov  x8, #57                 /* close */
	mov  x0, x9
	svc  #0
.Sf_rd_next:
	add  x21, x21, #1
	b    .Sf_rd_closeloop
.Sf_rd_fresh:
	/* clear slots: file_no=0, fd=-1 */
	add  x20, x19, #64
	mov  x21, #0
.Sf_rd_clrloop:
	cmp  x21, #8
	b.hs .Sf_rd_done
	add  x11, x20, x21, lsl #3
	str  wzr, [x11, #0]          /* file_no = 0 */
	mov  w9, #-1
	str  w9, [x11, #4]           /* fd = -1 */
	add  x21, x21, #1
	b    .Sf_rd_clrloop
.Sf_rd_done:
	movz x10, #0x0001
	movk x10, #0x4446, lsl #32
	movk x10, #0x5243, lsl #48
	str  x10, [x19, #56]         /* magic */
	ldp  x30, xzr, [sp], #16
	ldp  x21, x29, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_rd_init, .-store_rd_init

/* store_rd_close(st) == store_rd_init(st) */
store_rd_close:
	b    store_rd_init
	.size store_rd_close, .-store_rd_close

/* ============================================================================
 * store_rd_fd(st, file_no) -> fd (>=0) or negative errno
 * ========================================================================== */
store_rd_fd:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #16             /* name[16] @sp */
	mov  x19, x0
	mov  w20, w1                 /* file_no */
	movz x10, #0x0001
	movk x10, #0x4446, lsl #32
	movk x10, #0x5243, lsl #48
	ldr  x11, [x19, #56]
	cmp  x11, x10
	b.eq .Sf_fd_ready
	mov  x0, x19
	bl   store_rd_init
.Sf_fd_ready:
	and  w10, w20, #7
	add  x21, x19, #64
	add  x21, x21, x10, lsl #3   /* &slot */
	ldr  w9, [x21, #4]           /* fd */
	cmp  w9, #0
	b.lt .Sf_fd_miss
	ldr  w10, [x21, #0]          /* file_no */
	cmp  w10, w20
	b.ne .Sf_fd_evict
	mov  w0, w9                  /* HIT: zero syscalls */
	b    .Sf_fd_ret
.Sf_fd_evict:
	mov  x8, #57
	mov  x0, x9
	svc  #0                      /* close old */
	mov  w9, #-1
	str  w9, [x21, #4]
.Sf_fd_miss:
	mov  x0, sp
	mov  w1, w20
	bl   fmt_blkname
	mov  x8, #56                 /* openat */
	mov  x0, #-100               /* AT_FDCWD */
	mov  x1, sp
	mov  x2, #0x80000            /* O_RDONLY|O_CLOEXEC */
	mov  x3, #0
	svc  #0
	tbnz x0, #63, .Sf_fd_ret     /* propagate -errno */
	str  w20, [x21, #0]          /* file_no */
	str  w0, [x21, #4]           /* fd */
.Sf_fd_ret:
	add  sp, sp, #16
	ldp  x29, x30, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_rd_fd, .-store_rd_fd

/* ============================================================================
 * store_read_meta(st, height, meta[3], buf, cap) -> size / -4 / -3 / -2 / -1
 * ========================================================================== */
store_read_meta:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x29, [sp, #-16]!
	stp  x30, xzr, [sp, #-16]!
	mov  x19, x0                 /* st */
	mov  x20, x4                 /* cap */
	mov  x21, x2                 /* meta */
	mov  x22, x3                 /* buf */
	ldr  x9, [x21, #8]           /* size already known? */
	cbnz x9, .Sf_rm_have
	mov  x0, x19
	mov  x1, x1                  /* height (unchanged) */
	mov  x2, x21
	bl   store_get_at
	cmp  x0, #1
	b.ne .Sf_rm_ret              /* propagate store_get_at status */
.Sf_rm_have:
	ldr  x9, [x21, #8]           /* size */
	cmp  x9, x20                 /* cap */
	b.hi .Sf_rm_toobig
	ldr  w10, [x21, #16]         /* file_no */
	mov  x0, x19
	mov  w1, w10
	bl   store_rd_fd
	tbnz x0, #63, .Sf_rm_err
	mov  x23, x0                 /* fd */
	mov  x8, #67                 /* pread64 */
	mov  x0, x23
	mov  x1, x22                 /* buf */
	ldr  x2, [x21, #8]           /* size */
	ldr  x3, [x21, #0]           /* pos */
	add  x3, x3, #8              /* + frame header */
	svc  #0
	ldr  x9, [x21, #8]
	cmp  x0, x9
	b.ne .Sf_rm_err
	b    .Sf_rm_ret              /* x0 == size */
.Sf_rm_toobig:
	mov  x0, #-4
	b    .Sf_rm_ret
.Sf_rm_err:
	mov  x0, #-1
.Sf_rm_ret:
	ldp  x30, xzr, [sp], #16
	ldp  x23, x29, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_read_meta, .-store_read_meta

/* ============================================================================
 * store_read_at(st, height, buf, cap) -> size or negative
 * ========================================================================== */
store_read_at:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #32             /* meta[3] @sp */
	mov  x19, x0
	mov  x20, x1                 /* height */
	mov  x21, x2                 /* buf */
	mov  x22, x3                 /* cap */
	str  xzr, [sp]
	str  xzr, [sp, #8]
	str  xzr, [sp, #16]
	mov  x0, x19
	mov  x1, x20
	mov  x2, sp                  /* meta */
	mov  x3, x21                 /* buf */
	mov  x4, x22                 /* cap */
	bl   store_read_meta
	add  sp, sp, #32
	ldp  x29, x30, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_read_at, .-store_read_at

/* ============================================================================
 * store_rd_advise(st, height, nblocks) -- best-effort fadvise WILLNEED.
 * ========================================================================== */
store_rd_advise:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x29, [sp, #-16]!
	stp  x30, xzr, [sp, #-16]!
	sub  sp, sp, #48             /* m0[3]@sp, m1[3]@sp+24, len@sp+40 */
	mov  x19, x0
	mov  x20, x1                 /* height */
	mov  x21, x2                 /* nblocks */
	cbz  x21, .Sf_ra_ret
	mov  x0, x19
	mov  x1, x20
	mov  x2, sp                  /* m0 */
	bl   store_get_at
	cmp  x0, #1
	b.ne .Sf_ra_ret
	add  x9, x20, x21
	sub  x9, x9, #1              /* height+nblocks-1 */
	mov  x0, x19
	mov  x1, x9
	add  x2, sp, #24             /* m1 */
	bl   store_get_at
	cmp  x0, #1
	b.ne .Sf_ra_single
	ldr  w9, [sp, #16]           /* m0.file_no */
	ldr  w10, [sp, #40]          /* m1.file_no (sp+24+16) */
	cmp  w9, w10
	b.ne .Sf_ra_single
	ldr  x10, [sp, #24]          /* m1.pos */
	ldr  x9, [sp, #32]           /* m1.size */
	add  x10, x10, x9
	add  x10, x10, #8
	ldr  x9, [sp, #0]            /* m0.pos */
	sub  x10, x10, x9
	str  x10, [sp, #40]          /* len */
	b    .Sf_ra_advise
.Sf_ra_single:
	ldr  x9, [sp, #8]            /* m0.size */
	add  x9, x9, #8
	str  x9, [sp, #40]           /* len = size+8 */
.Sf_ra_advise:
	ldr  w1, [sp, #16]           /* m0.file_no */
	mov  x0, x19
	bl   store_rd_fd
	tbnz x0, #63, .Sf_ra_ret
	mov  x8, #223                /* fadvise64 */
	ldr  x1, [sp, #0]            /* offset */
	ldr  x2, [sp, #40]           /* len */
	mov  x3, #3                  /* FADV_WILLNEED */
	svc  #0                      /* best-effort */
.Sf_ra_ret:
	add  sp, sp, #48
	ldp  x30, xzr, [sp], #16
	ldp  x23, x29, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_rd_advise, .-store_rd_advise

/* ============================================================================
 * store_map_init(st)  -- reset the mapping cache, unmapping anything live.
 * ========================================================================== */
store_map_init:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x29, [sp, #-16]!
	stp  x30, xzr, [sp, #-16]!
	mov  x19, x0
	/* MAP_MAGIC = 0x4d415000_00000001 */
	movz x10, #0x0001
	movk x10, #0x5000, lsl #32
	movk x10, #0x4d41, lsl #48
	ldr  x11, [x19, #120]
	cmp  x11, x10
	b.ne .Sf_mp_fresh
	add  x20, x19, #128          /* slot base */
	mov  x21, #0
.Sf_mp_uloop:
	cmp  x21, #4
	b.hs .Sf_mp_fresh
	add  x11, x20, x21, lsl #5
	ldr  x9, [x11, #8]           /* addr */
	cbz  x9, .Sf_mp_ufd
	mov  x0, x9
	ldr  x1, [x11, #16]          /* maplen */
	mov  x8, #215                /* munmap */
	svc  #0
.Sf_mp_ufd:
	ldr  w9, [x11, #4]           /* fd */
	cmp  w9, #0
	b.lt .Sf_mp_unext
	mov  x8, #57
	mov  x0, x9
	svc  #0                      /* close */
.Sf_mp_unext:
	add  x21, x21, #1
	b    .Sf_mp_uloop
.Sf_mp_fresh:
	add  x20, x19, #128
	mov  x21, #0
.Sf_mp_cloop:
	cmp  x21, #4
	b.hs .Sf_mp_done
	add  x11, x20, x21, lsl #5
	str  wzr, [x11, #0]          /* file_no=0 */
	mov  w9, #-1
	str  w9, [x11, #4]           /* fd=-1 */
	str  xzr, [x11, #8]          /* addr=0 */
	str  xzr, [x11, #16]         /* maplen=0 */
	str  xzr, [x11, #24]         /* reserved=0 */
	add  x21, x21, #1
	b    .Sf_mp_cloop
.Sf_mp_done:
	movz x10, #0x0001
	movk x10, #0x5000, lsl #32
	movk x10, #0x4d41, lsl #48
	str  x10, [x19, #120]
	ldp  x30, xzr, [sp], #16
	ldp  x21, x29, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_map_init, .-store_map_init

/* store_map_close(st) == store_map_init(st) */
store_map_close:
	b    store_map_init
	.size store_map_close, .-store_map_close

/* ============================================================================
 * map_file(st, file_no, need_end) -> base addr (0 on failure)
 *   Local. Remaps if the cached mapping does not already cover need_end.
 *   Frame: 4 save pairs then sub 0xC0 (statbuf[144]@sp, name[16]@sp+160).
 *   Regs: x19=st x20=file_no x21=need_end x22=&slot x23=maplen/name.
 * ========================================================================== */
	.type map_file, %function
map_file:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x24, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #192
	mov  x19, x0
	mov  w20, w1
	mov  x21, x2
	movz x10, #0x0001
	movk x10, #0x5000, lsl #32
	movk x10, #0x4d41, lsl #48
	ldr  x11, [x19, #120]
	cmp  x11, x10
	b.eq .Sf_mf_ready
	mov  x0, x19
	bl   store_map_init
.Sf_mf_ready:
	and  w9, w20, #3
	add  x22, x19, #128
	add  x22, x22, x9, lsl #5    /* &slot */
	ldr  w9, [x22, #0]           /* file_no */
	cmp  w9, w20
	b.ne .Sf_mf_replace
	ldr  x9, [x22, #8]           /* addr */
	cbz  x9, .Sf_mf_replace
	ldr  x9, [x22, #16]          /* maplen */
	cmp  x21, x9
	b.hi .Sf_mf_grow
	ldr  x0, [x22, #8]           /* HIT */
	b    .Sf_mf_ret
.Sf_mf_replace:
	ldr  x9, [x22, #8]
	cbz  x9, .Sf_mf_repfd
	mov  x0, x9
	ldr  x1, [x22, #16]
	mov  x8, #215
	svc  #0                      /* munmap */
	str  xzr, [x22, #8]
.Sf_mf_repfd:
	ldr  w9, [x22, #4]           /* fd */
	cmp  w9, #0
	b.lt .Sf_mf_opennew
	mov  x8, #57
	mov  x0, x9
	svc  #0                      /* close */
	mov  w9, #-1
	str  w9, [x22, #4]
.Sf_mf_opennew:
	add  x23, sp, #160           /* name[16] */
	mov  x0, x23
	mov  w1, w20
	bl   fmt_blkname
	mov  x8, #56                 /* openat */
	mov  x0, #-100
	mov  x1, x23
	mov  x2, #0x80000
	mov  x3, #0
	svc  #0
	tbnz x0, #63, .Sf_mf_fail
	str  w0, [x22, #4]           /* fd */
	str  w20, [x22, #0]          /* file_no */
	b    .Sf_mf_domap
.Sf_mf_grow:
	ldr  x0, [x22, #8]
	ldr  x1, [x22, #16]
	mov  x8, #215
	svc  #0                      /* munmap old mapping */
	str  xzr, [x22, #8]
.Sf_mf_domap:
	ldr  w0, [x22, #4]           /* fd */
	mov  x1, sp                  /* statbuf */
	mov  x8, #80                 /* fstat */
	svc  #0
	tbnz x0, #63, .Sf_mf_fail
	ldr  x9, [sp, #48]           /* st_size */
	cmp  x9, x21                 /* need_end */
	b.lo .Sf_mf_fail
	mov  x23, x9                 /* maplen */
	mov  x8, #222                /* mmap */
	mov  x0, #0                  /* addr=NULL */
	mov  x1, x23                 /* length */
	mov  x2, #1                  /* PROT_READ */
	mov  w3, #0x4000
	orr  w3, w3, #2              /* MAP_NORESERVE|MAP_PRIVATE */
	ldr  x4, [x22, #4]           /* fd */
	mov  x5, #0                  /* offset */
	svc  #0
	tbnz x0, #63, .Sf_mf_fail    /* bit63 set -> -errno */
	str  x0, [x22, #8]           /* addr */
	str  x23, [x22, #16]         /* maplen */
	b    .Sf_mf_ret
.Sf_mf_fail:
	mov  x0, #0
.Sf_mf_ret:
	add  sp, sp, #192
	ldp  x29, x30, [sp], #16
	ldp  x23, x24, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size map_file, .-map_file

/* ============================================================================
 * store_map_at(st, height, out[2]) -> const u8 *block payload / NULL
 * ========================================================================== */
store_map_at:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, x29, [sp, #-16]!
	stp  x30, xzr, [sp, #-16]!
	sub  sp, sp, #32             /* meta[3] @sp */
	mov  x19, x0
	mov  x20, x1                 /* height */
	mov  x21, x2                 /* out */
	mov  x0, x19
	mov  x1, x20
	mov  x2, sp
	bl   store_get_at
	cmp  x0, #1
	b.ne .Sf_ma_fail
	ldr  x22, [sp, #0]           /* pos */
	ldr  x9, [sp, #8]            /* size */
	add  x23, x22, #8
	add  x23, x23, x9            /* need_end = pos+8+size */
	mov  x0, x19
	ldr  w1, [sp, #16]           /* file_no */
	mov  x2, x23
	bl   map_file
	cbz  x0, .Sf_ma_fail
	add  x0, x0, x22
	add  x0, x0, #8              /* skip [len][magic] frame header */
	cbz  x21, .Sf_ma_ret
	ldr  x9, [sp, #8]
	str  x9, [x21, #0]           /* size */
	ldr  x9, [sp, #16]
	str  x9, [x21, #8]           /* file_no */
	b    .Sf_ma_ret
.Sf_ma_fail:
	mov  x0, #0
	cbz  x21, .Sf_ma_ret
	str  xzr, [x21, #0]
	str  xzr, [x21, #8]
.Sf_ma_ret:
	add  sp, sp, #32
	ldp  x30, xzr, [sp], #16
	ldp  x23, x29, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_map_at, .-store_map_at

/* ============================================================================
 * store_map_advise(st, height, nblocks) -- madvise WILLNEED (best-effort).
 * ========================================================================== */
store_map_advise:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #32             /* out[2] @sp */
	mov  x19, x0
	mov  x20, x1
	mov  x21, x2
	cbz  x21, .Sf_mv_ret
	mov  x0, x19
	mov  x1, x20
	mov  x2, sp
	bl   store_map_at
	cbz  x0, .Sf_mv_ret
	mov  x22, x0                 /* base ptr */
	ldr  x9, [sp, #0]            /* size(first) */
	mul  x9, x9, x21             /* span ~ nblocks*size */
	mov  x8, #233                /* madvise */
	mov  x0, x22
	mov  x1, x9
	mov  x2, #3                  /* MADV_WILLNEED */
	svc  #0
.Sf_mv_ret:
	add  sp, sp, #32
	ldp  x29, x30, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_map_advise, .-store_map_advise

/* ============================================================================
 * store_prune_safe(st, prune_height) -> store_prune's result
 *   Invalidate both caches (unlink keeps deleted inodes alive via cached
 *   fds/mappings) before pruning.
 * ========================================================================== */
store_prune_safe:
	stp  x19, x20, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	mov  x19, x0
	mov  x20, x1
	mov  x0, x19
	bl   store_rd_close
	mov  x0, x19
	bl   store_map_close
	mov  x0, x19
	mov  x1, x20
	bl   store_prune
	ldp  x29, x30, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_prune_safe, .-store_prune_safe

	.section .note.GNU-stack,"",%progbits
