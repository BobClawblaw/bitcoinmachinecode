/* ============================================================================
 * bitcoin_store.S -- AArch64 (ARMv8-A) port of asm/bitcoin_store.asm
 *
 * Persistent multi-file block storage + positional block index (Bitcoin-style
 * blk%05u.dat + index.dat), raw file syscalls. AAPCS64 (SysV x64 -> AArch64):
 *   int store_init        (void *st)
 *   int store_reload      (void *st)
 *   int store_append      (void *st, const u8 hash[32], const void *raw, u64 len)
 *   int store_get_at      (void *st, u64 height, u64 out_meta[3])
 *   int store_get_tip     (void *st, u64 out_meta[3])
 *   int store_get_file_fd (void *st, u32 file_no)
 *   void fmt_blkname      (char *buf, u32 file_no)   // "blk%05u.dat"
 *
 * State st layout (mirrors x86): +0 cur_blk_fd(8) +8 idx_fd(8)
 *   +16 idx_len(8) +24 tip_height(4) +28 cur_file_no(4) +32 cur_file_pos(4)
 *   +36 magic(4) +40 pad(4) +44 pad(4) +48 prune_height(4).
 *
 * ARM64 syscalls: openat=56 close=57 lseek=62 read=63 write=64 pread64=67.
 * open() does not exist on ARM64 -> openat(AT_FDCWD=-100, path, flags, mode).
 * lseek offset is 64-bit (no separate _llseek needed). pread64 offset in x3.
 * ========================================================================== */

	.text

/* load a symbol's address into a register (adrp + :lo12:, range-safe) */
	.macro LAddr rd, sym
	adrp \rd, \sym
	add  \rd, \rd, :lo12:\sym
	.endm

/* ============================================================================
 * fmt_blkname(buf, file_no)   -- writes "blk%05u.dat", 12 bytes incl NUL
 * Leaf -> caller-saved only, no prologue.
 * ========================================================================== */
	.global fmt_blkname
	.type fmt_blkname, %function
fmt_blkname:
	mov  x9, x0             /* buf */
	mov  w10, #'b'
	strb w10, [x9], #1
	mov  w10, #'l'
	strb w10, [x9], #1
	mov  w10, #'k'
	strb w10, [x9], #1
	mov  w11, w1            /* value */
	mov  w12, #10000
	udiv w13, w11, w12
	msub w11, w13, w12, w11
	add  w13, w13, #48
	strb w13, [x9], #1
	mov  w12, #1000
	udiv w13, w11, w12
	msub w11, w13, w12, w11
	add  w13, w13, #48
	strb w13, [x9], #1
	mov  w12, #100
	udiv w13, w11, w12
	msub w11, w13, w12, w11
	add  w13, w13, #48
	strb w13, [x9], #1
	mov  w12, #10
	udiv w13, w11, w12
	msub w11, w13, w12, w11
	add  w13, w13, #48
	strb w13, [x9], #1
	add  w13, w11, #48
	strb w13, [x9], #1
	/* ".dat" LE dword = 0x7461642E then NUL */
	movz w13, #0x642E
	movk w13, #0x7461, lsl #16
	str  w13, [x9]
	mov  w13, #0
	strb w13, [x9, #4]
	ret
	.size fmt_blkname, .-fmt_blkname

/* ============================================================================
 * open_file(st, file_no) -> fd (int) ; also sets st->cur_blk_fd
 * Local helper. Non-leaf (calls fmt_blkname).
 * ========================================================================== */
open_file:
	stp x19, x20, [sp, #-16]!
	stp x29, x30, [sp, #-16]!
	sub sp, sp, #32         /* name[16] at sp */
	mov x19, x0             /* st */
	mov w20, w1             /* file_no */
	/* close previously-open block file (avoids fd leak) */
	ldr x10, [x19, #0]
	cmn x10, #1
	b.eq .Lo_noclose
	mov x8, #57
	mov x0, x10
	svc #0
.Lo_noclose:
	/* fmt name at sp */
	mov x0, sp
	mov w1, w20
	bl  fmt_blkname
	/* openat(AT_FDCWD, name, O_RDWR|O_CREAT=0x42, 0644) */
	mov x8, #56
	mov x0, #-100
	mov x1, sp
	mov x2, #0x42
	mov x3, #420
	svc #0
	cmp x0, #0
	b.lt .Lo_ret
	str x0, [x19, #0]       /* cur_blk_fd = fd */
.Lo_ret:
	add sp, sp, #32
	ldp x29, x30, [sp], #16
	ldp x19, x20, [sp], #16
	ret

/* ============================================================================
 * store_get_file_fd(st, file_no) -> fd  (tail-jumps open_file)
 * ========================================================================== */
	.global store_get_file_fd
	.type store_get_file_fd, %function
store_get_file_fd:
	b   open_file
	.size store_get_file_fd, .-store_get_file_fd

/* ============================================================================
 * store_init(st) -> 1 ok / -1 err
 * Leaf (syscalls only).
 * ========================================================================== */
	.global store_init
	.type store_init, %function
store_init:
	mov  x9, x0             /* st */
	/* openat(idxname, O_RDWR|O_CREAT, 0644) */
	mov  x8, #56
	mov  x0, #-100
	LAddr x1, idxname
	mov  x2, #0x42
	mov  x3, #420
	svc  #0
	cmp  x0, #0
	b.lt .Lsi_fail
	mov  x10, x0            /* idx_fd */
	str  x10, [x9, #8]      /* idx_fd */
	mov  x11, #-1
	str  x11, [x9, #0]      /* cur_blk_fd = -1 */
	mov  x11, #0
	str  x11, [x9, #16]     /* idx_len = 0 */
	mov  w11, #-1
	str  w11, [x9, #24]     /* tip_height = -1 */
	mov  w11, #0
	str  w11, [x9, #28]     /* cur_file_no = 0 */
	str  w11, [x9, #32]     /* cur_file_pos = 0 */
	movz w11, #0xbef9
	movk w11, #0xd9b4, lsl #16
	str  w11, [x9, #36]     /* magic = 0xd9b4bef9 */
	mov  w11, #0
	str  w11, [x9, #40]
	str  w11, [x9, #48]     /* prune_height = 0 */
	/* load persisted prune height from prune.dat, if present */
	mov  x8, #56
	mov  x0, #-100
	LAddr x1, prunename
	mov  x2, #0             /* O_RDONLY */
	mov  x3, #420
	svc  #0
	mov  x10, x0
	cmp  x0, #0
	b.lt .Lsi_noprune
	sub  sp, sp, #16
	mov  x8, #63            /* read(fd, sp, 4) */
	mov  x0, x10
	mov  x1, sp
	mov  x2, #4
	svc  #0
	cmp  x0, #4
	b.ne .Lsi_prcls
	ldr  w11, [sp]
	str  w11, [x9, #48]     /* prune_height */
.Lsi_prcls:
	add  sp, sp, #16
	mov  x8, #57            /* close */
	mov  x0, x10
	svc  #0
.Lsi_noprune:
	mov  w0, #1
	ret
.Lsi_fail:
	mov  w0, #-1
	ret
	.size store_init, .-store_init

/* ============================================================================
 * store_reload(st) -> 1 ok / -1 err
 * Re-sync idx_len/tip + reopen the last block file. Non-leaf (open_file).
 * ========================================================================== */
	.global store_reload
	.type store_reload, %function
store_reload:
	stp x19, x20, [sp, #-16]!
	stp x29, x30, [sp, #-16]!
	sub sp, sp, #64         /* record[48] at sp */
	mov x19, x0             /* st */
	/* lseek(idx_fd, 0, SEEK_END) -> size */
	mov x8, #62
	ldr x0, [x19, #8]
	mov x1, #0
	mov x2, #2
	svc #0
	mov x20, x0             /* size */
	cmp x0, #0
	b.lt .Lrl_err
	str x0, [x19, #16]      /* idx_len = size */
	cmp x0, #48
	b.lo .Lrl_empty
	/* tip = size/48 - 1 */
	mov x1, #48
	udiv x9, x20, x1
	sub  x9, x9, #1         /* tip height */
	/* pread64(idx_fd, rec, 48, size-48) */
	sub  x11, x20, #48
	mov  x8, #67
	ldr  x0, [x19, #8]
	mov  x1, sp
	mov  x2, #48
	mov  x3, x11
	svc  #0
	cmp  x0, #48
	b.ne .Lrl_err
	ldr  w10, [sp, #32]
	str  w10, [x19, #28]    /* cur_file_no = rec[32] */
	ldr  x10, [sp, #36]     /* data_pos */
	add  x10, x10, #8
	ldr  w11, [sp, #44]     /* data_size */
	add  x10, x10, x11
	str  w10, [x19, #32]    /* cur_file_pos = pos+8+size */
	str  w9,  [x19, #24]    /* tip_height */
	mov  x0, x19
	ldr  w1, [x19, #28]
	bl   open_file
	cmp  x0, #0
	b.lt .Lrl_err
	mov  w0, #1
	b    .Lrl_done
.Lrl_empty:
	mov  w9, #-1
	str  w9, [x19, #24]
	mov  w9, #0
	str  w9, [x19, #28]
	str  w9, [x19, #32]
	mov  x9, #-1
	str  x9, [x19, #0]
	mov  w0, #1
	b    .Lrl_done
.Lrl_err:
	mov  w0, #-1
.Lrl_done:
	add sp, sp, #64
	ldp x29, x30, [sp], #16
	ldp x19, x20, [sp], #16
	ret
	.size store_reload, .-store_reload

/* ============================================================================
 * store_get_at(st, height, out_meta[3]) -> 1 ok / -2 oor / -3 pruned / -1 err
 * Leaf (one pread64) -> caller-saved only.
 *   out_meta[0]=data_pos [1]=data_size [2]=file_no
 * ========================================================================== */
	.global store_get_at
	.type store_get_at, %function
store_get_at:
	sub  sp, sp, #64         /* record[48] at sp */
	mov  x9, x0              /* st */
	mov  x10, x1             /* height */
	mov  x11, x2             /* out_meta */
	ldr  x12, [x9, #16]
	mov  x13, #48
	udiv x12, x12, x13
	sub  x12, x12, #1        /* tip */
	cmn  x12, #1
	b.eq .Lga_oor            /* empty */
	cmp  x10, x12
	b.hi .Lga_oor
	ldr  w13, [x9, #48]      /* prune_height */
	cmp  w10, w13
	b.lt .Lga_pruned
	mov  x14, x10
	mov  x15, #48
	mul  x14, x14, x15
	mov  x8, #67             /* pread64 */
	ldr  x0, [x9, #8]
	mov  x1, sp
	mov  x2, #48
	mov  x3, x14
	svc  #0
	cmp  x0, #48
	b.ne .Lga_err
	ldr  w15, [sp, #44]
	mov  w16, #-1            /* 0xFFFFFFFF sparse-prune marker */
	cmp  w15, w16
	b.eq .Lga_pruned
	ldr  x0, [sp, #36]       /* data_pos */
	str  x0, [x11, #0]
	ldr  w0, [sp, #44]       /* data_size (zero-extended) */
	str  x0, [x11, #8]
	ldr  w0, [sp, #32]       /* file_no (zero-extended) */
	str  x0, [x11, #16]
	mov  w0, #1
	b    .Lga_ret
.Lga_oor:
	mov  w0, #-2
	b    .Lga_ret
.Lga_pruned:
	mov  w0, #-3
	b    .Lga_ret
.Lga_err:
	mov  w0, #-1
.Lga_ret:
	add  sp, sp, #64
	ret
	.size store_get_at, .-store_get_at

/* ============================================================================
 * store_get_tip(st, out_meta[3]) -> 1 ok / -1 empty
 * Non-leaf (calls store_get_at).
 * ========================================================================== */
	.global store_get_tip
	.type store_get_tip, %function
store_get_tip:
	stp x19, x30, [sp, #-16]!
	mov  x19, x1             /* out_meta */
	ldr  x9, [x0, #16]
	mov  x10, #48
	udiv x9, x9, x10
	sub  x9, x9, #1
	cmn  x9, #1
	b.eq .Lgt_empty
	mov  x1, x9              /* height */
	mov  x2, x19             /* out_meta */
	bl   store_get_at
	cmp  x0, #1
	b.ne .Lgt_err
	mov  w0, #1
	b    .Lgt_ret
.Lgt_empty:
	mov  w0, #-1
	b    .Lgt_ret
.Lgt_err:
	mov  w0, #-1
.Lgt_ret:
	ldp x19, x30, [sp], #16
	ret
	.size store_get_tip, .-store_get_tip

/* ============================================================================
 * store_append(st, hash[32], raw, len) -> new height or -1 err
 * Writes frame [u32 len][u32 magic] + raw into the current blk file, appends a
 * 48-byte index record. Non-leaf (open_file).
 *   x19=st x20=hash x21=raw x22=len
 * ========================================================================== */
	.global store_append
	.type store_append, %function
store_append:
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x29, x30, [sp, #-16]!
	sub sp, sp, #128        /* hdr[8] @sp+0  rec[48] @sp+16  pos@64  fileno@72 */
	mov x19, x0             /* st */
	mov x20, x1             /* hash */
	mov x21, x2             /* raw */
	mov x22, x3             /* len */
	/* if no blk file open, open cur_file_no */
	ldr x9, [x19, #0]
	cmp x9, #0
	b.ge .Lap_have_fd
	mov x0, x19
	ldr w1, [x19, #28]
	bl  open_file
	cmp x0, #0
	b.lt .Lap_err
.Lap_have_fd:
	/* rollover: cur_file_pos + 8 + len > MAX_FILE (0x08000000) */
	ldr  w9, [x19, #32]
	uxtw x9, w9
	add  x9, x9, #8
	add  x9, x9, x22
	movz x10, #0x0800, lsl #16   /* MAX_FILE = 0x08000000 */
	cmp  x9, x10
	b.ls .Lap_no_roll
	/* close current, file_no++, open new file, pos = 0 */
	mov  x8, #57
	ldr  x0, [x19, #0]
	svc  #0
	mov  x9, #-1
	str  x9, [x19, #0]
	ldr  w9, [x19, #28]
	add  w9, w9, #1
	str  w9, [x19, #28]
	mov  w9, #0
	str  w9, [x19, #32]
	mov  x0, x19
	ldr  w1, [x19, #28]
	bl   open_file
	cmp  x0, #0
	b.lt .Lap_err
.Lap_no_roll:
	/* save file_no / pos before appending */
	ldr  w9, [x19, #28]
	str  w9, [sp, #72]
	ldr  w9, [x19, #32]
	uxtw x9, w9
	str  x9, [sp, #64]
	/* frame header at sp: [u32 len][u32 magic] */
	str  w22, [sp, #0]
	ldr  w9, [x19, #36]
	str  w9, [sp, #4]
	/* lseek(cur_blk_fd, cur_file_pos, 0) */
	mov  x8, #62
	ldr  x0, [x19, #0]
	ldr  w10, [x19, #32]
	uxtw x10, w10
	mov  x1, x10
	mov  x2, #0
	svc  #0
	cmp  x0, #0
	b.lt .Lap_err
	/* write 8-byte header */
	mov  x8, #64
	ldr  x0, [x19, #0]
	mov  x1, sp
	mov  x2, #8
	svc  #0
	cmp  x0, #8
	b.ne .Lap_err
	/* write raw block (x22 bytes) */
	mov  x8, #64
	ldr  x0, [x19, #0]
	mov  x1, x21
	mov  x2, x22
	svc  #0
	cmp  x0, x22
	b.ne .Lap_err
	/* cur_file_pos += 8 + len */
	ldr  w9, [x19, #32]
	add  w9, w9, #8
	add  w9, w9, w22
	str  w9, [x19, #32]
	/* new height = idx_len / 48 */
	ldr  x9, [x19, #16]
	mov  x10, #48
	udiv x11, x9, x10       /* new height (survives: no nested calls below) */
	/* build idx record at sp+16: hash(32) | file_no(4) | pos(8) | size(4) */
	mov  x12, #32
	add  x13, sp, #16
	mov  x14, x20           /* src = hash */
.Lap_cp:
	cbz  x12, .Lap_cpd
	ldrb w15, [x14], #1
	strb w15, [x13], #1
	sub  x12, x12, #1
	b    .Lap_cp
.Lap_cpd:
	ldr  w9, [sp, #72]
	str  w9, [sp, #48]      /* rec+32 file_no */
	ldr  x9, [sp, #64]
	str  x9, [sp, #52]      /* rec+36 pos */
	str  w22, [sp, #60]     /* rec+44 size */
	/* append at idx_len: lseek(idx_fd, idx_len, 0) then write 48 */
	mov  x8, #62
	ldr  x0, [x19, #8]
	ldr  x1, [x19, #16]
	mov  x2, #0
	svc  #0
	mov  x8, #64
	ldr  x0, [x19, #8]
	add  x1, sp, #16
	mov  x2, #48
	svc  #0
	cmp  x0, #48
	b.ne .Lap_err
	ldr  x9, [x19, #16]
	add  x9, x9, #48
	str  x9, [x19, #16]     /* idx_len += 48 */
	str  w11, [x19, #24]    /* tip_height = new height */
	mov  w0, w11
	b    .Lap_ret
.Lap_err:
	mov  w0, #-1
.Lap_ret:
	add sp, sp, #128
	ldp x29, x30, [sp], #16
	ldp x21, x22, [sp], #16
	ldp x19, x20, [sp], #16
	ret
	.size store_append, .-store_append



/* ==========================================================================
 * store_append_shared(st,height,hash[32],raw,len)       (x0..x4)
 * store_append_shared_nolock(st,height,hash[32],raw,len)
 *   CONCURRENT-SAFE append: writes frame [u32 len][u32 magic]+raw at the TRUE
 *   current end of the blk file (lseek SEEK_END under flock st+40), and the
 *   48-byte index record at height*48 on idx_fd. Disjoint heights land each
 *   record at its own slot; payloads append at a consistent sequential offset.
 *   shared (dolock=1) takes/releases the st+40 append flock for this call;
 *   nolocked (dolock=0) skips it (caller already holds the lock). Returns
 *   height on success, -1 on error. AArch64 flock = 32 (LOCK_EX=2, LOCK_UN=8).
 * ========================================================================== */
    .global store_append_shared
    .type store_append_shared, %function
store_append_shared:
    mov  x5, #1
    b    store_append_shared_x
    .size store_append_shared, .-store_append_shared

    .global store_append_shared_nolock
    .type store_append_shared_nolock, %function
store_append_shared_nolock:
    mov  x5, #0
    b    store_append_shared_x
    .size store_append_shared_nolock, .-store_append_shared_nolock

    .type store_append_shared_x, %function
store_append_shared_x:
    stp  x19, x20, [sp, #-16]!
    stp  x21, x22, [sp, #-16]!
    stp  x29, x30, [sp, #-16]!
    sub  sp, sp, #96          /* len@0 dolock@8 filelen@16 datapos@24 fileno@32 hdr@40 rec@48 */
    mov  x19, x0             /* st */
    mov  x20, x1             /* height */
    mov  x21, x2             /* hash */
    mov  x22, x3             /* raw */
    str  x4, [sp, #0]        /* len */
    str  x5, [sp, #8]        /* dolock */
    /* acquire flock if dolock && st+40 >= 0 */
    ldr  x9, [sp, #8]
    cbz  x9, .Sx_hlock
    ldr  x9, [x19, #40]
    tbz  x9, #63, .Sx_flk
    b    .Sx_hlock
.Sx_flk:
    mov  x0, x9
    mov  x8, #32
    mov  x1, #2              /* LOCK_EX */
    svc  #0
.Sx_hlock:
    /* ensure idx_fd (st+8) open */
    ldr  x9, [x19, #8]
    tbz  x9, #63, .Sx_hidxok
    mov  x0, x19
    bl   open_idx_close
.Sx_hidxok:
    /* ensure blk_fd (st+0) open */
    ldr  x9, [x19, #0]
    tbz  x9, #63, .Sx_hblkok
    mov  x0, x19
    ldr  w1, [x19, #28]
    bl   open_file
    cmp  x0, #0
    b.lt .Sx_err
.Sx_hblkok:
.Sx_repos:
    /* lseek(blk_fd, 0, SEEK_END=2) -> true file length */
    mov  x8, #62
    ldr  x0, [x19, #0]
    mov  x1, #0
    mov  x2, #2
    svc  #0
    tbnz x0, #63, .Sx_err
    str  x0, [sp, #16]       /* true_file_len */
.Sx_rollck:
    /* if true_len + 8 + len > MAX_FILE -> roll */
    ldr  x10, [sp, #16]
    add  x10, x10, #8
    ldr  x11, [sp, #0]
    add  x10, x10, x11
    movz x12, #0x0800, lsl#16 /* MAX_FILE = 0x08000000 */
    cmp  x10, x12
    b.ls .Sx_nroll
    mov  x8, #57
    ldr  x0, [x19, #0]
    svc  #0
    mov  x9, #-1
    str  x9, [x19, #0]
    ldr  w9, [x19, #28]
    add  w9, w9, #1
    str  w9, [x19, #28]
    mov  x0, x19
    ldr  w1, [x19, #28]
    bl   open_file
    cmp  x0, #0
    b.lt .Sx_err
    b    .Sx_repos
.Sx_nroll:
    ldr  x9, [sp, #16]
    str  x9, [sp, #24]       /* data_pos */
    ldr  w9, [x19, #28]
    str  w9, [sp, #32]       /* file_no */
    /* frame header [u32 len][u32 magic] at sp+40 */
    ldr  w9, [sp, #0]
    str  w9, [sp, #40]
    ldr  w9, [x19, #36]
    str  w9, [sp, #44]
    /* lseek(blk_fd, data_pos, 0) */
    mov  x8, #62
    ldr  x0, [x19, #0]
    ldr  x1, [sp, #24]
    mov  x2, #0
    svc  #0
    tbnz x0, #63, .Sx_err
    /* write frame (8) */
    mov  x8, #64
    ldr  x0, [x19, #0]
    add  x1, sp, #40
    mov  x2, #8
    svc  #0
    cmp  x0, #8
    b.ne .Sx_err
    /* write raw */
    mov  x8, #64
    ldr  x0, [x19, #0]
    mov  x1, x22
    ldr  x2, [sp, #0]
    svc  #0
    ldr  x9, [sp, #0]
    cmp  x0, x9
    b.ne .Sx_err
    /* build index record [48] at sp+48: hash32 + file_no u32 + pos u64 + size u32 */
    add  x0, sp, #48
    mov  x1, x21
    mov  x2, #32
    bl   __stcopy
    ldr  w9, [sp, #32]
    str  w9, [sp, #80]       /* rec+32 file_no */
    ldr  x9, [sp, #24]
    str  x9, [sp, #84]       /* rec+36 pos */
    ldr  w9, [sp, #0]
    str  w9, [sp, #92]       /* rec+44 size */
    /* lseek(idx_fd, height*48, 0) */
    mov  x8, #62
    ldr  x0, [x19, #8]
    mov  x9, x20
    mov  x10, #48
    mul  x9, x9, x10
    mov  x1, x9
    mov  x2, #0
    svc  #0
    tbnz x0, #63, .Sx_err
    /* write rec (48) */
    mov  x8, #64
    ldr  x0, [x19, #8]
    add  x1, sp, #48
    mov  x2, #48
    svc  #0
    cmp  x0, #48
    b.ne .Sx_err
.Sx_hlockdone:
    /* release if dolock */
    ldr  x9, [sp, #8]
    cbz  x9, .Sx_ret
    ldr  x9, [x19, #40]
    tbz  x9, #63, .Sx_unl
    b    .Sx_ret
.Sx_unl:
    mov  x0, x9
    mov  x8, #32
    mov  x1, #8              /* LOCK_UN */
    svc  #0
    b    .Sx_ret
.Sx_err:
    /* release if dolock, return -1 */
    ldr  x9, [sp, #8]
    cbz  x9, .Sx_err2
    ldr  x9, [x19, #40]
    tbz  x9, #63, .Sx_err_u
    b    .Sx_err2
.Sx_err_u:
    mov  x0, x9
    mov  x8, #32
    mov  x1, #8
    svc  #0
.Sx_err2:
    mov  x0, #-1
    b    .Sx_done
.Sx_ret:
    mov  x0, x20              /* height */
.Sx_done:
    add  sp, sp, #96
    ldp  x29, x30, [sp], #16
    ldp  x21, x22, [sp], #16
    ldp  x19, x20, [sp], #16
    ret
    .size store_append_shared_x, .-store_append_shared_x

/* ---------- __stcopy(dst=x0, src=x1, n=x2) ---------- */
    .type __stcopy, %function
__stcopy:
    mov  x3, #0
.Lstc:
    cmp  x3, x2
    b.hs .Lstcd
    ldrb w4, [x1, x3]
    strb w4, [x0, x3]
    add  x3, x3, #1
    b    .Lstc
.Lstcd:
    ret
    .size __stcopy, .-__stcopy

/* ---------- open_idx_close(st=x0): reopen index.dat -> st+8 (non-leaf) ---------- */
    .type open_idx_close, %function
open_idx_close:
    stp  x19, x30, [sp, #-16]!
    mov  x19, x0
    mov  x0, #-100            /* AT_FDCWD */
    LAddr x1, idxname
    mov  x2, #0x42            /* O_RDWR|O_CREAT */
    mov  x3, #0644
    mov  x8, #56              /* openat */
    svc  #0
    tbnz x0, #63, .Sx_ocd
    str  x0, [x19, #8]        /* idx_fd */
.Sx_ocd:
    ldp  x19, x30, [sp], #16
    ret
    .size open_idx_close, .-open_idx_close


/* ============================================================================
 * store_set_prune(st, prune_height) -> 1 / -1
 *   Persist the prune gate (no physical deletion) to prune.dat (4-byte LE).
 * ========================================================================== */
	.global store_set_prune
	.type store_set_prune, %function
store_set_prune:
	stp  x19, x20, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #16          /* 4-byte value @sp */
	mov  x19, x0              /* st */
	str  w1, [x19, #48]       /* st->prune_height = height */
	/* openat(AT_FDCWD, prunename, O_RDWR|O_CREAT|O_TRUNC=0x242, 0644) */
	mov  x8, #56
	mov  x0, #-100
	LAddr x1, prunename
	mov  x2, #0x242
	mov  x3, #420
	svc  #0
	tbnz x0, #63, .Ssp_fail
	mov  x20, x0              /* fd */
	/* write(fd, &val, 4) */
	ldr  w9, [x19, #48]
	str  w9, [sp]
	mov  x0, x20
	mov  x1, sp
	mov  x2, #4
	mov  x8, #64
	svc  #0
	cmp  x0, #4
	b.ne .Ssp_wfail
	mov  x8, #57
	mov  x0, x20
	svc  #0
	mov  w0, #1
	b    .Ssp_ok
.Ssp_wfail:
	mov  x8, #57
	mov  x0, x20
	svc  #0
.Ssp_fail:
	mov  x0, #-1
.Ssp_ok:
	add  sp, sp, #16
	ldp  x29, x30, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_set_prune, .-store_set_prune

/* ---------- unlink_blk(st, file_no) -- remove blk%05u.dat (ignore ENOENT) ---------- */
	.type unlink_blk, %function
unlink_blk:
	stp  x29, x30, [sp, #-16]!
	sub  sp, sp, #32          /* name[16] @sp */
	mov  w9, w1               /* file_no (survives bl fmt_blkname) */
	mov  x0, sp
	mov  w1, w9
	bl   fmt_blkname
	/* unlinkat(AT_FDCWD, buf, 0) -- no plain unlink on arm64 */
	mov  x8, #35
	mov  x0, #-100
	mov  x1, sp
	mov  x2, #0
	svc  #0                   /* rc ignored (ENOENT ok) */
	add  sp, sp, #32
	ldp  x29, x30, [sp], #16
	ret
	.size unlink_blk, .-unlink_blk

/* ---------- read_idx_rec(st, height, buf) -> file_no / -1 ; fills buf[48] ---------- */
	.type read_idx_rec, %function
read_idx_rec:
	stp  x19, x20, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	mov  x19, x0              /* st */
	mov  x20, x2              /* buf (callee-saved across syscalls) */
	mov  x10, x1
	mov  x11, #48
	mul  x10, x10, x11        /* height*48 */
	ldr  x0, [x19, #8]        /* idx_fd */
	mov  x1, x10
	mov  x2, #0
	mov  x8, #62              /* lseek */
	svc  #0
	tbnz x0, #63, .Srr_er
	ldr  x0, [x19, #8]
	mov  x1, x20
	mov  x2, #48
	mov  x8, #63              /* read */
	svc  #0
	cmp  x0, #48
	b.ne .Srr_er
	ldr  w0, [x20, #32]       /* file_no */
	b    .Srr_ok
.Srr_er:
	mov  x0, #-1
.Srr_ok:
	ldp  x29, x30, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size read_idx_rec, .-read_idx_rec

/* ---------- write_idx_rec(st, height, buf) -> 1 / -1 ; writes buf[48] ---------- */
	.type write_idx_rec, %function
write_idx_rec:
	stp  x19, x20, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	mov  x19, x0
	mov  x20, x2
	mov  x10, x1
	mov  x11, #48
	mul  x10, x10, x11
	ldr  x0, [x19, #8]
	mov  x1, x10
	mov  x2, #0
	mov  x8, #62
	svc  #0
	tbnz x0, #63, .Swr_er
	ldr  x0, [x19, #8]
	mov  x1, x20
	mov  x2, #48
	mov  x8, #64              /* write */
	svc  #0
	cmp  x0, #48
	b.ne .Swr_er
	mov  w0, #1
	b    .Swr_ok
.Swr_er:
	mov  x0, #-1
.Swr_ok:
	ldp  x29, x30, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size write_idx_rec, .-write_idx_rec

/* ============================================================================
 * store_prune(st, prune_height) -> 1 / -1
 *   Set + persist the prune gate and PHYSICALLY delete pruned blk files;
 *   compact the boundary file in place (read at old_off, write at new_off,
 *   ftruncate). Mirrors x86 store_prune.
 *   Frame (4 save pairs then sub 0x10080): recA[48]@sp+0x00, recB[48]@sp+0x30,
 *   tip@+0x60 eff@+0x64 first@+0x68 h@+0x6C old_off@+0x70 size@+0x74
 *   remaining@+0x78 chunk@+0x7C, 64KB copy buf@sp+0x80.
 *   Regs: x19=st x20=fd w21=new_off x22=old_ptr x23=new_ptr w24=dl w25=h.
 * ========================================================================== */
	.global store_prune
	.type store_prune, %function
store_prune:
	stp  x19, x20, [sp, #-16]!
	stp  x21, x22, [sp, #-16]!
	stp  x23, xzr, [sp, #-16]!
	stp  x24, x25, [sp, #-16]!
	stp  x29, x30, [sp, #-16]!
	mov  x9, #0x80
	movk x9, #0x1, lsl #16    /* 0x10080 */
	sub  sp, sp, x9
	mov  x19, x0              /* st */
	ldr  w9, [x19, #24]       /* tip */
	cmp  w9, #-1
	b.eq .Spr_empty
	str  w9, [sp, #0x60]      /* tip */
	mov  w10, w1              /* requested prune_height */
	tbz  w10, #31, .Spr_nonneg
	mov  w10, #0
.Spr_nonneg:
	add  w11, w9, #1          /* tip+1 */
	cmp  w10, w11
	b.ls .Spr_clamped
	mov  w10, w11
.Spr_clamped:
	str  w10, [x19, #48]      /* st->prune_height */
	str  w10, [sp, #0x64]     /* eff */
	cbz  w10, .Spr_persist_only
	mov  x0, x19
	mov  w1, w10
	bl   store_set_prune      /* persist gate first */
	/* if eff == tip+1 -> prune ALL files */
	ldr  w9, [sp, #0x60]
	add  w11, w9, #1
	ldr  w10, [sp, #0x64]
	cmp  w10, w11
	b.eq .Spr_prune_all
	/* first_retained_file = file_no of block at height=eff */
	mov  x0, x19
	mov  w1, w10
	add  x2, sp, #0x00        /* recA */
	bl   read_idx_rec
	tbnz x0, #63, .Spr_fail
	str  w0, [sp, #0x68]      /* first_retained_file */
	/* delete files 0 .. first_retained_file-1 */
	mov  w24, #0
.Spr_delfiles:
	ldr  w9, [sp, #0x68]
	cmp  w24, w9
	b.hs .Spr_deldone
	mov  x0, x19
	mov  w1, w24
	bl   unlink_blk
	add  w24, w24, #1
	b    .Spr_delfiles
.Spr_deldone:
	/* compact boundary file (first_retained_file) in place */
	mov  x0, x19
	ldr  w1, [sp, #0x68]
	bl   open_file
	tbnz x0, #63, .Spr_fail
	mov  x20, x0              /* fd */
	mov  w21, #0              /* new_off */
	ldr  w25, [sp, #0x64]     /* h = eff */
.Spr_cmploop:
	ldr  w9, [sp, #0x60]      /* tip */
	cmp  w25, w9
	b.hi .Spr_cmpdone
	mov  x0, x19
	mov  w1, w25
	add  x2, sp, #0x00        /* recA */
	bl   read_idx_rec
	tbnz x0, #63, .Spr_fail
	ldr  w9, [sp, #0x68]
	cmp  w0, w9               /* rec.file_no == first_retained? */
	b.ne .Spr_cmpdone
	ldr  w9, [sp, #0x24]      /* recA+36 pos */
	str  w9, [sp, #0x70]      /* old_off */
	ldr  w9, [sp, #0x2C]      /* recA+44 size */
	str  w9, [sp, #0x74]      /* size */
	ldr  w9, [sp, #0x24]
	uxtw x22, w9              /* old_ptr */
	uxtw x23, w21             /* new_ptr */
	ldr  w9, [sp, #0x74]
	add  w9, w9, #8
	str  w9, [sp, #0x78]      /* remaining = size+8 */
.Spr_cpychunk:
	ldr  w9, [sp, #0x78]
	cbz  w9, .Spr_cpydone
	movz w10, #0x1, lsl #16   /* 0x10000 */
	cmp  w9, w10
	b.hi .Spr_big             /* remaining > 0x10000 -> chunk=0x10000 */
	mov  w10, w9              /* else chunk = remaining */
.Spr_big:
	str  w10, [sp, #0x7C]     /* chunk */
	/* lseek(fd, old_ptr, 0); read(fd, buf, chunk) */
	mov  x0, x20
	mov  x1, x22
	mov  x2, #0
	mov  x8, #62
	svc  #0
	tbnz x0, #63, .Spr_fail
	mov  x0, x20
	add  x1, sp, #0x80
	ldr  w2, [sp, #0x7C]
	mov  x8, #63
	svc  #0
	ldr  w9, [sp, #0x7C]
	cmp  x0, x9
	b.ne .Spr_fail
	/* lseek(fd, new_ptr, 0); write(fd, buf, chunk) */
	mov  x0, x20
	mov  x1, x23
	mov  x2, #0
	mov  x8, #62
	svc  #0
	tbnz x0, #63, .Spr_fail
	mov  x0, x20
	add  x1, sp, #0x80
	ldr  w2, [sp, #0x7C]
	mov  x8, #64
	svc  #0
	ldr  w9, [sp, #0x7C]
	cmp  x0, x9
	b.ne .Spr_fail
	/* advance pointers / remaining */
	ldr  w9, [sp, #0x7C]
	uxtw x10, w9
	add  x22, x22, x10
	add  x23, x23, x10
	ldr  w9, [sp, #0x78]      /* remaining */
	sub  w9, w9, w10
	str  w9, [sp, #0x78]
	b    .Spr_cpychunk
.Spr_cpydone:
	/* copy recA -> recB (48), set recB.data_pos=new_off, write back */
	add  x9, sp, #0x00
	add  x10, sp, #0x30
	add  x11, x9, #48
.Spr_cpy48:
	cmp  x9, x11
	b.hs .Spr_cpy48d
	ldr  w13, [x9], #4
	str  w13, [x10], #4
	b    .Spr_cpy48
.Spr_cpy48d:
	str  w21, [sp, #0x30+36]  /* recB+36 data_pos = new_off */
	mov  x0, x19
	mov  w1, w25
	add  x2, sp, #0x30        /* recB */
	bl   write_idx_rec
	tbnz x0, #63, .Spr_fail
	ldr  w9, [sp, #0x74]      /* size */
	add  w9, w9, #8
	add  w21, w21, w9         /* new_off += size+8 */
	add  w25, w25, #1         /* h++ */
	b    .Spr_cmploop
.Spr_cmpdone:
	/* ftruncate(fd, new_off) */
	mov  x0, x20
	uxtw x1, w21
	mov  x8, #46              /* ftruncate */
	svc  #0
	tbnz x0, #63, .Spr_fail
	mov  w0, #1
	b    .Spr_done
.Spr_prune_all:
	mov  w24, #0
.Spr_pall:
	ldr  w9, [x19, #28]       /* cur_file_no */
	cmp  w24, w9
	b.hi .Spr_ok_ret
	mov  x0, x19
	mov  w1, w24
	bl   unlink_blk
	add  w24, w24, #1
	b    .Spr_pall
.Spr_ok_ret:
	mov  w0, #1
	b    .Spr_done
.Spr_persist_only:
	mov  x0, x19
	mov  w1, #0
	bl   store_set_prune
	mov  w0, #1
	b    .Spr_done
.Spr_empty:
	str  wzr, [x19, #48]
	mov  x0, x19
	mov  w1, #0
	bl   store_set_prune
	mov  w0, #1
	b    .Spr_done
.Spr_fail:
	mov  x0, #-1
.Spr_done:
	mov  x9, #0x80
	movk x9, #0x1, lsl #16    /* 0x10080 */
	add  sp, sp, x9
	ldp  x29, x30, [sp], #16
	ldp  x24, x25, [sp], #16
	ldp  x23, xzr, [sp], #16
	ldp  x21, x22, [sp], #16
	ldp  x19, x20, [sp], #16
	ret
	.size store_prune, .-store_prune

	.section .rodata
idxname:   .asciz "index.dat"
prunename: .asciz "prune.dat"

	.section .note.GNU-stack,"",%progbits
