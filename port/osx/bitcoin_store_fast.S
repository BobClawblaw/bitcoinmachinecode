/* ============================================================================
 * bitcoin_store_fast.S -- the block store's read-cache layer in AArch64
 * assembly (Apple silicon), the counterpart of asm/bitcoin_store_fast.asm.
 * Replaces store_fast_twin.c on the Mac (2026-09-26); the twin stays in
 * port/osx/test_support as the oracle.
 *
 * Fields it owns in the store struct:
 *   +56  fd-cache magic 0x5244464300000001 ("RDFC" + version)
 *   +64  fd cache: 8 slots {file_no u32, fd i32}, direct-mapped by file_no & 7
 *   +128 map cache: 8 slots of 32 bytes {file_no u32, pad, map u64, size u64}
 *   +384 map-cache magic 0x4D41504300000001 ("MAPC" + version)
 *
 * The map magic was at +120, as on x86 -- INSIDE the fd cache, whose slot 7
 * is +120..127. Opening any file with file_no & 7 == 7 overwrote it, and the
 * next map call then took the cache for uninitialised and cleared its slots
 * WITHOUT munmap: a leaked mapping of up to a whole 128 MiB blk file, and a
 * lost cache, every time (found 2026-09-26 by the differential test of this
 * file, which saw the magic change on an fd-cache fill). +384 is past the map
 * slots; every caller's store state is 4096 bytes. The x86 has the same
 * overlap (MAP_MAGIC at st+120): see worklog/2026-09-25-note-for-x86-2.md.
 *
 *   void  store_rd_init(void* st);          (closes cached fds if initialised)
 *   void  store_rd_close(void* st);
 *   long  store_rd_fd(void* st, u32 file_no);                  fd / -1
 *   long  store_read_meta(void* st, u64 height, u64 meta[3], u8* buf, u64 cap);
 *   long  store_read_at(void* st, u64 height, void* buf, u64 cap);
 *                    bytes / store_get_at's -1..-3 / -4 too big / -1 io
 *   void  store_rd_advise(void* st, u64 height, u64 nblocks);
 *   void  store_map_random(long on);
 *   void  store_map_init(void* st);  void store_map_close(void* st);
 *   const u8* store_map_at(void* st, u64 height, u64 out[2]);  {size, file}
 *
 * meta = {data_pos, data_size, file_no}; a block's bytes start 8 past
 * data_pos (after the [magic][len] record header). Files are "blk%05u.dat"
 * in the cwd, formatted into 16 bytes as x86's fmt_blkname (the twin's
 * 13-byte snprintf truncated a file number past 99999 to "blk100001.da").
 * An evicted fd-cache slot is emptied before the new open, as x86 does: the
 * twin left the closed fd in the slot when that open failed, and once the
 * kernel reused the number, a read of the old file went to whatever file
 * now had it -- another block file's bytes (found 2026-09-26 by the
 * differential test; the twin is corrected with this file). Darwin has no
 * readahead(2): store_rd_advise warms the fd cache for the files a
 * sequential read will touch. store_map_random(1) makes later mappings
 * MADV_RANDOM (the filter backfill reads ~250 bytes per random block).
 * Through libc throughout; snprintf is variadic, so its file number goes on
 * the stack (Darwin arm64).
 * ========================================================================== */
#define FDC_MAGIC_LO  0x0001
#define FDC_OFF       64
#define MAP_OFF       128
#define MAP_MAGIC_OFF 384                 /* past the 8 map slots: see the header */
#define O_CLOEXEC     0x1000000
#define ST_SIZE_OFF   96                  /* struct stat.st_size, Darwin arm64 */
#define STAT_SIZE     144

    .text

/* x9 = FDC magic ; x10 = MAP magic */
.macro FDCMAGIC r
    movz  \r, #0x0001
    movk  \r, #0x4643, lsl #32
    movk  \r, #0x5244, lsl #48
.endm
.macro MAPMAGIC r
    movz  \r, #0x0001
    movk  \r, #0x5043, lsl #32
    movk  \r, #0x4D41, lsl #48
.endm

/* Lblkname(buf=x0, file_no=w1): snprintf(buf, 16, "blk%05u.dat", file_no) */
    .p2align 2
Lblkname:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #16
    mov   w9, w1
    str   x9, [sp]                        /* the variadic argument, at [sp] */
    mov   x1, #16
    adrp  x2, Lblkfmt@PAGE
    add   x2, x2, Lblkfmt@PAGEOFF
    bl    _snprintf
    add   sp, sp, #16
    ldp   x29, x30, [sp], #16
    ret

/* store_rd_init(st=x0) ; st x19, slot x20 */
    .p2align 2
    .globl _store_rd_init
    .globl _store_rd_close
_store_rd_close:
_store_rd_init:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    ldr   x9, [x19, #56]
    FDCMAGIC x10
    cmp   x9, x10
    b.ne  2f
    mov   x20, #0                         /* initialised: close the cached fds */
1:  add   x9, x19, #FDC_OFF
    add   x9, x9, x20, lsl #3
    ldr   w0, [x9, #4]
    tbnz  w0, #31, 11f
    bl    _close
11: add   x20, x20, #1
    cmp   x20, #8
    b.lo  1b
2:  add   x9, x19, #FDC_OFF               /* every slot {0, -1} */
    mov   x10, #0xffffffff00000000
    mov   x11, #8
3:  str   x10, [x9], #8
    subs  x11, x11, #1
    b.ne  3b
    FDCMAGIC x10
    str   x10, [x19, #56]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* store_rd_fd(st=x0, file_no=w1) ; st x19, file_no x20, slot ptr x21 ;
 * frame: name 0 (16) */
    .p2align 2
    .globl _store_rd_fd
_store_rd_fd:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #16
    mov   x19, x0
    mov   w20, w1
    ldr   x9, [x19, #56]
    FDCMAGIC x10
    cmp   x9, x10
    b.eq  1f
    bl    _store_rd_init
1:  and   x9, x20, #7
    add   x21, x19, #FDC_OFF
    add   x21, x21, x9, lsl #3
    ldp   w9, w0, [x21]                   /* cached file_no, fd */
    tbnz  w0, #31, 2f
    cmp   w9, w20
    b.eq  Lrf_hit
    bl    _close                          /* evict ... */
    mov   w9, #-1
    str   w9, [x21, #4]                   /* ... and empty the slot, as x86 */
2:  mov   x0, sp
    mov   w1, w20
    bl    Lblkname
    mov   x0, sp
    mov   w1, #O_CLOEXEC                  /* O_RDONLY | O_CLOEXEC */
    bl    _open
    tbnz  w0, #31, Lrf_no
    stp   w20, w0, [x21]
Lrf_hit:
    sxtw  x0, w0
    b     Lrf_ret
Lrf_no:
    mov   x0, #-1
Lrf_ret:
    add   sp, sp, #16
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* store_read_meta(st=x0, height=x1, meta=x2, buf=x3, cap=x4)
 * st x19, meta x20, buf x21, cap x22 */
    .p2align 2
    .globl _store_read_meta
_store_read_meta:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x2
    mov   x21, x3
    mov   x22, x4
    mov   x2, x20
    bl    _store_get_at
    cmp   x0, #1
    b.ne  Lrm_ret                         /* propagate -1 / -2 / -3 */
    ldr   x9, [x20, #8]
    cmp   x9, x22
    b.hi  3f                              /* too big for the buffer */
    mov   x0, x19
    ldr   w1, [x20, #16]
    bl    _store_rd_fd
    tbnz  x0, #63, 2f
    mov   w0, w0
    mov   x1, x21
    ldr   x2, [x20, #8]
    ldr   x3, [x20]
    add   x3, x3, #8                      /* past the record header */
    bl    _pread
    ldr   x9, [x20, #8]
    cmp   x0, x9
    b.eq  Lrm_ret                         /* the byte count */
2:  mov   x0, #-1
    b     Lrm_ret
3:  mov   x0, #-4
Lrm_ret:
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* store_read_at(st=x0, height=x1, buf=x2, cap=x3) ; frame meta 0 (32) */
    .p2align 2
    .globl _store_read_at
_store_read_at:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #32
    stp   xzr, xzr, [sp]
    str   xzr, [sp, #16]
    mov   x4, x3
    mov   x3, x2
    mov   x2, sp
    bl    _store_read_meta
    add   sp, sp, #32
    ldp   x29, x30, [sp], #16
    ret

/* store_rd_advise(st=x0, height=x1, nblocks=x2)
 * st x19, file x20, last file x21 ; frame: first meta 0, last meta 32 */
    .p2align 2
    .globl _store_rd_advise
_store_rd_advise:
    cbz   x2, 9f
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #64
    mov   x19, x0
    add   x22, x1, x2
    sub   x22, x22, #1                    /* the last height */
    mov   x2, sp
    bl    _store_get_at
    cmp   x0, #1
    b.ne  8f
    mov   x0, x19
    mov   x1, x22
    add   x2, sp, #32
    bl    _store_get_at
    cmp   x0, #1
    b.ne  8f
    ldr   w20, [sp, #16]                  /* (u32) first file */
    ldr   w21, [sp, #48]                  /* (u32) last file */
1:  cmp   w20, w21                        /* f <= last, u32 as the twin */
    b.hi  8f
    mov   x0, x19
    mov   w1, w20
    bl    _store_rd_fd
    cmp   w20, w21
    b.eq  8f                              /* done at last (where the twin's u32
                                             f <= last never ends for last = ~0) */
    add   w20, w20, #1
    b     1b
8:  add   sp, sp, #64
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
9:  ret

/* store_map_random(on=x0) ; leaf */
    .p2align 2
    .globl _store_map_random
_store_map_random:
    cmp   x0, #0
    cset  w9, ne
    adrp  x10, Lmap_random@PAGE
    str   w9, [x10, Lmap_random@PAGEOFF]
    ret

/* store_map_init(st=x0) ; st x19, slot ptr x20 */
    .p2align 2
    .globl _store_map_init
    .globl _store_map_close
_store_map_close:
_store_map_init:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    add   x20, x19, #MAP_OFF
1:  ldp   x0, x1, [x20, #8]               /* map, size */
    cbz   x0, 2f
    bl    _munmap
2:  str   wzr, [x20]
    stp   xzr, xzr, [x20, #8]
    add   x20, x20, #32
    add   x9, x19, #MAP_OFF + 8 * 32
    cmp   x20, x9
    b.lo  1b
    MAPMAGIC x10
    str   x10, [x19, #MAP_MAGIC_OFF]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* ============================================================================
 * Lmap_file(st=x0, file_no=w1, need_end=x2) -> x0 map (0 = none), x1 size
 * st x19, file_no x20, need x21, slot x22, fd x23 ;
 * frame: name 0 (16), stat 16 (144) -> 160
 * ========================================================================== */
    .p2align 2
Lmap_file:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    str   x23, [sp, #48]
    mov   x29, sp
    sub   sp, sp, #160
    mov   x19, x0
    mov   w20, w1
    mov   x21, x2
    ldr   x9, [x19, #MAP_MAGIC_OFF]
    MAPMAGIC x10
    cmp   x9, x10
    b.eq  2f
    add   x9, x19, #MAP_OFF               /* first use: empty slots */
    mov   x11, #8
1:  str   wzr, [x9]
    stp   xzr, xzr, [x9, #8]
    add   x9, x9, #32
    subs  x11, x11, #1
    b.ne  1b
    str   x10, [x19, #MAP_MAGIC_OFF]
2:  and   x9, x20, #7
    add   x22, x19, #MAP_OFF
    add   x22, x22, x9, lsl #5
    ldr   w9, [x22]
    ldp   x0, x1, [x22, #8]               /* map, size */
    cmp   w9, w20
    b.ne  3f
    cbz   x0, 3f
    cmp   x1, x21
    b.hs  Lmf_ret                         /* cached and long enough */
3:  cbz   x0, 4f                          /* replace */
    bl    _munmap
4:  str   xzr, [x22, #8]
    mov   x0, sp
    mov   w1, w20
    bl    Lblkname
    mov   x0, sp
    mov   w1, #0                          /* O_RDONLY */
    bl    _open
    tbnz  w0, #31, Lmf_none
    mov   w23, w0
    add   x1, sp, #16
    bl    _fstat
    tbnz  w0, #31, 5f
    ldr   x9, [sp, #16 + ST_SIZE_OFF]
    cmp   x9, x21
    b.hs  6f
5:  mov   w0, w23                         /* fstat failed or the file is short */
    bl    _close
    b     Lmf_none
6:  mov   x0, #0                          /* mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0) */
    ldr   x1, [sp, #16 + ST_SIZE_OFF]
    mov   w2, #1
    mov   w3, #1
    mov   w4, w23
    mov   x5, #0
    bl    _mmap
    mov   x21, x0                         /* (need is spent) */
    mov   w0, w23
    bl    _close
    cmn   x21, #1
    b.eq  Lmf_none                        /* MAP_FAILED */
    adrp  x9, Lmap_random@PAGE
    ldr   w9, [x9, Lmap_random@PAGEOFF]
    cbz   w9, 7f
    mov   x0, x21                         /* advisory: MADV_RANDOM */
    ldr   x1, [sp, #16 + ST_SIZE_OFF]
    mov   w2, #1
    bl    _madvise
7:  ldr   x1, [sp, #16 + ST_SIZE_OFF]
    str   w20, [x22]
    stp   x21, x1, [x22, #8]
    mov   x0, x21
    b     Lmf_ret
Lmf_none:
    mov   x0, #0
    mov   x1, #0
Lmf_ret:
    add   sp, sp, #160
    ldr   x23, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* store_map_at(st=x0, height=x1, out=x2) ; st x19, out x20 ; frame meta 0 */
    .p2align 2
    .globl _store_map_at
_store_map_at:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #32
    mov   x19, x0
    mov   x20, x2
    stp   xzr, xzr, [sp]
    str   xzr, [sp, #16]
    mov   x2, sp
    bl    _store_get_at
    cmp   x0, #1
    b.ne  Lma_none
    ldp   x9, x10, [sp]                   /* need = data_pos + 8 + data_size */
    add   x2, x9, x10
    add   x2, x2, #8
    mov   x0, x19
    ldr   w1, [sp, #16]
    bl    Lmap_file
    cbz   x0, Lma_none
    cbz   x20, 1f
    ldr   x9, [sp, #8]                    /* out = {data_size, file_no} */
    ldr   x10, [sp, #16]
    stp   x9, x10, [x20]
1:  ldr   x9, [sp]
    add   x0, x0, x9
    add   x0, x0, #8                      /* past the [len][magic] header */
    b     Lma_ret
Lma_none:
    cbz   x20, 2f
    stp   xzr, xzr, [x20]
2:  mov   x0, #0
Lma_ret:
    add   sp, sp, #32
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .section __TEXT,__cstring
Lblkfmt:
    .asciz "blk%05u.dat"

    .data
    .p2align 2
Lmap_random:
    .long 0
