/* ============================================================================
 * bitcoin_store.S -- persistent multi-file block storage and the block index
 * in AArch64 assembly (Apple silicon), the counterpart of
 * asm/bitcoin_store.asm. Replaces store_twin.c on the Mac (2026-09-26); the
 * twin stays in port/osx/test_support as the oracle.
 *
 * Core's layout: rolling 128 MiB blk%05u.dat files, each block framed as
 * [u32 len][u32 magic f9beb4d9][raw] at a file-local offset, and a
 * positional index.dat of 48-byte records: hash[32], file_no u32, data_pos
 * u64, data_size u32 (0xFFFFFFFF = sparse-pruned).
 *
 * State (the x86's; callers allocate and zero it):
 *   +0 cur blk fd (-1 none), +8 index fd, +16 index length, +24 tip height
 *   i32 (-1 empty), +28 cur_file_no i32, +32 cur_file_pos i32, +36 magic,
 *   +40 shared-append flock fd i32, +44 pos_file_no i32 (the file that
 *   cur_file_pos was measured in: every writer of +32 also writes +44 --
 *   the 2026-09-17 incident), +48 prune height i32 (persisted in prune.dat).
 *
 *   void fmt_blkname(char* buf, u32 file_no);    "blk" + 5 digits + ".dat"
 *   long store_init(st);  long store_reload(st);              1 / -1
 *   long store_append(st, hash, raw, len);            new height / -1
 *   long store_append_shared(st, height, hash, raw, len);    height / -1
 *   long store_append_shared_nolock(st, height, hash, raw, len);
 *   long store_get_at(st, height, u64 meta[3]);  1 / -2 oor / -3 pruned / -1
 *   long store_get_tip(st, u64 meta[3]);                      1 / -1
 *   long store_get_file_fd(st, u32 file_no);                  fd / -1
 *   int  store_set_prune(st, int h);  int store_prune(st, int h);  1 / -1
 *   int  store_get_tip_hash(st, u8 out[32]);                  1 / -1
 *   int  store_validates_prevhash(st, const u8 hdr[80]);      1 / 0 / -1
 *   long store_layout_monotonic(st, long upto);               1 / 0
 *   long store_truncate_to(st, i64 target);                   1 / -1
 *   long store_truncate_index_only(st, i64 target);           1 / -1
 *   void store_set_sync(int on);  long store_get_sync(void);
 *
 * Every rule is the twin's (itself the x86's): store_append drops its fd,
 * walks forward to the frontier file (the newest blk that exists), reopens,
 * retakes cur_file_pos from the file's end only when pos_file_no says it was
 * measured elsewhere, rolls over at 128 MiB, writes header + block, syncs
 * (STO-11, fdatasync when enabled) BEFORE the index record. The shared
 * append takes the caller's height, writes at the TRUE end of the frontier
 * file under an optional flock, and self-heals a stale index fd.
 * store_truncate_to refuses a non-monotonic archive; store_prune compacts
 * the boundary file in place through a 64 KiB buffer (taken from the stack
 * in touched 4 KiB steps). Through libc; open() is variadic, so its mode
 * goes on the stack (Darwin arm64). Every return is a full 64-bit value.
 * ========================================================================== */
#define MAX_FILE  0x08000000
#define O_RDONLY  0x0000
#define O_RDWR    0x0002
#define O_CREAT   0x0200
#define O_TRUNC   0x0400
#define LOCK_EX   2
#define LOCK_UN   8
#define COPYBUF   65536

    .text

/* fmt_blkname(buf=x0, file_no=w1) ; leaf -- digits (n / 10^k) % 10 */
    .p2align 2
    .globl _fmt_blkname
_fmt_blkname:
    mov   w9, #'b'
    strb  w9, [x0]
    mov   w9, #'l'
    strb  w9, [x0, #1]
    mov   w9, #'k'
    strb  w9, [x0, #2]
    mov   w10, #10
    mov   w11, w1                         /* digits 7, 6, 5, 4, 3 from the right */
    mov   x12, #7
1:  udiv  w13, w11, w10
    msub  w14, w13, w10, w11
    add   w14, w14, #'0'
    strb  w14, [x0, x12]
    mov   w11, w13
    sub   x12, x12, #1
    cmp   x12, #3
    b.hs  1b
    mov   w9, #'.'
    strb  w9, [x0, #8]
    mov   w9, #'d'
    strb  w9, [x0, #9]
    mov   w9, #'a'
    strb  w9, [x0, #10]
    mov   w9, #'t'
    strb  w9, [x0, #11]
    strb  wzr, [x0, #12]
    ret

    .p2align 2
    .globl _store_set_sync
_store_set_sync:
    cmp   w0, #0
    cset  x9, ne
    adrp  x10, Lsync@PAGE
    str   x9, [x10, Lsync@PAGEOFF]
    ret

    .p2align 2
    .globl _store_get_sync
_store_get_sync:
    adrp  x10, Lsync@PAGE
    ldr   x0, [x10, Lsync@PAGEOFF]
    ret

/* Lopen3(path=x0, flags=w1): open(path, flags, 0644), the mode on the stack */
    .p2align 2
Lopen3:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #16
    mov   x9, #0644
    str   x9, [sp]
    bl    _open
    add   sp, sp, #16
    ldp   x29, x30, [sp], #16
    ret

/* Lopen_file(st=x0, file_no=w1) -> x0 fd (sign-extended) or negative:
 * closes any current blk fd first ; st x19, frame name 0 (16) */
    .p2align 2
Lopen_file:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #16
    mov   x19, x0
    mov   w20, w1
    ldr   x0, [x19]
    tbnz  x0, #63, 1f
    bl    _close                          /* no fd leak */
1:  mov   x0, sp
    mov   w1, w20
    bl    _fmt_blkname
    mov   x0, sp
    mov   w1, #(O_RDWR | O_CREAT)
    bl    Lopen3
    sxtw  x0, w0
    tbnz  x0, #63, 2f
    str   x0, [x19]
2:  add   sp, sp, #16
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* Lunlink_blk(file_no=w0): unlink blk%05u.dat, ENOENT tolerated */
    .p2align 2
Lunlink_blk:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #16
    mov   w1, w0
    mov   x0, sp
    bl    _fmt_blkname
    mov   x0, sp
    bl    _unlink
    add   sp, sp, #16
    ldp   x29, x30, [sp], #16
    ret

/* Lfrontier(st=x0, dropfd=w1): while blk(cur_file_no + 1) exists, advance
 * cur_file_no (and, with dropfd, close the fd at each advance) ;
 * st x19, dropfd x20 ; frame name 0 (16) */
    .p2align 2
Lfrontier:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #16
    mov   x19, x0
    mov   w20, w1
1:  ldr   w1, [x19, #28]
    add   w1, w1, #1
    mov   x0, sp
    bl    _fmt_blkname
    mov   x0, sp
    mov   w1, #0                          /* F_OK */
    bl    _access
    cbnz  w0, 3f                          /* blk(cur+1) absent: cur is the frontier */
    ldr   w9, [x19, #28]
    add   w9, w9, #1
    str   w9, [x19, #28]
    cbz   w20, 1b
    ldr   x0, [x19]
    tbnz  x0, #63, 1b
    bl    _close
    mov   x9, #-1
    str   x9, [x19]
    b     1b
3:  add   sp, sp, #16
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* store_init(st=x0) ; st x19 ; frame b4 0 (16) */
    .p2align 2
    .globl _store_init
_store_init:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #16
    mov   x19, x0
    adrp  x0, Lidxname@PAGE
    add   x0, x0, Lidxname@PAGEOFF
    mov   w1, #(O_RDWR | O_CREAT)
    bl    Lopen3
    tbnz  w0, #31, 2f
    sxtw  x9, w0
    mov   x10, #-1
    stp   x10, x9, [x19]                  /* cur blk fd none, index fd */
    mov   x9, #0xffffffff                 /* tip -1 (i32 at +24), cur_file_no 0 */
    stp   xzr, x9, [x19, #16]             /* index length 0, tip -1, cur_file_no 0 */
    movz  w9, #0xbef9
    movk  w9, #0xd9b4, lsl #16
    str   wzr, [x19, #32]                 /* cur_file_pos */
    str   w9, [x19, #36]                  /* magic */
    str   xzr, [x19, #40]                 /* flock fd 0, pos_file_no 0 */
    str   wzr, [x19, #48]                 /* prune height */
    adrp  x0, Lprunename@PAGE             /* the persisted prune gate */
    add   x0, x0, Lprunename@PAGEOFF
    mov   w1, #O_RDONLY
    bl    _open
    tbnz  w0, #31, 1f
    mov   w20, w0
    mov   x1, sp
    mov   x2, #4
    bl    _read
    cmp   x0, #4
    b.ne  11f
    ldr   w9, [sp]
    str   w9, [x19, #48]
11: mov   w0, w20
    bl    _close
1:  mov   x0, #1
    b     3f
2:  mov   x0, #-1
3:  add   sp, sp, #16
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* store_reload(st=x0) ; st x19, size x20 ; frame rec 0 (48) */
    .p2align 2
    .globl _store_reload
_store_reload:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #48
    mov   x19, x0
    ldr   x0, [x19, #8]
    mov   x1, #0
    mov   w2, #2                          /* SEEK_END */
    bl    _lseek
    tbnz  x0, #63, Lrl_no
    mov   x20, x0
    str   x20, [x19, #16]
    cmp   x20, #48
    b.ge  1f
    mov   x9, #0xffffffff         /* empty: tip -1, cur_file_no 0 */
    str   x9, [x19, #24]
    str   wzr, [x19, #32]
    str   wzr, [x19, #44]
    mov   x9, #-1
    str   x9, [x19]
    mov   x0, #1
    b     Lrl_ret
1:  ldr   x0, [x19, #8]                   /* the last record */
    mov   x1, sp
    mov   x2, #48
    sub   x3, x20, #48
    bl    _pread
    cmp   x0, #48
    b.ne  Lrl_no
    ldr   w9, [sp, #32]                   /* file_no */
    ldur  x10, [sp, #36]                  /* data_pos */
    ldr   w11, [sp, #44]                  /* data_size */
    str   w9, [x19, #28]
    add   x10, x10, #8
    add   x10, x10, x11
    str   w10, [x19, #32]                 /* cur_file_pos = pos + 8 + size */
    str   w9, [x19, #44]                  /* pos_file_no := cur_file_no */
    mov   x10, #48
    sdiv  x10, x20, x10
    sub   x10, x10, #1
    str   w10, [x19, #24]                 /* tip */
    mov   x0, x19
    mov   w1, w9
    bl    Lopen_file
    tbnz  x0, #63, Lrl_no
    mov   x0, #1
    b     Lrl_ret
Lrl_no:
    mov   x0, #-1
Lrl_ret:
    add   sp, sp, #48
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* store_get_file_fd(st, file_no) = (int) open_file */
    .p2align 2
    .globl _store_get_file_fd
_store_get_file_fd:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    bl    Lopen_file
    sxtw  x0, w0
    ldp   x29, x30, [sp], #16
    ret

/* store_get_at(st=x0, height=x1, meta=x2) ; st x19, meta x20 ; frame rec */
    .p2align 2
    .globl _store_get_at
_store_get_at:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #48
    mov   x19, x0
    mov   x20, x2
    ldr   x9, [x19, #16]
    mov   x10, #48
    udiv  x9, x9, x10
    sub   x9, x9, #1                      /* tip (signed) */
    tbnz  x9, #63, 3f
    cmp   x1, x9
    b.gt  3f                              /* past the tip: -2 */
    ldrsw x10, [x19, #48]
    cmp   x1, x10
    b.lt  4f                              /* below the prune gate: -3 */
    ldr   x0, [x19, #8]
    mov   x3, #48
    mul   x3, x1, x3
    mov   x1, sp
    mov   x2, #48
    bl    _pread
    cmp   x0, #48
    b.ne  2f
    ldr   w10, [sp, #44]
    cmn   w10, #1
    b.eq  4f                              /* sparse-prune marker */
    ldur  x9, [sp, #36]
    ldr   w11, [sp, #32]                  /* (zero-extended, as x86's dword) */
    stp   x9, x10, [x20]
    str   x11, [x20, #16]
    mov   x0, #1
    b     5f
2:  mov   x0, #-1
    b     5f
3:  mov   x0, #-2
    b     5f
4:  mov   x0, #-3
5:  add   sp, sp, #48
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* store_get_tip(st=x0, meta=x1) */
    .p2align 2
    .globl _store_get_tip
_store_get_tip:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    mov   x2, x1
    ldr   x9, [x0, #16]
    mov   x10, #48
    udiv  x9, x9, x10
    subs  x1, x9, #1
    b.mi  1f
    bl    _store_get_at
    cmp   x0, #1
    b.eq  2f
1:  mov   x0, #-1
2:  ldp   x29, x30, [sp], #16
    ret

/* store_set_prune(st=x0, h=w1) ; st x19, h x20 ; frame b4 */
    .p2align 2
    .globl _store_set_prune
_store_set_prune:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #16
    mov   x19, x0
    mov   w20, w1
    str   w20, [x19, #48]
    adrp  x0, Lprunename@PAGE
    add   x0, x0, Lprunename@PAGEOFF
    mov   w1, #(O_RDWR | O_CREAT | O_TRUNC)
    bl    Lopen3
    tbnz  w0, #31, 2f
    mov   w21, w0
    str   w20, [sp]
    mov   x1, sp
    mov   x2, #4
    bl    _write
    mov   x9, x0
    mov   w0, w21
    str   x9, [sp, #8]
    bl    _close
    ldr   x9, [sp, #8]
    cmp   x9, #4
    b.ne  2f
    mov   x0, #1
    b     3f
2:  mov   x0, #-1
3:  add   sp, sp, #16
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* Lread_idx(st=x0, height=x1, buf=x2) -> x0 file_no (sign-extended) / -1 */
    .p2align 2
Lread_idx:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    mov   x19, x2
    ldr   x0, [x0, #8]
    mov   x9, #48
    mul   x3, x1, x9
    mov   x1, x19
    mov   x2, #48
    bl    _pread
    cmp   x0, #48
    b.ne  1f
    ldrsw x0, [x19, #32]
    b     2f
1:  mov   x0, #-1
2:  ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* Lwrite_idx(st=x0, height=x1, buf=x2) -> x0 1 / -1 */
    .p2align 2
Lwrite_idx:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    ldr   x0, [x0, #8]
    mov   x9, #48
    mul   x3, x1, x9
    mov   x1, x2
    mov   x2, #48
    bl    _pwrite
    cmp   x0, #48
    mov   x0, #1
    mov   x9, #-1
    csel  x0, x0, x9, eq
    ldp   x29, x30, [sp], #16
    ret

/* ============================================================================
 * store_prune(st=x0, prune_height=w1)
 * st x19, tip x20, eff x21, first_ret x22, fd x23, h x24, new_off x25,
 * old_ptr x26, new_ptr x27, remaining x28 ; frame (below the 64 KiB copy
 * buffer): recA 0 (48), chunk 48 -> 64 ; the buffer at sp + 64
 * ========================================================================== */
    .p2align 2
    .globl _store_prune
_store_prune:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    stp   x27, x28, [sp, #80]
    mov   x29, sp
    mov   x19, x0
    mov   w21, w1
    ldrsw x20, [x19, #24]                 /* tip */
    cmn   x20, #1
    b.ne  1f
    str   wzr, [x19, #48]                 /* empty store */
    mov   w1, #0
    bl    _store_set_prune
    b     Lpr_ok
1:  cmp   w21, #0                         /* clamp negatives to 0 ... */
    csel  w21, wzr, w21, lt
    add   w9, w20, #1
    cmp   w21, w9                         /* ... and (u32) past tip + 1 to tip + 1 */
    csel  w21, w9, w21, hi
    str   w21, [x19, #48]
    cbnz  w21, 2f
    mov   x0, x19                         /* nothing deleted */
    mov   w1, #0
    bl    _store_set_prune
    b     Lpr_ok
2:  mov   x0, x19
    mov   w1, w21
    bl    _store_set_prune
    add   w9, w20, #1
    cmp   w21, w9
    b.ne  4f
    mov   w22, #0                         /* retain nothing: every file goes */
3:  ldr   w9, [x19, #28]
    cmp   w22, w9
    b.gt  Lpr_ok
    mov   w0, w22
    bl    Lunlink_blk
    add   w22, w22, #1
    b     3b
4:  mov   x9, #(COPYBUF / 4096)           /* the copy buffer, 4 KiB at a time */
41: sub   sp, sp, #4096
    str   xzr, [sp]
    subs  x9, x9, #1
    b.ne  41b
    sub   sp, sp, #64
    sxtw  x24, w21                        /* h = eff */
    mov   x0, x19
    mov   x1, x24
    mov   x2, sp
    bl    Lread_idx
    tbnz  x0, #63, Lpr_no
    mov   x22, x0                         /* the first retained file */
    mov   w23, #0
5:  cmp   x23, x22                        /* unlink every file before it */
    b.ge  6f
    mov   w0, w23
    bl    Lunlink_blk
    add   w23, w23, #1
    b     5b
6:  mov   x0, x19                         /* compact the boundary file in place */
    mov   w1, w22
    bl    Lopen_file
    tbnz  x0, #63, Lpr_no
    mov   x23, x0
    mov   x25, #0                         /* new_off */
7:  cmp   x24, x20
    b.gt  9f
    mov   x0, x19
    mov   x1, x24
    mov   x2, sp
    bl    Lread_idx
    tbnz  x0, #63, Lpr_no
    cmp   x0, x22
    b.ne  9f                              /* past the boundary file */
    ldur  x26, [sp, #36]                  /* old_ptr */
    ldr   w28, [sp, #44]
    add   x28, x28, #8                    /* remaining = size + 8 */
    mov   x27, x25                        /* new_ptr */
8:  cbz   x28, 81f
    mov   x9, #COPYBUF
    cmp   x28, x9
    csel  x2, x28, x9, lo
    str   x2, [sp, #48]
    mov   w0, w23
    add   x1, sp, #64
    mov   x3, x26
    bl    _pread
    ldr   x2, [sp, #48]
    cmp   x0, x2
    b.ne  Lpr_no
    mov   w0, w23
    add   x1, sp, #64
    mov   x3, x27
    bl    _pwrite
    ldr   x2, [sp, #48]
    cmp   x0, x2
    b.ne  Lpr_no
    add   x26, x26, x2
    add   x27, x27, x2
    sub   x28, x28, x2
    b     8b
81: stur  x25, [sp, #36]                  /* the record, data_pos := new_off */
    mov   x0, x19
    mov   x1, x24
    mov   x2, sp
    bl    Lwrite_idx
    tbnz  x0, #63, Lpr_no
    ldr   w9, [sp, #44]
    add   x25, x25, x9
    add   x25, x25, #8
    add   x24, x24, #1
    b     7b
9:  mov   w0, w23
    mov   x1, x25
    bl    _ftruncate
    tbnz  w0, #31, Lpr_no
Lpr_ok:
    mov   x0, #1
    b     Lpr_ret
Lpr_no:
    mov   x0, #-1
Lpr_ret:
    mov   sp, x29
    ldp   x27, x28, [sp, #80]
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

/* Lwrite_block(st=x0, pos=x1, raw=x2, len=x3) -> x0 0 / -1: the frame
 * header [len][magic] at pos, the block at pos + 8, into the current fd ;
 * st x19, pos x20, raw x21, len x22 ; frame hdr 0 (16) */
    .p2align 2
Lwrite_block:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #16
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, x3
    str   w22, [sp]
    ldr   w9, [x19, #36]
    str   w9, [sp, #4]
    ldr   x0, [x19]
    mov   x1, sp
    mov   x2, #8
    mov   x3, x20
    bl    _pwrite
    cmp   x0, #8
    b.ne  1f
    ldr   x0, [x19]
    mov   x1, x21
    mov   x2, x22
    add   x3, x20, #8
    bl    _pwrite
    cmp   x0, x22
    b.ne  1f
    mov   x0, #0
    b     2f
1:  mov   x0, #-1
2:  add   sp, sp, #16
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* Lwrite_rec(st=x0, height=x1, hash=x2, file_no=w3, pos=x4, len=w5) ->
 * x0 0 / -1: the 48-byte index record ; frame rec 0 (48) */
    .p2align 2
Lwrite_rec:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #48
    ldp   x9, x10, [x2]
    stp   x9, x10, [sp]
    ldp   x9, x10, [x2, #16]
    stp   x9, x10, [sp, #16]
    str   w3, [sp, #32]
    stur  x4, [sp, #36]
    str   w5, [sp, #44]
    mov   x2, sp
    bl    Lwrite_idx
    cmp   x0, #1
    csetm x0, ne                          /* 1 -> 0, -1 -> -1 */
    add   sp, sp, #48
    ldp   x29, x30, [sp], #16
    ret

/* ============================================================================
 * store_append(st=x0, hash=x1, raw=x2, len=x3)
 * st x19, hash x20, raw x21, len x22, pos x23, file_no x24, height x25
 * ========================================================================== */
    .p2align 2
    .globl _store_append
_store_append:
    stp   x29, x30, [sp, #-80]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    str   x25, [sp, #64]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, x3
    ldr   x0, [x19]                       /* 1. drop the fd */
    tbnz  x0, #63, 1f
    bl    _close
    mov   x9, #-1
    str   x9, [x19]
1:  mov   x0, x19                         /* 2. the frontier walk */
    mov   w1, #0
    bl    Lfrontier
    ldr   x9, [x19]
    tbz   x9, #63, 2f
    mov   x0, x19
    ldr   w1, [x19, #28]
    bl    Lopen_file
    tbnz  x0, #63, Lap_no
2:  ldr   w9, [x19, #44]                  /* 3. the position measured elsewhere? */
    ldr   w10, [x19, #28]
    cmp   w9, w10
    b.eq  3f
    ldr   x0, [x19]
    mov   x1, #0
    mov   w2, #2                          /* SEEK_END */
    bl    _lseek
    tbnz  x0, #63, Lap_no
    str   w0, [x19, #32]                  /* retaken from the true end */
    ldr   w10, [x19, #28]
    str   w10, [x19, #44]
3:  ldr   w9, [x19, #32]                  /* rollover past 128 MiB */
    add   x9, x9, #8
    add   x9, x9, x22
    mov   x10, #MAX_FILE
    cmp   x9, x10
    b.ls  4f
    ldr   x0, [x19]
    bl    _close
    mov   x9, #-1
    str   x9, [x19]
    ldr   w10, [x19, #28]
    add   w10, w10, #1
    str   w10, [x19, #28]
    str   wzr, [x19, #32]
    str   w10, [x19, #44]
    mov   x0, x19
    mov   w1, w10
    bl    Lopen_file
    tbnz  x0, #63, Lap_no
4:  ldr   w23, [x19, #32]                 /* data_pos (u32) */
    ldr   w24, [x19, #28]                 /* file_no */
    mov   x0, x19
    mov   x1, x23
    mov   x2, x21
    mov   x3, x22
    bl    Lwrite_block
    cbnz  x0, Lap_no
    add   x9, x23, #8
    add   x9, x9, x22
    str   w9, [x19, #32]
    str   w24, [x19, #44]
    adrp  x9, Lsync@PAGE                  /* STO-11: the block before its record */
    ldr   x9, [x9, Lsync@PAGEOFF]
    cbz   x9, 5f
    ldr   x0, [x19]
    bl    _fdatasync
    tbnz  w0, #31, Lap_no
5:  ldr   x25, [x19, #16]
    mov   x9, #48
    udiv  x25, x25, x9                    /* height = index length / 48 */
    mov   x0, x19
    mov   x1, x25
    mov   x2, x20
    mov   w3, w24
    mov   x4, x23
    mov   w5, w22
    bl    Lwrite_rec
    cbnz  x0, Lap_no
    ldr   x9, [x19, #16]
    add   x9, x9, #48
    str   x9, [x19, #16]
    str   w25, [x19, #24]
    sxtw  x0, w25
    b     Lap_ret
Lap_no:
    mov   x0, #-1
Lap_ret:
    ldr   x25, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

/* ============================================================================
 * Lappend_shared(st=x0, height=x1, hash=x2, raw=x3, len=x4, dolock=w5)
 * st x19, height x20, hash x21, raw x22, len x23, lock fd x24 (or -1 when
 * not locking), ret x25, pos x26
 * ========================================================================== */
    .p2align 2
Lappend_shared:
    stp   x29, x30, [sp, #-96]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    stp   x25, x26, [sp, #64]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    mov   x21, x2
    mov   x22, x3
    mov   x23, x4
    mov   x24, #-1
    cbz   w5, 1f
    ldrsw x24, [x19, #40]
    tbnz  x24, #63, 1f
    mov   w0, w24
    mov   w1, #LOCK_EX
    bl    _flock
1:  mov   x25, #-1
    mov   x0, x19                         /* FRONTIER, dropping the fd at each step */
    mov   w1, #1
    bl    Lfrontier
    ldr   w9, [x19, #8]                   /* (int) index fd < 0: reopen */
    tbz   w9, #31, 2f
    adrp  x0, Lidxname@PAGE
    add   x0, x0, Lidxname@PAGEOFF
    mov   w1, #(O_RDWR | O_CREAT)
    bl    Lopen3
    tbnz  w0, #31, 2f
    sxtw  x9, w0
    str   x9, [x19, #8]
2:  ldr   x9, [x19]
    tbz   x9, #63, 3f
    mov   x0, x19
    ldr   w1, [x19, #28]
    bl    Lopen_file
    tbnz  x0, #63, Las_done
3:  ldr   x0, [x19]                       /* the TRUE end of the file */
    mov   x1, #0
    mov   w2, #2
    bl    _lseek
    tbnz  x0, #63, Las_done
    mov   x26, x0
    add   x9, x26, #8
    add   x9, x9, x23
    mov   x10, #MAX_FILE
    cmp   x9, x10
    b.ls  4f
    ldr   x0, [x19]                       /* full: the next file */
    bl    _close
    mov   x9, #-1
    str   x9, [x19]
    ldr   w1, [x19, #28]
    add   w1, w1, #1
    str   w1, [x19, #28]
    mov   x0, x19
    bl    Lopen_file
    tbnz  x0, #63, Las_done
    b     3b
4:  mov   x0, x19
    mov   x1, x26
    mov   x2, x22
    mov   x3, x23
    bl    Lwrite_block
    cbnz  x0, Las_done
    adrp  x9, Lsync@PAGE
    ldr   x9, [x9, Lsync@PAGEOFF]
    cbz   x9, 5f
    ldr   x0, [x19]
    bl    _fdatasync
    tbnz  w0, #31, Las_done
5:  mov   x0, x19
    mov   x1, x20
    mov   x2, x21
    ldr   w3, [x19, #28]
    mov   x4, x26
    mov   w5, w23
    bl    Lwrite_rec
    cbnz  x0, Las_done
    mov   x25, x20
Las_done:
    tbnz  x24, #63, 6f
    mov   w0, w24
    mov   w1, #LOCK_UN
    bl    _flock
6:  mov   x0, x25
    ldp   x25, x26, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #96
    ret

    .p2align 2
    .globl _store_append_shared
_store_append_shared:
    mov   w5, #1
    b     Lappend_shared

    .p2align 2
    .globl _store_append_shared_nolock
_store_append_shared_nolock:
    mov   w5, #0
    b     Lappend_shared

/* store_get_tip_hash(st=x0, out=x1) */
    .p2align 2
    .globl _store_get_tip_hash
_store_get_tip_hash:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    ldrsw x9, [x0, #24]
    cmn   x9, #1
    b.eq  1f
    ldr   x0, [x0, #8]
    mov   x10, #48
    mul   x3, x9, x10
    mov   x2, #32
    bl    _pread
    cmp   x0, #32
    b.ne  1f
    mov   x0, #1
    b     2f
1:  mov   x0, #-1
2:  ldp   x29, x30, [sp], #16
    ret

/* store_validates_prevhash(st=x0, hdr=x1) ; hdr x19 ; frame tip hash */
    .p2align 2
    .globl _store_validates_prevhash
_store_validates_prevhash:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #32
    mov   x19, x1
    mov   x1, sp
    bl    _store_get_tip_hash
    cmp   x0, #1
    b.ne  1f
    ldp   x9, x10, [sp]
    ldur  x11, [x19, #4]
    ldur  x12, [x19, #12]
    cmp   x9, x11
    ccmp  x10, x12, #0, eq
    ldp   x9, x10, [sp, #16]
    ldur  x11, [x19, #20]
    ldur  x12, [x19, #28]
    ccmp  x9, x11, #0, eq
    ccmp  x10, x12, #0, eq
    cset  x0, eq
    b     2f
1:  mov   x0, #-1
2:  add   sp, sp, #32
    ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* store_layout_monotonic(st=x0, upto=x1)
 * st x19, upto x20, h x21, prev_file x22, prev_pos x23, seen x24 */
    .p2align 2
    .globl _store_layout_monotonic
_store_layout_monotonic:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    mov   x29, sp
    sub   sp, sp, #48
    mov   x19, x0
    mov   x20, x1
    mov   x21, #0
    mov   w22, #0
    mov   x23, #0
    mov   x24, #0
1:  cmp   x21, x20
    b.gt  Llm_yes
    ldr   x0, [x19, #8]
    mov   x1, sp
    mov   x2, #48
    mov   x9, #48
    mul   x3, x21, x9
    bl    _pread
    cmp   x0, #48
    b.ne  Llm_yes                         /* a short read is the end */
    ldr   w9, [sp]
    cbz   w9, 3f                          /* a hole, not a block */
    ldr   w10, [sp, #32]
    ldur  x11, [sp, #36]
    cbz   x24, 2f
    cmp   w10, w22
    b.lo  Llm_no                          /* the file went backwards */
    b.ne  2f
    cmp   x11, x23
    b.lo  Llm_no                          /* the position went backwards */
2:  mov   w22, w10
    mov   x23, x11
    mov   x24, #1
3:  add   x21, x21, #1
    b     1b
Llm_yes:
    mov   x0, #1
    b     Llm_ret
Llm_no:
    mov   x0, #0
Llm_ret:
    add   sp, sp, #48
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* ============================================================================
 * store_truncate_to(st=x0, target=x1)
 * st x19, target x20, bfile x21, bpos x22, f x23, orig_cur x24 ; frame rec
 * ========================================================================== */
    .p2align 2
    .globl _store_truncate_to
_store_truncate_to:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    mov   x29, sp
    sub   sp, sp, #48
    mov   x19, x0
    mov   x20, x1
    ldrsw x9, [x19, #24]
    cmn   x9, #1
    b.eq  Ltt_ok                          /* already empty */
    cmp   x20, x9
    b.ge  Ltt_ok                          /* nothing to drop */
    cmn   x20, #1
    b.ne  2f
    ldr   x0, [x19, #8]                   /* wipe everything */
    mov   x1, #0
    bl    _ftruncate
    tbnz  w0, #31, Ltt_no
    mov   w23, #0
1:  ldr   w9, [x19, #28]
    cmp   w23, w9
    b.gt  11f
    mov   w0, w23
    bl    Lunlink_blk
    add   w23, w23, #1
    b     1b
11: str   xzr, [x19, #16]
    mov   x9, #0xffffffff
    str   x9, [x19, #24]                  /* tip -1, cur_file_no 0 */
    str   wzr, [x19, #32]
    str   wzr, [x19, #44]
    mov   x9, #-1
    str   x9, [x19]
    b     Ltt_ok
2:  mov   x0, x19                         /* SAFETY GATE */
    add   x1, x20, #1
    bl    _store_layout_monotonic
    cbz   x0, Ltt_no
    ldr   x0, [x19, #8]                   /* the boundary record */
    mov   x1, sp
    mov   x2, #48
    add   x3, x20, #1
    mov   x9, #48
    mul   x3, x3, x9
    bl    _pread
    cmp   x0, #48
    b.ne  Ltt_no
    ldr   w21, [sp, #32]
    ldur  x22, [sp, #36]
    ldr   x0, [x19, #8]
    add   x1, x20, #1
    mov   x9, #48
    mul   x1, x1, x9
    bl    _ftruncate
    tbnz  w0, #31, Ltt_no
    mov   x0, x19                         /* the boundary file becomes current */
    mov   w1, w21
    bl    Lopen_file
    tbnz  x0, #63, Ltt_no
    mov   x1, x22
    bl    _ftruncate
    tbnz  w0, #31, Ltt_no
    ldr   w24, [x19, #28]                 /* later files go */
    add   w23, w21, #1
3:  cmp   w23, w24
    b.gt  4f
    mov   w0, w23
    bl    Lunlink_blk
    add   w23, w23, #1
    b     3b
4:  str   w21, [x19, #28]
    str   w22, [x19, #32]
    str   w21, [x19, #44]
    add   x9, x20, #1
    mov   x10, #48
    mul   x9, x9, x10
    str   x9, [x19, #16]
    str   w20, [x19, #24]
Ltt_ok:
    mov   x0, #1
    b     Ltt_ret
Ltt_no:
    mov   x0, #-1
Ltt_ret:
    add   sp, sp, #48
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* store_truncate_index_only(st=x0, target=x1) ; st x19, target x20 */
    .p2align 2
    .globl _store_truncate_index_only
_store_truncate_index_only:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x1
    ldrsw x9, [x19, #24]
    cmn   x9, #1
    b.eq  2f
    cmp   x20, x9
    b.ge  2f
    add   x9, x20, #1
    mov   x10, #48
    mul   x1, x9, x10                     /* target -1 -> length 0 */
    str   x1, [sp, #-16]!
    ldr   x0, [x19, #8]
    bl    _ftruncate
    ldr   x1, [sp], #16
    tbnz  w0, #31, 3f
    str   x1, [x19, #16]
    str   w20, [x19, #24]                 /* (-1 when the index is dropped) */
2:  mov   x0, #1
    b     4f
3:  mov   x0, #-1
4:  ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .section __TEXT,__cstring
Lidxname:
    .asciz "index.dat"
Lprunename:
    .asciz "prune.dat"

    .data
    .p2align 3
Lsync:      /* STO-11 durability switch, on by default */
    .quad 1
