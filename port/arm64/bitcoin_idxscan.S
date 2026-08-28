/* bitcoin_idxscan.S -- AArch64 port of asm/bitcoin_idxscan.asm (AAPCS64).
 * On-disk index.dat 48-byte positional-record scans (presence = first 4 bytes
 * non-zero), buffered pread64 192KB window. AArch64 syscalls: openat=56
 * (AT_FDCWD=-100), close=57, lseek=62, pread64=67, flock=32.
 *
 * Exports:
 *   long idxscan_all_present(lo, hi) -> 1 if every height in [lo,hi] present
 *   long idxscan_tip(void)           -> highest present height / -1
 *   int  idxscan_append_locked(st, hash[32], raw, len)    -> height/-1/-2
 *   int  idxscan_append_nolocked(st, hash[32], raw, len)  -> height/-1
 *   long idxscan_first_hole(tip)     -> first zero-record height in [0,tip]/-1
 *   void idxscan_progress(long*, long*) -> *out_tip, *out_present
 *
 * store_append_shared / store_append_shared_nolock are bitcoin_store.S
 * exports (shared append body) -- not yet ported; the two append wrappers
 * reference them and link once bitcoin_store exposes them.
 */
    .section .rodata
idxscan_name:
    .asciz "index.dat"
    .p2align 4

    .bss
    .p2align 4
idxscan_buf:
    .space 4096*48        /* 192 KB read window */

    .text

/* ================= idxscan_all_present(lo=x0, hi=x1) -> 1/0 ================= */
    .global idxscan_all_present
    .type idxscan_all_present,%function
idxscan_all_present:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0                /* lo */
    mov  x20,x1                /* hi */
    cmp  x19,x20
    b.gt .ia_triv              /* empty range => vacuous true */
    mov  x0,#-100              /* AT_FDCWD */
    adrp x9,idxscan_name
    add  x1,x9,:lo12:idxscan_name
    mov  x2,#0                 /* O_RDONLY */
    mov  x8,#56                /* openat */
    svc  #0
    tbnz x0,#63,.ia_abs
    mov  x21,x0                /* fd */
    sub  x9,x20,x19
    add  x22,x9,#1             /* remaining = hi-lo+1 */
    mov  x23,x19               /* pos */
.ia_loop:
    cmp  x22,#0
    b.le .ia_all
    mov  x9,#4096
    mov  x24,x22
    cmp  x22,x9
    csel x24,x22,x9,le          /* take = min(remaining,4096) */
    mov  x9,#48
    mul  x12,x24,x9             /* count = take*48 */
    mul  x13,x23,x9             /* offset = pos*48 */
    mov  x0,x21
    adrp x11,idxscan_buf
    add  x1,x11,:lo12:idxscan_buf
    mov  x2,x12
    mov  x3,x13
    mov  x8,#67                 /* pread64 */
    svc  #0
    cmp  x0,x12
    b.ne .ia_cabs               /* short read */
    mov  x10,#0                 /* i */
.ia_scan:
    cmp  x10,x24
    b.ge .ia_adv
    mov  x9,x10
    mov  x11,#48
    mul  x9,x9,x11
    adrp x11,idxscan_buf
    add  x11,x11,:lo12:idxscan_buf
    ldr  w5,[x11,x9]
    cbz  w5,.ia_cabs
    add  x10,x10,#1
    b    .ia_scan
.ia_adv:
    add  x23,x23,x24
    sub  x22,x22,x24
    b    .ia_loop
.ia_all:
    mov  x25,#1
    b    .ia_cr
.ia_cabs:
    mov  x25,#0
.ia_cr:
    mov  x0,x21
    mov  x8,#57                 /* close */
    svc  #0
    mov  x0,x25
    b    .ia_ret
.ia_abs:
    mov  w0,#0
    b    .ia_ret
.ia_triv:
    mov  w0,#1
.ia_ret:
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size idxscan_all_present,.-idxscan_all_present

/* ================= idxscan_tip(void) -> highest present / -1 ================= */
    .global idxscan_tip
    .type idxscan_tip,%function
idxscan_tip:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    mov  x0,#-100
    adrp x9,idxscan_name
    add  x1,x9,:lo12:idxscan_name
    mov  x2,#0
    mov  x8,#56
    svc  #0
    tbnz x0,#63,.it_none
    mov  x19,x0                /* fd */
    mov  x0,x19
    mov  x1,#0
    mov  x2,#2                 /* SEEK_END */
    mov  x8,#62                /* lseek */
    svc  #0
    tbnz x0,#63,.it_cnone
    mov  x9,#48
    udiv x20,x0,x9             /* end = n records */
.it_loop:
    cmp  x20,#0
    b.le .it_cnone
    mov  x9,#4096
    mov  x21,x20
    cmp  x20,x9
    csel x21,x20,x9,le          /* take = min(end,4096) */
    sub  x22,x20,x21            /* start = end - take */
    mov  x9,#48
    mul  x12,x21,x9             /* count */
    mul  x13,x22,x9             /* offset */
    mov  x0,x19
    adrp x11,idxscan_buf
    add  x1,x11,:lo12:idxscan_buf
    mov  x2,x12
    mov  x3,x13
    mov  x8,#67
    svc  #0
    cmp  x0,x12
    b.ne .it_cnone
    mov  x10,x21
    sub  x10,x10,#1             /* i = take-1 */
.it_scan:
    cmp  x10,#0
    b.lt .it_adv
    mov  x9,x10
    mov  x11,#48
    mul  x9,x9,x11
    adrp x11,idxscan_buf
    add  x11,x11,:lo12:idxscan_buf
    ldr  w5,[x11,x9]
    cbnz w5,.it_found
    sub  x10,x10,#1
    b    .it_scan
.it_adv:
    mov  x20,x22                /* end = start; try prev block */
    b    .it_loop
.it_found:
    add  x23,x22,x10            /* tip = start + i */
    mov  x0,x19
    mov  x8,#57
    svc  #0
    mov  x0,x23
    b    .it_ret
.it_cnone:
    mov  x0,x19
    mov  x8,#57
    svc  #0
.it_none:
    mov  x0,#-1
.it_ret:
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size idxscan_tip,.-idxscan_tip

/* ================= idxscan_first_hole(tip=x0) -> hole height / -1 ================= */
    .global idxscan_first_hole
    .type idxscan_first_hole,%function
idxscan_first_hole:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0                /* tip */
    cmp  x19,#0
    b.lt .if_none
    mov  x0,#-100
    adrp x9,idxscan_name
    add  x1,x9,:lo12:idxscan_name
    mov  x2,#0
    mov  x8,#56
    svc  #0
    tbnz x0,#63,.if_none
    mov  x20,x0                /* fd */
    mov  x21,#0                /* pos */
    add  x22,x19,#1            /* remaining = tip+1 */
.if_loop:
    cmp  x22,#0
    b.le .if_cnone
    mov  x9,#4096
    mov  x23,x22
    cmp  x22,x9
    csel x23,x22,x9,le          /* take */
    mov  x9,#48
    mul  x12,x23,x9             /* count */
    mul  x13,x21,x9             /* offset */
    mov  x0,x20
    adrp x11,idxscan_buf
    add  x1,x11,:lo12:idxscan_buf
    mov  x2,x12
    mov  x3,x13
    mov  x8,#67
    svc  #0
    tbnz x0,#63,.if_atpos       /* read error -> pos is the hole */
    udiv x24,x0,x9              /* full = bytes/48 */
    mov  x10,#0                 /* i */
.if_scan:
    cmp  x10,x24
    b.ge .if_short
    mov  x9,x10
    mov  x11,#48
    mul  x9,x9,x11
    adrp x11,idxscan_buf
    add  x11,x11,:lo12:idxscan_buf
    ldr  w5,[x11,x9]
    cbz  w5,.if_at_i
    add  x10,x10,#1
    b    .if_scan
.if_short:
    cmp  x24,x23
    b.lt .if_at_i
    add  x21,x21,x23
    sub  x22,x22,x23
    b    .if_loop
.if_at_i:
    add  x25,x21,x10            /* hole = pos + i */
    b    .if_cf
.if_atpos:
    mov  x25,x21                /* hole = pos */
.if_cf:
    mov  x0,x20
    mov  x8,#57
    svc  #0
    mov  x0,x25
    b    .if_ret
.if_cnone:
    mov  x0,x20
    mov  x8,#57
    svc  #0
.if_none:
    mov  x0,#-1
.if_ret:
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size idxscan_first_hole,.-idxscan_first_hole

/* ======= idxscan_progress(out_tip=x0, out_present=x1) ======= */
    .global idxscan_progress
    .type idxscan_progress,%function
idxscan_progress:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    sub  sp,sp,#0x10            /* running_tip@[sp] running_present@[sp+8] (clear of saves) */
    mov  x29,sp
    mov  x19,x0                /* out_tip */
    mov  x20,x1                /* out_present */
    mov  x9,#-1
    str  x9,[x19]
    str  xzr,[x20]
    mov  x0,#-100
    adrp x9,idxscan_name
    add  x1,x9,:lo12:idxscan_name
    mov  x2,#0
    mov  x8,#56
    svc  #0
    tbnz x0,#63,.ip_flush
    mov  x21,x0                /* fd */
    mov  x0,x21
    mov  x1,#0
    mov  x2,#2
    mov  x8,#62
    svc  #0
    tbnz x0,#63,.ip_close
    mov  x9,#48
    udiv x22,x0,x9             /* n = total records */
    mov  x23,#0                /* pos */
    mov  x9,#-1
    str  x9,[sp]               /* running_tip = -1 */
    str  xzr,[sp,#8]           /* running_present = 0 */
.ip_loop:
	cmp  x23,x22
	b.ge .ip_flush
	sub  x9,x22,x23            /* remaining */
	mov  x10,#4096
	cmp  x9,x10
	csel x24,x10,x9,gt          /* take = min(remaining,4096): if rem>4096 take=4096 else rem */
    mov  x9,#48
    mul  x12,x24,x9             /* count */
    mul  x13,x23,x9             /* offset */
    mov  x0,x21
    adrp x11,idxscan_buf
    add  x1,x11,:lo12:idxscan_buf
    mov  x2,x12
    mov  x3,x13
    mov  x8,#67
    svc  #0
    cmp  x0,#0
    b.le .ip_flush
    udiv x25,x0,x9              /* full records read */
    mov  x26,#0                 /* i */
.ip_scan:
    cmp  x26,x25
    b.ge .ip_afterscan
    mov  x9,x26
    mov  x11,#48
    mul  x9,x9,x11
    adrp x11,idxscan_buf
    add  x11,x11,:lo12:idxscan_buf
    ldr  w5,[x11,x9]
    cbz  w5,.ip_next
    add  x9,x23,x26             /* pos+i */
    str  x9,[sp]               /* running_tip */
    ldr  x9,[sp,#8]
    add  x9,x9,#1
    str  x9,[sp,#8]            /* running_present++ */
.ip_next:
    add  x26,x26,#1
    b    .ip_scan
.ip_afterscan:
    add  x23,x23,x25
    cmp  x25,x24
    b.lt .ip_flush
    b    .ip_loop
.ip_flush:
    ldr  x9,[sp]
    str  x9,[x19]
    ldr  x9,[sp,#8]
    str  x9,[x20]
.ip_close:
    mov  x0,x21
    mov  x8,#57
    svc  #0
.ip_ret:
    add  sp,sp,#0x10
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size idxscan_progress,.-idxscan_progress

/* ======= idxscan_append_locked / idxscan_append_nolocked (thin wrappers
 * over store_append_shared[_nolock], the bitcoinstore shared-append body not
 * yet ported). Forward to bitcoin_store.S when it exports those symbols. */

/* ======= idxscan_append_locked(st=x0, hash=x1, raw=x2, len=x3) -> h/-1/-2 =======
 * Acquires the st+40 append flock, computes the hole-aware true tip+1 under
 * it, checks the INCIDENT #46 linkage gate (the new block's prev=raw+4 must
 * equal the current tip's hash), then delegates the write to
 * store_append_shared. -2 = refused (not tip-linked), store untouched. */
    .global idxscan_append_locked
    .type idxscan_append_locked,%function
idxscan_append_locked:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    sub  sp,sp,#0x20            /* tip-hash scratch @[sp,#8] (32B), clear of saves */
    mov  x29,sp
    mov  x19,x0                /* st */
    mov  x20,x1                /* hash */
    mov  x21,x2                /* raw */
    mov  x22,x3                /* len */
    /* flock(st+40, LOCK_EX=2) if st+40 >= 0 */
    ldr  x9,[x19,#40]
    tbnz x9,#63,.al_nof
    mov  x0,x9
    mov  x8,#32                /* flock */
    mov  x1,#2                 /* LOCK_EX */
    svc  #0
.al_nof:
    bl   idxscan_tip           /* x0 = tip (-1 empty) */
    add  x23,x0,#1             /* height = tip+1 */
    mov  x24,x0                /* tip (for linkage) */
    cmp  x24,#-1
    b.eq .al_linked            /* empty: genesis bootstrap */
    /* pread idx_fd tip-hash (32B) at tip*48 */
    mov  x9,#48
    mul  x13,x24,x9            /* offset */
    ldr  x0,[x19,#8]           /* idx_fd */
    add  x1,sp,#8              /* scratch */
    mov  x2,#32
    mov  x3,x13
    mov  x8,#67                /* pread64 */
    svc  #0
    cmp  x0,#32
    b.ne .al_refuse
    /* compare [scratch] vs [raw+4] (prev field, 32B) */
    mov  x0,#0
.al_lc:
    cmp  x0,#32
    b.ge .al_linked
    add  x9,sp,#8
    ldrb w10,[x9,x0]
    add  x11,x21,#4
    ldrb w12,[x11,x0]
    cmp  w10,w12
    b.ne .al_refuse
    add  x0,x0,#1
    b    .al_lc
.al_linked:
    /* store_append_shared(st,height,hash,raw,len) */
    mov  x0,x19
    mov  x1,x23
    mov  x2,x20
    mov  x3,x21
    mov  x4,x22
    bl   store_append_shared
    cmp  x0,#-1
    b.eq .al_ret
    str  w0,[x19,#24]          /* tip_height = height */
    add  x9,x0,#1
    mov  x10,#48
    mul  x9,x9,x10
    str  x9,[x19,#16]          /* idx_len = (height+1)*48 */
    b    .al_ret
.al_refuse:
    /* release the flock we took (store_append_shared not called), report -2 */
    ldr  x9,[x19,#40]
    tbnz x9,#63,.al_refuse_done
    mov  x0,x9
    mov  x8,#32
    mov  x1,#8                 /* LOCK_UN */
    svc  #0
.al_refuse_done:
    mov  x0,#-2
.al_ret:
    add  sp,sp,#0x20
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size idxscan_append_locked,.-idxscan_append_locked

/* ======= idxscan_append_nolocked(st, hash, raw, len) -> height/-1 =======
 * Same minus all locking (caller already holds the flock); delegates to
 * store_append_shared_nolock. */
    .global idxscan_append_nolocked
    .type idxscan_append_nolocked,%function
idxscan_append_nolocked:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0
    mov  x20,x1
    mov  x21,x2
    mov  x22,x3
    bl   idxscan_tip
    add  x23,x0,#1             /* height = tip+1 */
    mov  x0,x19
    mov  x1,x23
    mov  x2,x20
    mov  x3,x21
    mov  x4,x22
    bl   store_append_shared_nolock
    cmp  x0,#-1
    b.eq .an_ret
    str  w0,[x19,#24]
    add  x9,x0,#1
    mov  x10,#48
    mul  x9,x9,x10
    str  x9,[x19,#16]
.an_ret:
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size idxscan_append_nolocked,.-idxscan_append_nolocked


    .section .note.GNU-stack,"",@progbits
