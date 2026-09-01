/* bitcoin_idx.S -- AArch64 port of asm/bitcoin_idx.asm (AAPCS64).
 * Persisted hash->height open-addressing index (power-of-2 slots, stride 48).
 * Layout: +0 n, +8 mask, +16 res, +24 array; slot[48] = [+0 height][+8 hash[32]]
 *         [+40 pad]; empty marker height == -1.
 * Exports: idx_init, idx_put(1/0/2), idx_get(1/0), idx_count,
 *          idx_build_from_file (openat=56 pread64=67 lseek=62 close=57).
 */
    .text

#define STRIDE 48
    .bss
    .p2align 4
idxbuild_buf:
    .space 4096*48        /* 192 KB read window */
    .text

/* ---------- idx_init(idx=x0, slots=x1) ---------- */
    .global idx_init
    .type idx_init,%function
idx_init:
    str  xzr,[x0,#0]
    sub  x9,x1,#1
    str  x9,[x0,#8]        /* mask = slots-1 */
    add  x10,x0,#24
    mov  x11,x1
    mov  x12,#-1
.ii_c:
    cbz  x11,.ii_d
    str  x12,[x10]
    add  x10,x10,#48
    sub  x11,x11,#1
    b    .ii_c
.ii_d:
    ret
    .size idx_init,.-idx_init

/* ---------- idx_hash(hash=x0, mask=x1) -> slot index (FNV-1a, 32B, XOR-fold) */
idx_hash:
    mov  w8,#0x9dc5
    movk w8,#0x811c,lsl#16   /* offset basis */
    mov  w9,#0x0193
    movk w9,#0x0100,lsl#16   /* prime */
    mov  x6,#0
.ih_l:
    cmp  x6,#32
    b.hs .ih_d
    ldrb w7,[x0,x6]
    eor  w8,w8,w7            /* FNV-1a: ^ byte then * prime */
    mul  w8,w8,w9
    add  x6,x6,#1
    b    .ih_l
.ih_d:
    lsr  w10,w8,#15
    eor  w8,w8,w10           /* XOR-fold */
    and  w8,w8,w1            /* mask (w write zero-extends x8) */
    mov  w0,w8
    ret

/* ---------- memcmp_exact(a=x0,b=x1,n=x2) -> 0 equal / 1 diff ---------- */
memcmp_exact:
    mov  x3,#0
.ce_c:
    cmp  x3,x2
    b.hs .ce_eq
    ldrb w4,[x0,x3]
    ldrb w5,[x1,x3]
    cmp  w4,w5
    b.ne .ce_ne
    add  x3,x3,#1
    b    .ce_c
.ce_eq:
    mov  w0,#0
    ret
.ce_ne:
    mov  w0,#1
    ret

/* ---------- memcpy_len(dst=x0, src=x1, n=x2) ---------- */
memcpy_len:
    mov  x3,#0
.cl_c:
    cmp  x3,x2
    b.hs .cl_d
    ldrb w4,[x1,x3]
    strb w4,[x0,x3]
    add  x3,x3,#1
    b    .cl_c
.cl_d:
    ret

/* ---------- idx_put(idx=x0, hash=x1, height=x2) -> 1/0/2 ---------- */
    .global idx_put
    .type idx_put,%function
idx_put:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0               /* idx */
    mov  x20,x1               /* hash */
    mov  x21,x2               /* height */
    mov  x0,x20
    ldr  x1,[x19,#8]
    bl   idx_hash
    mov  x22,x0               /* probe slot */
    ldr  x23,[x19,#8]
    add  x23,x23,#1           /* budget */
    add  x24,x19,#24          /* array base */
.ip_probe:
    mov  x9,x22
    mov  x10,#48
    mul  x9,x9,x10            /* offset = slot*48 */
    add  x8,x24,x9            /* &slot */
    ldr  x10,[x8]             /* height */
    cmn  x10,#1
    b.eq .ip_empty
    add  x0,x8,#8
    mov  x1,x20
    mov  x2,#32
    bl   memcmp_exact
    cbz  x0,.ip_dup
.ip_next:
    sub  x23,x23,#1
    cbz  x23,.ip_full
    add  x22,x22,#1
    ldr  x9,[x19,#8]
    and  x22,x22,x9           /* wrap */
    b    .ip_probe
.ip_empty:
    mov  x9,x22
    mov  x10,#48
    mul  x9,x9,x10
    add  x8,x24,x9
    str  x21,[x8]             /* height */
    add  x0,x8,#8
    mov  x1,x20
    mov  x2,#32
    bl   memcpy_len
    ldr  x9,[x19]
    add  x9,x9,#1
    str  x9,[x19]             /* n++ */
    mov  w0,#1
    b    .ip_done
.ip_dup:
    mov  w0,#0
    b    .ip_done
.ip_full:
    mov  w0,#2
.ip_done:
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size idx_put,.-idx_put

/* ---------- idx_get(idx=x0, hash=x1, height*=x2) -> 1/0 ---------- */
    .global idx_get
    .type idx_get,%function
idx_get:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    mov  x29,sp
    mov  x19,x0
    mov  x20,x1
    mov  x21,x2
    mov  x0,x20
    ldr  x1,[x19,#8]
    bl   idx_hash
    mov  x22,x0
    ldr  x23,[x19,#8]
    add  x23,x23,#1
    add  x24,x19,#24
.ig_probe:
    mov  x9,x22
    mov  x10,#48
    mul  x9,x9,x10
    add  x8,x24,x9
    ldr  x10,[x8]
    cmn  x10,#1
    b.eq .ig_miss
    add  x0,x8,#8
    mov  x1,x20
    mov  x2,#32
    bl   memcmp_exact
    cbz  x0,.ig_hit
.ig_next:
    sub  x23,x23,#1
    cbz  x23,.ig_miss
    add  x22,x22,#1
    ldr  x9,[x19,#8]
    and  x22,x22,x9
    b    .ig_probe
.ig_hit:
    mov  x9,x22
    mov  x10,#48
    mul  x9,x9,x10
    add  x8,x24,x9
    ldr  x10,[x8]
    str  x10,[x21]            /* *height */
    mov  w0,#1
    b    .ig_done
.ig_miss:
    mov  w0,#0
.ig_done:
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size idx_get,.-idx_get

/* ---------- idx_count(idx=x0) ---------- */
    .global idx_count
    .type idx_count,%function
idx_count:
    ldr  x0,[x0]
    ret
    .size idx_count,.-idx_count

/* ---------- idx_build_from_file(idx=x0, path=x1) -> 0 / -1 ----------
 * Bulk-loads idx from a positional index.dat (48-byte records: presence =
 * first 4 bytes non-zero, hash stored in WIRE (raw sha256d) order at
 * rec[0..31]) and idx_puts each present record's hash UNCHANGED -- the serve
 * loop looks up with the hash as it arrives on the p2p wire, so the table
 * must be keyed the same way. (Port of x86 f80d09e: the loader used to
 * byte-reverse every record "into wire order" on the belief that the file
 * held DISPLAY order, keying the table backwards from every consumer.)
 * persistents: x19 idx, x20 fd, x21 total records (n), x22 pos, x23 full-records.
 * loop counter i in stack [sp+#0x28]. */
    .global idx_build_from_file
    .type idx_build_from_file,%function
idx_build_from_file:
    sub  sp,sp,#0x70
    stp  x29,x30,[sp,#0x00]
    stp  x19,x20,[sp,#0x10]
    stp  x21,x22,[sp,#0x20]
    stp  x23,x24,[sp,#0x30]
    mov  x29,sp
    mov  x19,x0               /* idx */
    /* open(path, O_RDONLY) */
    mov  x0,#-100             /* AT_FDCWD */
    mov  x1,x1                /* path */
    mov  x2,#0                /* O_RDONLY */
    mov  x8,#56               /* openat */
    svc  #0
    tbnz x0,#63,.ibf_fail
    mov  x20,x0               /* fd */
    mov  x0,x20
    mov  x1,#0
    mov  x2,#2                /* SEEK_END */
    mov  x8,#62               /* lseek */
    svc  #0
    tbnz x0,#63,.ibf_close_fail
    mov  x9,#48
    udiv x21,x0,x9            /* n = size/48 */
    mov  x22,#0               /* pos */
.ibf_outer:
    cmp  x22,x21
    b.ge .ibf_close_ok
    sub  x10,x21,x22          /* remaining */
    mov  x11,#4096
    cmp  x10,x11
    csel x10,x10,x11,lt      /* take = min(remaining, 4096) */
    mov  x12,x10
    mov  x13,#48
    mul  x12,x12,x13          /* count = take*48 */
    mov  x13,x22
    mov  x14,#48
    mul  x13,x13,x14          /* offset = pos*48 */
    mov  x0,x20
    adrp x14,idxbuild_buf
    add  x1,x14,:lo12:idxbuild_buf
    mov  x2,x12
    mov  x3,x13               /* pread64(fd,buf,count,offset) */
    mov  x8,#67
    svc  #0
    cmp  x0,#0
    b.le .ibf_close_ok
    mov  x15,x0               /* bytes read */
    mov  x9,#48
    udiv x23,x15,x9           /* full records */
    str  xzr,[sp,#0x60]       /* i = 0 */
.ibf_scanrec:
    ldr  x8,[sp,#0x60]        /* i */
    cmp  x8,x23
    b.ge .ibf_afterscan
    mov  x9,#48
    mul  x9,x9,x8
    adrp x14,idxbuild_buf
    add  x14,x14,:lo12:idxbuild_buf
    add  x14,x14,x9           /* record ptr */
    ldr  w5,[x14]
    cbz  w5,.ibf_nextrec      /* hole: skip */
    /* NO byte reversal: index.dat holds WIRE (raw sha256d) order -- verified
     * against the production archive (record 0 = genesis as 6fe28c0a..., the
     * exact reverse of its display form). x86 f80d09e. idx_put receives the
     * record hash as stored; x14 is re-derived at the top of every iteration,
     * so handing it across idx_put is safe. */
    ldr  x8,[sp,#0x60]
    add  x24,x22,x8           /* height = pos + i */
    mov  x0,x19
    mov  x1,x14               /* record hash, as stored (wire order) */
    mov  x2,x24
    bl   idx_put
.ibf_nextrec:
    ldr  x8,[sp,#0x60]
    add  x8,x8,#1
    str  x8,[sp,#0x60]
    b    .ibf_scanrec
.ibf_afterscan:
    add  x22,x22,x23
    cmp  x23,#4096
    b.lt .ibf_close_ok
    b    .ibf_outer
.ibf_close_ok:
    mov  x0,x20
    mov  x8,#57               /* close */
    svc  #0
    mov  w0,#0
    b    .ibf_ret
.ibf_close_fail:
    mov  x0,x20
    mov  x8,#57
    svc  #0
.ibf_fail:
    mov  x0,#-1
.ibf_ret:
    ldp  x23,x24,[sp,#0x30]
    ldp  x21,x22,[sp,#0x20]
    ldp  x19,x20,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x70
    ret
    .size idx_build_from_file,.-idx_build_from_file

    .section .note.GNU-stack,"",@progbits
