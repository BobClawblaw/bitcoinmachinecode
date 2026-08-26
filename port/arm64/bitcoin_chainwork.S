/* bitcoin_chainwork.S -- AArch64 port of asm/bitcoin_chainwork.asm (AAPCS64).
 * Exports (x86-identical):
 *   void u256_div(u8 q[32], const u8 a[32], const u8 b[32])  q=floor(a/b)
 *   void block_work(u8 work[16], u32 bits)                   low 128 bits
 *   void chainwork_add(u8 out[16], const u8 a[16], const u8 b[16])
 *   long chainwork_cmp(const u8 a[16], const u8 b[16]) -> -1/0/1
 *   int store_chainwork_init/append/get_at/get_tip/reload/truncate
 * All 256-bit ints are 4x u64 LE limbs. Scratch only x0-x17 (x19 saved where
 * used). AArch64 syscalls: close=57 openat=56 lseek=62 pread64=67 pwrite64=68
 * ftruncate=46.
 */
    .text

/* ---------- compact_to_target_le(out=x0, bits=x1)  internal ---------- */
compact_to_target_le:
    str  xzr,[x0,#0]
    str  xzr,[x0,#8]
    str  xzr,[x0,#16]
    str  xzr,[x0,#24]
    lsr  x2,x1,#24            /* exponent */
    and  w3,w1,#0x00ffffff    /* mantissa */
    cmp  x2,#3
    b.lt .ctdone
    sub  x4,x2,#3             /* byte offset */
    cmp  x4,#29
    b.gt .ctdone
    ubfx w5,w3,#0,#8
    strb w5,[x0,x4]
    cmp  x4,#31
    b.hs .ctdone
    add  x6,x4,#1
    ubfx w5,w3,#8,#8
    strb w5,[x0,x6]
    cmp  x4,#30
    b.hs .ctdone
    add  x7,x4,#2
    ubfx w5,w3,#16,#8
    strb w5,[x0,x7]
.ctdone:
    ret

/* ---------- chainwork_add(out=x0,a=x1,b=x2)  leaf ---------- */
    .global chainwork_add
    .type chainwork_add,%function
chainwork_add:
    ldr  x4,[x1,#0]
    ldr  x5,[x2,#0]
    adds x5,x4,x5
    str  x5,[x0,#0]
    ldr  x4,[x1,#8]
    ldr  x5,[x2,#8]
    adc  x5,x4,x5
    str  x5,[x0,#8]
    ret
    .size chainwork_add,.-chainwork_add

/* ---------- u256_div(q=x0, a=x1, b=x2)  bit-serial restoring division ----------
 * frame 0xD0: x29/x30@0, x19@0x10. A@0x20 B@0x40 Q@0x60 R@0x80 S@0xB0 i@0xC8.
 * NO callee-saved clobber beyond x19: bases computed ad hoc (scratch only). */
    .global u256_div
    .type u256_div,%function
u256_div:
    sub  sp,sp,#0xD0
    stp  x29,x30,[sp,#0x00]
    str  x19,[sp,#0x10]
    mov  x19,x0                /* q_out */
    ldr  x8,[x1,#0];  str x8,[sp,#0x20]
    ldr  x8,[x1,#8];  str x8,[sp,#0x28]
    ldr  x8,[x1,#16]; str x8,[sp,#0x30]
    ldr  x8,[x1,#24]; str x8,[sp,#0x38]
    ldr  x8,[x2,#0];  str x8,[sp,#0x40]
    ldr  x8,[x2,#8];  str x8,[sp,#0x48]
    ldr  x8,[x2,#16]; str x8,[sp,#0x50]
    ldr  x8,[x2,#24]; str x8,[sp,#0x58]
    str  xzr,[sp,#0x60]; str xzr,[sp,#0x68]; str xzr,[sp,#0x70]; str xzr,[sp,#0x78]
    str  xzr,[sp,#0x80]; str xzr,[sp,#0x88]; str xzr,[sp,#0x90]; str xzr,[sp,#0x98]
    mov  x8,#255
    str  x8,[sp,#0xC8]          /* i */
.udloop:
    ldr  x8,[sp,#0xC8]          /* i */
    lsr  x9,x8,#6               /* limb */
    and  x10,x8,#63             /* bitpos */
    add  x16,sp,#0x20           /* A base */
    ldr  x14,[x16,x9,lsl#3]     /* A[limb] */
    lsrv x14,x14,x10
    and  x14,x14,#1             /* bit */

    /* shift R(left 1) with carry; COUT = old R3 bit63; inject bit into R0 */
    add  x16,sp,#0x80           /* R base */
    ldr  x0,[x16,#0]
    ldr  x1,[x16,#8]
    ldr  x2,[x16,#16]
    ldr  x3,[x16,#24]
    lsr  x11,x3,#63             /* COUT */
    lsl  x10,x0,#1
    orr  x10,x10,x14
    lsr  x4,x0,#63
    lsl  x5,x1,#1
    orr  x5,x5,x4
    lsr  x4,x1,#63
    lsl  x15,x2,#1
    orr  x15,x15,x4
    lsr  x4,x2,#63
    lsl  x17,x3,#1
    orr  x17,x17,x4
    str  x10,[x16,#0]
    str  x5,[x16,#8]
    str  x15,[x16,#16]
    str  x17,[x16,#24]

    /* speculative S = R - B ; CF_sub(borrow) -> x4 ; S at 0xB0 */
    add  x16,sp,#0x80           /* R base */
    add  x12,sp,#0x40           /* B base */
    ldr  x0,[x16,#0]
    ldr  x1,[x16,#8]
    ldr  x2,[x16,#16]
    ldr  x3,[x16,#24]
    ldr  x13,[x12,#0]
    subs x0,x0,x13
    str  x0,[sp,#0xA0]
    ldr  x13,[x12,#8]
    sbcs x1,x1,x13
    str  x1,[sp,#0xA8]
    ldr  x13,[x12,#16]
    sbcs x2,x2,x13
    str  x2,[sp,#0xB0]
    ldr  x13,[x12,#24]
    sbcs x3,x3,x13
    str  x3,[sp,#0xB8]
    cset x4,cc                  /* CF_sub = borrow */

    /* commit iff COUT(x11)!=0 OR CF_sub(x4)==0 ; skip iff COUT==0 && CF_sub==1 */
    cbz  x11,.ud_chk_sub
    b    .ud_commit
.ud_chk_sub:
    cbz  x4,.ud_commit
    b    .ud_no_commit
.ud_commit:
    add  x16,sp,#0x80           /* R base */
    ldr  x0,[sp,#0xA0]; str x0,[x16,#0]
    ldr  x1,[sp,#0xA8]; str x1,[x16,#8]
    ldr  x2,[sp,#0xB0]; str x2,[x16,#16]
    ldr  x3,[sp,#0xB8]; str x3,[x16,#24]
    /* note: S[3]@0xC8 read BEFORE touching i@0xC8 below */
    ldr  x8,[sp,#0xC8]          /* i */
    lsr  x9,x8,#6
    and  x10,x8,#63
    mov  x11,#1
    lsl  x11,x11,x10
    add  x16,sp,#0x60           /* Q base */
    ldr  x12,[x16,x9,lsl#3]
    orr  x12,x12,x11
    str  x12,[x16,x9,lsl#3]
.ud_no_commit:
    ldr  x8,[sp,#0xC8]
    cbz  x8,.uddone
    sub  x8,x8,#1
    str  x8,[sp,#0xC8]
    b    .udloop
.uddone:
    add  x16,sp,#0x60           /* Q base */
    ldr  x8,[x16,#0];  str x8,[x19,#0]
    ldr  x8,[x16,#8];  str x8,[x19,#8]
    ldr  x8,[x16,#16]; str x8,[x19,#16]
    ldr  x8,[x16,#24]; str x8,[x19,#24]
    ldr  x19,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0xD0
    ret
    .size u256_div,.-u256_div


/* ---------- block_work(work=x0, bits=x1) ----------
 * frame 0xA0: x29/x30@0 x19@0x10; target_le@0x20 notA@0x40 divB@0x60 q@0x80 */
    .global block_work
    .type block_work,%function
block_work:
    sub  sp,sp,#0xA0
    stp  x29,x30,[sp,#0x00]
    str  x19,[sp,#0x10]
    mov  x19,x0                /* work */
    mov  x2,x1                 /* bits */
    add  x0,sp,#0x20           /* target_le */
    mov  x1,x2
    bl   compact_to_target_le
    ldr  x8,[sp,#0x20]
    ldr  x9,[sp,#0x28]
    orr  x8,x8,x9
    ldr  x9,[sp,#0x30]
    orr  x8,x8,x9
    ldr  x9,[sp,#0x38]
    orr  x8,x8,x9
    cbz  x8,.bw_zero
    ldr  x8,[sp,#0x20]; mvn x8,x8; str x8,[sp,#0x40]
    ldr  x8,[sp,#0x28]; mvn x8,x8; str x8,[sp,#0x48]
    ldr  x8,[sp,#0x30]; mvn x8,x8; str x8,[sp,#0x50]
    ldr  x8,[sp,#0x38]; mvn x8,x8; str x8,[sp,#0x58]
    ldr  x8,[sp,#0x20]
    adds x8,x8,#1
    str  x8,[sp,#0x60]
    ldr  x9,[sp,#0x28]
    adcs x9,x9,xzr
    str  x9,[sp,#0x68]
    ldr  x10,[sp,#0x30]
    adcs x10,x10,xzr
    str  x10,[sp,#0x70]
    ldr  x11,[sp,#0x38]
    adcs x11,x11,xzr
    str  x11,[sp,#0x78]
    b.cs .bw_overflow
    add  x0,sp,#0x80
    add  x1,sp,#0x40
    add  x2,sp,#0x60
    bl   u256_div
    ldr  x8,[sp,#0x80]
    adds x8,x8,#1
    str  x8,[x19,#0]
    ldr  x9,[sp,#0x88]
    adc  x9,x9,xzr
    str  x9,[x19,#8]
    b    .bw_ret
.bw_zero:
    str  xzr,[x19,#0]
    str  xzr,[x19,#8]
    b    .bw_ret
.bw_overflow:
    mov  x8,#1
    str  x8,[x19,#0]
    str  xzr,[x19,#8]
.bw_ret:
    ldr  x19,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0xA0
    ret
    .size block_work,.-block_work

/* ---------- chainwork_cmp(a=x0,b=x1) -> -1/0/1 ---------- */
    .global chainwork_cmp
    .type chainwork_cmp,%function
chainwork_cmp:
    ldr  x4,[x0,#8]
    ldr  x5,[x1,#8]
    cmp  x4,x5
    b.hi .cc_gt
    b.lo .cc_lt
    ldr  x4,[x0,#0]
    ldr  x5,[x1,#0]
    cmp  x4,x5
    b.hi .cc_gt
    b.lo .cc_lt
    mov  w0,#0
    ret
.cc_gt:
    mov  w0,#1
    ret
.cc_lt:
    mov  x0,#-1
    ret
    .size chainwork_cmp,.-chainwork_cmp

/* ================= store_chainwork_* persistence ================= */
    .data
    .p2align 3
cw_fd:
    .quad -1
cw_cum:
    .quad 0,0
    .section .rodata
cwname:
    .asciz "chainwork.dat"
    .text

/* store_chainwork_init(st=x0) -> 1 / -1 (st ignored) */
    .global store_chainwork_init
    .type store_chainwork_init,%function
store_chainwork_init:
    stp  x29,x30,[sp,#-16]!
    mov  x29,sp
    adrp x6,cw_fd
    add  x6,x6,:lo12:cw_fd
    ldr  x8,[x6]
    cmp  x8,#0
    b.lt .si_open
    mov  x0,x8
    mov  x8,#57                /* close */
    svc  #0
    mov  x8,#-1
    str  x8,[x6]
.si_open:
    mov  x0,#-100              /* AT_FDCWD */
    adrp x1,cwname
    add  x1,x1,:lo12:cwname
    mov  x2,#(2|0x40)          /* O_RDWR|O_CREAT */
    mov  x3,#0x1a4             /* 0644 */
    mov  x8,#56                /* openat */
    svc  #0
    tbnz x0,#63,.si_fail
    adrp x6,cw_fd
    add  x6,x6,:lo12:cw_fd
    str  x0,[x6]
    adrp x7,cw_cum
    add  x7,x7,:lo12:cw_cum
    str  xzr,[x7,#0]
    str  xzr,[x7,#8]
    mov  w0,#1
    ldp  x29,x30,[sp],#16
    ret
.si_fail:
    mov  x0,#-1
    ldp  x29,x30,[sp],#16
    ret
    .size store_chainwork_init,.-store_chainwork_init

/* store_chainwork_get_tip(st=x0, out=x1) -> 1 */
    .global store_chainwork_get_tip
    .type store_chainwork_get_tip,%function
store_chainwork_get_tip:
    adrp x4,cw_cum
    add  x4,x4,:lo12:cw_cum
    ldr  x5,[x4]
    str  x5,[x1,#0]
    ldr  x5,[x4,#8]
    str  x5,[x1,#8]
    mov  w0,#1
    ret
    .size store_chainwork_get_tip,.-store_chainwork_get_tip

/* store_chainwork_append(st=x0, height=x1, work=x2) -> 1/-1
 * frame 0x50: x29/x30@0 x19/x20@0x10 x21/x22@0x20 prev_cum@0x30 new_cum@0x40 */
    .global store_chainwork_append
    .type store_chainwork_append,%function
store_chainwork_append:
    sub  sp,sp,#0x50
    stp  x29,x30,[sp,#0x00]
    stp  x19,x20,[sp,#0x10]
    stp  x21,x22,[sp,#0x20]
    mov  x29,sp
    mov  x19,x1                /* height */
    mov  x20,x2                /* work */
    adrp x6,cw_fd
    add  x6,x6,:lo12:cw_fd
    ldr  x12,[x6]
    cmp  x12,#0
    b.lt .sa_err
    cbz  x19,.sa_prev_zero
    mov  x0,x12
    add  x1,sp,#0x30           /* prev_cum */
    mov  x2,#16
    sub  x3,x19,#1
    lsl  x3,x3,#4
    mov  x8,#67                /* pread64 */
    svc  #0
    cmp  x0,#16
    b.ne .sa_err
    b    .sa_have_prev
.sa_prev_zero:
    str  xzr,[sp,#0x30]        /* height 0: prev cumulative is zero */
    str  xzr,[sp,#0x38]
.sa_have_prev:
    add  x0,sp,#0x40           /* new_cum */
    add  x1,sp,#0x30           /* prev_cum */
    mov  x2,x20
    bl   chainwork_add
    mov  x0,x12
    add  x1,sp,#0x40
    mov  x2,#16
    mov  x3,x19
    lsl  x3,x3,#4
    mov  x8,#68                /* pwrite64 */
    svc  #0
    cmp  x0,#16
    b.ne .sa_err
    adrp x7,cw_cum
    add  x7,x7,:lo12:cw_cum
    ldr  x8,[sp,#0x40]
    str  x8,[x7,#0]
    ldr  x8,[sp,#0x48]
    str  x8,[x7,#8]
    mov  w0,#1
    b    .sa_ret
.sa_err:
    mov  x0,#-1
.sa_ret:
    ldp  x21,x22,[sp,#0x20]
    ldp  x19,x20,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x50
    ret
    .size store_chainwork_append,.-store_chainwork_append

/* store_chainwork_get_at(st=x0, height=x1, out=x2) -> 1/-1 */
    .global store_chainwork_get_at
    .type store_chainwork_get_at,%function
store_chainwork_get_at:
    stp  x29,x30,[sp,#-16]!
    mov  x29,sp
    adrp x6,cw_fd
    add  x6,x6,:lo12:cw_fd
    ldr  x8,[x6]
    cmp  x8,#0
    b.lt .ga_fail
    mov  x3,x1
    lsl  x3,x3,#4              /* offset */
    mov  x0,x8                 /* fd */
    mov  x1,x2                 /* out */
    mov  x2,#16
    mov  x8,#67                /* pread64 */
    svc  #0
    cmp  x0,#16
    b.ne .ga_fail
    mov  w0,#1
    ldp  x29,x30,[sp],#16
    ret
.ga_fail:
    mov  x0,#-1
    ldp  x29,x30,[sp],#16
    ret
    .size store_chainwork_get_at,.-store_chainwork_get_at

/* store_chainwork_reload(st=x0) -> record count (>=0)/-1
 * frame 0x30: x29/x30@0, last@0x10 */
    .global store_chainwork_reload
    .type store_chainwork_reload,%function
store_chainwork_reload:
    sub  sp,sp,#0x30
    stp  x29,x30,[sp,#0x00]
    mov  x29,sp
    adrp x6,cw_fd
    add  x6,x6,:lo12:cw_fd
    ldr  x12,[x6]
    cmp  x12,#0
    b.lt .rl_fail
    mov  x0,x12
    mov  x1,#0
    mov  x2,#2                 /* SEEK_END */
    mov  x8,#62                /* lseek */
    svc  #0
    tbnz x0,#63,.rl_fail
    lsr  x13,x0,#4             /* n = size/16 (floor) */
    adrp x7,cw_cum
    add  x7,x7,:lo12:cw_cum
    str  xzr,[x7,#0]
    str  xzr,[x7,#8]
    cbz  x13,.rl_done
    mov  x0,x12
    add  x1,sp,#0x10           /* last */
    mov  x2,#16
    sub  x3,x13,#1
    lsl  x3,x3,#4
    mov  x8,#67                /* pread64 */
    svc  #0
    cmp  x0,#16
    b.ne .rl_fail
    ldr  x8,[sp,#0x10]
    str  x8,[x7,#0]
    ldr  x8,[sp,#0x18]
    str  x8,[x7,#8]
.rl_done:
    mov  x0,x13
    b    .rl_ret
.rl_fail:
    mov  x0,#-1
.rl_ret:
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x30
    ret
    .size store_chainwork_reload,.-store_chainwork_reload

/* store_chainwork_truncate(st=x0, target=x1) -> 1/-1
 * frame 0x10: x29/x30@0, x19 saved @0x10? -> frame 0x20 */
    .global store_chainwork_truncate
    .type store_chainwork_truncate,%function
store_chainwork_truncate:
    sub  sp,sp,#0x20
    stp  x29,x30,[sp,#0x00]
    str  x19,[sp,#0x10]
    mov  x29,sp
    mov  x19,x1                /* target_height */
    cmp  x19,#-1
    b.lt .tr_fail
    adrp x6,cw_fd
    add  x6,x6,:lo12:cw_fd
    ldr  x12,[x6]
    cmp  x12,#0
    b.lt .tr_fail
    mov  x0,#0
    bl   store_chainwork_reload
    cmp  x0,#-1
    b.eq .tr_fail
    add  x2,x19,#1             /* new_n = target+1 */
    cmp  x2,x0
    b.ge .tr_noop
    lsl  x2,x2,#4              /* offset = new_n*16 */
    mov  x0,x12
    mov  x1,x2
    mov  x8,#46                /* ftruncate */
    svc  #0
    tbnz x0,#63,.tr_fail
    mov  x0,#0
    bl   store_chainwork_reload
    cmp  x0,#-1
    b.eq .tr_fail
.tr_noop:
    mov  w0,#1
    b    .tr_ret
.tr_fail:
    mov  x0,#-1
.tr_ret:
    ldr  x19,[sp,#0x10]
    ldp  x29,x30,[sp,#0x00]
    add  sp,sp,#0x20
    ret
    .size store_chainwork_truncate,.-store_chainwork_truncate

    .section .note.GNU-stack,"",@progbits
