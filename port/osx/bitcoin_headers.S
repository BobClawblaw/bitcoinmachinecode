/* ============================================================================
 * bitcoin_headers.S -- header chain store in AArch64 assembly (Apple
 * silicon), the counterpart of asm/bitcoin_headers.asm. Replaces
 * headers_twin.c on the Mac (2026-09-26); the twin stays in
 * port/osx/test_support as the oracle.
 *
 * hst struct: +0 fd (i64), +8 count (u64).
 * File "headers.dat" (cwd): 112-byte records = header[80] || hash[32].
 *
 *   long hst_init(void* hst);                  1 ok / -1 (open failed)
 *   long hst_reload(void* hst);                1 ok / -1; count = size / 112
 *   long hst_append(void* hst, const u8 hdr[80], const u8 hash[32]);
 *                                              the new count / -1
 *   long hst_count(void* hst);
 *   long hst_get_at(void* hst, u64 height, void* out112);  1 / 0 (oor) / -1
 *
 * Through libc (open/lseek/write/pread), as the twin: the x86 issues the
 * syscalls itself, which Darwin does not support as an ABI. open() is
 * variadic, and Apple's arm64 ABI passes variadic arguments on the STACK:
 * the mode goes at [sp], not in w2.
 * ========================================================================== */
#define O_RDWR   0x0002
#define O_CREAT  0x0200
#define SEEK_SET 0
#define SEEK_END 2

    .text

/* hst_init(hst=x0) */
    .p2align 2
    .globl _hst_init
_hst_init:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #16
    mov   x19, x0
    adrp  x0, Lhdr_path@PAGE
    add   x0, x0, Lhdr_path@PAGEOFF
    mov   w1, #(O_RDWR | O_CREAT)
    mov   x9, #0644
    str   x9, [sp]                        /* variadic mode: on the stack */
    bl    _open
    add   sp, sp, #16
    tbnz  w0, #31, 1f
    sxtw  x0, w0
    stp   x0, xzr, [x19]                  /* fd, count = 0 */
    mov   x0, #1
    b     2f
1:  mov   x0, #-1
2:  ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* hst_reload(hst=x0) */
    .p2align 2
    .globl _hst_reload
_hst_reload:
    stp   x29, x30, [sp, #-32]!
    str   x19, [sp, #16]
    mov   x29, sp
    mov   x19, x0
    ldr   w0, [x19]                       /* (int) fd */
    mov   x1, #0
    mov   w2, #SEEK_END
    bl    _lseek
    tbnz  x0, #63, 1f
    mov   x9, #112
    udiv  x0, x0, x9
    str   x0, [x19, #8]
    mov   x0, #1
    b     2f
1:  mov   x0, #-1
2:  ldr   x19, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

/* hst_append(hst=x0, hdr=x1, hash=x2) ; frame rec 0 (112 -> 128) */
    .p2align 2
    .globl _hst_append
_hst_append:
    stp   x29, x30, [sp, #-32]!
    stp   x19, x20, [sp, #16]
    mov   x29, sp
    sub   sp, sp, #128
    mov   x19, x0
    ldp   q0, q1, [x1]                    /* rec = hdr[80] || hash[32] */
    ldr   q2, [x1, #32]
    ldp   q3, q4, [x1, #48]               /* bytes 48..79 */
    stp   q0, q1, [sp]
    str   q2, [sp, #32]
    stp   q3, q4, [sp, #48]
    ldp   q0, q1, [x2]
    stp   q0, q1, [sp, #80]
    ldr   w0, [x19]
    ldr   x20, [x19, #8]                  /* count */
    mov   x9, #112
    mul   x1, x20, x9
    mov   w2, #SEEK_SET
    bl    _lseek
    tbnz  x0, #63, 1f
    ldr   w0, [x19]
    mov   x1, sp
    mov   x2, #112
    bl    _write
    cmp   x0, #112
    b.ne  1f
    add   x0, x20, #1
    str   x0, [x19, #8]                   /* the new count, returned */
    b     2f
1:  mov   x0, #-1
2:  add   sp, sp, #128
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #32
    ret

    .p2align 2
    .globl _hst_count
_hst_count:
    ldr   x0, [x0, #8]
    ret

/* hst_get_at(hst=x0, height=x1, out=x2) */
    .p2align 2
    .globl _hst_get_at
_hst_get_at:
    ldr   x9, [x0, #8]
    cmp   x1, x9
    b.hs  1f                              /* height >= count: 0 */
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    mov   x9, #112
    mul   x3, x1, x9                      /* offset */
    mov   x1, x2
    mov   x2, #112
    ldr   w0, [x0]
    bl    _pread
    cmp   x0, #112
    mov   x0, #1
    mov   x9, #-1
    csel  x0, x0, x9, eq
    ldp   x29, x30, [sp], #16
    ret
1:  mov   x0, #0
    ret

    .section __TEXT,__cstring
Lhdr_path:
    .asciz "headers.dat"
