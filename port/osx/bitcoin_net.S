/* ============================================================================
 * bitcoin_net.S -- P2P wire framing and fd plumbing in AArch64 assembly
 * (Apple silicon), the counterpart of asm/bitcoin_net.asm. Replaces
 * net_twin.c on the Mac (2026-09-26); the twin stays in port/osx/test_support
 * as the oracle.
 *
 *   u32  net_magic = 0xd9b4bef9;   u8 g_v2_active[4096];
 *   void* g_p2p_write_hook;  (fd, u32 plen, const char* cmd, u32 cmdlen)
 *   void* g_p2p_read_hook;   (fd, const char* cmd, u32 announced)
 *   long (*g_v2_hook_write)(int, const char*, u32, const void*, u64);
 *   long (*g_v2_hook_read)(int, char cmd[12], void*, u64, u64);
 *
 *   long fd_write_all(int fd, const void* buf, u64 n);   n / -1
 *   long fd_read_full(int fd, void* buf, u64 n);  bytes (< n only on EOF) / -1
 *   void fd_close(int fd);
 *   long tcp_connect_ip(u32 ip, u16 port);    fd / the NEGATIVE errno
 *   u64  p2p_frame(u8* out, const char* cmd, u32 cmdlen, const void* payload,
 *                  u64 plen);                                  24 + plen
 *   long p2p_write(int fd, const char* cmd, u32 cmdlen, const void* payload,
 *                  u64 plen);                                  24 + plen / -1
 *   long p2p_read(int fd, char cmd[12], void* payload, u64 cap,
 *                 unsigned* plen_out);  1 / 0 / -1 / -2 trunc / -3 oversize
 *
 * The contracts are the x86's (see the twin's header for the history):
 * fd_write_all polls POLLOUT (10 s) before EVERY write; tcp_connect_ip sets
 * 10 s receive/send timeouts and bounds the connect itself with a
 * non-blocking connect + poll (Darwin does not apply SO_SNDTIMEO to
 * connect), back to blocking before returning, -ETIMEDOUT on expiry;
 * p2p_write calls the pacer hook first with FOUR arguments, then the v2
 * hook for a v2 fd, else writes the 24-byte header and the payload in two
 * writes; p2p_read dispatches v2 (the hook gets the plen_out POINTER), else
 * reads the header (magic mismatch = 0), refuses > 4,000,000 announced
 * before reading anything more (-3), verifies sha256d[0:4] only when the
 * whole payload fits in cap (an empty payload is checked), drains the
 * excess 64 bytes at a time, sets *plen_out after the drain, and then fires
 * the receive hook on 1 / -2. fcntl() is variadic: its third argument goes
 * on the stack (Darwin arm64).
 * ========================================================================== */
#define V2_FD_MAX    4096
#define P2P_MAX_MSG  4000000
#define SOL_SOCKET   0xffff
#define SO_SNDTIMEO  0x1005
#define SO_RCVTIMEO  0x1006
#define SO_ERROR     0x1007
#define F_GETFL      3
#define F_SETFL      4
#define O_NONBLOCK   4
#define EINPROGRESS  36
#define ETIMEDOUT    60
#define POLLOUT      4

    .text

/* fd_write_all(fd=w0, buf=x1, n=x2) ; fd x19, buf x20, n x21, done x22 ;
 * frame pollfd 0 (16) */
    .p2align 2
    .globl _fd_write_all
_fd_write_all:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #16
    mov   w19, w0
    mov   x20, x1
    mov   x21, x2
    mov   x22, #0
1:  cmp   x22, x21
    b.hs  3f
    str   w19, [sp]                       /* {fd, POLLOUT, 0} */
    mov   w9, #POLLOUT
    str   w9, [sp, #4]
    mov   x0, sp
    mov   w1, #1
    mov   w2, #10000
    bl    _poll
    cmp   w0, #0
    b.le  2f                              /* timeout or error */
    mov   w0, w19
    add   x1, x20, x22
    sub   x2, x21, x22
    bl    _write
    cmp   x0, #0
    b.le  2f
    add   x22, x22, x0
    b     1b
2:  mov   x0, #-1
    b     4f
3:  mov   x0, x22
4:  add   sp, sp, #16
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* fd_read_full(fd=w0, buf=x1, n=x2) ; fd x19, buf x20, n x21, got x22 */
    .p2align 2
    .globl _fd_read_full
_fd_read_full:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   w19, w0
    mov   x20, x1
    mov   x21, x2
    mov   x22, #0
1:  cmp   x22, x21
    b.hs  3f
    mov   w0, w19
    add   x1, x20, x22
    sub   x2, x21, x22
    bl    _read
    cmp   x0, #0
    b.lt  2f
    b.eq  3f                              /* EOF: what we have */
    add   x22, x22, x0
    b     1b
2:  mov   x0, #-1
    b     4f
3:  mov   x0, x22
4:  ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

    .p2align 2
    .globl _fd_close
_fd_close:
    b     _close

/* Lfcntl3(fd=w0, cmd=w1, arg=x2): fcntl with its variadic arg on the stack */
    .p2align 2
Lfcntl3:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    sub   sp, sp, #16
    str   x2, [sp]
    bl    _fcntl
    add   sp, sp, #16
    ldp   x29, x30, [sp], #16
    ret

/* Lerrno -> w0 = errno */
    .p2align 2
Lerrno:
    stp   x29, x30, [sp, #-16]!
    mov   x29, sp
    bl    ___error
    ldr   w0, [x0]
    ldp   x29, x30, [sp], #16
    ret

/* ============================================================================
 * tcp_connect_ip(ip=w0, port=w1)
 * ip x19, port x20, fd x21, flags x22, e x23 ; frame: tv 0 (16),
 * sockaddr 16 (16), pollfd 32 (8), e 40 (4), el 44 (4) -> 48
 * ========================================================================== */
    .p2align 2
    .globl _tcp_connect_ip
_tcp_connect_ip:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    str   x23, [sp, #48]
    mov   x29, sp
    sub   sp, sp, #48
    mov   w19, w0
    mov   w20, w1
    mov   w0, #2                          /* AF_INET */
    mov   w1, #1                          /* SOCK_STREAM */
    mov   w2, #0
    bl    _socket
    tbz   w0, #31, 1f
    bl    Lerrno
    neg   w0, w0
    sxtw  x0, w0
    b     Ltc_ret
1:  mov   w21, w0
    mov   x9, #10                         /* timeval {10, 0} */
    stp   x9, xzr, [sp]
    mov   w0, w21                         /* receive / send timeouts, best effort */
    mov   w1, #SOL_SOCKET
    mov   w2, #SO_RCVTIMEO
    mov   x3, sp
    mov   w4, #16
    bl    _setsockopt
    mov   w0, w21
    mov   w1, #SOL_SOCKET
    mov   w2, #SO_SNDTIMEO
    mov   x3, sp
    mov   w4, #16
    bl    _setsockopt
    stp   xzr, xzr, [sp, #16]             /* sockaddr_in: family, port, addr */
    mov   w9, #2
    strb  w9, [sp, #17]
    strh  w20, [sp, #18]                  /* already network order */
    str   w19, [sp, #20]
    mov   w0, w21
    mov   w1, #F_GETFL
    mov   x2, #0
    bl    Lfcntl3
    tbnz  w0, #31, 2f
    mov   w22, w0
    mov   w0, w21
    mov   w1, #F_SETFL
    orr   w2, w22, #O_NONBLOCK
    bl    Lfcntl3
    tbz   w0, #31, 3f
2:  bl    Lerrno                          /* fcntl failed */
    mov   w23, w0
    b     Ltc_fail
3:  mov   w23, #0
    mov   w0, w21
    add   x1, sp, #16
    mov   w2, #16
    bl    _connect
    tbz   w0, #31, 5f
    bl    Lerrno
    mov   w23, w0
    cmp   w23, #EINPROGRESS
    b.ne  5f
    str   w21, [sp, #32]                  /* wait for the connect, 10 s */
    mov   w9, #POLLOUT
    str   w9, [sp, #36]
    add   x0, sp, #32
    mov   w1, #1
    mov   w2, #10000
    bl    _poll
    cmp   w0, #0
    b.gt  4f
    mov   w23, #ETIMEDOUT
    b.eq  5f
    bl    Lerrno                          /* poll failed (EINTR: the dial budget) */
    mov   w23, w0
    b     5f
4:  str   w23, [sp, #40]                  /* SO_ERROR */
    mov   w9, #4
    str   w9, [sp, #44]
    mov   w0, w21
    mov   w1, #SOL_SOCKET
    mov   w2, #SO_ERROR
    add   x3, sp, #40
    add   x4, sp, #44
    bl    _getsockopt
    ldr   w23, [sp, #40]
    tbz   w0, #31, 5f
    bl    Lerrno
    mov   w23, w0
5:  cbnz  w23, Ltc_fail
    mov   w0, w21                         /* blocking again */
    mov   w1, #F_SETFL
    mov   w2, w22
    bl    Lfcntl3
    sxtw  x0, w21
    b     Ltc_ret
Ltc_fail:
    mov   w0, w21
    bl    _close
    neg   w0, w23
    sxtw  x0, w0                          /* the raw negative errno */
Ltc_ret:
    add   sp, sp, #48
    ldr   x23, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* Lhdr(out=x0, cmd=x1, cmdlen=w2, payload=x3, plen=x4): the 24-byte header
 * magic | cmd[12] zero-padded, cut at 12 | len u32 | sha256d(payload)[0:4]
 * out x19, plen x20, payload x21 ; frame digest 0 (32) */
    .p2align 2
Lhdr:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    sub   sp, sp, #32
    mov   x19, x0
    mov   x20, x4
    mov   x21, x3
    adrp  x9, _net_magic@PAGE
    ldr   w9, [x9, _net_magic@PAGEOFF]
    str   w9, [x19]
    stur  xzr, [x19, #4]
    stur  wzr, [x19, #12]
    mov   w9, #12
    cmp   w2, #12
    csel  w2, w2, w9, lo
    mov   x10, #0
1:  cmp   x10, x2                         /* the command, byte by byte */
    b.hs  2f
    ldrb  w11, [x1, x10]
    add   x12, x19, #4
    strb  w11, [x12, x10]
    add   x10, x10, #1
    b     1b
2:  str   w20, [x19, #16]
    mov   x0, sp
    mov   x1, x21
    mov   x2, x20
    bl    _sha256d
    ldr   w9, [sp]
    str   w9, [x19, #20]
    add   sp, sp, #32
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* p2p_frame(out=x0, cmd=x1, cmdlen=w2, payload=x3, plen=x4) ; out x19,
 * payload x20, plen x21 */
    .p2align 2
    .globl _p2p_frame
_p2p_frame:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    str   x21, [sp, #32]
    mov   x29, sp
    mov   x19, x0
    mov   x20, x3
    mov   x21, x4
    bl    Lhdr
    add   x0, x19, #24
    mov   x1, x20
    mov   x2, x21
    bl    _memcpy
    add   x0, x21, #24
    ldr   x21, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

/* ============================================================================
 * p2p_write(fd=w0, cmd=x1, cmdlen=w2, payload=x3, plen=x4)
 * fd x19, cmd x20, cmdlen x21, payload x22, plen x23 ; frame hdr 0 (32)
 * ========================================================================== */
    .p2align 2
    .globl _p2p_write
_p2p_write:
    stp   x29, x30, [sp, #-64]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    str   x23, [sp, #48]
    mov   x29, sp
    sub   sp, sp, #32
    mov   w19, w0
    mov   x20, x1
    mov   w21, w2
    mov   x22, x3
    mov   x23, x4
    adrp  x9, _g_p2p_write_hook@PAGE      /* the pacer hook: (fd, plen, cmd, cmdlen) */
    ldr   x9, [x9, _g_p2p_write_hook@PAGEOFF]
    cbz   x9, 1f
    mov   w0, w19
    mov   w1, w23
    mov   x2, x20
    mov   w3, w21
    blr   x9
1:  cmp   w19, #V2_FD_MAX                 /* a v2 fd with a write hook? */
    b.hs  2f
    adrp  x9, _g_v2_active@PAGE
    add   x9, x9, _g_v2_active@PAGEOFF
    ldrb  w9, [x9, w19, uxtw]
    cbz   w9, 2f
    adrp  x9, _g_v2_hook_write@PAGE
    ldr   x9, [x9, _g_v2_hook_write@PAGEOFF]
    cbz   x9, 2f
    mov   w0, w19
    mov   x1, x20
    mov   w2, w21
    mov   x3, x22
    mov   x4, x23
    blr   x9
    b     Lpw_ret
2:  mov   x0, sp                          /* v1: header, then payload */
    mov   x1, x20
    mov   w2, w21
    mov   x3, x22
    mov   x4, x23
    bl    Lhdr
    mov   w0, w19
    mov   x1, sp
    mov   x2, #24
    bl    _fd_write_all
    cmp   x0, #24
    b.ne  3f
    cbz   x23, 21f
    mov   w0, w19
    mov   x1, x22
    mov   x2, x23
    bl    _fd_write_all
    cmp   x0, x23
    b.ne  3f
21: add   x0, x23, #24
    b     Lpw_ret
3:  mov   x0, #-1
Lpw_ret:
    add   sp, sp, #32
    ldr   x23, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #64
    ret

/* ============================================================================
 * Lread_v1(fd=w0, cmd=x1, payload=x2, cap=x3, plen_out=x4)
 * fd x19, cmd x20, payload x21, cap x22, plen_out x23, announced x24,
 * remain x25 ; frame: hdr 0 (24), want 24 (32 digest), sink 64 (64) -> 128
 * ========================================================================== */
    .p2align 2
Lread_v1:
    stp   x29, x30, [sp, #-80]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    stp   x23, x24, [sp, #48]
    str   x25, [sp, #64]
    mov   x29, sp
    sub   sp, sp, #128
    mov   w19, w0
    mov   x20, x1
    mov   x21, x2
    mov   x22, x3
    mov   x23, x4
    mov   x1, sp
    mov   x2, #24
    bl    _fd_read_full
    cmp   x0, #24
    b.ne  Lrv_err
    ldr   w9, [sp]
    adrp  x10, _net_magic@PAGE
    ldr   w10, [x10, _net_magic@PAGEOFF]
    cmp   w9, w10
    b.ne  Lrv_zero                        /* the same exit as EOF */
    ldur  x9, [sp, #4]                    /* the command */
    str   x9, [x20]
    ldur  w9, [sp, #12]
    str   w9, [x20, #8]
    ldr   w24, [sp, #16]                  /* announced */
    movz  w9, #(P2P_MAX_MSG & 0xffff)
    movk  w9, #(P2P_MAX_MSG >> 16), lsl #16
    cmp   w24, w9
    b.hi  Lrv_over                        /* before any payload or drain */
    cmp   x24, x22
    csel  x2, x24, x22, lo                /* tocopy */
    mov   x25, x2
    mov   w0, w19
    mov   x1, x21
    bl    _fd_read_full
    cmp   x0, x25
    b.ne  Lrv_zero                        /* EOF / short */
    cmp   x24, x22
    b.hi  1f
    add   x0, sp, #24                     /* the whole payload: verify it */
    mov   x1, x21
    mov   x2, x24
    bl    _sha256d
    ldr   w9, [sp, #24]
    ldr   w10, [sp, #20]
    cmp   w9, w10
    b.ne  Lrv_zero                        /* bad checksum: Core drops the peer */
1:  sub   x25, x24, x25                   /* drain past cap, 64 at a time */
2:  cbz   x25, 3f
    mov   x9, #64
    cmp   x25, x9
    csel  x2, x25, x9, lo
    mov   w0, w19
    add   x1, sp, #64
    bl    _fd_read_full
    cmp   x0, #0
    b.le  3f                              /* the peer went: stop */
    sub   x25, x25, x0
    b     2b
3:  cbz   x23, 4f
    str   w24, [x23]                      /* after the drain */
4:  cmp   x24, x22
    mov   x0, #1
    mov   x9, #-2
    csel  x0, x9, x0, hi
    b     Lrv_ret
Lrv_over:
    mov   x0, #-3
    b     Lrv_ret
Lrv_err:
    mov   x0, #-1
    b     Lrv_ret
Lrv_zero:
    mov   x0, #0
Lrv_ret:
    add   sp, sp, #128
    ldr   x25, [sp, #64]
    ldp   x23, x24, [sp, #48]
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #80
    ret

/* p2p_read(fd=w0, cmd=x1, payload=x2, cap=x3, plen_out=x4)
 * fd x19, cmd x20, plen_out x21, r x22 */
    .p2align 2
    .globl _p2p_read
_p2p_read:
    stp   x29, x30, [sp, #-48]!
    stp   x19, x20, [sp, #16]
    stp   x21, x22, [sp, #32]
    mov   x29, sp
    mov   w19, w0
    mov   x20, x1
    mov   x21, x4
    cmp   w19, #V2_FD_MAX
    b.hs  1f
    adrp  x9, _g_v2_active@PAGE
    add   x9, x9, _g_v2_active@PAGEOFF
    ldrb  w9, [x9, w19, uxtw]
    cbz   w9, 1f
    adrp  x9, _g_v2_hook_read@PAGE
    ldr   x9, [x9, _g_v2_hook_read@PAGEOFF]
    cbz   x9, 1f
    blr   x9                              /* arguments unmoved: 5th = the pointer */
    b     2f
1:  mov   w0, w19
    bl    Lread_v1                        /* (x1..x4 unmoved) */
2:  mov   x22, x0
    cmp   x22, #1                         /* the receive hook, on 1 / -2 */
    ccmn  x22, #2, #4, ne
    b.ne  3f
    adrp  x9, _g_p2p_read_hook@PAGE
    ldr   x9, [x9, _g_p2p_read_hook@PAGEOFF]
    cbz   x9, 3f
    mov   w0, w19
    mov   x1, x20
    ldr   w2, [x21]
    blr   x9
3:  mov   x0, x22
    ldp   x21, x22, [sp, #32]
    ldp   x19, x20, [sp, #16]
    ldp   x29, x30, [sp], #48
    ret

    .data
    .p2align 2
    .globl _net_magic
_net_magic:
    .long 0xd9b4bef9

    .globl _g_p2p_write_hook
    .globl _g_p2p_read_hook
    .globl _g_v2_hook_write
    .globl _g_v2_hook_read
    .globl _g_v2_active
.zerofill __DATA,__bss,_g_p2p_write_hook,8,3
.zerofill __DATA,__bss,_g_p2p_read_hook,8,3
.zerofill __DATA,__bss,_g_v2_hook_write,8,3
.zerofill __DATA,__bss,_g_v2_hook_read,8,3
.zerofill __DATA,__bss,_g_v2_active,V2_FD_MAX,4
