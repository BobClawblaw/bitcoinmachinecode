/* ============================================================================
 * net_twin.c -- BIP314 wire framing + fd plumbing for the macOS/AArch64 port.
 * Functional twin of asm/bitcoin_net.asm (branch bmc_osx).
 *
 *   extern u32 net_magic;                       0xd9b4bef9
 *   extern u8  g_v2_active[4096];
 *   extern void *g_p2p_write_hook;  (*)(int fd, u32 plen)
 *   extern long (*g_v2_hook_write)(int, const char*, u32, const void*, u64);
 *   extern long (*g_v2_hook_read)(int, char cmd_out[12], void*, u64, u64);
 *
 *   long fd_write_all(int fd, const void *buf, u64 n);
 *   long fd_read_full(int fd, void *buf, u64 n);
 *   void fd_close(int fd);
 *   long tcp_connect_ip(u32 ip, u16 port);
 *   u64  p2p_frame(u8 *out, const char *cmd, u32 cmdlen, const void *payload,
 *                  u64 plen);
 *   long p2p_write(int fd, const char *cmd, u32 cmdlen, const void *payload,
 *                  u64 plen);
 *   long p2p_read(int fd, char cmd_out[12], void *payload, u64 cap,
 *                 unsigned *plen_out);
 *
 * Contracts mirror the x86 asm exactly (see asm/bitcoin_net.asm):
 *   - fd_write_all: poll(POLLOUT, 10s) before EVERY write; -1 on poll
 *     failure/timeout or write error; returns bytes written (== n on success).
 *   - fd_read_full: loops read(); returns total read (< n only on EOF);
 *     -1 on error. EOF is 0 when nothing was read yet.
 *   - tcp_connect_ip: 10s SO_RCVTIMEO/SO_SNDTIMEO; returns fd, or the raw
 *     NEGATIVE errno on socket/connect failure (x86 keeps -errno for
 *     diagnosis) -- callers treat any <0 as a failed dial.
 *   - p2p_write: upload-pacer hook FIRST (g_p2p_write_hook, v1+v2 alike),
 *     then v2 dispatch, then v1: 24-byte header || payload in TWO writes;
 *     total = 24+plen, -1 on short write.
 *   - p2p_read: v2 dispatch (hook gets the plen_out POINTER as 5th arg),
 *     else v1: read 24B header; magic mismatch -> 0 (same exit as EOF);
 *     announced > P2P_MAX_MSG (4000000) -> -3 WITHOUT reading payload or
 *     draining (audit 2026-08-29 finding 6); payload read; checksum
 *     sha256d(payload)[0:4] verified ONLY when announced <= cap (a digest
 *     over a truncated prefix would always mismatch) -- empty payload IS
 *     checked; excess drained 64B at a time (short drain = peer gone, stop);
 *     *plen_out = announced AFTER the drain, on the success/trunc paths only;
 *     returns 1 ok / 0 eof-or-bad-magic-or-short-read / -1 err / -2 trunc.
 *
 * sha256d comes from port/osx/bitcoin_hash.o (native, gated separately).
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef unsigned char u8;

extern void sha256d(u8 out[32], const void *msg, long len);

/* ---- data symbols (section .data on x86; writable here) ---- */
u32 net_magic = 0xd9b4bef9u;

#define V2_FD_MAX 4096
u8 g_v2_active[V2_FD_MAX];

void *g_p2p_write_hook;   /* void (*)(int fd, u32 plen) */
long (*g_v2_hook_write)(int, const char *, u32, const void *, u64);
long (*g_v2_hook_read)(int, char cmd_out[12], void *, u64, u64);

#define P2P_MAX_MSG 4000000u

/* ---------------------------------------------------------------------------
 * fd_write_all(fd, buf, n) -> n on success, -1 on error/timeout
 * poll(POLLOUT, 10s) before every write: a peer that stops reading must not
 * hold a blocking write() forever (x86 comment: dead Tor circuit / stalled
 * subscriber). 0 = poll timeout, <0 = poll error: both are failed writes.
 * ------------------------------------------------------------------------- */
long fd_write_all(int fd, const void *buf, u64 n)
{
    const u8 *p = (const u8 *)buf;
    u64 done = 0;
    while (done < n) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        long pr = poll(&pfd, 1, 10000);
        if (pr <= 0) return -1;
        ssize_t w = write(fd, p + done, n - done);
        if (w <= 0) return -1;
        done += (u64)w;
    }
    return (long)done;
}

/* ---------------------------------------------------------------------------
 * fd_read_full(fd, buf, n) -> bytes read (< n only on EOF), -1 on error
 * ------------------------------------------------------------------------- */
long fd_read_full(int fd, void *buf, u64 n)
{
    u8 *p = (u8 *)buf;
    u64 got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r > 0) { got += (u64)r; continue; }
        if (r == 0) return (long)got;        /* EOF: partial */
        return -1;
    }
    return (long)got;
}

void fd_close(int fd) { close(fd); }

/* ---------------------------------------------------------------------------
 * tcp_connect_ip(ip, port): ip and port both in NETWORK byte order (x86
 * stores them into sockaddr_in verbatim). 10s SO_RCVTIMEO bounds a peer that
 * stops replying (2026-08-15 live-IBD finding); 10s SO_SNDTIMEO bounds the
 * blocking connect() itself (2026-08-31 / 2026-09-01 dial-wedge findings).
 * setsockopt errors are ignored (best-effort, as on x86).
 * Return: fd, or the raw negative errno from socket()/connect().
 * ------------------------------------------------------------------------- */
long tcp_connect_ip(u32 ip, u16 port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -(long)errno;
    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = port;                       /* already network order */
    sa.sin_addr.s_addr = ip;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        int e = errno;
        close(fd);
        return -(long)e;                      /* x86 returns the raw -errno */
    }
    return fd;
}

/* ---------------------------------------------------------------------------
 * cksum4(out4, payload, plen): sha256d(payload)[0:4]
 * ------------------------------------------------------------------------- */
static void cksum4(u8 out[4], const void *p, u64 n)
{
    u8 d[32];
    sha256d(d, p, (long)n);
    memcpy(out, d, 4);
}

/* ---------------------------------------------------------------------------
 * p2p_frame(out, cmd, cmdlen, payload, plen) -> 24+plen
 * magic | cmd[12] (zero-padded, truncated at 12) | len LE | sha256d[0:4] | pl
 * ------------------------------------------------------------------------- */
u64 p2p_frame(u8 *out, const char *cmd, u32 cmdlen, const void *payload, u64 plen)
{
    u32 magic = net_magic;
    memcpy(out + 0, &magic, 4);
    memset(out + 4, 0, 12);
    memcpy(out + 4, cmd, cmdlen < 12 ? cmdlen : 12);
    u32 len32 = (u32)plen;
    memcpy(out + 16, &len32, 4);
    cksum4(out + 20, payload, plen);
    memcpy(out + 24, payload, plen);
    return plen + 24;
}

/* ---------------------------------------------------------------------------
 * p2p_write(fd, cmd, cmdlen, payload, plen) -> 24+plen sent, or -1
 * pacer hook first (v1+v2 alike), v2 dispatch, then v1: header and payload
 * in TWO fd_write_all calls (x86 writes no big intermediate copy -- the twin
 * keeps that shape rather than p2p_frame+single-write).
 * ------------------------------------------------------------------------- */
long p2p_write(int fd, const char *cmd, u32 cmdlen, const void *payload, u64 plen)
{
    if (g_p2p_write_hook) {
        void (*fn)(int, u32) = (void (*)(int, u32))g_p2p_write_hook;
        fn(fd, (u32)plen);
    }
    if ((unsigned)fd < V2_FD_MAX && g_v2_active[fd]) {
        if (g_v2_hook_write) {
            long (*fn)(int, const char *, u32, const void *, u64) =
                (long (*)(int, const char *, u32, const void *, u64))g_v2_hook_write;
            return fn(fd, cmd, cmdlen, payload, plen);
        }
    }
    u8 hdr[24];
    u32 magic = net_magic;
    memcpy(hdr + 0, &magic, 4);
    memset(hdr + 4, 0, 12);
    memcpy(hdr + 4, cmd, cmdlen < 12 ? cmdlen : 12);
    u32 len32 = (u32)plen;
    memcpy(hdr + 16, &len32, 4);
    cksum4(hdr + 20, payload, plen);
    if (fd_write_all(fd, hdr, 24) != 24) return -1;
    if (plen && fd_write_all(fd, payload, plen) != (long)plen) return -1;
    return (long)(plen + 24);
}

/* ---------------------------------------------------------------------------
 * p2p_read(fd, cmd_out[12], payload, cap, plen_out) -> 1 ok / 0 eof / -1 err
 *                                                           / -2 trunc / -3 oversize
 * ------------------------------------------------------------------------- */
long p2p_read(int fd, char cmd_out[12], void *payload, u64 cap, unsigned *plen_out)
{
    if ((unsigned)fd < V2_FD_MAX && g_v2_active[fd]) {
        if (g_v2_hook_read) {
            long (*fn)(int, char *, void *, u64, u64) =
                (long (*)(int, char *, void *, u64, u64))g_v2_hook_read;
            /* x86 tail-calls with the ARGUMENTS UNMOVED: 5th arg is the
             * plen_out pointer itself, not *plen_out. */
            return fn(fd, cmd_out, payload, cap, (u64)plen_out);
        }
    }
    u8 hdr[24];
    if (fd_read_full(fd, hdr, 24) != 24) return -1;
    u32 magic;
    memcpy(&magic, hdr + 0, 4);
    if (magic != net_magic) return 0;         /* x86: same exit as EOF */
    memcpy(cmd_out, hdr + 4, 12);
    u32 announced;
    memcpy(&announced, hdr + 16, 4);
    if (announced > P2P_MAX_MSG) return -3;   /* oversize: BEFORE payload/drain */
    u64 tocopy = announced < cap ? announced : cap;
    if (fd_read_full(fd, payload, tocopy) != (long)tocopy) return 0; /* eof/short */
    if (announced <= cap) {                   /* NET-11: whole payload kept */
        u8 want[4];
        cksum4(want, payload, announced);     /* empty payload IS checked */
        if (memcmp(want, hdr + 20, 4) != 0) return 0;   /* Core: drop peer */
    }
    u64 remain = announced - tocopy;          /* drain beyond cap, 64B chunks */
    u8 sink[64];
    while (remain) {
        u64 chunk = remain < sizeof sink ? remain : sizeof sink;
        long got = fd_read_full(fd, sink, chunk);
        if (got <= 0) break;                  /* peer closed: stop draining */
        remain -= (u64)got;
    }
    if (plen_out) *plen_out = announced;      /* x86 reports AFTER the drain */
    return announced > cap ? -2 : 1;
}
