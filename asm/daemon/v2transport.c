/* daemon/v2transport.c -- BIP324 v2 transport bound to live sockets.
 *
 * WHY THE DISPATCH IS KEYED BY FILE DESCRIPTOR. p2p_read and p2p_write are
 * called from around sixty files and several hundred call sites. Threading a
 * transport handle through all of them would be a enormous change to every
 * networking path in the node for the sake of one feature. Instead
 * bitcoin_net.asm keeps a per-fd flag table and two function pointers; an fd
 * that has completed a handshake is flagged, and those two functions land
 * here. Callers see the same ABI and the same return values, and a build that
 * never links this file leaves the hooks NULL and behaves exactly as before.
 *
 * WHAT THE WRITE HOOK RETURNS. v1's p2p_write returns 24 + payload length,
 * and callers depend on that shape -- reorg.c treats a result below 24 as a
 * failure, and a v2 packet for an empty payload is only 20 bytes on the wire.
 * So this returns the v1 length too. It is a success indicator in the units
 * the callers already speak, not a byte count; the real v2 wire size is
 * different and nothing above this layer has any business knowing it.
 *
 * FALLBACK IS ASYMMETRIC. A responder can tell v1 from v2 in-band: a v1 peer
 * opens with magic + "version" + five NULs, and any mismatch in those 16 bytes
 * proves v2. Accepting inbound v2 therefore costs a v1 peer nothing, because
 * the detection peeks and leaves the socket untouched (see the peek phase in
 * bmc_v2_handshake -- consuming those bytes eats the peer's version message
 * and the connection dies on a timeout). An initiator has no such luxury: it has
 * already sent 64 bytes that a v1 peer will reject as a bad network magic, so
 * a failed outbound v2 attempt means closing the socket and redialling as v1.
 * That is why outbound v2 is only attempted against peers that advertise the
 * service bit.
 */
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>            /* NET-2: a real-time deadline on the handshake */
#include <sys/socket.h>
#include "v2transport.h"
#include "../crypto_bip324_transport.h"
#include "../crypto_ellswift.h"

#define V2_FD_MAX 4096

/* filled in by us, read by bitcoin_net.asm's p2p_read/p2p_write */
extern unsigned char g_v2_active[V2_FD_MAX];
extern long (*g_v2_hook_write)(int, const char*, unsigned, const void*, unsigned);
extern int  (*g_v2_hook_read)(int, char*, void*, unsigned, unsigned*);
extern unsigned int net_magic;

typedef struct {
    bip324_transport_t t;
    /* A message the transport produced that the caller has not collected.
     * p2p_read hands back one message per call, and a single socket read can
     * yield several packets, so the surplus has to wait somewhere. */
    unsigned char* held;
    unsigned long  held_len;
    char           held_cmd[13];
    int            has_held;
} v2_conn;

static v2_conn* g_conn[V2_FD_MAX];
int bmc_v2_is_active(int fd);
static unsigned g_garbage_max = 512;

void bmc_v2_set_garbage_max(unsigned max){
    g_garbage_max = max > BIP324_MAX_GARBAGE_LEN ? BIP324_MAX_GARBAGE_LEN : max;
}
int bmc_v2_session_id(int fd, unsigned char out32[32]){
    if (!bmc_v2_is_active(fd)) return 0;
    memcpy(out32, g_conn[fd]->t.cipher.session_id, 32);
    return 1;
}
int bmc_v2_is_active(int fd){
    return fd >= 0 && fd < V2_FD_MAX && g_v2_active[fd] && g_conn[fd];
}

/* ------------------------------- entropy --------------------------------- */

/* The ellswift encoding is only indistinguishable from random if the choice
 * among the many valid encodings is itself random. A deterministic pick would
 * make every connection from this node carry the same encoding for the same
 * key, which is a fingerprint. So this fails rather than fall back to
 * anything weaker. */
static int fill_random(unsigned char* p, unsigned long n){
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    unsigned long got = 0;
    while (got < n){
        ssize_t r = read(fd, p + got, n - got);
        if (r <= 0){ close(fd); return 0; }
        got += (unsigned long)r;
    }
    close(fd);
    return 1;
}

/* ------------------------------ socket I/O ------------------------------- */

static int write_all(int fd, const unsigned char* p, unsigned long n){
    unsigned long off = 0;
    while (off < n){
        ssize_t w = send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (w > 0){ off += (unsigned long)w; continue; }
        if (w < 0 && (errno == EINTR)) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)){
            struct pollfd pf = { fd, POLLOUT, 0 };
            if (poll(&pf, 1, 5000) <= 0) return 0;
            continue;
        }
        return 0;
    }
    return 1;
}

/* push whatever the transport wants to send */
static int flush_send(int fd, bip324_transport_t* t){
    unsigned long n;
    const unsigned char* p = bip324_t_send_pending(t, &n);
    if (!n) return 1;
    unsigned char* copy = (unsigned char*)malloc(n);
    if (!copy) return 0;
    memcpy(copy, p, n);
    bip324_t_send_consume(t, n);
    int ok = write_all(fd, copy, n);
    free(copy);
    return ok;
}

/* ------------------------------- handshake ------------------------------- */

static void conn_free(int fd){
    v2_conn* c = g_conn[fd];
    if (!c) return;
    bip324_t_free(&c->t);
    free(c->held);
    memset(c, 0, sizeof *c);
    free(c);
    g_conn[fd] = 0;
}

void bmc_v2_close(int fd){
    if (fd < 0 || fd >= V2_FD_MAX) return;
    g_v2_active[fd] = 0;
    conn_free(fd);
}

static long v2_write_hook(int fd, const char* cmd, unsigned cmdlen,
                          const void* payload, unsigned plen);
static int  v2_read_hook(int fd, char* cmd_out, void* payload,
                         unsigned cap, unsigned* plen_out);

static void install_hooks(void){
    g_v2_hook_write = v2_write_hook;
    g_v2_hook_read  = v2_read_hook;
}

/* NET-2: elapsed wall time since t0, against the handshake budget. */
static int hs_deadline_passed(const struct timespec* t0, int timeout_ms){
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long ms = (long)(now.tv_sec - t0->tv_sec) * 1000L
            + (long)(now.tv_nsec - t0->tv_nsec) / 1000000L;
    return ms >= (long)timeout_ms;
}

int bmc_v2_handshake(int fd, int initiator, int timeout_ms){
    if (fd < 0 || fd >= V2_FD_MAX) return -1;
    bmc_v2_close(fd);                       /* never inherit a stale session */

    unsigned char seckey[32], ellswift[64], rnd[32];
    unsigned char garbage[BIP324_MAX_GARBAGE_LEN];
    unsigned char lenpick[2];
    if (!fill_random(seckey, sizeof seckey)) return -1;
    if (!fill_random(rnd, sizeof rnd)) return -1;
    if (!fill_random(lenpick, sizeof lenpick)) return -1;
    seckey[0] &= 0x7f;                      /* keep it below the group order */
    if (!seckey[0] && !seckey[1]) seckey[1] = 1;

    unsigned long glen = 0;
    if (g_garbage_max){
        glen = ((unsigned long)lenpick[0] | ((unsigned long)lenpick[1] << 8)) % (g_garbage_max + 1);
        if (glen && !fill_random(garbage, glen)) return -1;
    }
    if (!ellswift_create(ellswift, seckey, rnd, sizeof rnd)) return -1;

    v2_conn* c = (v2_conn*)calloc(1, sizeof *c);
    if (!c) return -1;
    unsigned char magic[4];
    memcpy(magic, &net_magic, 4);
    if (!bip324_t_init(&c->t, seckey, ellswift, magic, initiator, garbage, glen)){
        free(c); return -1;
    }
    memset(seckey, 0, sizeof seckey);
    g_conn[fd] = c;

    if (!flush_send(fd, &c->t)){ conn_free(fd); return -1; }

    int elapsed = 0;
    const int slice = 200;
    /* NET-2 (audit 2026-09-03): a REAL-TIME deadline for the whole handshake.
     *
     * `elapsed` is only advanced on a poll timeout, so every path that
     * `continue`s without poll returning 0 was invisible to it. The v1
     * detection loop below has such a path -- peeked bytes stay in the
     * receive queue, so once a peer sends a partial v1 prefix and stops,
     * poll returns POLLIN immediately and forever, recv(MSG_PEEK) returns
     * the same n every time, and `n <= peeked` continues without charging
     * anything. One core pinned, an inbound slot held, no timeout. A peer
     * needs to send 8 bytes -- `f9beb4d9 76657273` -- and then nothing.
     * N connections pin N cores and take N of the ~189 inbound slots.
     *
     * A wall-clock deadline is checked on EVERY iteration regardless of what
     * poll did, so it bounds the paths that exist today and the ones a
     * future edit adds. The per-slice `elapsed` accounting is left in place
     * because it is what the non-spinning paths already use. */
    struct timespec hs_t0;
    clock_gettime(CLOCK_MONOTONIC, &hs_t0);
    #define HS_EXPIRED() (hs_deadline_passed(&hs_t0, timeout_ms))

    /* ---- responder: decide v1 or v2 WITHOUT consuming anything ----------
     *
     * A v1 peer's first message is its `version`, and if we fall back we have
     * to leave those bytes for the v1 reader. Reading them into the transport
     * and freeing it loses the message -- the peer then sits waiting for a
     * reply to a version we silently ate, and the connection dies on a
     * timeout with nothing in the log to explain it. That is exactly what an
     * earlier cut of this function did, and only a live Core with
     * -v2transport=0 caught it.
     *
     * So the detection phase peeks. MSG_PEEK always returns from the front of
     * the queue, so `peeked` tracks how much has already been handed to the
     * transport, and only once v2 is certain are those bytes consumed for
     * real. On the v1 path the socket is exactly as we found it. */
    if (!initiator){
        unsigned long peeked = 0;
        while (c->t.recv_state == BIP324_RECV_MAYBE_V1){
            if (HS_EXPIRED()){ conn_free(fd); return -1; }   /* NET-2 */
            struct pollfd pf = { fd, POLLIN, 0 };
            int pr = poll(&pf, 1, slice);
            if (pr < 0){
                if (errno == EINTR) continue;
                conn_free(fd); return -1;
            }
            if (pr == 0){
                elapsed += slice;
                if (elapsed >= timeout_ms){ conn_free(fd); return -1; }
                continue;
            }
            unsigned char pk[BIP324_V1_PREFIX_LEN];
            ssize_t n = recv(fd, pk, sizeof pk, MSG_PEEK);
            if (n == 0){ conn_free(fd); return -1; }
            if (n < 0){
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                conn_free(fd); return -1;
            }
            if ((unsigned long)n <= peeked){
                /* NET-2: nothing new. The bytes we peeked are still queued,
                 * so poll() will say POLLIN again immediately -- looping
                 * here is a busy spin, not a wait. Sleep the poll slice
                 * instead, and let the deadline below end it. A legitimate
                 * v1 peer whose version header is split across TCP segments
                 * lands within a slice or two; a peer that sends a partial
                 * prefix and stops is dropped at timeout_ms. */
                if (HS_EXPIRED()){ conn_free(fd); return -1; }
                struct timespec ts = { slice / 1000, (long)(slice % 1000) * 1000000L };
                nanosleep(&ts, NULL);
                continue;
            }
            if (!bip324_t_feed(&c->t, pk + peeked, (unsigned long)n - peeked)){
                conn_free(fd); return -1;
            }
            peeked = (unsigned long)n;
            if (bip324_t_is_v1(&c->t)){
                conn_free(fd);
                return 0;                    /* socket untouched; v1 reads on */
            }
        }
        /* v2 it is -- now take the bytes the transport has already seen off
         * the socket, so the loop below does not hand them over twice */
        while (peeked){
            unsigned char dump[BIP324_V1_PREFIX_LEN];
            ssize_t n = recv(fd, dump, peeked, 0);
            if (n <= 0){
                if (n < 0 && errno == EINTR) continue;
                conn_free(fd); return -1;
            }
            peeked -= (unsigned long)n;
        }
        if (!flush_send(fd, &c->t)){ conn_free(fd); return -1; }
    }

    /* drive the handshake to completion */
    while (c->t.recv_state != BIP324_RECV_APP){
        struct pollfd pf = { fd, POLLIN, 0 };
        int pr = poll(&pf, 1, slice);
        if (pr < 0){
            if (errno == EINTR) continue;
            conn_free(fd); return -1;
        }
        if (pr == 0){
            elapsed += slice;
            if (elapsed >= timeout_ms){ conn_free(fd); return -1; }
            continue;
        }
        unsigned char buf[4096];
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r == 0){ conn_free(fd); return -1; }        /* peer hung up */
        if (r < 0){
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            conn_free(fd); return -1;
        }
        if (!bip324_t_feed(&c->t, buf, (unsigned long)r)){ conn_free(fd); return -1; }

        /* v1 can only be concluded in the peek phase above, which every
         * responder passes through before reaching here. */
        if (bip324_t_is_v1(&c->t)){ conn_free(fd); return -1; }
        if (!flush_send(fd, &c->t)){ conn_free(fd); return -1; }
    }

    install_hooks();
    g_v2_active[fd] = 1;
    return 1;
}

/* --------------------------------- hooks --------------------------------- */

/* v1 p2p_write returns 24 + plen; callers depend on that shape. See the file
 * header -- this is a success indicator in v1's units, not a wire count. */
static long v2_write_hook(int fd, const char* cmd, unsigned cmdlen,
                          const void* payload, unsigned plen){
    v2_conn* c = (fd >= 0 && fd < V2_FD_MAX) ? g_conn[fd] : 0;
    if (!c) return -1;

    /* v1 commands are a 12-byte NUL-padded field; BIP324 wants the bare name */
    char type[13];
    unsigned n = cmdlen > 12 ? 12 : cmdlen;
    memcpy(type, cmd, n);
    type[n] = 0;
    for (unsigned i = 0; i < n; i++) if (!type[i]){ type[i] = 0; break; }

    if (!bip324_t_send_message(&c->t, type, (const unsigned char*)payload, plen)) return -1;
    if (!flush_send(fd, &c->t)) return -1;
    return (long)(24 + plen);
}

/* Hand one message to the caller in v1's shape: cmd_out is 12 bytes,
 * NUL-padded and NOT NUL-terminated, exactly as p2p_read fills it. */
static int deliver(v2_conn* c, const char* type, const unsigned char* body,
                   unsigned long blen, char* cmd_out, void* payload,
                   unsigned cap, unsigned* plen_out){
    memset(cmd_out, 0, 12);
    unsigned long tn = strlen(type);
    if (tn > 12) tn = 12;
    memcpy(cmd_out, type, tn);
    *plen_out = (unsigned)blen;
    unsigned long tocopy = blen < cap ? blen : cap;
    if (tocopy) memcpy(payload, body, tocopy);
    /* v1 reports -2 when the message did not fit the caller's buffer, having
     * drained the rest off the socket. Here the whole message is already in
     * hand, so the surplus is simply dropped -- same contract. */
    return blen > cap ? -2 : 1;
}

static int v2_read_hook(int fd, char* cmd_out, void* payload,
                        unsigned cap, unsigned* plen_out){
    v2_conn* c = (fd >= 0 && fd < V2_FD_MAX) ? g_conn[fd] : 0;
    if (!c) return -1;

    for (;;){
        const char* type; const unsigned char* body; unsigned long blen;
        int got = bip324_t_next_message(&c->t, &type, &body, &blen);
        if (got == 1) return deliver(c, type, body, blen, cmd_out, payload, cap, plen_out);
        if (got < 0) return -1;                       /* protocol violation */

        unsigned char buf[65536];
        ssize_t r = recv(fd, buf, sizeof buf, 0);
        if (r == 0) return 0;                          /* clean EOF */
        if (r < 0){
            if (errno == EINTR) continue;
            /* A timeout arrives as EAGAIN because callers set SO_RCVTIMEO and
             * rely on p2p_read returning on idle; v1 reports that as an
             * error, so this must too or the idle loops never turn over. */
            return -1;
        }
        if (!bip324_t_feed(&c->t, buf, (unsigned long)r)) return -1;
    }
}
