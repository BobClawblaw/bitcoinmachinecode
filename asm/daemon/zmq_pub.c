/* daemon/zmq_pub.c -- Core's ZMQ notification interface, over a ZMTP 3.1 PUB
 * socket implemented here rather than linked.
 *
 * WHY NOT libzmq. It is present on this box as a runtime .so but with no
 * development headers, and linking it would be this project's FIRST external
 * dependency beyond libc -- against the grain of a codebase that writes its
 * own base58, bech32, secp256k1, LSM store and JSON rather than pulling in
 * libraries. The publisher side of ZMTP is small: a fixed greeting, one
 * READY command each way, and length-prefixed frames. So it is written out.
 *
 * That decision is only defensible if it INTEROPERATES, so it is tested
 * against a real libzmq subscriber (pyzmq / libzmq 4.3.5), not against a
 * second implementation of my own reading of the spec.
 *
 * WIRE FORMAT (ZMTP 3.1, RFC 23/ZMTP):
 *   greeting, 64 bytes: FF 00*8 7F | 03 01 | "NULL" + 16 zeros | 00 | 31 zeros
 *   command frame:  flags(0x04) | size | body
 *   message frame:  flags(MORE 0x01 | LONG 0x02) | size | body
 *   sizes are 1 byte when < 256, else 8 bytes BIG-ENDIAN with the LONG bit.
 *   READY body: [5]"READY" [11]"Socket-Type" [u32be 3]"PUB"
 *
 * NOTIFICATION FORMAT (Core's zmqpublishnotifier.cpp): a three-part message
 *   [topic] [body] [sequence u32 LE]
 * with the sequence counted PER TOPIC, so a subscriber can detect a drop.
 *
 * NOT STALLING IS CORRECT. A PUB socket must never hold up its producer: this
 * is a consensus daemon and a slow subscriber must not be able to delay block
 * connection. So zmqpub_notify never touches a socket. It frames the message
 * ONCE into a refcounted buffer, appends a pointer to the queue of every
 * subscriber that wants it, and wakes the servicing thread, which writes each
 * queue out as its socket drains (POLLOUT) -- the shape of libzmq's I/O
 * thread and its per-peer pipes.
 *
 * THE QUEUE IS libzmq's, IN libzmq's UNIT. Each subscriber's queue holds at
 * most SNDHWM MESSAGES (-zmqpub<topic>hwm, default 1000; 0 = no count limit,
 * as in ZMQ). When it is full the NEW message is discarded for that
 * subscriber alone and the connection is KEPT -- what libzmq's PUB does -- so
 * the subscriber sees a gap in the per-topic sequence number, not a
 * disconnect. A message is queued whole or not at all, and a queue is written
 * strictly in order from one offset, so frames never interleave and a
 * subscriber never receives half a message.
 *
 * MEM-22 (audit 2026-09-03), CLOSED 2026-09-19. There used to be no queue: the
 * subscriber's kernel send buffer was sized to hwm x 256 bytes (~256 KB), the
 * three frames were written with non-blocking send, and a subscriber that
 * could not take the whole message was CLOSED. A rawblock is 1-2 MB, so it
 * hit EAGAIN mid-message every time: rawblock was never delivered to anyone,
 * and every block disconnected every subscriber on its endpoint. Production,
 * 2026-09-19 01:07Z: a pyzmq subscriber received 3,180 hashtx, 2 hashblock and
 * ZERO rawblock over two blocks, with 4 per-topic sequence gaps (reconnects).
 *
 * ONE DIVERGENCE, deliberate: a BYTE ceiling per subscriber (ZP_SUB_MAX_BYTES,
 * 512 MiB) on top of the message count. Core's worst case is 1000 rawblocks
 * (up to 4 GB) held for each stalled subscriber; this node has been OOM-killed
 * before, and 512 MiB is ~250 full blocks -- more than a day at the tip, so
 * it only binds during a catch-up burst to a subscriber that has stopped
 * reading. Past it, new messages drop exactly as at the high-water mark. A
 * message into an EMPTY queue is always accepted, so no single message is
 * undeliverable. Recorded in docs/CORE_DIVERGENCES.md.
 */
#include <stdio.h>
#include "log_ts.h"   /* timestamped fprintf(stderr), like every other daemon line */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <pthread.h>
#include "../bmc_thread.h"
#include <stdatomic.h>
#include <time.h>
#include <stdint.h>
#include <sys/eventfd.h>

typedef unsigned char u8;
typedef unsigned int  u32;

#define ZP_MAX_ENDPOINTS 8
#define ZP_MAX_SUBS      32
#define ZP_MAX_FILTERS   16
#define ZP_FILTER_LEN    64

/* One published message, framed for the wire ONCE and shared by every
 * subscriber queue holding it: a 2 MB rawblock sent to five subscribers is
 * one allocation, not five (libzmq shares large messages the same way).
 * refs is only ever touched under g_lock. */
typedef struct {
    int    refs;
    size_t len;
    u8     wire[];
} zp_msg;

/* a connected subscriber */
typedef struct {
    int  fd;
    int  state;          /* 0 = awaiting greeting, 1 = awaiting READY, 2 = live */
    u8   inbuf[512];
    int  inlen;
    u8   filter[ZP_MAX_FILTERS][ZP_FILTER_LEN];
    int  filterlen[ZP_MAX_FILTERS];
    int  nfilter;
    /* the outbound queue: a ring of whole messages, oldest at qhead, written
     * from qoff bytes into the oldest. qcap is 0 or a power of two. */
    zp_msg** q;
    u32  qcap, qhead, qn;
    size_t qoff, qbytes;
    unsigned long drop_run;    /* dropped since the queue last had room */
    unsigned long drop_total;
} zp_sub;

typedef struct {
    int   listen_fd;
    char  addr[64];
    zp_sub subs[ZP_MAX_SUBS];
    int   nsubs;
} zp_endpoint;

static zp_endpoint g_ep[ZP_MAX_ENDPOINTS];
static int g_nep = 0;

/* ---------------------------------------------------------------------------
 * SUBSCRIBER SERVICING RUNS ON ITS OWN THREAD (audit 2026-08-29 finding 8).
 *
 * Core does not have this problem: it links libzmq, whose background I/O
 * thread does every accept, subscription frame and delivery, so none of it
 * ever touches Core's validation or download paths. `zmq_poll` appears
 * nowhere in Core's source.
 *
 * This node speaks ZMTP itself, so that work has to live somewhere. It used
 * to live in the download worker's hot loop, which is what the audit flagged:
 * a subscriber that dribbles greeting bytes keeps the poll returning with data
 * pending, and 32 subscribers become a per-iteration tax on block catch-up.
 *
 * It now runs here, on a dedicated thread that blocks in poll() and idles at
 * zero cost -- the same shape as libzmq's I/O thread.
 *
 * WHAT THE LOCK PROTECTS. The servicing thread accepts subscribers, writes
 * their queues and COMPACTS the array when they disconnect; the publishing
 * thread walks that same array appending to the queues. Without the lock the
 * compaction moves entries out from under an in-progress walk, and a queue
 * could be appended to after it was freed -- or an fd closed and its number
 * reused under a write. Every read or write of subs/nsubs, of a queue and of
 * a message's refcount is therefore under g_lock; the servicing thread's
 * sends are non-blocking and budgeted, so the publisher's wait for it is
 * bounded. The endpoint list itself (g_ep, g_nep, listen_fd) is
 * built once by zmqpub_add before the thread starts and is read-only after.
 * ------------------------------------------------------------------------ */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t       g_thread;
static int             g_thread_up = 0;
/* atomic, not volatile: `volatile` orders nothing between threads and is not
 * a synchronisation primitive -- ThreadSanitizer flags the plain read/write
 * pair as a data race, correctly. It happens to work on x86 today, which is
 * exactly the kind of thing that stops being true on another target. */
static atomic_int      g_stop;

/* topic -> endpoint index, -1 when that topic is not published */
#define ZP_NTOPIC 5
static const char* const ZP_TOPICS[ZP_NTOPIC] =
    { "hashblock", "hashtx", "rawblock", "rawtx", "sequence" };
static int  g_topic_ep[ZP_NTOPIC] = { -1, -1, -1, -1, -1 };
static u32  g_topic_seq[ZP_NTOPIC];
/* Core -zmqpub<topic>hwm: libzmq's ZMQ_SNDHWM, in MESSAGES -- how many a
 * subscriber's queue may hold before new ones are dropped for it. Default
 * 1000 (Core's DEFAULT_ZMQ_SNDHWM), so a caller that never sets it gets
 * Core's value rather than "unlimited". 0 means no count limit, as in ZMQ.
 *
 * WHICH topic's value governs a shared endpoint: Core creates one socket per
 * address, and SNDHWM is set by the notifier that CREATES it -- the first in
 * its factories map, which is ordered pubhashblock, pubhashtx, pubrawblock,
 * pubrawtx, pubsequence (zmqpublishnotifier.cpp Initialize; later notifiers
 * "reuse" the socket as it is). ZP_TOPICS is in that order, so the first
 * topic bound to an endpoint is the one whose hwm applies, as in Core. */
static int g_topic_hwm[ZP_NTOPIC] = { 1000, 1000, 1000, 1000, 1000 };
void zmq_pub_set_hwm(const int* hwm5){
    if (!hwm5) return;
    for (int i = 0; i < ZP_NTOPIC && i < 5; i++)
        if (hwm5[i] >= 0) g_topic_hwm[i] = hwm5[i];   /* Core ignores a negative */
}
static int zp_ep_hwm(int ep){
    for (int t = 0; t < ZP_NTOPIC; t++) if (g_topic_ep[t] == ep) return g_topic_hwm[t];
    return 1000;
}
/* The divergence stated in the header: a per-subscriber byte ceiling on top
 * of the message count. Settable only so tests can reach it cheaply. */
#define ZP_SUB_MAX_BYTES ((size_t)512 << 20)
static size_t g_sub_max_bytes = ZP_SUB_MAX_BYTES;
void zmq_pub_set_byte_cap(unsigned long b){ g_sub_max_bytes = b ? (size_t)b : ZP_SUB_MAX_BYTES; }

/* how much one servicing pass writes to one subscriber before moving on, so
 * a fast reader of a big backlog cannot hold g_lock for long */
#define ZP_FLUSH_BUDGET ((size_t)4 << 20)

/* wakes the servicing thread when a queue goes from empty to not */
static int g_wake_fd = -1;
static void zp_wake(void){
    if (g_wake_fd < 0) return;
    uint64_t one = 1;
    ssize_t w = write(g_wake_fd, &one, sizeof one); (void)w;   /* EAGAIN: already pending */
}

static void zp_nonblock(int fd){
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* "tcp://127.0.0.1:28332" -> bound, listening, non-blocking fd (or -1) */
static int zp_bind(const char* addr){
    if (strncmp(addr, "tcp://", 6)) return -1;
    char host[64]; const char* p = addr + 6;
    const char* colon = strrchr(p, ':');
    if (!colon || (size_t)(colon - p) >= sizeof host) return -1;
    memcpy(host, p, (size_t)(colon - p)); host[colon - p] = 0;
    int port = atoi(colon + 1);
    if (port <= 0 || port > 65535) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    /* SECURITY (audit 2026-08-29 finding 8): `*` is REFUSED, not expanded to
     * INADDR_ANY.
     *
     * Core accepts it, but on a node like this one it silently publishes every
     * block and transaction to the whole LAN -- and the operator who typed
     * the wildcard bind (`tcp:` + `//` + `*:28332`) copied it from a tutorial and got a listener far wider
     * than intended. There is no authentication on a ZMQ publisher: whoever
     * connects, subscribes.
     *
     * Requiring an explicit interface costs one word in the config and makes
     * the blast radius something the operator chose rather than inherited.
     * 0.0.0.0 still works for anyone who genuinely wants every interface --
     * this refuses the ambiguous spelling, not the capability. */
    if (!strcmp(host, "*")){
        fprintf(stderr, "[zmq] refusing \"%s\": bind to an explicit interface "
                        "(127.0.0.1 for local subscribers, 0.0.0.0 only if you "
                        "really mean every interface -- there is no auth on a "
                        "ZMQ publisher)\n", addr);
        close(fd); return -1;
    }
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1){ close(fd); return -1; }
    if (bind(fd, (struct sockaddr*)&sa, sizeof sa) != 0){ close(fd); return -1; }
    if (listen(fd, 8) != 0){ close(fd); return -1; }
    zp_nonblock(fd);
    return fd;
}

/* Register one topic at one address. Topics sharing an address share the
 * socket, exactly as Core does. Returns 1 on success. */
int zmqpub_add(const char* topic, const char* addr){
    int t = -1;
    for (int i = 0; i < ZP_NTOPIC; i++) if (!strcmp(topic, ZP_TOPICS[i])) t = i;
    if (t < 0) return 0;
    for (int i = 0; i < g_nep; i++)
        if (!strcmp(g_ep[i].addr, addr)){ g_topic_ep[t] = i; return 1; }
    if (g_nep >= ZP_MAX_ENDPOINTS) return 0;
    int fd = zp_bind(addr);
    if (fd < 0){
        fprintf(stderr, "[zmq] cannot bind %s for %s: %s\n", addr, topic, strerror(errno));
        return 0;
    }
    zp_endpoint* e = &g_ep[g_nep];
    memset(e, 0, sizeof *e);
    e->listen_fd = fd;
    snprintf(e->addr, sizeof e->addr, "%s", addr);
    g_topic_ep[t] = g_nep;
    g_nep++;
    fprintf(stderr, "[zmq] publishing %s on %s\n", topic, addr);
    return 1;
}

int zmqpub_active(void){ return g_nep > 0; }

/* ---- ZMTP framing -------------------------------------------------------- */
static int zp_send_all(int fd, const u8* b, size_t n){
    size_t off = 0;
    while (off < n){
        ssize_t w = send(fd, b + off, n - off, MSG_NOSIGNAL);
        if (w > 0){ off += (size_t)w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;  /* would block: drop */
        return -1;
    }
    return 1;
}

static size_t zp_frame_hdr(u8* o, int more, int command, size_t len){
    u8 flags = (u8)((more ? 1 : 0) | (command ? 4 : 0));
    if (len < 256){ o[0] = flags; o[1] = (u8)len; return 2; }
    o[0] = (u8)(flags | 2);
    for (int i = 0; i < 8; i++) o[1 + i] = (u8)(len >> (8 * (7 - i)));  /* big-endian */
    return 9;
}

static void zp_send_greeting(int fd){
    u8 g[64]; memset(g, 0, sizeof g);
    g[0] = 0xff; g[9] = 0x7f;          /* signature */
    g[10] = 3; g[11] = 1;              /* ZMTP 3.1 */
    memcpy(g + 12, "NULL", 4);         /* mechanism, zero-padded to 20 */
    g[32] = 0;                         /* as-server: 0 for NULL */
    zp_send_all(fd, g, sizeof g);
}

static void zp_send_ready(int fd){
    u8 body[64]; size_t n = 0;
    body[n++] = 5; memcpy(body + n, "READY", 5); n += 5;
    body[n++] = 11; memcpy(body + n, "Socket-Type", 11); n += 11;
    body[n++] = 0; body[n++] = 0; body[n++] = 0; body[n++] = 3;   /* u32be */
    memcpy(body + n, "PUB", 3); n += 3;
    u8 hdr[9]; size_t hn = zp_frame_hdr(hdr, 0, 1, n);
    u8 out[80]; memcpy(out, hdr, hn); memcpy(out + hn, body, n);
    zp_send_all(fd, out, hn + n);
}

/* Record a subscription prefix. libzmq SUB filters on receive too, so
 * honouring these is not strictly required for correctness -- but a PUB that
 * ignored them would push every block to a subscriber that asked only for
 * txids, which on this node means megabytes it never wanted. */
static void zp_add_filter(zp_sub* s, const u8* topic, int len){
    if (len < 0 || len > ZP_FILTER_LEN || s->nfilter >= ZP_MAX_FILTERS) return;
    memcpy(s->filter[s->nfilter], topic, (size_t)len);
    s->filterlen[s->nfilter] = len;
    s->nfilter++;
}
static void zp_del_filter(zp_sub* s, const u8* topic, int len){
    for (int i = 0; i < s->nfilter; i++)
        if (s->filterlen[i] == len && !memcmp(s->filter[i], topic, (size_t)len)){
            s->filter[i][0] = s->filter[s->nfilter - 1][0];
            memcpy(s->filter[i], s->filter[s->nfilter - 1], ZP_FILTER_LEN);
            s->filterlen[i] = s->filterlen[s->nfilter - 1];
            s->nfilter--;
            return;
        }
}
static int zp_wants(const zp_sub* s, const char* topic){
    if (s->nfilter == 0) return 0;          /* subscribed to nothing yet */
    size_t tl = strlen(topic);
    for (int i = 0; i < s->nfilter; i++){
        if (s->filterlen[i] == 0) return 1;                  /* subscribe-all */
        if ((size_t)s->filterlen[i] > tl) continue;
        if (!memcmp(s->filter[i], topic, (size_t)s->filterlen[i])) return 1;
    }
    return 0;
}

/* ---- the per-subscriber outbound queue (all under g_lock) ---------------- */
static void zp_msg_unref(zp_msg* m){ if (--m->refs == 0) free(m); }

static void zp_queue_free(zp_sub* s){
    for (u32 i = 0; i < s->qn; i++) zp_msg_unref(s->q[(s->qhead + i) & (s->qcap - 1)]);
    free(s->q);
    s->q = NULL; s->qcap = s->qhead = s->qn = 0; s->qoff = s->qbytes = 0;
}

/* Queue m for s, or drop it for s alone. libzmq's rule: a full pipe discards
 * the NEW message and keeps the peer. Returns 1 if queued. */
static int zp_enqueue(zp_sub* s, zp_msg* m, int hwm, const char* addr, const char* topic){
    const char* why = NULL;
    if (hwm > 0 && s->qn >= (u32)hwm) why = "high-water mark";
    else if (s->qn > 0 && s->qbytes + m->len > g_sub_max_bytes) why = "byte ceiling";
    else if (s->qn == s->qcap){
        u32 nc = s->qcap ? s->qcap * 2 : 16;
        zp_msg** nq = nc > s->qcap ? malloc((size_t)nc * sizeof *nq) : NULL;
        if (!nq) why = "out of memory";
        else {
            for (u32 i = 0; i < s->qn; i++) nq[i] = s->q[(s->qhead + i) & (s->qcap - 1)];
            free(s->q); s->q = nq; s->qcap = nc; s->qhead = 0;
        }
    }
    if (why){
        /* once per streak, not once per message: a stalled subscriber would
         * otherwise log every transaction the node relays */
        if (s->drop_run++ == 0)
            fprintf(stderr, "[zmq] subscriber on %s is %u message(s) / %zu bytes behind "
                            "(%s, hwm %d): dropping new messages for it, first a %s; "
                            "the connection is kept\n",
                    addr, s->qn, s->qbytes, why, hwm, topic);
        s->drop_total++;
        return 0;
    }
    if (s->drop_run){
        fprintf(stderr, "[zmq] subscriber on %s is taking messages again after %lu "
                        "were dropped for it\n", addr, s->drop_run);
        s->drop_run = 0;
    }
    s->q[(s->qhead + s->qn) & (s->qcap - 1)] = m;
    s->qn++; s->qbytes += m->len; m->refs++;
    return 1;
}

/* Write as much of s's queue as the socket takes now: whole messages, in
 * order, resuming at qoff. EAGAIN leaves the rest for the next POLLOUT; any
 * other error means the peer is gone. */
static void zp_flush(zp_sub* s){
    size_t budget = ZP_FLUSH_BUDGET;
    while (s->fd >= 0 && s->qn && budget){
        zp_msg* m = s->q[s->qhead];
        size_t want = m->len - s->qoff;
        if (want > budget) want = budget;
        ssize_t w = send(s->fd, m->wire + s->qoff, want, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w > 0){
            s->qoff += (size_t)w; budget -= (size_t)w;
            if (s->qoff == m->len){
                s->qhead = (s->qhead + 1) & (s->qcap - 1);
                s->qn--; s->qbytes -= m->len; s->qoff = 0;
                zp_msg_unref(m);
            }
            continue;
        }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        close(s->fd); s->fd = -1;
        return;
    }
}

/* Consume whatever complete frames are buffered for this subscriber. */
static void zp_consume(zp_sub* s){
    for (;;){
        if (s->state == 0){
            if (s->inlen < 64) return;
            /* we do not police the peer's greeting beyond the signature:
             * anything else is libzmq's business and rejecting on version
             * minor would break 3.0 subscribers that work fine here */
            if (s->inbuf[0] != 0xff){ close(s->fd); s->fd = -1; return; }
            memmove(s->inbuf, s->inbuf + 64, (size_t)(s->inlen - 64));
            s->inlen -= 64;
            zp_send_ready(s->fd);
            s->state = 1;
            continue;
        }
        /* frames */
        if (s->inlen < 2) return;
        u8 flags = s->inbuf[0];
        size_t len, hn;
        if (flags & 2){
            if (s->inlen < 9) return;
            len = 0;
            for (int i = 0; i < 8; i++) len = (len << 8) | s->inbuf[1 + i];
            hn = 9;
        } else { len = s->inbuf[1]; hn = 2; }
        if (len > sizeof s->inbuf - 16){ close(s->fd); s->fd = -1; return; }
        if ((size_t)s->inlen < hn + len) return;
        const u8* body = s->inbuf + hn;
        if (flags & 4){
            /* a COMMAND: READY, SUBSCRIBE or CANCEL (ZMTP 3.1) */
            if (len >= 1){
                int nl = body[0];
                if (nl > 0 && (size_t)nl + 1 <= len){
                    const char* nm = (const char*)body + 1;
                    if (nl == 5 && !memcmp(nm, "READY", 5)) s->state = 2;
                    else if (nl == 9 && !memcmp(nm, "SUBSCRIBE", 9))
                        zp_add_filter(s, body + 1 + nl, (int)(len - 1 - nl));
                    else if (nl == 6 && !memcmp(nm, "CANCEL", 6))
                        zp_del_filter(s, body + 1 + nl, (int)(len - 1 - nl));
                }
            }
        } else if (s->state == 2 && len >= 1){
            /* ZMTP 3.0 style subscription carried as a message: 0x01/0x00 */
            if (body[0] == 1)      zp_add_filter(s, body + 1, (int)len - 1);
            else if (body[0] == 0) zp_del_filter(s, body + 1, (int)len - 1);
        }
        memmove(s->inbuf, s->inbuf + hn + len, (size_t)s->inlen - hn - len);
        s->inlen -= (int)(hn + len);
    }
}

/* Accept new subscribers and service their handshakes. Cheap and
 * non-blocking; called from the worker loop. */
/* Caller must hold g_lock. */
static void zp_poll_locked(void){
    for (int i = 0; i < g_nep; i++){
        zp_endpoint* e = &g_ep[i];
        for (;;){
            int c = accept(e->listen_fd, NULL, NULL);
            /* The kernel send buffer is left to autotune: the high-water mark
             * is enforced on the user-space queue, in messages, as libzmq
             * does. (It used to size SO_SNDBUF to hwm x 256 bytes, which is
             * what made a rawblock undeliverable -- MEM-22, header.) */
            if (c < 0) break;
            if (e->nsubs >= ZP_MAX_SUBS){ close(c); continue; }
            zp_nonblock(c);
            int one = 1; setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
            setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);   /* Core: ZMQ_TCP_KEEPALIVE=1 */
            zp_sub* s = &e->subs[e->nsubs++];
            memset(s, 0, sizeof *s);
            s->fd = c;
            zp_send_greeting(c);
            fprintf(stderr, "[zmq] subscriber connected on %s (%d total)\n", e->addr, e->nsubs);
        }
        for (int k = 0; k < e->nsubs; k++){
            zp_sub* s = &e->subs[k];
            if (s->fd < 0) continue;
            for (;;){
                ssize_t r = recv(s->fd, s->inbuf + s->inlen,
                                 sizeof s->inbuf - (size_t)s->inlen, 0);
                if (r > 0){ s->inlen += (int)r; zp_consume(s); if (s->fd < 0) break; continue; }
                if (r == 0){ close(s->fd); s->fd = -1; }
                break;
            }
            if (s->fd >= 0 && s->qn) zp_flush(s);
        }
        /* compact away closed subscribers, releasing what they had queued */
        int w = 0;
        for (int k = 0; k < e->nsubs; k++){
            zp_sub* s = &e->subs[k];
            if (s->fd >= 0){ if (w != k) e->subs[w] = *s; w++; continue; }
            if (s->drop_total)
                fprintf(stderr, "[zmq] subscriber on %s disconnected; %lu message(s) had "
                                "been dropped for it\n", e->addr, s->drop_total);
            zp_queue_free(s);
        }
        /* the vacated tail holds copies of moved queue pointers: clear it so
         * nothing can ever free one of those queues twice */
        for (int k = w; k < e->nsubs; k++){ memset(&e->subs[k], 0, sizeof e->subs[k]); e->subs[k].fd = -1; }
        e->nsubs = w;
    }
}

void zmqpub_poll(void){
    pthread_mutex_lock(&g_lock);
    zp_poll_locked();
    pthread_mutex_unlock(&g_lock);
}

/* The servicing thread. Blocks in poll() on the listeners and the current
 * subscribers, so an idle publisher costs nothing. The fd set is snapshotted
 * under the lock and poll()ed outside it -- an fd closed in between simply
 * reports POLLNVAL, and the real work re-derives state under the lock, so the
 * snapshot is only ever a wake-up hint. */
static void* zp_thread_main(void* arg){
    (void)arg;
    while (!atomic_load(&g_stop)){
        struct pollfd pf[1 + ZP_MAX_ENDPOINTS * (ZP_MAX_SUBS + 1)];
        int n = 0;
        pf[n].fd = g_wake_fd; pf[n].events = POLLIN; pf[n].revents = 0; n++;
        pthread_mutex_lock(&g_lock);
        for (int i = 0; i < g_nep && n < (int)(sizeof pf / sizeof pf[0]); i++){
            if (g_ep[i].listen_fd >= 0){
                pf[n].fd = g_ep[i].listen_fd; pf[n].events = POLLIN; pf[n].revents = 0; n++;
            }
            for (int k = 0; k < g_ep[i].nsubs && n < (int)(sizeof pf / sizeof pf[0]); k++)
                if (g_ep[i].subs[k].fd >= 0){
                    /* POLLOUT only while something is queued, or an idle
                     * writable socket would spin this loop */
                    pf[n].fd = g_ep[i].subs[k].fd;
                    pf[n].events = (short)(POLLIN | (g_ep[i].subs[k].qn ? POLLOUT : 0));
                    pf[n].revents = 0; n++;
                }
        }
        pthread_mutex_unlock(&g_lock);

        if (n == 1){
            struct timespec ts = { 0, 100 * 1000 * 1000 };   /* nothing to watch yet */
            nanosleep(&ts, NULL);
            continue;
        }
        int r = poll(pf, (nfds_t)n, 200);
        if (r < 0 && errno != EINTR) break;
        if (r > 0 && (pf[0].revents & POLLIN)){
            uint64_t v; ssize_t rd = read(g_wake_fd, &v, sizeof v); (void)rd;
        }
        if (r > 0) zmqpub_poll();
    }
    return NULL;
}

/* Start the servicing thread. Idempotent; safe to call after every
 * zmqpub_add. Returns 1 if the thread is running. */
int zmqpub_start(void){
    if (g_thread_up) return 1;
    if (g_nep == 0) return 0;
    atomic_store(&g_stop, 0);
    if (g_wake_fd < 0) g_wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (g_wake_fd < 0){
        fprintf(stderr, "[zmq] could not create the wake-up eventfd: %s -- "
                        "subscribers will not connect\n", strerror(errno));
        return 0;
    }
    if (bmc_pthread_create(&g_thread, zp_thread_main, NULL) != 0){
        fprintf(stderr, "[zmq] could not start the subscriber thread -- "
                        "publishing still works, subscribers will not connect\n");
        return 0;
    }
    g_thread_up = 1;
    return 1;
}

static void zp_stop_thread(void){
    if (!g_thread_up) return;
    atomic_store(&g_stop, 1);
    pthread_join(g_thread, NULL);
    g_thread_up = 0;
}

static int zp_any_wants_locked(const zp_endpoint* e, const char* topic){
    for (int k = 0; k < e->nsubs; k++){
        const zp_sub* s = &e->subs[k];
        if (s->fd >= 0 && s->state == 2 && zp_wants(s, topic)) return 1;
    }
    return 0;
}

/* Publish [topic][body][seq u32 LE] to every subscriber of `topic`.
 *
 * NEVER touches a socket and never waits on one: the cost is one allocation
 * and one copy of the message (the copy made OUTSIDE the lock), then a
 * pointer append per subscriber. The servicing thread does the writing. */
void zmqpub_notify(const char* topic, const void* body, unsigned long blen){
    int t = -1;
    for (int i = 0; i < ZP_NTOPIC; i++) if (!strcmp(topic, ZP_TOPICS[i])) t = i;
    if (t < 0 || g_topic_ep[t] < 0) return;
    int ep = g_topic_ep[t];
    zp_endpoint* e = &g_ep[ep];
    /* The sequence number belongs to the publisher alone and is bumped
     * whether or not anyone takes the message -- Core's nSequence is too,
     * which is what makes a dropped message visible as a gap. */
    u32 seq = g_topic_seq[t]++;

    /* nobody subscribed is the common case: answer it without allocating */
    pthread_mutex_lock(&g_lock);
    int any = zp_any_wants_locked(e, topic);
    pthread_mutex_unlock(&g_lock);
    if (!any) return;

    size_t tl = strlen(topic);
    u8 h1[9], h2[9], h3[9];
    size_t n1 = zp_frame_hdr(h1, 1, 0, tl);
    size_t n2 = zp_frame_hdr(h2, 1, 0, blen);
    size_t n3 = zp_frame_hdr(h3, 0, 0, 4);
    size_t total = n1 + tl + n2 + blen + n3 + 4;
    zp_msg* m = malloc(sizeof *m + total);
    if (!m){
        fprintf(stderr, "[zmq] cannot allocate %zu bytes for a %s message; not published\n",
                total, topic);
        return;
    }
    m->refs = 0; m->len = total;
    u8* p = m->wire;
    memcpy(p, h1, n1); p += n1; memcpy(p, topic, tl); p += tl;
    memcpy(p, h2, n2); p += n2; memcpy(p, body, blen); p += blen;
    memcpy(p, h3, n3); p += n3;
    for (int i = 0; i < 4; i++) *p++ = (u8)(seq >> (8 * i));   /* little-endian */

    int wake = 0;
    pthread_mutex_lock(&g_lock);
    int hwm = zp_ep_hwm(ep);
    for (int k = 0; k < e->nsubs; k++){
        zp_sub* s = &e->subs[k];
        if (s->fd < 0 || s->state != 2 || !zp_wants(s, topic)) continue;
        int was_empty = s->qn == 0;
        /* a non-empty queue is already polled for POLLOUT; only a queue
         * that just became non-empty needs the thread woken */
        if (zp_enqueue(s, m, hwm, e->addr, topic) && was_empty) wake = 1;
    }
    int held = m->refs;
    pthread_mutex_unlock(&g_lock);
    if (!held) free(m);
    if (wake) zp_wake();
}

/* Subscribers past the handshake, across all endpoints (tests, diagnostics). */
int zmqpub_live_subscribers(void){
    int n = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_nep; i++)
        for (int k = 0; k < g_ep[i].nsubs; k++)
            if (g_ep[i].subs[k].fd >= 0 && g_ep[i].subs[k].state == 2) n++;
    pthread_mutex_unlock(&g_lock);
    return n;
}

void zmqpub_close(void){
    zp_stop_thread();          /* before any fd goes away under it */
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_nep; i++){
        for (int k = 0; k < g_ep[i].nsubs; k++){
            if (g_ep[i].subs[k].fd >= 0) close(g_ep[i].subs[k].fd);
            zp_queue_free(&g_ep[i].subs[k]);
        }
        g_ep[i].nsubs = 0;
        if (g_ep[i].listen_fd >= 0) close(g_ep[i].listen_fd);
    }
    g_nep = 0;
    for (int i = 0; i < ZP_NTOPIC; i++){ g_topic_ep[i] = -1; g_topic_seq[i] = 0; }
    if (g_wake_fd >= 0){ close(g_wake_fd); g_wake_fd = -1; }
    pthread_mutex_unlock(&g_lock);
}
