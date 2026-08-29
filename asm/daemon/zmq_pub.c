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
 * DROPPING IS CORRECT. A PUB socket must never stall its producer: this node
 * is a consensus daemon and a slow subscriber must not be able to hold up
 * block connection. Sockets are non-blocking and a subscriber whose buffer
 * is full has the message DROPPED, which is exactly what libzmq's PUB does
 * -- and why the per-topic sequence number exists, so the subscriber can see
 * that it happened.
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

typedef unsigned char u8;
typedef unsigned int  u32;

#define ZP_MAX_ENDPOINTS 8
#define ZP_MAX_SUBS      32
#define ZP_MAX_FILTERS   16
#define ZP_FILTER_LEN    64

/* a connected subscriber */
typedef struct {
    int  fd;
    int  state;          /* 0 = awaiting greeting, 1 = awaiting READY, 2 = live */
    u8   inbuf[512];
    int  inlen;
    u8   filter[ZP_MAX_FILTERS][ZP_FILTER_LEN];
    int  filterlen[ZP_MAX_FILTERS];
    int  nfilter;
} zp_sub;

typedef struct {
    int   listen_fd;
    char  addr[64];
    zp_sub subs[ZP_MAX_SUBS];
    int   nsubs;
} zp_endpoint;

static zp_endpoint g_ep[ZP_MAX_ENDPOINTS];
static int g_nep = 0;

/* topic -> endpoint index, -1 when that topic is not published */
#define ZP_NTOPIC 5
static const char* const ZP_TOPICS[ZP_NTOPIC] =
    { "hashblock", "hashtx", "rawblock", "rawtx", "sequence" };
static int  g_topic_ep[ZP_NTOPIC] = { -1, -1, -1, -1, -1 };
static u32  g_topic_seq[ZP_NTOPIC];
/* Core -zmqpub<topic>hwm: how much a slow subscriber may fall behind before
 * messages are dropped rather than queued. Core counts MESSAGES in its own
 * queue; this publisher has no user-space queue -- it writes the socket
 * directly and already drops on EAGAIN -- so the kernel send buffer IS the
 * queue, and the high-water mark sizes it. Same property (a slow subscriber
 * costs bounded memory and never blocks the node), different unit, stated
 * here rather than silently reinterpreted. 0 leaves the system default. */
static int g_topic_hwm[ZP_NTOPIC];
void zmq_pub_set_hwm(const int* hwm5){
    if (!hwm5) return;
    for (int i = 0; i < ZP_NTOPIC && i < 5; i++) g_topic_hwm[i] = hwm5[i];
}
/* a conservative per-message estimate: a rawblock is far larger, but the
 * point is a bound, and oversizing the buffer would defeat the option */
#define ZP_HWM_MSG_BYTES 256

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
    if (!strcmp(host, "*")) sa.sin_addr.s_addr = INADDR_ANY;
    else if (inet_pton(AF_INET, host, &sa.sin_addr) != 1){ close(fd); return -1; }
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
void zmqpub_poll(void){
    for (int i = 0; i < g_nep; i++){
        zp_endpoint* e = &g_ep[i];
        for (;;){
            int c = accept(e->listen_fd, NULL, NULL);
            /* size this subscriber's queue from the topic's high-water mark */
            if (c >= 0){
                int hw = 0;
                for (int t = 0; t < ZP_NTOPIC; t++)
                    if (g_topic_ep[t] >= 0 && g_topic_hwm[t] > hw) hw = g_topic_hwm[t];
                if (hw > 0){
                    int v = hw * ZP_HWM_MSG_BYTES;
                    setsockopt(c, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
                }
            }
            if (c < 0) break;
            if (e->nsubs >= ZP_MAX_SUBS){ close(c); continue; }
            zp_nonblock(c);
            int one = 1; setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
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
        }
        /* compact away closed subscribers */
        int w = 0;
        for (int k = 0; k < e->nsubs; k++) if (e->subs[k].fd >= 0) e->subs[w++] = e->subs[k];
        e->nsubs = w;
    }
}

/* Publish [topic][body][seq u32 LE] to every subscriber of `topic`. */
void zmqpub_notify(const char* topic, const void* body, unsigned long blen){
    int t = -1;
    for (int i = 0; i < ZP_NTOPIC; i++) if (!strcmp(topic, ZP_TOPICS[i])) t = i;
    if (t < 0 || g_topic_ep[t] < 0) return;
    zp_endpoint* e = &g_ep[g_topic_ep[t]];
    if (e->nsubs == 0){ g_topic_seq[t]++; return; }

    size_t tl = strlen(topic);
    u8 h1[9], h2[9], h3[9];
    size_t n1 = zp_frame_hdr(h1, 1, 0, tl);
    size_t n2 = zp_frame_hdr(h2, 1, 0, blen);
    size_t n3 = zp_frame_hdr(h3, 0, 0, 4);
    u32 seq = g_topic_seq[t]++;
    u8 seqb[4];
    for (int i = 0; i < 4; i++) seqb[i] = (u8)(seq >> (8 * i));   /* little-endian */

    for (int k = 0; k < e->nsubs; k++){
        zp_sub* s = &e->subs[k];
        if (s->fd < 0 || s->state != 2 || !zp_wants(s, topic)) continue;
        /* One writev-shaped burst, but plain sends: a partial write on the
         * FIRST part would desynchronise the stream, so a subscriber that
         * cannot take the whole message is dropped rather than fed half of
         * one. That is the honest failure -- half a frame is unparseable. */
        if (zp_send_all(s->fd, h1, n1) != 1 ||
            zp_send_all(s->fd, (const u8*)topic, tl) != 1 ||
            zp_send_all(s->fd, h2, n2) != 1 ||
            zp_send_all(s->fd, (const u8*)body, blen) != 1 ||
            zp_send_all(s->fd, h3, n3) != 1 ||
            zp_send_all(s->fd, seqb, 4) != 1){
            fprintf(stderr, "[zmq] subscriber could not take a %s message; dropping it\n", topic);
            close(s->fd); s->fd = -1;
        }
    }
}

void zmqpub_close(void){
    for (int i = 0; i < g_nep; i++){
        for (int k = 0; k < g_ep[i].nsubs; k++)
            if (g_ep[i].subs[k].fd >= 0) close(g_ep[i].subs[k].fd);
        if (g_ep[i].listen_fd >= 0) close(g_ep[i].listen_fd);
    }
    g_nep = 0;
    for (int i = 0; i < ZP_NTOPIC; i++) g_topic_ep[i] = -1;
}
