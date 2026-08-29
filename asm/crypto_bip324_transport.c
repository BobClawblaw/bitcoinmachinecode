/* crypto_bip324_transport.c -- the BIP324 v2 transport state machine.
 *
 * THE SHAPE OF A V2 CONNECTION
 *
 *   ->  64-byte ElligatorSwift encoding, then 0..4095 bytes of garbage
 *   <-  the same, from the other side
 *   ->  16-byte garbage terminator, then the version packet, whose AAD is
 *       the garbage WE sent
 *   <-  the same
 *   <-> ordinary packets, empty AAD
 *
 * The 64 bytes and the garbage are indistinguishable from random, so an
 * observer sees a connection that begins with no recognisable header at all.
 * That is the point of the whole design, and it is why the garbage has no
 * length prefix: a length would be structure. The receiver instead scans for
 * the 16-byte terminator, which it can only compute after the key exchange.
 *
 * V1 FALLBACK. A responder cannot know which protocol it is being spoken
 * until bytes arrive. It compares the first 16 against the v1 header for a
 * version message -- network magic + "version" + five NULs. A mismatch at any
 * byte proves v2 immediately (a v1 peer always opens with exactly this), so
 * the responder can reply with its key as soon as one byte differs. A full
 * 16-byte match means v1, and those bytes must be replayed into the v1 path
 * rather than dropped.
 *
 * An initiator never does this: it chose v2, so it sends its key first.
 *
 * THE GARBAGE SCAN IS BOUNDED. A peer that never sends a terminator would
 * otherwise make us buffer forever. The limit is 4095 garbage bytes plus the
 * 16-byte terminator; past that the connection is a protocol violation. This
 * is the only place in the handshake where an attacker controls how much we
 * hold, so the bound is not optional.
 */
#include <string.h>
#include <stdlib.h>
#include "crypto_bip324_transport.h"
#include "crypto_ellswift.h"

/* ------------------------------- buffers --------------------------------- */

static int buf_reserve(bip324_buf* b, unsigned long need){
    if (b->cap >= need) return 1;
    unsigned long cap = b->cap ? b->cap : 256;
    while (cap < need){
        if (cap > (unsigned long)-1 / 2) return 0;
        cap *= 2;
    }
    unsigned char* p = (unsigned char*)realloc(b->p, cap);
    if (!p) return 0;
    b->p = p; b->cap = cap;
    return 1;
}
static int buf_append(bip324_buf* b, const unsigned char* d, unsigned long n){
    if (!n) return 1;
    if (!buf_reserve(b, b->len + n)) return 0;
    memcpy(b->p + b->len, d, n);
    b->len += n;
    return 1;
}
static void buf_drop_front(bip324_buf* b, unsigned long n){
    if (n >= b->len){ b->len = 0; return; }
    memmove(b->p, b->p + n, b->len - n);
    b->len -= n;
}
static void buf_free(bip324_buf* b){ free(b->p); b->p = 0; b->len = b->cap = 0; }

/* --------------------------- the short-ID table -------------------------- */

/* BIP324 assigns one-byte ids to the common message types; anything else is
 * sent as a zero byte followed by the same 12-byte NUL-padded name v1 uses.
 * Index 0 is reserved for exactly that escape, so it is never a name. */
static const char* const SHORTID[] = {
    0,            "addr",       "block",      "blocktxn",   "cmpctblock",
    "feefilter",  "filteradd",  "filterclear","filterload", "getblocks",
    "getblocktxn","getdata",    "getheaders", "headers",    "inv",
    "mempool",    "merkleblock","notfound",   "ping",       "pong",
    "sendcmpct",  "tx",         "getcfilters","cfilter",    "getcfheaders",
    "cfheaders",  "getcfcheckpt","cfcheckpt", "addrv2"
};
#define SHORTID_N ((int)(sizeof(SHORTID)/sizeof(SHORTID[0])))

const char* bip324_shortid_name(unsigned id){
    if (id >= (unsigned)SHORTID_N) return 0;
    return SHORTID[id];
}
int bip324_shortid_for(const char* type){
    for (int i = 1; i < SHORTID_N; i++)
        if (SHORTID[i] && !strcmp(SHORTID[i], type)) return i;
    return -1;
}

/* ------------------------------ handshake -------------------------------- */

static void v1_prefix(unsigned char out[BIP324_V1_PREFIX_LEN], const unsigned char magic[4]){
    memcpy(out, magic, 4);
    memcpy(out + 4, "version", 7);
    memset(out + 11, 0, 5);
}

/* our key and garbage: everything we can send before hearing from them */
static int queue_key_and_garbage(bip324_transport_t* t){
    if (!buf_append(&t->send, t->our_ellswift, 64)) return 0;
    return buf_append(&t->send, t->sent_garbage.p, t->sent_garbage.len);
}

int bip324_t_init(bip324_transport_t* t, const unsigned char seckey32[32],
                  const unsigned char our_ellswift64[64], const unsigned char net_magic[4],
                  int initiator, const unsigned char* garbage, unsigned long garbage_len){
    memset(t, 0, sizeof *t);
    if (garbage_len > BIP324_MAX_GARBAGE_LEN) return 0;
    memcpy(t->our_seckey, seckey32, 32);
    memcpy(t->our_ellswift, our_ellswift64, 64);
    memcpy(t->net_magic, net_magic, 4);
    t->initiator = initiator ? 1 : 0;
    if (garbage_len && !buf_append(&t->sent_garbage, garbage, garbage_len)) return 0;

    /* An initiator has nothing to wait for; a responder must first rule out
     * a v1 peer, so it stays silent until then. */
    t->recv_state = t->initiator ? BIP324_RECV_KEY : BIP324_RECV_MAYBE_V1;
    if (t->initiator && !queue_key_and_garbage(t)) return 0;
    return 1;
}

void bip324_t_free(bip324_transport_t* t){
    buf_free(&t->recv); buf_free(&t->send);
    buf_free(&t->recv_garbage); buf_free(&t->sent_garbage); buf_free(&t->msg);
    memset(t->our_seckey, 0, sizeof t->our_seckey);
}

int bip324_t_is_v1(const bip324_transport_t* t){ return t->recv_state == BIP324_RECV_V1; }
const unsigned char* bip324_t_v1_prefix(const bip324_transport_t* t, unsigned long* len){
    *len = t->recv.len; return t->recv.p;
}

const unsigned char* bip324_t_send_pending(bip324_transport_t* t, unsigned long* len){
    *len = t->send.len; return t->send.p;
}
void bip324_t_send_consume(bip324_transport_t* t, unsigned long n){ buf_drop_front(&t->send, n); }

/* Send our garbage terminator and the version packet. The version packet's
 * AAD is OUR garbage, which is what binds the unauthenticated garbage bytes
 * to the session -- without it an attacker could rewrite them freely. */
static int queue_terminator_and_version(bip324_transport_t* t){
    unsigned char pkt[BIP324_EXPANSION];
    if (!buf_append(&t->send, t->cipher.send_garbage_terminator,
                    BIP324_GARBAGE_TERMINATOR_LEN)) return 0;
    bip324_encrypt(&t->cipher, pkt, 0, 0, t->sent_garbage.p, t->sent_garbage.len, 0);
    if (!buf_append(&t->send, pkt, sizeof pkt)) return 0;
    buf_free(&t->sent_garbage);          /* its only use is now spent */
    t->sent_version = 1;
    return 1;
}

/* Drive the state machine over whatever is in t->recv. 0 = protocol error. */
static int advance(bip324_transport_t* t){
    for (;;){
        switch (t->recv_state){

        case BIP324_RECV_MAYBE_V1: {
            unsigned char want[BIP324_V1_PREFIX_LEN];
            if (t->recv.len == 0) return 1;
            v1_prefix(want, t->net_magic);
            unsigned long n = t->recv.len < BIP324_V1_PREFIX_LEN ? t->recv.len : BIP324_V1_PREFIX_LEN;
            if (memcmp(t->recv.p, want, n)){
                /* one differing byte is already proof of v2 */
                t->recv_state = BIP324_RECV_KEY;
                if (!queue_key_and_garbage(t)) return 0;
                break;
            }
            if (n == BIP324_V1_PREFIX_LEN){
                t->recv_state = BIP324_RECV_V1;   /* caller replays recv buffer */
                return 1;
            }
            return 1;                              /* need more bytes to decide */
        }

        case BIP324_RECV_KEY: {
            if (t->recv.len < 64) return 1;
            memcpy(t->their_ellswift, t->recv.p, 64);
            buf_drop_front(&t->recv, 64);
            if (!bip324_init(&t->cipher, t->our_seckey, t->our_ellswift,
                             t->their_ellswift, t->net_magic, t->initiator, 0)) return 0;
            memset(t->our_seckey, 0, sizeof t->our_seckey);
            t->keys_ready = 1;
            if (!queue_terminator_and_version(t)) return 0;
            t->recv_state = BIP324_RECV_GARBAGE;
            break;
        }

        case BIP324_RECV_GARBAGE: {
            /* scan for their terminator; everything before it is garbage */
            const unsigned char* term = t->cipher.recv_garbage_terminator;
            unsigned long limit = BIP324_MAX_GARBAGE_LEN + BIP324_GARBAGE_TERMINATOR_LEN;
            unsigned long searchable = t->recv.len;
            if (searchable < BIP324_GARBAGE_TERMINATOR_LEN){
                if (t->recv.len > limit) return 0;
                return 1;
            }
            unsigned long last = searchable - BIP324_GARBAGE_TERMINATOR_LEN;
            for (unsigned long i = 0; i <= last; i++){
                if (i > BIP324_MAX_GARBAGE_LEN) return 0;      /* over the bound */
                if (!memcmp(t->recv.p + i, term, BIP324_GARBAGE_TERMINATOR_LEN)){
                    if (!buf_append(&t->recv_garbage, t->recv.p, i)) return 0;
                    buf_drop_front(&t->recv, i + BIP324_GARBAGE_TERMINATOR_LEN);
                    t->recv_state = BIP324_RECV_VERSION;
                    goto found;
                }
            }
            if (t->recv.len > limit) return 0;
            return 1;                                          /* keep waiting */
        found:
            break;
        }

        case BIP324_RECV_VERSION:
        case BIP324_RECV_APP: {
            /* Do not decrypt ahead of the caller: a second message would
             * overwrite one that has not been collected yet. */
            if (t->msg_ready) return 1;
            if (!t->have_len){
                if (t->recv.len < BIP324_LENGTH_LEN) return 1;
                t->pending_len = bip324_decrypt_length(&t->cipher, t->recv.p);
                if (t->pending_len > BIP324_MAX_MESSAGE_LEN) return 0;
                buf_drop_front(&t->recv, BIP324_LENGTH_LEN);
                t->have_len = 1;
            }
            unsigned long rest = t->pending_len + BIP324_HEADER_LEN + BIP324_AEAD_EXPANSION;
            if (t->recv.len < rest) return 1;

            unsigned char* plain = (unsigned char*)malloc(t->pending_len ? t->pending_len : 1);
            if (!plain) return 0;
            int ignore = 0;
            /* The version packet -- and only it -- is authenticated over the
             * garbage the peer sent. Every later packet has empty AAD. */
            const unsigned char* aad = (t->recv_state == BIP324_RECV_VERSION) ? t->recv_garbage.p : 0;
            unsigned long alen = (t->recv_state == BIP324_RECV_VERSION) ? t->recv_garbage.len : 0;
            int ok = bip324_decrypt(&t->cipher, plain, t->recv.p, rest, aad, alen, &ignore);
            buf_drop_front(&t->recv, rest);
            t->have_len = 0;
            if (!ok){ free(plain); return 0; }

            if (t->recv_state == BIP324_RECV_VERSION){
                buf_free(&t->recv_garbage);
                t->recv_state = BIP324_RECV_APP;
                free(plain);                       /* contents reserved; ignored */
                break;
            }
            if (ignore || t->pending_len == 0){    /* decoy, or an empty packet */
                free(plain);
                break;
            }
            /* decode the message type, then stash the payload for the caller */
            {
                unsigned char id = plain[0];
                unsigned long off;
                if (id == 0){
                    if (t->pending_len < 13){ free(plain); return 0; }
                    memcpy(t->msg_type, plain + 1, 12);
                    t->msg_type[12] = 0;
                    for (int i = 0; i < 12; i++)   /* NUL-padded, like v1 */
                        if (t->msg_type[i] == 0){ for (int j = i; j < 12; j++) t->msg_type[j] = 0; break; }
                    off = 13;
                } else {
                    const char* nm = bip324_shortid_name(id);
                    if (!nm){ free(plain); break; }   /* unknown id: ignore it */
                    strcpy(t->msg_type, nm);
                    off = 1;
                }
                t->msg.len = 0;
                if (!buf_append(&t->msg, plain + off, t->pending_len - off)){ free(plain); return 0; }
                t->msg_ready = 1;
            }
            free(plain);
            return 1;                              /* a message is ready */
        }

        case BIP324_RECV_V1:
            return 1;
        }
    }
}

int bip324_t_feed(bip324_transport_t* t, const unsigned char* data, unsigned long len){
    if (!buf_append(&t->recv, data, len)) return 0;
    if (t->recv_state == BIP324_RECV_V1) return 1;
    return advance(t);
}

int bip324_t_next_message(bip324_transport_t* t, const char** type,
                          const unsigned char** payload, unsigned long* plen){
    if (!t->msg_ready){
        if (t->recv_state == BIP324_RECV_V1 || !t->keys_ready) return 0;
        if (!advance(t)) return -1;
        if (!t->msg_ready) return 0;
    }
    *type = t->msg_type; *payload = t->msg.p; *plen = t->msg.len;
    t->msg_ready = 0;
    return 1;
}

int bip324_t_send_message(bip324_transport_t* t, const char* type,
                          const unsigned char* payload, unsigned long plen){
    if (!t->keys_ready || !t->sent_version) return 0;
    if (plen > BIP324_MAX_MESSAGE_LEN) return 0;

    int id = bip324_shortid_for(type);
    unsigned long hdr = (id > 0) ? 1 : 13;
    unsigned long clen = hdr + plen;
    unsigned char* contents = (unsigned char*)malloc(clen);
    if (!contents) return 0;
    if (id > 0) contents[0] = (unsigned char)id;
    else {
        unsigned long n = strlen(type);
        if (n > 12){ free(contents); return 0; }
        contents[0] = 0;
        memset(contents + 1, 0, 12);
        memcpy(contents + 1, type, n);
    }
    if (plen) memcpy(contents + hdr, payload, plen);

    unsigned char* pkt = (unsigned char*)malloc(clen + BIP324_EXPANSION);
    if (!pkt){ free(contents); return 0; }
    bip324_encrypt(&t->cipher, pkt, contents, clen, 0, 0, 0);
    int ok = buf_append(&t->send, pkt, clen + BIP324_EXPANSION);
    memset(contents, 0, clen);
    free(contents); free(pkt);
    return ok;
}
