/* crypto_bip324_transport.h -- the BIP324 v2 transport state machine.
 *
 * Socket-independent on purpose: it consumes received bytes and produces
 * whole messages, and produces bytes to send from whole messages. Nothing in
 * here touches a file descriptor, which is what makes the handshake -- the
 * part hardest to get right and most dangerous to get wrong -- testable
 * without a network. */
#ifndef BMC_CRYPTO_BIP324_TRANSPORT_H
#define BMC_CRYPTO_BIP324_TRANSPORT_H
#include "crypto_bip324.h"

#define BIP324_V1_PREFIX_LEN 16
#define BIP324_MAX_MESSAGE_LEN 4000000     /* Core's MAX_PROTOCOL_MESSAGE_LENGTH */

enum {
    BIP324_RECV_MAYBE_V1 = 0,  /* responder: could still be a v1 peer */
    BIP324_RECV_KEY,           /* collecting their 64-byte ellswift */
    BIP324_RECV_GARBAGE,       /* scanning for their garbage terminator */
    BIP324_RECV_VERSION,       /* their first packet, aad = their garbage */
    BIP324_RECV_APP,           /* ordinary packets */
    BIP324_RECV_V1             /* fell back; caller should use the v1 path */
};

typedef struct {
    unsigned char* p;
    unsigned long  len, cap;
} bip324_buf;

typedef struct {
    bip324_cipher_t cipher;
    int             initiator;
    int             recv_state;
    int             keys_ready;
    unsigned char   net_magic[4];
    unsigned char   our_seckey[32];
    unsigned char   our_ellswift[64];
    unsigned char   their_ellswift[64];

    bip324_buf      recv;         /* undigested received bytes */
    bip324_buf      send;         /* bytes waiting to go out */
    bip324_buf      recv_garbage; /* their garbage, the version packet's aad */
    bip324_buf      sent_garbage; /* ours, the aad of the version packet we send */

    bip324_buf      msg;          /* the most recently completed message */
    char            msg_type[13];
    /* Separate from msg_type on purpose: the caller is handed a pointer INTO
     * msg_type, so "consumed" cannot be signalled by zeroing that buffer --
     * doing so blanks the string the caller is still holding. */
    int             msg_ready;

    int             sent_version;
    unsigned long   pending_len;  /* decrypted length of the packet in flight */
    int             have_len;
} bip324_transport_t;

/* `garbage`/`garbage_len` is our decoy prefix (0..BIP324_MAX_GARBAGE_LEN).
 * An initiator starts sending immediately; a responder waits until it has
 * ruled out a v1 peer. Returns 1 on success. */
int  bip324_t_init(bip324_transport_t* t, const unsigned char seckey32[32],
                   const unsigned char our_ellswift64[64], const unsigned char net_magic[4],
                   int initiator, const unsigned char* garbage, unsigned long garbage_len);
void bip324_t_free(bip324_transport_t* t);

/* Feed received bytes. 0 means a protocol violation and the caller must drop
 * the connection. */
int  bip324_t_feed(bip324_transport_t* t, const unsigned char* data, unsigned long len);

/* Pull one complete application message, if any. 1 = got one; `type` is a
 * NUL-terminated command name and the payload pointer is valid until the next
 * call. 0 = nothing complete yet, -1 = protocol violation, drop the peer.
 * Decoy (ignore-bit) packets never surface here. */
int  bip324_t_next_message(bip324_transport_t* t, const char** type,
                           const unsigned char** payload, unsigned long* plen);

/* Bytes the caller should write to the socket, and how many were taken. */
const unsigned char* bip324_t_send_pending(bip324_transport_t* t, unsigned long* len);
void bip324_t_send_consume(bip324_transport_t* t, unsigned long n);

/* Queue an application message. 0 if the session is not up yet or the message
 * is too large. */
int  bip324_t_send_message(bip324_transport_t* t, const char* type,
                           const unsigned char* payload, unsigned long plen);

/* Once this is true the caller must hand the connection to the v1 code path,
 * replaying bip324_t_v1_prefix() first. */
int  bip324_t_is_v1(const bip324_transport_t* t);
const unsigned char* bip324_t_v1_prefix(const bip324_transport_t* t, unsigned long* len);

/* The short-ID table, exposed for tests. NULL for unassigned ids. */
const char* bip324_shortid_name(unsigned id);
int         bip324_shortid_for(const char* type);   /* -1 if not in the table */
#endif
