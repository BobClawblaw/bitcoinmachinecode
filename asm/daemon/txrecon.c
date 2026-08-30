/* daemon/txrecon.c -- BIP330 sendtxrcncl negotiation. See txrecon.h for why
 * this stops at negotiation.
 *
 * Every rule below is Core's, taken from net_processing.cpp's SENDTXRCNCL
 * send and receive sites and node/txreconciliation.cpp's RegisterPeer, rather
 * than from a reading of the BIP. Where the BIP is looser than Core, Core
 * wins: a peer that disagrees with Core disconnects us, and being right about
 * the specification is no comfort at that point.
 */
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "txrecon.h"

extern void sha256_full(unsigned char* out, const void* msg, long long len);

/* BIP340-style tagged hash: SHA256(H(tag) || H(tag) || msg). Core builds the
 * same thing via TaggedHash("Tx Relay Salting"). Spelled out rather than
 * carried as a precomputed midstate so there is no constant to mistranscribe
 * -- the ellswift work in this tree lost an afternoon to exactly that. */
static void tagged_hash(unsigned char out32[32], const char* tag,
                        const unsigned char* msg, long long mlen){
    unsigned char th[32];
    unsigned char buf[64 + 64];
    sha256_full(th, tag, (long long)strlen(tag));
    memcpy(buf, th, 32);
    memcpy(buf + 32, th, 32);
    memcpy(buf + 64, msg, (size_t)mlen);
    sha256_full(out32, buf, 64 + mlen);
    memset(buf, 0, sizeof buf);
}

void txrecon_combine_salt(unsigned char out32[32], unsigned long long salt1,
                          unsigned long long salt2){
    /* ASCENDING order, per BIP330. Both peers hold the same pair but in
     * opposite local roles, so ordering by VALUE is what makes the two sides
     * agree without having to settle who counts as first -- the same reason
     * BIP324's ECDH orders its inputs by role rather than by who is asking. */
    unsigned long long lo = salt1 < salt2 ? salt1 : salt2;
    unsigned long long hi = salt1 < salt2 ? salt2 : salt1;
    unsigned char msg[16];
    for (int i = 0; i < 8; i++) msg[i]     = (unsigned char)(lo >> (8 * i));
    for (int i = 0; i < 8; i++) msg[8 + i] = (unsigned char)(hi >> (8 * i));
    tagged_hash(out32, "Tx Relay Salting", msg, 16);
}

int txrecon_may_offer(int peer_proto_version, int peer_relays_txs,
                      int is_block_relay_only, int is_feeler,
                      int is_addr_fetch, int we_ignore_incoming_txs){
    /* Core: protocol >= WTXID_RELAY_VERSION (70016), the peer relays txs,
     * not block-relay-only, not a feeler, not an addr-fetch connection, and
     * we are not in -blocksonly. */
    if (peer_proto_version < 70016) return 0;
    if (!peer_relays_txs)           return 0;
    if (is_block_relay_only)        return 0;
    if (is_feeler)                  return 0;
    if (is_addr_fetch)              return 0;
    if (we_ignore_incoming_txs)     return 0;
    return 1;
}

int txrecon_may_accept(int we_have_txrecon, int after_verack,
                       int we_reject_incoming_txs, int peer_relays_txs){
    /* Not enabled here: Core IGNORES the message rather than dropping the
     * peer. Offering something we do not support is not the peer's fault. */
    if (!we_have_txrecon) return 0;
    /* sendtxrcncl is a pre-verack message; later is a protocol violation. */
    if (after_verack) return 0;
    /* The peer must not offer reconciliation to a node that said it wants no
     * transactions, in either direction. */
    if (we_reject_incoming_txs) return 0;
    if (!peer_relays_txs) return 0;
    return 1;
}

int txrecon_register(int offered, int registered, unsigned int peer_version,
                     unsigned long long local_salt, unsigned long long remote_salt,
                     unsigned char out_salt32[32], unsigned int* negotiated_version){
    /* We never offered, so this peer has no pre-registered salt. Core logs and
     * ignores -- it does NOT drop, because an unsolicited signal is not a
     * violation, only unexpected. */
    if (!offered) return TXRECON_NOT_FOUND;
    /* A second sendtxrcncl from a peer already registered IS a violation. */
    if (registered) return TXRECON_ALREADY_REGISTERED;

    /* Downgrade to the lower of the two versions, so a future peer may still
     * choose to reconcile at this one. */
    unsigned int v = peer_version < TXRECON_VERSION ? peer_version : TXRECON_VERSION;
    /* v1 is the floor; proposing below it is a violation, not a downgrade. */
    if (v < 1) return TXRECON_PROTOCOL_VIOLATION;

    if (negotiated_version) *negotiated_version = v;
    if (out_salt32) txrecon_combine_salt(out_salt32, local_salt, remote_salt);
    return TXRECON_SUCCESS;
}


/* ---- version-payload parsing and the wire messages ---------------------- */

/* The version payload, per Core's CNetMsgMaker: version u32, services u64,
 * timestamp i64, addr_recv 26, addr_from 26, nonce u64, user-agent (varstr),
 * start_height i32, and then -- only on 70001+ and only if the sender chose
 * to include it -- a single fRelay byte. Its ABSENCE means true. */
static int version_relays_txs(const unsigned char* p, long len, int* proto_out){
    if (!p || len < 4) return -1;
    unsigned int proto = (unsigned)p[0] | ((unsigned)p[1] << 8) |
                         ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
    if (proto_out) *proto_out = (int)proto;
    long o = 4 + 8 + 8 + 26 + 26 + 8;          /* through the nonce */
    if (o >= len) return -1;
    /* user agent: a CompactSize length then that many bytes */
    unsigned long long ualen; unsigned char b0 = p[o];
    if (b0 < 0xfd){ ualen = b0; o += 1; }
    else if (b0 == 0xfd){ if (o + 3 > len) return -1;
        ualen = (unsigned long long)p[o+1] | ((unsigned long long)p[o+2] << 8); o += 3; }
    else return -1;                            /* a >64 KiB user agent is nonsense */
    if (ualen > (unsigned long long)(len - o)) return -1;
    o += (long)ualen;
    if (o + 4 > len) return -1;
    o += 4;                                    /* start_height */
    /* fRelay is optional; absent means the peer WILL relay transactions. */
    if (o >= len) return 1;
    return p[o] ? 1 : 0;
}

static int random_u64(unsigned long long* v){
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    unsigned char b[8];
    int ok = read(fd, b, 8) == 8;
    close(fd);
    if (!ok) return 0;
    *v = 0;
    for (int i = 0; i < 8; i++) *v |= (unsigned long long)b[i] << (8 * i);
    return 1;
}

int txrecon_build_offer(const unsigned char* version_payload, long len,
                        int is_block_relay_only, int is_feeler, int is_addr_fetch,
                        int we_ignore_incoming_txs,
                        unsigned char out12[12], unsigned long long* salt_out){
    int proto = 0;
    int relays = version_relays_txs(version_payload, len, &proto);
    if (relays < 0) return 0;                  /* unparseable: do not offer */
    if (!txrecon_may_offer(proto, relays, is_block_relay_only, is_feeler,
                           is_addr_fetch, we_ignore_incoming_txs)) return 0;

    unsigned long long salt;
    if (!random_u64(&salt)) return 0;          /* no entropy: do not offer */

    unsigned int v = TXRECON_VERSION;
    for (int i = 0; i < 4; i++) out12[i]     = (unsigned char)(v >> (8 * i));
    for (int i = 0; i < 8; i++) out12[4 + i] = (unsigned char)(salt >> (8 * i));
    if (salt_out) *salt_out = salt;
    return 1;
}

int txrecon_parse(const unsigned char* payload, long len,
                  unsigned int* version_out, unsigned long long* salt_out){
    if (!payload || len < 12) return 0;        /* u32 + u64, exactly */
    unsigned int v = 0;
    for (int i = 0; i < 4; i++) v |= (unsigned int)payload[i] << (8 * i);
    unsigned long long s = 0;
    for (int i = 0; i < 8; i++) s |= (unsigned long long)payload[4 + i] << (8 * i);
    if (version_out) *version_out = v;
    if (salt_out) *salt_out = s;
    return 1;
}
