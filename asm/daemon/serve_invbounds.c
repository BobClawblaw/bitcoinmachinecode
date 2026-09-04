/* daemon/serve_invbounds.c -- bounds for inbound inv / getdata vectors.
 *
 * WHY THIS IS IN C. bitcoin_serve.asm read the entry count as a SINGLE BYTE
 * (`cnt = pl[0]`) and then walked count*36 bytes without ever consulting the
 * payload length. Two things follow, both wrong:
 *
 *   1. A vector with more than 252 entries uses a multi-byte varint, which
 *      Core sends routinely. Reading 0xfd as the count and starting entries
 *      one byte later misparses the whole message.
 *   2. A SHORT message with a large count byte walks past the bytes actually
 *      received into whatever the previous, larger message left in the 8 MB
 *      receive buffer -- so a peer can make this node issue getdata for
 *      hashes assembled out of earlier traffic. Not a memory-safety bug (the
 *      buffer is far larger than 255*36) but peer-influenced nonsense.
 *
 * Hand-writing varint parsing plus overflow-safe bounds in assembly to fix
 * that would be trading one subtle parser for another. It lives here, and
 * the assembly calls it.
 *
 * The limit is Core's MAX_INV_SZ (50,000), and exceeding it is scored as
 * misbehaviour exactly as Core does ("inv message size = %u").
 */
#include <stddef.h>

#define INV_ENTRY   36                 /* type u32 LE + 32-byte hash */
#define INV_MAX_SZ  50000              /* Core's MAX_INV_SZ */

/* Parse the leading varint of an inv/getdata payload and check the vector
 * actually fits in what the peer sent.
 *
 *   1  -> ok; *count is the entry count, *off the first entry's offset
 *   0  -> malformed or short: the caller must drop the peer (no score;
 *         a truncated read is not necessarily malice)
 *  -1  -> count exceeds MAX_INV_SZ: a protocol violation, score it
 */
int serve_inv_bounds(const unsigned char* pl, long plen,
                     unsigned long long* count, long* off){
    if (!pl || plen < 1 || !count || !off) return 0;
    unsigned long long c;
    long o;
    unsigned char b0 = pl[0];
    if (b0 < 0xfd){ c = b0; o = 1; }
    else if (b0 == 0xfd){ if (plen < 3) return 0;
        c = (unsigned long long)pl[1] | ((unsigned long long)pl[2] << 8); o = 3; }
    else if (b0 == 0xfe){ if (plen < 5) return 0;
        c = 0; for (int i = 0; i < 4; i++) c |= (unsigned long long)pl[1+i] << (8*i); o = 5; }
    else { if (plen < 9) return 0;
        c = 0; for (int i = 0; i < 8; i++) c |= (unsigned long long)pl[1+i] << (8*i); o = 9; }

    /* CANONICAL ENCODING. Core's ReadCompactSize rejects a value encoded in
     * more bytes than it needs, and so must this: without the check, 0xff
     * followed by eight zero bytes is an alternative spelling of "0", and any
     * count has several valid encodings. That turns a length prefix into
     * something with more than one representation, which is exactly the kind
     * of ambiguity a parser should refuse rather than normalise. */
    if ((o == 3 && c < 0xfd) || (o == 5 && c <= 0xffff) ||
        (o == 9 && c <= 0xffffffffULL)) return 0;

    /* Size first: above the cap the multiplication below is the only thing
     * that could overflow, and this bounds it long before that. */
    if (c > INV_MAX_SZ) return -1;

    /* and the vector must fit in the bytes actually received */
    if ((unsigned long long)(plen - o) / INV_ENTRY < c) return 0;

    *count = c; *off = o;
    return 1;
}

/* ---------------------------------------------------------------- NET-8
 * getheaders: walk the WHOLE locator, not just its first hash.
 *
 * bitcoin_serve.asm looked up pl+5 alone and, on a miss, served from height
 * 0. It also checked only `plen >= 5`, so a 5-byte message read a stale hash
 * out of the receive buffer.
 *
 * Every peer that is one block ahead of us starts its locator with a hash we
 * do not have -- the incident report calls that "common, not rare" -- so each
 * getheaders was answered with 2000 headers from genesis, 162 KB, which a
 * Core peer discards as already known. Pure waste on every announcement, and
 * a fingerprint.
 *
 * Core's FindForkInGlobalIndex walks every locator entry and serves from the
 * first one on the active chain, falling back to genesis only when none
 * matches, and honours hashStop.
 *
 * Payload: version(4) | CompactSize(count) | count*32 locator | 32 stop.
 *
 * Returns 1 with *out_from set to the height to serve FROM, and *out_stop set
 * to the stop hash's height or -1 when the stop hash is zero/unknown.
 * Returns 0 when the message is malformed, which the caller drops. In C for
 * the same reason the inv bounds are: a second hand-written varint walk in
 * assembly is how the first one went wrong.
 */
extern int idx_get(void* idx, const unsigned char hash[32], long* height);

int serve_locator_from(const unsigned char* pl, unsigned long plen, void* htidx,
                       long* out_from, long* out_stop){
    *out_from = 0;
    *out_stop = -1;
    if (!pl || !htidx) return 0;
    if (plen < 4 + 1) return 0;

    unsigned long p = 4;                       /* skip nVersion */
    unsigned long long n = 0;
    unsigned char c = pl[p];
    if (c < 0xfd)      { n = c;                                    p += 1; }
    else if (c == 0xfd){ if (plen < p+3) return 0;
                         n = (unsigned long long)pl[p+1] | ((unsigned long long)pl[p+2] << 8);
                         p += 3; }
    else if (c == 0xfe){ if (plen < p+5) return 0;
                         n = 0; for (int i=0;i<4;i++) n |= (unsigned long long)pl[p+1+i] << (8*i);
                         p += 5; }
    else               { if (plen < p+9) return 0;
                         n = 0; for (int i=0;i<8;i++) n |= (unsigned long long)pl[p+1+i] << (8*i);
                         p += 9; }

    /* Core's MAX_LOCATOR_SZ is 101; anything larger is a malformed request.
     * The bound also stops an absurd count from making the walk expensive. */
    if (n > 101) return 0;
    if (plen < p + n * 32u + 32u) return 0;    /* locator + the stop hash */

    /* first locator entry we know wins, in the order the peer sent them --
     * they run newest-first, so this is the most recent common block */
    for (unsigned long long i = 0; i < n; i++){
        long h = 0;
        if (idx_get(htidx, pl + p + i * 32u, &h) == 1){ *out_from = h + 1; break; }
    }

    /* hashStop: all-zero means "as many as you have" */
    { const unsigned char* stop = pl + p + n * 32u;
      int zero = 1;
      for (int i = 0; i < 32; i++) if (stop[i]){ zero = 0; break; }
      if (!zero){ long sh = 0; if (idx_get(htidx, stop, &sh) == 1) *out_stop = sh; } }
    return 1;
}
