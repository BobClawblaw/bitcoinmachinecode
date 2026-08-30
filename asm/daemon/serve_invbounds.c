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
