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
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

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
 * matches -- so an unknown locator is served from height 1, the block after
 * genesis, not from genesis itself -- and honours hashStop.
 *
 * Payload: version(4) | CompactSize(count) | count*32 locator | 32 stop.
 *
 * Returns 1 with *out_from set to the height to serve FROM, or 2 with the same
 * outputs when the locator is EMPTY (Core's getheaders answers that with the
 * hashStop header alone; getblocks treats it as 1), and *out_stop set
 * to the stop hash's height or -1 when the stop hash is zero/unknown. When
 * out_stop_hash is not NULL the stop hash itself is copied there (getblocks
 * compares it against each block it walks, as Core does; zeroed on a
 * malformed message).
 * Returns 0 when the message is malformed, which the caller drops, and -1
 * when it is well formed but carries more than MAX_LOCATOR_SZ (101) entries,
 * for which Core disconnects the peer. In C for
 * the same reason the inv bounds are: a second hand-written varint walk in
 * assembly is how the first one went wrong.
 */
extern int idx_get(void* idx, const unsigned char hash[32], long* height);

/* A hash-index hit names a height; the block at that height is the one the
 * peer means only if index.dat still holds that hash there. A serve child's
 * index is its own copy: after a reorg it keeps the losing branch's hashes
 * until serve_reorg_check rebuilds it, which the getheaders path reached only
 * AFTER the locator walk (through serve_public_tip), and the worker can
 * truncate and rewrite index.dat at any moment of the walk. A stale hit
 * mis-placed the fork point: the peer was served the new branch from the
 * height of a block it has and we no longer do. Core walks the locator
 * against its active chain (FindForkInGlobalIndex: chain.Contains), so a
 * hash off it is skipped, and a stop hash off it never matches. Checking the
 * record closes the window whatever its timing. node_serve_loop registers
 * its store (index.dat is st+8); with none registered nothing is checked. */
static const void* g_loc_store = 0;
void serve_set_locator_store(const void* st){ g_loc_store = st; }
static int loc_on_chain(long h, const unsigned char hash[32]){
    if (!g_loc_store) return 1;
    int fd = (int)*(const long*)((const char*)g_loc_store + 8);
    if (fd < 0) return 1;
    unsigned char rec[48];
    if (h < 0 || pread(fd, rec, sizeof rec, (off_t)h * 48) != (ssize_t)sizeof rec) return 0;
    return memcmp(rec, hash, 32) == 0;    /* the record holds the hash in wire order */
}

int serve_locator_from(const unsigned char* pl, unsigned long plen, void* htidx,
                       long* out_from, long* out_stop, unsigned char* out_stop_hash){
    *out_from = 0;
    *out_stop = -1;
    if (out_stop_hash) for (int i = 0; i < 32; i++) out_stop_hash[i] = 0;
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

    /* CANONICAL COUNT (formal/parsers F1, 2026-10-23). Core reads the locator
     * with ReadCompactSize, which throws "non-canonical ReadCompactSize()"
     * for a value spelled in more bytes than it needs (fd 0100 for 1); the
     * exception is caught in ProcessMessages and the message is dropped,
     * unscored. This accepted the long spelling and served from it -- a
     * fingerprint, and the one parser here that still took one (the inv
     * bounds above refuse it). Drop it the same way: return 0. */
    if ((p == 4 + 3 && n < 0xfd) || (p == 4 + 5 && n <= 0xffff) ||
        (p == 4 + 9 && n <= 0xffffffffULL)) return 0;

    /* Core reads the whole CBlockLocator and the stop hash before it looks
     * at the count, so the order of these three matters (2026-10-23):
     *  - above MAX_SIZE (serialize.h 32), ReadCompactSize throws "size too
     *    large": dropped, like any parse failure;
     *  - fewer bytes than count*32 + 32: the vector read throws at the end
     *    of the message: dropped;
     *  - a complete locator of more than MAX_LOCATOR_SZ (101) entries:
     *    GETBLOCKS and GETHEADERS both set fDisconnect (net_processing.cpp
     *    4272, 4399). This returned 0 for it, so the peer was only ignored.
     * The 101 bound also keeps the walk below cheap. */
    if (n > 0x02000000ULL) return 0;
    if (plen < p + n * 32u + 32u) return 0;    /* locator + the stop hash */
    if (n > 101) return -1;

    /* first locator entry we know wins, in the order the peer sent them --
     * they run newest-first, so this is the most recent common block. None
     * known: FindForkInGlobalIndex returns genesis (validation.cpp 127-143)
     * and both handlers serve from its successor, height 1. This said 0 and
     * sent genesis, which no peer lacks (2026-10-23). */
    *out_from = 1;
    for (unsigned long long i = 0; i < n; i++){
        long h = 0;
        if (idx_get(htidx, pl + p + i * 32u, &h) == 1 && loc_on_chain(h, pl + p + i * 32u)){ *out_from = h + 1; break; }
    }

    /* hashStop: all-zero means "as many as you have" */
    { const unsigned char* stop = pl + p + n * 32u;
      if (out_stop_hash) for (int i = 0; i < 32; i++) out_stop_hash[i] = stop[i];
      int zero = 1;
      for (int i = 0; i < 32; i++) if (stop[i]){ zero = 0; break; }
      if (!zero){ long sh = 0; if (idx_get(htidx, stop, &sh) == 1 && loc_on_chain(sh, stop)) *out_stop = sh; } }
    return n == 0 ? 2 : 1;
}

/* ---- 3.1 (UTXO_INLINE_CONNECT_SCOPE, 2026-09-06): the tip bitcoin_serve.asm
 * tells a peer about is the CONNECTED tip.
 *
 * Five places in the serve loop read `*(int*)(st+24)` -- the per-connection
 * announce baseline, getheaders, getblocks, the tip-watch that announces a
 * new block, and node_announce_tip itself. During a download backlog that is
 * a height this node has stored but never validated, and a peer asking us
 * for headers was told about it. They now all call this instead: the stored
 * tip capped by the connected tip the worker publishes into the shared
 * status block (node_status_t.connected_tip). No pointer registered, or the
 * field at NODE_TIP_UNTRACKED (live tracking off), means the stored tip --
 * the pre-3.1 behaviour, and what the test harnesses that never register
 * anything still get.
 *
 * In C, like serve_locator_from, because it is one read of shared memory
 * and a compare, and the asm caller keeps its state in statics across the
 * call (rax..r11 are clobbered by any call). */
static const volatile long long* g_connected_tip = 0;
void serve_set_connected_tip_ptr(const volatile long long* p){ g_connected_tip = p; }

/* Follow the archive (2026-10-03). The serve process and its inbound children
 * hold a store handle whose idx_len (st+16) and tip (st+24) were read at boot;
 * the download worker -- another process -- appends every later block, and
 * nothing moved them. serve_idx_topup kept the HASH index current (getdata
 * works), but every reader of the stored tip -- getheaders, getblocks and the
 * tip-watch that announces a new block -- was capped at the boot height:
 * production's serve process reported tip=969479 at shutdown after nine hours
 * in which the chain passed 969,528, and a Core peer that dialled a freshly
 * synced bmc got an empty headers reply (validation/wtxid_relay_regtest_e2e.sh
 * found it). When index.dat has grown, move the two fields -- the tip from
 * idxscan_tip, which skips a zero-padded tail (idx_len/48-1 does not) -- and
 * fold the new heights into the hash index. Only those two fields: writers
 * take the append lock and find the true tip themselves
 * (idxscan_append_locked), so no append cursor is touched here. One fstat per
 * call, and only when the file grew more. */
extern long idxscan_tip(void) __attribute__((weak));
extern long serve_idx_topup(void) __attribute__((weak));
extern long serve_reorg_check(void) __attribute__((weak));   /* daemon/main.c, 2026-10-04 */
static long g_followed_len = -1;            /* index.dat size this process last followed */
static void serve_store_follow(const void* stc){
    char* st = (char*)stc;
    int fd = (int)*(long*)(st + 8);
    struct stat sb;
    if (fd < 0 || fstat(fd, &sb) != 0) return;
    long len = (long)sb.st_size - (long)(sb.st_size % 48);
    /* A reorg (2026-10-04): the worker rebuilt and bumped the generation;
     * rebuild our index and let the tip move BACK to the new branch's, once
     * -- forward-only following kept the old branch's height */
    if (serve_reorg_check && serve_reorg_check()){
        long tip = idxscan_tip ? idxscan_tip() : len / 48 - 1;
        *(long*)(st + 16) = len; *(int*)(st + 24) = (int)tip; g_followed_len = len;
        return;
    }
    /* keyed on the FILE, not on idx_len: the accept path refreshes idx_len
     * (st+16) before forking a child but never the tip, so a child starts
     * with idx_len current and st+24 at the boot height (seen in a live
     * child under gdb: 5808 = 121 records, tip 0) */
    if (len == g_followed_len) return;
    g_followed_len = len;
    long tip = idxscan_tip ? idxscan_tip() : len / 48 - 1;
    if (len > *(long*)(st + 16)) *(long*)(st + 16) = len;
    if (tip > (long)*(int*)(st + 24)) *(int*)(st + 24) = (int)tip;   /* never moved back */
    if (serve_idx_topup) serve_idx_topup();
}
long serve_public_tip(const void* st){
    serve_store_follow(st);
    long stored = (long)*(const int*)((const char*)st + 24);
    if (!g_connected_tip) return stored;
    long long cap = *g_connected_tip;
    if (cap == -2LL /* NODE_TIP_UNTRACKED */) return stored;
    return cap < (long long)stored ? (long)cap : stored;
}
