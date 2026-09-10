/* ============================================================================
 * addrmgr_twin.c -- peer address book + addr/addrv2 wire codecs, macOS/AArch64.
 * Functional twin of asm/bitcoin_addrmgr.asm (branch bmc_osx).
 *
 * Persisted address book (peers.dat, CWD), fixed 18-byte records, dedup by IP:
 *   [0..3]   ip        u32 (network order, as inet_pton yields)
 *   [4..5]   port      u16 BE (callers pass htons(host_port))
 *   [6..13]  services  u64 LE
 *   [14..17] last_seen u32 LE
 *   count = filesize / 18.
 *
 *   int  amr_init   (void *ab);                       -> 1 ok / -1 err
 *   long amr_count  (void *ab);                       -> #records / -1
 *   int  amr_add    (void *ab, u32 ip, u16 port, u64 services, u32 lastseen);
 *                                                     -> 1 added / 0 dup / -1
 *   int  amr_get_i  (void *ab, long i, u8 out[18]);   -> 1 / 0 (oor) / -1
 *   long amr_lookup (void *ab, u32 ip);               -> index / -1
 *   long p2p_addr_v1  (u8 *out, const u8 src[18n], long n);  -> bytes
 *   long p2p_addr_v2  (u8 *out, const u8 src[18n], long n);  -> bytes
 *   long p2p_addr_count (const u8 *pl, long plen);    -> #entries / -1
 *
 * Wire codecs reference Core's test_framework/messages.py (msg_addr /
 * msg_addrv2 over CAddress.serialize / serialize_v2):
 *   v1: CompactSize count, then per record 30 bytes [time u32][services u64]
 *       [ip16 ::ffff:a.b.c.d][port u16 BE].  v1 count is a CompactSize, NOT
 *       a single byte (300 records -> fd 2c 01).
 *   v2: CompactSize count, then [time u32][services CompactSize][net id 1]
 *       [len CompactSize = 4][a.b.c.d][port u16 BE].
 *
 * The 5 file-backed ops go through Darwin libc (open/lseek/read/write);
 * the x86 raw syscalls (nr in rax) collapse to libc calls here. Semantics
 * kept exactly: amr_count divides filesize by 18 (no error on partial
 * tail), amr_add seeks to end + writes 18 bytes, amr_get_i = lseek(i*18) +
 * read(18), amr_lookup walks get_i sequentially.
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef unsigned char u8;

static const char peername[] = "peers.dat";

long amr_lookup(void *ab, u32 ip);   /* fwd: amr_add dedups through it */

int amr_init(void *ab)
{
    int fd = open(peername, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;
    *(int *)ab = fd;                       /* x86: ab[0..7] = fd (64-bit store) */
    return 1;
}

long amr_count(void *ab)
{
    int fd = *(int *)ab;
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz < 0) return -1;
    return (long)(sz / 18);
}

/* CompactSize writer: 1/3/5/9 bytes. Returns bytes written.
 * Values < 0xfd: one byte. < 0x10000: fd + u16 LE. < 0x100000000:
 * fe + u32 LE. Else: ff + u64 LE. (Leaf, like the x86 amr_put_csize.) */
static long amr_put_csize(u8 *dst, u64 value)
{
    if (value < 0xfd) { dst[0] = (u8)value; return 1; }
    if (value < 0x10000) {
        dst[0] = 0xfd;
        for (int i = 0; i < 2; i++) dst[1 + i] = (u8)(value >> (8 * i));
        return 3;
    }
    if (value < 0x100000000ull) {
        dst[0] = 0xfe;
        for (int i = 0; i < 4; i++) dst[1 + i] = (u8)(value >> (8 * i));
        return 5;
    }
    dst[0] = 0xff;
    for (int i = 0; i < 8; i++) dst[1 + i] = (u8)(value >> (8 * i));
    return 9;
}

int amr_add(void *ab, u32 ip, u16 port, u64 services, u32 lastseen)
{
    int fd = *(int *)ab;
    if (amr_lookup(ab, ip) != -1) return 0;         /* dup */
    u8 rec[18];
    memcpy(rec + 0, &ip, 4);                        /* u32 as stored */
    memcpy(rec + 4, &port, 2);                      /* BE as passed */
    memcpy(rec + 6, &services, 8);                  /* u64 LE on LE hosts */
    memcpy(rec + 14, &lastseen, 4);
    off_t end = lseek(fd, 0, SEEK_END);
    if (end < 0) return -1;
    if (write(fd, rec, 18) != 18) return -1;
    return 1;
}

int amr_get_i(void *ab, long i, void *out)
{
    int fd = *(int *)ab;
    if (lseek(fd, (off_t)i * 18, SEEK_SET) < 0) return -1;
    if (read(fd, out, 18) != 18) return -1;         /* x86: short read -> -1 too */
    return 1;
}

long amr_lookup(void *ab, u32 ip)
{
    u8 rec[18];
    for (long i = 0;; i++) {
        if (amr_get_i(ab, i, rec) != 1) return -1;
        u32 rip;
        memcpy(&rip, rec, 4);
        if (rip == ip) return i;
    }
}

long p2p_addr_v1(u8 *out, const u8 *src, long n)
{
    long cur = amr_put_csize(out, (u64)n);
    for (long i = 0; i < n; i++) {
        const u8 *s = src + i * 18;
        u8 *r = out + cur;
        memcpy(r + 0, s + 14, 4);                   /* time = last_seen */
        memcpy(r + 4, s + 6, 8);                    /* services u64 LE */
        memset(r + 12, 0, 10);                      /* ::ffff: marker */
        r[22] = 0xff; r[23] = 0xff;
        memcpy(r + 24, s + 0, 4);                   /* a.b.c.d */
        memcpy(r + 28, s + 4, 2);                   /* port BE */
        cur += 30;
    }
    return cur;
}

long p2p_addr_v2(u8 *out, const u8 *src, long n)
{
    long cur = amr_put_csize(out, (u64)n);
    for (long i = 0; i < n; i++) {
        const u8 *s = src + i * 18;
        u8 *r = out + cur;
        memcpy(r + 0, s + 14, 4);                   /* time */
        cur += 4;
        cur += amr_put_csize(out + cur, *(const u64 *)(s + 6));  /* services */
        out[cur + 0] = 1;                           /* BIP155 network id: IPv4 */
        out[cur + 1] = 4;                           /* addr len CompactSize */
        memcpy(out + cur + 2, s + 0, 4);            /* a.b.c.d */
        memcpy(out + cur + 6, s + 4, 2);            /* port BE */
        cur += 8;
    }
    return cur;
}

long p2p_addr_count(const u8 *pl, long plen)
{
    if (plen < 1) return -1;
    u64 count;
    long vlen;
    u8 al = pl[0];
    if (al < 0xfd) { count = al; vlen = 1; }
    else if (al == 0xfd) {
        if (plen < 3) return -1;
        u16 w; memcpy(&w, pl + 1, 2);
        count = w; vlen = 3;
    } else if (al == 0xfe) {
        if (plen < 5) return -1;
        u32 w; memcpy(&w, pl + 1, 4);
        count = w; vlen = 5;
    } else if (al == 0xff) {
        if (plen < 9) return -1;
        memcpy(&count, pl + 1, 8);
        vlen = 9;
    } else {
        return -1;
    }
    /* x86 does this math in 32-bit eax (count*30 + vlen, ja plen). count is
     * u32 here, so the product is taken in u64 to avoid wrapping; for the
     * values the x86 can represent (count <= 0xffffffff) a u64 product can
     * only differ from the x86 when count*30 itself overflows u32 -- a
     * payload claiming >143 million entries, which fails the plen check
     * either way. */
    u64 needed = count * 30 + (u64)vlen;
    if (needed > (u64)plen) return -1;
    return (long)count;
}
