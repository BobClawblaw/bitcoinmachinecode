/* daemon/asmap.c -- Core's -asmap: map an IP to its autonomous-system number,
 * so the address manager can bucket peers by AS instead of by /16.
 *
 * WHY IT MATTERS. Address-book diversity is what stops one party filling the
 * book and choosing all our peers (eclipse). Bucketing by IPv4 /16 assumes an
 * attacker cannot cheaply obtain addresses across many /16s -- but a single
 * hosting provider routinely announces dozens of unrelated /16s from ONE AS,
 * so /16 bucketing counts them as diverse when they are not. Bucketing by ASN
 * counts them as one, which is the truth.
 *
 * THE FORMAT is Core's asmap bytecode, implemented here to be byte-compatible
 * with src/util/asmap.cpp so the same file works with both. It is a bit-
 * serialised binary trie over the address bits:
 *
 *   instruction  encoding   argument
 *   RETURN       0          ASN            -- leaf: this is the answer
 *   JUMP         10         offset >= 17   -- if the next address bit is 1,
 *                                             skip `offset` bits (right subtree)
 *   MATCH        110        value in [2,511] -- compare several address bits
 *                                             against a pattern; on mismatch
 *                                             return the current default
 *   DEFAULT      111        ASN            -- set the default for later MATCHes
 *
 * Two different bit orders are in play and mixing them silently produces
 * plausible-looking wrong answers, so they are named apart below: the
 * BYTECODE is read least-significant-bit-first within each byte, while the IP
 * ADDRESS is read most-significant-bit-first (network order, as a human reads
 * a prefix). Core does the same and calls them ConsumeBitLE / ConsumeBitBE.
 *
 * Integers use Core's class-prefixed variable-length coding: a run of
 * continuation bits selects a size class, then that many bits are read big-
 * endian within the class, with the class's base added.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include "asmap.h"
#include "log_ts.h"

#define ASMAP_INVALID 0xFFFFFFFFu

static const unsigned char* g_map;      /* mmap'd bytecode, or NULL */
static unsigned long        g_map_len;
static char                 g_map_path[512];

/* bytecode bit: least-significant-bit-first within each byte */
static int bit_le(unsigned long* bitpos, const unsigned char* d, unsigned long nbytes){
    if (*bitpos >= nbytes * 8) return -1;
    int b = (d[*bitpos / 8] >> (*bitpos % 8)) & 1;
    (*bitpos)++;
    return b;
}
/* address bit: most-significant-bit-first (network order) */
static int bit_be(unsigned* bitpos, const unsigned char* d){
    int b = (d[*bitpos / 8] >> (7 - (*bitpos % 8))) & 1;
    (*bitpos)++;
    return b;
}

/* Core's DecodeBits: continuation bits pick a size class, then `size` bits are
 * read big-endian within it. Returns ASMAP_INVALID on running off the end. */
static unsigned decode_bits(unsigned long* bitpos, const unsigned char* d, unsigned long nbytes,
                            unsigned minval, const unsigned char* sizes, int nsizes){
    unsigned val = minval;
    for (int i = 0; i < nsizes; i++){
        int bit;
        if (i + 1 != nsizes){
            bit = bit_le(bitpos, d, nbytes);
            if (bit < 0) return ASMAP_INVALID;
        } else bit = 0;                       /* last class: no continuation */
        if (bit){
            val += (1u << sizes[i]);
        } else {
            for (int b = 0; b < sizes[i]; b++){
                int x = bit_le(bitpos, d, nbytes);
                if (x < 0) return ASMAP_INVALID;
                val += (unsigned)x << (sizes[i] - 1 - b);
            }
            return val;
        }
    }
    return ASMAP_INVALID;
}

static const unsigned char TYPE_SIZES[]  = {0, 0, 1};
static const unsigned char ASN_SIZES[]   = {15,16,17,18,19,20,21,22,23,24};
static const unsigned char MATCH_SIZES[] = {1,2,3,4,5,6,7,8};
static const unsigned char JUMP_SIZES[]  = {5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,
                                            21,22,23,24,25,26,27,28,29,30};

enum { OP_RETURN = 0, OP_JUMP = 1, OP_MATCH = 2, OP_DEFAULT = 3 };

/* bit_width(x) - 1: a MATCH value's highest set bit gives the pattern length */
static int top_bit(unsigned v){ int n = 0; while (v){ n++; v >>= 1; } return n; }

/* Interpret the bytecode against `ip` (nbytes: 4 for IPv4, 16 for IPv6).
 * 0 means "no answer" -- 0 is not a valid ASN, which is how Core signals it. */
unsigned asmap_lookup_raw(const unsigned char* code, unsigned long codelen,
                          const unsigned char* ip, int nbytes){
    if (!code || !codelen || !ip) return 0;
    unsigned long pos = 0, endpos = codelen * 8;
    unsigned ip_bit = 0, ip_bits_end = (unsigned)nbytes * 8;
    unsigned default_asn = 0;
    while (pos < endpos){
        unsigned op = decode_bits(&pos, code, codelen, 0, TYPE_SIZES, 3);
        if (op == ASMAP_INVALID) break;
        if (op == OP_RETURN){
            unsigned asn = decode_bits(&pos, code, codelen, 1, ASN_SIZES, 10);
            if (asn == ASMAP_INVALID) break;
            return asn;
        } else if (op == OP_JUMP){
            unsigned jump = decode_bits(&pos, code, codelen, 17, JUMP_SIZES, 26);
            if (jump == ASMAP_INVALID) break;
            if (ip_bit == ip_bits_end) break;
            if ((unsigned long)jump >= endpos - pos) break;      /* jump past EOF */
            if (bit_be(&ip_bit, ip)) pos += jump;                /* 1 -> right subtree */
        } else if (op == OP_MATCH){
            unsigned match = decode_bits(&pos, code, codelen, 2, MATCH_SIZES, 8);
            if (match == ASMAP_INVALID) break;
            int matchlen = top_bit(match) - 1;
            if ((int)(ip_bits_end - ip_bit) < matchlen) break;
            for (int b = 0; b < matchlen; b++)
                if (bit_be(&ip_bit, ip) != (int)((match >> (matchlen - 1 - b)) & 1))
                    return default_asn;                          /* pattern miss */
        } else if (op == OP_DEFAULT){
            default_asn = decode_bits(&pos, code, codelen, 1, ASN_SIZES, 10);
            if (default_asn == ASMAP_INVALID) break;
        } else break;
    }
    /* Core asserts here because it sanity-checks the file at load. We return
     * 0 instead: a malformed map must degrade to "no ASN" and let the caller
     * fall back to /16 bucketing, never abort a running node. */
    return 0;
}

/* 1 on success. Failure is NOT fatal -- the caller falls back to /16. */
int asmap_load(const char* path){
    asmap_unload();
    if (!path || !*path) return 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0){ fprintf(stderr,"[asmap] cannot open %s: %s\n", path, strerror(errno)); return 0; }
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size <= 0){ close(fd); fprintf(stderr,"[asmap] %s is empty\n", path); return 0; }
    void* m = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED){ fprintf(stderr,"[asmap] cannot map %s\n", path); return 0; }
    g_map = m; g_map_len = (unsigned long)sb.st_size;
    snprintf(g_map_path, sizeof g_map_path, "%s", path);
    return 1;
}

void asmap_unload(void){
    if (g_map) munmap((void*)g_map, (size_t)g_map_len);
    g_map = NULL; g_map_len = 0; g_map_path[0] = 0;
}

int  asmap_active(void){ return g_map != NULL; }
unsigned long asmap_size(void){ return g_map_len; }

unsigned asmap_lookup(const unsigned char* ip, int nbytes){
    if (!g_map) return 0;
    return asmap_lookup_raw(g_map, g_map_len, ip, nbytes);
}

/* The form Core actually looks up (netgroup.cpp GetMappedAS): ALWAYS 128 bits.
 * An IPv4 goes in as ::ffff:a.b.c.d, not as four bare bytes -- the trie is
 * built over v6-mapped space, so a 4-byte lookup walks the wrong branches and
 * returns a confidently wrong ASN. Networks that are not IPv4/IPv6 have no
 * ASN at all (AS0 is reserved by RFC7607, which is why 0 is safe as "none"). */
unsigned asmap_lookup_net(int net, const unsigned char* addr, int len){
    if (!g_map || !addr) return 0;
    unsigned char v6[16];
    if (net == 1 /* BMC_NET_IPV4 */ && len == 4){
        memset(v6, 0, 10); v6[10] = 0xff; v6[11] = 0xff;
        memcpy(v6 + 12, addr, 4);
    } else if ((net == 2 /* IPV6 */ || net == 6 /* CJDNS */) && len == 16){
        memcpy(v6, addr, 16);
    } else return 0;                 /* onion / i2p / unknown: no ASN */
    return asmap_lookup_raw(g_map, g_map_len, v6, 16);
}
