/* daemon/netaddr.c -- see netaddr.h. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "netaddr.h"
#include "asmap.h"   /* -asmap: AS-level bucketing */
#include "../base32.h"
extern void sha3_256(unsigned char out[32], const void* data, unsigned long len);

int bmc_net_addrlen(int net){
    switch (net){ case BMC_NET_IPV4: return 4; case BMC_NET_IPV6: return 16; case BMC_NET_TORV3: return 32;
                  case BMC_NET_I2P: return 32; case BMC_NET_CJDNS: return 16; default: return 0; }
}
const char* bmc_net_name(int net){
    switch (net){ case BMC_NET_IPV4: return "ipv4"; case BMC_NET_IPV6: return "ipv6"; case BMC_NET_TORV3: return "onion";
                  case BMC_NET_I2P: return "i2p"; case BMC_NET_CJDNS: return "cjdns"; default: return "unroutable"; }
}
int bmc_net_from_name(const char* s){
    if (!s) return -1;
    if (!strcmp(s, "ipv4"))  return BMC_NET_IPV4;
    if (!strcmp(s, "ipv6"))  return BMC_NET_IPV6;
    if (!strcmp(s, "onion")) return BMC_NET_TORV3;
    if (!strcmp(s, "i2p"))   return BMC_NET_I2P;
    if (!strcmp(s, "cjdns")) return BMC_NET_CJDNS;
    return -1;
}

/* Tor v3: checksum = SHA3-256(".onion checksum" || pubkey || 0x03)[0..1] */
static void onion_checksum(unsigned char out[2], const unsigned char pk[32]){
    unsigned char m[48], h[32];
    memcpy(m, ".onion checksum", 15); memcpy(m + 15, pk, 32); m[47] = 3;
    sha3_256(h, m, 48); out[0] = h[0]; out[1] = h[1];
}

long bmc_addr_to_string(char* out, long cap, const bmc_addr_t* a){
    /* The longest form is an onion name: 56 base32 chars + ".onion" + NUL =
     * 63. A caller with a smaller buffer than the address needs gets 0 and an
     * EMPTY string -- never a truncated address (2026-08-28 review: a caller
     * passing 64 silently produced a pool of empty strings). */
    long need = 0;
    switch (a->net){
    case BMC_NET_IPV4:  need = 16; break;
    case BMC_NET_IPV6:  case BMC_NET_CJDNS: need = 46; break;
    case BMC_NET_TORV3: need = 63; break;
    case BMC_NET_I2P:   need = 61; break;
    default: break;
    }
    if (cap < need || !need){ if (cap > 0) out[0] = 0; return 0; }
    switch (a->net){
    case BMC_NET_IPV4:
        return snprintf(out, (size_t)cap, "%u.%u.%u.%u", a->addr[0], a->addr[1], a->addr[2], a->addr[3]);
    case BMC_NET_IPV6: case BMC_NET_CJDNS:
        if (!inet_ntop(AF_INET6, a->addr, out, (socklen_t)cap)) return 0;
        return (long)strlen(out);
    case BMC_NET_TORV3: {
        unsigned char raw[35]; memcpy(raw, a->addr, 32); onion_checksum(raw + 32, a->addr); raw[34] = 3;
        long n = base32_encode(out, raw, 35); memcpy(out + n, ".onion", 7); return n + 6; }
    case BMC_NET_I2P: {
        long n = base32_encode(out, a->addr, 32); memcpy(out + n, ".b32.i2p", 9); return n + 8; }
    default: out[0] = 0; return 0;
    }
}
long bmc_addr_to_string_port(char* out, long cap, const bmc_addr_t* a){
    char h[80]; if (!bmc_addr_to_string(h, sizeof h, a)) return 0;
    int br = (a->net == BMC_NET_IPV6 || a->net == BMC_NET_CJDNS);
    return snprintf(out, (size_t)cap, br ? "[%s]:%u" : "%s:%u", h, a->port);
}

static int ends_with(const char* s, const char* suf, long* stem){
    long ls = (long)strlen(s), lf = (long)strlen(suf);
    if (ls <= lf || strcmp(s + ls - lf, suf)) return 0;
    *stem = ls - lf; return 1;
}
int bmc_addr_from_string(bmc_addr_t* a, const char* s){
    long stem; memset(a, 0, sizeof *a);
    if (!s || !*s) return 0;
    if (ends_with(s, ".onion", &stem)){
        if (stem != 56) return 0;
        unsigned char raw[40]; if (base32_decode(raw, s, 56) != 35) return 0;
        if (raw[34] != 3) return 0;
        unsigned char ck[2]; onion_checksum(ck, raw);
        if (ck[0] != raw[32] || ck[1] != raw[33]) return 0;
        a->net = BMC_NET_TORV3; a->len = 32; memcpy(a->addr, raw, 32); return 1;
    }
    if (ends_with(s, ".b32.i2p", &stem)){
        if (stem != 52) return 0;
        unsigned char raw[40]; if (base32_decode(raw, s, 52) != 32) return 0;
        a->net = BMC_NET_I2P; a->len = 32; memcpy(a->addr, raw, 32); return 1;
    }
    unsigned char b[16];
    if (inet_pton(AF_INET, s, b) == 1){ a->net = BMC_NET_IPV4; a->len = 4; memcpy(a->addr, b, 4); return 1; }
    if (inet_pton(AF_INET6, s, b) == 1){
        /* an IPv4-mapped IPv6 string is still an IPv4 address */
        static const unsigned char v4map[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if (!memcmp(b, v4map, 12)){ a->net = BMC_NET_IPV4; a->len = 4; memcpy(a->addr, b + 12, 4); return 1; }
        /* fc00::/8 is CJDNS *as a network*, and this is how an operator names
         * one (addpeeraddress, config). Core reaches the same classification
         * only when -cjdnsreachable is set; we accept the string and let
         * routability/reachability decide what may be dialled. A legacy addr
         * RECORD is never read this way -- see bmc_addr_decode_v1. */
        a->net = (b[0] == 0xfc) ? BMC_NET_CJDNS : BMC_NET_IPV6; a->len = 16; memcpy(a->addr, b, 16); return 1;
    }
    return 0;
}
int bmc_addr_from_string_port(bmc_addr_t* a, const char* s, unsigned short def_port){
    char host[128]; const char* pstr = NULL;
    if (!s || strlen(s) >= sizeof host) return 0;
    if (s[0] == '['){
        const char* e = strchr(s, ']'); if (!e) return 0;
        memcpy(host, s + 1, (size_t)(e - s - 1)); host[e - s - 1] = 0;
        if (e[1] == ':') pstr = e + 2; else if (e[1]) return 0;
    } else {
        const char* c = strrchr(s, ':');
        /* a bare IPv6 (many colons) has no port; "host:port" has exactly one */
        if (c && strchr(s, ':') == c){ memcpy(host, s, (size_t)(c - s)); host[c - s] = 0; pstr = c + 1; }
        else strcpy(host, s);
    }
    if (!bmc_addr_from_string(a, host)) return 0;
    if (pstr){ long p = atol(pstr); if (p <= 0 || p > 65535) return 0; a->port = (unsigned short)p; }
    else a->port = def_port;
    return 1;
}

int bmc_addr_is_v1_compatible(const bmc_addr_t* a){ return a->net == BMC_NET_IPV4 || a->net == BMC_NET_IPV6; }
int bmc_addr_is_routable(const bmc_addr_t* a){
    const unsigned char* b = a->addr;
    switch (a->net){
    case BMC_NET_IPV4:
        if (b[0] == 0 || b[0] == 127 || b[0] >= 240) return 0;
        if (b[0] == 10) return 0;
        if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return 0;
        if (b[0] == 192 && b[1] == 168) return 0;
        if (b[0] == 169 && b[1] == 254) return 0;
        if (b[0] == 100 && (b[1] & 0xc0) == 64) return 0;      /* RFC 6598 CGNAT */
        if (b[0] == 198 && (b[1] & 0xfe) == 18) return 0;      /* RFC 2544 benchmarking */
        if (b[0] == 192 && b[1] == 0 && b[2] == 2) return 0;   /* RFC 5737 doc TEST-NET-1 */
        if (b[0] == 198 && b[1] == 51 && b[2] == 100) return 0;/* RFC 5737 TEST-NET-2 */
        if (b[0] == 203 && b[1] == 0 && b[2] == 113) return 0; /* RFC 5737 TEST-NET-3 */
        if (b[0] == 192 && b[1] == 175 && b[2] == 48) return 0;/* RFC 7534 AS112 */
        if (b[0] == 192 && b[1] == 0 && b[2] == 0) return 0;   /* RFC 6890 IETF protocol assignments */
        return 1;
    case BMC_NET_IPV6: {
        static const unsigned char zero[16] = {0};
        if (!memcmp(b, zero, 15) && (b[15] == 0 || b[15] == 1)) return 0;  /* :: and ::1 */
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return 0;   /* fe80::/10 link-local */
        if ((b[0] & 0xfe) == 0xfc) return 0;                   /* fc00::/7 ULA (cjdns is its own net) */
        if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return 0; /* 2001:db8::/32 doc */
        if (b[0] == 0x20 && b[1] == 0x01 && (b[2] & 0xfe) == 0x00) return 0;       /* 2001::/23 ORCHID/Teredo etc (Core IsRFC4380/4843) */
        if (b[0] == 0x20 && b[1] == 0x02) return 0;            /* 2002::/16 6to4 (Core IsRFC3964) */
        { static const unsigned char v4map[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
          if (!memcmp(b, v4map, 12)) return 0;                 /* ::ffff:0:0/96 is IPv4, not a routable IPv6 */ }
        if (b[0] == 0xff) return 0;                            /* multicast */
        return 1; }
    case BMC_NET_CJDNS: return b[0] == 0xfc;
    case BMC_NET_TORV3: case BMC_NET_I2P: return 1;
    default: return 0;
    }
}
unsigned long long bmc_addr_group(const bmc_addr_t* a){
    unsigned long long g = (unsigned long long)a->net << 56;
    const unsigned char* b = a->addr;
    /* -asmap: bucket by AUTONOMOUS SYSTEM when a map is loaded. A /16 assumes
     * an attacker cannot cheaply get addresses across many /16s, but one
     * hosting provider routinely announces dozens of unrelated /16s from a
     * single AS -- so /16 counts them as diverse when they are not, and the
     * per-netgroup cap that is supposed to bound one party's share of the
     * book does not bound them at all. An ASN counts them as one.
     *
     * Falls back to the /16 (or /32 for v6) silently when no map is loaded,
     * so this is additive: a node without -asmap behaves exactly as before.
     * The 0x415300 tag ("AS") keeps AS-derived groups from colliding with
     * prefix-derived ones. */
    if (asmap_active() && (a->net == BMC_NET_IPV4 || a->net == BMC_NET_IPV6 || a->net == BMC_NET_CJDNS)){
        unsigned asn = asmap_lookup_net(a->net, a->addr, a->len);
        if (asn) return g | 0x415300ULL << 32 | asn;
    }
    switch (a->net){
    case BMC_NET_IPV4: return g | ((unsigned long long)b[0] << 8) | b[1];
    case BMC_NET_IPV6: case BMC_NET_CJDNS: return g | ((unsigned long long)b[0] << 24) | ((unsigned long long)b[1] << 16) | ((unsigned long long)b[2] << 8) | b[3];
    /* Core buckets Tor and I2P by NETWORK, not per address (addrman's
     * GetGroup returns the net id alone for them), so a flood of distinct
     * onion addresses from one peer is bounded by AI_MAX_PER_NETGROUP like
     * any other group -- giving each its own group made that cap useless
     * (2026-08-28 review). */
    default: return g;
    }
}
int bmc_addr_equal(const bmc_addr_t* a, const bmc_addr_t* b){
    return a->net == b->net && a->len == b->len && a->port == b->port && !memcmp(a->addr, b->addr, a->len);
}

static long put_csize(unsigned char* o, unsigned long long v){
    if (v < 0xfd){ o[0] = (unsigned char)v; return 1; }
    if (v <= 0xffff){ o[0] = 0xfd; o[1] = (unsigned char)v; o[2] = (unsigned char)(v >> 8); return 3; }
    if (v <= 0xffffffffULL){ o[0] = 0xfe; for (int i = 0; i < 4; i++) o[1+i] = (unsigned char)(v >> (8*i)); return 5; }
    o[0] = 0xff; for (int i = 0; i < 8; i++) o[1+i] = (unsigned char)(v >> (8*i)); return 9;
}
static long get_csize(const unsigned char* p, long len, unsigned long long* v){
    if (len < 1) return -1;
    if (p[0] < 0xfd){ *v = p[0]; return 1; }
    if (p[0] == 0xfd){ if (len < 3) return -1; *v = (unsigned long long)p[1] | ((unsigned long long)p[2] << 8); return 3; }
    if (p[0] == 0xfe){ if (len < 5) return -1; *v = 0; for (int i = 0; i < 4; i++) *v |= (unsigned long long)p[1+i] << (8*i); return 5; }
    if (len < 9) return -1;
    *v = 0; for (int i = 0; i < 8; i++) *v |= (unsigned long long)p[1+i] << (8*i);
    return 9;
}
long bmc_addr_encode_v2(unsigned char* out, long cap, const bmc_addr_t* a, unsigned long long services, unsigned time){
    int al = bmc_net_addrlen(a->net); if (!al || a->len != al) return 0;
    if (cap < 4 + 9 + 1 + 1 + al + 2) return 0;
    long o = 0;
    for (int i = 0; i < 4; i++) out[o++] = (unsigned char)(time >> (8*i));
    o += put_csize(out + o, services);
    out[o++] = a->net;
    out[o++] = (unsigned char)al;
    memcpy(out + o, a->addr, (size_t)al); o += al;
    out[o++] = (unsigned char)(a->port >> 8); out[o++] = (unsigned char)a->port;
    return o;
}
long bmc_addr_decode_v2(bmc_addr_t* a, unsigned long long* services, unsigned* time,
                        const unsigned char* p, long len, long* consumed){
    long o = 0; unsigned long long v;
    if (len < 4) return -1;
    *time = (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24); o = 4;
    long n = get_csize(p + o, len - o, &v); if (n < 0) return -1; *services = v; o += n;
    if (o >= len) return -1;
    int net = p[o++];
    n = get_csize(p + o, len - o, &v); if (n < 0 || v > 512) return -1; o += n;
    long al = (long)v;
    if (o + al + 2 > len) return -1;
    memset(a, 0, sizeof *a);
    int want = bmc_net_addrlen(net);
    if (!want || want != al){ *consumed = o + al + 2; return -2; }   /* unknown/odd: skip it, as Core does */
    a->net = (unsigned char)net; a->len = (unsigned char)al; memcpy(a->addr, p + o, (size_t)al); o += al;
    a->port = (unsigned short)((p[o] << 8) | p[o+1]); o += 2;
    if (net == BMC_NET_CJDNS && a->addr[0] != 0xfc){ *consumed = o; return -2; }  /* Core: CJDNS must be fc00::/8 */
    *consumed = o; return o;
}
long bmc_addr_encode_v1(unsigned char* out, long cap, const bmc_addr_t* a, unsigned long long services, unsigned time){
    if (!bmc_addr_is_v1_compatible(a) || cap < 30) return 0;
    for (int i = 0; i < 4; i++) out[i] = (unsigned char)(time >> (8*i));
    for (int i = 0; i < 8; i++) out[4+i] = (unsigned char)(services >> (8*i));
    if (a->net == BMC_NET_IPV4){ memset(out + 12, 0, 10); out[22] = 0xff; out[23] = 0xff; memcpy(out + 24, a->addr, 4); }
    else memcpy(out + 12, a->addr, 16);
    out[28] = (unsigned char)(a->port >> 8); out[29] = (unsigned char)a->port;
    return 30;
}
long bmc_addr_decode_v1(bmc_addr_t* a, unsigned long long* services, unsigned* time,
                        const unsigned char* p, long len){
    if (len < 30) return -1;
    *time = (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
    *services = 0; for (int i = 0; i < 8; i++) *services |= (unsigned long long)p[4+i] << (8*i);
    static const unsigned char v4map[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    memset(a, 0, sizeof *a);
    if (!memcmp(p + 12, v4map, 12)){ a->net = BMC_NET_IPV4; a->len = 4; memcpy(a->addr, p + 24, 4); }
    else {
        /* A legacy record has no network field: 16 bytes are IPv6, full stop.
         * Core's SetLegacyIPv6 does the same, and an fc00::/8 address arriving
         * this way is therefore an RFC 4193 ULA -- unroutable -- NOT CJDNS.
         * CJDNS exists only as addrv2 network id 6 (2026-08-28 review). */
        a->net = BMC_NET_IPV6; a->len = 16; memcpy(a->addr, p + 12, 16);
    }
    a->port = (unsigned short)((p[28] << 8) | p[29]);
    return 30;
}
