/* P-ADDR1 / P-ADDRV2: addr and addrv2 ingestion (daemon/addr_ingest.c
 * addr_ingest_msg_vg, with the real record decoders of daemon/netaddr.c),
 * reached by any peer after the handshake.
 *
 * Environment (stubs; trusted):
 *   p2p_addr_count (bitcoin_addrmgr.asm): modelled in C below, instruction
 *     for instruction (the 0xff form reads only 4 count bytes; 32-bit imul,
 *     add and unsigned compare against the low 32 bits of plen)
 *   the address book (ab2_open/ab2_add_from): a sink that checks each record
 *   asmap: inactive;  time(): free;  g_cfg: free per-response / per-netgroup
 *     caps in [0, 1000]
 * Claims, for every payload of length <= FP_N and every token limit:
 *   - memory safety of the parsers and the quota table,
 *   - added <= 1000 (MAX_ADDR_TO_SEND) and <= the limit when one is given,
 *   - every address handed to the book has the length of its network,
 *   - a count over 1000 is always a violation,
 *   - FP_CORE_STRICT: an address is taken only from a payload Core's
 *     deserializer accepts whole (canonical CompactSizes within MAX_SIZE, no
 *     known network with the wrong length, no truncation before `count`
 *     records); a payload Core throws on is dropped by Core with nothing taken. */
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include "nd.h"
#include "netaddr.h"
#include "addrbook.h"
#include "node_config.h"
node_config_t g_cfg;
long p2p_addr_count(const void* plv, long plen){
    const unsigned char* b = plv;
    if (plen < 1) return -1;
    unsigned long long eax = b[0], ecx = 1;                             /* movzx eax, byte [rbx] */
    if (b[0] == 0xfd){ if (plen < 3) return -1; eax = (eax & 0xffff0000ull) | (unsigned long long)(b[1] | (b[2] << 8)); ecx = 3; }   /* mov ax,[rbx+1] */
    else if (b[0] == 0xfe){ if (plen < 5) return -1; eax = (unsigned long long)b[1] | ((unsigned long long)b[2] << 8) | ((unsigned long long)b[3] << 16) | ((unsigned long long)b[4] << 24); ecx = 5; }
    else if (b[0] == 0xff){ if (plen < 9) return -1; eax = (unsigned long long)b[1] | ((unsigned long long)b[2] << 8) | ((unsigned long long)b[3] << 16) | ((unsigned long long)b[4] << 24); ecx = 9; }   /* mov eax,[rbx+1]: 4 bytes only */
    unsigned long long edx = eax;
    unsigned long long need = ((eax * 30u) + ecx) & 0xffffffffull;      /* imul eax,30 ; add eax,ecx (mod 2^32) */
    if (need > ((unsigned long long)plen & 0xffffffffull)) return -1;   /* cmp eax, r12d ; ja .err (unsigned) */
    return (long)edx;
}
/* the clock: some second between 2001 and 2100 (environment) */
time_t time(time_t* t){ time_t v = (time_t)nondet_long(); ASSUME(v >= 1000000000L && v <= 4000000000L); if (t) *t = v; return v; }
int asmap_active(void){ return 0; }
unsigned asmap_lookup_net(int net, const unsigned char* a, int len){ (void)net; (void)a; (void)len; return 0; }
static char g_book_obj; static long g_added_calls;
ab2_t* ab2_open(const char* dir, int rw){ (void)dir; (void)rw; return (ab2_t*)&g_book_obj; }
int ab2_add_from(ab2_t* b, const bmc_addr_t* a, unsigned long long svc, unsigned tm, unsigned src){
    (void)b; (void)svc; (void)tm; (void)src; g_added_calls++;
    CHECK(a->len == bmc_net_addrlen(a->net) && a->len > 0, "book gets an address of its network's length");
    int r = nondet_int(); ASSUME(r >= -1 && r <= 1); return r;
}
#include SRC
#include <netaddr.c>     /* <..>: a mutated copy can stand in (mutanth) */
#ifndef FP_N
#define FP_N 64
#endif
/* ---- Core's deserializer, as a reference (serialize.h ReadCompactSize,
 * netaddress.h UnserializeV2Stream / SetNetFromBIP155Network, protocol.h
 * CAddress) : 1 = the whole vector deserializes, 0 = Core throws */
static int core_cs(const unsigned char* p, unsigned long len, unsigned long* pos, unsigned long long* v, int range){
    if (*pos >= len) return 0;
    unsigned char c = p[*pos]; unsigned w = c < 0xfd ? 1 : c == 0xfd ? 3 : c == 0xfe ? 5 : 9;
    if (*pos + w > len) return 0;
    unsigned long long x = 0;
    if (w == 1) x = c; else for (unsigned i = 0; i + 1 < w; i++) x |= (unsigned long long)p[*pos + 1 + i] << (8*i);
    if ((w == 3 && x < 0xfd) || (w == 5 && x <= 0xffff) || (w == 9 && x <= 0xffffffffULL)) return 0;
    if (range && x > 0x02000000ULL) return 0;
    *pos += w; *v = x; return 1;
}
static int core_addr_ok(const unsigned char* p, unsigned long len, int v2){
    unsigned long pos = 0; unsigned long long n;
    if (!core_cs(p, len, &pos, &n, 1)) return 0;
    for (unsigned long long k = 0; k < n; k++){
        if (!v2){ if (pos + 30 > len) return 0; pos += 30; continue; }
        unsigned long long s, al;
        if (pos + 4 > len) return 0; pos += 4;
        if (!core_cs(p, len, &pos, &s, 0)) return 0;
        if (pos + 1 > len) return 0; int net = p[pos++];
        if (!core_cs(p, len, &pos, &al, 1)) return 0;
        if (al > 512) return 0;
        int want = net == 1 ? 4 : net == 2 ? 16 : net == 3 ? 10 : net == 4 ? 32 : net == 5 ? 32 : net == 6 ? 16 : -1;
        if (want >= 0 && (unsigned long long)want != al) return 0;
        if (pos + al + 2 > len) return 0; pos += al + 2;
    }
    return 1;
}
int main(void){
    g_cfg.addr_max_per_response = nondet_int(); ASSUME(g_cfg.addr_max_per_response >= 0 && g_cfg.addr_max_per_response <= 1000);
    g_cfg.addr_max_per_netgroup = nondet_int(); ASSUME(g_cfg.addr_max_per_netgroup >= 0 && g_cfg.addr_max_per_netgroup <= 1000);
    size_t plen = nondet_size(); ASSUME(plen <= FP_N);
    unsigned char* pl = nd_buf(plen);
    long limit = nondet_long(); ASSUME(limit >= 0 && limit <= 1000);
    int viol = 7;
#ifdef FP_V2
#define FP_V2F 1
    const char* cmd = "addrv2";
#else
#define FP_V2F 0
    const char* cmd = "addr";
#endif
    long added = addr_ingest_msg_vg(0, cmd, pl, (long)plen, limit, &viol, nondet_uint());
    CHECK(viol == 0 || viol == 1, "viol is set");
    CHECK(added >= 0 && added <= 1000 && added <= g_added_calls, "added within MAX_ADDR_TO_SEND");
    if (limit > 0) CHECK(added <= limit, "added within the token budget");
    /* the code's own rule (ai_quota_t.viol): a count above MAX_ADDR_TO_SEND
     * is a violation and nothing is taken. Read the count as Core does; the
     * 9-byte form is left to X-ADDR1-core (the asm counter reads 4 bytes) */
    { unsigned long cpos = 0; unsigned long long c;
      if (plen >= 1 && pl[0] != 0xff && core_cs(pl, plen, &cpos, &c, 0) && c > 1000) CHECK(viol == 1 && added == 0, "count over 1000 is a violation and takes nothing"); }
#ifdef FP_CORE_STRICT
    if (added > 0) CHECK(core_addr_ok(pl, plen, FP_V2F), "CORE: addresses taken only from a payload Core deserializes");
#endif
    free(pl);
    COVER(added >= 2, "two addresses taken");
    COVER(viol == 1 && plen > 8, "a violation");
    COVER(g_added_calls >= 1 && added == 0, "an add the book refused");
    return 0;
}
