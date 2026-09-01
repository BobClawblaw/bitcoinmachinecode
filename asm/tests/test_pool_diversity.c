/* tests/test_pool_diversity.c -- the dial pool samples across networks.
 *
 * The address book is appended in the order addresses were learned, so a
 * pool built from "the first N dialable entries" is N IPv4 peers every time
 * and the anonymity networks are never dialled, however many of their
 * addresses the book holds. dl_pool_from_book now reservoir-samples each
 * reachable network and lays the pool out with per-network quotas and an
 * interleaving the rotation walks, keeping the boot dials mostly clearnet.
 *
 * dl_pool_from_book is static in daemon/main.c; include the TU (the
 * test_dial_budget pattern). The book is the real ab2 store in a temp dir. */
#include <stdio.h>
extern void sha3_256(unsigned char out[32], const void* data, unsigned long len);
extern long base32_encode(char* out, const unsigned char* in, long len);
extern int dialer_reset_for_test(void);
#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }
static int net_of(const char* s){ bmc_addr_t a; if(!bmc_addr_from_string_port(&a, s, 8333)) return -1; return a.net; }

int main(void){
    char dir[] = "/tmp/bmc_pool_XXXXXX";
    if(!mkdtemp(dir)){ perror("mkdtemp"); return 1; }
    if(chdir(dir) != 0){ perror("chdir"); return 1; }
    node_config_load("/nonexistent/bitcoin.conf");
    snprintf(g_cfg.onion_proxy, sizeof g_cfg.onion_proxy, "127.0.0.1:9050");   /* onion reachable */
    g_cfg.cjdnsreachable = 1;                                                  /* cjdns reachable (host has IPv6) */
    g_cfg.i2psam[0] = 0;                                                       /* i2p NOT reachable */
    dialer_reset_for_test();                       /* the transport state latched before these were set */
    ab2_t* b = addr_book(); ok(b != 0, "book opened in a temp dir");
    char s[128]; bmc_addr_t a; int added = 0;
    for(int i = 0; i < 600; i++){ snprintf(s, sizeof s, "%d.%d.%d.%d", 11, 1 + (i >> 7), 1 + (i & 127), 7); if(bmc_addr_from_string_port(&a, s, 8333) && ab2_add(b, &a, 0x409, 100 + i) == 1) added++; }
    ok(added == 600, "600 IPv4 entries added");
    { int extra = 0; for(int i = 600; i < 4300; i++){ snprintf(s, sizeof s, "%d.%d.%d.%d", i < 4096 ? 11 : 22, 1 + (i >> 7) % 250, 1 + (i & 127), 9); if(bmc_addr_from_string_port(&a, s, 8333) && ab2_add(b, &a, 0x409, 100 + i) == 1) extra++; }
      ok(extra == 3700, "3700 more IPv4 entries: the book now has 4300, the last 204 with a 22. prefix beyond the head window"); }
    static const char* alpha = "abcdefghijklmnopqrstuvwxyz234567";
    int nonion = 0;
    for(int i = 0; i < 30; i++){
        /* a syntactically valid v3 onion needs a correct checksum; build the
         * 35-byte payload (pubkey, checksum, version) and encode it */
        unsigned char pub[32]; memset(pub, 0x40 + i, 32); pub[31] = (unsigned char)i;
        unsigned char chk_in[48]; memcpy(chk_in, ".onion checksum", 15); memcpy(chk_in + 15, pub, 32); chk_in[47] = 3;
        unsigned char chk[32]; sha3_256(chk, chk_in, 48);
        unsigned char payload[35]; memcpy(payload, pub, 32); payload[32] = chk[0]; payload[33] = chk[1]; payload[34] = 3;
        char b32[64]; long bl = base32_encode(b32, payload, 35); if(bl > 0 && bl < 64) b32[bl] = 0;
        snprintf(s, sizeof s, "%s.onion", b32);
        if(bmc_addr_from_string_port(&a, s, 8333) && ab2_add(b, &a, 0x409, 300 + i) == 1) nonion++;
    }
    ok(nonion == 30, "30 onion entries added");
    int ni2p = 0;
    for(int i = 0; i < 10; i++){ char h[64]; for(int j = 0; j < 52; j++) h[j] = alpha[(i * 7 + j * 3) % 32]; h[51] = 'a'; h[52] = 0;   /* last symbol: padding bits zero */ snprintf(s, sizeof s, "%s.b32.i2p", h); if(bmc_addr_from_string_port(&a, s, 0) && ab2_add(b, &a, 0x409, 400 + i) == 1) ni2p++; }
    ok(ni2p == 10, "10 i2p entries added");
    int nv6 = 0, ncj = 0;
    for(int i = 0; i < 20; i++){ snprintf(s, sizeof s, "[2a02:1234:%x::%x]:8333", i + 1, i + 1); if(bmc_addr_from_string_port(&a, s, 0) && ab2_add(b, &a, 0x409, 500 + i) == 1) nv6++; }
    for(int i = 0; i < 5; i++){ snprintf(s, sizeof s, "[fc00:1:2:%x::%x]:8333", i + 1, i + 1); if(bmc_addr_from_string_port(&a, s, 0) && ab2_add(b, &a, 0x409, 600 + i) == 1) ncj++; }
    ok(nv6 == 20 && ncj == 5, "20 ipv6 and 5 cjdns entries added");
    printf("  book: %ld entries\n", ab2_count(b));

    { const char* nm[7] = {"?","ipv4","ipv6","?","onion","i2p","cjdns"}; printf("  reachable:"); for(int k = 1; k <= 6; k++) if(k != 3) printf(" %s=%d", nm[k], dialer_net_reachable(k)); printf("\n");
      bmc_addr_t t; bmc_addr_from_string_port(&t, "[2a02:1234:1::1]:8333", 0); printf("  routable ipv6=%d", bmc_addr_is_routable(&t)); bmc_addr_from_string_port(&t, "[fc00:1:2:1::1]:8333", 0); printf(" cjdns=%d\n", bmc_addr_is_routable(&t)); }
    printf("== the pool ==\n");
    static char pool[64][DL_POOL_SLOT];
    dl_pool_test_seed(12345);
    int n = dl_pool_from_book(NULL, pool, 64);
    ok(n == 64, "64 entries");
    int c[8] = {0}; int dup = 0;
    for(int i = 0; i < n; i++){ int k = net_of(pool[i]); if(k >= 0 && k < 8) c[k]++; for(int j = 0; j < i; j++) if(!strcmp(pool[i], pool[j])) dup++; }
    printf("  ipv4 %d ipv6 %d onion %d i2p %d cjdns %d\n", c[BMC_NET_IPV4], c[BMC_NET_IPV6], c[BMC_NET_TORV3], c[BMC_NET_I2P], c[BMC_NET_CJDNS]);
    ok(dup == 0, "no duplicates");
    int r6 = dialer_net_reachable(BMC_NET_IPV6), exp6 = r6 ? 8 : 0;
    printf("  (global IPv6 route on this host: %s)\n", r6 ? "yes" : "no -- ipv6 quota expected 0");
    ok(c[BMC_NET_TORV3] == 12, "onion quota: 12 of 64");
    ok(c[BMC_NET_IPV6] == exp6, "ipv6 quota: 8 of 64 when a global route exists, else none");
    ok(c[BMC_NET_CJDNS] == 3, "cjdns quota: 3 of 64");
    ok(c[BMC_NET_I2P] == 0, "i2p: none -- its transport is not configured, so nothing in the pool");
    ok(c[BMC_NET_IPV4] == 64 - 15 - exp6, "clearnet fills the rest");
    ok(net_of(pool[3]) == BMC_NET_TORV3 && (!r6 || net_of(pool[6]) == BMC_NET_IPV6), "boot slots: an onion at 3 (and an ipv6 at 6 when reachable)");
    int early_v4 = 0; for(int i = 0; i < 8; i++) if(i != 3 && !(r6 && i == 6) && net_of(pool[i]) == BMC_NET_IPV4) early_v4++;
    ok(early_v4 == (r6 ? 6 : 7), "...and the other boot slots are clearnet (sequential dials stay fast)");
    int beyond = 0; for(int i = 0; i < n; i++) if(!strncmp(pool[i], "22.", 3)) beyond++;
    ok(beyond == 0, "no clearnet entry from beyond the head window (gossip tail)");
    int first_onion_after8 = -1; for(int i = 8; i < n; i++) if(net_of(pool[i]) == BMC_NET_TORV3){ first_onion_after8 = i; break; }
    ok(first_onion_after8 >= 8 && first_onion_after8 <= 12, "the rotation reaches an onion within its first few dials past the boot slots");

    printf("== the 512-slot catch-up pool: floors, not proportions ==\n");
    { static char big[512][DL_POOL_SLOT]; dl_pool_test_seed(7);
      int nb = dl_pool_from_book(NULL, big, 512); int cb[8] = {0};
      for(int i = 0; i < nb; i++){ int k = net_of(big[i]); if(k >= 0 && k < 8) cb[k]++; }
      printf("  ipv4 %d ipv6 %d onion %d i2p %d cjdns %d\n", cb[BMC_NET_IPV4], cb[BMC_NET_IPV6], cb[BMC_NET_TORV3], cb[BMC_NET_I2P], cb[BMC_NET_CJDNS]);
      ok(nb == 512, "512 entries");
      ok(cb[BMC_NET_TORV3] == 12 && cb[BMC_NET_IPV6] == exp6 && cb[BMC_NET_CJDNS] == 3, "the anonymity floors stay 12/(8|0)/3 in the big pool");
      ok(cb[BMC_NET_IPV4] == 512 - 15 - exp6, "clearnet fills the rest (the downloader stays fast)"); }
    printf("== it is a sample, not the head of the file ==\n");
    static char pool2[64][DL_POOL_SLOT];
    dl_pool_test_seed(999);
    int n2 = dl_pool_from_book(NULL, pool2, 64);
    int same = 0; for(int i = 0; i < n && i < n2; i++) if(!strcmp(pool[i], pool2[i])) same++;
    ok(n2 == 64 && same < 64, "a different seed gives a different pool");
    int head = 0; for(int i = 0; i < n; i++) if(net_of(pool[i]) == BMC_NET_IPV4){ unsigned q0 = 0; sscanf(pool[i], "%u.", &q0); (void)q0; head++; }
    ok(head == 64 - 15 - exp6, "every clearnet entry is a parseable ipv4");

    printf("== nothing reachable but clearnet ==\n");
    g_cfg.onion_proxy[0] = 0; g_cfg.cjdnsreachable = 0; dialer_reset_for_test();
    int n3 = dl_pool_from_book(NULL, pool2, 64);
    int anon = 0; for(int i = 0; i < n3; i++){ int k = net_of(pool2[i]); if(k == BMC_NET_TORV3 || k == BMC_NET_I2P || k == BMC_NET_CJDNS) anon++; }
    ok(n3 == 64 && anon == 0, "with no anonymity transport configured the pool holds none of their addresses");

    char cmd[256]; snprintf(cmd, sizeof cmd, "rm -rf %s", dir); (void)!system(cmd);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
