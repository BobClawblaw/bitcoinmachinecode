/* tests/test_netaddr.c -- the generic address type against Core's string
 * forms and Core's own wire bytes (test_framework/messages.py) for all five
 * BIP155 networks. */
#include <stdio.h>
#include <string.h>
#include "../daemon/netaddr.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static long unhex(unsigned char* o, const char* h){ long n = 0; for (; h[0] && h[1]; h += 2){ unsigned v; sscanf(h, "%2x", &v); o[n++] = (unsigned char)v; } return n; }
/* Core: msg_addrv2 of [ipv4 123.123.123.1:8333 svc9 t1700000000] [ipv6 2001:db8::1:8334 svc1]
 * [onion pg6mm...:8335 svc9] [i2p c4gfn...:0 svc9] [cjdns fc00:1:2:3::4:8337 svc0x409] */
static const char* V2_MIXED = "0500f153650901047b7b7b01208d01f1536501021020010db8000000000000000000000001208e02f1536509042079bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f208f03f15365090520170c56ce72a5a0e62306a3c7084318ee3a46355d17f67896a09c51efbe23fd71000004f15365fd09040610fc0000010002000300000000000000042091";
static const char* V1_V4_V6 = "0200f15365090000000000000000000000000000000000ffff7b7b7b01208d01f15365010000000000000020010db8000000000000000000000001208e";
static const char* ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
static const char* I2P = "c4gfnttsuwqomiygupdqqqyy5y5emnk5c73hrfvatri67prd7vyq.b32.i2p";
int main(void){
    bmc_addr_t a; char s[96];
    printf("== strings, Core's forms ==\n");
    ck("ipv4 parse", bmc_addr_from_string(&a, "123.123.123.1") && a.net == BMC_NET_IPV4 && a.addr[3] == 1);
    ck("ipv4 print", bmc_addr_to_string(s, sizeof s, &a) && !strcmp(s, "123.123.123.1"));
    ck("ipv6 parse", bmc_addr_from_string(&a, "2001:db8::1") && a.net == BMC_NET_IPV6 && a.addr[0] == 0x20 && a.addr[15] == 1);
    ck("ipv6 print", bmc_addr_to_string(s, sizeof s, &a) && !strcmp(s, "2001:db8::1"));
    ck("::ffff:1.2.3.4 is ipv4", bmc_addr_from_string(&a, "::ffff:1.2.3.4") && a.net == BMC_NET_IPV4 && a.addr[0] == 1);
    ck("onion parse (checksum + version verified)", bmc_addr_from_string(&a, ONION) && a.net == BMC_NET_TORV3 && a.addr[0] == 0x79 && a.addr[31] == 0x1f);
    ck("onion print", bmc_addr_to_string(s, sizeof s, &a) && !strcmp(s, ONION));
    { char bad[80]; strcpy(bad, ONION); bad[10] = (bad[10] == 'a') ? 'b' : 'a';
      ck("onion with a corrupted character is rejected (checksum)", !bmc_addr_from_string(&a, bad)); }
    ck("i2p parse", bmc_addr_from_string(&a, I2P) && a.net == BMC_NET_I2P && a.addr[0] == 0x17 && a.addr[31] == 0x71);
    ck("i2p print", bmc_addr_to_string(s, sizeof s, &a) && !strcmp(s, I2P));
    ck("cjdns parse (fc00::/8 -> cjdns, not ipv6)", bmc_addr_from_string(&a, "fc00:1:2:3::4") && a.net == BMC_NET_CJDNS);
    ck("cjdns print", bmc_addr_to_string(s, sizeof s, &a) && !strcmp(s, "fc00:1:2:3::4"));
    ck("fd00:: (ULA, not cjdns) is ipv6 and unroutable", bmc_addr_from_string(&a, "fd00::1") && a.net == BMC_NET_IPV6 && !bmc_addr_is_routable(&a));
    ck("garbage rejected", !bmc_addr_from_string(&a, "not.an.address") && !bmc_addr_from_string(&a, "pg6mm.onion"));
    ck("host:port", bmc_addr_from_string_port(&a, "1.2.3.4:8333", 1) && a.port == 8333);
    ck("[v6]:port", bmc_addr_from_string_port(&a, "[2001:db8::1]:8334", 1) && a.net == BMC_NET_IPV6 && a.port == 8334);
    ck("bare v6 gets the default port", bmc_addr_from_string_port(&a, "2001:db8::1", 7) && a.port == 7);
    ck("onion:port", bmc_addr_from_string_port(&a, "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8335", 1) && a.net == BMC_NET_TORV3 && a.port == 8335);
    ck("[v6]:port printed", bmc_addr_from_string_port(&a, "[fc00:1:2:3::4]:8337", 1) && bmc_addr_to_string_port(s, sizeof s, &a) && !strcmp(s, "[fc00:1:2:3::4]:8337"));

    printf("\n== addrv2: decode Core's mixed message, re-encode byte-exact ==\n");
    unsigned char buf[512]; long n = unhex(buf, V2_MIXED);
    ck("count 5", buf[0] == 5);
    long pos = 1; int got = 0; unsigned char re[512]; long ro = 1; re[0] = 5;
    const char* want_str[5] = { "123.123.123.1", "2001:db8::1", ONION, I2P, "fc00:1:2:3::4" };
    unsigned short want_port[5] = { 8333, 8334, 8335, 0, 8337 };
    unsigned long long want_svc[5] = { 9, 1, 9, 9, 0x409 };
    while (pos < n && got < 5){
        unsigned long long svc; unsigned t; long used;
        long r = bmc_addr_decode_v2(&a, &svc, &t, buf + pos, n - pos, &used);
        if (r < 0){ printf("  FAIL decode entry %d rc=%ld\n", got, r); fails++; break; }
        char l[160]; bmc_addr_to_string(s, sizeof s, &a);
        snprintf(l, sizeof l, "entry %d = %s:%u svc %llu t %u", got, s, a.port, svc, t);
        ck(l, !strcmp(s, want_str[got]) && a.port == want_port[got] && svc == want_svc[got] && t == 1700000000u + (unsigned)got);
        ro += bmc_addr_encode_v2(re + ro, sizeof re - ro, &a, svc, t);
        pos += used; got++;
    }
    ck("5 entries decoded, message fully consumed", got == 5 && pos == n);
    ck("re-encoded bytes == Core's msg_addrv2 (all five networks)", ro == n && !memcmp(re, buf, (size_t)n));

    printf("\n== legacy addr: native IPv6 record and v4-mapped record ==\n");
    n = unhex(buf, V1_V4_V6);
    { unsigned long long svc; unsigned t;
      ck("v1 rec 0 = ipv4 123.123.123.1:8333", bmc_addr_decode_v1(&a, &svc, &t, buf + 1, 30) == 30 && a.net == BMC_NET_IPV4 && a.port == 8333 && svc == 9);
      unsigned char e[32]; ck("v1 rec 0 re-encodes byte-exact", bmc_addr_encode_v1(e, 32, &a, svc, t) == 30 && !memcmp(e, buf + 1, 30));
      ck("v1 rec 1 = native ipv6 2001:db8::1:8334", bmc_addr_decode_v1(&a, &svc, &t, buf + 31, 30) == 30 && a.net == BMC_NET_IPV6 && a.port == 8334 && svc == 1);
      ck("v1 rec 1 re-encodes byte-exact", bmc_addr_encode_v1(e, 32, &a, svc, t) == 30 && !memcmp(e, buf + 31, 30));
      bmc_addr_from_string(&a, ONION);
      ck("an onion address cannot be encoded as legacy addr", bmc_addr_encode_v1(e, 32, &a, 9, 1) == 0 && !bmc_addr_is_v1_compatible(&a)); }

    printf("\n== a 16-byte LEGACY record is IPv6, never CJDNS (Core SetLegacyIPv6) ==\n");
    { unsigned char rec[30]; memset(rec, 0, 30);
      rec[0]=1; rec[4]=9; rec[12]=0xfc; rec[13]=0x00; rec[27]=1; rec[28]=0x20; rec[29]=0x8d;
      unsigned long long svc; unsigned t;
      ck("fc00::1 in a v1 record decodes as ipv6", bmc_addr_decode_v1(&a, &svc, &t, rec, 30) == 30 && a.net == BMC_NET_IPV6);
      ck("and is unroutable (RFC 4193 ULA), so it is never stored or dialled", !bmc_addr_is_routable(&a));
      ck("the same address TYPED by an operator is cjdns (addrv2 network 6)", bmc_addr_from_string(&a, "fc00::1") && a.net == BMC_NET_CJDNS); }

    printf("\n== to_string refuses a buffer smaller than the address needs ==\n");
    { char small[64]; bmc_addr_from_string(&a, ONION);
      ck("an onion into 32 bytes -> 0 and an EMPTY string, never truncation", bmc_addr_to_string(small, 32, &a) == 0 && small[0] == 0);
      ck("an onion needs 63 bytes: 64 is enough", bmc_addr_to_string(small, 64, &a) == 62 && !strcmp(small, ONION));
      bmc_addr_from_string(&a, "1.2.3.4");
      ck("an IPv4 into 64 bytes is fine (it needs 16)", bmc_addr_to_string(small, 64, &a) == 7 && !strcmp(small, "1.2.3.4"));
      ck("an IPv4 into 8 bytes is refused, empty", bmc_addr_to_string(small, 8, &a) == 0 && small[0] == 0); }

    printf("\n== classification ==\n");
    bmc_addr_from_string(&a, "10.0.0.1"); ck("10/8 unroutable", !bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, "100.64.0.1"); ck("100.64/10 unroutable", !bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, "8.8.8.8"); ck("8.8.8.8 routable", bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, "2001:db8::1"); ck("2001:db8::/32 (documentation) unroutable", !bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, "2a01::1"); ck("2a01::1 routable", bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, "198.18.0.1");   ck("RFC 2544 benchmarking unroutable", !bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, "192.0.2.1");    ck("RFC 5737 TEST-NET-1 unroutable", !bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, "198.51.100.1"); ck("RFC 5737 TEST-NET-2 unroutable", !bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, "203.0.113.1");  ck("RFC 5737 TEST-NET-3 unroutable", !bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, "2002::1");      ck("2002::/16 6to4 unroutable", !bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, "fc00:1:2:3::4"); ck("cjdns routable", bmc_addr_is_routable(&a));
    bmc_addr_from_string(&a, ONION); ck("onion routable", bmc_addr_is_routable(&a));
    { bmc_addr_t b; bmc_addr_from_string(&a, "1.2.3.4"); bmc_addr_from_string(&b, "1.2.9.9");
      ck("ipv4 group is the /16", bmc_addr_group(&a) == bmc_addr_group(&b));
      bmc_addr_from_string(&b, "1.3.3.4"); ck("different /16, different group", bmc_addr_group(&a) != bmc_addr_group(&b));
      /* Core buckets Tor and I2P by network, so the per-group quota bites a
       * flood of distinct onion addresses from one peer */
      bmc_addr_from_string(&a, ONION); char other[80]; strcpy(other, ONION); 
      ck("two DIFFERENT onion addresses share one group (Core buckets Tor per network)",
         bmc_addr_from_string(&b, "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion") && bmc_addr_group(&a) == bmc_addr_group(&b));
      ck("an onion group differs from an i2p group", bmc_addr_from_string(&a, I2P) && bmc_addr_group(&a) != bmc_addr_group(&b)); }
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}
