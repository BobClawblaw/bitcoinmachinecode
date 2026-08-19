#include <stdio.h>
/* script_find_and_delete / script_op_len / script_push_encode vs Core's own FindAndDelete unit-test cases (script_tests.cpp) -- see also test_legacy_sighash.c for the sighash.json fixture. */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

extern int64_t script_find_and_delete(unsigned char* dst, uint64_t dstcap,
    const unsigned char* src, uint64_t srclen,
    const unsigned char* needle, uint64_t needlelen);
extern int64_t script_op_len(const unsigned char* pos, const unsigned char* end);
extern int64_t script_push_encode(unsigned char* dst, uint64_t dstcap,
    const unsigned char* data, uint64_t datalen);

static int fails = 0, checks = 0;

static int hex2b(const char* h, unsigned char* out){
    int i=0;
    while (h[2*i] && h[2*i+1]){ unsigned v; sscanf(h+2*i, "%2x", &v); out[i]=(unsigned char)v; i++; }
    return i;
}

static void ck(const char* label, const char* s_hex, const char* d_hex, const char* expect_hex){
    unsigned char s[256], d[256], exp[256], out[256];
    int sn = hex2b(s_hex, s);
    int dn = hex2b(d_hex, d);
    int en = hex2b(expect_hex, exp);
    checks++;
    int64_t r = script_find_and_delete(out, sizeof out, s, sn, d, dn);
    if (r < 0 || (int)r != en || memcmp(out, exp, en) != 0) {
        printf("FAIL %-30s got_len=%lld want_len=%d\n", label, (long long)r, en);
        printf("     got: "); for(int i=0;i<(r>0?(int)r:0) && i<64;i++) printf("%02x", out[i]); printf("\n");
        printf("     exp: "); for(int i=0;i<en;i++) printf("%02x", exp[i]); printf("\n");
        fails++;
    } else {
        printf("ok   %s\n", label);
    }
}

int main(void){
    /* Bitcoin Core's own BOOST_AUTO_TEST_CASE(script_FindAndDelete) cases,
     * transcribed from src/test/script_tests.cpp. */
    ck("delete-nothing-noop",           "5152",             "",       "5152");
    ck("single-match",                  "515253",           "52",     "5153");
    ck("multi-match-4x",                "535153535453",     "53",     "5154");
    ck("whole-push-matches-itself",     "0302ff03",         "0302ff03","");
    ck("two-consecutive-pushes-match",  "0302ff030302ff03", "0302ff03","");
    ck("single-byte-needle-no-boundary","0302ff030302ff03", "02",     "0302ff030302ff03");
    ck("single-byte-needle-no-match",   "0302ff030302ff03", "ff",     "0302ff030302ff03");
    ck("odd-strip-produces-new-push",   "0302ff030302ff03", "03",     "02ff0302ff03");
    ck("needle-spans-ops-no-match",     "02feed5169",       "feed51", "02feed5169");
    ck("needle-spans-ops-match",        "02feed5169",       "02feed51","69");
    ck("prefixed-needle-spans-nomatch", "516902feed5169",   "feed51", "516902feed5169");
    ck("prefixed-needle-spans-match",   "516902feed5169",   "02feed51","516969");
    ck("single-pass-not-iterative-1",   "00005151",         "0051",   "0051");
    ck("single-pass-not-iterative-2",   "000051005151",     "0051",   "0051");
    ck("malformed-trailing-pushdata1",  "4c05aabb",         "ff",     "4c05aabb");
    ck("needlelen-zero-empty-needle",   "abababab",         "",       "abababab");

    /* script_op_len direct boundary checks */
    {
        unsigned char b1[1] = {0x00};                 /* OP_0: unit=1 */
        unsigned char b2[76]; memset(b2,0,76); b2[0]=75; /* direct push, 75 data bytes: unit=76 */
        unsigned char b3[3] = {0x4c, 0x00, 0x00};      /* PUSHDATA1 len=0: unit=2 */
        unsigned char b4[5] = {0x4d, 0x02,0x00, 0xaa,0xbb}; /* PUSHDATA2 len=2: unit=5 */
        checks++; int64_t r1 = script_op_len(b1, b1+1);
        if (r1!=1){ printf("FAIL op_len OP_0 got=%lld want=1\n",(long long)r1); fails++; } else printf("ok   op_len OP_0\n");
        checks++; int64_t r2 = script_op_len(b2, b2+76);
        if (r2!=76){ printf("FAIL op_len direct75 got=%lld want=76\n",(long long)r2); fails++; } else printf("ok   op_len direct75\n");
        checks++; int64_t r3 = script_op_len(b3, b3+3);
        if (r3!=2){ printf("FAIL op_len PUSHDATA1-empty got=%lld want=2\n",(long long)r3); fails++; } else printf("ok   op_len PUSHDATA1-empty\n");
        checks++; int64_t r4 = script_op_len(b4, b4+5);
        if (r4!=5){ printf("FAIL op_len PUSHDATA2 got=%lld want=5\n",(long long)r4); fails++; } else printf("ok   op_len PUSHDATA2\n");
        checks++; int64_t r5 = script_op_len(b3, b3+1); /* PUSHDATA1 header truncated */
        if (r5!=0){ printf("FAIL op_len truncated-header got=%lld want=0\n",(long long)r5); fails++; } else printf("ok   op_len truncated-header\n");
    }

    /* script_push_encode round-trip: encode a sig-length payload, then
     * confirm find_and_delete recognizes it as a needle against a scriptCode
     * that literally contains that exact push. */
    {
        unsigned char sig[71]; for(int i=0;i<71;i++) sig[i] = (unsigned char)(i*7+3);
        unsigned char needle[80];
        int64_t nlen = script_push_encode(needle, sizeof needle, sig, 71);
        checks++;
        if (nlen != 72 || needle[0] != 71) { printf("FAIL push_encode len=%lld hdr=%02x\n",(long long)nlen, needle[0]); fails++; }
        else printf("ok   push_encode direct-length header\n");

        unsigned char script[200]; int p=0;
        script[p++] = 0x51; /* OP_1 */
        memcpy(script+p, needle, nlen); p += nlen;
        script[p++] = 0xac; /* OP_CHECKSIG */
        unsigned char out[200];
        int64_t r = script_find_and_delete(out, sizeof out, script, p, needle, nlen);
        checks++;
        if (r != 2 || out[0]!=0x51 || out[1]!=0xac) { printf("FAIL find_and_delete real-sig-needle r=%lld\n",(long long)r); fails++; }
        else printf("ok   find_and_delete real-sig-needle\n");
    }

    printf("\n%s (%d/%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks-fails, checks, fails);
    return fails?1:0;
}
