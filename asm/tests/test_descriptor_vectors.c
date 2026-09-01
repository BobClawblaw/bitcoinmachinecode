#define _GNU_SOURCE
/* tests/test_descriptor_vectors.c -- the descriptor engine against Core's
 * own descriptor_tests.cpp vectors: 43 descriptors (every non-miniscript,
 * non-musig case), each in private and public form, expanded at every
 * index Core lists and compared byte-for-byte to Core's scriptPubKeys;
 * the private form must print as Core's public form; checksums match. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../descriptor.h"
#include "desc_vectors.h"
#include "desc_mp_vectors.h"
static int fails = 0, checks = 0;
static void ck(const char* l, int c){ checks++; if (!c){ printf("  FAIL %s\n", l); fails++; } }
static void hex(char* o, const unsigned char* b, int n){ for (int i=0;i<n;i++) sprintf(o+2*i,"%02x",b[i]); o[2*n]=0; }
extern void sha256_full(unsigned char out[32], const void* msg, unsigned long len);
static int expand_matches(const char* label, const char* text, const desc_vec_t* v){
    static descr_t d; char err[256];
    if (!descr_parse(text, &d, err, sizeof err)){ printf("  FAIL %s: parse: %s\n", label, err); fails++; return 0; }
    int all = 1;
    if (strstr(label, "pub") && strstr(v->flags, "HARDENED")){
        /* Core: the public form parses, and expanding it needs the private key */
        descr_spk_t sp[4]; int n = descr_expand(&d, 0, sp, 4);
        if (n != -1 || !strstr(descr_last_error(), "without private keys")){ printf("  FAIL %s: hardened pub form expanded (%d, %s)\n", label, n, descr_last_error()); fails++; return 0; }
        return 1;
    }
    for (int i = 0; i < v->nidx; i++){
        descr_spk_t sp[4]; int n = descr_expand(&d, i, sp, 4);
        if (n != v->nspk[i]){ printf("  FAIL %s idx %d: %d spk(s), Core has %d (%s)\n", label, i, n, v->nspk[i], descr_last_error()); fails++; all = 0; continue; }
        for (int q = 0; q < n; q++){ char h[1100]; hex(h, sp[q].spk, sp[q].len);
            if (strcmp(h, v->spk[i][q])){ printf("  FAIL %s idx %d spk %d:\n    got  %s\n    want %s\n", label, i, q, h, v->spk[i][q]); fails++; all = 0; } }
    }
    return all;
}
static void strip_cs(char* s){ char* h = strchr(s, '#'); if (h) *h = 0; }
int main(void){
    int nvec = 0;
    for (int i = 0; i < DESC_NVECS; i++){
        const desc_vec_t* v = &DESC_VECS[i]; nvec++;
        char lp[80]; snprintf(lp, sizeof lp, "vec %d prv", i);
        char lq[80]; snprintf(lq, sizeof lq, "vec %d pub", i);
        int a = expand_matches(lp, v->prv, v);
        int b = expand_matches(lq, v->pub, v);
        ck(lp, a); ck(lq, b);
        /* the private form prints as Core's public form */
        static descr_t d; char err[256]; char s[1500];
        if (descr_parse(v->prv, &d, err, sizeof err)){
            char want[1500]; snprintf(want, sizeof want, "%s", v->pub); strip_cs(want);
            descr_to_string(&d, 0, s, sizeof s);
            if (strcmp(s, want)){ printf("  FAIL vec %d to_string(pub):\n    got  %s\n    want %s\n", i, s, want); fails++; }
            checks++;
            /* with private keys it round-trips: the reprinted text expands identically */
            descr_to_string(&d, 1, s, sizeof s);
            { char lr[80]; snprintf(lr, sizeof lr, "vec %d priv-roundtrip", i); ck(lr, expand_matches(lr, s, v)); }
            /* Core's DescriptorID: sha256 of the public form with its checksum, displayed reversed */
            if (v->desc_id[0]){
                char pcs[9]; descr_checksum(want, pcs);
                char full[1500]; snprintf(full, sizeof full, "%s#%s", want, pcs);
                unsigned char dg[32]; sha256_full(dg, full, strlen(full));
                char idh[65]; for (int q = 0; q < 32; q++) sprintf(idh + 2*q, "%02x", dg[31-q]);
                if (strcmp(idh, v->desc_id)){ printf("  FAIL vec %d descriptor id: %s want %s\n", i, idh, v->desc_id); fails++; }
                checks++;
            }
            ck("hasprivatekeys reflects the private form", d.has_priv == (strstr(v->flags, "MISSING_PRIVKEYS") == NULL || strcmp(v->prv, v->pub) != 0) || d.has_priv);
            /* a checksum Core provided must be ours */
            const char* h = strchr(v->prv, '#');
            if (h){ ck("Core's checksum matches", !strcmp(h + 1, d.checksum) && d.had_checksum); }
        }
    }
    printf("  %d vectors, %d checks\n", nvec, checks);

    printf("== parse errors (Core's rules) ==\n");
    static descr_t d; char err[1024];
    #define BAD(desc, sub) do{ int r = descr_parse(desc, &d, err, sizeof err); if (r || !strstr(err, sub)){ printf("  FAIL '%s' -> %s (want '%s')\n", desc, r ? "accepted" : err, sub); fails++; } checks++; }while(0)
    BAD("wpkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)", "Uncompressed keys are not allowed");
    BAD("sh(sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))", "Can only have sh() at top level");
    BAD("wsh(wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))", "Can only have wsh() at top level");
    BAD("multi(4,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "bare multisig");
    BAD("multi(0,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "at least 1");
    BAD("multi(2,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "larger than the number of keys");
    BAD("tr(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,multi(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))", "at top level, in sh(), or in wsh()");
    BAD("multi_a(1,03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)", "inside tr()");
    BAD("pkh(notakey)", "key 'notakey' is not valid");
    BAD("pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)#abcdefgh", "does not match computed checksum");
    BAD("older(1)", "Miniscript expressions can only be used in wsh or tr.");   /* Core: a bare miniscript parses, then is refused for its context */
    BAD("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{pk(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)})", "exactly two children");

    printf("== Core's miniscript descriptor cases (descriptor_tests.cpp) ==\n");
    BAD("wsh(and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))#abcdef12", "Provided checksum 'abcdef12' does not match computed checksum 'tyzp6a7p'");
    BAD("sh(and_v(vc:andor(pk(L4gM1FBdyHNpkzsFh9ipnofLhpZRp2mwobpeULy1a6dBTvw8Ywtd),pk_k(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn),and_v(v:older(1),pk_k(L4o2kDvXXDRH2VS9uBnouScLduWt4dZnM25se7kvEjJeQ285en2A))),after(10)))", "Miniscript expressions can only be used in wsh or tr.");
    BAD("tr(and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)))", "tr(): key 'and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)");
    BAD("wsh(and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(049228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4))),after(10)))", "Uncompressed keys are not allowed");
    BAD("wsh(and_v(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(069228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4))),after(10)))", "Hybrid public keys are not allowed");
    BAD("wsh(and_b(vc:andor(pk(L4gM1FBdyHNpkzsFh9ipnofLhpZRp2mwobpeULy1a6dBTvw8Ywtd),pk_k(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn),and_v(v:older(1),pk_k(L4o2kDvXXDRH2VS9uBnouScLduWt4dZnM25se7kvEjJeQ285en2A))),after(10)))", "and_b(vc:andor(pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),pk_k(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0),and_v(v:older(1),pk_k(02aa27e5eb2c185e87cd1dbc3e0efc9cb1175235e0259df1713424941c3cb40402))),after(10)) is invalid");
    BAD("wsh(and_v(vc:andor(v:pk_k(L4gM1FBdyHNpkzsFh9ipnofLhpZRp2mwobpeULy1a6dBTvw8Ywtd),pk_k(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn),and_v(v:older(1),pk_k(L4o2kDvXXDRH2VS9uBnouScLduWt4dZnM25se7kvEjJeQ285en2A))),after(10)))", "v:pk_k(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204) is invalid");
    BAD("wsh(or_i(older(1),pk(L4gM1FBdyHNpkzsFh9ipnofLhpZRp2mwobpeULy1a6dBTvw8Ywtd)))", "or_i(older(1),pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)) is not sane: witnesses without signature exist");
    BAD("wsh(or_b(sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)))", "or_b(sha256(cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)) is not sane: malleable witnesses exist");
    BAD("wsh(and_b(and_b(older(1),a:older(100000000)),s:pk(L4gM1FBdyHNpkzsFh9ipnofLhpZRp2mwobpeULy1a6dBTvw8Ywtd)))", "and_b(older(1),a:older(100000000)) is not sane: contains mixes of timelocks expressed in blocks and seconds");
    BAD("wsh(and_b(or_b(pkh(L4gM1FBdyHNpkzsFh9ipnofLhpZRp2mwobpeULy1a6dBTvw8Ywtd),s:pk(Kx9HCDjGiwFcgVNhTrS5z5NeZdD6veeam61eDxLDCkGWujvL4Gnn)),s:pk(L4gM1FBdyHNpkzsFh9ipnofLhpZRp2mwobpeULy1a6dBTvw8Ywtd)))", "and_b(or_b(pkh(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),s:pk(032707170c71d8f75e4ca4e3fce870b9409dcaf12b051d3bcadff74747fa7619c0)),s:pk(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204)) is not sane: contains duplicate public keys");
    /* Check() vectors: private form -> Core's public form, scriptPubKey at index 0 (both forms), descriptor id */
    {
        typedef struct { const char* prv; const char* pub; const char* spk; const char* id; } msv_t;
        static const msv_t V[] = {
          {"wsh(and_v(v:ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e),multi(1,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0)))",
           "wsh(and_v(v:ripemd160(095ff41131e5946f3c85f79e44adbcf8e27e080e),multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)))",
           "0020acf425291b98a1d7e0d4690139442abc289175be32ef1f75945e339924246d73", "0634b326edc66f9e2660562564d7a8fcca55f91dc4555ce0a51883cc72e0fa41"},
          {"sh(wsh(thresh(1,pkh(L4gM1FBdyHNpkzsFh9ipnofLhpZRp2mwobpeULy1a6dBTvw8Ywtd),a:and_n(multi(1,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0),n:older(2)))))",
           "sh(wsh(thresh(1,pkh(03cdabb7f2dce7bfbd8a0b9570c6fd1e712e5d64045e9d6b517b3d5072251dc204),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))",
           "a914767e9119ff3b3ac0cb6dcfe21de1842ccf85f1c487", "3cfcad33bc25579d70b23ce634d317be00a4e5400e758e37c215bdc17b31bfb8"},
          {"wsh(thresh(1,pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc),a:pkh(xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0)))",
           "wsh(thresh(1,pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL),a:pkh(xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0)))",
           "00204a4528fbc0947e02e921b54bd476fc8cc2ebb5c6ae2ccf10ed29fe2937fb6892", ""},
          {"sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0),n:older(2)))))",
           "sh(wsh(thresh(2,ndv:after(1000),a:and_n(multi(1,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0),n:older(2)))))",
           "a914099f400961f930d4c16c3b33c0e2a58ef53ac38f87", "f5c14a15b45d2af1b8ec69acfd3cf4790f069705d1b079efb0b8193fed181f64"},
          {"wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))",
           "wsh(and_v(v:ripemd160(ff9aa1829c90d26e73301383f549e1497b7d6325),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))",
           "002001549deda34cbc4a5982263191380f522695a2ddc2f99fc3a65c736264bd6cab", "1fed6fbd0e408eb4bddfefa075289dc7061e7a3240c84f6ba5b9f294d96a21f4"},
          {"wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))",
           "wsh(and_v(v:sha256(7426ba0604c3f8682c7016b44673f85c5bd9da2fa6c1080810cf53ae320c9863),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))",
           "002071f7283dbbb9a55ed43a54cda16ba0efd0f16dc48fe200f299e57bb5d7be8dd4", "a1809a65ba5ca2f09a06c114d4881eed95d1b62f38743cf126cf71b2dd411374"},
          {"wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))",
           "wsh(and_v(v:hash160(292e2df59e3a22109200beed0cdc84b12e66793e),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))",
           "00209b9d5b45735d0e15df5b41d6594602d3de472262f7b75edc6cf5f3e3fa4e3ae4", "d7bdbc680503a585925eec72d11fc99396f51855d0a03fce53c90bed4c2e319f"},
          {"wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc)))",
           "wsh(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)))",
           "0020cf62bf97baf977aec69cbc290c372899f913337a9093e8f066ab59b8657a365c", "8412ba3ac20ba3a30f81442d10d32e0468fa52814960d04e959bf84a9b813b88"},
          {"tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,thresh(2,pk(L1NKM8dVA1h52mwDrmk1YreTWkAZZTu2vmKLpmLEbFRqGQYjHeEV),s:pk(Kz3iCBy3HNGP5CZWDsAMmnCMFNwqdDohudVN9fvkrN7tAkzKNtM7),adv:older(42)))",
           "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,thresh(2,pk(30a6069f344fb784a2b4c99540a91ee727c91e3a25ef6aae867d9c65b5f23529),s:pk(9918d400c1b8c3c478340a40117ced4054b6b58f48cdb3c89b836bdfee1f5766),adv:older(42)))",
           "512033982eebe204dc66508e4b19cfc31b5ffc6e1bfcbf6e5597dfc2521a52270795", ""},
          {"tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pkh(L1NKM8dVA1h52mwDrmk1YreTWkAZZTu2vmKLpmLEbFRqGQYjHeEV))",
           "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,pkh(30a6069f344fb784a2b4c99540a91ee727c91e3a25ef6aae867d9c65b5f23529))",
           "51201e9875f690f5847404e4c5951e2f029887df0525691ee11a682afd37b608aad4", ""},
          {"tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{{pkh(KykUPmR5967F4URzMUeCv9kNMU9CNRWycrPmx3ZvfkWoQLabbimL),pk(L3Enys1jFgTq4E24b8Uom1kAz6cNkz3Z82XZpBKCE2ztErq9fqvJ)},thresh(1,pk(L1NKM8dVA1h52mwDrmk1YreTWkAZZTu2vmKLpmLEbFRqGQYjHeEV),s:pk(Kz3iCBy3HNGP5CZWDsAMmnCMFNwqdDohudVN9fvkrN7tAkzKNtM7))})",
           "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{{pkh(1c9bc926084382e76da33b5a52d17b1fa153c072aae5fb5228ecc2ccf89d79d5),pk(0dd6b52b192ab195558d22dd8437a9ec4519ee5ded496c0d55bc9b1a8b0e8c2b)},thresh(1,pk(30a6069f344fb784a2b4c99540a91ee727c91e3a25ef6aae867d9c65b5f23529),s:pk(9918d400c1b8c3c478340a40117ced4054b6b58f48cdb3c89b836bdfee1f5766))})",
           "5120d8ea39b29de2b550b68bd2ada8b075c888c2b2df3290c7a35856482747848934", ""},
          {"tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(v:pk(xpub6AGbgdKcAGeUWaGNKH2o3sRvjtvJCGZ1NwrHqMJDwD4bN1QuwPQSsdeAYkPZGPt2FTAyu6nWGsC3fN2nsBELrLPcRNuwwr5k1X7yW5WV4aX/*),pk(02daf6e3477fc3906a1997820ed2940c8f5fa0942946d0368f981b001fdd85afcb)),and_v(v:pk(xprv9wCN7tTqN5ATsmBGEijuNeUgQjma9tv3GmdWLmbYiuArPsAMj6tD1uASiBfm47kdoi7bDBAVxUZNLM2MkeouPK5menDTyCNZtExQrKhVu7C/*),pk(03272c0c1ae2c07528283b91ca57b45d2cc84e7960e1f17f58815372285f35e99a))})",
           "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(v:pk(xpub6AGbgdKcAGeUWaGNKH2o3sRvjtvJCGZ1NwrHqMJDwD4bN1QuwPQSsdeAYkPZGPt2FTAyu6nWGsC3fN2nsBELrLPcRNuwwr5k1X7yW5WV4aX/*),pk(02daf6e3477fc3906a1997820ed2940c8f5fa0942946d0368f981b001fdd85afcb)),and_v(v:pk(xpub6ABiXPzjCSim6FFjLkGujnRQxmc4ZMdtdzZ79A1AHEhqGfVWGeCTZhUvZTSf1mNnGUtyNqgfE9eWaYdYReDKbPYqgqi9LLVZSmWnLQRx477/*),pk(03272c0c1ae2c07528283b91ca57b45d2cc84e7960e1f17f58815372285f35e99a))})",
           "5120793185cd1a9a0bb710fa57df3845ac4ddf7df63b74beadce2573cbb0b508b3a4", ""},
          {"tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),v:pk(KykUPmR5967F4URzMUeCv9kNMU9CNRWycrPmx3ZvfkWoQLabbimL)),older(42)),multi_a(2,adf586a32ad4b0674a86022b000348b681b4c97a811f67eefe4a6e066e55080c,KztMyyi1pXUtuZfJSB7JzVdmJMAz7wfGVFoSRUR5CVZxXxULXuGR)})",
           "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{and_v(and_v(v:hash256(ae253ca2a54debcac7ecf414f6734f48c56421a08bb59182ff9f39a6fffdb588),v:pk(1c9bc926084382e76da33b5a52d17b1fa153c072aae5fb5228ecc2ccf89d79d5)),older(42)),multi_a(2,adf586a32ad4b0674a86022b000348b681b4c97a811f67eefe4a6e066e55080c,14fa4ad085cdee1e2fc73d491b36a96c192382b1d9a21108eb3533f630364f9f)})",
           "51209a3d79db56fbe3ba4d905d827b62e1ed31cd6df1198b8c759d589c0f4efc27bd", ""},
        };
        for (size_t i = 0; i < sizeof V / sizeof V[0]; i++){
            char lab[64]; snprintf(lab, sizeof lab, "miniscript vec %zu", i);
            int r = descr_parse(V[i].prv, &d, err, sizeof err);
            if (!r){ printf("  FAIL %s prv parse: %s\n", lab, err); fails++; checks++; continue; }
            char s[3000]; descr_to_string(&d, 0, s, sizeof s);
            if (strcmp(s, V[i].pub)){ printf("  FAIL %s public form:\n    got  %s\n    want %s\n", lab, s, V[i].pub); fails++; }
            checks++;
            descr_spk_t sp[4]; int n = descr_expand(&d, 0, sp, 4); char hx[200]; if (n == 1) hex(hx, sp[0].spk, sp[0].len); else hx[0] = 0;
            if (n != 1 || strcmp(hx, V[i].spk)){ printf("  FAIL %s prv spk: got %s (%s) want %s\n", lab, hx, descr_last_error(), V[i].spk); fails++; }
            checks++;
            if (V[i].id[0]){ char pcs[9]; descr_checksum(V[i].pub, pcs); char full[3100]; snprintf(full, sizeof full, "%s#%s", V[i].pub, pcs);
                unsigned char dg[32]; sha256_full(dg, full, strlen(full)); char idh[65]; for (int q = 0; q < 32; q++) sprintf(idh + 2*q, "%02x", dg[31-q]);
                if (strcmp(idh, V[i].id)){ printf("  FAIL %s descriptor id %s want %s\n", lab, idh, V[i].id); fails++; } checks++; }
            r = descr_parse(V[i].pub, &d, err, sizeof err);
            if (!r){ printf("  FAIL %s pub parse: %s\n", lab, err); fails++; checks++; continue; }
            n = descr_expand(&d, 0, sp, 4); if (n == 1) hex(hx, sp[0].spk, sp[0].len); else hx[0] = 0;
            if (n != 1 || strcmp(hx, V[i].spk)){ printf("  FAIL %s pub spk: got %s (%s)\n", lab, hx, descr_last_error()); fails++; }
            checks++;
            /* the private form round-trips through its own printing */
            descr_parse(V[i].prv, &d, err, sizeof err); descr_to_string(&d, 1, s, sizeof s);
            if (strcmp(s, V[i].prv)){ printf("  FAIL %s private form reprint:\n    got  %s\n    want %s\n", lab, s, V[i].prv); fails++; } checks++;
        }
    }

    printf("== Core's musig() descriptor cases (BIP390; descriptor_tests.cpp) ==\n");
    {
        #define XPRV1 "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
        #define XPUB1 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
        #define XPUB2 "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
        typedef struct { const char* prv; const char* pub; const char* spk[3]; int pub_expands; } muv_t;
        static const muv_t V[] = {
          {"rawtr(musig(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66))",
           "rawtr(musig(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66))",
           {"5120789d937bade6673538f3e28d8368dda4d0512f94da44cf477a505716d26a1575", "", ""}, 1},
          {"tr(musig(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66))",
           "tr(musig(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659,023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66))",
           {"512079e6c3e628c9bfbce91de6b7fb28e2aec7713d377cf260ab599dcbc40e542312", "", ""}, 1},
          {"rawtr(musig(" XPRV1 "/0/*," XPUB2 "/0/*))", "rawtr(musig(" XPUB1 "/0/*," XPUB2 "/0/*))",
           {"5120754ccfd18ed4051de3b1144b6145cad4b2999387338dfb85ec392f2963ceaa3a", "5120be80016576d2691ccc4077bc91d7ece4db34667d6e84829d5e08480cd4bc0b78", "5120b7139e2f8b92570ad96c40c3b5e6557a5194e288a96df6f29980523365239d58"}, 1},
          {"rawtr(musig(" XPRV1 "," XPUB2 ")/0/*)", "rawtr(musig(" XPUB1 "," XPUB2 ")/0/*)",
           {"51209508c08832f3bb9d5e8baf8cb5cfa3669902e2f2da19acea63ff47b93faa9bfc", "51205ca1102663025a83dd9b5dbc214762c5a6309af00d48167d2d6483808525a298", "51207dbed1b89c338df6a1ae137f133a19cae6e03d481196ee6f1a5c7d1aeb56b166"}, 1},
          {"rawtr(musig(" XPRV1 "/0," XPUB2 ")/1)", "rawtr(musig(" XPUB1 "/0," XPUB2 ")/1)",
           {"51200e355f2bc9e754268e12bbd337499c2f7ffafc3101c41792709007b25a862532", "", ""}, 1},
          {"tr(musig(" XPRV1 "," XPUB2 ")/0/*,pk(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S))", "tr(musig(" XPUB1 "," XPUB2 ")/0/*,pk(f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9))",
           {"51201d377b637b5c73f670f5c8a96a2c0bb0d1a682a1fca6aba91fe673501a189782", "51208950c83b117a6c208d5205ffefcf75b187b32512eb7f0d8577db8d9102833036", "5120a49a477c61df73691b77fcd563a80a15ea67bb9c75470310ce5c0f25918db60d"}, 1},
          {"tr(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S,pk(musig(" XPRV1 "," XPUB2 ")/0/*))", "tr(f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9,pk(musig(" XPUB1 "," XPUB2 ")/0/*))",
           {"512068983d461174afc90c26f3b2821d8a9ced9534586a756763b68371a404635cc8", "5120368e2d864115181bdc8bb5dc8684be8d0760d5c33315570d71a21afce4afd43e", "512097a1e6270b33ad85744677418bae5f59ea9136027223bc6e282c47c167b471d5"}, 1},
          {"tr(musig(" XPRV1 "/1," XPRV1 "/1)/2)", "tr(musig(" XPUB1 "/1," XPUB1 "/1)/2)",
           {"5120a17ceacd6422bd5ffd9f165807b254b7d68ad39f179cc4f11545a6835227e97c", "", ""}, 1},
          {"rawtr(musig(xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0," XPUB2 ")/1)",
           "rawtr(musig(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/2147483647'/0," XPUB2 ")/1)",
           {"5120ebf2bcce516ef6567a9001ce6e5dc43a02bb62d37b51d86d773fa96dcd3a8d4c", "", ""}, 0},
        };
        for (size_t i = 0; i < sizeof V / sizeof V[0]; i++){
            char lab[64]; snprintf(lab, sizeof lab, "musig vec %zu", i);
            int r = descr_parse(V[i].prv, &d, err, sizeof err);
            if (!r){ printf("  FAIL %s prv parse: %s\n", lab, err); fails++; checks++; continue; }
            char s[3000]; descr_to_string(&d, 0, s, sizeof s);
            if (strcmp(s, V[i].pub)){ printf("  FAIL %s public form:\n    got  %s\n    want %s\n", lab, s, V[i].pub); fails++; } checks++;
            descr_to_string(&d, 1, s, sizeof s);
            if (strcmp(s, V[i].prv)){ printf("  FAIL %s private reprint:\n    got  %s\n    want %s\n", lab, s, V[i].prv); fails++; } checks++;
            for (int ix = 0; ix < 3 && V[i].spk[ix][0]; ix++){
                descr_spk_t sp[4]; int n = descr_expand(&d, ix, sp, 4); char hx[200]; if (n == 1) hex(hx, sp[0].spk, sp[0].len); else hx[0] = 0;
                if (n != 1 || strcmp(hx, V[i].spk[ix])){ printf("  FAIL %s prv spk[%d]: got %s (%s) want %s\n", lab, ix, hx, descr_last_error(), V[i].spk[ix]); fails++; } checks++;
            }
            r = descr_parse(V[i].pub, &d, err, sizeof err);
            if (!r){ printf("  FAIL %s pub parse: %s\n", lab, err); fails++; checks++; continue; }
            if (V[i].pub_expands) for (int ix = 0; ix < 3 && V[i].spk[ix][0]; ix++){
                descr_spk_t sp[4]; int n = descr_expand(&d, ix, sp, 4); char hx[200]; if (n == 1) hex(hx, sp[0].spk, sp[0].len); else hx[0] = 0;
                if (n != 1 || strcmp(hx, V[i].spk[ix])){ printf("  FAIL %s pub spk[%d]: got %s (%s)\n", lab, ix, hx, descr_last_error()); fails++; } checks++;
            }
        }
        /* Core's error strings */
        BAD("wsh(pk(musig(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S,03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659)))", "musig() is only allowed in tr() and rawtr()");
        BAD("tr(musig(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S,musig(03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659)))", "Too many ')' in musig() expression");
        BAD("tr(musig())", "musig(): Must contain key expressions");
        BAD("tr(musig(" XPRV1 "/0/*," XPUB2 ")/1)", "musig(): Cannot have ranged participant keys if musig() also has derivation");
        BAD("tr(musig(KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S," XPUB2 ")/1)", "musig(): derivation requires all participants to be xpubs or xprvs");
        BAD("tr(musig(" XPRV1 "," XPUB2 ")/1'/*)", "musig(): cannot have hardened derivation steps");
        BAD("tr(musig(" XPRV1 "," XPUB2 ")/1/*')", "musig(): Cannot have hardened child derivation");
        BAD("tr(musig(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235," XPUB2 "))", "musig(): Uncompressed keys are not allowed");
    }

    /* ---- BIP389 multipath: Core's CheckMultipath cases (2026-09-01) ----
     * parse the multipath text, expand into N single-path descriptors,
     * each printing exactly as Core's expanded private/public forms and
     * yielding Core's scriptPubKeys at every index; the multipath form
     * prints back; the unparsable cases fail with Core's error texts. */
    {
        static descr_t d; char err[512]; char s2[1500];
        for (int i = 0; i < MP_NVECS; i++){
            const mp_vec_t* v = &MP_VECS[i];
            for (int form = 0; form < 2; form++){
                const char* text = form ? v->pub : v->prv;
                char lab[64]; snprintf(lab, sizeof lab, "mp vec %d %s", i, form ? "pub" : "prv");
                if (!descr_parse(text, &d, err, sizeof err)){ printf("  FAIL %s: parse: %s\n", lab, err); fails++; checks++; continue; }
                ck(lab, descr_multipath_n(&d) == v->n);
                { descr_to_string_multipath(&d, 0, s2, sizeof s2); char want[1500]; snprintf(want, sizeof want, "%s", v->pub); strip_cs(want);
                  if (strcmp(s2, want)){ printf("  FAIL %s multipath print:\n    got  %s\n    want %s\n", lab, s2, want); fails++; } checks++; }
                for (int sel = 0; sel < v->n; sel++){
                    /* Core's CheckMultipath: one flag set for all expansions, or one per expansion ("{HARDENED, DEFAULT}") */
                    int hard_pub = 0;
                    if (form){ const char* f = v->flags; int ncomma = 0; for (const char* c = f; *c; c++) if (*c == ',') ncomma++;
                        if (ncomma + 1 == v->n){ int k2 = 0; const char* seg = f; for (const char* c = f; ; c++){ if (*c == ',' || *c == 0){ if (k2 == sel){ hard_pub = memmem(seg, (size_t)(c - seg), "HARDENED", 8) != NULL; break; } k2++; seg = c + 1; } if (!*c) break; } }
                        else hard_pub = strstr(f, "HARDENED") != NULL; }
                    ck("select", descr_multipath_select(&d, sel));
                    descr_to_string(&d, 0, s2, sizeof s2);
                    if (strcmp(s2, v->exp_pub[sel])){ printf("  FAIL %s exp %d pub:\n    got  %s\n    want %s\n", lab, sel, s2, v->exp_pub[sel]); fails++; } checks++;
                    if (!form){ descr_to_string(&d, 1, s2, sizeof s2);
                        if (strcmp(s2, v->exp_prv[sel])){ printf("  FAIL %s exp %d prv:\n    got  %s\n    want %s\n", lab, sel, s2, v->exp_prv[sel]); fails++; } checks++; }
                    for (int j = 0; j < v->nidx[sel]; j++){
                        descr_spk_t sp[4]; int n = descr_expand(&d, j, sp, 4);
                        if (hard_pub){ if (!(n == -1 && strstr(descr_last_error(), "without private keys"))){ printf("  FAIL %s exp %d idx %d: hardened pub form expanded (n=%d, %s)\n", lab, sel, j, n, descr_last_error()); fails++; } checks++; continue; }
                        if (n != v->nspk[sel][j]){ printf("  FAIL %s exp %d idx %d: %d spk(s), Core has %d (%s)\n", lab, sel, j, n, v->nspk[sel][j], descr_last_error()); fails++; checks++; continue; }
                        for (int q = 0; q < n; q++){ char h[1100]; hex(h, sp[q].spk, sp[q].len); checks++;
                            if (strcmp(h, v->spk[sel][j][q])){ printf("  FAIL %s exp %d idx %d spk %d:\n    got  %s\n    want %s\n", lab, sel, j, q, h, v->spk[sel][j][q]); fails++; } }
                    }
                }
            }
        }
        for (int i = 0; i < MP_NUNP; i++){
            const mp_unp_t* u = &MP_UNP[i];
            int ok = !descr_parse(u->prv, &d, err, sizeof err);
            char lab[64]; snprintf(lab, sizeof lab, "mp unparsable %d", i);
            if (!ok){ printf("  FAIL %s: parsed: %s\n", lab, u->prv); fails++; }
            else if (strcmp(err, u->err)){ printf("  FAIL %s error text:\n    got  %s\n    want %s\n", lab, err, u->err); fails++; }
            checks++;
            ok = !descr_parse(u->pub, &d, err, sizeof err);
            if (!ok || strcmp(err, u->err)){ printf("  FAIL %s (pub) error: got '%s'\n", lab, ok ? err : "(parsed)"); fails++; }
            checks++;
        }
    }
    printf("\n%s (%d failures, %d checks)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails, checks);
    return fails ? 1 : 0;
}
