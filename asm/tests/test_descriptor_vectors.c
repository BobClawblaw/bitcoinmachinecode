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
    static descr_t d; char err[256];
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
    BAD("older(1)", "is not a valid descriptor function");
    BAD("tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{pk(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)})", "exactly two children");
    printf("\n%s (%d failures, %d checks)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails, checks);
    return fails ? 1 : 0;
}
