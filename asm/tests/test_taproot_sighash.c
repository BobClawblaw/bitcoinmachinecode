/* test_taproot_sighash.c -- end-to-end Taproot / segwit-v1 (BIP341/BIP340)
 * validation over the verified asm crypto core.
 *
 * Covers:
 *   - BIP341 SigMsg serialization + TapSighash, validated byte-for-byte against
 *     the official Bitcoin Core wallet-test-vectors (bip-0341) via the reference
 *     preimages in taproot_vec.h (View{R,S}-equal to Core's sigMsg/sigHash).
 *   - key-path spend: verify a genuine schnorr signature over the key-path
 *     sighash against the P2TR output key.
 *   - script-path spend: OP_CHECKSIG and OP_CHECKSIGADD (BIP342 ext) with real
 *     tapscript schnorr signatures.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "taproot_spend.h"
#include "taproot_vec.h"
#include "official_keypath.h"

/* bitcoin_taproot_sighash.c API */
typedef struct {
    const uint8_t* tx;   int64_t txlen;
    int64_t  n_in;
    uint8_t  hash_type;
    const uint8_t* prevouts;
    const uint8_t* amounts;
    const uint8_t* spks;
    int64_t  num_inputs;
    int      ext_flag;
    const uint8_t* tapleaf;
    uint32_t codesep_pos;
    const uint8_t* annex;
    uint64_t annexlen;
} tapctx_t;
extern long taproot_sighash(uint8_t* out32, const tapctx_t* c, uint8_t* pre, long cap);
extern int  taproot_keypath_verify(const uint8_t* spk, const uint8_t* sig, int siglen,
                                   const uint8_t* tx, int64_t txlen, int64_t n_in,
                                   const uint8_t* prevouts, const uint8_t* amounts,
                                   const uint8_t* spks, int64_t num_inputs);
extern int  taproot_keypath_verify_annex(const uint8_t* spk, const uint8_t* sig, int siglen,
                                         const uint8_t* tx, int64_t txlen, int64_t n_in,
                                         const uint8_t* prevouts, const uint8_t* amounts,
                                         const uint8_t* spks, int64_t num_inputs,
                                         const uint8_t* annex, uint64_t annexlen,
                                         uint8_t* out_hash);
extern int  tapscript_checksig(const uint8_t* sig, int siglen, const uint8_t* pubkey,
                               const uint8_t* tx, int64_t txlen, int64_t n_in,
                               const uint8_t* prevouts, const uint8_t* amounts,
                               const uint8_t* spks, int64_t num_inputs,
                               const uint8_t* tapleaf, uint32_t codesep_pos,
                               uint8_t* out_hash);

/* bech32m P2TR address codec (ASM) */
extern void    bech32_init(void);extern long long bech32_encode(char* out, const char* hrp, long long hrplen,
                               const unsigned char* data5, long long datalen, long long spec);
extern long long bech32_decode(unsigned char* out5, char* out_hrp, long long hrp_cap,
                               const char* s);
extern long long bech32_convert_bits(unsigned char* out, const unsigned char* in,
                                     long long inlen, long long frombits,
                                     long long tobits, long long pad);

static int p2tr_addr_roundtrip(const uint8_t prog[32]){
    /* 8-bit program -> 5-bit groups (bech32 convert with pad) */
    uint8_t five[64]; long long five_n = 0;
    five_n = bech32_convert_bits(five, prog, 32, 8, 5, 1);
    if (five_n <= 0) return 0;
    /* witness v1 => first 5-bit group = 1 */
    uint8_t data5[64]; long long dn = 0;
    data5[dn++] = 1;
    for (long long i=0;i<five_n;i++) data5[dn++] = five[i];
    char addr[100];
    if (bech32_encode(addr, "bc", 2, data5, dn, 1 /*bech32m*/) < 0) return 0;
    /* decode back: out5 includes the 6 checksum groups (see bech32.asm) */
    uint8_t out5[64]; char hrp[8];
    long long r = bech32_decode(out5, hrp, 8, addr);
    if (r <= 0) return 0;
    if (strcmp(hrp,"bc")!=0) return 0;
    if (out5[0] != 1) return 0;              /* witness version 1 */
    long long data_n = r - 6;                /* exclude checksum */
    uint8_t back[64]; long long bn=0;
    bn = bech32_convert_bits(back, out5+1, data_n-1, 5, 8, 1);
    /* witness program: 52 five-groups -> 33 bytes with trailing zero pad; the
       program itself is the leading 32 bytes (remaining pad must be 0). */
    if (bn < 32 || memcmp(back, prog, 32)!=0) return 0;
    for (long long k=32;k<bn;k++) if (back[k]!=0) return 0;
    return 1;
}

static int g_fails = 0, g_checks = 0;
static void ckb(const char* name, int cond){
    g_checks++;
    if (cond) { printf("  ok  %s\n", name); }
    else { g_fails++; printf("  FAIL %s\n", name); }
}

/* Concatenated 36-byte outpoints of the official Core tx, from core_utx. */
static const uint8_t* prevouts_of_core(void){
    static uint8_t buf[9*36];
    const uint8_t* p = core_utx + 5;   /* skip version(4) + nin varint(1) */
    size_t n = 0;
    for (int i=0;i<core_numin;i++){
        memcpy(buf+n, p, 36); n += 36;
        p += 36;
        /* scriptSig compact size + data + nSequence(4) */
        uint8_t f = *p++;
        if (f < 0xfd){ p += 0 + 4; }
        else if (f == 0xfd){ uint16_t sl = (uint16_t)(p[0]|(p[1]<<8)); p += 2 + sl + 4; }
        else { p += 4 + 0 + 4; }   /* not expected here */
    }
    return buf;
}


/* ---- ASM script interpreter (bitcoin_interp.asm) ---- */
#define ELEM_SIZE 528
#define ELEM_DATA_OFF 4
#define MAX_STACK 1000
struct sc_slice { const uint8_t* p; size_t n; };   /* named: an anonymous struct in a parameter list is a distinct type per declaration */
struct script_state {
    uint8_t* main_elems;      /* +0  */
    size_t   main_sp;         /* +8  */
    uint8_t* alt_elems;       /* +16 */
    size_t   alt_sp;          /* +24 */
    uint8_t* script;          /* +32 */
    size_t   script_len;      /* +40 */
    int      sigversion;      /* +48 */
    uint64_t flags;           /* +56 */
    uint8_t* work;            /* +64 */
    size_t   work_cap;        /* +72 */
    uint64_t* error_out;      /* +80 */
    void*    checksig_ctx;    /* +88 */
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t,
                            const uint8_t*, size_t,
                            const struct sc_slice*); /* +96 */
};
extern int script_eval(struct script_state* st);

#include "../bitcoin_taproot_ctx.h"   /* ONE definition; see the note there */

/* Run a tapscript through the ASM interpreter with the taproot checksig_fn wired.
 * init: hex stack elements bottom-to-top (index 0 = bottom). */
static int interp_tapspend(const tspend_t* s, const uint8_t* tapleaf,
                           const uint8_t* script, int slen,
                           const char* const* init, const int* linit, int ninit)
{
    static uint8_t main_elems[MAX_STACK*ELEM_SIZE];
    static uint8_t alt_elems[MAX_STACK*ELEM_SIZE];
    static uint64_t gerr;
    memset(main_elems, 0, sizeof(main_elems));
    memset(alt_elems, 0, sizeof(alt_elems));
    for (int i=0;i<ninit;i++){
        uint8_t* rec = main_elems + i*ELEM_SIZE;
        /* decode hex element into raw bytes of length linit[i] */
        uint8_t buf[520]; int n = 0;
        for (int k=0;k<linit[i];k++){
            unsigned v; sscanf(init[i]+2*k,"%2x",&v); buf[n++]=(uint8_t)v;
        }
        ((uint32_t*)rec)[0]=(uint32_t)n;
        memcpy(rec+ELEM_DATA_OFF, buf, n);
    }
    taproot_checksig_ctx cctx = {0};   /* see the note at the struct: it grows fields */
    cctx.tx = s->tx; cctx.txlen = s->txlen; cctx.n_in = s->index;
    cctx.prevouts = s->prevouts; cctx.amounts = s->amounts; cctx.spks = s->spks;
    cctx.num_inputs = s->numin; cctx.tapleaf = tapleaf; cctx.codesep_pos = 0xffffffff;
    cctx.annex = NULL; cctx.annexlen = 0;
    cctx.weight_left = 1000000; /* generous: this harness isn't testing the budget itself */

    struct script_state st;
    memset(&st, 0, sizeof(st));
    st.main_elems = main_elems; st.main_sp = (size_t)ninit;
    st.alt_elems = alt_elems; st.alt_sp = 0;
    st.script = (uint8_t*)script; st.script_len = (size_t)slen;
    st.sigversion = 2;                   /* tapscript */
    st.flags = 0;
    st.work = NULL; st.work_cap = 0;
    st.error_out = &gerr; gerr = 0;
    st.checksig_ctx = &cctx; st.checksig_fn = (void*)(size_t)taproot_checksig_fn;
    int r = script_eval(&st);
    /* Mirror the production caller (taproot_verify_input): a checksig that set
     * hard_fail invalidates the script even when the stack ends truthy. A
     * harness that skipped this would report the empty-pubkey case as passing
     * while the node rejected the block, which is the wrong way round. */
    if (cctx.hard_fail) return 0;
    return r;
}

/* OP_CHECKSIG tapscript: script <pk> CHECKSIG, witness [sig] */
static void run_interp_tapspend(void){
    /* CHECKSIG: scriptpath_checksig = ts5_leaf_script; init stack [sig] */
    {
        const tspend_t* s = &taproot_spends[5];
        static char sighex[256]; static int siglen;
        /* copy sig bytes to local 8-bit array */
        uint8_t sigbuf[65]; memcpy(sigbuf, s->sig, s->siglen);
        char* p = sighex; for (int i=0;i<s->siglen;i++){ sprintf(p,"%02x",sigbuf[i]); p+=2; }
        siglen = s->siglen;
        const char* init[1] = { sighex };
        int linit[1] = { siglen };
        /* build script bytes <pk32> CHECKSIG = 0x20 key 0xac */
        static uint8_t sc[64]; sc[0]=0x20; memcpy(sc+1, s->key, 32); sc[33]=0xac;
        int r = interp_tapspend(s, taproot_vecs[5].leaf, sc, 34, init, linit, 1);
        ckb("interp: <pk> CHECKSIG tapscript passes", r==1);
        /* corrupted sig must fail */
        uint8_t bad[65]; memcpy(bad, s->sig, 65); bad[0]^=1;
        /* 65 bytes -> 130 hex chars + sprintf's NUL at index 130, so 131 is the
         * minimum. Was [130]: a one-byte overflow that -O0 never saw, because
         * glibc's _FORTIFY_SOURCE checks only activate with optimisation. */
        char bhex[136]; char* q=bhex; for(int i=0;i<65;i++){ sprintf(q,"%02x",bad[i]); q+=2; }
        const char* ib[1]={bhex}; int lb[1]={65};
        r = interp_tapspend(s, taproot_vecs[5].leaf, sc, 34, ib, lb, 1);
        ckb("interp: <pk> CHECKSIG with bad sig fails", r==0);
    }
    /* CHECKSIGADD 2-of-2 tapscript (BIP342): script
     *   <pk1> CHECKSIG <pk2> CHECKSIGADD 2 EQUAL
     * witness (bottom->top) [sig2, sig1]: sig1 pairs with pk1 (CHECKSIG),
     * sig2 pairs with pk2 (CHECKSIGADD accumulator). */
    {
        const tspend_t* s = &taproot_spends[6];
        char h1[136], h2[136];   /* same +NUL headroom as bhex above */
        char* q=h1; for(int i=0;i<s->siglen;i++){ sprintf(q,"%02x",s->sig[i]); q+=2; }
        q=h2; for(int i=0;i<s->sig2len;i++){ sprintf(q,"%02x",s->sig2[i]); q+=2; }
        const char* init[2] = { h2, h1 };   /* bottom=sig2, top=sig1 */
        int linit[2] = { s->sig2len, s->siglen };
        static uint8_t sc[96]; int n=0;
        sc[n++]=0x20; memcpy(sc+n, s->key, 32); n+=32; sc[n++]=0xac;   /* pk1 CHECKSIG */
        sc[n++]=0x20; memcpy(sc+n, s->key2, 32); n+=32; sc[n++]=0xba;  /* pk2 CHECKSIGADD */
        sc[n++]=0x52; sc[n++]=0x87;                       /* 2 EQUAL */
        int r = interp_tapspend(s, taproot_vecs[6].leaf, sc, n, init, linit, 2);
        ckb("interp: CHECKSIGADD 2-of-2 tapscript passes", r==1);
        /* only one valid sig -> accumulator 1 != 2 -> fails */
        const char* init1[1] = { h1 }; int linit1[1] = { s->siglen };
        r = interp_tapspend(s, taproot_vecs[6].leaf, sc, n, init1, linit1, 1);
        ckb("interp: CHECKSIGADD 1-of-2 fails (needs 2)", r==0);
    }

    /* BIP342 pubkey-size rules. A REAL signet block (109788) stalled this
     * node's sync on the middle case: its tapscript is `OP_1 OP_CHECKSIG`,
     * whose pubkey is the 1-byte value 0x01 -- an UNKNOWN public key type,
     * which BIP342 says verifies successfully when the signature is
     * non-empty. Rejecting it was a false reject, and no test here covered a
     * non-32-byte tapscript pubkey. */
    {
        const tspend_t* s = &taproot_spends[5];
        char sighex[136]; char* q=sighex;
        for(int i=0;i<s->siglen;i++){ sprintf(q,"%02x",s->sig[i]); q+=2; }
        const char* init[1] = { sighex }; int linit[1] = { s->siglen };

        /* OP_1 OP_CHECKSIG -- exactly the script from signet 109788. */
        uint8_t sc_unk[2] = { 0x51, 0xac };
        int r = interp_tapspend(s, taproot_vecs[5].leaf, sc_unk, 2, init, linit, 1);
        ckb("interp: unknown pubkey type (1 byte) + sig SUCCEEDS (BIP342 upgrade path)", r==1);

        /* Same script, empty signature: success is "a signature was supplied",
         * so this pushes false rather than erroring. */
        const char* none[1] = { "" }; int lnone[1] = { 0 };
        r = interp_tapspend(s, taproot_vecs[5].leaf, sc_unk, 2, none, lnone, 1);
        ckb("interp: unknown pubkey type with EMPTY sig is false", r==0);

        /* An EMPTY pubkey is a hard error in Core (SCRIPT_ERR_PUBKEYTYPE),
         * not a false result. `OP_0 OP_CHECKSIG OP_DROP OP_1` would end with a
         * truthy stack if the failure were merely false, so this is the case
         * that distinguishes the two -- and the one hard_fail exists for. */
        uint8_t sc_empty[4] = { 0x00, 0xac, 0x75, 0x51 };  /* OP_0 CHECKSIG DROP 1 */
        r = interp_tapspend(s, taproot_vecs[5].leaf, sc_empty, 4, init, linit, 1);
        ckb("interp: EMPTY pubkey fails the script even when the stack ends truthy", r==0);
    }
}

int main(void){
    bech32_init();
    printf("== bech32m P2TR address <-> scriptPubKey end-to-end ==\n");
    ckb("P2TR output-key0 -> bc1p addr roundtrip", p2tr_addr_roundtrip(taproot_spends[4].output_key) &&
                                                     p2tr_addr_roundtrip(taproot_spends[5].output_key) &&
                                                     p2tr_addr_roundtrip(taproot_spends[3].output_key));

    printf("\n== BIP341 sighash vs Bitcoin Core-validated reference preimages ==\n");
    for (int i = 0; i < taproot_num_vecs && i < taproot_num_spends; i++){
        const tspend_t* s = &taproot_spends[i];
        tapctx_t c;
        c.tx = s->tx; c.txlen = (int64_t)s->txlen; c.n_in = s->index;
        c.hash_type = (uint8_t)s->hash_type;
        c.prevouts = s->prevouts; c.amounts = s->amounts; c.spks = s->spks;
        c.num_inputs = s->numin; c.ext_flag = (s->output_key && s->leaf_len) ? 1 : 0;
        c.tapleaf = (c.ext_flag ? taproot_vecs[i].leaf : NULL);
        c.codesep_pos = 0xffffffff;
        c.annex = taproot_vecs[i].annex;
        c.annexlen = (uint64_t)taproot_vecs[i].annexlen;

        uint8_t hash[32], pre[256];
        long plen = taproot_sighash(hash, &c, pre, sizeof(pre));
        char nm[96]; snprintf(nm, sizeof(nm), "sighash[%d] %s (ref pre)", i, s->name);
        ckb(nm, plen > 0 && memcmp(hash, s->expect_sighash, 32) == 0);
        g_checks++;
        if (plen != (long)taproot_vecs[i].prelen ||
            memcmp(pre, taproot_vecs[i].pre, (size_t)plen) != 0){
            g_fails++; printf("  FAIL preimage[%d] %s byte mismatch (len %ld vs %d)\n",
                              i, s->name, plen, taproot_vecs[i].prelen);
        } else {
            printf("  ok  preimage[%d] %s byte-exact vs Core reference\n", i, s->name);
        }
    }

    printf("\n== key-path spend (BIP341) end-to-end ==\n");
    {
        const tspend_t* s = &taproot_spends[3];   /* keypath_signed */
        uint8_t spk[34]; spk[0]=0x51; spk[1]=0x20; memcpy(spk+2, s->output_key, 32);
        ckb("keypath genuine sig verified", taproot_keypath_verify(
                spk, s->sig, s->siglen, s->tx, s->txlen, s->index,
                s->prevouts, s->amounts, s->spks, s->numin));
        uint8_t bad[65]; memcpy(bad, s->sig, 65); bad[0] ^= 0x01;
        ckb("keypath corrupted sig rejected", !taproot_keypath_verify(
                spk, bad, 65, s->tx, s->txlen, s->index,
                s->prevouts, s->amounts, s->spks, s->numin));
        uint8_t wrong_pk[32]; memcpy(wrong_pk, s->output_key, 32); wrong_pk[0]^=1;
        uint8_t spk2[34]; spk2[0]=0x51; spk2[1]=0x20; memcpy(spk2+2, wrong_pk, 32);
        ckb("keypath wrong output-key rejected", !taproot_keypath_verify(
                spk2, s->sig, s->siglen, s->tx, s->txlen, s->index,
                s->prevouts, s->amounts, s->spks, s->numin));
    }

    printf("\n== differential vs official Bitcoin Core keyPathSpending vector ==\n");
    {
        /* walk core_spks to map input index -> scriptPubKey */
        static uint8_t core_spk_by_idx[9][40];
        {
            const uint8_t* p = core_spks;
            for (int i=0;i<core_numin;i++){
                uint64_t sl = 0;
                uint8_t f = *p++;
                if (f < 0xfd) sl = f;
                else if (f==0xfd){ sl = p[0]|(p[1]<<8); p+=2; }
                memcpy(core_spk_by_idx[i], p, (size_t)sl);
                p += sl;
            }
        }
        /* re-parse for the amount of each input */
        int ok_all = 1;
        for (int k=0;k<core_num_sigs;k++){
            int idx = core_sigs[k].index;
            const uint8_t* spk = core_spk_by_idx[idx];
            int p2tr = (spk[0]==0x51 && spk[1]==0x20);   /* P2TR */
            if (!p2tr){ printf("  skip input %d (non-P2TR spk)\n", idx); continue; }
            uint8_t expect[32]; memcpy(expect, core_sigs[k].expect_sighash, 32);
            uint8_t actual[32];
            /* compute + verify */
            tapctx_t c;
            c.tx = core_utx; c.txlen = core_utx_len; c.n_in = idx;
            c.hash_type = (uint8_t)core_sigs[k].hash_type;
            c.prevouts = prevouts_of_core();
            c.amounts = core_amounts; c.spks = core_spks;
            c.num_inputs = core_numin; c.ext_flag = 0; c.tapleaf=NULL;
            c.codesep_pos = 0xffffffff;
            uint8_t pre[256];
            long n = taproot_sighash(actual, &c, pre, sizeof(pre));
            int sig_ok = taproot_keypath_verify(spk, core_sigs[k].sig, core_sigs[k].siglen,
                                                core_utx, core_utx_len, idx,
                                                prevouts_of_core(), core_amounts,
                                                core_spks, core_numin);
            int hash_ok = (n>0 && memcmp(actual, expect, 32)==0);
            char nm[96];
            snprintf(nm,sizeof(nm),"core input %d (ht=%#x) sighash match", idx, core_sigs[k].hash_type);
            ckb(nm, hash_ok);
            snprintf(nm,sizeof(nm),"core input %d (ht=%#x) sig verified", idx, core_sigs[k].hash_type);
            ckb(nm, sig_ok && hash_ok);
            if (!sig_ok || !hash_ok) ok_all = 0;
        }
        ckb("official Core keyPathSpending fully accepted", ok_all);
    }

    printf("\n== script-path spend: OP_CHECKSIG (BIP342) ==\n");
    {
        const tspend_t* s = &taproot_spends[5];
        uint8_t hash[32];
        ckb("scriptpath CHECKSIG genuine sig", tapscript_checksig(
                s->sig, s->siglen, s->key, s->tx, s->txlen, s->index,
                s->prevouts, s->amounts, s->spks, s->numin,
                taproot_vecs[5].leaf, 0xffffffff, hash));
        ckb("scriptpath CHECKSIG hash matches ref", memcmp(hash, s->expect_sighash, 32)==0);
        uint8_t bad[65]; memcpy(bad, s->sig, 65); bad[3] ^= 0x80;
        ckb("scriptpath CHECKSIG corrupted sig rejected", !tapscript_checksig(
                bad, 65, s->key, s->tx, s->txlen, s->index,
                s->prevouts, s->amounts, s->spks, s->numin,
                taproot_vecs[5].leaf, 0xffffffff, NULL));
        ckb("scriptpath wrong pubkey rejected", !tapscript_checksig(
                s->sig, s->siglen, s->output_key, s->tx, s->txlen, s->index,
                s->prevouts, s->amounts, s->spks, s->numin,
                taproot_vecs[5].leaf, 0xffffffff, NULL));
    }

    printf("\n== script-path spend: OP_CHECKSIGADD / tapscript multisig ==\n");
    {
        const tspend_t* s = &taproot_spends[6];
        uint8_t hash[32];
        int k1 = tapscript_checksig(s->sig, s->siglen, s->key,
                                    s->tx, s->txlen, s->index, s->prevouts,
                                    s->amounts, s->spks, s->numin,
                                    taproot_vecs[6].leaf, 0xffffffff, hash);
        int k2 = tapscript_checksig(s->sig2, s->sig2len, s->key2,
                                    s->tx, s->txlen, s->index, s->prevouts,
                                    s->amounts, s->spks, s->numin,
                                    taproot_vecs[6].leaf, 0xffffffff, NULL);
        ckb("CHECKSIGADD sig1 verified", k1==1);
        ckb("CHECKSIGADD sig2 verified", k2==1);
        ckb("CHECKSIGADD hash matches ref", memcmp(hash, s->expect_sighash,32)==0);
        /* 2-of-2 tapscript: both must sign; a single signature leaves sum=1 != 2 */
        ckb("2-of-2 requires both sigs (sum 2)", k1 + k2 == 2);
        uint8_t bad1[65]; memcpy(bad1, s->sig, 65); bad1[10]^=0x04;
        int k1b = tapscript_checksig(bad1, 65, s->key, s->tx, s->txlen, s->index,
                                     s->prevouts, s->amounts, s->spks, s->numin,
                                     taproot_vecs[6].leaf, 0xffffffff, NULL);
        ckb("CHECKSIGADD corrupted sig1 rejected", k1b==0);
    }

    printf("\n== key-path spend with annex (BIP341 annex rules) ==\n");
    {
        const tspend_t* s = &taproot_spends[4];       /* keypath_annex */
        const tvec_t* v = &taproot_vecs[4];
        uint8_t spk[34]; spk[0]=0x51; spk[1]=0x20; memcpy(spk+2, s->output_key, 32);
        uint8_t hash[32];
        int r = taproot_keypath_verify_annex(spk, s->sig, s->siglen, s->tx, s->txlen,
                                             s->index, s->prevouts, s->amounts,
                                             s->spks, s->numin, v->annex, v->annexlen,
                                             hash);
        ckb("keypath-annex genuine sig verified", r==1);
        ckb("keypath-annex sighash matches ref", memcmp(hash, v->sighash, 32)==0);
        ckb("keypath-annex spend_type committed (annex != no-annex)",
            taproot_keypath_verify_annex(spk, s->sig, s->siglen, s->tx, s->txlen,
                                         s->index, s->prevouts, s->amounts,
                                         s->spks, s->numin, NULL, 0, NULL) == 0);
        uint8_t bad[65]; memcpy(bad, s->sig, 65); bad[0]^=0x01;
        ckb("keypath-annex corrupted sig rejected", !taproot_keypath_verify_annex(
                spk, bad, 65, s->tx, s->txlen, s->index, s->prevouts, s->amounts,
                s->spks, s->numin, v->annex, v->annexlen, NULL));
    }

    printf("\n== script-path spend through the ASM script interpreter ==\n");
    run_interp_tapspend();

    printf("\n%s (%d checks, %d failures)\n", g_fails?"TESTS FAILED":"ALL PASS", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
