/* tests/test_scr5_spkrun.c -- SCR-5 end-to-end (audit 2026-09-03): the
 * BIP341 sha_scriptpubkeys aggregate with a >= 253-byte co-input script.
 *
 * The writers (tapagg_build C twin + asm twin) previously REJECTED such a
 * co-input, so the reader path beyond 252 bytes was never exercised by the
 * consensus pipeline. This test drives the reader (ts_agg_hashes via
 * ts_agg_hashes_export) with the exact run the fixed writers emit, and pins
 * the digest against validation/scr5_spkrun_oracle.py -- a pure-stdlib
 * recomputation of Core's PrecomputedTransactionData::Init ser_compactsize
 * || spk concatenation, NOT code from this repo.
 *
 * It also pins the reader's fail-closed behaviour on a NON-MINIMAL encoding
 * (531 written as 0xfe LE32): Core's deserialization rejects non-canonical
 * CompactSizes and so does read_cs; a corrupted run must return 0, not a
 * hash. The struct copies below mirror bitcoin_taproot_sighash.c exactly
 * (same pattern as tests/test_taproot_bounds_fuzz.c).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    const uint8_t* tx;   int64_t txlen;
    int64_t  n_in;
    uint8_t  hash_type;
    const uint8_t* prevouts;
    const uint8_t* amounts;
    const uint8_t* spks;       /* compactsize+data each, for all inputs */
    int64_t  num_inputs;
    int      ext_flag;
    const uint8_t* tapleaf;
    uint32_t codesep_pos;
    const uint8_t* annex;
    uint64_t annexlen;
} tapctx_local_t;                          /* == tapctx_t */

typedef struct {
    const uint8_t* tx;   int64_t txlen;
    const uint8_t* end;
    int      version;
    uint32_t locktime;
    int64_t  nin, nout;
    const uint32_t* in_off;
    const uint32_t* out_off;
} txview_local_t;                          /* == txview_t */

extern int ts_agg_hashes_export(const void* c, const void* t, uint8_t hp[32],
                                uint8_t ha[32], uint8_t hs[32], uint8_t hq[32],
                                const uint8_t** sp, uint64_t* sl);
extern int ts_tx_parse_export(void* t, uint32_t* off);

static int failures=0;
static void ckh(const char* l, const uint8_t got[32], const uint8_t exp[32]){
    if (!memcmp(got, exp, 32)) printf("PASS %s\n", l);
    else { printf("FAIL %s\n  got ", l); for(int i=0;i<32;i++)printf("%02x",got[i]);
           printf("\n  exp "); for(int i=0;i<32;i++)printf("%02x",exp[i]); printf("\n"); failures++; }
}
static void ck(const char* l,long g,long e){
    if(g==e) printf("PASS %s\n",l);
    else { printf("FAIL %s got=%ld exp=%ld\n",l,g,e); failures++; }
}

int main(void){
    /* ---- the run, exactly as the fixed writers emit it and the oracle
     * recomputes it ---- */
    static uint8_t spk0[531];
    for (int i=0;i<531;i++) spk0[i]=(uint8_t)((i*7+3) % 256);   /* audit's multisig-shape size */
    uint8_t spk1[34]; spk1[0]=0x51; spk1[1]=0x20;
    for (int i=0;i<32;i++) spk1[2+i]=(uint8_t)i;

    static uint8_t run[3+531+1+34];
    int rn=0;
    run[rn++]=0xfd; run[rn++]=(uint8_t)(531 & 0xff); run[rn++]=(uint8_t)(531 >> 8);
    memcpy(run+rn, spk0, 531); rn+=531;
    run[rn++]=34; memcpy(run+rn, spk1, 34); rn+=34;

    uint8_t prevouts[72]; for(int i=0;i<72;i++) prevouts[i]=(uint8_t)((i+1) % 256);
    uint8_t amounts[16]  = {1,0,0,0,0,0,0,0, 2,0,0,0,0,0,0,0};

    /* the NON-WITNESS serialization (what BIP341 hashes and what the
     * pipeline feeds the sighash after strip_witness): version, nin,
     * inputs [op36 sl seq], nout, outputs, locktime */
    uint8_t tx[256]; int tn=0;
    tx[tn++]=2;tx[tn++]=0;tx[tn++]=0;tx[tn++]=0;
    tx[tn++]=2;
    memcpy(tx+tn,prevouts,36); tn+=36; tx[tn++]=0; tx[tn++]=0xff;tx[tn++]=0xff;tx[tn++]=0xff;tx[tn++]=0xff;
    memcpy(tx+tn,prevouts+36,36); tn+=36; tx[tn++]=0; tx[tn++]=0xff;tx[tn++]=0xff;tx[tn++]=0xff;tx[tn++]=0xff;
    tx[tn++]=1;
    for(int i=0;i<8;i++) tx[tn++]=0;
    tx[tn++]=2; tx[tn++]=0x51;tx[tn++]=0x51;
    tx[tn++]=0;tx[tn++]=0;tx[tn++]=0;tx[tn++]=0;

    static uint32_t off[4096];
    txview_local_t t; memset(&t,0,sizeof t);
    t.tx=tx; t.txlen=tn;
    ck("txview parses", ts_tx_parse_export(&t, off), 1);

    tapctx_local_t c; memset(&c,0,sizeof c);
    c.tx=tx; c.txlen=tn; c.n_in=1;
    c.prevouts=prevouts; c.amounts=amounts; c.spks=run; c.num_inputs=2;
    c.codesep_pos=0xffffffffu;

    uint8_t hp[32],ha[32],hs[32],hq[32]; const uint8_t* sp=NULL; uint64_t sl=0;
    int ok = ts_agg_hashes_export(&c, &t, hp,ha,hs,hq, &sp,&sl);
    ck("ts_agg_hashes ACCEPTS the 531-byte co-input run", ok, 1);
    /* the reader points INTO the script bytes (past the length prefix):
     * entry 1 sits at 3 + 531 (cs header + entry 0) + 1 (entry 1's length byte) */
    ck("the run locates input 1's script", (long)(sp==run+3+531+1 && sl==34), 1);

    /* ---- oracle digests (validation/scr5_spkrun_oracle.py, stdlib-only) ---- */
    {
        uint8_t e_hs[32] = {
            0x37,0x44,0xb7,0x7d,0xc1,0x33,0x50,0x90,0x27,0x22,0x4b,0x1c,0xb8,0x4f,0xd3,0x8e,
            0x28,0xeb,0x75,0x11,0x4b,0x76,0xde,0x73,0x42,0x55,0x9d,0x6f,0xcf,0xc8,0x08,0x54};
        uint8_t e_hp[32] = {
            0x87,0xa2,0xfa,0x2e,0xec,0x53,0x05,0x3c,0xb1,0xee,0x07,0xd7,0x59,0x70,0xf6,0x50,
            0xcd,0x9d,0xc5,0x8b,0xdc,0xb8,0x65,0x30,0x4f,0x70,0x82,0x9e,0xbd,0xe2,0x7d,0xac};
        uint8_t e_ha[32] = {
            0x0c,0x73,0x0b,0x69,0x90,0x5c,0x5e,0xf7,0xa4,0xca,0x52,0x69,0xf7,0x23,0x65,0x40,
            0x0b,0xde,0x2d,0xd2,0xc0,0x4e,0xaf,0x9b,0xbb,0x3d,0x1c,0x4a,0x26,0x5a,0x01,0x31};
        ckh("h_spk == BIP341 sha_scriptpubkeys (oracle)", hs, e_hs);
        ckh("h_prev == sha_prevouts (oracle)", hp, e_hp);
        ckh("h_amt == sha_amounts (oracle)", ha, e_ha);
    }

    /* ---- fail-closed on a NON-MINIMAL length (0xfe LE32 for 531): the
     * reader's minimality check must reject, mirroring Core's deserialization ---- */
    {
        static uint8_t bad[5+531+1+34];
        int n=0;
        bad[n++]=0xfe; bad[n++]=(uint8_t)(531 & 0xff); bad[n++]=0; bad[n++]=0; bad[n++]=0;
        memcpy(bad+n, spk0, 531); n+=531;
        bad[n++]=34; memcpy(bad+n, spk1, 34); n+=34;
        tapctx_local_t c2 = c; c2.spks = bad;
        uint8_t hp2[32]; const uint8_t* sp2=NULL; uint64_t sl2=0;
        ck("reader REJECTS the non-minimal 0xfe encoding (fail closed)",
           ts_agg_hashes_export(&c2, &t, hp2,ha,hs,hq,&sp2,&sl2), 0);
    }
    /* ---- fail-closed when num_inputs disagrees with the transaction (the
     * BIP341 all-inputs invariant) ---- */
    {
        tapctx_local_t c3 = c; c3.num_inputs = 3;
        uint8_t hp3[32]; const uint8_t* sp3=NULL; uint64_t sl3=0;
        ck("reader REJECTS num_inputs != tx nin",
           ts_agg_hashes_export(&c3, &t, hp3,ha,hs,hq,&sp3,&sl3), 0);
    }

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
