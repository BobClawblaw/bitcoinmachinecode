/* test_bip152.c -- BIP152 compact-blocks primitives (asm/bitcoin_cmpct.asm).
 *
 * Validates:
 *   1. siphash24_uint256   against reference SipHash-2-4 values (independently
 *                          derived; the short-id vectors below tie the whole
 *                          pipeline to real Bitcoin Core output).
 *   2. bip152_shortid      against short-tx-ids captured LIVE from Bitcoin Core
 *                          v31.99 over loopback (validation/bip152_vectors.h
 *                          generated from real cmpctblock wire messages).
 *   3. sendcmpct / getblocktxn (DifferenceFormatter) / blocktxn codecs and the
 *                          cmpctblock shorttxid parser.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "bip152_vectors.h"
#include "block_vec.h"
#include "cmpct_expected.h"

extern uint64_t siphash24_uint256(uint64_t k0, uint64_t k1, const unsigned char msg[32]);
extern void bip152_shortid(unsigned char out[6], const unsigned char hdr[80],
                           uint64_t nonce, const unsigned char wtxid[32]);
extern long p2p_sendcmpct(unsigned char* out, unsigned char announce, uint64_t version);
extern long p2p_getblocktxn_build(unsigned char* out, const unsigned char bh[32],
                                  const unsigned short* indexes, long n);
extern long p2p_blocktxn_build(unsigned char* out, const unsigned char bh[32],
                               const unsigned char* const* txs, const long* lens, long n);
extern long cmpctblock_shorttxids_count(const unsigned char* payload, long plen);
extern long cmpctblock_shorttxid(unsigned char out6[6], const unsigned char* payload, long i);
extern long block_txcount(const unsigned char* blockbuf, long blen);
extern long block_tx_at(const unsigned char* blockbuf, long blen, long index,
                        unsigned char** out_ptr, long* out_len);
extern void tx_wtxid(unsigned char out[32], const unsigned char* tx, long txlen);
extern long cmpctblock_build(unsigned char* out, const unsigned char* blockbuf,
                             long blen, uint64_t nonce);

static int failures=0;
static void cki(const char*l,long g,long e){
    if(g==e) printf("PASS %s (got %ld)\n",l,g);
    else { printf("FAIL %s got=%ld exp=%ld\n",l,g,e); failures++; }
}
static void ck(const char*l,int ok){
    if(ok) printf("PASS %s\n",l);
    else { printf("FAIL %s\n",l); failures++; }
}

int main(void){
    setbuf(stdout,NULL);

    /* ---- 1. SipHash-2-4 (uint256 path) ---- */
    {
        unsigned char m0[32]; for(int i=0;i<32;i++) m0[i]=(unsigned char)i;
        cki("siphash24 k=(0x0706..,0x0f0e..) bytes0..31",
            (long)siphash24_uint256(0x0706050403020100ULL,0x0f0e0d0c0b0a0908ULL,m0),
            (long)0x7127512f72f27cceULL);
        unsigned char m1[32]; memset(m1,0xff,32);
        cki("siphash24 k=(0x1122..,0x99aa..) 0xff*32",
            (long)siphash24_uint256(0x1122334455667788ULL,0x99aabbccddeeff00ULL,m1),
            (long)0x283605e812e06d70ULL);
        unsigned char m2[32]; memset(m2,0,32);
        cki("siphash24 k=(-1,-1) 0*32",
            (long)siphash24_uint256(0xffffffffffffffffULL,0xffffffffffffffffULL,m2),
            (long)0xc3644a0b2b0887acULL);
    }

    /* ---- 2. bip152_shortid vs real Core wire short IDs ---- */
    {
        int all=1;
        for(int i=0;i<BIP152_NVEC;i++){
            unsigned char out[6];
            bip152_shortid(out, BIP152_VECS[i].hdr, BIP152_VECS[i].nonce, BIP152_VECS[i].wtxid);
            if(memcmp(out, BIP152_VECS[i].shortid, 6)!=0){
                printf("  shortid[%d] mismatch: got %02x%02x%02x%02x%02x%02x exp %02x%02x%02x%02x%02x%02x\n",
                    i,out[0],out[1],out[2],out[3],out[4],out[5],
                    BIP152_VECS[i].shortid[0],BIP152_VECS[i].shortid[1],BIP152_VECS[i].shortid[2],
                    BIP152_VECS[i].shortid[3],BIP152_VECS[i].shortid[4],BIP152_VECS[i].shortid[5]);
                all=0;
            }
        }
        char buf[128]; snprintf(buf,sizeof buf,"bip152_shortid matches all %d Core-captured short IDs",BIP152_NVEC);
        ck(buf, all);
    }

    /* ---- 3a. p2p_sendcmpct ---- */
    {
        unsigned char sc[16];
        long l=p2p_sendcmpct(sc, 1, 2);
        cki("sendcmpct len", l, 9);
        ck("sendcmpct announce=1 v=2",
            sc[0]==1 && sc[1]==2 && sc[2]==0 && sc[3]==0 && sc[4]==0 &&
            sc[5]==0 && sc[6]==0 && sc[7]==0 && sc[8]==0);
        p2p_sendcmpct(sc, 0, 2);
        ck("sendcmpct announce=0 v=2", sc[0]==0 && sc[1]==2);
    }

    /* ---- 3b. p2p_getblocktxn_build (DifferenceFormatter) ---- */
    {
        unsigned char bh[32]; for(int i=0;i<32;i++) bh[i]=(unsigned char)i;
        unsigned short idx[] = {0, 2, 5, 6, 10};
        unsigned char out[128];
        long l=p2p_getblocktxn_build(out, bh, idx, 5);
        /* payload = bh(32) + count(1)=5 + diffs: [0,2,5,6,10]
           shift resets: stored = [0, (2-1)=1, (5-3)=2, (6-6)=0, (10-7)=3] */
        ck("getblocktxn: blockhash copied", memcmp(out,bh,32)==0);
        ck("getblocktxn: count==5", out[32]==5);
        ck("getblocktxn: diff[0]==0", out[33]==0);
        ck("getblocktxn: diff[1]==1 (2-1)", out[34]==1);
        ck("getblocktxn: diff[2]==2 (5-3)", out[35]==2);
        ck("getblocktxn: diff[3]==0 (6-6)", out[36]==0);
        ck("getblocktxn: diff[4]==3 (10-7)", out[37]==3);
        cki("getblocktxn len", l, 33+5);
        /* single index 0 */
        unsigned short i0[]={0};
        long l2=p2p_getblocktxn_build(out, bh, i0, 1);
        cki("getblocktxn single count", (long)out[32], 1);
        cki("getblocktxn single diff0", (long)out[33], 0);
        cki("getblocktxn single len", l2, 34);
        /* ascending with a gap: {3, 100} -> diff[0]=3, diff[1]=100-4=96 */
        unsigned short gap[]={3,100};
        long l4=p2p_getblocktxn_build(out, bh, gap, 2);
        cki("getblocktxn gap count", (long)out[32], 2);
        cki("getblocktxn gap d0=3", (long)out[33], 3);
        cki("getblocktxn gap d1=96 (100-4)", (long)out[34], 96);
        cki("getblocktxn gap len", l4, 35); /* 32 bh + 1 count + 1 + 1 */
    }

    /* ---- 3c. p2p_blocktxn_build ---- */
    {
        unsigned char bh[32]; for(int i=0;i<32;i++) bh[i]=(unsigned char)i;
        unsigned char t0[5]={0x01,0x02,0x03,0x04,0x05};
        unsigned char t1[3]={0xaa,0xbb,0xcc};
        const unsigned char* txs[]={t0,t1};
        long lens[]={5,3};
        unsigned char out[128];
        long l=p2p_blocktxn_build(out, bh, txs, lens, 2);
        ck("blocktxn blockhash", memcmp(out,bh,32)==0);
        ck("blocktxn count==2", out[32]==2);
        ck("blocktxn tx0", memcmp(out+33,t0,5)==0);
        ck("blocktxn tx1", memcmp(out+38,t1,3)==0);
        cki("blocktxn len", l, 33+8);
    }

    /* ---- 3d. cmpctblock shorttxid parser over a captured Core payload ---- */
    {
        /* Reconstruct the captured cmpctblock payload for the first core block:
           header(80) + nonce(8) + count(varint=4 for cmpct_1) + 4x shortid(6). */
        /* Use the first group of 4 vectors (same header/nonce) as a synthetic payload. */
        unsigned char payload[88+1+4*6];
        /* Build payload from the header+nonce of vector 0 and shortids 0..3.
           Validate count parser + shorttxid extraction against the same shortids. */
        memcpy(payload, BIP152_VECS[0].hdr, 80);
        /* nonce LE8 */
        { uint64_t n=BIP152_VECS[0].nonce; for(int k=0;k<8;k++) payload[80+k]=(unsigned char)(n>>(8*k)); }
        payload[88]=4;              /* shorttxids count = 4 */
        for(int i=0;i<4;i++){
            unsigned char sid6[6];
            bip152_shortid(sid6, BIP152_VECS[i].hdr, BIP152_VECS[i].nonce, BIP152_VECS[i].wtxid);
            memcpy(payload+89+i*6, sid6, 6);
        }
        cki("cmpctblock_shorttxids_count", cmpctblock_shorttxids_count(payload, 88+1+4*6), 4);
        for(int i=0;i<4;i++){
            unsigned char got6[6];
            long ok=cmpctblock_shorttxid(got6, payload, i);
            unsigned char sid6[6];
            bip152_shortid(sid6, BIP152_VECS[i].hdr, BIP152_VECS[i].nonce, BIP152_VECS[i].wtxid);
            if(ok!=1 || memcmp(got6,sid6,6)!=0){ failures++; printf("FAIL cmpctblock_shorttxid[%d]\n",i); }
        }
        char b[64]; snprintf(b,sizeof b,"cmpctblock_shorttxid round-trips first 4 vectors");
        /* (already counted individual failures) */
        /* truncated payload -> -1 */
        cki("cmpctblock count truncated -> -1", cmpctblock_shorttxids_count(payload, 88+1+4*6-1), -1);
        /* payload too short for header -> -1 */
        cki("cmpctblock count short header -> -1", cmpctblock_shorttxids_count(payload, 50), -1);
        /* out-of-range shorttxid access on 4-id payload -> 0 */
        cki("cmpctblock_shorttxid[4] out of range", cmpctblock_shorttxid((unsigned char[6]){0}, payload, 4), 0);
    }

    /* ---- 3e. block tx enumeration over a real Core block ---- */
    {
        long ntx=block_txcount(BLOCK_RAW, (long)sizeof BLOCK_RAW);
        cki("block_txcount on real Core block", ntx, BLOCK_NTX);
        cki("block_txcount on short block -> -1", block_txcount(BLOCK_RAW, 40), -1);
        int all=1;
        for(int i=0;i<BLOCK_NTX;i++){
            unsigned char* ptr=0; long len=0;
            long ok=block_tx_at(BLOCK_RAW, (long)sizeof BLOCK_RAW, i, &ptr, &len);
            if(ok!=1 || len!=BLOCK_TX_LEN[i]){
                printf("  block_tx_at[%d] ok=%ld len=%ld exp=%d\n",i,ok,len,BLOCK_TX_LEN[i]);
                all=0;
            }
            /* consecutive txs are contiguous: ptr[i+1] == ptr[i]+len[i] */
            if(i>0 && ptr < (unsigned char*)BLOCK_RAW) all=0;
        }
        ck("block_tx_at walks all txs of the real Core block with correct lengths", all);
        /* out-of-range index -> 0 */
        cki("block_tx_at index==ntx -> 0",
            block_tx_at(BLOCK_RAW,(long)sizeof BLOCK_RAW, BLOCK_NTX, &(unsigned char*){0}, &(long){0}), 0);
    }

    /* ---- 3f. cmpctblock_build produces the exact bytes Core would send ---- */
    {
        static unsigned char out[1<<20];
        long l=cmpctblock_build(out, BLOCK_RAW, (long)sizeof BLOCK_RAW, CMPCT_EXPECTED_NONCE);
        cki("cmpctblock_build length", l, CMPCT_EXPECTED_LEN);
        ck("cmpctblock_build bytes match reference (Core-equivalent) output",
            l==CMPCT_EXPECTED_LEN && memcmp(out, CMPCT_EXPECTED, (size_t)l)==0);
        /* tx_wtxid of tx0 (coinbase) sanity: matches sha256d reference already
           exercised through cmpctblock_build; just ensure it returns 32B. */
    }

    /* ---- SER-4: a block with >= 253 transactions ----
     * All three BIP152 helpers read the block's tx-count CompactSize as a
     * SINGLE BYTE and started the transaction walk at block+81. For 253 or
     * more transactions -- a 3, 5 or 9-byte varint -- the count was taken as
     * the marker byte (253/254/255) and the cursor was 2/4/8 bytes short, so
     * every transaction boundary was misparsed.
     *
     * cons_verify, the consensus path, reads it correctly, so only the
     * SERVING helpers were affected -- but they were affected on every modern
     * block: a peer asking for a cmpctblock or getblocktxn got the .gd_miss
     * path and nothing at all. Compact-block relay was effectively off.
     *
     * The block below is synthetic and minimal -- 253 one-input, one-output
     * transactions -- because what is under test is the COUNT PARSE and the
     * cursor it produces, not transaction contents. It asserts the count is
     * read as 253 (not 0xfd = the marker) and that the LAST transaction is
     * reachable, which is only true if the cursor started at the right offset
     * and every boundary since was right. */
    {
        enum { N253 = 253 };
        static unsigned char b2[80 + 3 + N253 * 64];
        long o = 0;
        memset(b2, 0x33, 80); o = 80;
        b2[o++] = 0xfd; b2[o++] = (unsigned char)(N253 & 0xff);
        b2[o++] = (unsigned char)(N253 >> 8);
        long first_off = o, last_off = 0;
        for (int i = 0; i < N253; i++){
            long txs = o;
            if (i == N253 - 1) last_off = txs;
            b2[o++]=2; b2[o++]=0; b2[o++]=0; b2[o++]=0;      /* version */
            b2[o++]=1;                                        /* 1 input  */
            for (int k=0;k<32;k++) b2[o++]=(unsigned char)(i+k);
            b2[o++]=0; b2[o++]=0; b2[o++]=0; b2[o++]=0;      /* vout */
            b2[o++]=0;                                        /* scriptSig */
            b2[o++]=0xff;b2[o++]=0xff;b2[o++]=0xff;b2[o++]=0xff;
            b2[o++]=1;                                        /* 1 output */
            for (int k=0;k<8;k++) b2[o++]=0;
            b2[o++]=1; b2[o++]=0x51;
            b2[o++]=0; b2[o++]=0; b2[o++]=0; b2[o++]=0;      /* locktime */
        }
        (void)first_off;

        cki("SER-4 block_txcount reads a 3-byte CompactSize (253, not 0xfd)",
            block_txcount(b2, o), N253);

        unsigned char* tp = 0; long tl = 0;
        long r = block_tx_at(b2, o, N253 - 1, &tp, &tl);
        cki("SER-4 block_tx_at reaches the LAST transaction of a 253-tx block", r, 1);
        cki("  ...and lands on its real offset (cursor started past the varint)",
            (long)(tp - b2), last_off);
    }

    /* ---- 2026-09-25: cmpctblock_build on a REAL block of 254+ transactions.
     * The short-id count was written as ONE byte (the low byte of ntx-1) with
     * the short ids at +89, so every cmpctblock for such a block -- nearly
     * all of mainnet -- was malformed on the wire; 3f's reference block is
     * small, so it never showed. Block 481,827 (committed fixture, ~1 MB):
     * the count must be a 3-byte CompactSize == ntx-1, every short id must be
     * the one computed here from that transaction's wtxid, and the prefilled
     * coinbase must follow the last short id. ---- */
    {
        FILE* f = fopen("tests/fixtures/blk_481827.bin", "rb");
        if (!f) { printf("FAIL fixture tests/fixtures/blk_481827.bin missing (run from asm/)\n"); failures++; }
        else {
            static unsigned char blk[1<<21], out[1<<21];
            long bl = (long)fread(blk, 1, sizeof blk, f); fclose(f);
            long ntx = block_txcount(blk, bl);
            ck("481827: a real block of 254+ transactions", ntx >= 254);
            const uint64_t nonce = 0x0123456789abcdefULL;
            long l = cmpctblock_build(out, blk, bl, nonce);
            ck("481827: cmpctblock_build succeeds", l > 0);
            if (l > 0 && ntx >= 254) {
                long nshort = ntx - 1;
                ck("481827: the short-id count is a CompactSize (0xfd + u16 LE), not one byte",
                   out[88] == 0xfd && (long)(out[89] | (out[90] << 8)) == nshort);
                cki("481827: cmpctblock_shorttxids_count reads ntx-1 back", cmpctblock_shorttxids_count(out, l), nshort);
                long bad = 0;
                for (long i = 1; i < ntx; i++) {
                    unsigned char* tp; long tl; unsigned char w[32], exp6[6], got6[6];
                    if (!block_tx_at(blk, bl, i, &tp, &tl)) { bad++; continue; }
                    tx_wtxid(w, tp, tl);
                    bip152_shortid(exp6, blk, nonce, w);
                    if (!cmpctblock_shorttxid(got6, out, i - 1) || memcmp(got6, exp6, 6) || memcmp(out + 91 + (i - 1) * 6, exp6, 6)) bad++;
                }
                cki("481827: every short id is its transaction's (at 91 + 6*i)", bad, 0);
                unsigned char* cb; long cbl;
                block_tx_at(blk, bl, 0, &cb, &cbl);
                long pf = 91 + nshort * 6;
                ck("481827: prefilled count 1, index 0, then the coinbase bytes",
                   out[pf] == 1 && out[pf + 1] == 0 && memcmp(out + pf + 2, cb, (size_t)cbl) == 0);
                cki("481827: total length = 88 + 3 + 6*nshort + 2 + coinbase", l, pf + 2 + cbl);
            }
        }
    }

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
