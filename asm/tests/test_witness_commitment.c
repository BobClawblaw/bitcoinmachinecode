/* test_witness_commitment.c -- BIP141 coinbase witness-commitment validation
 * (daemon/block_witness.c) against REAL blocks.
 *
 * Committed fixtures (always run):
 *   - genesis (285 bytes, from constants): pre-activation, no witness, no
 *     commitment.
 *   - tests/block_vec.h BLOCK_RAW: a real Core regtest block with a coinbase
 *     witness nonce + commitment output.
 *   - tests/fixtures/blk_witness_small.bin: real mainnet segwit-era block
 *     0000000000000000003a5d8de2b26ce91ca3e8a208ea9071f9f3af61ee137e5e
 *     (1563 bytes, 6 txs, coinbase commitment + nonce, >=1 witness tx),
 *     extracted from the scratch Core oracle's blk*.dat (XOR-obfuscated,
 *     blocks/xor.dat) -- the smallest block found that exercises every
 *     negative below. Height resolvable via `getblockheader` on the oracle.
 * Optional large fixtures (tests/fixtures/blk_<height>.bin, gitignored, from
 * validation/fetch_witness_blocks.py): 481823, 481824, 600000 -- SKIP if
 * absent, never silently pass.
 *
 * Negatives are built by byte surgery on real blocks: (a) strip every witness
 * -- byte-for-byte what the archive held for >= 481824 until 2026-08-22 --
 * must fail "bad-witness-nonce-size"; (b) flip one witness byte -> "bad-
 * witness-merkle-match"; (c) flip a nonce byte -> same; (d) drop the
 * commitment output but keep witnesses -> "unexpected-witness"; (e) graft a
 * witness onto a pre-activation block -> "unexpected-witness". The stripper
 * is self-checked: every stripped tx must keep its txid. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../daemon/block_witness.h"
#include "block_vec.h"

typedef uint8_t u8; typedef uint64_t u64; typedef uint32_t u32;
extern int  tx_parse(void* info, const u8* tx, unsigned long txlen);
extern void tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern unsigned long long script_flags_for_block(unsigned long long height, const u8 hash32[32]);

static int fails = 0, passes = 0, skips = 0;
#define CHECK(c, ...) do { if (c) { passes++; printf("PASS "); } else { fails++; printf("FAIL "); } printf(__VA_ARGS__); printf("\n"); } while (0)

typedef struct { const u8* ptr; u64 len; u8 txid[32]; u32 pn_in; } tx_t;   /* same prefix as block_tx_t */
static u8 g_scratch[4<<20];
static u8 g_txscratch[4<<20];

static u64 rd_varint(const u8* p, u64* used){
    if (p[0] < 0xfd){ *used=1; return p[0]; }
    if (p[0]==0xfd){ *used=3; return p[1]|((u64)p[2]<<8); }
    if (p[0]==0xfe){ *used=5; return p[1]|((u64)p[2]<<8)|((u64)p[3]<<16)|((u64)p[4]<<24); }
    *used=9; u64 v=0; for(int i=0;i<8;i++) v|=(u64)p[1+i]<<(8*i); return v;
}
static u64 wr_varint(u8* p, u64 v){
    if (v<0xfd){ p[0]=(u8)v; return 1; }
    if (v<=0xffff){ p[0]=0xfd; p[1]=v&0xff; p[2]=(v>>8)&0xff; return 3; }
    p[0]=0xfe; for(int i=0;i<4;i++) p[1+i]=(v>>(8*i))&0xff; return 5;
}

/* parse a block into a tx array; returns ntx or 0 on failure */
static u64 parse_block(const u8* blk, u64 len, tx_t* txs, u64 cap){
    if (len < 81) return 0;
    u64 used; u64 ntx = rd_varint(blk+80, &used); const u8* q = blk+80+used; const u8* end = blk+len;
    if (ntx > cap) return 0;
    for (u64 t=0;t<ntx;t++){
        u8 info[64]; if (!tx_parse(info, q, (unsigned long)(end-q))) return 0;
        u64 tl; memcpy(&tl, info, 8); u32 nin; memcpy(&nin, info+12, 4);
        txs[t].ptr=q; txs[t].len=tl; txs[t].pn_in=nin;
        tx_txid(txs[t].txid, q, tl, g_txscratch, sizeof g_txscratch);
        q += tl;
    }
    return q==end ? ntx : 0;
}

/* minimal witness stripper (wire -> legacy serialization); returns out len */
static u64 strip_tx(const u8* tx, u64 len, u8* out){
    const u8* p = tx; u8* o = out; u64 used, v;
    memcpy(o, p, 4); o+=4; p+=4;
    int segwit = (p[0]==0 && p[1]==1); if (segwit) p+=2;
    u64 nin = rd_varint(p,&used); memcpy(o,p,used); o+=used; p+=used;
    for (u64 i=0;i<nin;i++){ memcpy(o,p,36); o+=36; p+=36; v=rd_varint(p,&used); memcpy(o,p,used+v); o+=used+v; p+=used+v; memcpy(o,p,4); o+=4; p+=4; }
    u64 nout = rd_varint(p,&used); memcpy(o,p,used); o+=used; p+=used;
    for (u64 i=0;i<nout;i++){ memcpy(o,p,8); o+=8; p+=8; v=rd_varint(p,&used); memcpy(o,p,used+v); o+=used+v; p+=used+v; }
    if (segwit){ for (u64 i=0;i<nin;i++){ u64 n=rd_varint(p,&used); p+=used; for(u64 k=0;k<n;k++){ v=rd_varint(p,&used); p+=used+v; } } }
    memcpy(o,p,4); o+=4; p+=4;
    (void)len; return (u64)(o-out);
}

/* rebuild a block from a tx list (header + varint + concatenated txs) */
static u64 rebuild(const u8* hdr, const tx_t* txs, u64 ntx, u8* out){
    memcpy(out, hdr, 80); u64 o = 80 + wr_varint(out+80, ntx);
    for (u64 t=0;t<ntx;t++){ memcpy(out+o, txs[t].ptr, txs[t].len); o += txs[t].len; }
    return o;
}

static long run(const char* label, const u8* blk, u64 len, int segwit_active, const char** reason){
    static tx_t txs[65536];
    u64 ntx = parse_block(blk, len, txs, 65536);
    if (!ntx){ *reason="(parse failed)"; return -2; }
    *reason="";
    return block_check_witness_commitment(txs, ntx, sizeof(tx_t), segwit_active, g_scratch, sizeof g_scratch, reason);
}

static u8* load(const char* path, u64* len){
    FILE* f=fopen(path,"rb"); if(!f) return 0;
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    u8* b=malloc(n); if (fread(b,1,n,f)!=(size_t)n){ fclose(f); free(b); return 0; }
    fclose(f); *len=n; return b;
}

/* ---- the negatives, all built from a real segwit block ---- */
static void negatives(const char* label, const u8* blk, u64 len){
    static tx_t txs[65536]; static u8 buf[8<<20]; static u8 buf2[8<<20]; static u8 stripped[65536][1]; (void)stripped;
    const char* r; long v;
    u64 ntx = parse_block(blk, len, txs, 65536);
    CHECK(ntx>1, "%s: parses (%llu txs)", label, (unsigned long long)ntx);
    v = run(label, blk, len, 1, &r);
    CHECK(v==1, "%s: real block passes with segwit active (%s)", label, r);

    /* (a) strip ALL witness data -> what the archive held. Self-check: txids unchanged. */
    static tx_t st[65536]; u64 o=0; int txid_ok=1;
    for (u64 t=0;t<ntx;t++){ u64 l=strip_tx(txs[t].ptr, txs[t].len, buf+o); st[t].ptr=buf+o; st[t].len=l; o+=l;
        u8 id[32]; tx_txid(id, st[t].ptr, l, g_txscratch, sizeof g_txscratch); if (memcmp(id, txs[t].txid, 32)) txid_ok=0; }
    CHECK(txid_ok, "%s: stripper keeps every txid (self-check)", label);
    u64 slen = rebuild(blk, st, ntx, buf2);
    CHECK(slen < len, "%s: stripped block is smaller (%llu < %llu)", label, (unsigned long long)slen, (unsigned long long)len);
    v = run(label, buf2, slen, 1, &r);
    CHECK(v==0 && !strcmp(r,"bad-witness-nonce-size"), "%s: (a) STRIPPED block rejected: %s  [the archive's bytes until 2026-08-22]", label, r);
    v = run(label, buf2, slen, 0, &r);
    CHECK(v==1, "%s: (a') stripped block passes when segwit NOT active (no witness, commitment ignored) (%s)", label, r);

    /* (b) flip one byte inside a non-coinbase tx's witness */
    memcpy(buf, blk, len); u64 nparsed = parse_block(buf, len, txs, 65536); (void)nparsed;
    int flipped=0;
    for (u64 t=1;t<ntx && !flipped;t++){
        int hw; u64 n,l0; const u8* it; const u8* c;
        if (bw_walk_tx(txs[t].ptr, txs[t].len, &hw,&n,&l0,&it,&c) && hw && it && l0>0){ ((u8*)it)[0]^=0x01; flipped=1; }
    }
    CHECK(flipped, "%s: found a witness byte to flip", label);
    v = run(label, buf, len, 1, &r);
    CHECK(v==0 && !strcmp(r,"bad-witness-merkle-match"), "%s: (b) flipped witness byte rejected: %s", label, r);

    /* (c) flip a byte of the coinbase nonce */
    memcpy(buf, blk, len); parse_block(buf, len, txs, 65536);
    { int hw; u64 n,l0; const u8* it; const u8* c; bw_walk_tx(txs[0].ptr, txs[0].len, &hw,&n,&l0,&it,&c);
      CHECK(n==1 && l0==32 && c, "%s: coinbase has 1x32 nonce + commitment", label); ((u8*)it)[5]^=0x80; }
    v = run(label, buf, len, 1, &r);
    CHECK(v==0 && !strcmp(r,"bad-witness-merkle-match"), "%s: (c) flipped nonce rejected: %s", label, r);

    /* (c2) nonce of the wrong size: truncate coinbase witness item to 31 bytes */
    memcpy(buf, blk, len); parse_block(buf, len, txs, 65536);
    { int hw; u64 n,l0; const u8* it; const u8* c; bw_walk_tx(txs[0].ptr, txs[0].len, &hw,&n,&l0,&it,&c);
      u8* lenb=(u8*)it-1; /* 1-byte varint for len 32 */ *lenb=31;
      /* shift the rest of the block left by one byte to keep the tx well-formed */
      u8* rest=(u8*)it+32; memmove(rest-1, rest, (size_t)(buf+len-rest)); }
    v = run(label, buf, len-1, 1, &r);
    CHECK(v==0 && !strcmp(r,"bad-witness-nonce-size"), "%s: (c2) 31-byte nonce rejected: %s", label, r);

    /* (d) remove the commitment output, keep witnesses -> unexpected-witness */
    memcpy(buf, blk, len); parse_block(buf, len, txs, 65536);
    { const u8* cb=txs[0].ptr; u64 cl=txs[0].len; const u8* p=cb+4; if (p[0]==0&&p[1]==1) p+=2;
      u64 used; u64 nin=rd_varint(p,&used); p+=used;
      for(u64 i=0;i<nin;i++){ p+=36; u64 s=rd_varint(p,&used); p+=used+s+4; }
      u8* noutp=(u8*)p; u64 nout=rd_varint(p,&used); p+=used;
      const u8* last_commit_out=0; u64 last_commit_len=0;
      for(u64 i=0;i<nout;i++){ const u8* outp=p; p+=8; u64 s=rd_varint(p,&used); if(s>=38&&p[used]==0x6a&&p[used+1]==0x24&&p[used+2]==0xaa&&p[used+3]==0x21&&p[used+4]==0xa9&&p[used+5]==0xed){ last_commit_out=outp; last_commit_len=8+used+s; } p+=used+s; }
      CHECK(last_commit_out && nout<0xfd, "%s: locate commitment output (%llu outputs)", label, (unsigned long long)nout);
      memmove((u8*)last_commit_out, last_commit_out+last_commit_len, (size_t)(buf+len-(last_commit_out+last_commit_len)));
      *noutp=(u8)(nout-1); (void)cl;
      /* coinbase got shorter by last_commit_len; block too */
      v = run(label, buf, len-last_commit_len, 1, &r);
      CHECK(v==0 && !strcmp(r,"unexpected-witness"), "%s: (d) commitment removed, witnesses kept -> %s", label, r); }
}

static const char GENESIS_HEX[] =
 "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
 "0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

static u64 unhex(const char* h, u8* out){ u64 n=strlen(h)/2; for(u64 i=0;i<n;i++){ unsigned b; sscanf(h+2*i,"%2x",&b); out[i]=(u8)b; } return n; }

int main(void){
    const char* r; long v;

    /* --- runtime cross-check of the C-side bit against the generated asm --- */
    u8 zero[32]={0};
    unsigned long long fb=script_flags_for_block(481823, zero), fa=script_flags_for_block(481824, zero);
    CHECK(!((fb>>BW_SFC_BIT_NULLDUMMY)&1) && ((fa>>BW_SFC_BIT_NULLDUMMY)&1), "BW_SFC_BIT_NULLDUMMY (%d) flips exactly at 481824 in script_flags_for_block", BW_SFC_BIT_NULLDUMMY);

    /* --- genesis: pre-activation, no witness, no commitment --- */
    static u8 gen[512]; u64 glen=unhex(GENESIS_HEX, gen);
    u8 gh[32]; block_hash(gh, gen);
    CHECK(glen==285 && gh[31]==0 && gh[28]==0, "genesis decodes (285 bytes, hash ends in zeros)");
    v=run("genesis", gen, glen, 0, &r); CHECK(v==1, "genesis passes, segwit inactive (%s)", r);
    v=run("genesis", gen, glen, 1, &r); CHECK(v==1, "genesis passes, segwit active (no commitment, no witness) (%s)", r);
    /* (e) graft a witness onto genesis's coinbase: version | 00 01 | ... | [1 item of 1 byte] | locktime */
    { static u8 g2[512]; u64 o=0; memcpy(g2,gen,80+1); o=81; const u8* tx=gen+81; u64 tl=glen-81;
      memcpy(g2+o, tx, 4); o+=4; g2[o++]=0; g2[o++]=1; memcpy(g2+o, tx+4, tl-4-4); o+=tl-8;  /* body minus locktime */
      g2[o++]=1; g2[o++]=1; g2[o++]=0xAB;  /* witness: 1 item, 1 byte */
      memcpy(g2+o, tx+tl-4, 4); o+=4;
      v=run("genesis+wit", g2, o, 0, &r); CHECK(v==0 && !strcmp(r,"unexpected-witness"), "(e) witness grafted on pre-activation block -> %s", r);
      v=run("genesis+wit", g2, o, 1, &r); CHECK(v==0 && !strcmp(r,"unexpected-witness"), "(e') same with segwit active but no commitment -> %s", r); }

    /* --- real regtest segwit block from block_vec.h --- */
    v=run("regtest", BLOCK_RAW, sizeof BLOCK_RAW, 1, &r);
    CHECK(v==1, "block_vec.h regtest block (coinbase nonce + commitment) passes (%s)", r);

    /* --- committed small real mainnet early-segwit block --- */
    u64 len; u8* b = load("tests/fixtures/blk_witness_small.bin", &len);
    if (!b) b = load("fixtures/blk_witness_small.bin", &len);
    if (b){ negatives("small-mainnet", b, len); free(b); }
    else { fails++; printf("FAIL committed fixture tests/fixtures/blk_witness_small.bin missing\n"); }

    /* --- optional large real fixtures --- */
    struct { const char* f; int act; int expect_wit; } big[] = {
        {"tests/fixtures/blk_481823.bin", 0, 0}, {"tests/fixtures/blk_481824.bin", 1, 1}, {"tests/fixtures/blk_600000.bin", 1, 1} };
    for (unsigned i=0;i<3;i++){
        b = load(big[i].f, &len);
        if (!b){ skips++; printf("SKIP %s (run validation/fetch_witness_blocks.py)\n", big[i].f); continue; }
        v=run(big[i].f, b, len, big[i].act, &r); CHECK(v==1, "%s passes as stored by Core (%s)", big[i].f, r);
        if (!big[i].act){
            /* Pre-activation block evaluated AS IF segwit were active: Core's
             * order (validation.cpp:3891-3900) finds the commitment first, then
             * demands the 32-byte nonce. 481823's coinbase already carries a
             * commitment (miners signalled early) but no witness at all, so the
             * expected verdict is bad-witness-nonce-size -- NOT a pass. */
            static tx_t t0[65536]; u64 n0 = parse_block(b, len, t0, 65536); int hw; u64 n,l0; const u8* it; const u8* c;
            CHECK(n0 > 0, "%s parses (%llu txs)", big[i].f, (unsigned long long)n0);
            bw_walk_tx(t0[0].ptr, t0[0].len, &hw,&n,&l0,&it,&c);
            v=run(big[i].f, b, len, 1, &r);
            if (c) CHECK(v==0 && !strcmp(r,"bad-witness-nonce-size"), "%s has a commitment but no nonce: as-if-active -> %s (Core order: commitment found, then nonce)", big[i].f, r);
            else   CHECK(v==1, "%s as-if-active passes (no commitment, no witness) (%s)", big[i].f, r);
        }
        if (big[i].expect_wit) negatives(big[i].f, b, len);
        free(b);
    }

    printf("\n%d passed, %d failed, %d skipped\n", passes, fails, skips);
    if (fails){ printf("TESTS FAILED (%d failures)\n", fails); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n"); return 0;
}
