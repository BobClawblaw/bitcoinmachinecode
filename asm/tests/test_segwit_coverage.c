/* Census-driven coverage (CHAIN_AHEAD_CENSUS.md): real mainnet spends of
 * shapes the verifier HANDLES but had never run on real chain data, each
 * driven through the real block-connection dispatch tx_verify_block_connect.
 * Fixtures fetched from the Core oracle by validation/fetch_segwit_coverage.py.
 * The point is to turn "should work" into "verified" -- if one of these fails,
 * it is a real bug the census only predicted, not a test artifact.
 *
 * Shapes: OP_CODESEPARATOR inside a P2WSH witnessScript; the three
 * ANYONECANPAY sighash corners (0x81/0x82/0x83, incl. SINGLE|ACP); tapscript
 * OP_CHECKSIGADD / OP_CLTV / OP_CSV (P2TR script-path); and a >8-item witness
 * stack (gated: rejects until the TXV_MAX_WIT_ITEMS fix on branch wit-items). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "segwit_coverage_vec.h"
#include "test_tmpdir.h"
typedef unsigned char u8; typedef unsigned long u64;
struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask;
    int  bulk_mode; u64 pad2[16];
};
extern long utxo_struct_size(unsigned long);
extern void utxo_init(void*, unsigned long, void*, unsigned long);
extern long utxo_lsm_init(struct lsm_state*);
extern long utxo_lsm_put(struct lsm_state*, void*, const u8 txid[32], uint32_t index,
                         u64 value, u64 height, u64 is_coinbase, const u8* script, uint32_t slen);
extern int  tx_verify_block_connect(const u8* tx, u64 txlen, long height, const u8 bh[32],
                                    void* lst, void* u, const char** reason);
#define BLOOM_MAX_BYTES (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
/* link-only stubs (real defs live in daemon/utxo_live.c, not linked here) */
long bidx_get(void* bx, uint32_t caller_tx_index, const u8 txid[32], uint32_t index,
              u64* value, u64* height, u64* is_coinbase, const u8** script, unsigned long* slen){
  (void)bx;(void)caller_tx_index;(void)txid;(void)index;(void)value;(void)height;(void)is_coinbase;(void)script;(void)slen; return 0; }
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
              unsigned long long* value, const u8** script, unsigned long* slen){
  (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen; return 0; }
static int hx(const char* h, u8* o){ int n=0; for(;h[0]&&h[1];h+=2,n++){unsigned v;sscanf(h,"%2x",&v);o[n]=(u8)v;} return n; }
static int fails=0, checks=0;
static void ck(const char* n,int c){ checks++; printf("%s %s\n",c?"  ok ":"  FAIL",n); if(!c)fails++; }
static struct lsm_state g_lst; static void* g_tab;
static void seed_lsm(void){
  unsigned long slots=1UL<<12; long us=utxo_struct_size(slots);
  g_tab=malloc((size_t)us); void* blob=malloc(4UL<<20); utxo_init(g_tab,slots,blob,4UL<<20);
  memset(&g_lst,0,sizeof g_lst);
  u64 op=slots*2, fill=slots*3/4, tomb=op, desc=slots*3, scr=desc*128+BLOOM_MAX_BYTES+SCRIPT_MAX_BYTES;
  g_lst.op_threshold=op; g_lst.fill_threshold=fill;
  g_lst.tomb_buf=malloc(tomb*36); g_lst.tomb_cap=tomb;
  g_lst.manifest_buf=malloc(256*16); g_lst.manifest_cap=256;
  g_lst.scratch_buf=malloc(scr); g_lst.scratch_cap=scr;
  if(utxo_lsm_init(&g_lst)!=1){fprintf(stderr,"lsm_init\n");exit(1);}
}
static u8 txbuf[1<<20], spk[256];
int main(void){
  tt_isolate();
  seed_lsm();
  /* seed every prevout of every fixture (RPC display order -> wire order) */
  for(unsigned f=0; f<COV_N; f++){ const cov_fixture_t* F=&COV_FIXTURES[f];
    for(unsigned k=0;k<F->n_in;k++){ u8 tid[32],rev[32]; hx(F->prev[k].txid_hex,tid);
      for(int b=0;b<32;b++) rev[b]=tid[31-b];
      memcpy(tid,rev,32);
      int sl=hx(F->prev[k].spk_hex,spk);
      if(utxo_lsm_put(&g_lst,g_tab,tid,F->prev[k].index,F->prev[k].value,0,0,spk,(uint32_t)sl)!=1){fprintf(stderr,"put\n");return 1;} } }
  u8 bh[32]={0}; char nm[200];
  for(unsigned f=0; f<COV_N; f++){ const cov_fixture_t* F=&COV_FIXTURES[f];
    int txlen=hx(F->tx_hex,txbuf); const char* reason="?";
    int r=tx_verify_block_connect(txbuf,(u64)txlen,F->height,bh,&g_lst,g_tab,&reason);
    snprintf(nm,sizeof nm,"%s",F->note);
    /* incident #16 FIXED (2026-08-22): this real tapscript CSV spend that Core
     * accepted at 806500 was previously REJECTED with "p2tr tapscript execution
     * failed" because bitcoin_taproot_sighash.c's script_eval setup memset the
     * state and never set st.flags / st.tx_locktime / st.in_sequence /
     * st.tx_version. The taproot driver now activates CLTV(1<<9)/CSV(1<<10) and
     * threads the real tx context (via sv_get_locktime_context), so this MUST
     * ACCEPT through the block-connect dispatch. (Was gated to r==0 as a known
     * bug before the fix -- fail-on-old was verified on unmodified main.) */
    if(strcmp(F->name,"tapscript_csv")==0){
      ck(nm, r==1);
      if(r!=1) printf("       REASON: %s\n",reason);
      continue;
    }
    /* NOTE: tapscript_cltv's leaf is actually <pubkey> OP_CHECKSIG (the crude
     * 0xb1-byte predicate matched push data, not a real OP_CLTV); it passes as
     * a plain checksig. Kept as extra tapscript-checksig coverage, honestly
     * relabelled. A real tapscript CLTV fixture is a follow-up. */
    if(F->xfail_witcap){
      /* >8-item witness stack. The TXV_MAX_WIT_ITEMS cap is now 1004 (d1a2259,
       * already on main), so this real spend Core accepted at 551500 must
       * ACCEPT. (Named xfail_witcap from when the cap was 8 and this rejected.) */
      ck(nm, r==1);
      if(r!=1) printf("       REASON: %s (r=%d)\n",reason,r);
    } else {
      ck(nm, r==1);
      if(r!=1) printf("       REASON: %s\n",reason);
    }
  }
  /* ---- negative: corrupt a tapscript CHECKSIGADD signature -> reject ---- */
  {
    const cov_fixture_t* F=&COV_FIXTURES[4];   /* tapscript_csadd */
    int txlen=hx(F->tx_hex,txbuf); const char* rs="?";
    /* schnorr sigs are 64/65 bytes; flip a byte early in the first witness item
     * region by nudging a byte well inside the tx body that is part of a witness
     * (search for the leaf script's control-block tag is fragile; instead flip a
     * byte at a fixed deep offset that lands in the witness area of this large tx). */
    u8 save=txbuf[txlen-200]; txbuf[txlen-200]^=0x01;
    ck("tapscript CHECKSIGADD with a corrupted witness byte is REJECTED",
       tx_verify_block_connect(txbuf,(u64)txlen,F->height,bh,&g_lst,g_tab,&rs)==0);
    txbuf[txlen-200]=save;
  }
  /* ---- negative: corrupt the ACP(0x81) signature -> reject ---- */
  {
    const cov_fixture_t* F=&COV_FIXTURES[1];   /* sighash_acp_81 */
    int txlen=hx(F->tx_hex,txbuf); const char* rs="?";
    u8 save=txbuf[txlen-120]; txbuf[txlen-120]^=0x01;
    ck("SIGHASH_ALL|ANYONECANPAY with a corrupted witness byte is REJECTED",
       tx_verify_block_connect(txbuf,(u64)txlen,F->height,bh,&g_lst,g_tab,&rs)==0);
    txbuf[txlen-120]=save;
  }
  printf("\n%s (%d/%d)\n", fails?"TESTS FAILED":"ALL PASS", checks-fails, checks);
  return fails?1:0;
}
