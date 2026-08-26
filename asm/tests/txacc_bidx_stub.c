/* tests/txacc_bidx_stub.c -- bidx_get stub for TXACCEPTOBJS test binaries.
 * The real symbol lives in daemon/utxo_live.c (the in-block chained-spend
 * index used during BLOCK connection); mempool-admission tests never have a
 * block context, and tx_verify's callers already treat a miss as "fall back
 * to the confirmed set", so an unconditional miss is the honest stub. */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
long bidx_get(void* bx, u32 caller_tx_index, const u8 txid[32], u32 index,
              u64* value, u64* height, u64* is_coinbase,
              const u8** script, unsigned long* slen){
    (void)bx; (void)caller_tx_index; (void)txid; (void)index; (void)value;
    (void)height; (void)is_coinbase; (void)script; (void)slen;
    return 0;
}
