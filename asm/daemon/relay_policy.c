/* daemon/relay_policy.c -- see relay_policy.h. Mirrors Core v31.99
 * net_processing.cpp (RejectIncomingTxs, PushNodeVersion, MaybeSendFeefilter)
 * and net.cpp/net.h (m_max_inbound_full_relay). */
#include "relay_policy.h"
#include "netperm.h"

static int g_blocksonly;
void rp_set_blocksonly(int on){ g_blocksonly = on ? 1 : 0; }
int  rp_blocksonly(void){ return g_blocksonly; }

int rp_reject_incoming_txs(unsigned perms, int conn_kind){
    if (conn_kind == RP_CONN_BLOCK_RELAY) return 1;      /* block-relay-only peers may never send txs to us */
    if (conn_kind == RP_CONN_FEELER) return 1;
    if (g_blocksonly && !(perms & NP_RELAY)) return 1;   /* -blocksonly: `relay` permission needed */
    return 0;
}

int rp_our_frelay(unsigned perms, int conn_kind, int share_exhausted){
    if (rp_reject_incoming_txs(perms, conn_kind)) return 0;
    if (conn_kind == RP_CONN_INBOUND && share_exhausted && !(perms & NP_RELAY)) return 0;
    return 1;
}

int rp_inbound_share_exhausted(long relaying_now, long inbound_limit, int percent){
    if (inbound_limit <= 0) return 0;
    if (percent < 0) percent = 0;
    if (percent > 100) percent = 100;
    long max_full_relay = (long)(percent / 100.0 * (double)inbound_limit);   /* Core: static_cast<int>(pct/100.0 * max_inbound) */
    return relaying_now >= max_full_relay;
}

int rp_version_frelay(const unsigned char* p, long len){
    /* version: i32 version, u64 services, i64 time, addr_recv(26), addr_from(26),
     * u64 nonce, varstr user_agent, i32 start_height, [u8 fRelay] */
    if (!p || len < 80) return -1;
    long off = 80; unsigned long long ualen;
    if (p[off] < 0xfd){ ualen = p[off]; off += 1; }
    else if (p[off] == 0xfd){ if (off + 3 > len) return -1; ualen = (unsigned)p[off+1] | ((unsigned)p[off+2] << 8); off += 3; }
    else return -1;                                    /* a user agent needing more than 2 bytes of length is not a version message */
    off += (long)ualen;
    if (off + 4 > len) return -1;                      /* start_height missing */
    off += 4;
    if (off >= len) return 1;                          /* fRelay absent -> relay */
    return p[off] ? 1 : 0;
}

int rp_send_feefilter(unsigned perms){
    if (g_blocksonly) return 0;
    if (perms & NP_FORCERELAY) return 0;
    return 1;
}
