/* test_rpc_node.c -- live-node RPC module (rpc_node.c) in isolation: populate a
 * fake node_status_t (as the serve parent would in shared memory), dispatch,
 * and assert the JSON. No serve daemon / sockets needed. */
#include "../rpc_node.h"
#include "../rpc_json.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>

/* Link stub: mpool_policy_add resolves confirmed prevouts through this. Any
 * outpoint not found in the policy's own outreg resolves to a 100000-sat
 * P2WPKH -- enough to make fees real without a UTXO store. */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char* txid, unsigned long index,
                                    unsigned long long* val, const unsigned char** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;
static const unsigned char SPK[22] = {0x00,0x14, 0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,
                                          0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99,0x99};
    *val = 100000; *spk = SPK; *spklen = 22;
    return 1;
}

/* Fake tx-submit worker: acks whatever the parent stages, recording the
 * tx_submit_test flag it saw so the test can prove sendrawtransaction clears
 * it (a stale 1 would turn a real broadcast into a dry run). */
static volatile int g_tw_run = 1;
static int g_tw_saw_test[8];      /* per handled submission, in order */
static int g_tw_n;
static int g_tw_verdict = 1;      /* what to report back */
static int g_tw_saw_pkg[8];       /* tx_submit_pkg_n per submission, in order */
static const char* g_tw_pkg_msg = "success";   /* package-level verdict */
/* g_tw_last is captured by the PARENT before pthread_create: reading it in
 * the new thread would race the parent's first submission, which can be
 * staged and the seq bumped before the thread is ever scheduled -- the
 * worker would then start from the already-bumped value and wait forever. */
static volatile unsigned long long g_tw_last;
static void* fake_txworker(void* arg){
    node_status_t* ns = (node_status_t*)arg;
    unsigned long long last = g_tw_last;
    while (g_tw_run){
        if (ns->tx_submit_seq != last){
            last = ns->tx_submit_seq;
            if (g_tw_n < 8){ g_tw_saw_pkg[g_tw_n] = ns->tx_submit_pkg_n;
                             g_tw_saw_test[g_tw_n++] = ns->tx_submit_test; }
            ns->tx_submit_result = g_tw_verdict;
            ns->tx_submit_fee = 12345;
            if (ns->tx_submit_pkg_n > 0){
                /* package dry run, as txsub_package publishes it */
                int pn = ns->tx_submit_pkg_n;
                int pkg_ok = !strcmp(g_tw_pkg_msg, "success");
                for (int i = 0; i < pn; i++){
                    ns->pkg_result[i] = pkg_ok ? (g_tw_verdict == 1) : 0;
                    ns->pkg_fee[i]    = 12345;
                    ns->pkg_vsize[i]  = 200;
                    snprintf((char*)ns->pkg_reason[i], sizeof ns->pkg_reason[i], "%s",
                             pkg_ok ? (g_tw_verdict == 1 ? "" : "min relay fee not met")
                                    : "package-not-validated");
                }
                ns->pkg_eff_fee   = 12345ull * (unsigned)pn;
                ns->pkg_eff_vsize = 200ull   * (unsigned)pn;
                snprintf((char*)ns->tx_submit_reason, sizeof ns->tx_submit_reason,
                         "%s", g_tw_pkg_msg);
            } else {
                snprintf((char*)ns->tx_submit_reason, sizeof ns->tx_submit_reason,
                         g_tw_verdict == 1 ? "" : "min relay fee not met");
            }
            __sync_synchronize();
            ns->tx_submit_ack = last;
        }
        struct timespec ts = {0, 200000}; nanosleep(&ts, 0);
    }
    return 0;
}

/* Fake control worker: mirrors the real worker's ctl_* handler closely
 * enough to drive the parent side end to end -- it applies bans to the
 * SHARED list (which is the point: listbanned reads what the worker writes)
 * and reports 0 for a no-op so the parent's error mapping is exercised. */
static volatile int g_cw_run = 1;
static volatile unsigned long long g_cw_last;
static int g_cw_ops[16]; static int g_cw_nops;
static void* fake_ctlworker(void* arg){
    node_status_t* ns = (node_status_t*)arg;
    unsigned long long last = g_cw_last;
    while (g_cw_run){
        if (ns->ctl_seq != last){
            last = ns->ctl_seq;
            int op = ns->ctl_op; long long num = ns->ctl_num;
            char a[128]; snprintf(a, sizeof a, "%s", (const char*)ns->ctl_arg);
            int result = 0;
            if (g_cw_nops < 16) g_cw_ops[g_cw_nops++] = op;
            if (op == RPC_CTL_SETNETACTIVE){ ns->net_active = num ? 1 : 0; result = 1; }
            else if (op == RPC_CTL_PING) result = 1;
            else if (op == RPC_CTL_ADDNODE) result = (num == 1) ? 0 : 1;  /* remove: not found */
            else if (op == RPC_CTL_DISCONNECT) result = a[0] && !strcmp(a, "1.2.3.4") ? 1 : 0;
            else if (op == RPC_CTL_SETBAN){
                if (num == 0){
                    result = 0;
                    for (int i = 0; i < RPC_MAX_BANS; i++)
                        if (ns->bans[i].until && !strcmp((const char*)ns->bans[i].subnet, a)){
                            ns->bans[i].until = 0; result = 1; break; }
                } else {
                    int dup = 0, slot = -1;
                    for (int i = 0; i < RPC_MAX_BANS; i++){
                        if (ns->bans[i].until && !strcmp((const char*)ns->bans[i].subnet, a)) dup = 1;
                        if (!ns->bans[i].until && slot < 0) slot = i;
                    }
                    if (dup || slot < 0) result = 0;
                    else { snprintf((char*)ns->bans[slot].subnet, 64, "%.63s", a);
                           ns->bans[slot].created = 111;
                           ns->bans[slot].until = num; result = 1; }
                }
            }
            else if (op == RPC_CTL_CLEARBANNED){
                for (int i = 0; i < RPC_MAX_BANS; i++) ns->bans[i].until = 0;
                result = 1;
            }
            ns->ctl_reason[0] = 0;
            ns->ctl_result = result;
            __sync_synchronize();
            ns->ctl_ack = last;
        }
        struct timespec ts = {0, 200000}; nanosleep(&ts, 0);
    }
    return 0;
}

/* local shorthands, in this file's own idiom (it dispatches through
 * rpc_node_dispatch directly rather than rpc_dispatch) */
#define P(j) rj_parse((j), strlen(j))
#define D(m, p) (r = NULL, ec = 0, em = NULL, rc = rpc_node_dispatch((m), (p), &r, &ec, &em))

static int g_fw_len_ok = -1;   /* fake_worker's view of the staged length */
static void* fake_worker(void* arg){
    node_status_t* ns = (node_status_t*)arg;
    for (int spins=0; spins<400000; spins++){
        if (ns->blk_submit_seq != ns->blk_submit_ack){
            g_fw_len_ok = (ns->blk_submit_len == 162);
            snprintf((char*)ns->blk_submit_reason, sizeof ns->blk_submit_reason, "duplicate");
            ns->blk_submit_result = 0;
            __sync_synchronize();
            ns->blk_submit_ack = ns->blk_submit_seq;
            return 0;
        }
        struct timespec ts={0,1000000}; nanosleep(&ts,0);
    }
    return 0;
}

/* Fake address book: two 18-byte records in the on-disk layout of
 * bitcoin_addrmgr.asm -- ip u32 LE, port u16 BE, services u64 LE at [6],
 * last_seen u32 LE at [14]. */
#include "../daemon/addrbook.h"
/* tx_txid (bitcoin_tx.asm): declared at file scope so every block in main sees it */
extern int tx_txid(unsigned char*, const unsigned char*, unsigned long, unsigned char*, unsigned long);
static ab2_rec_t FAKE_AB[3];
static void fake_ab_init(void){
    bmc_addr_from_string_port(&FAKE_AB[0].a, "76.156.14.11:8333", 0); FAKE_AB[0].services = 0x409; FAKE_AB[0].last_seen = 1700000000u;
    bmc_addr_from_string_port(&FAKE_AB[1].a, "1.2.3.4:8333", 0);      FAKE_AB[1].services = 13;    FAKE_AB[1].last_seen = 1700000001u;
    bmc_addr_from_string_port(&FAKE_AB[2].a, "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333", 0);
    FAKE_AB[2].services = 9; FAKE_AB[2].last_seen = 1700000002u;
}
static long fake_ab_count(void* ab){ (void)ab; return 3; }
static int fake_ab_get_i(void* ab, long i, ab2_rec_t* out){
    (void)ab; if (i < 0 || i > 2) return 0; *out = FAKE_AB[i]; return 1; }

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }
static const char* S(const rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o,k) : 0; return v ? v->str : 0; }

int main(void){
    /* static: node_status_t now carries the 4MB submitblock channel buffer,
     * far too large for the stack. */
    static node_status_t st;
    st.n_out = 8; st.n_inbound = 3; st.tip_height = 800000; st.start_time = 0;
    rpc_node_set_status(&st);
    long ec; const char* em; rj_val* r;

    r = NULL; int rc = rpc_node_dispatch("getconnectioncount", NULL, &r, &ec, &em);
    ck("getconnectioncount dispatched", rc == 1 && r != NULL);
    ck("getconnectioncount == 11 (8 out + 3 in)", r && r->str && !strcmp(r->str, "11"));
    rj_free(r);

    r = NULL; rc = rpc_node_dispatch("getnetworkinfo", NULL, &r, &ec, &em);
    ck("getnetworkinfo dispatched", rc == 1 && r != NULL);
    ck("protocolversion 70016",  r && S(r,"protocolversion") && !strcmp(S(r,"protocolversion"), "70016"));
    ck("subversion is ours",     r && S(r,"subversion") && !strcmp(S(r,"subversion"), "/BitcoinMachineCode:0.0.1/"));
    /* 2026-09-10: which BUILD is answering. bmcmonitor could not tell a fixed
     * node from a broken one over RPC -- both reported this same subversion. */
    { rj_val* bc = rj_obj_get(r, "bmc_build_commit"); rj_val* bd = rj_obj_get(r, "bmc_build_dirty");
      ck("getnetworkinfo names the build's commit, so a monitor can tell which binary answered",
         bc && bc->typ == RJ_STR && bc->str && bc->str[0] && strcmp(bc->str, "unknown") != 0);
      ck("...and whether that build had uncommitted changes", bd && bd->typ == RJ_BOOL); }
    ck("localservices NETWORK",  r && S(r,"localservices") && !strcmp(S(r,"localservices"), "0000000000000009"));
    ck("connections 11",         r && S(r,"connections") && !strcmp(S(r,"connections"), "11"));
    ck("connections_out 8",      r && S(r,"connections_out") && !strcmp(S(r,"connections_out"), "8"));
    ck("connections_in 3",       r && S(r,"connections_in") && !strcmp(S(r,"connections_in"), "3"));
    ck("localrelay true",        r && S(r,"localrelay") && !strcmp(S(r,"localrelay"), "1"));
    ck("networkactive reflects the REAL toggle, not a constant "
       "(unset in this status block, so false)",
       r && S(r,"networkactive") && !strcmp(S(r,"networkactive"), "0"));
    { rj_val* nets = r ? rj_obj_get(r,"networks") : 0;
      ck("networks is a 5-entry array", nets && nets->typ == RJ_ARR && nets->nitems == 5);
      rj_val* n0 = (nets && nets->nitems) ? nets->items[0] : 0;
      ck("networks[0].name ipv4", n0 && S(n0,"name") && !strcmp(S(n0,"name"), "ipv4")); }
    { rj_val* names = r ? rj_obj_get(r,"localservicesnames") : 0;
      ck("localservicesnames [NETWORK, WITNESS]", names && names->typ == RJ_ARR && names->nitems == 2
         && names->items[0]->str && !strcmp(names->items[0]->str, "NETWORK")
         && names->items[1]->str && !strcmp(names->items[1]->str, "WITNESS")); }
    rj_free(r);

    /* getpeerinfo: populate a couple of fake outbound peers in the table */
    st.peers[0].used = 1; st.peers[0].inbound = 0;
    strcpy(st.peers[0].addr, "1.2.3.4:8333"); st.peers[0].proto = 70016;
    st.peers[0].services = 0x0000000000000409ULL;   /* NETWORK|WITNESS|NETWORK_LIMITED */
    strcpy(st.peers[0].subver, "/Satoshi:27.0.0/"); st.peers[0].start_height = 800000;
    st.peers[0].conn_time = 1700000000LL;
    st.peers[0].bytes_sent = 4096; st.peers[0].bytes_recv = 1048576;
    st.peers[0].last_send = 1700000100LL; st.peers[0].last_recv = 1700000200LL;
    st.peers[0].nodeid = 0;
    /* RPC-3: a deliberately NON-contiguous slot with a NON-contiguous nodeid.
     * Slots 1 and 2 are free -- the state left by ordinary leg churn -- so the
     * old counter would have called this peer "1" while the worker's
     * disconnect matcher meant leg index 3. Both now say 7. */
    st.peers[3].used = 1; strcpy(st.peers[3].addr, "5.6.7.8:8333"); st.peers[3].proto = 70016;
    st.peers[3].nodeid = 7;
    rpc_node_set_status(&st);
    r = NULL; rc = rpc_node_dispatch("getpeerinfo", NULL, &r, &ec, &em);
    ck("getpeerinfo dispatched to array", rc == 1 && r && r->typ == RJ_ARR);
    ck("getpeerinfo has 2 peers", r && r->nitems == 2);
    /* every peer gets the shared fields, not just download workers: the two
     * builders used to emit different field sets from the same RPC. */
    { rj_val* p0 = (r && r->nitems) ? r->items[0] : NULL;
      ck("a relay leg carries connection_type", p0 && rj_obj_get(p0, "connection_type"));
      ck("a relay leg carries inflight (empty, honestly)", p0 && rj_obj_get(p0, "inflight")
         && rj_obj_get(p0, "inflight")->typ == RJ_ARR);
      ck("no peer carries startingheight, which Core v31.1 dropped",
         p0 && rj_obj_get(p0, "startingheight") == NULL); }
    /* 2026-09-08: the parallel download's peers are listed too, with the chunk in flight */
    rj_free(r);
    st.n_dlpeers = 1; memset(&st.dlpeers[0], 0, sizeof st.dlpeers[0]); st.dlpeers[0].used = 1;
    strcpy(st.dlpeers[0].addr, "203.0.113.9:8333"); strcpy(st.dlpeers[0].subver, "/Satoshi:31.1.0/"); st.dlpeers[0].proto = 70016;
    st.dlpeers[0].services = 0x409; st.dlpeers[0].start_height = 966000; st.dlpeers[0].bytes_recv = 123456789LL; st.dlpeers[0].conn_time = 1800000000LL;
    st.dlpeers[0].inflight_lo = 500001; st.dlpeers[0].inflight_hi = 500040; st.dlpeers[0].dl_worker = 7; st.dl_bytes_total = 50000000000LL;
    r = NULL; rc = rpc_node_dispatch("getpeerinfo", NULL, &r, &ec, &em);
    ck("getpeerinfo lists the download worker's peer as a third entry", rc == 1 && r && r->nitems == 3);
    { rj_val* d = (r && r->nitems == 3) ? r->items[2] : NULL; rj_val* fl = d ? rj_obj_get(d, "inflight") : NULL; rj_val* br = d ? rj_obj_get(d, "bytesrecv") : NULL; rj_val* ct = d ? rj_obj_get(d, "connection_type") : NULL;
      ck("...with 40 heights in flight, 500001..500040", fl && fl->nitems == 40 && !strcmp(fl->items[0]->str, "500001") && !strcmp(fl->items[39]->str, "500040"));
      ck("...its bytes, and connection_type outbound-full-relay", br && !strcmp(br->str, "123456789") && ct && !strcmp(ct->str, "outbound-full-relay"));
      /* bmc_download_worker was an ADDITIVE key in a Core call. It is gone
       * (2026-09-12), the same category as the startingheight dropped for
       * exactness; the worker index lives on bmcgetdownloadinfo, which is
       * ours to define. This assertion used to require the extra key, so it
       * pinned the divergence -- it now pins its absence. */
      ck("getpeerinfo carries no additive bmc_ key", d && rj_obj_get(d, "bmc_download_worker") == NULL); }
    rj_free(r);
    r = NULL; rc = rpc_node_dispatch("getnettotals", NULL, &r, &ec, &em);
    { rj_val* tr = r ? rj_obj_get(r, "totalbytesrecv") : NULL;
      ck("getnettotals counts the download's bytes (50 GB + the legs)", rc == 1 && tr && strtoll(tr->str, NULL, 10) >= 50000000000LL); }
    /* 2026-09-10: bmcgetdownloadinfo -- the window state getpeerinfo cannot
     * carry. Core has no counterpart, so nothing here mirrors a Core shape. */
    st.dl_active = 1; st.dl_workers = 8; st.dl_pool = 120; st.dl_banned = 10; st.dl_free_peers = 37;
    st.dl_window = 4096; st.dl_first_hole = 500001; st.dl_claim = 504097; st.dl_applied = 499000;
    st.dl_end_h = 966368; st.dl_staged = 12; st.dl_stall_timeout_s = 4; st.dl_stall_evictions = 3;
    st.dl_median_bps = 1361510; st.dlpeers[0].bps_recv = 1400000LL;
    r = NULL; rc = rpc_node_dispatch("bmcgetdownloadinfo", NULL, &r, &ec, &em);
    { rj_val* a = r ? rj_obj_get(r, "active") : NULL;
      rj_val* wk = r ? rj_obj_get(r, "workers") : NULL;
      rj_val* wn = r ? rj_obj_get(r, "window") : NULL;
      rj_val* fh = r ? rj_obj_get(r, "first_hole") : NULL;
      rj_val* so = r ? rj_obj_get(r, "stall_timeout_s") : NULL;
      rj_val* bn = r ? rj_obj_get(r, "banned") : NULL;
      rj_val* pa = r ? rj_obj_get(r, "peers") : NULL;
      ck("bmcgetdownloadinfo reports the window state while a download runs",
         rc == 1 && a && a->typ == RJ_BOOL && a->str && a->str[0] == '1' && wk && !strcmp(wk->str, "8") && wn && !strcmp(wn->str, "4096")
         && fh && !strcmp(fh->str, "500001") && so && !strcmp(so->str, "4") && bn && !strcmp(bn->str, "10"));
      { rj_val* w0 = (pa && pa->nitems == 1) ? pa->items[0] : NULL;
        rj_val* ad = w0 ? rj_obj_get(w0, "addr") : NULL;
        rj_val* bp = w0 ? rj_obj_get(w0, "bps_recv") : NULL;
        rj_val* iw = w0 ? rj_obj_get(w0, "worker") : NULL;
        ck("...and one worker entry mapping worker 7 to its peer, chunk and rate",
           ad && !strcmp(ad->str, "203.0.113.9:8333") && bp && !strcmp(bp->str, "1400000") && iw && !strcmp(iw->str, "7")); } }
    rj_free(r);
    st.dl_active = 0;
    r = NULL; rc = rpc_node_dispatch("bmcgetdownloadinfo", NULL, &r, &ec, &em);
    { rj_val* a = r ? rj_obj_get(r, "active") : NULL; rj_val* bt = r ? rj_obj_get(r, "bytes_total") : NULL;
      ck("with no download running it answers active=false rather than failing (a poller calls it unconditionally)",
         rc == 1 && a && a->typ == RJ_BOOL && a->str && a->str[0] == '0' && bt); }
    rj_free(r);

    st.n_dlpeers = 0; st.dl_bytes_total = 0;
    r = NULL; rc = rpc_node_dispatch("getpeerinfo", NULL, &r, &ec, &em);
    ck("with the download over, getpeerinfo is back to the 2 legs", rc == 1 && r && r->nitems == 2);
    { rj_val* p0 = (r && r->nitems) ? r->items[0] : 0;
      ck("peer0 addr", p0 && S(p0,"addr") && !strcmp(S(p0,"addr"), "1.2.3.4:8333"));
      ck("peer0 version", p0 && S(p0,"version") && !strcmp(S(p0,"version"), "70016"));
      ck("peer0 subver", p0 && S(p0,"subver") && !strcmp(S(p0,"subver"), "/Satoshi:27.0.0/"));
      ck("peer0 services hex", p0 && S(p0,"services") && !strcmp(S(p0,"services"), "0000000000000409"));
      ck("peer0 inbound false", p0 && S(p0,"inbound") && !strcmp(S(p0,"inbound"), "0"));
      ck("peer0 id 0", p0 && S(p0,"id") && !strcmp(S(p0,"id"), "0"));
      ck("peer0 bytessent", p0 && S(p0,"bytessent") && !strcmp(S(p0,"bytessent"), "4096"));
      ck("peer0 bytesrecv", p0 && S(p0,"bytesrecv") && !strcmp(S(p0,"bytesrecv"), "1048576"));
      ck("peer0 lastrecv", p0 && S(p0,"lastrecv") && !strcmp(S(p0,"lastrecv"), "1700000200"));
      rj_val* sn = p0 ? rj_obj_get(p0,"servicesnames") : 0;
      ck("peer0 servicesnames NETWORK+WITNESS+NETWORK_LIMITED", sn && sn->typ==RJ_ARR && sn->nitems==3); }
    /* ---- RPC-3 (audit 2026-09-03) ----
     *
     * This used to assert "peer1 id 1", with a comment reading "contiguous
     * ids, not the slot index". That pinned the defect: getpeerinfo counted
     * live entries while daemon/main.c's RPC_CTL_DISCONNECT matched the raw
     * outbound leg index, so with slots 1 and 2 free an operator who read
     * `id: 1` and ran `disconnectnode "" 1` dropped leg 1 -- a different peer,
     * or nothing -- and got success back. getpeerinfo now reports the peer's
     * own monotonic, never-reused nodeid, which is what the worker matches. */
    { rj_val* p1 = (r && r->nitems>1) ? r->items[1] : 0;
      ck("RPC-3 peer in slot 3 reports its own nodeid 7, not the position 1",
         p1 && S(p1,"id") && !strcmp(S(p1,"id"), "7"));
      ck("RPC-3 ...and it is NOT the old contiguous counter",
         !(p1 && S(p1,"id") && !strcmp(S(p1,"id"), "1"))); }
    rj_free(r);
    memset(st.peers, 0, sizeof st.peers);   /* reset for the remaining checks */

    /* getmempoolinfo: accurate config, empty for this process's mempool */
    r = NULL; rc = rpc_node_dispatch("getmempoolinfo", NULL, &r, &ec, &em);
    ck("getmempoolinfo dispatched", rc == 1 && r != NULL);
    ck("mempool loaded true", r && S(r,"loaded") && !strcmp(S(r,"loaded"), "1"));
    ck("mempool size 0", r && S(r,"size") && !strcmp(S(r,"size"), "0"));
    ck("mempool maxmempool 300MB", r && S(r,"maxmempool") && !strcmp(S(r,"maxmempool"), "300000000"));
    ck("mempool minrelaytxfee (Core field name, not minrelayfee)",
       r && S(r,"minrelaytxfee") && !strcmp(S(r,"minrelaytxfee"), "0.00000100") && S(r,"minrelayfee")==NULL);
    ck("mempool permitbaremultisig present", r && S(r,"permitbaremultisig") != NULL);
    ck("mempool maxdatacarriersize present", r && S(r,"maxdatacarriersize") && !strcmp(S(r,"maxdatacarriersize"),"100000"));
    rj_free(r);
    /* getrawmempool: [] non-verbose, {} verbose */
    r = NULL; rpc_node_dispatch("getrawmempool", NULL, &r, &ec, &em);
    ck("getrawmempool -> empty array", r && r->typ == RJ_ARR && r->nitems == 0); rj_free(r);
    { rj_val* pv = rj_parse("[true]", 6);
      r = NULL; rpc_node_dispatch("getrawmempool", pv, &r, &ec, &em);
      ck("getrawmempool true -> empty object", r && r->typ == RJ_OBJ && r->nmembers == 0);
      rj_free(r); rj_free(pv); }

    /* ---- injected SHARED mempool (2026-08-25 coherence slice): the daemon
     * hands the pre-fork MAP_SHARED pool to this layer via
     * rpc_node_set_mempool; here a local pool stands in for it. Two entries:
     * a legacy tx (vsize == size) and a segwit tx with a known witness split
     * (weight = base*3 + total), so both arms of the vsize parser are pinned.
     * The txids are what the pool was keyed with; getrawmempool must render
     * them REVERSED (display order). ---- */
    { extern void mpool_init(void*, unsigned long, void*, unsigned long);
      extern long mpool_put(void*, const unsigned char*, const unsigned char*, unsigned long);
      extern unsigned long mpool_struct_size(unsigned long);
      extern long mpool_count(void*);
      static unsigned char pool[40 + 1024*80 + 8];
      static unsigned char blob[1<<16];
      mpool_init(pool, 1024, blob, sizeof blob);
      /* legacy: the createrawtransaction P2PKH KAT tx (85 bytes, no witness) */
      static const char* LHEX = "020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000fdffffff01a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000";
      static unsigned char ltx[200]; unsigned long lln = strlen(LHEX)/2;
      for (unsigned long i=0;i<lln;i++){ unsigned hv; sscanf(LHEX+2*i,"%2x",&hv); ltx[i]=(unsigned char)hv; }
      unsigned char lid[32]; memset(lid, 0x5A, 32);
      /* segwit: same body with marker+flag and one 2-item witness stack
       * (71B sig + 33B pubkey): total = 85 + 2 + 107 = 194, base = 85,
       * weight = 85*3 + 194 = 449, vsize = ceil(449/4) = 113. */
      static unsigned char wtx[400]; unsigned long wln = 0;
      memcpy(wtx, ltx, 4); wln = 4;                     /* version */
      wtx[wln++]=0x00; wtx[wln++]=0x01;                 /* marker+flag */
      memcpy(wtx+wln, ltx+4, lln-8); wln += lln-8;      /* ins/outs (no locktime) */
      wtx[wln++]=0x02;                                  /* 2 witness items */
      wtx[wln++]=71; for (int i=0;i<71;i++) wtx[wln++]=0x11;
      wtx[wln++]=33; for (int i=0;i<33;i++) wtx[wln++]=0x22;
      memcpy(wtx+wln, ltx+lln-4, 4); wln += 4;          /* locktime */
      unsigned char wid[32]; memset(wid, 0xA5, 32);
      ck("test pool: put legacy", mpool_put(pool, lid, ltx, lln) == 1);
      ck("test pool: put segwit", mpool_put(pool, wid, wtx, wln) == 1);
      { rpc_mempool_hooks h; memset(&h,0,sizeof h);
        h.mp = pool; h.maxbytes = 8388608; h.count = mpool_count;
        rpc_node_set_mempool(&h); }

      /* ---- gettxspendingprevout (Core lists it under Blockchain; the pool
       * enumeration lives here). LHEX spends outpoint (wire txid
       * 67452301..b1a3, vout 0), so its DISPLAY txid is that reversed. ---- */
      { const char* SPENT_DISP =
            "a3b1c2d4e5f6079889abcdef0123456789abcdef0123456789abcdef01234567";
        char pj[400];
        snprintf(pj, sizeof pj, "[[{\"txid\":\"%s\",\"vout\":0}]]", SPENT_DISP);
        rj_val* p = rj_parse(pj, strlen(pj));
        r = NULL; int rcs = rpc_node_dispatch("gettxspendingprevout", p, &r, &ec, &em);
        ck("gettxspendingprevout -> array", rcs == 1 && r && r->typ == RJ_ARR && r->nitems == 1);
        { rj_val* e0 = (r && r->nitems) ? r->items[0] : 0;
          ck("the outpoint is echoed back", e0 && S(e0,"txid") &&
             !strcmp(S(e0,"txid"), SPENT_DISP) && !strcmp(S(e0,"vout"), "0"));
          /* both pool entries spend it (the segwit tx is the same body), so
             any one of the two txids is a correct answer */
          ck("spendingtxid names a mempool tx that really spends it",
             e0 && S(e0,"spendingtxid") &&
             (!strcmp(S(e0,"spendingtxid"),
                      "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a") ||
              !strcmp(S(e0,"spendingtxid"),
                      "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"))); }
        rj_free(r); rj_free(p);

        /* an unspent outpoint: the ENTRY still appears, with no spendingtxid.
         * Omitting the entry would silently shift the caller's indexes. */
        snprintf(pj, sizeof pj, "[[{\"txid\":\"%s\",\"vout\":7}]]", SPENT_DISP);
        p = rj_parse(pj, strlen(pj));
        r = NULL; rpc_node_dispatch("gettxspendingprevout", p, &r, &ec, &em);
        ck("an unspent outpoint still yields an entry", r && r->nitems == 1);
        ck("...with no spendingtxid",
           r && r->nitems && rj_obj_get(r->items[0], "spendingtxid") == NULL);
        rj_free(r); rj_free(p);

        /* a malformed second entry rejects the WHOLE call, so the caller
         * never gets a partially-answered array it might index by position */
        snprintf(pj, sizeof pj,
                 "[[{\"txid\":\"%s\",\"vout\":0},{\"txid\":\"zz\",\"vout\":0}]]", SPENT_DISP);
        p = rj_parse(pj, strlen(pj));
        r = NULL; ec = 0;
        int rcb = rpc_node_dispatch("gettxspendingprevout", p, &r, &ec, &em);
        ck("a malformed entry rejects the whole list -> -8", rcb == 0 && ec == -8);
        rj_free(r); rj_free(p);

        p = rj_parse("[[]]", 4);
        r = NULL; ec = 0;
        rcb = rpc_node_dispatch("gettxspendingprevout", p, &r, &ec, &em);
        ck("an empty outputs array -> -8 (Core rejects it too)", rcb == 0 && ec == -8);
        rj_free(r); rj_free(p); }

      /* the two node-side Blockchain refusals name what is missing */
      { r = NULL; ec = 0; em = NULL;
        int rcb = rpc_node_dispatch("getmempoolcluster", NULL, &r, &ec, &em);
        ck("getmempoolcluster -> -1 naming the missing cluster structure",
           rcb == 0 && ec == -1 && em && strstr(em, "cluster"));
        rj_free(r);
        r = NULL; ec = 0; em = NULL;
        rcb = rpc_node_dispatch("getblockfrompeer", NULL, &r, &ec, &em);
        ck("getblockfrompeer -> -1 naming the missing worker channel",
           rcb == 0 && ec == -1 && em && strstr(em, "download worker"));
        rj_free(r); }

      r = NULL; rpc_node_dispatch("getrawmempool", NULL, &r, &ec, &em);
      ck("shared pool: getrawmempool has 2 txids", r && r->typ == RJ_ARR && r->nitems == 2);
      int saw_l=0, saw_w=0;
      /* display order = reversed bytes: lid -> 64 x '5a', wid -> 64 x 'a5' */
      for (unsigned long i=0; r && i<r->nitems; i++){
          if (r->items[i]->str && !strncmp(r->items[i]->str,"5a5a",4) && strlen(r->items[i]->str)==64) saw_l=1;
          if (r->items[i]->str && !strncmp(r->items[i]->str,"a5a5",4) && strlen(r->items[i]->str)==64) saw_w=1;
      }
      ck("shared pool: both txids present (display order)", saw_l && saw_w);
      rj_free(r);

      { rj_val* pv = rj_parse("[true]", 6);
        r = NULL; rpc_node_dispatch("getrawmempool", pv, &r, &ec, &em);
        ck("shared pool: verbose -> object of 2", r && r->typ == RJ_OBJ && r->nmembers == 2);
        rj_val* went = r ? rj_obj_get(r, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5") : NULL;
        ck("verbose segwit vsize 113 (weight 449)", went && S(went,"vsize") && !strcmp(S(went,"vsize"),"113")
           && S(went,"weight") && !strcmp(S(went,"weight"),"449"));
        rj_val* lent = r ? rj_obj_get(r, "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a") : NULL;
        ck("verbose legacy vsize == size (85)", lent && S(lent,"vsize") && !strcmp(S(lent,"vsize"),"85")
           && S(lent,"weight") && !strcmp(S(lent,"weight"),"340"));
        rj_free(r); rj_free(pv); }

      r = NULL; rpc_node_dispatch("getmempoolinfo", NULL, &r, &ec, &em);
      ck("shared pool: getmempoolinfo size 2", r && S(r,"size") && !strcmp(S(r,"size"),"2"));
      ck("shared pool: bytes = 85 + 113 = 198 (vsize sum)", r && S(r,"bytes") && !strcmp(S(r,"bytes"),"198"));
      ck("shared pool: maxmempool = injected 8388608", r && S(r,"maxmempool") && !strcmp(S(r,"maxmempool"),"8388608"));
      rj_free(r);

      /* ---- getmempoolentry: drive a REAL parent->child chain through the
       * REAL policy accept path (mpool_policy_add), then assert the graph
       * fields. The resolver stub below supplies prevout values, so fees are
       * genuine policy-computed numbers: parent spends a 100000-sat confirmed
       * prevout -> fee 10000 (one 90000-sat P2WPKH out); child spends the
       * parent's output -> fee 90000 - 80000 = 10000. ---- */
      { extern void mpool_policy_init(void*, unsigned long long, unsigned, unsigned,
                                      unsigned, unsigned, unsigned);
        extern long mpool_policy_add(void*, void*, void*, const unsigned char*,
                                     unsigned long, const unsigned char*, void*);
        extern unsigned long mpool_policy_state_size(unsigned long);
        extern void mpool_policy_state_init(void*, unsigned long);
        extern long mpool_policy_entry_info(void*, const unsigned char*, struct mp_entry_info*);
        extern const unsigned char* mpool_get(void*, const unsigned char*, unsigned long*);
        extern int tx_txid(unsigned char*, const unsigned char*, unsigned long,
                           unsigned char*, unsigned long);
        static unsigned char polcfg[128];
        static unsigned char polstate[1<<22];
        mpool_policy_init(polcfg, 1000 /* sat/kvB: 1 sat/vB, as before */, 25, 101000, 25, 101000, 1);
        if (mpool_policy_state_size(4096) > sizeof polstate){ ck("polstate fits", 0); }
        mpool_policy_state_init(polstate, 4096);

        /* parent: spends confirmed prevout 0x33..33:0, one 90000-sat P2WPKH out */
        static unsigned char ptx[200]; unsigned long pln=0;
        ptx[pln++]=2;ptx[pln++]=0;ptx[pln++]=0;ptx[pln++]=0;         /* version */
        ptx[pln++]=1;                                                 /* 1 in */
        for(int i=0;i<32;i++) ptx[pln++]=0x33;                        /* prev txid */
        ptx[pln++]=0;ptx[pln++]=0;ptx[pln++]=0;ptx[pln++]=0;          /* vout 0 */
        ptx[pln++]=0;                                                 /* scriptsig */
        ptx[pln++]=0xfd;ptx[pln++]=0xff;ptx[pln++]=0xff;ptx[pln++]=0xff;
        ptx[pln++]=1;                                                 /* 1 out */
        unsigned long long pv=90000; for(int i=0;i<8;i++) ptx[pln++]=(unsigned char)(pv>>(8*i));
        ptx[pln++]=22; ptx[pln++]=0x00; ptx[pln++]=0x14; for(int i=0;i<20;i++) ptx[pln++]=0x44;
        ptx[pln++]=0;ptx[pln++]=0;ptx[pln++]=0;ptx[pln++]=0;          /* locktime */
        unsigned char pid[32]; static unsigned char scratch[4096];
        ck("parent txid computed", tx_txid(pid, ptx, pln, scratch, sizeof scratch)==1);
        ck("policy add parent", mpool_policy_add(polcfg, polstate, pool, ptx, pln, pid, (void*)1)==1);

        /* child: spends parent:0, one 80000-sat out */
        static unsigned char ctx[200]; unsigned long cln=0;
        ctx[cln++]=2;ctx[cln++]=0;ctx[cln++]=0;ctx[cln++]=0;
        ctx[cln++]=1;
        for(int i=0;i<32;i++) ctx[cln++]=pid[i];
        ctx[cln++]=0;ctx[cln++]=0;ctx[cln++]=0;ctx[cln++]=0;
        ctx[cln++]=0;
        ctx[cln++]=0xfd;ctx[cln++]=0xff;ctx[cln++]=0xff;ctx[cln++]=0xff;
        ctx[cln++]=1;
        unsigned long long cv=80000; for(int i=0;i<8;i++) ctx[cln++]=(unsigned char)(cv>>(8*i));
        ctx[cln++]=22; ctx[cln++]=0x00; ctx[cln++]=0x14; for(int i=0;i<20;i++) ctx[cln++]=0x55;
        ctx[cln++]=0;ctx[cln++]=0;ctx[cln++]=0;ctx[cln++]=0;
        unsigned char cid[32];
        ck("child txid computed", tx_txid(cid, ctx, cln, scratch, sizeof scratch)==1);
        ck("policy add child", mpool_policy_add(polcfg, polstate, pool, ctx, cln, cid, (void*)1)==1);

        { rpc_mempool_hooks h; memset(&h,0,sizeof h);
          h.mp = pool; h.maxbytes = 8388608; h.count = mpool_count;
          h.get = mpool_get; h.polstate = polstate;
          h.pol_entry_info = mpool_policy_entry_info;
          rpc_node_set_mempool(&h); }

        char pidhex[65]; static const char* HD="0123456789abcdef";
        for (int k=0;k<32;k++){ unsigned char b=pid[31-k]; pidhex[k*2]=HD[b>>4]; pidhex[k*2+1]=HD[b&15]; }
        pidhex[64]=0;
        char cidhex[65];
        for (int k=0;k<32;k++){ unsigned char b=cid[31-k]; cidhex[k*2]=HD[b>>4]; cidhex[k*2+1]=HD[b&15]; }
        cidhex[64]=0;

        char pj[128]; snprintf(pj,sizeof pj,"[\"%s\"]",pidhex);
        rj_val* pp=rj_parse(pj,strlen(pj)); r=NULL;
        rc = rpc_node_dispatch("getmempoolentry", pp, &r, &ec, &em);
        ck("entry(parent) dispatched", rc==1 && r!=NULL);
        ck("entry(parent) fees.base 0.00010000",
           r && rj_obj_get(r,"fees") && S(rj_obj_get(r,"fees"),"base") && !strcmp(S(rj_obj_get(r,"fees"),"base"),"0.00010000"));
        ck("entry(parent) descendantcount 2 (self+child)",
           r && S(r,"descendantcount") && !strcmp(S(r,"descendantcount"),"2"));
        ck("entry(parent) ancestorcount 1",
           r && S(r,"ancestorcount") && !strcmp(S(r,"ancestorcount"),"1"));
        ck("entry(parent) fees.descendant 0.00020000 (both fees)",
           r && rj_obj_get(r,"fees") && S(rj_obj_get(r,"fees"),"descendant") && !strcmp(S(rj_obj_get(r,"fees"),"descendant"),"0.00020000"));
        { rj_val* sb = r?rj_obj_get(r,"spentby"):NULL;
          ck("entry(parent) spentby [child]", sb && sb->typ==RJ_ARR && sb->nitems==1
             && sb->items[0]->str && !strcmp(sb->items[0]->str,cidhex)); }
        { rj_val* dp = r?rj_obj_get(r,"depends"):NULL;
          ck("entry(parent) depends []", dp && dp->typ==RJ_ARR && dp->nitems==0); }
        ck("entry(parent) wtxid==txid (legacy, sha256d not injected)",
           r && S(r,"wtxid") && !strcmp(S(r,"wtxid"),pidhex));
        ck("entry(parent) vsize == 82 (legacy: size==vsize)", r && S(r,"vsize") && !strcmp(S(r,"vsize"),"82"));
        rj_free(r); rj_free(pp);

        snprintf(pj,sizeof pj,"[\"%s\"]",cidhex);
        pp=rj_parse(pj,strlen(pj)); r=NULL;
        rc = rpc_node_dispatch("getmempoolentry", pp, &r, &ec, &em);
        ck("entry(child) ancestorcount 2 / descendantcount 1",
           rc==1 && r && S(r,"ancestorcount") && !strcmp(S(r,"ancestorcount"),"2")
           && S(r,"descendantcount") && !strcmp(S(r,"descendantcount"),"1"));
        ck("entry(child) fees.ancestor 0.00020000",
           r && rj_obj_get(r,"fees") && S(rj_obj_get(r,"fees"),"ancestor") && !strcmp(S(rj_obj_get(r,"fees"),"ancestor"),"0.00020000"));
        { rj_val* dp = r?rj_obj_get(r,"depends"):NULL;
          ck("entry(child) depends [parent]", dp && dp->typ==RJ_ARR && dp->nitems==1
             && dp->items[0]->str && !strcmp(dp->items[0]->str,pidhex)); }
        rj_free(r); rj_free(pp);

        /* ---- getmempoolancestors / getmempooldescendants: EXCLUDING self
         * (oracle-verified), non-verbose arrays + verbose entry objects ---- */
        { char aj[128]; snprintf(aj,sizeof aj,"[\"%s\"]",pidhex);
          rj_val* ap=rj_parse(aj,strlen(aj)); r=NULL;
          rc=rpc_node_dispatch("getmempoolancestors",ap,&r,&ec,&em);
          ck("ancestors(parent) -> []", rc==1 && r && r->typ==RJ_ARR && r->nitems==0);
          rj_free(r); rj_free(ap);
          snprintf(aj,sizeof aj,"[\"%s\"]",cidhex);
          ap=rj_parse(aj,strlen(aj)); r=NULL;
          rc=rpc_node_dispatch("getmempoolancestors",ap,&r,&ec,&em);
          ck("ancestors(child) -> [parent]", rc==1 && r && r->typ==RJ_ARR && r->nitems==1
             && r->items[0]->str && !strcmp(r->items[0]->str,pidhex));
          rj_free(r); rj_free(ap);
          snprintf(aj,sizeof aj,"[\"%s\"]",pidhex);
          ap=rj_parse(aj,strlen(aj)); r=NULL;
          rc=rpc_node_dispatch("getmempooldescendants",ap,&r,&ec,&em);
          ck("descendants(parent) -> [child]", rc==1 && r && r->typ==RJ_ARR && r->nitems==1
             && r->items[0]->str && !strcmp(r->items[0]->str,cidhex));
          rj_free(r); rj_free(ap);
          snprintf(aj,sizeof aj,"[\"%s\"]",cidhex);
          ap=rj_parse(aj,strlen(aj)); r=NULL;
          rc=rpc_node_dispatch("getmempooldescendants",ap,&r,&ec,&em);
          ck("descendants(child) -> []", rc==1 && r && r->typ==RJ_ARR && r->nitems==0);
          rj_free(r); rj_free(ap);
          /* verbose: entry-shaped member objects */
          snprintf(aj,sizeof aj,"[\"%s\", true]",cidhex);
          ap=rj_parse(aj,strlen(aj)); r=NULL;
          rc=rpc_node_dispatch("getmempoolancestors",ap,&r,&ec,&em);
          ck("ancestors(child,true) -> {parent: entry}", rc==1 && r && r->typ==RJ_OBJ && r->nmembers==1);
          { rj_val* pe = r?rj_obj_get(r,pidhex):NULL;
            ck("verbose ancestor entry has fees.base + descendantcount 2",
               pe && rj_obj_get(pe,"fees") && S(rj_obj_get(pe,"fees"),"base")
               && !strcmp(S(rj_obj_get(pe,"fees"),"base"),"0.00010000")
               && S(pe,"descendantcount") && !strcmp(S(pe,"descendantcount"),"2")); }
          rj_free(r); rj_free(ap);
          /* -5 miss parity */
          ap=rj_parse("[\"0000000000000000000000000000000000000000000000000000000000000001\"]",68);
          r=NULL; long e5; const char* m5;
          rc=rpc_node_dispatch("getmempoolancestors",ap,&r,&e5,&m5);
          ck("ancestors miss -> -5", rc==0 && e5==-5 && m5 && !strcmp(m5,"Transaction not in mempool"));
          rj_free(r); rj_free(ap); }

        /* ---- estimatesmartfee / estimaterawfee: Core rpc/fees.cpp over the
         * CBlockPolicyEstimator port (daemon/fee_estimator.c). Without an
         * estimator the answer is a fresh Core's: "Insufficient data", blocks
         * 0. With one fed Core's own policyestimator_tests scenario, the
         * JSON carries Core's field names and the target semantics. ---- */
        { { rpc_mempool_hooks h; memset(&h,0,sizeof h);
            h.mp = pool; h.maxbytes = 8388608; h.count = mpool_count;
            h.get = mpool_get; h.polstate = polstate;
            h.pol_entry_info = mpool_policy_entry_info;
            rpc_node_set_mempool(&h); }
          rj_val* fp=rj_parse("[6]",3); r=NULL;
          rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&ec,&em);
          { rj_val* errs = r?rj_obj_get(r,"errors"):NULL;
            ck("esf(6) without an estimator -> errors[Insufficient data...], blocks 0 (fresh Core)", rc==1 && errs && errs->typ==RJ_ARR
               && errs->nitems==1 && errs->items[0]->str && !strcmp(errs->items[0]->str,"Insufficient data or no feerate found")
               && S(r,"blocks") && !strcmp(S(r,"blocks"),"0") && rj_obj_get(r,"feerate")==NULL); }
          rj_free(r); rj_free(fp);
          /* argument errors, Core-exact */
          fp=rj_parse("[0]",3); r=NULL; long e8; const char* m8;
          rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&e8,&m8);
          ck("esf(0) -> -8 conf_target range", rc==0 && e8==-8 && m8 && !strcmp(m8,"Invalid conf_target, must be between 1 and 1008"));
          rj_free(r); rj_free(fp);
          fp=rj_parse("[1009]",6); r=NULL;
          rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&e8,&m8);
          ck("esf(1009) -> -8", rc==0 && e8==-8);
          rj_free(r); rj_free(fp);
          fp=rj_parse("[\"6\"]",5); r=NULL;
          rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&e8,&m8);
          ck("esf(\"6\") -> -3 type error", rc==0 && e8==-3 && m8 && !strcmp(m8,"JSON value of type string is not of expected type number"));
          rj_free(r); rj_free(fp);
          fp=rj_parse("[6, \"bogus\"]",12); r=NULL;
          rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&e8,&m8);
          ck("esf bad mode -> -8 Core message", rc==0 && e8==-8 && m8 && strstr(m8,"Invalid estimate_mode parameter"));
          rj_free(r); rj_free(fp);

          /* a real estimator, fed Core's test scenario (10 feerates x 4 txs per
           * block, the j-th feerate confirming after j+1 blocks) for 60 blocks */
          { extern unsigned long fest_state_size(unsigned long); extern int fest_init(void*, unsigned long);
            extern void fest_process_transaction(void*, const unsigned char*, unsigned long long, unsigned long long, unsigned, int);
            extern int fest_block_begin(void*, unsigned); extern int fest_block_tx(void*, const unsigned char*); extern void fest_block_end(void*);
            static unsigned char festbuf[1<<20]; void* fe = malloc(fest_state_size(4096)); fest_init(fe, 4096); (void)festbuf;
            static unsigned char pend[10][2048][32]; static int np[10]; memset(np,0,sizeof np);
            for (unsigned bn = 0; bn < 60; bn++){
                for (int j=0;j<10;j++) for (int k=0;k<4;k++){ unsigned char t[32]; memset(t,0,32); t[0]=(unsigned char)bn; t[1]=(unsigned char)(bn>>8); t[2]=(unsigned char)j; t[3]=(unsigned char)k; t[31]=0x55;
                    fest_process_transaction(fe, t, 2000ULL*(j+1), 188, bn, 1); memcpy(pend[j][np[j]++], t, 32); }
                fest_block_begin(fe, bn+1);
                for (unsigned h2=0; h2<=bn%10; h2++){ int j=9-(int)h2; while (np[j]) fest_block_tx(fe, pend[j][--np[j]]); }
                fest_block_end(fe);
            }
            { extern long mpool_policy_entry_info(void*, const unsigned char*, struct mp_entry_info*);
              rpc_mempool_hooks h; memset(&h,0,sizeof h);
              h.mp = pool; h.maxbytes = 8388608; h.count = mpool_count; h.get = mpool_get; h.polstate = polstate;
              h.pol_entry_info = mpool_policy_entry_info; h.feeest = fe; h.min_relay_satkvb = 100;
              rpc_node_set_mempool(&h); }
            fp=rj_parse("[6]",3); r=NULL;
            rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&ec,&em);
            ck("esf(6) with data: feerate + blocks 6, no errors", rc==1 && r && S(r,"feerate") && S(r,"blocks") && !strcmp(S(r,"blocks"),"6") && rj_obj_get(r,"errors")==NULL);
            if (r && S(r,"feerate")) printf("  (esf(6) = %s BTC/kvB)\n", S(r,"feerate"));
            rj_free(r); rj_free(fp);
            fp=rj_parse("[1]",3); r=NULL;
            rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&ec,&em);
            ck("esf(1) -> blocks 2 (Core clamps 1 to 2)", rc==1 && r && S(r,"blocks") && !strcmp(S(r,"blocks"),"2"));
            rj_free(r); rj_free(fp);
            fp=rj_parse("[6, \"ECONOMICAL\"]",17); r=NULL;
            rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&ec,&em);
            ck("esf ECONOMICAL accepted (case-insensitive)", rc==1 && r && S(r,"feerate"));
            rj_free(r); rj_free(fp);
            { rj_val* a=rj_parse("[6, \"economical\"]",17); rj_val* c=rj_parse("[6, \"conservative\"]",19); rj_val *ra=NULL,*rc2=NULL;
              rpc_node_dispatch("estimatesmartfee",a,&ra,&ec,&em); rpc_node_dispatch("estimatesmartfee",c,&rc2,&ec,&em);
              ck("conservative feerate >= economical", ra && rc2 && S(ra,"feerate") && S(rc2,"feerate") && strcmp(S(rc2,"feerate"),S(ra,"feerate"))>=0);
              rj_free(ra); rj_free(rc2); rj_free(a); rj_free(c); }
            /* estimaterawfee: Core's per-horizon shape */
            fp=rj_parse("[6]",3); r=NULL;
            rc=rpc_node_dispatch("estimaterawfee",fp,&r,&ec,&em);
            { rj_val *sh=r?rj_obj_get(r,"short"):0, *md=r?rj_obj_get(r,"medium"):0, *lg=r?rj_obj_get(r,"long"):0;
              ck("erf(6): short/medium/long objects", rc==1 && sh && md && lg);
              ck("erf(6).medium: feerate, decay 0.9952, scale 2, pass bucket with Core's six fields", md && S(md,"feerate") && S(md,"decay") && !strcmp(S(md,"decay"),"0.9952")
                 && S(md,"scale") && !strcmp(S(md,"scale"),"2") && rj_obj_get(md,"pass") && S(rj_obj_get(md,"pass"),"startrange") && S(rj_obj_get(md,"pass"),"endrange")
                 && S(rj_obj_get(md,"pass"),"withintarget") && S(rj_obj_get(md,"pass"),"totalconfirmed") && S(rj_obj_get(md,"pass"),"inmempool") && S(rj_obj_get(md,"pass"),"leftmempool"));
              ck("erf(6).short: decay 0.962 scale 1; long: decay 0.99931 scale 24", sh && S(sh,"decay") && !strcmp(S(sh,"decay"),"0.962") && S(sh,"scale") && !strcmp(S(sh,"scale"),"1")
                 && lg && S(lg,"decay") && !strcmp(S(lg,"decay"),"0.99931") && S(lg,"scale") && !strcmp(S(lg,"scale"),"24"));
              if (md && rj_obj_get(md,"pass")) printf("  (erf(6).medium pass %s..%s within %s of %s)\n", S(rj_obj_get(md,"pass"),"startrange"), S(rj_obj_get(md,"pass"),"endrange"), S(rj_obj_get(md,"pass"),"withintarget"), S(rj_obj_get(md,"pass"),"totalconfirmed")); }
            rj_free(r); rj_free(fp);
            fp=rj_parse("[13]",4); r=NULL;
            rc=rpc_node_dispatch("estimaterawfee",fp,&r,&ec,&em);
            ck("erf(13): no short horizon (tracks 12), medium + long present", rc==1 && r && !rj_obj_get(r,"short") && rj_obj_get(r,"medium") && rj_obj_get(r,"long"));
            rj_free(r); rj_free(fp);
            fp=rj_parse("[49]",4); r=NULL;
            rc=rpc_node_dispatch("estimaterawfee",fp,&r,&ec,&em);
            ck("erf(49): only long", rc==1 && r && !rj_obj_get(r,"short") && !rj_obj_get(r,"medium") && rj_obj_get(r,"long"));
            rj_free(r); rj_free(fp);
            fp=rj_parse("[6, 1.5]",8); r=NULL;
            rc=rpc_node_dispatch("estimaterawfee",fp,&r,&e8,&m8);
            ck("erf threshold 1.5 -> -8 Invalid threshold", rc==0 && e8==-8 && m8 && !strcmp(m8,"Invalid threshold"));
            rj_free(r); rj_free(fp);
            fp=rj_parse("[6, \"x\"]",8); r=NULL;
            rc=rpc_node_dispatch("estimaterawfee",fp,&r,&e8,&m8);
            ck("erf non-numeric threshold -> -3", rc==0 && e8==-3);
            rj_free(r); rj_free(fp);
            /* Core prints the INF bucket bound as 1e+99 (UniValue setprecision(16)).
             * Park 8 unconfirmed txs in the INF bucket (>= 1e7 sat/kvB) for one block:
             * at target 1 the top range then fails (0 of them confirmed) and the fail
             * range's end is the INF bound. */
            for (int k=0;k<8;k++){ unsigned char t[32]; memset(t,0x99,32); t[0]=(unsigned char)k; fest_process_transaction(fe, t, 2000000000ULL, 100, 60, 1); }
            fest_block_begin(fe, 61); fest_block_end(fe);
            fp=rj_parse("[1, 1.0]",8); r=NULL;
            rc=rpc_node_dispatch("estimaterawfee",fp,&r,&ec,&em);
            { rj_val* sh=r?rj_obj_get(r,"short"):0; rj_val* fl=sh?rj_obj_get(sh,"fail"):0;
              ck("erf(1, 1.0).short.fail.endrange prints 1e+99 like Core", fl && S(fl,"endrange") && !strcmp(S(fl,"endrange"),"1e+99"));
              if (fl) printf("  (erf(1,1.0).short.fail = %s..%s)\n", S(fl,"startrange"), S(fl,"endrange")); }
            rj_free(r); rj_free(fp);
            fp=rj_parse("[2, 0.5]",8); r=NULL;
            rc=rpc_node_dispatch("estimaterawfee",fp,&r,&ec,&em);
            ck("erf(2, 0.5) answers on all three horizons", rc==1 && r && rj_obj_get(r,"short") && rj_obj_get(r,"medium") && rj_obj_get(r,"long"));
            rj_free(r); rj_free(fp);
            free(fe); }
          /* restore the populated hooks for any later checks */
          { extern long mpool_policy_entry(void*, const unsigned char*,
                                           unsigned long long*, unsigned long long*);
            rpc_mempool_hooks h; memset(&h,0,sizeof h);
            h.mp = pool; h.maxbytes = 8388608; h.count = mpool_count;
            h.get = mpool_get; h.polstate = polstate;
            h.pol_entry = mpool_policy_entry;
            h.pol_entry_info = mpool_policy_entry_info;
            rpc_node_set_mempool(&h); } }

        /* ---- verbose getrawmempool carries the SAME per-entry object as
         * getmempoolentry (2026-09-11).
         *
         * It used to carry four fields -- vsize, weight, time, fees.base --
         * because it was landed as a first slice whose comment said the
         * aggregates would come with getmempoolentry. They did, and nobody
         * widened the bulk call, so a consumer wanting CPFP clusters over the
         * whole pool had to issue one getmempoolentry per transaction against
         * an RPC server that handles one request at a time.
         *
         * Two properties are pinned here. The graph must be PRESENT, and the
         * bulk answer must AGREE with the per-txid answer -- they are now
         * computed by different code (a one-pass graph build vs. the original
         * per-entry scans), and a fast path that disagrees with the slow one
         * is worse than no fast path. ---- */
        for (int bulk_on = 0; bulk_on < 2; bulk_on++){
          /* run every assertion below through BOTH paths: the one-pass graph
           * build (bulk_on) and the original per-txid scans. They are separate
           * code, and the fast one exists only if it agrees with the slow one.
           * The first cut of the fast path made the per-txid branch
           * conditional on there being no cache, so a node without
           * pol_entry_info_all got an entry with NO graph at all. */
          { extern long mpool_policy_entry(void*, const unsigned char*,
                                           unsigned long long*, unsigned long long*);
            extern long mpool_policy_entry_info_all(void*, struct mp_entry_info*,
                                                    unsigned char (*)[32], unsigned);
            rpc_mempool_hooks h; memset(&h,0,sizeof h);
            h.mp = pool; h.maxbytes = 8388608; h.count = mpool_count;
            h.get = mpool_get; h.polstate = polstate;
            h.pol_entry = mpool_policy_entry;
            h.pol_entry_info = mpool_policy_entry_info;
            if (bulk_on) h.pol_entry_info_all = mpool_policy_entry_info_all;
            rpc_node_set_mempool(&h); }
          printf("  (graph path: %s)\n", bulk_on ? "one-pass bulk" : "per-txid fallback");
          rj_val* pv2 = rj_parse("[true]", 6); r = NULL;
          rc = rpc_node_dispatch("getrawmempool", pv2, &r, &ec, &em);
          ck("getrawmempool true -> an object with the pool in it", rc==1 && r && r->typ==RJ_OBJ && r->nmembers >= 2);
          rj_val* pe = r ? rj_obj_get(r, pidhex) : NULL;
          rj_val* ce = r ? rj_obj_get(r, cidhex) : NULL;
          ck("the parent entry is present", pe != NULL);
          ck("the child entry is present", ce != NULL);
          ck("child carries depends -> its parent (CPFP clusters buildable from ONE call)",
             ce && rj_obj_get(ce,"depends") && rj_obj_get(ce,"depends")->typ==RJ_ARR
             && rj_obj_get(ce,"depends")->nitems==1
             && rj_obj_get(ce,"depends")->items[0]->str
             && !strcmp(rj_obj_get(ce,"depends")->items[0]->str, pidhex));
          ck("parent carries spentby -> its child",
             pe && rj_obj_get(pe,"spentby") && rj_obj_get(pe,"spentby")->typ==RJ_ARR
             && rj_obj_get(pe,"spentby")->nitems==1
             && rj_obj_get(pe,"spentby")->items[0]->str
             && !strcmp(rj_obj_get(pe,"spentby")->items[0]->str, cidhex));
          ck("child ancestorcount counts itself and the parent (2)",
             ce && S(ce,"ancestorcount") && !strcmp(S(ce,"ancestorcount"),"2"));
          ck("parent descendantcount counts itself and the child (2)",
             pe && S(pe,"descendantcount") && !strcmp(S(pe,"descendantcount"),"2"));
          { const char* FIELDS[] = {"vsize","weight","height","ancestorcount","ancestorsize",
                                    "descendantcount","descendantsize","wtxid"};
            int agree = 1;
            const char* who[2] = { pidhex, cidhex };
            for (int q=0;q<2;q++){
                char one[128]; snprintf(one,sizeof one,"[\"%s\"]",who[q]);
                rj_val* op = rj_parse(one, strlen(one)); rj_val* o1 = NULL;
                if (rpc_node_dispatch("getmempoolentry", op, &o1, &ec, &em) == 1 && o1){
                    rj_val* bulk = rj_obj_get(r, who[q]);
                    for (unsigned f=0; f<sizeof FIELDS/sizeof *FIELDS; f++){
                        const char* a = bulk ? S(bulk, FIELDS[f]) : NULL;
                        const char* b = S(o1, FIELDS[f]);
                        if (!a || !b || strcmp(a,b)){ agree = 0;
                            printf("  (disagree on %s: bulk=%s single=%s)\n", FIELDS[f], a?a:"(none)", b?b:"(none)"); }
                    }
                }
                rj_free(o1); rj_free(op);
            }
            ck("bulk getrawmempool agrees with getmempoolentry field for field", agree); }
          rj_free(r); rj_free(pv2); }

        /* ---- prioritisetransaction / getprioritisedtransactions: deltas
         * accumulate, zero-sum entries erased, fees.modified = base + delta,
         * companion shows modified_fee (sats) only when in mempool -- all
         * oracle-verified semantics. Uses the real chain's parent tx
         * (base fee 10000 sat). ---- */
        { char pj2[160];
          snprintf(pj2,sizeof pj2,"[\"%s\", 0, 1000]",pidhex);
          rj_val* pp2=rj_parse(pj2,strlen(pj2)); r=NULL;
          rc=rpc_node_dispatch("prioritisetransaction",pp2,&r,&ec,&em);
          ck("pritx(+1000) -> true", rc==1 && r && r->typ==RJ_BOOL && r->str[0]=='1');
          rj_free(r); rj_free(pp2);
          /* fees.modified reflects the delta */
          snprintf(pj2,sizeof pj2,"[\"%s\"]",pidhex);
          pp2=rj_parse(pj2,strlen(pj2)); r=NULL;
          rpc_node_dispatch("getmempoolentry",pp2,&r,&ec,&em);
          ck("entry fees.modified = 0.00011000 (base+delta)",
             r && rj_obj_get(r,"fees") && S(rj_obj_get(r,"fees"),"modified")
             && !strcmp(S(rj_obj_get(r,"fees"),"modified"),"0.00011000"));
          ck("entry fees.base unchanged 0.00010000",
             r && rj_obj_get(r,"fees") && S(rj_obj_get(r,"fees"),"base")
             && !strcmp(S(rj_obj_get(r,"fees"),"base"),"0.00010000"));
          rj_free(r); rj_free(pp2);
          /* companion: in-mempool entry carries modified_fee in sats */
          r=NULL; rpc_node_dispatch("getprioritisedtransactions",NULL,&r,&ec,&em);
          { rj_val* e = r?rj_obj_get(r,pidhex):NULL;
            ck("gpt entry {fee_delta:1000,in_mempool:true,modified_fee:11000}",
               e && S(e,"fee_delta") && !strcmp(S(e,"fee_delta"),"1000")
               && rj_obj_get(e,"in_mempool") && rj_obj_get(e,"in_mempool")->str[0]=='1'
               && S(e,"modified_fee") && !strcmp(S(e,"modified_fee"),"11000")); }
          rj_free(r);
          /* accumulate: +500 -> 1500 */
          snprintf(pj2,sizeof pj2,"[\"%s\", 0, 500]",pidhex);
          pp2=rj_parse(pj2,strlen(pj2)); r=NULL;
          rpc_node_dispatch("prioritisetransaction",pp2,&r,&ec,&em); rj_free(r); rj_free(pp2);
          r=NULL; rpc_node_dispatch("getprioritisedtransactions",NULL,&r,&ec,&em);
          { rj_val* e = r?rj_obj_get(r,pidhex):NULL;
            ck("gpt deltas ACCUMULATE (1500)", e && S(e,"fee_delta") && !strcmp(S(e,"fee_delta"),"1500")); }
          rj_free(r);
          /* not-in-mempool txid accepted; shows in_mempool:false, no modified_fee */
          pp2=rj_parse("[\"0000000000000000000000000000000000000000000000000000000000000002\", 0, 250]",76);
          r=NULL; rc=rpc_node_dispatch("prioritisetransaction",pp2,&r,&ec,&em);
          ck("pritx not-in-mempool accepted -> true", rc==1 && r && r->typ==RJ_BOOL);
          rj_free(r); rj_free(pp2);
          r=NULL; rpc_node_dispatch("getprioritisedtransactions",NULL,&r,&ec,&em);
          { rj_val* e = r?rj_obj_get(r,"0000000000000000000000000000000000000000000000000000000000000002"):NULL;
            ck("gpt absent tx: in_mempool false, no modified_fee",
               e && rj_obj_get(e,"in_mempool") && rj_obj_get(e,"in_mempool")->str[0]=='0'
               && rj_obj_get(e,"modified_fee")==NULL); }
          rj_free(r);
          /* zero-sum erasure: -1500 removes the parent's entry */
          snprintf(pj2,sizeof pj2,"[\"%s\", 0, -1500]",pidhex);
          pp2=rj_parse(pj2,strlen(pj2)); r=NULL;
          rpc_node_dispatch("prioritisetransaction",pp2,&r,&ec,&em); rj_free(r); rj_free(pp2);
          r=NULL; rpc_node_dispatch("getprioritisedtransactions",NULL,&r,&ec,&em);
          ck("gpt zero-sum entry ERASED", r && rj_obj_get(r,pidhex)==NULL);
          rj_free(r);
          /* dummy != 0 -> Core-exact -8 */
          snprintf(pj2,sizeof pj2,"[\"%s\", 1.5, 100]",pidhex);
          pp2=rj_parse(pj2,strlen(pj2)); r=NULL; long e8p; const char* m8p;
          rc=rpc_node_dispatch("prioritisetransaction",pp2,&r,&e8p,&m8p);
          ck("pritx dummy!=0 -> -8 Core message", rc==0 && e8p==-8 && m8p
             && strstr(m8p,"Priority is no longer supported"));
          rj_free(r); rj_free(pp2);
          /* bad txid -> shared Core-exact -8 */
          { const char* bj="[\"deadbeef\", 0, 100]"; pp2=rj_parse(bj,strlen(bj)); } r=NULL;
          rc=rpc_node_dispatch("prioritisetransaction",pp2,&r,&e8p,&m8p);
          ck("pritx bad txid -> -8", rc==0 && e8p==-8 && m8p && strstr(m8p,"not 8, for 'deadbeef'"));
          rj_free(r); rj_free(pp2);
          /* leave the map clean for later checks */
          pp2=rj_parse("[\"0000000000000000000000000000000000000000000000000000000000000002\", 0, -250]",77);
          r=NULL; rpc_node_dispatch("prioritisetransaction",pp2,&r,&ec,&em); rj_free(r); rj_free(pp2); }

        /* error parity: -5 not in mempool; -8 bad txid with Core's message */
        { rj_val* p5=rj_parse("[\"0000000000000000000000000000000000000000000000000000000000000001\"]",68);
          r=NULL; long e5; const char* m5; rc=rpc_node_dispatch("getmempoolentry",p5,&r,&e5,&m5);
          ck("entry miss -> -5 Transaction not in mempool", rc==0 && e5==-5 && m5 && !strcmp(m5,"Transaction not in mempool"));
          rj_free(r); rj_free(p5); }
        { rj_val* p8=rj_parse("[\"deadbeef\"]",12);
          r=NULL; long e8; const char* m8; rc=rpc_node_dispatch("getmempoolentry",p8,&r,&e8,&m8);
          ck("entry bad txid -> -8 Core message", rc==0 && e8==-8 && m8 && strstr(m8,"txid must be of length 64 (not 8, for 'deadbeef')"));
          rj_free(r); rj_free(p8); }
      }

      /* detach again so the empty-pool checks stay valid for later runs */
      rpc_node_set_mempool(NULL); }

    /* ---- submitblock: decode errors parent-side; the staging handshake
     * against a fake worker thread that acks with a BIP22 string (the real
     * worker half -- daemon/blk_submit.c -- has its own test on the actual
     * genesis block). ---- */
    { rpc_node_set_status_rw(&st);
      /* decode errors never reach the channel */
      const char* j1="[\"abc\"]"; rj_val* p8=rj_parse(j1,strlen(j1)); r=NULL; long eb; const char* mb;
      int rcb=rpc_node_dispatch("submitblock",p8,&r,&eb,&mb);
      ck("submitblock odd hex -> -22 Block decode failed", rcb==0 && eb==-22 && mb && !strcmp(mb,"Block decode failed"));
      rj_free(r); rj_free(p8);
      { const char* j2="[\"zz\"]"; p8=rj_parse(j2,strlen(j2)); } r=NULL;
      rcb=rpc_node_dispatch("submitblock",p8,&r,&eb,&mb);
      ck("submitblock short/bad -> -22", rcb==0 && eb==-22);
      rj_free(r); rj_free(p8);
      /* handshake: fake worker acks "duplicate" (fake_worker at file scope) */
      { pthread_t th; pthread_create(&th, 0, fake_worker, &st);
        /* 162 zero bytes >= the 81-byte floor */
        static char big[162*2+16]; memset(big,'0',162*2);
        char pj3[400]; snprintf(pj3,sizeof pj3,"[\"%.*s\"]",162*2,big);
        rj_val* pb=rj_parse(pj3,strlen(pj3)); r=NULL;
        rcb=rpc_node_dispatch("submitblock",pb,&r,&eb,&mb);
        pthread_join(th,0);
        ck("fake worker saw staged 162 bytes", g_fw_len_ok==1);
        ck("submitblock round-trip -> BIP22 string from worker",
           rcb==1 && r && r->typ==RJ_STR && !strcmp(r->str,"duplicate"));
        rj_free(r); rj_free(pb); }
      rpc_node_set_status_rw(NULL); }

    /* ---- network / ops 12, shaped against the Core oracle (2026-08-25).
     * The peer table was reset at line 117, so re-stage it here: two LIVE
     * slots carrying counters, plus a NON-live slot whose bytes must NOT be
     * counted -- that is the whole point of gating the sum on `used`. ---- */
    memset(st.peers, 0, sizeof st.peers);
    st.peers[0].used = 1; st.peers[0].bytes_sent = 4096;  st.peers[0].bytes_recv = 1048576;
    st.peers[3].used = 1; st.peers[3].bytes_sent = 900;   st.peers[3].bytes_recv = 24;
    st.peers[7].used = 0; st.peers[7].bytes_sent = 1<<20; st.peers[7].bytes_recv = 1<<20;
    { r = NULL; rc = rpc_node_dispatch("getnettotals", NULL, &r, &ec, &em);
      ck("getnettotals dispatched", rc == 1 && r && r->typ == RJ_OBJ);
      ck("totalbytessent sums the LIVE peers only (4096+900, not the dead slot)",
         S(r,"totalbytessent") && !strcmp(S(r,"totalbytessent"), "4996"));
      ck("totalbytesrecv sums the LIVE peers only",
         S(r,"totalbytesrecv") && !strcmp(S(r,"totalbytesrecv"), "1048600"));
      ck("getnettotals has timemillis", rj_obj_get(r,"timemillis") != NULL);
      { rj_val* up = rj_obj_get(r,"uploadtarget");
        ck("uploadtarget object present", up && up->typ == RJ_OBJ);
        /* Core's six sub-fields, in Core's order */
        static const char* UT[] = {"timeframe","target","target_reached",
                                   "serve_historical_blocks","bytes_left_in_cycle",
                                   "time_left_in_cycle"};
        int all = up != NULL;
        for (int i = 0; up && i < 6; i++) if (!rj_obj_get(up, UT[i])) all = 0;
        ck("uploadtarget carries all six Core fields", all); }
      rj_free(r); }

    /* no book injected yet -> honestly empty, never a fabricated peer */
    { r = NULL; rc = rpc_node_dispatch("getnodeaddresses", NULL, &r, &ec, &em);
      ck("getnodeaddresses with no book -> empty array",
         rc == 1 && r && r->typ == RJ_ARR && r->nitems == 0);
      rj_free(r);
      r = NULL; rc = rpc_node_dispatch("getaddrmaninfo", NULL, &r, &ec, &em);
      ck("getaddrmaninfo with no book -> zeros",
         rc == 1 && r && rj_obj_get(r,"ipv4") &&
         !strcmp(S(rj_obj_get(r,"ipv4"),"total"), "0"));
      rj_free(r); }

    fake_ab_init(); rpc_node_set_addrbook((void*)FAKE_AB, fake_ab_count, fake_ab_get_i);

    { /* Core's default count is 1 -> exactly one address, not the whole book */
      r = NULL; rc = rpc_node_dispatch("getnodeaddresses", NULL, &r, &ec, &em);
      ck("getnodeaddresses default count == 1", rc == 1 && r && r->nitems == 1);
      { rj_val* a0 = (r && r->nitems) ? r->items[0] : 0;
        ck("address printed from the v2 record",
           a0 && S(a0,"address") && !strcmp(S(a0,"address"), "76.156.14.11"));
        ck("port decoded big-endian (8333)",
           a0 && S(a0,"port") && !strcmp(S(a0,"port"), "8333"));
        ck("services decoded little-endian (0x0409 = 1033)",
           a0 && S(a0,"services") && !strcmp(S(a0,"services"), "1033"));
        ck("network reported as ipv4",
           a0 && S(a0,"network") && !strcmp(S(a0,"network"), "ipv4"));
        ck("time field present", a0 && rj_obj_get(a0,"time") != NULL); }
      rj_free(r); }

    { const char* j = "[0]"; rj_val* p = rj_parse(j, strlen(j));
      r = NULL; rc = rpc_node_dispatch("getnodeaddresses", p, &r, &ec, &em);
      ck("getnodeaddresses 0 -> the whole book (3)", rc == 1 && r && r->nitems == 3);
      rj_free(r); rj_free(p); }

    { const char* j = "[0,\"onion\"]"; rj_val* p = rj_parse(j, strlen(j));
      r = NULL; rc = rpc_node_dispatch("getnodeaddresses", p, &r, &ec, &em);
      ck("network filter onion -> exactly the onion entry",
         rc == 1 && r && r->typ == RJ_ARR && r->nitems == 1
         && S(r->items[0],"network") && !strcmp(S(r->items[0],"network"), "onion")
         && S(r->items[0],"address") && !strcmp(S(r->items[0],"address"), "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"));
      rj_free(r); rj_free(p); }

    { r = NULL; rc = rpc_node_dispatch("getaddrmaninfo", NULL, &r, &ec, &em);
      ck("getaddrmaninfo dispatched", rc == 1 && r && r->typ == RJ_OBJ);
      /* Core's exact key set, in Core's order */
      static const char* NETS[] = {"ipv4","ipv6","onion","i2p","cjdns","all_networks"};
      int shaped = r != NULL;
      for (int i = 0; r && i < 6; i++){
          rj_val* e = rj_obj_get(r, NETS[i]);
          if (!e || !rj_obj_get(e,"new") || !rj_obj_get(e,"tried") || !rj_obj_get(e,"total"))
              shaped = 0;
      }
      ck("getaddrmaninfo has Core's six networks x {new,tried,total}", shaped);
      ck("ipv4 total == book count", r && rj_obj_get(r,"ipv4") &&
         !strcmp(S(rj_obj_get(r,"ipv4"),"total"), "2"));
      ck("ipv6 total == 0 (none in the book)", r && rj_obj_get(r,"ipv6") &&
         !strcmp(S(rj_obj_get(r,"ipv6"),"total"), "0"));
      ck("onion total == 1 (per-network counts are real)", r && rj_obj_get(r,"onion") &&
         !strcmp(S(rj_obj_get(r,"onion"),"total"), "1"));
      ck("all_networks total == book count (3)", r && rj_obj_get(r,"all_networks") &&
         !strcmp(S(rj_obj_get(r,"all_networks"),"total"), "3"));
      rj_free(r); }

    { r = NULL; rc = rpc_node_dispatch("listbanned", NULL, &r, &ec, &em);
      ck("listbanned -> [] (same answer Core gives with nothing banned)",
         rc == 1 && r && r->typ == RJ_ARR && r->nitems == 0);
      rj_free(r);
      /* no addnode= configured -> [] , exactly as Core answers */
      r = NULL; rc = rpc_node_dispatch("getaddednodeinfo", NULL, &r, &ec, &em);
      ck("getaddednodeinfo with no addnode= -> []",
         rc == 1 && r && r->typ == RJ_ARR && r->nitems == 0);
      rj_free(r);
      r = NULL; rc = rpc_node_dispatch("clearbanned", NULL, &r, &ec, &em);
      ck("clearbanned with no worker -> -4 (it is a real mutation now)",
         rc == 0 && ec == -4);
      rj_free(r); }

    /* The mutators are REAL now (the ctl_* channel). With no worker attached
     * they must say exactly that -- not pretend to have acted, and not claim
     * the capability is missing when it is the worker that is absent. */
    { static const char* MUT[] = {"addnode","disconnectnode","setban",
                                  "setnetworkactive","ping"};
      static const char* ARGS[] = {"[\"1.2.3.4\",\"add\"]", "[\"1.2.3.4\"]",
                                   "[\"1.2.3.4\",\"add\"]", "[true]", "[]"};
      rpc_node_set_status_rw(NULL);
      for (int i = 0; i < 5; i++){
          rj_val* p = rj_parse(ARGS[i], strlen(ARGS[i]));
          r = NULL; ec = 0; em = NULL;
          rc = rpc_node_dispatch(MUT[i], p, &r, &ec, &em);
          char lbl[112]; snprintf(lbl, sizeof lbl,
                                  "%s with no worker -> -4 naming the missing worker", MUT[i]);
          ck(lbl, rc == 0 && ec == -4 && em && strstr(em, "download worker"));
          rj_free(r); rj_free(p);
      }
      ck("all twelve are owned by this module",
         rpc_node_known_method("getnettotals") &&
         rpc_node_known_method("getnodeaddresses") &&
         rpc_node_known_method("getaddrmaninfo") &&
         rpc_node_known_method("listbanned") &&
         rpc_node_known_method("clearbanned") &&
         rpc_node_known_method("getaddednodeinfo") &&
         rpc_node_known_method("addnode") &&
         rpc_node_known_method("disconnectnode") &&
         rpc_node_known_method("setban") &&
         rpc_node_known_method("setnetworkactive") &&
         rpc_node_known_method("ping")); }

    /* getaddednodeinfo over a real addnode= list. peers[0]/[3] are live but
     * carry no addr string at this point, so stage one that matches. */
    { static const char ADDED[2][64] = { "1.2.3.4", "9.9.9.9" };
      rpc_node_set_addednodes(ADDED, 2);
      strcpy(st.peers[0].addr, "1.2.3.4:8333"); st.peers[0].inbound = 0;
      r = NULL; rc = rpc_node_dispatch("getaddednodeinfo", NULL, &r, &ec, &em);
      ck("getaddednodeinfo lists both configured nodes",
         rc == 1 && r && r->typ == RJ_ARR && r->nitems == 2);
      { rj_val* e0 = (r && r->nitems > 0) ? r->items[0] : 0;
        rj_val* e1 = (r && r->nitems > 1) ? r->items[1] : 0;
        ck("added node matched to a live peer -> connected true",
           e0 && S(e0,"connected") && !strcmp(S(e0,"connected"), "1"));
        ck("connected node carries one addresses[] entry with a direction",
           e0 && rj_obj_get(e0,"addresses") && rj_obj_get(e0,"addresses")->nitems == 1 &&
           !strcmp(S(rj_obj_get(e0,"addresses")->items[0], "connected"), "outbound"));
        ck("unconnected added node -> connected false, addresses[] empty",
           e1 && S(e1,"connected") && !strcmp(S(e1,"connected"), "0") &&
           rj_obj_get(e1,"addresses") && rj_obj_get(e1,"addresses")->nitems == 0); }
      rj_free(r);

      /* prefix-only matches must NOT count: "1.2.3.4" vs peer "1.2.3.45" */
      strcpy(st.peers[0].addr, "1.2.3.45:8333");
      r = NULL; rc = rpc_node_dispatch("getaddednodeinfo", NULL, &r, &ec, &em);
      ck("host prefix of a longer IP does not count as connected",
         rc == 1 && r && r->nitems == 2 &&
         !strcmp(S(r->items[0],"connected"), "0"));
      rj_free(r);
      strcpy(st.peers[0].addr, "1.2.3.4:8333");

      /* filter form, and Core's -24 for a node that was never added */
      { const char* j = "[\"9.9.9.9\"]"; rj_val* p = rj_parse(j, strlen(j));
        r = NULL; rc = rpc_node_dispatch("getaddednodeinfo", p, &r, &ec, &em);
        ck("getaddednodeinfo \"node\" filters to that node",
           rc == 1 && r && r->nitems == 1 &&
           !strcmp(S(r->items[0],"addednode"), "9.9.9.9"));
        rj_free(r); rj_free(p); }
      { const char* j = "[\"5.5.5.5\"]"; rj_val* p = rj_parse(j, strlen(j));
        r = NULL; ec = 0; em = NULL;
        rc = rpc_node_dispatch("getaddednodeinfo", p, &r, &ec, &em);
        ck("unknown node -> Core's -24 'Error: Node has not been added.'",
           rc == 0 && ec == -24 && em && !strcmp(em, "Error: Node has not been added."));
        rj_free(r); rj_free(p); }
      rpc_node_set_addednodes(NULL, 0); }

    rpc_node_set_addrbook(NULL, NULL, NULL);

    /* ---- testmempoolaccept ----
     * Without a download worker there is nothing to ask, and the method says
     * so rather than answering from the parent's own guess. */
    { rpc_node_set_status_rw(NULL);
      const char* j = "[[\"0200000001000000000000000000000000000000000000000000000000000000000000000000000000000000fdffffff0100000000000000000000000000\"]]";
      rj_val* p = rj_parse(j, strlen(j));
      r = NULL; ec = 0;
      rc = rpc_node_dispatch("testmempoolaccept", p, &r, &ec, &em);
      ck("testmempoolaccept with no worker -> -4", rc == 0 && ec == -4);
      rj_free(r); rj_free(p); }

    { rpc_node_set_status_rw(&st);
      pthread_t th; g_tw_run = 1; g_tw_n = 0; g_tw_verdict = 1;
      g_tw_last = st.tx_submit_seq;          /* captured BEFORE the thread starts */
      pthread_create(&th, 0, fake_txworker, &st);

      /* a well-formed legacy tx (the createrawtransaction KAT body) */
      const char* TX1 = "020000000167452301efcdab8967452301efcdab8967452301efcdab899807f6e5d4c2b1a30000000000fdffffff01a0860100000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000";
      char j[1200]; snprintf(j, sizeof j, "[[\"%s\"]]", TX1);
      rj_val* p = rj_parse(j, strlen(j));
      r = NULL; rc = rpc_node_dispatch("testmempoolaccept", p, &r, &ec, &em);
      ck("testmempoolaccept -> array of one", rc == 1 && r && r->typ == RJ_ARR && r->nitems == 1);
      { rj_val* e0 = (r && r->nitems) ? r->items[0] : 0;
        ck("entry carries txid and wtxid", e0 && S(e0,"txid") && S(e0,"wtxid"));
        ck("a non-witness tx has wtxid == txid",
           e0 && S(e0,"txid") && S(e0,"wtxid") && !strcmp(S(e0,"txid"), S(e0,"wtxid")));
        ck("allowed:true from the worker's verdict",
           e0 && S(e0,"allowed") && !strcmp(S(e0,"allowed"), "1"));
        ck("vsize reported when allowed", e0 && S(e0,"vsize"));
        ck("fees.base carries the worker's fee (12345 sat)",
           e0 && rj_obj_get(e0,"fees") &&
           !strcmp(S(rj_obj_get(e0,"fees"),"base"), "0.00012345"));
        /* package feerate is not computed here, so it must be absent */
        ck("effective-feerate is omitted, not guessed",
           e0 && rj_obj_get(e0,"fees") &&
           rj_obj_get(rj_obj_get(e0,"fees"),"effective-feerate") == NULL);
        ck("a single tx carries no package-error",
           e0 && rj_obj_get(e0,"package-error") == NULL); }
      rj_free(r); rj_free(p);
      ck("the worker saw tx_submit_test set", g_tw_n >= 1 && g_tw_saw_test[0] == 1);

      /* a rejection carries the worker's reason and no fee/vsize */
      g_tw_verdict = -26;
      p = rj_parse(j, strlen(j));
      r = NULL; rpc_node_dispatch("testmempoolaccept", p, &r, &ec, &em);
      { rj_val* e0 = (r && r->nitems) ? r->items[0] : 0;
        ck("allowed:false on rejection", e0 && !strcmp(S(e0,"allowed"), "0"));
        ck("reject-reason is the worker's text",
           e0 && S(e0,"reject-reason") && !strcmp(S(e0,"reject-reason"), "min relay fee not met"));
        ck("no fees on a rejected tx", e0 && rj_obj_get(e0,"fees") == NULL);
        ck("no vsize on a rejected tx", e0 && rj_obj_get(e0,"vsize") == NULL); }
      rj_free(r); rj_free(p);
      g_tw_verdict = 1;

      /* more than one tx: PACKAGE mode. The array must go to the worker as
       * one staged package with the dry-run flag set -- that is what lets a
       * child see an in-array parent -- and come back with per-member
       * verdicts and the package's effective feerate. */
      { int before = g_tw_n;
        char j2[2400]; snprintf(j2, sizeof j2, "[[\"%s\",\"%s\"]]", TX1, TX1);
        p = rj_parse(j2, strlen(j2));
        r = NULL; rpc_node_dispatch("testmempoolaccept", p, &r, &ec, &em);
        ck("two txs -> two entries", r && r->nitems == 2);
        ck("staged as a PACKAGE of 2, as a dry run",
           g_tw_n > before && g_tw_saw_pkg[g_tw_n-1] == 2 && g_tw_saw_test[g_tw_n-1] == 1);
        ck("no package-error when the package validates",
           r && r->nitems == 2 && rj_obj_get(r->items[0],"package-error") == NULL);
        ck("both members allowed", r && r->nitems == 2 &&
           S(r->items[0],"allowed") && !strcmp(S(r->items[0],"allowed"), "1") &&
           S(r->items[1],"allowed") && !strcmp(S(r->items[1],"allowed"), "1"));
        /* the whole point of package mode: the feerate reported is the
         * PACKAGE's, not each member's own */
        { rj_val* f = r && r->nitems ? rj_obj_get(r->items[0],"fees") : 0;
          ck("fees.effective-feerate is the package feerate",
             f && S(f,"effective-feerate") &&
             !strcmp(S(f,"effective-feerate"), "0.00061725"));   /* 24690 sat / 400 vB * 1000 */
          rj_val* inc = f ? rj_obj_get(f,"effective-includes") : 0;
          ck("effective-includes names both members",
             inc && inc->typ == RJ_ARR && inc->nitems == 2); }
        rj_free(r); rj_free(p); }

      /* a package-level rejection: no member got an individual verdict, so
       * every entry carries package-error and NO `allowed` -- Core's shape */
      { g_tw_pkg_msg = "package-contains-duplicates";
        char j2[2400]; snprintf(j2, sizeof j2, "[[\"%s\",\"%s\"]]", TX1, TX1);
        p = rj_parse(j2, strlen(j2));
        r = NULL; rpc_node_dispatch("testmempoolaccept", p, &r, &ec, &em);
        ck("package-level reject -> package-error on every entry",
           r && r->nitems == 2 &&
           S(r->items[0],"package-error") &&
           !strcmp(S(r->items[0],"package-error"), "package-contains-duplicates") &&
           S(r->items[1],"package-error"));
        ck("...and `allowed` is OMITTED, not false",
           r && r->nitems == 2 && rj_obj_get(r->items[0],"allowed") == NULL);
        rj_free(r); rj_free(p);
        g_tw_pkg_msg = "success"; }

      /* sendrawtransaction MUST clear the flag the dry run left set */
      { int before = g_tw_n;
        char j3[1200]; snprintf(j3, sizeof j3, "[\"%s\"]", TX1);
        p = rj_parse(j3, strlen(j3));
        r = NULL; rpc_node_dispatch("sendrawtransaction", p, &r, &ec, &em);
        rj_free(r); rj_free(p);
        ck("sendrawtransaction after testmempoolaccept clears tx_submit_test",
           g_tw_n > before && g_tw_saw_test[g_tw_n-1] == 0); }

      g_tw_run = 0; pthread_join(th, 0);

      /* argument validation happens before anything is staged */
      { rj_val* q = rj_parse("[[]]", 4);
        r = NULL; ec = 0;
        rc = rpc_node_dispatch("testmempoolaccept", q, &r, &ec, &em);
        ck("an empty array -> -8", rc == 0 && ec == -8);
        rj_free(r); rj_free(q); }
      { char big[3000]; int n = snprintf(big, sizeof big, "[[");
        for (int i = 0; i < 26; i++) n += snprintf(big+n, sizeof big-n, "%s\"00112233445566778899\"", i?",":"");
        snprintf(big+n, sizeof big-n, "]]");
        rj_val* q = rj_parse(big, strlen(big));
        r = NULL; ec = 0;
        rc = rpc_node_dispatch("testmempoolaccept", q, &r, &ec, &em);
        ck("26 transactions -> -8 (Core caps at 25)", rc == 0 && ec == -8);
        rj_free(r); rj_free(q); }
      { rj_val* q = rj_parse("[[\"zz\"]]", 8);
        r = NULL; ec = 0;
        rc = rpc_node_dispatch("testmempoolaccept", q, &r, &ec, &em);
        ck("undecodable hex -> -22 for the WHOLE call, not a short array",
           rc == 0 && ec == -22);
        rj_free(r); rj_free(q); }
      rpc_node_set_status_rw(NULL); }

    /* submitpackage is REAL since 2026-08-27, so what is pinned here is its
     * PARAMETER surface, which must answer the same way in any build: the
     * package-validation refusal this used to assert is gone. */
    { r = NULL; ec = 0; em = NULL;
      rc = rpc_node_dispatch("submitpackage", NULL, &r, &ec, &em);
      ck("submitpackage with no package -> -8", rc == 0 && ec == -8);
      rj_free(r);
      { rj_val* big = rj_arr(); rj_val* outer = rj_arr();
        for (int i = 0; i < 26; i++) rj_arr_push(big, rj_str("00"));
        rj_arr_push(outer, big);
        r = NULL; ec = 0; em = NULL;
        rc = rpc_node_dispatch("submitpackage", outer, &r, &ec, &em);
        ck("submitpackage with 26 transactions -> -8 (Core caps at 25)",
           rc == 0 && ec == -8);
        rj_free(r); rj_free(outer); }
      r = NULL; ec = 0; em = NULL;
      rc = rpc_node_dispatch("getprivatebroadcastinfo", NULL, &r, &ec, &em);
      /* Core: RPC_METHOD_NOT_FOUND with this exact text while -privatebroadcast is off */
      ck("getprivatebroadcastinfo while the option is off -> -32601 with Core's text",
         rc == 0 && ec == -32601 && em && strstr(em, "Private broadcast is not enabled"));
      rj_free(r); }

    /* ---- the peer-control channel, end to end ---- */
    { pthread_t th; g_cw_run = 1; g_cw_nops = 0;
      memset((void*)st.bans, 0, sizeof st.bans);
      st.ctl_seq = st.ctl_ack = 0;
      g_cw_last = st.ctl_seq;              /* captured BEFORE the thread starts */
      rpc_node_set_status_rw(&st);
      pthread_create(&th, 0, fake_ctlworker, &st);

      { rj_val* p = P("[true]");
        D("setnetworkactive", p);
        ck("setnetworkactive true -> true, and the flag is set",
           rc == 1 && r && !strcmp(r->str, "1") && st.net_active == 1);
        rj_free(r); rj_free(p); }
      { rj_val* p = P("[false]");
        D("setnetworkactive", p);
        ck("setnetworkactive false -> false, flag cleared",
           rc == 1 && r && !strcmp(r->str, "0") && st.net_active == 0);
        rj_free(r); rj_free(p); }
      D("getnetworkinfo", NULL);
      ck("getnetworkinfo now REPORTS the disabled network",
         r && S(r,"networkactive") && !strcmp(S(r,"networkactive"), "0"));
      rj_free(r);
      { rj_val* p = P("[true]"); D("setnetworkactive", p); rj_free(r); rj_free(p); }

      D("ping", NULL);
      ck("ping -> null (queued, as Core does)", rc == 1 && r && r->typ == RJ_NULL);
      rj_free(r);

      /* --- bans: the parent must SEE what the worker wrote --- */
      { rj_val* p = P("[\"5.6.7.8\",\"add\",3600]");
        D("setban", p);
        ck("setban add -> null", rc == 1 && r && r->typ == RJ_NULL);
        rj_free(r); rj_free(p); }
      D("listbanned", NULL);
      ck("listbanned reads the SHARED list the worker wrote",
         rc == 1 && r && r->typ == RJ_ARR && r->nitems == 1);
      { rj_val* b0 = (r && r->nitems) ? r->items[0] : 0;
        ck("...with Core's address/banned_until/ban_created",
           b0 && S(b0,"address") && !strcmp(S(b0,"address"), "5.6.7.8") &&
           rj_obj_get(b0,"banned_until") && rj_obj_get(b0,"ban_created")); }
      rj_free(r);
      { rj_val* p = P("[\"5.6.7.8\",\"add\"]");
        D("setban", p);
        ck("banning the same subnet twice -> Core's -30, not a false success",
           rc == 0 && ec == -30 && em && strstr(em, "already banned"));
        rj_free(r); rj_free(p); }
      { rj_val* p = P("[\"9.9.9.9\",\"remove\"]");
        D("setban", p);
        ck("unbanning something not banned -> -30", rc == 0 && ec == -30);
        rj_free(r); rj_free(p); }
      { rj_val* p = P("[\"5.6.7.8\",\"remove\"]");
        D("setban", p);
        ck("unbanning a real ban succeeds", rc == 1);
        rj_free(r); rj_free(p); }
      D("listbanned", NULL);
      ck("...and it leaves the list", rc == 1 && r && r->nitems == 0);
      rj_free(r);
      { /* an expired ban must not be listed */
        st.bans[0].until = 1; st.bans[0].created = 1;
        snprintf((char*)st.bans[0].subnet, 64, "7.7.7.7");
        D("listbanned", NULL);
        ck("an EXPIRED ban is not listed", rc == 1 && r && r->nitems == 0);
        rj_free(r); st.bans[0].until = 0; }
      { rj_val* p = P("[\"1.2.3.0/24\",\"add\",1893456000,true]");
        D("setban", p);
        ck("setban with an absolute bantime succeeds", rc == 1);
        rj_free(r); rj_free(p);
        D("listbanned", NULL);
        ck("...and the absolute time is stored verbatim",
           rc == 1 && r && r->nitems == 1 &&
           !strcmp(S(r->items[0],"banned_until"), "1893456000"));
        rj_free(r); }
      D("clearbanned", NULL);
      ck("clearbanned -> null", rc == 1 && r && r->typ == RJ_NULL);
      rj_free(r);
      D("listbanned", NULL);
      ck("...and the list is empty", rc == 1 && r && r->nitems == 0);
      rj_free(r);

      /* --- addnode / disconnectnode error mapping --- */
      { rj_val* p = P("[\"1.2.3.4\",\"add\"]");
        D("addnode", p);
        ck("addnode add -> null", rc == 1 && r && r->typ == RJ_NULL);
        rj_free(r); rj_free(p); }
      { rj_val* p = P("[\"1.2.3.4\",\"remove\"]");
        D("addnode", p);
        ck("addnode remove of an unknown node -> Core's -24",
           rc == 0 && ec == -24 && em && strstr(em, "has not been added"));
        rj_free(r); rj_free(p); }
      { rj_val* p = P("[\"1.2.3.4\",\"bogus\"]");
        D("addnode", p);
        ck("an invalid addnode command -> -8", rc == 0 && ec == -8);
        rj_free(r); rj_free(p); }
      { rj_val* p = P("[\"1.2.3.4\"]");
        D("disconnectnode", p);
        ck("disconnectnode of a live peer succeeds", rc == 1);
        rj_free(r); rj_free(p); }
      { rj_val* p = P("[\"9.9.9.9\"]");
        D("disconnectnode", p);
        ck("disconnectnode of an unknown peer -> Core's -29",
           rc == 0 && ec == -29 && em && strstr(em, "not found"));
        rj_free(r); rj_free(p); }
      { rj_val* p = P("[\"1.2.3.4\",5]");
        D("disconnectnode", p);
        ck("both address and nodeid -> Core's -32602",
           rc == 0 && ec == -32602 && em && strstr(em, "Only one of"));
        rj_free(r); rj_free(p); }

      ck("the worker saw every op type", g_cw_nops >= 10);
      g_cw_run = 0; pthread_join(th, 0);
      rpc_node_set_status_rw(NULL); }

    /* a method we don't own -> -1 (caller keeps looking) */
    r = NULL; rc = rpc_node_dispatch("getblockcount", NULL, &r, &ec, &em);
    ck("unknown method -> -1", rc == -1);
    ck("rpc_node_known_method(getnetworkinfo)", rpc_node_known_method("getnetworkinfo") == 1);
    ck("rpc_node_known_method(getblockcount) == 0", rpc_node_known_method("getblockcount") == 0);

    /* NULL status (RPC up before the worker published) -> zeros, no crash */
    rpc_node_set_status(NULL);
    r = NULL; rpc_node_dispatch("getconnectioncount", NULL, &r, &ec, &em);
    ck("null status -> connectioncount 0", r && r->str && !strcmp(r->str, "0"));
    rj_free(r);

    /* getzmqnotifications: reports exactly the configured endpoints, in
     * Core's shape and order. Unconfigured -> empty array (Core without any
     * zmqpub options answers []), never a refusal -- an empty answer and a
     * missing method are different facts to a subscriber probing support. */
    rpc_node_set_zmq(NULL, NULL, NULL, NULL);
    r = NULL; rc = rpc_node_dispatch("getzmqnotifications", NULL, &r, &ec, &em);
    ck("getzmqnotifications unconfigured -> rc 1", rc == 1);
    ck("getzmqnotifications unconfigured -> empty array",
       r && r->typ == RJ_ARR && r->nitems == 0);
    rj_free(r);

    rpc_node_set_zmq("tcp://127.0.0.1:28332", NULL, NULL, "tcp://127.0.0.1:28333");
    r = NULL; rc = rpc_node_dispatch("getzmqnotifications", NULL, &r, &ec, &em);
    ck("getzmqnotifications -> 2 configured entries", rc == 1 && r && r->nitems == 2);
    if (r && r->nitems == 2){
        rj_val* e0 = r->items[0]; rj_val* e1 = r->items[1];
        rj_val* t0 = rj_obj_get(e0, "type");    rj_val* a0 = rj_obj_get(e0, "address");
        rj_val* t1 = rj_obj_get(e1, "type");    rj_val* a1 = rj_obj_get(e1, "address");
        ck("entry 0 is pubhashblock at its address",
           t0 && !strcmp(t0->str, "pubhashblock") && a0 && !strcmp(a0->str, "tcp://127.0.0.1:28332"));
        ck("entry 1 is pubrawtx at its address (unset topics skipped, order kept)",
           t1 && !strcmp(t1->str, "pubrawtx") && a1 && !strcmp(a1->str, "tcp://127.0.0.1:28333"));
        ck("hwm present", rj_obj_get(e0, "hwm") != NULL);
    }
    rj_free(r);

    /* ---- mempool.dat reload: parents-first ordering (2026-09-01) ----
     * A dump written in pool order can list a child before its parent; the
     * loader now orders entries so every in-dump parent is offered first. */
    {
        typedef struct { unsigned char* tx; unsigned long len; long long t, d; unsigned char txid[32]; } ent_t;
        extern long mpd_order_parents_first(const ent_t* v, long n, long* order);
        static unsigned char sc[4096];
        /* A: spends an outside coin; B spends A:0; C spends B:0; D independent */
        static unsigned char A[128], B[128], C[128], D[128]; ent_t e[4]; long la, lb, lc, ld;
        unsigned char outside[32]; memset(outside, 0x77, 32);
        /* minimal legacy tx builder: version, 1 input (prev, vout 0), empty scriptSig, seq, 1 output, locktime */
        #define MKTX(buf, prev, tag, lenvar) do{ unsigned char* p = buf; *p++=1;*p++=0;*p++=0;*p++=(tag); *p++=1; memcpy(p, prev, 32); p+=32; *p++=0;*p++=0;*p++=0;*p++=0; *p++=0; *p++=0xff;*p++=0xff;*p++=0xff;*p++=0xff; *p++=1; memset(p, (tag), 8); p+=8; *p++=1; *p++=0x51; *p++=0;*p++=0;*p++=0;*p++=0; lenvar = p - buf; }while(0)
        MKTX(A, outside, 0x0a, la); e[2].tx = A; e[2].len = la; tx_txid(e[2].txid, A, la, sc, sizeof sc);
        MKTX(B, e[2].txid, 0x0b, lb); e[1].tx = B; e[1].len = lb; tx_txid(e[1].txid, B, lb, sc, sizeof sc);
        MKTX(C, e[1].txid, 0x0c, lc); e[0].tx = C; e[0].len = lc; tx_txid(e[0].txid, C, lc, sc, sizeof sc);
        MKTX(D, outside, 0x0d, ld); e[3].tx = D; e[3].len = ld; tx_txid(e[3].txid, D, ld, sc, sizeof sc);
        long order[4] = {-1,-1,-1,-1};
        long placed = mpd_order_parents_first(e, 4, order);
        int pos[4]; for (int i = 0; i < 4; i++) pos[i] = -1; for (int k = 0; k < 4; k++) if (order[k] >= 0 && order[k] < 4) pos[order[k]] = k;
        ck("reload order: every entry placed", placed == 4 && pos[0] >= 0 && pos[1] >= 0 && pos[2] >= 0 && pos[3] >= 0);
        ck("reload order: A (parent) before B before C (file order was C,B,A)", pos[2] < pos[1] && pos[1] < pos[0]);
        ck("reload order: independent entries keep file order among the ready ones (A before D)", pos[2] < pos[3]);
        #undef MKTX
    }

    /* ---- RPC-9 (audit 2026-09-03): getnetworkinfo's fee fields were literals
     *
     * relayfee and incrementalfee were hardcoded 0.00001000 while the real
     * floors default to 100 sat/kvB, so getnetworkinfo.relayfee and
     * getmempoolinfo.minrelaytxfee DISAGREED BY 10x ON A STOCK NODE -- not
     * only with a non-default floor, as the audit states. main.c calls
     * rpc_node_set_relay_floors at boot, so the configured value was
     * available at that line all along.
     *
     * The assertion is CONSISTENCY between the two RPCs rather than a literal,
     * so it survives any future change to the default -- and the second half
     * moves the floors and re-checks, which a re-hardcoded constant cannot
     * satisfy. */
    {
        rj_val* a = NULL; rj_val* b = NULL;
        rpc_node_dispatch("getnetworkinfo", NULL, &a, &ec, &em);
        rpc_node_dispatch("getmempoolinfo", NULL, &b, &ec, &em);
        ck("RPC-9 both RPCs answer", a && b);
        if (a && b){
            ck("RPC-9 getnetworkinfo.relayfee == getmempoolinfo.minrelaytxfee",
               S(a,"relayfee") && S(b,"minrelaytxfee") &&
               !strcmp(S(a,"relayfee"), S(b,"minrelaytxfee")));
            if (S(a,"relayfee") && S(b,"minrelaytxfee") && strcmp(S(a,"relayfee"), S(b,"minrelaytxfee")))
                printf("      relayfee=%s minrelaytxfee=%s\n", S(a,"relayfee"), S(b,"minrelaytxfee"));
            ck("RPC-9 incrementalfee is reported too",
               S(a,"incrementalfee") && !strcmp(S(a,"incrementalfee"), "0.00000100"));
        }
        rj_free(a); rj_free(b);

        /* move the floors and confirm the field FOLLOWS -- a literal cannot */
        extern void rpc_node_set_relay_floors(unsigned long long, unsigned long long);
        rpc_node_set_relay_floors(500, 700);
        a = NULL; rpc_node_dispatch("getnetworkinfo", NULL, &a, &ec, &em);
        ck("RPC-9 relayfee follows a configured floor (500 sat/kvB)",
           a && S(a,"relayfee") && !strcmp(S(a,"relayfee"), "0.00000500"));
        ck("RPC-9 incrementalfee follows its own floor (700 sat/kvB)",
           a && S(a,"incrementalfee") && !strcmp(S(a,"incrementalfee"), "0.00000700"));
        rj_free(a);
        rpc_node_set_relay_floors(100, 100);   /* restore for any later case */
    }

    /* ---- RPC-8 (audit 2026-09-03): setban validates its argument ----
     * The subnet string was never parsed before storage, so `setban
     * "not-an-ip" add` succeeded, was listed by listbanned, and never matched
     * anything -- a ban the operator believes is in force and is not. Core
     * runs LookupSubNet first and raises -30.
     *
     * The worker ALSO refused any prefix that was not a multiple of 8 in
     * [8,32], claiming the matcher could not enforce it -- false since
     * subnet.c landed, and inverted for IPv6 (it accepted 2001:db8::/32 while
     * refusing ::1/128). That half is exercised by test_subnet.c directly;
     * what this file can reach is the RPC-side parse.
     *
     * Both directions are asserted: garbage must be refused AND ordinary
     * forms must still be accepted, so a validator that rejects everything
     * fails just as loudly as none at all. */
    {
        rj_val* p = P("[\"not-an-ip\",\"add\"]");
        D("setban", p);
        ck("RPC-8 an unparseable subnet is refused with Core's -30",
           rc == 0 && ec == -30 && em && strstr(em, "Invalid IP/Subnet"));
        rj_free(r); rj_free(p);

        p = P("[\"192.168.1.16/28\",\"add\"]");
        D("setban", p);
        ck("RPC-8 a /28 (not a multiple of 8) reaches the worker", rc != 0 || ec != -30);
        rj_free(r); rj_free(p);

        p = P("[\"2001:db8::/64\",\"add\"]");
        D("setban", p);
        ck("RPC-8 an IPv6 /64 reaches the worker", rc != 0 || ec != -30);
        rj_free(r); rj_free(p);

        p = P("[\"5.6.7.8\",\"add\"]");
        D("setban", p);
        ck("RPC-8 a bare IPv4 address is still accepted", rc != 0 || ec != -30);
        rj_free(r); rj_free(p);
    }

    printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
