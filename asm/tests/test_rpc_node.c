/* test_rpc_node.c -- live-node RPC module (rpc_node.c) in isolation: populate a
 * fake node_status_t (as the serve parent would in shared memory), dispatch,
 * and assert the JSON. No serve daemon / sockets needed. */
#include "../rpc_node.h"
#include "../rpc_json.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }
static const char* S(const rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get(o,k) : 0; return v ? v->str : 0; }

int main(void){
    node_status_t st = { .n_out = 8, .n_inbound = 3, .tip_height = 800000, .start_time = 0 };
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
    ck("localservices NETWORK",  r && S(r,"localservices") && !strcmp(S(r,"localservices"), "0000000000000001"));
    ck("connections 11",         r && S(r,"connections") && !strcmp(S(r,"connections"), "11"));
    ck("connections_out 8",      r && S(r,"connections_out") && !strcmp(S(r,"connections_out"), "8"));
    ck("connections_in 3",       r && S(r,"connections_in") && !strcmp(S(r,"connections_in"), "3"));
    ck("localrelay true",        r && S(r,"localrelay") && !strcmp(S(r,"localrelay"), "1"));
    ck("networkactive true",     r && S(r,"networkactive") && !strcmp(S(r,"networkactive"), "1"));
    { rj_val* nets = r ? rj_obj_get(r,"networks") : 0;
      ck("networks is a 5-entry array", nets && nets->typ == RJ_ARR && nets->nitems == 5);
      rj_val* n0 = (nets && nets->nitems) ? nets->items[0] : 0;
      ck("networks[0].name ipv4", n0 && S(n0,"name") && !strcmp(S(n0,"name"), "ipv4")); }
    { rj_val* names = r ? rj_obj_get(r,"localservicesnames") : 0;
      ck("localservicesnames [NETWORK]", names && names->typ == RJ_ARR && names->nitems == 1
         && names->items[0]->str && !strcmp(names->items[0]->str, "NETWORK")); }
    rj_free(r);

    /* getpeerinfo: populate a couple of fake outbound peers in the table */
    st.peers[0].used = 1; st.peers[0].inbound = 0;
    strcpy(st.peers[0].addr, "1.2.3.4:8333"); st.peers[0].proto = 70016;
    st.peers[0].services = 0x0000000000000409ULL;   /* NETWORK|WITNESS|NETWORK_LIMITED */
    strcpy(st.peers[0].subver, "/Satoshi:27.0.0/"); st.peers[0].start_height = 800000;
    st.peers[0].conn_time = 1700000000LL;
    st.peers[0].bytes_sent = 4096; st.peers[0].bytes_recv = 1048576;
    st.peers[0].last_send = 1700000100LL; st.peers[0].last_recv = 1700000200LL;
    st.peers[3].used = 1; strcpy(st.peers[3].addr, "5.6.7.8:8333"); st.peers[3].proto = 70016;
    rpc_node_set_status(&st);
    r = NULL; rc = rpc_node_dispatch("getpeerinfo", NULL, &r, &ec, &em);
    ck("getpeerinfo dispatched to array", rc == 1 && r && r->typ == RJ_ARR);
    ck("getpeerinfo has 2 peers", r && r->nitems == 2);
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
    /* second peer should get id 1 (contiguous ids, not the slot index) */
    { rj_val* p1 = (r && r->nitems>1) ? r->items[1] : 0;
      ck("peer1 id 1", p1 && S(p1,"id") && !strcmp(S(p1,"id"), "1")); }
    rj_free(r);
    memset(st.peers, 0, sizeof st.peers);   /* reset for the remaining checks */

    /* getmempoolinfo: accurate config, empty for this process's mempool */
    r = NULL; rc = rpc_node_dispatch("getmempoolinfo", NULL, &r, &ec, &em);
    ck("getmempoolinfo dispatched", rc == 1 && r != NULL);
    ck("mempool loaded true", r && S(r,"loaded") && !strcmp(S(r,"loaded"), "1"));
    ck("mempool size 0", r && S(r,"size") && !strcmp(S(r,"size"), "0"));
    ck("mempool maxmempool 300MB", r && S(r,"maxmempool") && !strcmp(S(r,"maxmempool"), "300000000"));
    ck("mempool minrelaytxfee (Core field name, not minrelayfee)",
       r && S(r,"minrelaytxfee") && !strcmp(S(r,"minrelaytxfee"), "0.00001000") && S(r,"minrelayfee")==NULL);
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
      static unsigned char pool[40 + 1024*48 + 8];
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
      rpc_node_set_mempool(pool, NULL, 8388608, mpool_count, NULL, NULL, NULL, NULL);

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

      /* detach again so the empty-pool checks stay valid for later runs */
      rpc_node_set_mempool(NULL, NULL, 300000000LL, NULL, NULL, NULL, NULL, NULL); }

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

    printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
