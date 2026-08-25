/* test_rpc_node.c -- live-node RPC module (rpc_node.c) in isolation: populate a
 * fake node_status_t (as the serve parent would in shared memory), dispatch,
 * and assert the JSON. No serve daemon / sockets needed. */
#include "../rpc_node.h"
#include "../rpc_json.h"
#include <stdio.h>
#include <string.h>

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
      { rpc_mempool_hooks h; memset(&h,0,sizeof h);
        h.mp = pool; h.maxbytes = 8388608; h.count = mpool_count;
        rpc_node_set_mempool(&h); }

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
        mpool_policy_init(polcfg, 1, 25, 101000, 25, 101000, 1);
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

        /* ---- estimatesmartfee: Core's contract over OUR EMA estimator.
         * The two policy adds above fed the EMA real samples (fee 10000 over
         * 82 bytes -> ~121951 sat/kB first sample; EMA converges toward it),
         * so the feerate is a genuine policy-computed number. ---- */
        { extern long mpool_policy_estimate(void*, unsigned long long*, unsigned long long*);
          { rpc_mempool_hooks h; memset(&h,0,sizeof h);
            h.mp = pool; h.maxbytes = 8388608; h.count = mpool_count;
            h.get = mpool_get; h.polstate = polstate;
            h.pol_entry_info = mpool_policy_entry_info;
            h.estimate = mpool_policy_estimate;
            rpc_node_set_mempool(&h); }
          rj_val* fp=rj_parse("[6]",3); r=NULL;
          rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&ec,&em);
          ck("esf(6) dispatched with feerate+blocks", rc==1 && r && S(r,"feerate") && S(r,"blocks") && !strcmp(S(r,"blocks"),"6"));
          ck("esf(6) no errors array", r && rj_obj_get(r,"errors")==NULL);
          { unsigned long long spk=0, n=0; mpool_policy_estimate(polstate,&spk,&n);
            char want[32]; snprintf(want,sizeof want,"%llu.%08llu",
                (spk<1000?1000ULL:spk)/100000000ULL, (spk<1000?1000ULL:spk)%100000000ULL);
            ck("esf(6) feerate == policy EMA (floored)", n>0 && S(r,"feerate") && !strcmp(S(r,"feerate"),want)); }
          rj_free(r); rj_free(fp);
          /* conf_target 1 -> blocks clamps to 2 (oracle-verified) */
          fp=rj_parse("[1]",3); r=NULL;
          rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&ec,&em);
          ck("esf(1) -> blocks 2", rc==1 && r && S(r,"blocks") && !strcmp(S(r,"blocks"),"2"));
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
          fp=rj_parse("[6, \"bogus\"]",12); r=NULL;
          rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&e8,&m8);
          ck("esf bad mode -> -8 Core message", rc==0 && e8==-8 && m8 && strstr(m8,"Invalid estimate_mode parameter"));
          rj_free(r); rj_free(fp);
          fp=rj_parse("[6, \"ECONOMICAL\"]",17); r=NULL;
          rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&ec,&em);
          ck("esf ECONOMICAL accepted (case-insensitive)", rc==1 && r && S(r,"feerate"));
          rj_free(r); rj_free(fp);
          /* fresh estimator -> Core's insufficient-data shape */
          { static unsigned char fresh[1<<22];
            extern void mpool_policy_state_init(void*, unsigned long);
            mpool_policy_state_init(fresh, 4096);
            rpc_mempool_hooks h; memset(&h,0,sizeof h);
            h.mp = pool; h.polstate = fresh; h.estimate = mpool_policy_estimate;
            rpc_node_set_mempool(&h);
            fp=rj_parse("[6]",3); r=NULL;
            rc=rpc_node_dispatch("estimatesmartfee",fp,&r,&ec,&em);
            rj_val* errs = r?rj_obj_get(r,"errors"):NULL;
            ck("esf fresh estimator -> errors[Insufficient data...]", rc==1 && errs && errs->typ==RJ_ARR
               && errs->nitems==1 && errs->items[0]->str
               && !strcmp(errs->items[0]->str,"Insufficient data or no feerate found"));
            ck("esf fresh -> no feerate field", r && rj_obj_get(r,"feerate")==NULL);
            rj_free(r); rj_free(fp); }
          /* restore the populated hooks for any later checks */
          { rpc_mempool_hooks h; memset(&h,0,sizeof h);
            h.mp = pool; h.maxbytes = 8388608; h.count = mpool_count;
            h.get = mpool_get; h.polstate = polstate;
            h.pol_entry_info = mpool_policy_entry_info;
            rpc_node_set_mempool(&h); } }

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
