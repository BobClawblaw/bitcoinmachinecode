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
      rj_val* sn = p0 ? rj_obj_get(p0,"servicesnames") : 0;
      ck("peer0 servicesnames NETWORK+WITNESS+NETWORK_LIMITED", sn && sn->typ==RJ_ARR && sn->nitems==3); }
    /* second peer should get id 1 (contiguous ids, not the slot index) */
    { rj_val* p1 = (r && r->nitems>1) ? r->items[1] : 0;
      ck("peer1 id 1", p1 && S(p1,"id") && !strcmp(S(p1,"id"), "1")); }
    rj_free(r);
    memset(st.peers, 0, sizeof st.peers);   /* reset for the remaining checks */

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
