/* tests/test_relay_policy.c -- Core's relay-policy decisions (daemon/relay_policy.c
 * + the permission tokens in daemon/netperm.c). What matters is the
 * DECISION, per Core v31.99 net_processing.cpp/net.cpp:
 *   - RejectIncomingTxs: block-relay-only and feeler conns always; in
 *     -blocksonly everyone without `relay`;
 *   - our version's fRelay = !RejectIncomingTxs, and 0 past the inbound
 *     relay share unless the peer has `relay`;
 *   - the share counts only peers that negotiated tx relay, and is
 *     static_cast<int>(pct/100.0 * limit);
 *   - fRelay parsing of a version payload (absent = 1);
 *   - feefilter is not sent in -blocksonly nor to forcerelay peers;
 *   - permission tokens: noban implies download, forcerelay implies relay;
 *     bloomfilter and out are refused, in is accepted; ToStrings order. */
#include <stdio.h>
#include <string.h>
#include "../daemon/relay_policy.h"
#include "../daemon/netperm.h"
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c ? "ok " : "FAIL", w); if (!c) fails++; }
static long mkver(unsigned char* v, const char* ua, int with_frelay, int frelay){
    memset(v, 0, 80); v[0] = 0x80; v[1] = 0x11; v[2] = 1;   /* 70016 */
    long o = 80; size_t ul = strlen(ua); v[o++] = (unsigned char)ul; memcpy(v + o, ua, ul); o += (long)ul;
    v[o++] = 1; v[o++] = 0; v[o++] = 0; v[o++] = 0;          /* start_height */
    if (with_frelay) v[o++] = (unsigned char)frelay;
    return o;
}
int main(void){
    printf("== RejectIncomingTxs / our fRelay ==\n");
    rp_set_blocksonly(0);
    ok(!rp_reject_incoming_txs(0, RP_CONN_INBOUND), "not blocksonly: inbound peers may send txs");
    ok(!rp_reject_incoming_txs(0, RP_CONN_OUTBOUND), "...and full outbound legs");
    ok(rp_reject_incoming_txs(0, RP_CONN_BLOCK_RELAY), "block-relay-only legs never");
    ok(rp_reject_incoming_txs(NP_RELAY, RP_CONN_FEELER), "feelers never, even with relay");
    ok(rp_our_frelay(0, RP_CONN_INBOUND, 0) == 1, "fRelay=1 to an ordinary inbound peer");
    ok(rp_our_frelay(0, RP_CONN_BLOCK_RELAY, 0) == 0, "fRelay=0 on a block-relay-only leg");
    ok(rp_our_frelay(0, RP_CONN_INBOUND, 1) == 0, "fRelay=0 to an inbound peer past the relay share");
    ok(rp_our_frelay(NP_RELAY, RP_CONN_INBOUND, 1) == 1, "...unless it has the relay permission");
    rp_set_blocksonly(1);
    ok(rp_reject_incoming_txs(0, RP_CONN_INBOUND), "blocksonly: inbound peers without relay are rejected");
    ok(!rp_reject_incoming_txs(NP_RELAY, RP_CONN_INBOUND), "...with relay they are accepted");
    ok(!rp_reject_incoming_txs(NP_FORCERELAY | NP_RELAY, RP_CONN_INBOUND), "...forcerelay implies relay");
    ok(rp_reject_incoming_txs(0, RP_CONN_OUTBOUND), "blocksonly: outbound legs get fRelay=0 too");
    ok(rp_our_frelay(0, RP_CONN_OUTBOUND, 0) == 0 && rp_our_frelay(NP_RELAY, RP_CONN_INBOUND, 0) == 1, "our fRelay follows");
    printf("== inbound relay share ==\n");
    ok(!rp_inbound_share_exhausted(0, 245, 50), "0 of 122 relaying: room");
    ok(!rp_inbound_share_exhausted(121, 245, 50), "121 of 122: room");
    ok(rp_inbound_share_exhausted(122, 245, 50), "122 of 122 (static_cast<int>(0.5*245)=122): exhausted");
    ok(rp_inbound_share_exhausted(0, 245, 0), "percent 0: nobody relays");
    ok(!rp_inbound_share_exhausted(244, 245, 100), "percent 100: everyone");
    ok(!rp_inbound_share_exhausted(5, 0, 50), "no inbound limit: never exhausted");
    printf("== version fRelay parse ==\n");
    unsigned char v[200]; long n;
    n = mkver(v, "/Satoshi:31.99.0/", 1, 0); ok(rp_version_frelay(v, n) == 0, "fRelay=0 parsed");
    n = mkver(v, "/Satoshi:31.99.0/", 1, 1); ok(rp_version_frelay(v, n) == 1, "fRelay=1 parsed");
    n = mkver(v, "/bmc/", 0, 0);            ok(rp_version_frelay(v, n) == 1, "fRelay absent means relay");
    ok(rp_version_frelay(v, 60) == -1, "a truncated version is unparseable");
    printf("== feefilter ==\n");
    rp_set_blocksonly(0);
    ok(rp_send_feefilter(0) && !rp_send_feefilter(NP_FORCERELAY | NP_RELAY), "sent normally, never to a forcerelay peer");
    rp_set_blocksonly(1); ok(!rp_send_feefilter(0), "never in blocksonly");
    printf("== permission tokens ==\n");
    const char* e = 0; netperm_reset();
    ok(netperm_add("noban@10.0.0.1", &e) && (netperm_for("10.0.0.1") & NP_DOWNLOAD), "noban implies download");
    ok(netperm_add("forcerelay@10.0.0.2", &e) && (netperm_for("10.0.0.2") & NP_RELAY), "forcerelay implies relay");
    ok(netperm_add("mempool,download,addr,in@10.0.0.3", &e) && netperm_for("10.0.0.3") == (NP_MEMPOOL|NP_DOWNLOAD|NP_ADDR), "mempool/download/addr/in accepted");
    ok(!netperm_add("bloomfilter@10.0.0.4", &e) && e && strstr(e, "BIP37"), "bloomfilter refused, names BIP37");
    ok(!netperm_add("out@10.0.0.5", &e) && e && strstr(e, "inbound"), "out refused, says inbound-only");
    ok(!netperm_add("rpc@10.0.0.6", &e) && e && !strcmp(e, "unknown permission"), "unknown token still refused");
    const char* names[8]; int k = netperm_names(NP_NOBAN|NP_DOWNLOAD|NP_FORCERELAY|NP_RELAY|NP_MEMPOOL|NP_ADDR, names, 8);
    ok(k == 6 && !strcmp(names[0], "noban") && !strcmp(names[1], "forcerelay") && !strcmp(names[2], "relay") && !strcmp(names[3], "mempool") && !strcmp(names[4], "download") && !strcmp(names[5], "addr"), "ToStrings order: noban forcerelay relay mempool download addr");
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
