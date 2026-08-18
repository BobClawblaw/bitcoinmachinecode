/* node_config: Core-key compatibility, clamping, and wedge-proofing.
 *
 * The clamp tests matter as much as the parse tests: a config file is
 * OPERATOR input, not trusted input, and a bad tuning value is exactly what
 * stalled a live sync on 2026-08-18. A typo must not be able to reproduce
 * that. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "node_config.h"

static void wr(const char* path, const char* body){
    FILE* f=fopen(path,"w"); if(!f) return; fputs(body,f); fclose(f);
}

int main(void){
    int failures=0;
    printf("---- node_config ----\n");

    /* 1. absent file -> compiled defaults, no crash */
    node_config_load("/nonexistent/bitcoin.conf");
    if (g_cfg.max_connections==200 && g_cfg.max_outbound==8 && g_cfg.dbcache_mb==1024)
        printf("PASS: missing file falls back to compiled defaults (Core v31 dbcache default 1024)\n");
    else { printf("FAIL: defaults wrong (conns=%d out=%d dbcache=%d)\n",
                  g_cfg.max_connections,g_cfg.max_outbound,g_cfg.dbcache_mb); failures++; }

    /* 2. the REAL repo config -- must parse, and honour Core keys already in it */
    long n = node_config_load("/storage/bitcoinmachinecode/config/bitcoin.conf");
    printf("  real bitcoin.conf applied %ld setting(s)\n", n);
    if (g_cfg.max_connections==256)
        printf("PASS: honoured maxconnections=256 from the real file\n");
    else { printf("FAIL: maxconnections=%d, expected 256\n", g_cfg.max_connections); failures++; }
    if (g_cfg.dbcache_mb==4096)
        printf("PASS: honoured Core's dbcache=4096 from the real file\n");
    else { printf("FAIL: dbcache_mb=%d, expected 4096\n", g_cfg.dbcache_mb); failures++; }
    if (g_cfg.utxo_bulk_slots_log2 > 22)
        printf("PASS: dbcache=4096 scaled the memtable up (2^%d slots, %dMB blob)\n",
               g_cfg.utxo_bulk_slots_log2, g_cfg.utxo_bulk_blob_mb);
    else { printf("FAIL: dbcache did not scale sizing (2^%d)\n", g_cfg.utxo_bulk_slots_log2); failures++; }

    /* 3. out-of-range values are rejected, not applied */
    wr("/storage/bitcoinmachinecode/asm/bmc_t1.conf", "maxconnections=2\nbmc.peerminusable=0\nbmc.peerpool=-5\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t1.conf");
    if (g_cfg.max_connections==200 && g_cfg.min_usable_peers==8 && g_cfg.maxpool==2048)
        printf("PASS: out-of-range values rejected, defaults kept\n");
    else { printf("FAIL: bad values applied (conns=%d usable=%d pool=%d)\n",
                  g_cfg.max_connections,g_cfg.min_usable_peers,g_cfg.maxpool); failures++; }

    /* 4. a config that would leave zero inbound slots must be refused wholesale */
    wr("/storage/bitcoinmachinecode/asm/bmc_t2.conf", "maxconnections=16\nbmc.maxoutbound=32\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t2.conf");
    { int outb=g_cfg.max_outbound+g_cfg.max_block_relay_only+g_cfg.max_feeler;
      if (outb < g_cfg.max_connections)
          printf("PASS: no-inbound-slots config reverted (outbound %d < max %d)\n", outb, g_cfg.max_connections);
      else { printf("FAIL: node would have zero inbound slots (outbound %d, max %d)\n", outb, g_cfg.max_connections); failures++; } }

    /* 5. valid extension keys DO apply */
    wr("/storage/bitcoinmachinecode/asm/bmc_t3.conf", "bmc.feelers=0\nbmc.peerminticks=5\nbmc.addrmaxpernetgroup=4\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t3.conf");
    if (g_cfg.max_feeler==0 && g_cfg.dead_weight_ticks==5 && g_cfg.addr_max_per_netgroup==4)
        printf("PASS: extension keys applied (feelers=0 ticks=5 netgroup=4)\n");
    else { printf("FAIL: extension keys not applied\n"); failures++; }

    /* 6. unknown/foreign keys ignored -> file stays shareable with Core */
    wr("/storage/bitcoinmachinecode/asm/bmc_t4.conf", "rpcuser=x\nrpcpassword=y\ntxindex=1\nprune=0\nwhitelist=rpc\nmaxconnections=64\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t4.conf");
    if (g_cfg.max_connections==64)
        printf("PASS: foreign Core keys ignored without disturbing parsing\n");
    else { printf("FAIL: parsing disturbed by foreign keys (conns=%d)\n", g_cfg.max_connections); failures++; }

    /* ---- peer sourcing: dnsseed / seednode / addnode / connect ---- */

    /* 7. dnsseed=0 is honoured (it gates ALL DNS bootstrapping) */
    wr("/storage/bitcoinmachinecode/asm/bmc_t5.conf", "dnsseed=0\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t5.conf");
    if (g_cfg.dnsseed==0 && g_cfg.connect_only==0)
        printf("PASS: dnsseed=0 honoured without implying connect-only\n");
    else { printf("FAIL: dnsseed=%d connect_only=%d\n", g_cfg.dnsseed, g_cfg.connect_only); failures++; }

    /* 8. the repeatable keys accumulate, and duplicates collapse */
    wr("/storage/bitcoinmachinecode/asm/bmc_t6.conf",
       "addnode=1.2.3.4\naddnode=5.6.7.8\naddnode=1.2.3.4\nseednode=9.9.9.9\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t6.conf");
    if (g_cfg.n_addnode==2 && g_cfg.n_seednode==1
        && !strcmp(g_cfg.addnode[0],"1.2.3.4") && !strcmp(g_cfg.addnode[1],"5.6.7.8")
        && !strcmp(g_cfg.seednode[0],"9.9.9.9"))
        printf("PASS: addnode/seednode repeat and de-duplicate (%d addnode, %d seednode)\n",
               g_cfg.n_addnode, g_cfg.n_seednode);
    else { printf("FAIL: list parse (addnode=%d seednode=%d)\n", g_cfg.n_addnode, g_cfg.n_seednode); failures++; }

    /* 9. connect= implies dnsseed=0 and listen=0, as in Core */
    wr("/storage/bitcoinmachinecode/asm/bmc_t7.conf", "connect=10.0.0.1\nconnect=10.0.0.2\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t7.conf");
    if (g_cfg.connect_only==1 && g_cfg.n_connect==2 && g_cfg.dnsseed==0 && g_cfg.listen==0)
        printf("PASS: connect= implies dnsseed=0 listen=0 (2 nodes pinned)\n");
    else { printf("FAIL: connect implications (only=%d n=%d dnsseed=%d listen=%d)\n",
                  g_cfg.connect_only,g_cfg.n_connect,g_cfg.dnsseed,g_cfg.listen); failures++; }

    /* 10. an EXPLICIT listen=1/dnsseed=1 beats the implication -- and does so
     *     even when it appears BELOW connect=, because a config file must not
     *     change meaning with key order. */
    wr("/storage/bitcoinmachinecode/asm/bmc_t8.conf", "connect=10.0.0.1\nlisten=1\ndnsseed=1\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t8.conf");
    if (g_cfg.connect_only==1 && g_cfg.listen==1 && g_cfg.dnsseed==1)
        printf("PASS: explicit listen/dnsseed below connect= still win (order-independent)\n");
    else { printf("FAIL: order dependence (listen=%d dnsseed=%d)\n", g_cfg.listen, g_cfg.dnsseed); failures++; }

    /* 11. connect=0 -- no automatic connections, and no manual ones either */
    wr("/storage/bitcoinmachinecode/asm/bmc_t9.conf", "connect=0\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t9.conf");
    if (g_cfg.connect_only==1 && g_cfg.n_connect==0)
        printf("PASS: connect=0 disables automatic connections with an empty node list\n");
    else { printf("FAIL: connect=0 (only=%d n=%d)\n", g_cfg.connect_only, g_cfg.n_connect); failures++; }

    /* 12. manual-peer lookup drives the never-evict rule in the downloader */
    wr("/storage/bitcoinmachinecode/asm/bmc_t10.conf", "addnode=1.1.1.1\nconnect=2.2.2.2\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t10.conf");
    if (node_config_is_manual("1.1.1.1") && node_config_is_manual("2.2.2.2")
        && !node_config_is_manual("3.3.3.3") && !node_config_is_manual(""))
        printf("PASS: node_config_is_manual identifies addnode+connect peers only\n");
    else { printf("FAIL: is_manual wrong\n"); failures++; }

    /* 13. host:port -- the default port is stripped and kept; anything else is
     *     REJECTED rather than silently dialled on 8333 */
    wr("/storage/bitcoinmachinecode/asm/bmc_t11.conf", "addnode=4.4.4.4:8333\naddnode=5.5.5.5:18333\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t11.conf");
    if (g_cfg.n_addnode==1 && !strcmp(g_cfg.addnode[0],"4.4.4.4"))
        printf("PASS: :8333 stripped, non-default port rejected (not silently redirected)\n");
    else { printf("FAIL: port handling (n=%d first=%s)\n",
                  g_cfg.n_addnode, g_cfg.n_addnode?g_cfg.addnode[0]:"-"); failures++; }

    /* 14. more entries than the fixed array holds must not overflow it */
    { char big[8192]; int o=0;
      for(int i=0;i<CFG_MAX_NODES+8;i++) o+=snprintf(big+o,sizeof big-o,"addnode=10.1.%d.1\n",i);
      wr("/storage/bitcoinmachinecode/asm/bmc_t12.conf", big);
      node_config_load("/storage/bitcoinmachinecode/asm/bmc_t12.conf");
      if (g_cfg.n_addnode==CFG_MAX_NODES)
          printf("PASS: addnode list capped at CFG_MAX_NODES (%d) without overflow\n", CFG_MAX_NODES);
      else { printf("FAIL: cap not enforced (n=%d)\n", g_cfg.n_addnode); failures++; } }

    /* 15. a reload must not inherit the previous file's lists */
    wr("/storage/bitcoinmachinecode/asm/bmc_t13.conf", "maxconnections=64\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t13.conf");
    if (g_cfg.n_addnode==0 && g_cfg.n_connect==0 && g_cfg.n_seednode==0
        && g_cfg.connect_only==0 && g_cfg.dnsseed==1)
        printf("PASS: reload clears peer lists from the previous config\n");
    else { printf("FAIL: stale lists after reload (add=%d conn=%d seed=%d)\n",
                  g_cfg.n_addnode,g_cfg.n_connect,g_cfg.n_seednode); failures++; }

    /* ---- chain / storage: prune, checkblocks, checklevel, stopatheight ---- */

    /* 16. prune accepts 0 and 1 as MODES, and a real budget only at >=550 */
    wr("/storage/bitcoinmachinecode/asm/bmc_t14.conf", "prune=1\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t14.conf");
    if (g_cfg.prune_mib==1) printf("PASS: prune=1 (manual-only mode) accepted\n");
    else { printf("FAIL: prune=1 -> %ld\n", g_cfg.prune_mib); failures++; }

    wr("/storage/bitcoinmachinecode/asm/bmc_t15.conf", "prune=100\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t15.conf");
    if (g_cfg.prune_mib==0)
        printf("PASS: prune=100 rejected -- a budget below 550 MiB cannot hold a usable node\n");
    else { printf("FAIL: prune=100 accepted as %ld\n", g_cfg.prune_mib); failures++; }

    wr("/storage/bitcoinmachinecode/asm/bmc_t16.conf", "prune=2000\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t16.conf");
    if (g_cfg.prune_mib==2000) printf("PASS: prune=2000 accepted as a MiB budget\n");
    else { printf("FAIL: prune=2000 -> %ld\n", g_cfg.prune_mib); failures++; }

    /* 17. checkblocks/checklevel, including an out-of-range level */
    wr("/storage/bitcoinmachinecode/asm/bmc_t17.conf", "checkblocks=100\nchecklevel=4\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t17.conf");
    if (g_cfg.checkblocks==100 && g_cfg.checklevel==4)
        printf("PASS: checkblocks=100 checklevel=4 applied\n");
    else { printf("FAIL: checkblocks=%ld checklevel=%d\n", g_cfg.checkblocks, g_cfg.checklevel); failures++; }

    wr("/storage/bitcoinmachinecode/asm/bmc_t18.conf", "checklevel=9\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t18.conf");
    if (g_cfg.checklevel==3)
        printf("PASS: checklevel=9 rejected, Core default 3 kept\n");
    else { printf("FAIL: checklevel=%d\n", g_cfg.checklevel); failures++; }

    /* 18. checkblocks=0 means ALL blocks in Core, so it must be accepted as 0
     *     rather than treated as unset */
    wr("/storage/bitcoinmachinecode/asm/bmc_t19.conf", "checkblocks=0\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t19.conf");
    if (g_cfg.checkblocks==0) printf("PASS: checkblocks=0 accepted (means: check all)\n");
    else { printf("FAIL: checkblocks=%ld\n", g_cfg.checkblocks); failures++; }

    /* 19. stopatheight */
    wr("/storage/bitcoinmachinecode/asm/bmc_t20.conf", "stopatheight=500000\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t20.conf");
    if (g_cfg.stopatheight==500000) printf("PASS: stopatheight=500000 applied\n");
    else { printf("FAIL: stopatheight=%ld\n", g_cfg.stopatheight); failures++; }

    /* 20. the two keys we accept ONLY to warn about must not change anything,
     *     and must not disturb the rest of the parse */
    wr("/storage/bitcoinmachinecode/asm/bmc_t21.conf", "txindex=1\nassumevalid=00000000000000000008a89e854d57e5667df88f1cdef6fea2db3d5eeb8ea9c1\nmaxconnections=77\n");
    node_config_load("/storage/bitcoinmachinecode/asm/bmc_t21.conf");
    if (g_cfg.max_connections==77)
        printf("PASS: txindex/assumevalid warn without disturbing the parse\n");
    else { printf("FAIL: parse disturbed (conns=%d)\n", g_cfg.max_connections); failures++; }

    /* the fixtures are written into the repo dir; do not leave 13 stray
     * bmc_t*.conf files behind for the next `git status` to trip over. */
    { char rmpath[256];
      for(int i=1;i<=21;i++){
          snprintf(rmpath,sizeof rmpath,"/storage/bitcoinmachinecode/asm/bmc_t%d.conf",i);
          remove(rmpath);
      } }

    printf("\n");
    node_config_log();
    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures?1:0;
}
