/* node_config: Core-key compatibility, clamping, and wedge-proofing.
 *
 * The clamp tests matter as much as the parse tests: a config file is
 * OPERATOR input, not trusted input, and a bad tuning value is exactly what
 * stalled a live sync on 2026-08-18. A typo must not be able to reproduce
 * that. */
#include <stdio.h>
#include <string.h>
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
    if (g_cfg.max_connections==125 && g_cfg.min_usable_peers==8 && g_cfg.maxpool==2048)
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

    printf("\n");
    node_config_log();
    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures?1:0;
}
