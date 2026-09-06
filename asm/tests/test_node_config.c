/* node_config: Core-key compatibility, clamping, and wedge-proofing.
 *
 * The clamp tests matter as much as the parse tests: a config file is
 * OPERATOR input, not trusted input, and a bad tuning value is exactly what
 * stalled a live sync on 2026-08-18. A typo must not be able to reproduce
 * that. */
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "node_config.h"
#include "test_tmpdir.h"

static void wr(const char* path, const char* body){
    FILE* f=fopen(path,"w"); if(!f) return; fputs(body,f); fclose(f);
}

int main(void){
    tt_isolate();
    int failures=0;
    printf("---- node_config ----\n");

    /* 1. absent file -> compiled defaults, no crash */
    node_config_load("/nonexistent/bitcoin.conf");
    if (g_cfg.max_connections==200 && g_cfg.max_outbound==8 && g_cfg.dbcache_mb==1024)
        printf("PASS: missing file falls back to compiled defaults (Core v31 dbcache default 1024)\n");
    else { printf("FAIL: defaults wrong (conns=%d out=%d dbcache=%d)\n",
                  g_cfg.max_connections,g_cfg.max_outbound,g_cfg.dbcache_mb); failures++; }

    /* 2. the repo's SAMPLE config -- the tracked one. config/bitcoin.conf is
     * an operator file (rpcpassword) and is gitignored since 2026-08-29, so a
     * test that read it passed only on a machine that happened to have one.
     * The sample is every key at its default, ALL COMMENTED OUT, so the right
     * assertion is that it parses and changes nothing. */
    long n = node_config_load(tt_src("../config/bitcoin.sample.conf"));
    printf("  bitcoin.sample.conf applied %ld setting(s)\n", n);
    if (n == 0) printf("PASS: the sample config is fully commented out (applies nothing)\n");
    else { printf("FAIL: the sample config applied %ld setting(s); it must be all defaults, commented\n", n); failures++; }
    { /* and every key it documents must be one the parser knows: an
       * uncommented copy has to apply them all */
      FILE* f = fopen(tt_src("../config/bitcoin.sample.conf"), "r");
      FILE* o = fopen("uncommented.conf", "w");
      char line[512]; long keys = 0;
      if (f && o){
          while (fgets(line, sizeof line, f)){
              if (line[0] != '#' || !strchr(line, '=')) continue;
              const char* eq = strchr(line, '=');
              if (eq == line + 1) continue;                 /* "#=" is not a key */
              int alpha = 1;
              for (const char* c = line + 1; c < eq; c++) if (!(*c >= 'a' && *c <= 'z') && !(*c >= '0' && *c <= '9') && *c != '_') alpha = 0;
              if (!alpha) continue;
              if (!strncmp(line+1, "rpc", 3)) continue;     /* read by the RPC server, not this parser */
              /* an empty value (e.g. "#proxy=" or "#proxy=   # comment")
               * legitimately applies nothing, so only keys that carry a
               * value can be expected to count */
              const char* v = eq + 1;
              while (*v == ' ' || *v == '\t') v++;
              if (*v == '\n' || *v == 0 || *v == '#'){ fputs(line + 1, o); continue; }
              fputs(line + 1, o); keys++;
          }
      }
      if (f) fclose(f);
      if (o) fclose(o);
      long applied = node_config_load("uncommented.conf");
      printf("  sample documents %ld parser keys; uncommenting applied %ld\n", keys, applied);
      if (keys > 30 && applied >= keys)
          printf("PASS: the documented keys are keys the parser actually knows\n");
      else { printf("FAIL: %ld of %ld documented keys were not applied\n", keys - applied, keys); failures++; }
      unlink("uncommented.conf"); }
    /* dbcache still scales the memtable -- with its own file now that the
     * operator's config is no longer read here */
    { FILE* d = fopen("dbcache.conf", "w"); if (d){ fputs("dbcache=4096\n", d); fclose(d); } }
    node_config_load("dbcache.conf");
    if (g_cfg.utxo_bulk_slots_log2 > 22)
        printf("PASS: dbcache=4096 scaled the memtable up (2^%d slots, %dMB blob)\n",
               g_cfg.utxo_bulk_slots_log2, g_cfg.utxo_bulk_blob_mb);
    else { printf("FAIL: dbcache did not scale sizing (2^%d)\n", g_cfg.utxo_bulk_slots_log2); failures++; }
    unlink("dbcache.conf");
    node_config_load("/nonexistent/reset.conf");

    /* 3. out-of-range values are rejected, not applied */
    wr("bmc_t1.conf", "maxconnections=2\nbmc.peerminusable=0\nbmc.peerpool=-5\n");
    node_config_load("bmc_t1.conf");
    if (g_cfg.max_connections==200 && g_cfg.min_usable_peers==8 && g_cfg.maxpool==2048)
        printf("PASS: out-of-range values rejected, defaults kept\n");
    else { printf("FAIL: bad values applied (conns=%d usable=%d pool=%d)\n",
                  g_cfg.max_connections,g_cfg.min_usable_peers,g_cfg.maxpool); failures++; }

    /* 4. a config that would leave zero inbound slots must be refused wholesale */
    wr("bmc_t2.conf", "maxconnections=16\nbmc.maxoutbound=32\n");
    node_config_load("bmc_t2.conf");
    { int outb=g_cfg.max_outbound+g_cfg.max_block_relay_only+g_cfg.max_feeler;
      if (outb < g_cfg.max_connections)
          printf("PASS: no-inbound-slots config reverted (outbound %d < max %d)\n", outb, g_cfg.max_connections);
      else { printf("FAIL: node would have zero inbound slots (outbound %d, max %d)\n", outb, g_cfg.max_connections); failures++; } }

    /* 5b. Core knobs added for config parity */
    wr("bmc_t5.conf", "signet=1\nbytespersigop=50\ndisablewallet=1\ndebuglogfile=/tmp/bmc-test.log\nwalletdir=/tmp/bmc-wallets\n");
    node_config_load("bmc_t5.conf");
    if (!strcmp(g_cfg.chain,"signet") && g_cfg.bytespersigop==50 && g_cfg.disablewallet==1 &&
        !strcmp(g_cfg.debuglogfile,"/tmp/bmc-test.log") && !strcmp(g_cfg.walletdir,"/tmp/bmc-wallets"))
        printf("PASS: signet=1 / bytespersigop / disablewallet / debuglogfile / walletdir applied\n");
    else { printf("FAIL: parity knobs (chain=%s bps=%d dw=%d log=%s)\n", g_cfg.chain, g_cfg.bytespersigop,
                  g_cfg.disablewallet, g_cfg.debuglogfile); failures++; }
    wr("bmc_t6.conf", "bytespersigop=0\n");
    node_config_load("bmc_t6.conf");
    if (g_cfg.bytespersigop==20) printf("PASS: bytespersigop=0 rejected, default 20 kept\n");
    else { printf("FAIL: bytespersigop=0 applied (%d)\n", g_cfg.bytespersigop); failures++; }
    unlink("bmc_t5.conf"); unlink("bmc_t6.conf");

    /* 5. valid extension keys DO apply */
    wr("bmc_t3.conf", "bmc.feelers=0\nbmc.peerminticks=5\nbmc.addrmaxpernetgroup=4\n");
    node_config_load("bmc_t3.conf");
    if (g_cfg.max_feeler==0 && g_cfg.dead_weight_ticks==5 && g_cfg.addr_max_per_netgroup==4)
        printf("PASS: extension keys applied (feelers=0 ticks=5 netgroup=4)\n");
    else { printf("FAIL: extension keys not applied\n"); failures++; }

    /* 6. unknown/foreign keys ignored -> file stays shareable with Core */
    wr("bmc_t4.conf", "rpcuser=x\nrpcpassword=y\ntxindex=1\nprune=0\nwhitelist=rpc\nmaxconnections=64\n");
    node_config_load("bmc_t4.conf");
    if (g_cfg.max_connections==64)
        printf("PASS: foreign Core keys ignored without disturbing parsing\n");
    else { printf("FAIL: parsing disturbed by foreign keys (conns=%d)\n", g_cfg.max_connections); failures++; }

    /* ---- peer sourcing: dnsseed / seednode / addnode / connect ---- */

    /* 7. dnsseed=0 is honoured (it gates ALL DNS bootstrapping) */
    wr("bmc_t5.conf", "dnsseed=0\n");
    node_config_load("bmc_t5.conf");
    if (g_cfg.dnsseed==0 && g_cfg.connect_only==0)
        printf("PASS: dnsseed=0 honoured without implying connect-only\n");
    else { printf("FAIL: dnsseed=%d connect_only=%d\n", g_cfg.dnsseed, g_cfg.connect_only); failures++; }

    /* 8. the repeatable keys accumulate, and duplicates collapse */
    wr("bmc_t6.conf",
       "addnode=1.2.3.4\naddnode=5.6.7.8\naddnode=1.2.3.4\nseednode=9.9.9.9\n");
    node_config_load("bmc_t6.conf");
    if (g_cfg.n_addnode==2 && g_cfg.n_seednode==1
        && !strcmp(g_cfg.addnode[0],"1.2.3.4") && !strcmp(g_cfg.addnode[1],"5.6.7.8")
        && !strcmp(g_cfg.seednode[0],"9.9.9.9"))
        printf("PASS: addnode/seednode repeat and de-duplicate (%d addnode, %d seednode)\n",
               g_cfg.n_addnode, g_cfg.n_seednode);
    else { printf("FAIL: list parse (addnode=%d seednode=%d)\n", g_cfg.n_addnode, g_cfg.n_seednode); failures++; }

    /* 9. connect= implies dnsseed=0 and listen=0, as in Core */
    wr("bmc_t7.conf", "connect=10.0.0.1\nconnect=10.0.0.2\n");
    node_config_load("bmc_t7.conf");
    if (g_cfg.connect_only==1 && g_cfg.n_connect==2 && g_cfg.dnsseed==0 && g_cfg.listen==0)
        printf("PASS: connect= implies dnsseed=0 listen=0 (2 nodes pinned)\n");
    else { printf("FAIL: connect implications (only=%d n=%d dnsseed=%d listen=%d)\n",
                  g_cfg.connect_only,g_cfg.n_connect,g_cfg.dnsseed,g_cfg.listen); failures++; }

    /* 10. an EXPLICIT listen=1/dnsseed=1 beats the implication -- and does so
     *     even when it appears BELOW connect=, because a config file must not
     *     change meaning with key order. */
    wr("bmc_t8.conf", "connect=10.0.0.1\nlisten=1\ndnsseed=1\n");
    node_config_load("bmc_t8.conf");
    if (g_cfg.connect_only==1 && g_cfg.listen==1 && g_cfg.dnsseed==1)
        printf("PASS: explicit listen/dnsseed below connect= still win (order-independent)\n");
    else { printf("FAIL: order dependence (listen=%d dnsseed=%d)\n", g_cfg.listen, g_cfg.dnsseed); failures++; }

    /* 11. connect=0 -- no automatic connections, and no manual ones either */
    wr("bmc_t9.conf", "connect=0\n");
    node_config_load("bmc_t9.conf");
    if (g_cfg.connect_only==1 && g_cfg.n_connect==0)
        printf("PASS: connect=0 disables automatic connections with an empty node list\n");
    else { printf("FAIL: connect=0 (only=%d n=%d)\n", g_cfg.connect_only, g_cfg.n_connect); failures++; }

    /* 12. manual-peer lookup drives the never-evict rule in the downloader */
    wr("bmc_t10.conf", "addnode=1.1.1.1\nconnect=2.2.2.2\n");
    node_config_load("bmc_t10.conf");
    if (node_config_is_manual("1.1.1.1") && node_config_is_manual("2.2.2.2")
        && !node_config_is_manual("3.3.3.3") && !node_config_is_manual(""))
        printf("PASS: node_config_is_manual identifies addnode+connect peers only\n");
    else { printf("FAIL: is_manual wrong\n"); failures++; }

    /* 13. host:port -- ANY port is honoured (Core does), the host is stored
     *     BARE (those strings reach inet_pton/address-book paths) and the
     *     port lands in the parallel array that the dial paths read through
     *     node_config_peer_port. This used to reject every non-default port,
     *     which dropped the entry SILENTLY and left the node at peers=0/0. */
    wr("bmc_t11.conf", "addnode=4.4.4.4:8333\naddnode=5.5.5.5:18333\n"
                       "addnode=6.6.6.6\n");
    node_config_load("bmc_t11.conf");
    if (g_cfg.n_addnode==3
        && !strcmp(g_cfg.addnode[0],"4.4.4.4") && !strcmp(g_cfg.addnode[1],"5.5.5.5")
        && !strcmp(g_cfg.addnode[2],"6.6.6.6")
        && node_config_peer_port("4.4.4.4")==8333
        && node_config_peer_port("5.5.5.5")==18333   /* the case that used to be dropped */
        && node_config_peer_port("6.6.6.6")==0       /* no port named -> chain default */
        && node_config_peer_port("9.9.9.9")==0)      /* not configured at all */
        printf("PASS: any host:port is honoured; host stored bare, port beside it\n");
    else { printf("FAIL: port handling (n=%d first=%s p5=%d p6=%d)\n",
                  g_cfg.n_addnode, g_cfg.n_addnode?g_cfg.addnode[0]:"-",
                  node_config_peer_port("5.5.5.5"), node_config_peer_port("6.6.6.6"));
           failures++; }

    /* 13b. a malformed or out-of-range port is still refused outright -- the
     *      point of the change was to honour real ports, not to stop
     *      validating. */
    wr("bmc_t11b.conf", "addnode=7.7.7.7:0\naddnode=8.8.8.8:70000\n"
                        "addnode=9.9.9.9:abc\n");
    node_config_load("bmc_t11b.conf");
    if (g_cfg.n_addnode==0)
        printf("PASS: port 0, out-of-range and non-numeric ports are all refused\n");
    else { printf("FAIL: bad ports accepted (n=%d)\n", g_cfg.n_addnode); failures++; }

    /* 14. more entries than the fixed array holds must not overflow it */
    { char big[8192]; int o=0;
      for(int i=0;i<CFG_MAX_NODES+8;i++) o+=snprintf(big+o,sizeof big-o,"addnode=10.1.%d.1\n",i);
      wr("bmc_t12.conf", big);
      node_config_load("bmc_t12.conf");
      if (g_cfg.n_addnode==CFG_MAX_NODES)
          printf("PASS: addnode list capped at CFG_MAX_NODES (%d) without overflow\n", CFG_MAX_NODES);
      else { printf("FAIL: cap not enforced (n=%d)\n", g_cfg.n_addnode); failures++; } }

    /* 15. a reload must not inherit the previous file's lists */
    wr("bmc_t13.conf", "maxconnections=64\n");
    node_config_load("bmc_t13.conf");
    if (g_cfg.n_addnode==0 && g_cfg.n_connect==0 && g_cfg.n_seednode==0
        && g_cfg.connect_only==0 && g_cfg.dnsseed==1)
        printf("PASS: reload clears peer lists from the previous config\n");
    else { printf("FAIL: stale lists after reload (add=%d conn=%d seed=%d)\n",
                  g_cfg.n_addnode,g_cfg.n_connect,g_cfg.n_seednode); failures++; }

    /* ---- chain / storage: prune, checkblocks, checklevel, stopatheight ---- */

    /* 16. prune accepts 0 and 1 as MODES, and a real budget only at >=550 */
    wr("bmc_t14.conf", "prune=1\n");
    node_config_load("bmc_t14.conf");
    if (g_cfg.prune_mib==1) printf("PASS: prune=1 (manual-only mode) accepted\n");
    else { printf("FAIL: prune=1 -> %ld\n", g_cfg.prune_mib); failures++; }

    wr("bmc_t15.conf", "prune=100\n");
    node_config_load("bmc_t15.conf");
    if (g_cfg.prune_mib==0)
        printf("PASS: prune=100 rejected -- a budget below 550 MiB cannot hold a usable node\n");
    else { printf("FAIL: prune=100 accepted as %ld\n", g_cfg.prune_mib); failures++; }

    wr("bmc_t16.conf", "prune=2000\n");
    node_config_load("bmc_t16.conf");
    if (g_cfg.prune_mib==2000) printf("PASS: prune=2000 accepted as a MiB budget\n");
    else { printf("FAIL: prune=2000 -> %ld\n", g_cfg.prune_mib); failures++; }

    /* 17. checkblocks/checklevel, including an out-of-range level */
    wr("bmc_t17.conf", "checkblocks=100\nchecklevel=4\n");
    node_config_load("bmc_t17.conf");
    if (g_cfg.checkblocks==100 && g_cfg.checklevel==4)
        printf("PASS: checkblocks=100 checklevel=4 applied\n");
    else { printf("FAIL: checkblocks=%ld checklevel=%d\n", g_cfg.checkblocks, g_cfg.checklevel); failures++; }

    wr("bmc_t18.conf", "checklevel=9\n");
    node_config_load("bmc_t18.conf");
    if (g_cfg.checklevel==3)
        printf("PASS: checklevel=9 rejected, Core default 3 kept\n");
    else { printf("FAIL: checklevel=%d\n", g_cfg.checklevel); failures++; }

    /* 18. checkblocks=0 means ALL blocks in Core, so it must be accepted as 0
     *     rather than treated as unset */
    wr("bmc_t19.conf", "checkblocks=0\n");
    node_config_load("bmc_t19.conf");
    if (g_cfg.checkblocks==0) printf("PASS: checkblocks=0 accepted (means: check all)\n");
    else { printf("FAIL: checkblocks=%ld\n", g_cfg.checkblocks); failures++; }

    /* 19. stopatheight */
    wr("bmc_t20.conf", "stopatheight=500000\n");
    node_config_load("bmc_t20.conf");
    if (g_cfg.stopatheight==500000) printf("PASS: stopatheight=500000 applied\n");
    else { printf("FAIL: stopatheight=%ld\n", g_cfg.stopatheight); failures++; }

    /* 20. the two keys we accept ONLY to warn about must not change anything,
     *     and must not disturb the rest of the parse */
    wr("bmc_t21.conf", "txindex=1\nassumevalid=00000000000000000008a89e854d57e5667df88f1cdef6fea2db3d5eeb8ea9c1\nmaxconnections=77\n");
    node_config_load("bmc_t21.conf");
    if (g_cfg.max_connections==77)
        printf("PASS: txindex warns without disturbing the parse\n");
    else { printf("FAIL: parse disturbed (conns=%d)\n", g_cfg.max_connections); failures++; }
    /* assumevalid is honoured when set (2026-09-01): stored in wire order */
    if (g_cfg.assumevalid_mode==1 && g_cfg.assumevalid[31]==0x00 && g_cfg.assumevalid[0]==0xc1 && g_cfg.assumevalid[1]==0xa9)
        printf("PASS: assumevalid parsed into wire order\n");
    else { printf("FAIL: assumevalid not parsed (mode=%d b0=%02x)\n", g_cfg.assumevalid_mode, g_cfg.assumevalid[0]); failures++; }
    wr("bmc_t22.conf", "assumevalid=0\n");
    node_config_load("bmc_t22.conf");
    if (g_cfg.assumevalid_mode==2) printf("PASS: assumevalid=0 evaluates every script\n");
    else { printf("FAIL: assumevalid=0 not honoured (mode=%d)\n", g_cfg.assumevalid_mode); failures++; }
    wr("bmc_t23.conf", "assumevalid=notahash\n");
    node_config_load("bmc_t23.conf");
    if (g_cfg.assumevalid_mode==0) printf("PASS: a malformed assumevalid is ignored (chain default stays)\n");
    else { printf("FAIL: malformed assumevalid accepted (mode=%d)\n", g_cfg.assumevalid_mode); failures++; }

    /* The fixtures used to be written into the repo dir by absolute path -- into
     * the MAIN checkout, even from a worktree -- and were removed only on this
     * success path. They now live in the private working directory, which goes
     * away on every exit path including a crash. */

    /* ---- 2026-09-01: option-surface completion ---- */
    wr("cs1.conf",
       "uacomment=hello\nuacomment=bad(paren)\nuacomment=second one\n"
       "blockmaxweight=3000000\nblockreservedweight=4000\nblockmintxfee=0.00001\nblockversion=536870913\nprintpriority=1\n"
       "mintxfee=0.00002\nfallbackfee=0.0002\ndiscardfee=0.00005\nconsolidatefeerate=0.00003\nmaxapsfee=-1\n"
       "avoidpartialspends=1\nspendzeroconfchange=0\nwalletrbf=0\ntxconfirmtarget=3\nwalletbroadcast=0\nkeypool=50\n"
       "walletnotify=/bin/true %s\nwallet=alpha\nwallet=beta\nwallet=has/slash\naddresstype=legacy\nchangetype=bech32m\n"
       "maxtipage=3600\ninboundrelaypercent=25\nwhitelistrelay=0\nwhitelistforcerelay=1\npeerblockfilters=1\nfixedseeds=0\n"
       "logtimestamps=0\nlogtimemicros=1\nlogthreadnames=1\nlogsourcelocations=1\nshrinkdebugfile=0\n"
       "rpcthreads=4\nrpcworkqueue=8\nrpcservertimeout=5\nrpcwhitelist=alice:getblockcount,getbestblockhash\nrpcwhitelist=nocolon\n"
       "rpcwhitelistdefault=0\nrpccookieperms=group\nlimitclustercount=30\nlimitclustersize=50\n"
       "addresstype=nonsense\ntxconfirmtarget=5000\nblockmaxweight=1\n");
    node_config_load("cs1.conf");
    if (g_cfg.n_uacomment==2 && !strcmp(g_cfg.uacomment[0],"hello") && !strcmp(g_cfg.uacomment[1],"second one"))
        printf("PASS: uacomment: two safe comments kept, the one with parentheses refused\n");
    else { printf("FAIL: uacomment (n=%d)\n", g_cfg.n_uacomment); failures++; }
    if (g_cfg.blockmaxweight==3000000 && g_cfg.blockreservedweight==4000 && g_cfg.blockmintxfee_satkvb==1000 && g_cfg.blockversion==536870913 && g_cfg.printpriority==1)
        printf("PASS: mining options parsed (blockmintxfee 0.00001 BTC/kvB = 1000 sat/kvB); blockmaxweight=1 refused\n");
    else { printf("FAIL: mining options (%d %d %ld %d)\n", g_cfg.blockmaxweight, g_cfg.blockreservedweight, g_cfg.blockmintxfee_satkvb, g_cfg.blockversion); failures++; }
    if (g_cfg.mintxfee_satkvb==2000 && g_cfg.fallbackfee_satkvb==20000 && g_cfg.discardfee_satkvb==5000 && g_cfg.consolidatefeerate_satkvb==3000 && g_cfg.maxapsfee_sat==-1)
        printf("PASS: wallet fee options in sat/kvB; maxapsfee=-1 means always\n");
    else { printf("FAIL: wallet fees (%ld %ld %ld %ld %ld)\n", g_cfg.mintxfee_satkvb, g_cfg.fallbackfee_satkvb, g_cfg.discardfee_satkvb, g_cfg.consolidatefeerate_satkvb, g_cfg.maxapsfee_sat); failures++; }
    if (g_cfg.avoidpartialspends==1 && g_cfg.spendzeroconfchange==0 && g_cfg.walletrbf==0 && g_cfg.txconfirmtarget==3 && g_cfg.walletbroadcast==0 && g_cfg.keypool==50)
        printf("PASS: wallet bools/ints; txconfirmtarget=5000 (over 1008) refused, 3 kept\n");
    else { printf("FAIL: wallet bools (%d %d %d %d %d %d)\n", g_cfg.avoidpartialspends, g_cfg.spendzeroconfchange, g_cfg.walletrbf, g_cfg.txconfirmtarget, g_cfg.walletbroadcast, g_cfg.keypool); failures++; }
    if (!strcmp(g_cfg.walletnotify, "/bin/true %s") && g_cfg.n_wallet_names==2 && !strcmp(g_cfg.wallet_names[1],"beta"))
        printf("PASS: walletnotify kept; wallet= names collected, a path refused\n");
    else { printf("FAIL: walletnotify/wallet (%s n=%d)\n", g_cfg.walletnotify, g_cfg.n_wallet_names); failures++; }
    if (!strcmp(g_cfg.addresstype,"legacy") && !strcmp(g_cfg.changetype,"bech32m"))
        printf("PASS: addresstype/changetype validated (nonsense refused, legacy kept)\n");
    else { printf("FAIL: address types (%s/%s)\n", g_cfg.addresstype, g_cfg.changetype); failures++; }
    if (g_cfg.maxtipage==3600 && g_cfg.inboundrelaypercent==25 && g_cfg.whitelistrelay==0 && g_cfg.whitelistforcerelay==1 && g_cfg.peerblockfilters==1 && g_cfg.fixedseeds==0)
        printf("PASS: peer options parsed\n");
    else { printf("FAIL: peer options\n"); failures++; }
    if (g_cfg.logtimestamps==0 && g_cfg.logtimemicros==1 && g_cfg.logthreadnames==1 && g_cfg.logsourcelocations==1 && g_cfg.shrinkdebugfile==0)
        printf("PASS: logging options parsed\n");
    else { printf("FAIL: logging options\n"); failures++; }
    if (g_cfg.rpcthreads==4 && g_cfg.rpcworkqueue==8 && g_cfg.rpcservertimeout==5 && g_cfg.n_rpcwhitelist==1 && g_cfg.rpcwhitelistdefault==0 && g_cfg.rpccookieperms==1)
        printf("PASS: rpc server options; a whitelist without ':' refused\n");
    else { printf("FAIL: rpc options (%d %d %d n=%d d=%d p=%d)\n", g_cfg.rpcthreads, g_cfg.rpcworkqueue, g_cfg.rpcservertimeout, g_cfg.n_rpcwhitelist, g_cfg.rpcwhitelistdefault, g_cfg.rpccookieperms); failures++; }
    if (g_cfg.limitclustercount==30 && g_cfg.limitancestorcount==30 && g_cfg.limitdescendantcount==30 && g_cfg.limitclustersize_kvb==50 && g_cfg.limitancestorsize_kvb==50)
        printf("PASS: limitclustercount/size map onto the ancestor and descendant limits\n");
    else { printf("FAIL: cluster limits\n"); failures++; }
    /* includeconf: relative to the main file, once, not from an included file */
    wr("inc_main.conf", "maxconnections=77\nincludeconf=inc_a.conf\n");
    wr("inc_a.conf", "maxconnections=88\ndbcache=2048\nincludeconf=inc_b.conf\n");
    wr("inc_b.conf", "maxconnections=99\n");
    node_config_load("inc_main.conf");
    if (g_cfg.max_connections==88 && g_cfg.dbcache_mb==2048)
        printf("PASS: includeconf read after the main file (its value wins), nested includeconf ignored\n");
    else { printf("FAIL: includeconf (conns=%d dbcache=%d)\n", g_cfg.max_connections, g_cfg.dbcache_mb); failures++; }
    /* signetseednode applies only on signet */
    wr("sig1.conf", "signetseednode=1.2.3.4:38333\nchain=signet\n");
    node_config_load("sig1.conf");
    int sig_ok = g_cfg.n_seednode==1 && !strcmp(g_cfg.seednode[0],"1.2.3.4:38333");
    wr("sig2.conf", "signetseednode=1.2.3.4:38333\nchain=main\n");
    node_config_load("sig2.conf");
    if (sig_ok && g_cfg.n_seednode==0) printf("PASS: signetseednode becomes a seednode on signet only\n");
    else { printf("FAIL: signetseednode (signet ok=%d main n=%d)\n", sig_ok, g_cfg.n_seednode); failures++; }
    /* no-effect Core options are recognised with a reason */
    if (nodecfg_noeffect_reason("mocktime") && nodecfg_noeffect_reason("rest") && !nodecfg_noeffect_reason("uacomment") && !nodecfg_noeffect_reason("dbcache"))
        printf("PASS: no-effect table names mocktime/rest, not implemented keys\n");
    else { printf("FAIL: no-effect table\n"); failures++; }
    node_config_load("/nonexistent/reset.conf");
    if (g_cfg.blockmaxweight==4000000 && g_cfg.txconfirmtarget==6 && g_cfg.walletrbf==1 && g_cfg.rpcthreads==16 && g_cfg.maxtipage==86400 && !strcmp(g_cfg.addresstype,"bech32") && g_cfg.n_uacomment==0)
        printf("PASS: Core defaults restored on reload\n");
    else { printf("FAIL: defaults after reload\n"); failures++; }

    /* ================================================================
     * DMN-4 (audit 2026-09-03): config-file SECTIONS and NEGATION.
     *
     * A `[section]` line has no `=`, so the parser skipped it and applied
     * every following key unconditionally. The reachable consequence is the
     * one Core's own scoping exists to prevent: an operator reusing a Core
     * bitcoin.conf with the common dev block
     *
     *     [regtest]
     *     rpcallowip=0.0.0.0/0
     *     rpcbind=0.0.0.0
     *
     * while running MAINNET had those applied -- the mainnet RPC server bound
     * every interface and accepted every source. And `no<key>` negation was
     * not implemented at all, so `nolisten=1` was read as an unknown key and
     * listening stayed on.
     * ================================================================ */
    printf("\n---- DMN-4: sections and negation ----\n");

    /* (1) A key under a foreign section must NOT apply. */
    wr("sec_foreign.conf",
       "chain=main\n"
       "maxconnections=200\n"
       "[regtest]\n"
       "maxconnections=999\n"
       "port=18444\n");
    node_config_load("sec_foreign.conf");
    if (g_cfg.max_connections == 200 && g_cfg.port != 18444)
        printf("PASS: [regtest] keys do NOT apply while chain=main\n");
    else { printf("FAIL: [regtest] key leaked into main (conns=%d port=%d)\n",
                  g_cfg.max_connections, g_cfg.port); failures++; }

    /* (2) The SAME file on the chain it names must apply. This is what stops
     * "ignore everything sectioned" from passing as a fix. */
    wr("sec_match.conf",
       "regtest=1\n"
       "maxconnections=200\n"
       "[regtest]\n"
       "maxconnections=999\n");
    node_config_load("sec_match.conf");
    if (g_cfg.max_connections == 999 && !strcmp(g_cfg.chain, "regtest"))
        printf("PASS: [regtest] keys DO apply when the chain is regtest\n");
    else { printf("FAIL: [regtest] key ignored on regtest (conns=%d chain=%s)\n",
                  g_cfg.max_connections, g_cfg.chain); failures++; }

    /* (3a) A chain selector INSIDE a section does not select the chain. Core
     * honours -chain/-regtest/-signet only in the base section, and it has to
     * be that way: a [regtest] section that could switch the node to regtest
     * would make every such section self-activating. */
    wr("sec_selector.conf",
       "maxconnections=200\n"
       "[regtest]\n"
       "chain=regtest\n"
       "maxconnections=777\n");
    node_config_load("sec_selector.conf");
    if (!strcmp(g_cfg.chain, "main") && g_cfg.max_connections == 200)
        printf("PASS: chain= inside a section does not select that chain\n");
    else { printf("FAIL: sectioned chain selector (chain=%s conns=%d)\n",
                  g_cfg.chain, g_cfg.max_connections); failures++; }

    /* (3b) A base-section selector works wherever it sits in that section --
     * including as its LAST line, below keys that depend on it. This is why
     * the file is read twice; a file must not mean different things depending
     * on line order. */
    wr("sec_order.conf",
       "maxconnections=200\n"
       "regtest=1\n"
       "[regtest]\n"
       "maxconnections=777\n");
    node_config_load("sec_order.conf");
    if (g_cfg.max_connections == 777 && !strcmp(g_cfg.chain, "regtest"))
        printf("PASS: a base-section selector governs sections that follow it\n");
    else { printf("FAIL: section/chain ordering (conns=%d chain=%s)\n",
                  g_cfg.max_connections, g_cfg.chain); failures++; }

    /* (4) The audit's actual scenario, end to end. */
    wr("sec_audit.conf",
       "chain=main\n"
       "[regtest]\n"
       "rpcallowip=0.0.0.0/0\n"
       "rpcbind=0.0.0.0\n"
       "connect=127.0.0.1:18444\n");
    node_config_load("sec_audit.conf");
    if (g_cfg.rpcbind[0] == 0 && !g_cfg.connect_only)
        printf("PASS: a [regtest] dev block does not open the MAINNET rpc or pin its peer\n");
    else { printf("FAIL: [regtest] dev block applied to mainnet (rpcbind='%s' connect_only=%d)\n",
                  g_cfg.rpcbind, g_cfg.connect_only); failures++; }

    /* (5) Negation: noX=1 means X=0, noX=0 means X=1. */
    wr("neg1.conf", "chain=main\nlisten=1\nnolisten=1\n");
    node_config_load("neg1.conf");
    if (g_cfg.listen == 0) printf("PASS: nolisten=1 turns listen off\n");
    else { printf("FAIL: nolisten=1 ignored (listen=%d)\n", g_cfg.listen); failures++; }

    wr("neg2.conf", "chain=main\nnolisten=0\n");
    node_config_load("neg2.conf");
    if (g_cfg.listen == 1) printf("PASS: nolisten=0 turns listen on (Core's -noX=0)\n");
    else { printf("FAIL: nolisten=0 (listen=%d)\n", g_cfg.listen); failures++; }

    /* (6) A network-specific key outside any section is ignored on a
     * non-main chain, and honoured on main. */
    wr("netspec.conf", "chain=regtest\nport=8333\n");
    node_config_load("netspec.conf");
    int rt_port = g_cfg.port_explicit;
    wr("netspec2.conf", "chain=main\nport=8333\n");
    node_config_load("netspec2.conf");
    if (!rt_port && g_cfg.port == 8333)
        printf("PASS: a bare port= is ignored off mainnet and honoured on it\n");
    else { printf("FAIL: network-specific base-section rule (rt_explicit=%d main port=%d)\n",
                  rt_port, g_cfg.port); failures++; }

    /* (7) The predicates themselves, so a reader can see the rules. */
    if (nodecfg_section_is("regtest","regtest") && !nodecfg_section_is("regtest","main")
        && nodecfg_is_network_specific("rpcallowip") && !nodecfg_is_network_specific("dbcache")
        && nodecfg_known_key("listen") && !nodecfg_known_key("nolisten"))
        printf("PASS: section/network-specific/known-key predicates\n");
    else { printf("FAIL: DMN-4 predicates\n"); failures++; }

    node_config_load("/nonexistent/reset.conf");

    /* ---- DMN-9 (audit 2026-09-03): integer parsing wraps before clamping ----
     *
     * Every numeric key went through atoi, which truncates strtol's long to
     * an int, so maxconnections=4294967496 wrapped to 200 -- a plausible
     * value that passed the clamp meant to catch exactly this. And bantime
     * was atol with only a `> 0` test: main.c computes time(NULL) + bantime,
     * so a huge value wraps NEGATIVE and every automatic ban expires on the
     * next check. That one is FAIL-OPEN -- banning quietly turns itself off.
     *
     * The controls are the wrapped values themselves: 4294967496 must not
     * read as 200, and a saturating bantime must not read as something that
     * makes time()+bantime negative. */
    node_config_load("/nonexistent/reset.conf");
    /* 4294967373 = 2^32 + 77, so atoi's truncation yields 77 -- an entirely
     * legal value that passes the clamp. NOT the audit's own 4294967496,
     * which wraps to exactly 200: that is also the DEFAULT, so "wrapped" and
     * "rejected, default kept" are indistinguishable and the assertion would
     * pass either way. (It did, on the first run of this test.) */
    wr("dmn9_a.conf", "maxconnections=4294967373\n");
    node_config_load("dmn9_a.conf");
    if (g_cfg.max_connections != 77)
        printf("PASS DMN-9: maxconnections=2^32+77 did not wrap to 77 (got %d)\n",
               g_cfg.max_connections);
    else { printf("FAIL DMN-9: maxconnections=2^32+77 wrapped to 77\n"); failures++; }

    node_config_load("/nonexistent/reset.conf");
    wr("dmn9_b.conf", "bantime=9223372036854775807\n");
    node_config_load("dmn9_b.conf");
    { long long until = (long long)time(NULL) + (long long)g_cfg.bantime;
      if (g_cfg.bantime > 0 && until > (long long)time(NULL))
          printf("PASS DMN-9: a saturating bantime still yields a FUTURE expiry (bantime=%ld)\n",
                 (long)g_cfg.bantime);
      else { printf("FAIL DMN-9: bantime=%ld makes the ban expire immediately (until=%lld)\n",
                    (long)g_cfg.bantime, until); failures++; } }

    node_config_load("/nonexistent/reset.conf");
    wr("dmn9_c.conf", "bantime=3600\n");
    node_config_load("dmn9_c.conf");
    if (g_cfg.bantime == 3600) printf("PASS DMN-9: an ordinary bantime is untouched\n");
    else { printf("FAIL DMN-9: bantime=3600 read as %ld\n", (long)g_cfg.bantime); failures++; }

    node_config_load("/nonexistent/reset.conf");
    wr("dmn9_d.conf", "maxconnections=64\n");
    node_config_load("dmn9_d.conf");
    if (g_cfg.max_connections == 64) printf("PASS DMN-9: an ordinary maxconnections is untouched\n");
    else { printf("FAIL DMN-9: maxconnections=64 read as %d\n", g_cfg.max_connections); failures++; }

    printf("\n");
    node_config_log();
    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures?1:0;
}
