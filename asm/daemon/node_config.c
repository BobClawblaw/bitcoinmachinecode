/* daemon/node_config.c -- see node_config.h for why this exists.
 *
 * Parser is deliberately the same shape as daemon/bitcoin_rpcd.c's
 * load_config (key=value, '#' comments, whitespace-trimmed): that one already
 * reads bitcoin.conf correctly, and this codebase has twice been bitten by a
 * second implementation of something that already existed and then rotted
 * (daemon/addrgather.c's addr parser, daemon/build_utxo.c's missing rule).
 * Unknown keys are ignored, so the file stays shared with the RPC daemon.
 */
#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <limits.h>
#define NODECFG_BANTIME_MAX (100LL*365*24*3600)   /* DMN-9: 100 years */
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "node_config.h"
#include "netperm.h"

/* STATICALLY initialised to the compiled defaults.
 *
 * g_cfg must be valid even if node_config_load() is never called. It is read
 * by daemon/utxo_live.c, addr_ingest.c and main.c, and several test harnesses
 * link those without any config step -- with a plain `node_config_t g_cfg;`
 * they got an all-zero struct, so utxo_live sized its memtable as
 * (1UL << 0) == 1 slot with a 0-byte blob and crashed (signal 11 in
 * test_reorg, 11 suite failures). Defaults belong at the definition, not
 * only in a loader the caller might skip. set_defaults() re-applies these
 * so a second load starts from a known base rather than the previous file. */
node_config_t g_cfg = {
    .max_connections       = 200,      /* Core v31 -maxconnections default   */
    .max_outbound          = 8,
    .max_block_relay_only  = 2,
    .max_feeler            = 1,
    .feeler_interval_ms    = 120000L,
    .dead_weight_bps       = 32768.0,
    .dead_weight_ticks     = 3,
    .min_usable_peers      = 8,
    .maxpool               = 2048,
    .addr_max_per_response = 256,
    .addr_max_per_netgroup = 16,
    .utxo_bulk_slots_log2  = 22,
    .utxo_bulk_blob_mb     = 1024,
    .utxo_bulk_gap_blocks  = 50000L,
    .utxo_compact_threshold= 12,
    .dbcache_mb            = 1024,     /* Core v31 -dbcache default (MiB)    */
    .connect_timeout_ms    = 5000,     /* Core v31 -timeout default          */
    .peer_timeout_s        = 60,
    .port                  = 8333,
    .port_explicit         = 0,
    .chain                 = "main",
    .listen                = 1,
    .addrindex             = 0,      /* extension index: off unless asked    */
    .blocksonly            = 0,
    .bind_addr             = "",     /* empty == INADDR_ANY */
    .par                   = 0,      /* Core -par default: auto              */
    .maxrecvbuffer_kb      = 5000,   /* Core -maxreceivebuffer default       */
    .maxmempool_mb         = 300,    /* Core -maxmempool default (MB)        */
    .mempoolexpiry_h       = 336,    /* Core -mempoolexpiry default (2 weeks)*/
    .maxuploadtarget_mb    = 0,      /* Core -maxuploadtarget default: none  */
    .minrelaytxfee_satkvb  = 100,    /* Core -minrelaytxfee 0.000001 BTC/kvB (v30: 0.1 sat/vB) */
    .incrementalrelayfee_satkvb = 100, /* Core -incrementalrelayfee default (v30)             */
    .limitancestorcount    = 64,     /* Core v31 accepts by CLUSTER (64 txs / 101 kvB); 25 is only the wallet default now */
    .limitancestorsize_kvb = 101,    /* Core -limitancestorsize default (kvB)*/
    .limitdescendantcount  = 64,     /* same: a chain of up to 64 is one cluster of 64   */
    .limitdescendantsize_kvb = 101,  /* Core -limitdescendantsize default    */
    .mempoolfullrbf        = 1,      /* Core -mempoolfullrbf default (v28+)  */
    .dustrelayfee_satkvb   = 3000,   /* Core DUST_RELAY_TX_FEE               */
    .datacarrier           = 1,      /* Core -datacarrier default            */
    .datacarriersize       = 100000, /* Core v31 -datacarriersize default    */
    .acceptnonstdtxn       = 0,      /* Core -acceptnonstdtxn default        */
    .dnsseed               = 1,      /* Core -dnsseed default: on            */
    /* Core DEFAULT_PROXYRANDOMIZE = true: random SOCKS5 credentials per
     * connection, so tor gives each its own circuit. Documented as
     * "default 1" in node_config.h and never actually defaulted until
     * 2026-08-28 -- which left stream isolation OFF for exactly the
     * operator who configured nothing but a proxy. */
    .proxyrandomize        = 1,
    .privatebroadcast      = 0,      /* Core DEFAULT_PRIVATE_BROADCAST         */
    .dns                   = 1,      /* Core -dns default: on                */
    .discover              = 1,      /* Core -discover default: on           */
    .i2pacceptincoming     = 1,      /* Core -i2pacceptincoming default: on  */
    .listenonion           = 1,      /* Core -listenonion default: on        */
    .bantime               = 86400,  /* Core -bantime default: 24h           */
    .blockfilterindex      = 1,      /* both indexes already run; the knob    */
    .coinstatsindex        = 1,      /* only lets an operator turn them OFF   */
    .rpccookie             = 1,      /* Core's default auth method            */
    .permitbaremultisig    = 1,      /* Core DEFAULT_PERMIT_BAREMULTISIG      */
    .v2transport           = 1,      /* Core DEFAULT_V2_TRANSPORT             */
    .persistmempool        = 1,      /* Core DEFAULT_PERSIST_MEMPOOL          */
    .reindex_chainstate    = 0,      /* one-shot; never a standing default    */
    .networkactive         = 1,      /* Core -networkactive default: on       */
    .forcednsseed          = 0,      /* Core -forcednsseed default: off       */
    .connect_only          = 0,
    .n_seednode            = 0,
    .n_addnode             = 0,
    .n_connect             = 0,
    .prune_mib             = 0,      /* Core -prune default: disabled        */
    .checkblocks           = 6,      /* Core -checkblocks default            */
    .checklevel            = 3,      /* Core -checklevel default             */
    .stopatheight          = 0,      /* Core -stopatheight default: no stop  */
};

/* "0000..0abc" -> 32 big-endian bytes, right-aligned, exactly how Core spells
 * nMinimumChainWork. Returns 0 on any non-hex character or on more than 64
 * digits, so a typo is reported instead of silently truncated. */
int nodecfg_hex32_be(const char* str, unsigned char out[32]){
    if(!str) return 0;
    while(*str==' '||*str=='\t') str++;
    if(str[0]=='0'&&(str[1]=='x'||str[1]=='X')) str+=2;
    long n=0;
    while(str[n] && str[n]!=' ' && str[n]!='\t' && str[n]!='\r' && str[n]!='\n') n++;
    if(n==0 || n>64) return 0;
    for(long i=0;i<n;i++){
        char c=str[i];
        if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) return 0;
    }
    memset(out,0,32);
    long bi=31, i=n;
    while(i>0 && bi>=0){
        int hi=0, lo;
        char c1=str[--i];
        lo=(c1<='9')?c1-'0':((c1|32)-'a'+10);
        if(i>0){ char c0=str[--i]; hi=(c0<='9')?c0-'0':((c0|32)-'a'+10); }
        out[bi--]=(unsigned char)((hi<<4)|lo);
    }
    return 1;
}

/* Core options this node does not implement. Listed explicitly rather than
 * inferred, so adding support means deleting a line here and the warning
 * stops -- and so the list itself is a readable statement of the gap. */
/* Core options this node ACCEPTS WITHOUT EFFECT, each with the reason it is
 * inert here. Named at every start-up (Core would silently accept them; an
 * operator who sets one deserves to know it does nothing). Everything Core
 * defines that is not here and not parsed above is implemented. Kept in
 * sync with docs/FEATURE_GAPS.md's config table (2026-09-01). */
static const struct { const char* key; const char* why; } k_noeffect[] = {
    {"peerbloomfilters",   "BIP37 bloom filtering is not implemented; NODE_BLOOM is never advertised (Core's default is 0 too)"},
    {"txreconciliation",   "Erlay: BIP330 negotiation is built but reconciliation is a deliberate stop"},
    {"natpmp",             "no NAT-PMP/UPnP port mapping by design"},
    {"upnp",               "no NAT-PMP/UPnP port mapping by design"},
    {"rest",               "no REST interface by design"},
    {"server",             "the JSON-RPC server is always on"},
    {"daemon",             "a systemd unit (or the shell) backgrounds the process"},
    {"daemonwait",         "a systemd unit (or the shell) backgrounds the process"},
    {"loadblock",          "the block archive is this node's own format (index.dat + blk files); Core blk*.dat files are not imported"},
    {"blocksdir",          "the archive lives under <datadir>/<chain> and is not relocatable"},
    {"blocksxor",          "the archive is never XOR-obfuscated"},
    {"stopafterblockimport","no block import step"},
    {"persistmempoolv1",   "mempool.dat is written in the current format only"},
    {"dbbatchsize",        "no LevelDB"},
    {"prevoutfetchthreads","prevouts come from the in-process UTXO set"},
    {"maxsigcachesize",    "no signature cache: each block's scripts are verified once by the parallel verifier"},
    {"settings",           "no settings.json: values set over RPC are not persisted"},
    {"allowignoredconf",   "-conf is always honoured"},
    {"includeconf",        NULL},   /* implemented (see node_config_load); listed so the table is complete */
    {"fixedseeds",         "no compiled-in seed list: DNS seeds, seednode= and peers.dat only"},
    {"blockreconstructionextratxn","compact-block reconstruction draws on the mempool only"},
    {"logips",             "peer addresses are always logged"},
    {"loglevel",           "no per-category log levels"},
    {"loglevelalways",     "no per-category log levels"},
    {"logratelimit",       "no log rate limiting"},
    {"debug",              "no log categories"},
    {"debugexclude",       "no log categories"},
    {"printtoconsole",     "stderr IS the log (systemd appends it to the log file)"},
    {"checkblockindex",    "index invariants are checked at boot (archive self-heal) and in the test suite, not on a timer"},
    {"checkmempool",       "mempool invariants are checked in the test suite, not on a timer"},
    {"checkaddrman",       "address-book invariants are checked in the test suite, not on a timer"},
    {"mocktime",           "no mock clock: regtest tests drive time through block timestamps"},
    {"testactivationheight","regtest deployments are active from genesis here"},
    {"vbparams",           "regtest deployments are active from genesis here"},
    {"capturemessages",    "no P2P message capture"},
    {"keypool",            "the descriptor wallet derives keys on demand; there is no keypool"},
    {"unsafesqlitesync",   "no sqlite"},
    {"walletrejectlongchains","the mempool's cluster limits bound unconfirmed chains"},
    {"walletcrosschain",   "one chain per datadir"},
    {"txsendrate",         "no inbound tx send-rate limiter (debug-only in Core)"},
    {"deprecatedrpc",      "no deprecated-RPC toggles"},
    {"rpcdoccheck",        "debug-only"},
    {"test",               "debug-only"},
    {"txospenderindex",    "the index is on whenever txospender.dat exists (build it with daemon/build_txospender_index); the key itself changes nothing"},
    {"fastprune",          "debug-only pruning knob; this node prunes by its own MiB budget"},
    {"testnet",            "testnet3 is refused by design; use testnet4=1"},
    {"version",            "command-line only"},
    {"help",               "command-line only"},
    {"conf",               "command-line only (-conf=)"},
    {"datadir",            "command-line only (-datadir=)"},
    {NULL, NULL}
};
const char* nodecfg_noeffect_reason(const char* key){
    for (int i = 0; k_noeffect[i].key; i++)
        if (!strcmp(key, k_noeffect[i].key)) return k_noeffect[i].why ? k_noeffect[i].why : "";
    return NULL;
}
int nodecfg_unimplemented(const char* key){
    const char* r = nodecfg_noeffect_reason(key);
    return r != NULL && *r != 0;
}

/* ---- DMN-4 (audit 2026-09-03) helpers ---------------------------------- */

/* Does a `[section]` header name the selected chain?
 *
 * Core's section names are the chain's own name, with one exception: [test]
 * is testnet3. This build refuses testnet3 outright (see the k_noeffect table
 * entry for "testnet"), so a [test] section can never match and its keys are
 * always skipped -- which is the correct outcome, not an oversight.
 * Comparison is exact and case-sensitive, as Core's is. */
int nodecfg_section_is(const char* section, const char* chain){
    if (!section || !chain) return 0;
    if (!strcmp(section, chain)) return 1;
    /* Core writes the mainnet section as [main] and the chain as "main". */
    return 0;
}

/* The options Core refuses to read from the base section on a non-main chain
 * (common/args.cpp's "-only-applies-to" set): anything that names a port, an
 * address, or a peer, because such a value written without a section is
 * almost always the mainnet one and would silently move the test node onto
 * it. */
int nodecfg_is_network_specific(const char* key){
    static const char* net_keys[] = {
        "port", "rpcport", "bind", "rpcbind", "rpcallowip",
        "addnode", "connect", "seednode", "whitebind", "externalip",
        "onion", "proxy", "torcontrol", "i2psam", "zmqpubrawblock",
        "zmqpubrawtx", "zmqpubhashblock", "zmqpubhashtx", "zmqpubsequence",
        NULL };
    for (int i = 0; net_keys[i]; i++) if (!strcmp(key, net_keys[i])) return 1;
    return 0;
}

/* Is `key` a name this parser applies (as opposed to an unknown key it
 * ignores)? Used only to decide whether a leading "no" is Core's negation
 * prefix or part of a genuine option name, so a future option actually
 * called "noXYZ" cannot be silently rewritten into "XYZ". */
int nodecfg_known_key(const char* key){
    static const char* known[] = {
        "maxconnections","dbcache","maxmempool","mempoolexpiry","minrelaytxfee",
        "incrementalrelayfee","dustrelayfee","blockmintxfee","datacarrier",
        "datacarriersize","permitbaremultisig","acceptnonstdtxn","blocksonly",
        "whitelistrelay","whitelistforcerelay","listen","discover","dnsseed",
        "upnp","natpmp","peerbloomfilters","peerblockfilters","blockfilterindex",
        "txindex","coinstatsindex","addressindex","spentindex","timestampindex",
        "prune","par","checkblockindex","checkmempool","checkaddrman",
        "capturemessages","stopafterblockimport","persistmempool","rest",
        "server","daemon","logips","logtimestamps","debuglogfile","printtoconsole",
        "reindex","reindex-chainstate","fixedseeds","forcednsseed","i2pacceptincoming",
        "v2transport","networkactive","rpccookieperms","deprecatedrpc",
        NULL };
    for (int i = 0; known[i]; i++) if (!strcmp(key, known[i])) return 1;
    return 0;
}

static void set_defaults(void){
    g_cfg.max_connections       = 200;   /* Core v31 default */
    g_cfg.max_outbound          = 8;
    g_cfg.max_block_relay_only  = 2;
    g_cfg.max_feeler            = 1;
    g_cfg.feeler_interval_ms    = 120000L;
    g_cfg.dead_weight_bps       = 32768.0;
    g_cfg.dead_weight_ticks     = 3;
    g_cfg.min_usable_peers      = 8;
    g_cfg.maxpool               = 2048;
    g_cfg.addr_max_per_response = 256;
    g_cfg.addr_max_per_netgroup = 16;
    g_cfg.proxyrandomize        = 1;     /* Core DEFAULT_PROXYRANDOMIZE */
    g_cfg.privatebroadcast      = 0;
    g_cfg.dns                   = 1;
    g_cfg.discover              = 1;
    g_cfg.i2pacceptincoming     = 1;
    g_cfg.listenonion           = 1;
    /* 2026-09-01 surface completion -- Core v31.99 defaults */
    g_cfg.n_uacomment = 0; memset(g_cfg.uacomment, 0, sizeof g_cfg.uacomment);
    g_cfg.blockmaxweight = 4000000; g_cfg.blockreservedweight = 8000; g_cfg.blockmintxfee_satkvb = 1;
    g_cfg.blockversion = 0; g_cfg.printpriority = 0;
    g_cfg.mintxfee_satkvb = 1000; g_cfg.fallbackfee_satkvb = 0; g_cfg.discardfee_satkvb = 10000;
    g_cfg.consolidatefeerate_satkvb = 10000; g_cfg.maxapsfee_sat = 0; g_cfg.avoidpartialspends = 0;
    g_cfg.spendzeroconfchange = 1; g_cfg.walletrbf = 1; g_cfg.txconfirmtarget = 6; g_cfg.walletbroadcast = 1;
    g_cfg.keypool = 1000; g_cfg.walletnotify[0] = 0; g_cfg.n_wallet_names = 0;
    snprintf(g_cfg.addresstype, sizeof g_cfg.addresstype, "bech32"); g_cfg.changetype[0] = 0;
    g_cfg.maxtipage = 86400; g_cfg.inboundrelaypercent = 50; g_cfg.whitelistrelay = 1; g_cfg.whitelistforcerelay = 0;
    g_cfg.whitelistrelay_explicit = 0; g_cfg.maxmempool_explicit = 0; g_cfg.acceptstalefeeestimates = 0;
    g_cfg.peerbloomfilters = 0; g_cfg.peerblockfilters = 0; g_cfg.fixedseeds = 1; g_cfg.n_signetseednode = 0;
    g_cfg.txreconciliation = 0;
    g_cfg.logips = 0; g_cfg.logtimestamps = 1; g_cfg.logtimemicros = 0; g_cfg.logthreadnames = 0;
    g_cfg.logsourcelocations = 0; g_cfg.shrinkdebugfile = 1; g_cfg.printtoconsole = 0; g_cfg.loglevel[0] = 0;
    g_cfg.rpcthreads = 16; g_cfg.rpcworkqueue = 64; g_cfg.rpcservertimeout = 30; g_cfg.n_rpcwhitelist = 0;
    g_cfg.rpcwhitelistdefault = -1; g_cfg.rpccookieperms = 0;
    g_cfg.limitclustercount = 64; g_cfg.limitclustersize_kvb = 101;
    g_cfg.checkblockindex = 0; g_cfg.checkmempool = 0; g_cfg.checkaddrman = 0; g_cfg.capturemessages = 0;
    g_cfg.stopafterblockimport = 0; g_cfg.mocktime = 0; g_cfg.n_includeconf = 0;
    g_cfg.bantime               = 86400;
    g_cfg.blockfilterindex      = 1;
    g_cfg.coinstatsindex        = 1;
    g_cfg.rpccookie             = 1;
    g_cfg.permitbaremultisig    = 1;
    g_cfg.v2transport           = 1;
    g_cfg.bytespersigop         = 20;    /* Core DEFAULT_BYTES_PER_SIGOP */
    g_cfg.disablewallet         = 0;
    g_cfg.reindex               = 0;
    g_cfg.walletdir[0]          = 0;
    g_cfg.debuglogfile[0]       = 0;
    g_cfg.persistmempool        = 1;
    g_cfg.reindex_chainstate    = 0;
    g_cfg.walletpassfile[0]     = 0;
    g_cfg.signetchallenge[0]    = 0;
    g_cfg.boot_catchup          = 1;
    g_cfg.rpcbind[0]            = 0;
    g_cfg.n_rpcallowip          = 0;
    g_cfg.networkactive         = 1;
    g_cfg.forcednsseed          = 0;
    g_cfg.pidfile[0]            = 0;
    g_cfg.blocknotify[0]        = 0;
    g_cfg.alertnotify[0]        = 0;
    g_cfg.startupnotify[0]      = 0;
    g_cfg.shutdownnotify[0]     = 0;
    g_cfg.maxtxfee_sat          = 0;
    g_cfg.asmap[0]              = 0;
    g_cfg.n_rpcauth             = 0;
    g_cfg.maxsendbuffer_kb      = 1000;   /* Core -maxsendbuffer default */
    for (int i = 0; i < 5; i++) g_cfg.zmq_hwm[i] = 1000;
    g_cfg.rpccookiefile[0]      = 0;
    memset(g_cfg.minchainwork, 0, 32);
    g_cfg.have_minchainwork     = 0;
    g_cfg.utxo_bulk_slots_log2  = 22;
    g_cfg.utxo_bulk_blob_mb     = 1024;
    g_cfg.utxo_bulk_gap_blocks  = 50000L;
    g_cfg.utxo_compact_threshold= 12;
    g_cfg.assumevalid_mode      = 0;        /* the chain default (Core defaultAssumeValid) */
    memset(g_cfg.assumevalid, 0, 32);
    g_cfg.dbcache_mb            = 1024;     /* Core v31 default (MiB) */
    g_cfg.connect_timeout_ms    = 5000;     /* Core's -timeout default */
    g_cfg.peer_timeout_s        = 60;       /* Core's -peertimeout default */
    g_cfg.port                  = 8333;
    g_cfg.port_explicit         = 0;
    snprintf(g_cfg.chain, sizeof g_cfg.chain, "main");
    g_cfg.listen                = 1;
    g_cfg.addrindex             = 0;
    g_cfg.blocksonly            = 0;
    g_cfg.bind_addr[0]          = 0;
    g_cfg.par                   = 0;
    g_cfg.maxrecvbuffer_kb      = 5000;
    g_cfg.maxmempool_mb         = 300;
    g_cfg.mempoolexpiry_h       = 336;
    g_cfg.maxuploadtarget_mb    = 0;
    g_cfg.minrelaytxfee_satkvb  = 100;
    g_cfg.incrementalrelayfee_satkvb = 100;
    g_cfg.limitancestorcount    = 64;
    g_cfg.limitancestorsize_kvb = 101;
    g_cfg.limitdescendantcount  = 64;
    g_cfg.limitdescendantsize_kvb = 101;
    g_cfg.mempoolfullrbf        = 1;
    g_cfg.dustrelayfee_satkvb   = 3000;
    g_cfg.datacarrier           = 1;
    g_cfg.datacarriersize       = 100000;
    g_cfg.acceptnonstdtxn       = 0;
    g_cfg.dnsseed               = 1;
    g_cfg.connect_only          = 0;
    g_cfg.n_seednode = g_cfg.n_addnode = g_cfg.n_connect = 0;
    g_cfg.seednode[0][0] = g_cfg.addnode[0][0] = g_cfg.connectn[0][0] = 0;
    memset(g_cfg.seednode_port, 0, sizeof g_cfg.seednode_port);
    memset(g_cfg.addnode_port,  0, sizeof g_cfg.addnode_port);
    memset(g_cfg.connectn_port, 0, sizeof g_cfg.connectn_port);
    g_cfg.prune_mib             = 0;
    g_cfg.checkblocks           = 6;
    g_cfg.checklevel            = 3;
    g_cfg.stopatheight          = 0;
}

/* Append one host to a repeatable-key list.
 *
 * Accepts "host" or "host:port". ANY port is honoured: the host is stored
 * bare (those strings flow into inet_pton()/address-book paths that must not
 * see a suffix) and the port goes in the PARALLEL <list>_port array, which
 * the dial paths consult through node_config_peer_port().
 *
 * This used to reject every port but a chain default, on the grounds that the
 * dial paths took a bare IP and one fixed port. The cost was worse than the
 * gap it papered over: pointing the node at a peer on any other port dropped
 * the entry, and the node then sat at tip=0 with peers=0/0 looking healthy.
 * Core accepts any host:port; so do we now.
 * Returns 1 if the entry was stored. */
static int cfg_addlist(char list[][64], unsigned short ports[], int* n,
                       const char* val, const char* key, int* bad){
    char host[64];
    if(!*val){ fprintf(stderr,"[config] %s= empty -- ignoring\n", key); (*bad)++; return 0; }
    if(strlen(val) >= sizeof host){
        fprintf(stderr,"[config] %s=%s too long (max %d) -- ignoring\n", key, val, (int)sizeof host - 1);
        (*bad)++; return 0;
    }
    snprintf(host, sizeof host, "%s", val);
    if(strchr(host,' ')||strchr(host,'\t')){
        fprintf(stderr,"[config] %s=%s contains whitespace -- ignoring\n", key, val);
        (*bad)++; return 0;
    }
    int port = 0;
    { char* colon = strrchr(host,':');
      if(colon){
        /* IPv6 literals would need brackets to be unambiguous here; the dial
         * paths are IPv4-only (AF_INET throughout), so a bare trailing colon
         * group can only be a port. */
        char* end = NULL;
        long p = strtol(colon+1, &end, 10);
        if(end == colon+1 || (end && *end)){
            fprintf(stderr,"[config] %s=%s has a non-numeric port -- ignoring\n", key, val);
            (*bad)++; return 0;
        }
        if(p < 1 || p > 65535){
            fprintf(stderr,"[config] %s=%s port out of range (1-65535) -- ignoring\n", key, val);
            (*bad)++; return 0;
        }
        port = (int)p;
        *colon = 0;
      } }
    if(!host[0]){ fprintf(stderr,"[config] %s=%s has no host part -- ignoring\n", key, val); (*bad)++; return 0; }
    for(int i=0;i<*n;i++) if(!strcmp(list[i],host)) return 0;   /* dedupe, silently */
    if(*n >= CFG_MAX_NODES){
        fprintf(stderr,"[config] %s=%s ignored -- at most %d entries per key\n", key, val, CFG_MAX_NODES);
        (*bad)++; return 0;
    }
    snprintf(list[*n], 64, "%s", host);
    if(ports) ports[*n] = (unsigned short)port;
    (*n)++;
    return 1;
}

/* See node_config.h. Scans all three named-peer lists; 0 means "no port was
 * configured for this host", which callers read as "dial the chain default". */
int node_config_peer_port(const char* host){
    if(!host || !*host) return 0;
    for(int i=0;i<g_cfg.n_connect;i++)
        if(!strcmp(g_cfg.connectn[i], host) && g_cfg.connectn_port[i]) return g_cfg.connectn_port[i];
    for(int i=0;i<g_cfg.n_addnode;i++)
        if(!strcmp(g_cfg.addnode[i], host) && g_cfg.addnode_port[i]) return g_cfg.addnode_port[i];
    for(int i=0;i<g_cfg.n_seednode;i++)
        if(!strcmp(g_cfg.seednode[i], host) && g_cfg.seednode_port[i]) return g_cfg.seednode_port[i];
    return 0;
}

int node_config_is_manual(const char* ip){
    if(!ip || !*ip) return 0;
    for(int i=0;i<g_cfg.n_addnode;i++) if(!strcmp(g_cfg.addnode[i], ip)) return 1;
    for(int i=0;i<g_cfg.n_connect;i++) if(!strcmp(g_cfg.connectn[i], ip)) return 1;
    return 0;
}

/* Clamp to values that cannot wedge the node. A config file is operator input,
 * not trusted input: a typo that sets min_usable_peers to 0 or maxpool to -1
 * should not be able to reproduce the peer-starvation stall that a bad
 * eviction threshold caused on 2026-08-18. */
static int hexval(int c){ return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1; }
/* ---------------------------------------------------------------- DMN-9
 * (audit 2026-09-03) Bounded integer parsing.
 *
 * Every numeric key went through `atoi`, which truncates strtol's long to an
 * int: `maxconnections=4294967496` wrapped to 200 and sailed straight through
 * the clamp that exists to catch exactly that, so a typo silently produced a
 * plausible-looking wrong setting. Core's LocaleIndependentAtoi returns 0 for
 * anything it cannot represent, which the clamp below then reports.
 *
 * Returns 0 (and warns) on overflow, trailing garbage or an empty value, so
 * an unusable setting is visible instead of being quietly reinterpreted. */
static long long nodecfg_strtoll(const char* s, const char* key, int* overflowed){
    if (overflowed) *overflowed = 0;
    if (!s || !*s) return 0;
    errno = 0;
    char* end = 0;
    long long v = strtoll(s, &end, 10);
    if (errno == ERANGE || end == s || (end && *end)){
        if (overflowed) *overflowed = 1;
        fprintf(stderr, "[config] %s=%s is not a usable number -- reading it as 0\n",
                key ? key : "?", s);
        return 0;
    }
    return v;
}

/* The int-width form: out-of-range is 0, as Core's LocaleIndependentAtoi. */
static int nodecfg_atoi(const char* s, const char* key){
    int ovf = 0;
    long long v = nodecfg_strtoll(s, key, &ovf);
    if (ovf) return 0;
    if (v > INT_MAX || v < INT_MIN){
        fprintf(stderr, "[config] %s=%s does not fit an int -- reading it as 0\n",
                key ? key : "?", s);
        return 0;
    }
    return (int)v;
}

static int clamp_int(int v, int lo, int hi, const char* key, int* bad){
    if(v < lo || v > hi){
        fprintf(stderr,"[config] %s=%d out of range [%d,%d] -- ignoring\n", key, v, lo, hi);
        (*bad)++; return -1;
    }
    return v;
}

/* -conf=<path>, set by main() before any load. Highest precedence: an
 * operator who names a file must get that file or a clear failure, never a
 * silent fallback to a different one. */
static char g_conf_override[512];
void node_config_set_conf_path(const char* path){
    snprintf(g_conf_override, sizeof g_conf_override, "%s", path ? path : "");
}
const char* node_config_path(const char* datadir, char* buf, unsigned long cap){
    if(g_conf_override[0]){ snprintf(buf, cap, "%s", g_conf_override); return buf; }
    const char* env = getenv("BITCOIN_CONF");
    if(env && *env){ snprintf(buf, cap, "%s", env); return buf; }
    snprintf(buf, cap, "%s/bitcoin.conf", datadir);
    if(access(buf, R_OK)==0) return buf;
    snprintf(buf, cap, "%s/../config/bitcoin.conf", datadir);
    return buf;
}

static int g_include_depth = 0;
long node_config_load(const char* path){
    if(!g_include_depth) set_defaults();
    FILE* f = fopen(path, "r");
    if(!f){
        fprintf(stderr,"[config] no config file at %s -- using compiled defaults\n", path);
        return 0;
    }
    long applied = 0; int bad = 0; int unimpl = 0;
    /* ---- DMN-4 (audit 2026-09-03): SECTIONS and NEGATION ----
     *
     * A `[section]` line has no `=`, so the loop below used to `continue`
     * past it and then apply every following key unconditionally. That is
     * not a cosmetic gap. An operator who reuses a Core bitcoin.conf holding
     * the common dev block
     *
     *     [regtest]
     *     rpcallowip=0.0.0.0/0
     *     rpcbind=0.0.0.0
     *
     * while running mainnet gets, in Core, three inert lines. Here they were
     * applied: rpc_acl_add("0.0.0.0/0") succeeded, rpcbind was honoured
     * because rpc_acl_configured() > 0, and the MAINNET RPC server bound
     * every interface and accepted every source. `[regtest] connect=...`
     * likewise pinned a mainnet node to a loopback peer.
     *
     * Core scopes keys under [main], [test], [testnet4], [signet] and
     * [regtest] to that chain. Doing the same needs the chain BEFORE the
     * keys are applied, and the chain itself comes from this file -- so the
     * file is read twice: once for the chain selectors in the base section
     * (which is the only place Core honours them), then once for real. */
    char cur_section[32] = "";
    {
        char l0[1024]; char sec0[32] = "";
        while(fgets(l0, sizeof l0, f)){
            char* q = l0;
            while(*q==' '||*q=='\t') q++;
            if(*q=='#'||*q=='\n'||*q==0) continue;
            if(*q=='['){
                char* e = strchr(q, ']');
                if(e){ size_t n2 = (size_t)(e - q - 1); if(n2 >= sizeof sec0) n2 = sizeof sec0 - 1;
                       memcpy(sec0, q+1, n2); sec0[n2] = 0; }
                continue;
            }
            if(sec0[0]) continue;                 /* chain selectors: base section only */
            char* e2 = strchr(q,'='); if(!e2) continue;
            *e2 = 0;
            char* k0 = q; char* v0 = e2+1;
            size_t vl0 = strlen(v0);
            while(vl0 && (v0[vl0-1]=='\n'||v0[vl0-1]=='\r'||v0[vl0-1]==' '||v0[vl0-1]=='\t')) v0[--vl0]=0;
            size_t kl0 = strlen(k0);
            while(kl0 && (k0[kl0-1]==' '||k0[kl0-1]=='\t')) k0[--kl0]=0;
            int b0 = atoi(v0);
            if     (!strcmp(k0,"chain")   && *v0)  snprintf(g_cfg.chain,sizeof g_cfg.chain,"%s",v0);
            else if(!strcmp(k0,"regtest") && b0==1) snprintf(g_cfg.chain,sizeof g_cfg.chain,"regtest");
            else if(!strcmp(k0,"signet")  && b0==1) snprintf(g_cfg.chain,sizeof g_cfg.chain,"signet");
            else if(!strcmp(k0,"testnet4")&& b0==1) snprintf(g_cfg.chain,sizeof g_cfg.chain,"testnet4");
        }
        rewind(f);
    }

    /* -connect implies -dnsseed=0 and -listen=0 in Core, but only when those
     * were not set explicitly. The implication therefore has to run AFTER the
     * whole file is read: `listen=1` may appear on a line BELOW `connect=`,
     * and a file must not mean different things depending on key order. */
    int saw_dnsseed = 0, saw_listen = 0;
    char line[1024];
    while(fgets(line, sizeof line, f)){
        char* p = line;
        while(*p==' '||*p=='\t') p++;
        if(*p=='#'||*p=='\n'||*p==0) continue;
        /* DMN-4: a section header changes which chain the following keys
         * belong to. Previously it fell through the `no =` test and was
         * simply ignored, taking its scoping with it. */
        if(*p=='['){
            char* e = strchr(p, ']');
            if(e){ size_t n2 = (size_t)(e - p - 1); if(n2 >= sizeof cur_section) n2 = sizeof cur_section - 1;
                   memcpy(cur_section, p+1, n2); cur_section[n2] = 0; }
            else fprintf(stderr,"[config] malformed section header (no ']'): %s", p);
            continue;
        }
        char* eq = strchr(p,'='); if(!eq) continue;
        *eq = 0;
        char* key = p; char* val = eq+1;
        size_t vl = strlen(val);
        while(vl && (val[vl-1]=='\n'||val[vl-1]=='\r'||val[vl-1]==' '||val[vl-1]=='\t')) val[--vl]=0;
        size_t kl = strlen(key);
        while(kl && (key[kl-1]==' '||key[kl-1]=='\t')) key[--kl]=0;

        /* DMN-4: apply a sectioned key only on its own chain. */
        if(cur_section[0] && !nodecfg_section_is(cur_section, g_cfg.chain)){
            continue;
        }
        /* DMN-4: Core IGNORES network-specific options that appear outside
         * any section when the selected chain is not main, with a warning --
         * because a bare `port=` in a file that also has a [regtest] block
         * almost always means the mainnet port and would silently move the
         * test node. Same rule, same reason, said out loud. */
        if(!cur_section[0] && strcmp(g_cfg.chain, "main") != 0 && nodecfg_is_network_specific(key)){
            fprintf(stderr,"[config] %s= is network-specific and appears outside any section "
                           "while chain=%s: ignoring it (Core does the same; put it under [%s] to apply it)\n",
                    key, g_cfg.chain, g_cfg.chain);
            continue;
        }
        /* DMN-4: Core's negation. `-noX` is `-X=0`, so `noX=1` means X=0 and
         * `noX=0` means X=1. Rewritten here into the key/value the chain
         * below already understands, so every boolean option gets it at once
         * rather than one at a time. Only applied when the remainder is a key
         * this parser knows, so a genuine option starting with "no" -- there
         * is none today, but there could be -- is not silently mangled. */
        char negbuf[128];
        if(kl > 2 && key[0]=='n' && key[1]=='o' && nodecfg_known_key(key+2)){
            snprintf(negbuf, sizeof negbuf, "%s", key+2);
            int on = nodecfg_atoi(val, key) ? 0 : 1;    /* noX=1 -> X=0 (DMN-9: bounded) */
            fprintf(stderr,"[config] %s=%s -> %s=%d (Core negation)\n", key, val, negbuf, on);
            key = negbuf; kl = strlen(negbuf);
            val = on ? (char*)"1" : (char*)"0";
        }

        int iv = nodecfg_atoi(val, key); int t;   /* DMN-9: bounded, not atoi */

        /* ---- keys Bitcoin Core actually defines: same name, same units ----
         * A real bitcoin.conf must work here unchanged, and our file must not
         * break Core. Core ignores unknown keys and so do we, so the file
         * stays genuinely shared. */
        if     (!strcmp(key,"maxconnections")){ t=clamp_int(iv,16,4096,key,&bad); if(t>=0){g_cfg.max_connections=t;applied++;} }
        else if(!strcmp(key,"dbcache")){
            /* Core's -dbcache is the UTXO cache size in MB (default 450) --
             * exactly the knob this node needs for catch-up memtable sizing,
             * so honour it rather than inventing a parallel setting. Split it
             * ~1:3 between the slot table and the value/script blob, and
             * derive slots_log2 from the table's share at ~64B per slot. */
            t=clamp_int(iv,4,262144,key,&bad);
            if(t>=0){
                g_cfg.dbcache_mb = t;
                double table_bytes = (double)t * 1048576.0 * 0.25;
                int lg = 16; while(lg < 26 && ((double)(1UL<<(lg+1)) * 64.0) <= table_bytes) lg++;
                g_cfg.utxo_bulk_slots_log2 = lg;
                g_cfg.utxo_bulk_blob_mb    = (t*3)/4 < 16 ? 16 : (t*3)/4;
                applied++;
            }
        }
        else if(!strcmp(key,"timeout")){      /* Core: connect timeout, ms  */
            t=clamp_int(iv,1000,120000,key,&bad); if(t>=0){g_cfg.connect_timeout_ms=t;applied++;} }
        else if(!strcmp(key,"peertimeout")){  /* Core: peer inactivity, s   */
            t=clamp_int(iv,5,3600,key,&bad);  if(t>=0){g_cfg.peer_timeout_s=t;applied++;} }
        else if(!strcmp(key,"port")){         /* Core: P2P listen port      */
            t=clamp_int(iv,1,65535,key,&bad); if(t>=0){g_cfg.port=t;g_cfg.port_explicit=1;applied++;} }
        else if(!strcmp(key,"chain")){        /* Core: -chain=main|regtest  */
            snprintf(g_cfg.chain,sizeof g_cfg.chain,"%s",val); applied++; }
        else if(!strcmp(key,"addrindex")){    /* EXTENSION: live addr index */
            t=clamp_int(iv,0,1,key,&bad); if(t>=0){g_cfg.addrindex=t;applied++;} }
        else if(!strcmp(key,"regtest")){      /* Core: -regtest (bool form) */
            t=clamp_int(iv,0,1,key,&bad);
            if(t==1){ snprintf(g_cfg.chain,sizeof g_cfg.chain,"regtest"); applied++; } }
        else if(!strcmp(key,"testnet4")){     /* Core: -testnet4 (bool form) */
            t=clamp_int(iv,0,1,key,&bad);
            if(t==1){ snprintf(g_cfg.chain,sizeof g_cfg.chain,"testnet4"); applied++; } }
        else if(!strcmp(key,"signet")){       /* Core: -signet (bool form) */
            t=clamp_int(iv,0,1,key,&bad);
            if(t==1){ snprintf(g_cfg.chain,sizeof g_cfg.chain,"signet"); applied++; } }
        else if(!strcmp(key,"bytespersigop")){ /* Core: -bytespersigop=<n> */
            t=clamp_int(iv,1,100000,key,&bad);
            if(!bad){ g_cfg.bytespersigop=t; applied++; } }
        else if(!strcmp(key,"disablewallet")){ /* Core: -disablewallet */
            g_cfg.disablewallet = iv?1:0; applied++; }
        else if(!strcmp(key,"reindex")){       /* Core -reindex (one-shot, see main.c) */
            g_cfg.reindex = iv?1:0; applied++; }
        else if(!strcmp(key,"walletdir")){     /* Core -walletdir=<dir> (absolute, or relative to the chain dir) */
            snprintf(g_cfg.walletdir,sizeof g_cfg.walletdir,"%s",val); applied++; }
        else if(!strcmp(key,"debuglogfile")){ /* Core: -debuglogfile=<file>, 0 = none */
            snprintf(g_cfg.debuglogfile,sizeof g_cfg.debuglogfile,"%s",val); applied++; }
        else if(!strcmp(key,"bind")){         /* Core: -bind=<addr>[:<port>] */
            char tmp[64]; snprintf(tmp,sizeof tmp,"%s",val);
            char* colon = strrchr(tmp,':');
            if(colon){ *colon = 0; int bp = atoi(colon+1);
                       if(bp>0 && bp<65536){ g_cfg.port = bp; } }
            snprintf(g_cfg.bind_addr,sizeof g_cfg.bind_addr,"%s",tmp);
            applied++; }
        else if(!strcmp(key,"par")){
            /* Core -par: worker threads. 0 = auto, and NEGATIVE means "leave
             * that many cores free", which is why the lower bound is not 0.
             * Drives the chunk-claiming catch-up worker count. */
            t=clamp_int(iv,-64,64,key,&bad); if(t!=-1 || iv>=-64){ g_cfg.par=iv; applied++; } }
        else if(!strcmp(key,"maxreceivebuffer")){
            /* Core -maxreceivebuffer is in units of 1000 bytes. Bounds how
             * much a single peer can make us buffer for one message. */
            t=clamp_int(iv,64,262144,key,&bad); if(t>=0){ g_cfg.maxrecvbuffer_kb=t; applied++; } }
        else if(!strcmp(key,"maxmempool")){    /* Core: MB */
            t=clamp_int(iv,1,65536,key,&bad); if(t>=0){ g_cfg.maxmempool_mb=t; g_cfg.maxmempool_explicit=1; applied++; } }
        else if(!strcmp(key,"mempoolexpiry")){ /* Core: hours */
            t=clamp_int(iv,0,8760,key,&bad);  if(t>=0){ g_cfg.mempoolexpiry_h=t; applied++; } }
        /* mempool policy limits (Core limit-count/size, relay fees, mempoolfullrbf).
         * The two fees are BTC/kvB in Core's config; keep them in sat/kvB
         * (round(BTC/kvB * 1e8)). Integer sat/vB could not represent Core's
         * v30 default of 0.1 sat/vB -- which is how this node kept refusing
         * everything between 0.1 and 1 sat/vB that its peers relay. */
        else if(!strcmp(key,"minrelaytxfee") || !strcmp(key,"incrementalrelayfee")){
            double btc = atof(val);
            long satkvb = (long)(btc * 1e8 + 0.5);
            if(satkvb < 0) satkvb = 0;
            if(!strcmp(key,"minrelaytxfee"))      g_cfg.minrelaytxfee_satkvb = satkvb;
            else                                  g_cfg.incrementalrelayfee_satkvb = satkvb;
            applied++; }
        else if(!strcmp(key,"limitancestorcount")){
            t=clamp_int(iv,1,10000,key,&bad); if(t>=0){ g_cfg.limitancestorcount=t; applied++; } }
        else if(!strcmp(key,"limitancestorsize")){   /* Core: kvB */
            t=clamp_int(iv,1,100000,key,&bad); if(t>=0){ g_cfg.limitancestorsize_kvb=t; applied++; } }
        else if(!strcmp(key,"limitdescendantcount")){
            t=clamp_int(iv,1,10000,key,&bad); if(t>=0){ g_cfg.limitdescendantcount=t; applied++; } }
        else if(!strcmp(key,"limitdescendantsize")){ /* Core: kvB */
            t=clamp_int(iv,1,100000,key,&bad); if(t>=0){ g_cfg.limitdescendantsize_kvb=t; applied++; } }
        else if(!strcmp(key,"mempoolfullrbf")){
            g_cfg.mempoolfullrbf = (iv != 0); applied++; }
        else if(!strcmp(key,"dustrelayfee")){  /* Core: BTC/kvB -> sat/kvB */
            double b = atof(val);
            if(b >= 0 && b < 1.0){ g_cfg.dustrelayfee_satkvb = (long)(b*1e8 + 0.5); applied++; }
            else { fprintf(stderr,"[config] dustrelayfee=%s out of range -- ignoring\n", val); bad++; } }
        else if(!strcmp(key,"datacarrier")){
            t=clamp_int(iv,0,1,key,&bad); if(t>=0){g_cfg.datacarrier=t;applied++;} }
        else if(!strcmp(key,"datacarriersize")){
            t=clamp_int(iv,0,1000000,key,&bad); if(t>=0){g_cfg.datacarriersize=t;applied++;} }
        else if(!strcmp(key,"acceptnonstdtxn")){
            t=clamp_int(iv,0,1,key,&bad); if(t>=0){g_cfg.acceptnonstdtxn=t;applied++;} }
        else if(!strcmp(key,"maxuploadtarget")){ /* Core: MB per 24h, 0=off */
            t=clamp_int(iv,0,1048576,key,&bad); if(t>=0){ g_cfg.maxuploadtarget_mb=t; applied++; } }
        /* ---- anonymity networks (2026-08-28) ---- */
        else if(!strcmp(key,"proxy")){        /* Core -proxy=ip:port        */
            snprintf(g_cfg.proxy,sizeof g_cfg.proxy,"%s",val); applied++; }
        else if(!strcmp(key,"onion")){        /* Core -onion=ip:port        */
            snprintf(g_cfg.onion_proxy,sizeof g_cfg.onion_proxy,"%s",val); applied++; }
        else if(!strcmp(key,"torcontrol")){   /* Core -torcontrol=ip:port   */
            snprintf(g_cfg.torcontrol,sizeof g_cfg.torcontrol,"%s",val); applied++; }
        else if(!strcmp(key,"torpassword")){
            snprintf(g_cfg.torpassword,sizeof g_cfg.torpassword,"%s",val); applied++; }
        else if(!strcmp(key,"listenonion")){
            g_cfg.listenonion = iv?1:0; applied++; }
        else if(!strcmp(key,"bantime")){      /* Core -bantime, seconds      */
            /* DMN-9: an unbounded bantime is FAIL-OPEN. main.c computes
             * time(NULL) + bantime, so bantime=9223372036854775807 wraps
             * negative and every automatic ban expires on the very next
             * check -- banning silently switches itself off. Core has no cap
             * but adds an int64 to GetTime(); a hundred years is longer than
             * any real ban and cannot overflow that sum. */
            { long long bv = nodecfg_strtoll(val, key, 0);
              if(bv > NODECFG_BANTIME_MAX){
                  fprintf(stderr,"[config] bantime=%s exceeds the %lld-second cap -- using the cap\n",
                          val, (long long)NODECFG_BANTIME_MAX);
                  bv = NODECFG_BANTIME_MAX;
              }
              if(bv > 0) g_cfg.bantime = (long)bv; } applied++; }
        else if(!strcmp(key,"blockfilterindex")){
            /* Core takes "basic"/"0"/"1"; "basic" is the only index type
             * that exists in Core either, so treat it as on. */
            g_cfg.blockfilterindex = (!strcmp(val,"basic") || iv) ? 1 : 0; applied++; }
        else if(!strcmp(key,"coinstatsindex")){
            g_cfg.coinstatsindex = iv?1:0; applied++; }
        else if(!strcmp(key,"permitbaremultisig")){
            g_cfg.permitbaremultisig = iv?1:0; applied++; }
        else if(!strcmp(key,"v2transport")){
            g_cfg.v2transport = iv?1:0; applied++; }
        else if(!strcmp(key,"persistmempool")){
            g_cfg.persistmempool = iv?1:0; applied++; }
        else if(!strcmp(key,"reindex-chainstate")){
            g_cfg.reindex_chainstate = iv?1:0; applied++; }
        else if(!strcmp(key,"whitebind")){    /* Core: permissions by listener */
            const char* wberr = 0;
            if(netperm_whitebind_add(val, &wberr)) applied++;
            else { fprintf(stderr,"[config] whitebind=%s rejected: %s\n",
                           val, wberr ? wberr : "?"); bad++; } }
        else if(!strcmp(key,"rpcallowip")){   /* Core: HTTP allow list */
            if(g_cfg.n_rpcallowip >= 16){
                fprintf(stderr,"[config] rpcallowip: at most 16 entries -- ignoring %s\n", val); bad++; }
            else { snprintf(g_cfg.rpcallowip[g_cfg.n_rpcallowip], 64, "%s", val);
                   g_cfg.n_rpcallowip++; applied++; } }
        else if(!strcmp(key,"rpcbind")){      /* Core: RPC listen address */
            snprintf(g_cfg.rpcbind, sizeof g_cfg.rpcbind, "%s", val); applied++; }
        else if(!strcmp(key,"whitelist")){    /* Core: peer permissions */
            const char* nperr = 0;
            if(netperm_add(val, &nperr)) applied++;
            else { fprintf(stderr,"[config] whitelist=%s rejected: %s\n",
                           val, nperr ? nperr : "?"); bad++; } }
        else if(!strcmp(key,"signetchallenge")){  /* Core: -signetchallenge */
            snprintf(g_cfg.signetchallenge, sizeof g_cfg.signetchallenge, "%s", val); applied++; }
        else if(!strcmp(key,"walletpassfile")){
            snprintf(g_cfg.walletpassfile, sizeof g_cfg.walletpassfile, "%s", val); applied++; }
        else if(!strcmp(key,"networkactive")){
            g_cfg.networkactive = iv?1:0; applied++; }
        else if(!strcmp(key,"forcednsseed")){
            g_cfg.forcednsseed = iv?1:0; applied++; }
        else if(!strcmp(key,"pid")){
            snprintf(g_cfg.pidfile,sizeof g_cfg.pidfile,"%s",val); applied++; }
        else if(!strcmp(key,"maxsendbuffer")){
            t=clamp_int(iv,1,1000000,key,&bad); if(t>=0){ g_cfg.maxsendbuffer_kb=t; applied++; } }
        else if(!strcmp(key,"zmqpubhashblockhwm")){ t=clamp_int(iv,0,1000000,key,&bad); if(t>=0){g_cfg.zmq_hwm[0]=t;applied++;} }
        else if(!strcmp(key,"zmqpubhashtxhwm")){    t=clamp_int(iv,0,1000000,key,&bad); if(t>=0){g_cfg.zmq_hwm[1]=t;applied++;} }
        else if(!strcmp(key,"zmqpubrawblockhwm")){  t=clamp_int(iv,0,1000000,key,&bad); if(t>=0){g_cfg.zmq_hwm[2]=t;applied++;} }
        else if(!strcmp(key,"zmqpubrawtxhwm")){     t=clamp_int(iv,0,1000000,key,&bad); if(t>=0){g_cfg.zmq_hwm[3]=t;applied++;} }
        else if(!strcmp(key,"zmqpubsequencehwm")){  t=clamp_int(iv,0,1000000,key,&bad); if(t>=0){g_cfg.zmq_hwm[4]=t;applied++;} }
        else if(!strcmp(key,"rpcauth")){    /* repeatable, like onlynet */
            if (g_cfg.n_rpcauth < 8){
                snprintf(g_cfg.rpcauth[g_cfg.n_rpcauth], 256, "%s", val);
                g_cfg.n_rpcauth++; applied++;
            } else fprintf(stderr,"[config] at most 8 rpcauth entries -- ignoring %s\n", val); }
        else if(!strcmp(key,"asmap")){
            snprintf(g_cfg.asmap,sizeof g_cfg.asmap,"%s",val); applied++; }
        else if(!strcmp(key,"blocknotify")){
            snprintf(g_cfg.blocknotify,sizeof g_cfg.blocknotify,"%s",val); applied++; }
        else if(!strcmp(key,"alertnotify")){
            snprintf(g_cfg.alertnotify,sizeof g_cfg.alertnotify,"%s",val); applied++; }
        else if(!strcmp(key,"startupnotify")){
            snprintf(g_cfg.startupnotify,sizeof g_cfg.startupnotify,"%s",val); applied++; }
        else if(!strcmp(key,"shutdownnotify")){
            snprintf(g_cfg.shutdownnotify,sizeof g_cfg.shutdownnotify,"%s",val); applied++; }
        else if(!strcmp(key,"maxtxfee")){
            /* Core takes BTC; stored in satoshis like every other fee here */
            double b = atof(val); if(b >= 0) g_cfg.maxtxfee_sat = (long)(b * 100000000.0 + 0.5);
            applied++; }
        else if(!strcmp(key,"rpccookiefile")){
            snprintf(g_cfg.rpccookiefile,sizeof g_cfg.rpccookiefile,"%s",val); applied++; }
        else if(!strcmp(key,"minimumchainwork")){
            /* 64 hex digits, big-endian, exactly Core's uint256 spelling.
             * Shorter input is right-aligned so "0" and a full hash both
             * mean what an operator expects. */
            if(nodecfg_hex32_be(val, g_cfg.minchainwork)){
                g_cfg.have_minchainwork = 1; applied++;
            } else {
                fprintf(stderr,"[config] minimumchainwork=%s is not a hex number -- ignoring\n", val);
            } }
        else if(!strcmp(key,"i2psam")){       /* Core -i2psam=ip:port       */
            snprintf(g_cfg.i2psam,sizeof g_cfg.i2psam,"%s",val); applied++; }
        else if(!strcmp(key,"i2pacceptincoming")){
            g_cfg.i2pacceptincoming = iv?1:0; applied++; }
        else if(!strcmp(key,"cjdnsreachable")){
            g_cfg.cjdnsreachable = iv?1:0; applied++; }
        else if(!strcmp(key,"dns")){          /* Core -dns                  */
            g_cfg.dns = iv?1:0; applied++; }
        else if(!strcmp(key,"discover")){     /* Core -discover             */
            g_cfg.discover = iv?1:0; applied++; }
        else if(!strcmp(key,"externalip")){   /* Core -externalip           */
            snprintf(g_cfg.externalip,sizeof g_cfg.externalip,"%s",val); applied++; }
        else if(!strcmp(key,"proxyrandomize")){
            g_cfg.proxyrandomize = iv?1:0; applied++; }
        else if(!strcmp(key,"privatebroadcast")){   /* Core -privatebroadcast */
            g_cfg.privatebroadcast = iv?1:0; applied++; }
        else if(!strcmp(key,"onlynet")){      /* Core -onlynet, repeatable  */
            if(g_cfg.n_onlynet < 6){
                snprintf(g_cfg.onlynet[g_cfg.n_onlynet],8,"%s",val);
                g_cfg.n_onlynet++; applied++;
            } else fprintf(stderr,"[config] onlynet: at most 6 networks\n"); }
        else if(!strcmp(key,"bmc.bootcatchup")){ g_cfg.boot_catchup = iv ? 1 : 0; applied++; }
        else if(!strcmp(key,"listen")){       /* Core: accept inbound       */
            g_cfg.listen = iv?1:0; saw_listen = 1; applied++; }
        else if(!strcmp(key,"prune")){
            /* Core -prune: 0 disabled, 1 manual-only (no automatic deletion),
             * >=550 a target size in MiB for the block data. Values in 2..549
             * are refused by Core too -- a budget that small cannot hold the
             * blocks a node must keep to stay usable. */
            if(iv==0 || iv==1){ g_cfg.prune_mib=iv; applied++; }
            else { t=clamp_int(iv,550,1073741824,key,&bad); if(t>=0){ g_cfg.prune_mib=t; applied++; } } }
        else if(!strcmp(key,"checkblocks")){  /* Core: 0 = all              */
            t=clamp_int(iv,0,1000000,key,&bad); if(t>=0){ g_cfg.checkblocks=t; applied++; } }
        else if(!strcmp(key,"checklevel")){   /* Core: 0..4                 */
            t=clamp_int(iv,0,4,key,&bad); if(t>=0){ g_cfg.checklevel=t; applied++; } }
        else if(!strcmp(key,"stopatheight")){
            t=clamp_int(iv,0,100000000,key,&bad); if(t>=0){ g_cfg.stopatheight=iv; applied++; } }

        /* ---- Core keys we PARSE ONLY TO SAY WE DO NOT HONOUR THEM ----
         * Silence would be worse than a warning: this repo's own bitcoin.conf
         * carries txindex=1, which reads as "enabled" and is not. A key that
         * changes nothing must say so on every boot, not be quietly ignored
         * alongside genuinely foreign keys like rpcuser. */
        else if(!strcmp(key,"txindex")){
            /* The index EXISTS as of 2026-08-26, but it is built OFFLINE by
             * daemon/build_tx_index -- this daemon does not maintain it. So
             * the flag still changes nothing, and still says so: what it
             * would mean in Core (the node builds and keeps it current) is
             * not what happens here. getrawtransaction picks the file up on
             * its own when it is present, with or without this key. */
            if(iv) fprintf(stderr,"[config] txindex=1 has no effect -- the txid index is built "
                                  "OFFLINE (daemon/build_tx_index <datadir>) and is used "
                                  "automatically when txindex.dat is present; this daemon "
                                  "does not build or update it\n"); }
        else if(!strcmp(key,"assumevalid")){
            /* Core's -assumevalid: script evaluation is skipped for blocks
             * that are ancestors of this block; PoW, merkle, structure and
             * every UTXO check still run. Honoured ONLY when set explicitly
             * (2026-09-01); with no value this node verifies every script of
             * every block, which stays the default and the README's promise.
             * "0" disables it, as in Core. */
            const char* v = val;
            if(!v || !*v || !strcmp(v,"0")){ g_cfg.assumevalid_mode = 2; applied++;
                fprintf(stderr,"[config] assumevalid=0: every script of every block is evaluated (Core's default skips them below its built-in block)\n"); }
            else if(strlen(v)==64){
                int okh = 1;
                for(int q=0;q<32;q++){
                    int hi = hexval(v[2*q]), lo = hexval(v[2*q+1]);
                    if(hi<0||lo<0){ okh=0; break; }
                    g_cfg.assumevalid[31-q] = (unsigned char)((hi<<4)|lo);   /* display order -> wire order */
                }
                if(okh){ g_cfg.assumevalid_mode = 1; applied++;
                         fprintf(stderr,"[config] assumevalid=%s: script evaluation is skipped for blocks at or below it (Core semantics); every other consensus check still runs\n", v); }
                else { fprintf(stderr,"[config] assumevalid: not a 64-hex block hash -- ignored\n"); bad++; }
            } else { fprintf(stderr,"[config] assumevalid: not a 64-hex block hash -- ignored\n"); bad++; } }

        else if(!strcmp(key,"dnsseed")){      /* Core: query the DNS seeds  */
            g_cfg.dnsseed = iv?1:0; saw_dnsseed = 1; applied++; }
        else if(!strcmp(key,"seednode")){     /* Core: getaddr from, then drop */
            if(cfg_addlist(g_cfg.seednode,g_cfg.seednode_port,&g_cfg.n_seednode,val,key,&bad)) applied++; }
        else if(!strcmp(key,"addnode")){      /* Core: prefer + keep connected */
            if(cfg_addlist(g_cfg.addnode,g_cfg.addnode_port,&g_cfg.n_addnode,val,key,&bad)) applied++; }
        else if(!strcmp(key,"connect")){
            /* Core: connect ONLY to these; `connect=0` means no automatic
             * connections at all. Either form sets connect_only, which is
             * what the rest of the daemon keys off. */
            if(!strcmp(val,"0")){ g_cfg.n_connect = 0; g_cfg.connect_only = 1; applied++; }
            else if(cfg_addlist(g_cfg.connectn,g_cfg.connectn_port,&g_cfg.n_connect,val,key,&bad)){
                g_cfg.connect_only = 1; applied++;
            } }
        else if(!strcmp(key,"signer")){
            /* Core: the external signer command (HWI). Stored verbatim; the
             * RPC layer shells out to it for enumeratesigners /
             * walletdisplayaddress. */
            snprintf(g_cfg.signer, sizeof g_cfg.signer, "%s", val); applied++; }
        /* ---- Core -zmqpub<topic>=<address> ----
         * Validated only for shape here; the bind happens at daemon start
         * (zmqpub_add), because a bind failure must be reported once, in the
         * daemon's own startup log, rather than while parsing a file. */
        else if(!strcmp(key,"zmqpubhashblock")){ snprintf(g_cfg.zmq_hashblock,sizeof g_cfg.zmq_hashblock,"%s",val); applied++; }
        else if(!strcmp(key,"zmqpubhashtx"))   { snprintf(g_cfg.zmq_hashtx,   sizeof g_cfg.zmq_hashtx,   "%s",val); applied++; }
        else if(!strcmp(key,"zmqpubrawblock")) { snprintf(g_cfg.zmq_rawblock, sizeof g_cfg.zmq_rawblock, "%s",val); applied++; }
        else if(!strcmp(key,"zmqpubrawtx"))    { snprintf(g_cfg.zmq_rawtx,    sizeof g_cfg.zmq_rawtx,    "%s",val); applied++; }
        else if(!strcmp(key,"zmqpubsequence")){
            /* REFUSED, deliberately, and this is not laziness.
             *
             * Core's `sequence` topic exists so a subscriber can track mempool
             * membership EXACTLY: it carries A(dd) and R(emove) alongside
             * C(onnect)/D(isconnect). This node has one clean choke point for
             * "accepted" but no single one for "removed" -- eviction, expiry
             * and reorg each call mpool_del independently.
             *
             * Publishing A without R would be worse than publishing nothing:
             * a subscriber's model of the mempool would grow and never shrink,
             * and it would have no way to know. So the topic refuses, loudly,
             * instead of emitting a stream that quietly lies. */
            fprintf(stderr,"[config] zmqpubsequence is NOT supported: this node has no single "
                           "mempool-removal choke point, so it could publish adds but not "
                           "removes -- a subscriber tracking membership from that would drift "
                           "silently. Use zmqpubrawtx/zmqpubhashtx for arrivals.\n");
            bad++; }
        else if(!strncmp(key,"zmqpub",6)){
            fprintf(stderr,"[config] unknown ZMQ topic '%s' (have: hashblock, hashtx, rawblock, rawtx)\n", key);
            bad++; }
        else if(!strcmp(key,"blocksonly")){
            /* Core: do not participate in tx relay. We honour it by setting
             * relay=0 on ordinary outbound legs too, which is what the flag
             * means on the wire. */
            g_cfg.blocksonly = iv?1:0; applied++; }

        /* ---- extensions: Core has no equivalent option (these are
         * compile-time constants there). Prefixed so they are obviously not
         * Core keys and cannot collide with a future Core option. ---- */
        else if(!strcmp(key,"bmc.blockrelayonly"))    { t=clamp_int(iv,0,16,key,&bad);     if(t>=0){g_cfg.max_block_relay_only=t;applied++;} }
        else if(!strcmp(key,"bmc.feelers"))           { t=clamp_int(iv,0,8,key,&bad);      if(t>=0){g_cfg.max_feeler=t;applied++;} }
        else if(!strcmp(key,"bmc.feelerinterval"))    { t=clamp_int(iv,10000,3600000,key,&bad); if(t>=0){g_cfg.feeler_interval_ms=t;applied++;} }
        else if(!strcmp(key,"bmc.maxoutbound"))       { t=clamp_int(iv,1,64,key,&bad);     if(t>=0){g_cfg.max_outbound=t;applied++;} }
        else if(!strcmp(key,"bmc.peerminbps"))        { t=clamp_int(iv,1024,10485760,key,&bad); if(t>=0){g_cfg.dead_weight_bps=(double)t;applied++;} }
        else if(!strcmp(key,"bmc.peerminticks"))      { t=clamp_int(iv,1,60,key,&bad);     if(t>=0){g_cfg.dead_weight_ticks=t;applied++;} }
        else if(!strcmp(key,"bmc.peerminusable"))     { t=clamp_int(iv,1,256,key,&bad);    if(t>=0){g_cfg.min_usable_peers=t;applied++;} }
        else if(!strcmp(key,"bmc.peerpool"))          { t=clamp_int(iv,16,8192,key,&bad);  if(t>=0){g_cfg.maxpool=t;applied++;} }
        else if(!strcmp(key,"bmc.addrmaxperresponse")){ t=clamp_int(iv,1,1000,key,&bad);   if(t>=0){g_cfg.addr_max_per_response=t;applied++;} }
        else if(!strcmp(key,"bmc.addrmaxpernetgroup")){ t=clamp_int(iv,1,256,key,&bad);    if(t>=0){g_cfg.addr_max_per_netgroup=t;applied++;} }
        else if(!strcmp(key,"bmc.utxobulkgapblocks")) { t=clamp_int(iv,0,1000000,key,&bad);if(t>=0){g_cfg.utxo_bulk_gap_blocks=t;applied++;} }
        else if(!strcmp(key,"bmc.utxocompactthreshold")){ t=clamp_int(iv,2,4096,key,&bad); if(t>=0){g_cfg.utxo_compact_threshold=t;applied++;} }
        /* anything else (rpcport, rpcuser, dbcache, ...) belongs to another
         * consumer of this shared file -- ignore rather than warn.
         *
         * EXCEPT a Core option this node does not implement. Silently
         * accepting one is the failure mode this whole config surface keeps
         * hitting: `whitelist=rpc` has been sitting in the live conf doing
         * nothing, and `externalip` was parsed-but-unread for weeks. An
         * operator who sets a real Core option deserves to be told it has no
         * effect here, rather than discovering it from behaviour. */
        /* ---- 2026-09-01: Core v31.99 option-surface completion ---- */
        else if(!strcmp(key,"uacomment")){
            /* Core SAFE_CHARS_UA_COMMENT: printable ASCII minus ( ) / \ ; : and control */
            int okc = *val != 0;
            for(const char* c = val; *c; c++)
                if(*c < 0x20 || *c > 0x7e || *c=='(' || *c==')' || *c=='/' || *c=='\\' || *c==';' || *c==':') okc = 0;
            if(!okc){ fprintf(stderr,"[config] uacomment=%s contains unsafe characters -- ignoring\n", val); bad++; }
            else if(g_cfg.n_uacomment >= 4){ fprintf(stderr,"[config] uacomment: at most 4 entries -- ignoring %s\n", val); bad++; }
            else if(strlen(val) > 63){ fprintf(stderr,"[config] uacomment=%s too long (max 63) -- ignoring\n", val); bad++; }
            else { snprintf(g_cfg.uacomment[g_cfg.n_uacomment++], 64, "%s", val); applied++; } }
        else if(!strcmp(key,"blockmaxweight")){
            t=clamp_int(iv,4000,4000000,key,&bad); if(t>=0){ g_cfg.blockmaxweight=t; applied++; } }
        else if(!strcmp(key,"blockreservedweight")){
            t=clamp_int(iv,2000,4000000,key,&bad); if(t>=0){ g_cfg.blockreservedweight=t; applied++; } }
        else if(!strcmp(key,"blockmintxfee") || !strcmp(key,"mintxfee") || !strcmp(key,"fallbackfee") ||
                !strcmp(key,"discardfee") || !strcmp(key,"consolidatefeerate")){
            double btc = atof(val);
            if(btc < 0 || btc >= 1.0){ fprintf(stderr,"[config] %s=%s out of range -- ignoring\n", key, val); bad++; }
            else { long satkvb = (long)(btc * 1e8 + 0.5);
                   if(!strcmp(key,"blockmintxfee"))      g_cfg.blockmintxfee_satkvb = satkvb;
                   else if(!strcmp(key,"mintxfee"))      g_cfg.mintxfee_satkvb = satkvb;
                   else if(!strcmp(key,"fallbackfee"))   g_cfg.fallbackfee_satkvb = satkvb;
                   else if(!strcmp(key,"discardfee"))    g_cfg.discardfee_satkvb = satkvb;
                   else                                  g_cfg.consolidatefeerate_satkvb = satkvb;
                   applied++; } }
        else if(!strcmp(key,"maxapsfee")){           /* Core: BTC absolute; -1 = always avoid partial spends */
            double btc = atof(val);
            if(btc < 0){ g_cfg.maxapsfee_sat = -1; applied++; }
            else if(btc >= 1.0){ fprintf(stderr,"[config] maxapsfee=%s out of range -- ignoring\n", val); bad++; }
            else { g_cfg.maxapsfee_sat = (long)(btc * 1e8 + 0.5); applied++; } }
        else if(!strcmp(key,"blockversion")){ g_cfg.blockversion = iv; applied++; }
        else if(!strcmp(key,"printpriority")){ g_cfg.printpriority = iv?1:0; applied++; }
        else if(!strcmp(key,"avoidpartialspends")){ g_cfg.avoidpartialspends = iv?1:0; applied++; }
        else if(!strcmp(key,"spendzeroconfchange")){ g_cfg.spendzeroconfchange = iv?1:0; applied++; }
        else if(!strcmp(key,"walletrbf")){ g_cfg.walletrbf = iv?1:0; applied++; }
        else if(!strcmp(key,"walletbroadcast")){ g_cfg.walletbroadcast = iv?1:0; applied++; }
        else if(!strcmp(key,"txconfirmtarget")){
            t=clamp_int(iv,1,1008,key,&bad); if(t>=0){ g_cfg.txconfirmtarget=t; applied++; } }
        else if(!strcmp(key,"keypool")){
            t=clamp_int(iv,1,1000000,key,&bad); if(t>=0){ g_cfg.keypool=t; applied++; } }
        else if(!strcmp(key,"walletnotify")){
            snprintf(g_cfg.walletnotify,sizeof g_cfg.walletnotify,"%s",val); applied++; }
        else if(!strcmp(key,"wallet")){
            if(g_cfg.n_wallet_names >= 8){ fprintf(stderr,"[config] wallet: at most 8 entries -- ignoring %s\n", val); bad++; }
            else if(strchr(val,'/') || strlen(val) > 63){ fprintf(stderr,"[config] wallet=%s: a wallet NAME (no path), max 63 chars -- ignoring\n", val); bad++; }
            else { snprintf(g_cfg.wallet_names[g_cfg.n_wallet_names++], 64, "%s", val); applied++; } }
        else if(!strcmp(key,"addresstype") || !strcmp(key,"changetype")){
            if(strcmp(val,"legacy") && strcmp(val,"p2sh-segwit") && strcmp(val,"bech32") && strcmp(val,"bech32m")){
                fprintf(stderr,"[config] %s=%s: expected legacy, p2sh-segwit, bech32 or bech32m -- ignoring\n", key, val); bad++; }
            else { snprintf(!strcmp(key,"addresstype") ? g_cfg.addresstype : g_cfg.changetype, 16, "%s", val); applied++; } }
        else if(!strcmp(key,"maxtipage")){
            long long lv = nodecfg_strtoll(val, key, 0);   /* DMN-9: bounded */
            if(lv < 0){ fprintf(stderr,"[config] maxtipage=%s out of range -- ignoring\n", val); bad++; }
            else { g_cfg.maxtipage = (long)lv; applied++; } }
        else if(!strcmp(key,"inboundrelaypercent")){
            t=clamp_int(iv,0,100,key,&bad); if(t>=0){ g_cfg.inboundrelaypercent=t; applied++; } }
        else if(!strcmp(key,"whitelistrelay")){ g_cfg.whitelistrelay = iv?1:0; g_cfg.whitelistrelay_explicit = 1; applied++; }
        else if(!strcmp(key,"acceptstalefeeestimates")){ g_cfg.acceptstalefeeestimates = iv?1:0; applied++; }
        else if(!strcmp(key,"whitelistforcerelay")){ g_cfg.whitelistforcerelay = iv?1:0; applied++; }
        else if(!strcmp(key,"peerbloomfilters")){
            g_cfg.peerbloomfilters = iv?1:0;
            if(iv) fprintf(stderr,"[config] peerbloomfilters=1: BIP37 bloom filtering is not implemented -- NODE_BLOOM is not advertised\n");
            applied++; }
        else if(!strcmp(key,"peerblockfilters")){ g_cfg.peerblockfilters = iv?1:0; applied++; }
        else if(!strcmp(key,"fixedseeds")){ g_cfg.fixedseeds = iv?1:0; applied++; }
        else if(!strcmp(key,"txreconciliation")){ g_cfg.txreconciliation = iv?1:0; applied++; }
        else if(!strcmp(key,"signetseednode")){
            if(g_cfg.n_signetseednode >= 4){ fprintf(stderr,"[config] signetseednode: at most 4 entries -- ignoring %s\n", val); bad++; }
            else if(strlen(val) > 79 || !*val){ fprintf(stderr,"[config] signetseednode=%s rejected\n", val); bad++; }
            else { snprintf(g_cfg.signetseednode[g_cfg.n_signetseednode++], 80, "%s", val); applied++; } }
        else if(!strcmp(key,"logips")){ g_cfg.logips = iv?1:0; applied++; }
        else if(!strcmp(key,"logtimestamps")){ g_cfg.logtimestamps = iv?1:0; applied++; }
        else if(!strcmp(key,"logtimemicros")){ g_cfg.logtimemicros = iv?1:0; applied++; }
        else if(!strcmp(key,"logthreadnames")){ g_cfg.logthreadnames = iv?1:0; applied++; }
        else if(!strcmp(key,"logsourcelocations")){ g_cfg.logsourcelocations = iv?1:0; applied++; }
        else if(!strcmp(key,"shrinkdebugfile")){ g_cfg.shrinkdebugfile = iv?1:0; applied++; }
        else if(!strcmp(key,"printtoconsole")){ g_cfg.printtoconsole = iv?1:0; applied++; }
        else if(!strcmp(key,"loglevel")){ snprintf(g_cfg.loglevel,sizeof g_cfg.loglevel,"%s",val); applied++; }
        else if(!strcmp(key,"rpcthreads")){
            t=clamp_int(iv,1,256,key,&bad); if(t>=0){ g_cfg.rpcthreads=t; applied++; } }
        else if(!strcmp(key,"rpcworkqueue")){
            t=clamp_int(iv,1,4096,key,&bad); if(t>=0){ g_cfg.rpcworkqueue=t; applied++; } }
        else if(!strcmp(key,"rpcservertimeout")){
            t=clamp_int(iv,1,86400,key,&bad); if(t>=0){ g_cfg.rpcservertimeout=t; applied++; } }
        else if(!strcmp(key,"rpcwhitelist")){
            if(!strchr(val,':')){ fprintf(stderr,"[config] rpcwhitelist=%s: expected <user>:<rpc1>,<rpc2>,... -- ignoring\n", val); bad++; }
            else if(g_cfg.n_rpcwhitelist >= 16){ fprintf(stderr,"[config] rpcwhitelist: at most 16 entries -- ignoring %s\n", val); bad++; }
            else if(strlen(val) > 511){ fprintf(stderr,"[config] rpcwhitelist entry too long -- ignoring\n"); bad++; }
            else { snprintf(g_cfg.rpcwhitelist[g_cfg.n_rpcwhitelist++], 512, "%s", val); applied++; } }
        else if(!strcmp(key,"rpcwhitelistdefault")){ g_cfg.rpcwhitelistdefault = iv?1:0; applied++; }
        else if(!strcmp(key,"rpccookieperms")){
            if(!strcmp(val,"owner")) g_cfg.rpccookieperms = 0;
            else if(!strcmp(val,"group")) g_cfg.rpccookieperms = 1;
            else if(!strcmp(val,"all")) g_cfg.rpccookieperms = 2;
            else { fprintf(stderr,"[config] rpccookieperms=%s: expected owner, group or all -- ignoring\n", val); bad++; continue; }
            applied++; }
        else if(!strcmp(key,"limitclustercount")){
            /* Core v31 bounds a mempool cluster; this mempool's ancestor/descendant
             * limits are the same bound seen from either end of a chain */
            t=clamp_int(iv,1,10000,key,&bad); if(t>=0){ g_cfg.limitclustercount=t; g_cfg.limitancestorcount=t; g_cfg.limitdescendantcount=t; applied++; } }
        else if(!strcmp(key,"limitclustersize")){    /* Core: kvB */
            t=clamp_int(iv,1,100000,key,&bad); if(t>=0){ g_cfg.limitclustersize_kvb=t; g_cfg.limitancestorsize_kvb=t; g_cfg.limitdescendantsize_kvb=t; applied++; } }
        else if(!strcmp(key,"checkblockindex")){ g_cfg.checkblockindex = iv?1:0; applied++; }
        else if(!strcmp(key,"checkmempool")){ g_cfg.checkmempool = iv?1:0; applied++; }
        else if(!strcmp(key,"checkaddrman")){ g_cfg.checkaddrman = iv?1:0; applied++; }
        else if(!strcmp(key,"capturemessages")){ g_cfg.capturemessages = iv?1:0; applied++; }
        else if(!strcmp(key,"stopafterblockimport")){ g_cfg.stopafterblockimport = iv?1:0; applied++; }
        else if(!strcmp(key,"mocktime")){ g_cfg.mocktime = atoll(val); applied++; }
        else if(!strcmp(key,"includeconf")){
            if(g_include_depth){ fprintf(stderr,"[config] includeconf inside an included file is not allowed (Core rule) -- ignoring %s\n", val); bad++; }
            else if(g_cfg.n_includeconf >= 8){ fprintf(stderr,"[config] includeconf: at most 8 files -- ignoring %s\n", val); bad++; }
            else if(strlen(val) > 255 || !*val){ fprintf(stderr,"[config] includeconf=%s rejected\n", val); bad++; }
            else { snprintf(g_cfg.includeconf[g_cfg.n_includeconf++], 256, "%s", val); applied++; } }
        else if(nodecfg_unimplemented(key)){
            fprintf(stderr,"[config] %s= is a Bitcoin Core option that has NO EFFECT here: %s\n",
                    key, nodecfg_noeffect_reason(key));
            unimpl++;
        }
    }
    fclose(f);
    if(unimpl)
        fprintf(stderr,"[config] %d Core option(s) in this file have no effect here "
                       "and were ignored (each named above)\n", unimpl);
    /* -includeconf: Core reads each named file after the main one, relative
     * to the main file's directory; an included file may not include. */
    if(!g_include_depth && g_cfg.n_includeconf){
        char dir[512]; snprintf(dir, sizeof dir, "%s", path);
        char* sl = strrchr(dir, '/'); if(sl) sl[1] = 0; else dir[0] = 0;
        int n = g_cfg.n_includeconf; g_include_depth = 1;
        for(int i = 0; i < n; i++){
            char ip[800];
            if(g_cfg.includeconf[i][0] == '/') snprintf(ip, sizeof ip, "%s", g_cfg.includeconf[i]);
            else snprintf(ip, sizeof ip, "%s%s", dir, g_cfg.includeconf[i]);
            fprintf(stderr,"[config] includeconf: reading %s\n", ip);
            long a = node_config_load(ip);
            if(a > 0) applied += a;
        }
        g_include_depth = 0;
    }

    /* -whitelistrelay / -whitelistforcerelay: the permissions implicit
     * whitelist entries carry (recomputed now, after every line is read) */
    /* Core init.cpp parameter interactions, same log lines:
     *   -blocksonly=1 -> -whitelistrelay=0 (unless set) and -maxmempool=5 (unless set)
     *   -whitelistforcerelay=1 -> -whitelistrelay=1 */
    if(!g_include_depth){
        if(g_cfg.blocksonly){
            if(!g_cfg.whitelistrelay_explicit && g_cfg.whitelistrelay){ g_cfg.whitelistrelay = 0;
                fprintf(stderr,"[config] parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0\n"); }
            if(!g_cfg.maxmempool_explicit && g_cfg.maxmempool_mb != 5){ g_cfg.maxmempool_mb = 5;
                fprintf(stderr,"[config] parameter interaction: -blocksonly=1 -> setting -maxmempool=5\n"); }
        }
        if(g_cfg.whitelistforcerelay && !g_cfg.whitelistrelay && !g_cfg.whitelistrelay_explicit){ g_cfg.whitelistrelay = 1;   /* SoftSet: an explicit 0 stands */
            fprintf(stderr,"[config] parameter interaction: -whitelistforcerelay=1 -> setting -whitelistrelay=1\n"); }
    }
    if(!g_include_depth) netperm_set_implicit_defaults(g_cfg.whitelistrelay, g_cfg.whitelistforcerelay);
    /* -signetseednode: seed nodes that apply only when the chain is signet
     * (Core keeps them separate so a shared file can carry both). */
    if(!g_include_depth && !strcmp(g_cfg.chain, "signet"))
        for(int i = 0; i < g_cfg.n_signetseednode; i++){
            if(g_cfg.n_seednode >= CFG_MAX_NODES) break;
            snprintf(g_cfg.seednode[g_cfg.n_seednode++], sizeof g_cfg.seednode[0], "%s", g_cfg.signetseednode[i]);
        }
    /* -connect's implications, applied once the whole file has been seen. */
    if(g_cfg.connect_only){
        if(!saw_dnsseed && g_cfg.dnsseed){
            g_cfg.dnsseed = 0;
            fprintf(stderr,"[config] connect= set -- disabling dnsseed (Core does the same; set dnsseed=1 to override)\n");
        }
        if(!saw_listen && g_cfg.listen){
            g_cfg.listen = 0;
            fprintf(stderr,"[config] connect= set -- disabling listen (Core does the same; set listen=1 to override)\n");
        }
    }

    /* Cross-field sanity: outbound classes must leave room for inbound. */
    int outbound = g_cfg.max_outbound + g_cfg.max_block_relay_only + g_cfg.max_feeler;
    if(outbound >= g_cfg.max_connections){
        fprintf(stderr,"[config] outbound classes (%d) >= maxconnections (%d) -- would leave no inbound slots; reverting connection budget to defaults\n",
                outbound, g_cfg.max_connections);
        g_cfg.max_connections=200;   /* Core v31 default -- must track the
                                      * value at the top of this file, not the
                                      * 125 this line was written against */
        g_cfg.max_outbound=8;
        g_cfg.max_block_relay_only=2; g_cfg.max_feeler=1;
        bad++;
    }
    fprintf(stderr,"[config] loaded %s: %ld setting(s) applied%s\n",
            path, applied, bad?" (some rejected -- see above)":"");
    return applied;
}

void node_config_log(void){
    int outbound = g_cfg.max_outbound + g_cfg.max_block_relay_only + g_cfg.max_feeler;
    fprintf(stderr,"[config] conns: max=%d outbound=%d (full=%d blockrelay=%d feeler=%d) inbound=%d feeler_every=%lds\n",
            g_cfg.max_connections, outbound, g_cfg.max_outbound,
            g_cfg.max_block_relay_only, g_cfg.max_feeler,
            g_cfg.max_connections-outbound, g_cfg.feeler_interval_ms/1000);
    fprintf(stderr,"[config] peers: min_bps=%.0f ticks=%d min_usable=%d pool=%d\n",
            g_cfg.dead_weight_bps, g_cfg.dead_weight_ticks,
            g_cfg.min_usable_peers, g_cfg.maxpool);
    fprintf(stderr,"[config] addr : max_per_response=%d max_per_netgroup=%d\n",
            g_cfg.addr_max_per_response, g_cfg.addr_max_per_netgroup);
    fprintf(stderr,"[config] utxo : dbcache=%dMB -> bulk_slots=2^%d bulk_blob=%dMB bulk_gap=%ld compact_at=%d\n",
            g_cfg.dbcache_mb, g_cfg.utxo_bulk_slots_log2, g_cfg.utxo_bulk_blob_mb,
            g_cfg.utxo_bulk_gap_blocks, g_cfg.utxo_compact_threshold);
    fprintf(stderr,"[config] pool : maxmempool=%ldMB mempoolexpiry=%ldh maxuploadtarget=%ldMB\n",
            g_cfg.maxmempool_mb, g_cfg.mempoolexpiry_h, g_cfg.maxuploadtarget_mb);
    fprintf(stderr,"[config] mpol : minrelay=%ld inc=%ld sat/vB, anc=%ld/%ldkvB desc=%ld/%ldkvB fullrbf=%d\n",
            g_cfg.minrelaytxfee_satkvb, g_cfg.incrementalrelayfee_satkvb,
            g_cfg.limitancestorcount, g_cfg.limitancestorsize_kvb,
            g_cfg.limitdescendantcount, g_cfg.limitdescendantsize_kvb, g_cfg.mempoolfullrbf);
    fprintf(stderr,"[config] res  : par=%d (%s) maxreceivebuffer=%d*1000B\n",
            g_cfg.par, g_cfg.par==0?"auto":(g_cfg.par<0?"leave cores free":"fixed"),
            g_cfg.maxrecvbuffer_kb);
    fprintf(stderr,"[config] net  : port=%d bind=%s listen=%d blocksonly=%d timeout=%dms peertimeout=%ds\n",
            g_cfg.port, g_cfg.bind_addr[0]?g_cfg.bind_addr:"0.0.0.0", g_cfg.listen,
            g_cfg.blocksonly, g_cfg.connect_timeout_ms, g_cfg.peer_timeout_s);
    fprintf(stderr,"[config] src  : dnsseed=%d seednode=%d addnode=%d connect=%d%s\n",
            g_cfg.dnsseed, g_cfg.n_seednode, g_cfg.n_addnode, g_cfg.n_connect,
            g_cfg.connect_only?" (connect-only: no automatic peer discovery)":"");
    for(int i=0;i<g_cfg.n_addnode;i++)  fprintf(stderr,"[config] src  :   addnode  %s\n", g_cfg.addnode[i]);
    for(int i=0;i<g_cfg.n_seednode;i++) fprintf(stderr,"[config] src  :   seednode %s\n", g_cfg.seednode[i]);
    for(int i=0;i<g_cfg.n_connect;i++)  fprintf(stderr,"[config] src  :   connect  %s\n", g_cfg.connectn[i]);
    fprintf(stderr,"[config] chain: prune=%s checkblocks=%s checklevel=%d stopatheight=%s\n",
            g_cfg.prune_mib==0?"off":(g_cfg.prune_mib==1?"manual-only":"MiB-budget"),
            g_cfg.checkblocks?"n":"all", g_cfg.checklevel,
            g_cfg.stopatheight?"set":"none");
    if(g_cfg.prune_mib>1)     fprintf(stderr,"[config] chain:   prune budget %ld MiB\n", g_cfg.prune_mib);
    if(g_cfg.checkblocks)     fprintf(stderr,"[config] chain:   checking last %ld block(s)\n", g_cfg.checkblocks);
    if(g_cfg.stopatheight)    fprintf(stderr,"[config] chain:   stopping at height %ld\n", g_cfg.stopatheight);
    fprintf(stderr,"[config] mine : blockmaxweight=%d reserved=%d blockmintxfee=%ld sat/kvB version=%s printpriority=%d\n",
            g_cfg.blockmaxweight, g_cfg.blockreservedweight, g_cfg.blockmintxfee_satkvb,
            g_cfg.blockversion ? "override" : "0x20000000", g_cfg.printpriority);
    fprintf(stderr,"[config] wallet: addresstype=%s changetype=%s txconfirmtarget=%d walletrbf=%d broadcast=%d "
                   "mintxfee=%ld fallbackfee=%ld discardfee=%ld consolidate=%ld sat/kvB aps=%d/%ld zeroconfchange=%d wallets=%d\n",
            g_cfg.addresstype, g_cfg.changetype[0] ? g_cfg.changetype : "(auto)", g_cfg.txconfirmtarget, g_cfg.walletrbf,
            g_cfg.walletbroadcast, g_cfg.mintxfee_satkvb, g_cfg.fallbackfee_satkvb, g_cfg.discardfee_satkvb,
            g_cfg.consolidatefeerate_satkvb, g_cfg.avoidpartialspends, g_cfg.maxapsfee_sat, g_cfg.spendzeroconfchange,
            g_cfg.n_wallet_names);
    fprintf(stderr,"[config] rpc  : threads=%d workqueue=%d timeout=%ds whitelists=%d(default=%s) cookieperms=%s\n",
            g_cfg.rpcthreads, g_cfg.rpcworkqueue, g_cfg.rpcservertimeout, g_cfg.n_rpcwhitelist,
            g_cfg.rpcwhitelistdefault < 0 ? "auto" : (g_cfg.rpcwhitelistdefault ? "1" : "0"),
            g_cfg.rpccookieperms == 0 ? "owner" : (g_cfg.rpccookieperms == 1 ? "group" : "all"));
    fprintf(stderr,"[config] log  : timestamps=%d micros=%d threadnames=%d sourcelocations=%d shrink=%d\n",
            g_cfg.logtimestamps, g_cfg.logtimemicros, g_cfg.logthreadnames, g_cfg.logsourcelocations, g_cfg.shrinkdebugfile);
    fprintf(stderr,"[config] peers: maxtipage=%lds inboundrelay=%d%% whitelistrelay=%d forcerelay=%d peerblockfilters=%d uacomment=%d\n",
            g_cfg.maxtipage, g_cfg.inboundrelaypercent, g_cfg.whitelistrelay, g_cfg.whitelistforcerelay,
            g_cfg.peerblockfilters, g_cfg.n_uacomment);
}

/* -acceptstalefeeestimates for daemon/mempool_cfg.c (weakly bound there). */
int node_config_accept_stale_fee(void){ return g_cfg.acceptstalefeeestimates; }

/* Small accessor for callers that link this file only weakly (rpc_node.c's
 * getnetworkinfo needs g_cfg's proxy fields, but bmc_cli -- a pure HTTP
 * client that never executes that RPC's implementation -- does not link
 * this file at all). Exporting one narrow function keeps g_cfg itself out
 * of that weak-symbol surface, which matters because g_cfg is a struct
 * object, not a pointer: an unresolved weak OBJECT has no clean "is this
 * present" check the way a weak FUNCTION POINTER does (compared against
 * NULL, the convention this file's callers already use for fest_estimate_*
 * and g_chainp). */
void node_config_get_proxy_info(const char** proxy, const char** onion_proxy,
                                const char** i2psam, int* proxyrandomize){
    *proxy = g_cfg.proxy; *onion_proxy = g_cfg.onion_proxy;
    *i2psam = g_cfg.i2psam; *proxyrandomize = g_cfg.proxyrandomize;
}
