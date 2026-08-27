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
#include <string.h>
#include <unistd.h>
#include "node_config.h"

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
    .minrelaytxfee_satvb   = 1,      /* Core -minrelaytxfee 0.00001 BTC/kvB  */
    .incrementalrelayfee_satvb = 1,  /* Core -incrementalrelayfee default    */
    .limitancestorcount    = 25,     /* Core -limitancestorcount default     */
    .limitancestorsize_kvb = 101,    /* Core -limitancestorsize default (kvB)*/
    .limitdescendantcount  = 25,     /* Core -limitdescendantcount default   */
    .limitdescendantsize_kvb = 101,  /* Core -limitdescendantsize default    */
    .mempoolfullrbf        = 1,      /* Core -mempoolfullrbf default (v28+)  */
    .dnsseed               = 1,      /* Core -dnsseed default: on            */
    .connect_only          = 0,
    .n_seednode            = 0,
    .n_addnode             = 0,
    .n_connect             = 0,
    .prune_mib             = 0,      /* Core -prune default: disabled        */
    .checkblocks           = 6,      /* Core -checkblocks default            */
    .checklevel            = 3,      /* Core -checklevel default             */
    .stopatheight          = 0,      /* Core -stopatheight default: no stop  */
};

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
    g_cfg.utxo_bulk_slots_log2  = 22;
    g_cfg.utxo_bulk_blob_mb     = 1024;
    g_cfg.utxo_bulk_gap_blocks  = 50000L;
    g_cfg.utxo_compact_threshold= 12;
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
    g_cfg.minrelaytxfee_satvb   = 1;
    g_cfg.incrementalrelayfee_satvb = 1;
    g_cfg.limitancestorcount    = 25;
    g_cfg.limitancestorsize_kvb = 101;
    g_cfg.limitdescendantcount  = 25;
    g_cfg.limitdescendantsize_kvb = 101;
    g_cfg.mempoolfullrbf        = 1;
    g_cfg.dnsseed               = 1;
    g_cfg.connect_only          = 0;
    g_cfg.n_seednode = g_cfg.n_addnode = g_cfg.n_connect = 0;
    g_cfg.seednode[0][0] = g_cfg.addnode[0][0] = g_cfg.connectn[0][0] = 0;
    g_cfg.prune_mib             = 0;
    g_cfg.checkblocks           = 6;
    g_cfg.checklevel            = 3;
    g_cfg.stopatheight          = 0;
}

/* Append one host to a repeatable-key list.
 *
 * Accepts "host" or "host:port". A per-entry port cannot be honoured yet --
 * every dial path downstream (dl_bootstrap, dlc_probe_round, the workers,
 * addr_gather_from) takes a bare IP string and dials one fixed port -- so a
 * NON-DEFAULT port is REJECTED rather than silently dialled on 8333. Being
 * loudly unsupported beats connecting somewhere the operator did not ask for.
 * Returns 1 if the entry was stored. */
static int cfg_addlist(char list[][64], int* n, const char* val, const char* key, int* bad){
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
    { char* colon = strrchr(host,':');
      if(colon){
        int p = atoi(colon+1);
        /* 8333 (main) or 18444 (regtest) -- the port is stripped here and the
         * dial paths use the chain's own g_cfg.port for every connection, so
         * this guard only refuses ports that could never be honoured. Checked
         * against both chain defaults because chain= may appear on any line
         * of the file relative to this entry. */
        if(p != 8333 && p != 18444){
            fprintf(stderr,"[config] %s=%s -- only a chain's default P2P port (8333 main, 18444 regtest) is supported for named peers; ignoring this entry\n", key, val);
            (*bad)++; return 0;
        }
        *colon = 0;
      } }
    if(!host[0]){ fprintf(stderr,"[config] %s=%s has no host part -- ignoring\n", key, val); (*bad)++; return 0; }
    for(int i=0;i<*n;i++) if(!strcmp(list[i],host)) return 0;   /* dedupe, silently */
    if(*n >= CFG_MAX_NODES){
        fprintf(stderr,"[config] %s=%s ignored -- at most %d entries per key\n", key, val, CFG_MAX_NODES);
        (*bad)++; return 0;
    }
    snprintf(list[*n], 64, "%s", host); (*n)++;
    return 1;
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
static int clamp_int(int v, int lo, int hi, const char* key, int* bad){
    if(v < lo || v > hi){
        fprintf(stderr,"[config] %s=%d out of range [%d,%d] -- ignoring\n", key, v, lo, hi);
        (*bad)++; return -1;
    }
    return v;
}

const char* node_config_path(const char* datadir, char* buf, unsigned long cap){
    const char* env = getenv("BITCOIN_CONF");
    if(env && *env){ snprintf(buf, cap, "%s", env); return buf; }
    snprintf(buf, cap, "%s/bitcoin.conf", datadir);
    if(access(buf, R_OK)==0) return buf;
    snprintf(buf, cap, "%s/../config/bitcoin.conf", datadir);
    return buf;
}

long node_config_load(const char* path){
    set_defaults();
    FILE* f = fopen(path, "r");
    if(!f){
        fprintf(stderr,"[config] no config file at %s -- using compiled defaults\n", path);
        return 0;
    }
    long applied = 0; int bad = 0;
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
        char* eq = strchr(p,'='); if(!eq) continue;
        *eq = 0;
        char* key = p; char* val = eq+1;
        size_t vl = strlen(val);
        while(vl && (val[vl-1]=='\n'||val[vl-1]=='\r'||val[vl-1]==' '||val[vl-1]=='\t')) val[--vl]=0;
        size_t kl = strlen(key);
        while(kl && (key[kl-1]==' '||key[kl-1]=='\t')) key[--kl]=0;

        int iv = atoi(val); int t;

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
            t=clamp_int(iv,1,65536,key,&bad); if(t>=0){ g_cfg.maxmempool_mb=t; applied++; } }
        else if(!strcmp(key,"mempoolexpiry")){ /* Core: hours */
            t=clamp_int(iv,0,8760,key,&bad);  if(t>=0){ g_cfg.mempoolexpiry_h=t; applied++; } }
        /* mempool policy limits (Core limit-count/size, relay fees, mempoolfullrbf).
         * The two fees are BTC/kvB in Core's config; convert to sat/vByte:
         * sat/vB = round(BTC/kvB * 1e8 / 1000) = round(BTC/kvB * 1e5). */
        else if(!strcmp(key,"minrelaytxfee") || !strcmp(key,"incrementalrelayfee")){
            double btc = atof(val);
            long satvb = (long)(btc * 1e5 + 0.5);
            if(satvb < 0) satvb = 0;
            if(!strcmp(key,"minrelaytxfee"))      g_cfg.minrelaytxfee_satvb = satvb;
            else                                  g_cfg.incrementalrelayfee_satvb = satvb;
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
        else if(!strcmp(key,"maxuploadtarget")){ /* Core: MB per 24h, 0=off */
            t=clamp_int(iv,0,1048576,key,&bad); if(t>=0){ g_cfg.maxuploadtarget_mb=t; applied++; } }
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
            fprintf(stderr,"[config] assumevalid IGNORED -- block connection performs no script/signature "
                           "verification (cons_verify checks PoW, parsing, coinbase and merkle root only), "
                           "so there is nothing for it to skip\n"); }

        else if(!strcmp(key,"dnsseed")){      /* Core: query the DNS seeds  */
            g_cfg.dnsseed = iv?1:0; saw_dnsseed = 1; applied++; }
        else if(!strcmp(key,"seednode")){     /* Core: getaddr from, then drop */
            if(cfg_addlist(g_cfg.seednode,&g_cfg.n_seednode,val,key,&bad)) applied++; }
        else if(!strcmp(key,"addnode")){      /* Core: prefer + keep connected */
            if(cfg_addlist(g_cfg.addnode,&g_cfg.n_addnode,val,key,&bad)) applied++; }
        else if(!strcmp(key,"connect")){
            /* Core: connect ONLY to these; `connect=0` means no automatic
             * connections at all. Either form sets connect_only, which is
             * what the rest of the daemon keys off. */
            if(!strcmp(val,"0")){ g_cfg.n_connect = 0; g_cfg.connect_only = 1; applied++; }
            else if(cfg_addlist(g_cfg.connectn,&g_cfg.n_connect,val,key,&bad)){
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
         * consumer of this shared file -- ignore rather than warn. */
    }
    fclose(f);

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
            g_cfg.minrelaytxfee_satvb, g_cfg.incrementalrelayfee_satvb,
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
}
