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
    .listen                = 1,
    .blocksonly            = 0,
    .bind_addr             = "",     /* empty == INADDR_ANY */
    .par                   = 0,      /* Core -par default: auto              */
    .maxrecvbuffer_kb      = 5000,   /* Core -maxreceivebuffer default       */
    .maxmempool_mb         = 300,    /* Core -maxmempool default (MB)        */
    .mempoolexpiry_h       = 336,    /* Core -mempoolexpiry default (2 weeks)*/
    .maxuploadtarget_mb    = 0,      /* Core -maxuploadtarget default: none  */
    .dnsseed               = 1,      /* Core -dnsseed default: on            */
    .connect_only          = 0,
    .n_seednode            = 0,
    .n_addnode             = 0,
    .n_connect             = 0,
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
    g_cfg.listen                = 1;
    g_cfg.blocksonly            = 0;
    g_cfg.bind_addr[0]          = 0;
    g_cfg.par                   = 0;
    g_cfg.maxrecvbuffer_kb      = 5000;
    g_cfg.maxmempool_mb         = 300;
    g_cfg.mempoolexpiry_h       = 336;
    g_cfg.maxuploadtarget_mb    = 0;
    g_cfg.dnsseed               = 1;
    g_cfg.connect_only          = 0;
    g_cfg.n_seednode = g_cfg.n_addnode = g_cfg.n_connect = 0;
    g_cfg.seednode[0][0] = g_cfg.addnode[0][0] = g_cfg.connectn[0][0] = 0;
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
        if(p != 8333){
            fprintf(stderr,"[config] %s=%s -- only the default P2P port (8333) is supported for named peers; ignoring this entry\n", key, val);
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
            t=clamp_int(iv,1,65535,key,&bad); if(t>=0){g_cfg.port=t;applied++;} }
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
        else if(!strcmp(key,"maxuploadtarget")){ /* Core: MB per 24h, 0=off */
            t=clamp_int(iv,0,1048576,key,&bad); if(t>=0){ g_cfg.maxuploadtarget_mb=t; applied++; } }
        else if(!strcmp(key,"listen")){       /* Core: accept inbound       */
            g_cfg.listen = iv?1:0; saw_listen = 1; applied++; }
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
}
