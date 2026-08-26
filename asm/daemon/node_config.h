/* daemon/node_config.h -- durable, file-backed tuning for the node.
 *
 * Every operational knob was a compile-time #define, so changing one meant
 * edit -> recompile -> redeploy. On 2026-08-18 that cost several production
 * restarts just to retune peer eviction, and a bad value could only be backed
 * out with another build. Worse, the WRONG value stalled a live sync and the
 * only recovery was a code change.
 *
 * Precedence, highest first:
 *   1. command line   (explicit operator intent for this run)
 *   2. bitcoin.conf   (durable, survives restarts -- the point of this file)
 *   3. compiled default
 *
 * The compiled defaults are exactly the previous #define values, so a node
 * with no config file behaves precisely as before.
 */
#ifndef NODE_CONFIG_H
#define NODE_CONFIG_H

/* addnode/seednode/connect are the only REPEATABLE keys: a bitcoin.conf may
 * name several and every occurrence counts. 32 is well past what an operator
 * hand-lists and keeps g_cfg a fixed-size static (no allocation on a path
 * that must never fail). */
#define CFG_MAX_NODES 32

typedef struct {
    /* connection budget (Core: -maxconnections and the outbound classes) */
    int  max_connections;        /* total; inbound = this - outbound classes */
    int  max_outbound;           /* full-relay legs                          */
    int  max_block_relay_only;   /* relay=0, never addr-gossiped             */
    int  max_feeler;             /* short-lived liveness probes              */
    long feeler_interval_ms;

    /* peer quality / eviction (daemon/main.c dlc worker) */
    double dead_weight_bps;      /* below this for N ticks == useless        */
    int    dead_weight_ticks;
    int    min_usable_peers;     /* never ban the pool below this            */
    int    maxpool;              /* candidate pool drawn from the book       */

    /* address ingestion limits (anti-eclipse; daemon/addr_ingest.c) */
    int  addr_max_per_response;
    int  addr_max_per_netgroup;

    /* UTXO catch-up sizing (daemon/utxo_live.c) */
    int  utxo_bulk_slots_log2;
    int  utxo_bulk_blob_mb;
    long utxo_bulk_gap_blocks;
    int  utxo_compact_threshold;

    /* Bitcoin Core options honoured by name and unit */
    int  dbcache_mb;             /* Core -dbcache: UTXO cache MB (def 450)   */
    int  connect_timeout_ms;     /* Core -timeout    (def 5000ms)            */
    int  peer_timeout_s;         /* Core -peertimeout(def 60s)               */
    int  port;                   /* Core -port                               */
    int  listen;                 /* Core -listen                             */
    int  blocksonly;
    char signer[512];   /* external signer command (Core -signer / HWI); "" = none */             /* Core -blocksonly: no tx relay            */
    char bind_addr[64];          /* Core -bind: listen address (empty = any) */
    int  par;                    /* Core -par: worker threads, 0 = auto      */
    int  maxrecvbuffer_kb;       /* Core -maxreceivebuffer: n*1000 bytes     */
    long maxmempool_mb;          /* Core -maxmempool (MB, 0 = built-in 2MiB) */
    long mempoolexpiry_h;        /* Core -mempoolexpiry (hours, 0 = never)   */
    long maxuploadtarget_mb;     /* Core -maxuploadtarget (MB, 0 = no limit) */

    /* ---- peer sourcing (Core -dnsseed/-seednode/-addnode/-connect) ----
     * Until now the DNS seed list was compiled in and there was no way to
     * point the node at specific peers -- which made isolated/regtest-style
     * bring-up and "just use these two nodes" debugging impossible without a
     * rebuild. Entries are hostnames or dotted-quad IPv4; they are resolved
     * at use, not at parse (a seed host that is down at boot must not be a
     * permanent config error). */
    int  dnsseed;                /* Core -dnsseed: query DNS seeds (def 1)   */
    int  connect_only;           /* Core -connect was given: no auto conns   */
    int  n_seednode;
    int  n_addnode;
    int  n_connect;
    char seednode[CFG_MAX_NODES][64];  /* getaddr from, then drop            */
    char addnode [CFG_MAX_NODES][64];  /* prefer, and never evict            */
    char connectn[CFG_MAX_NODES][64];  /* the ONLY peers, when non-empty     */

    /* ---- chain / storage (Core -prune/-checkblocks/-checklevel/
     *                       -stopatheight) ---- */
    long prune_mib;              /* Core -prune: 0 off, 1 manual-only, else
                                  * target block-data size in MiB (min 550)  */
    long checkblocks;            /* Core -checkblocks: trailing blocks to
                                  * verify at boot; 0 = all (def 6)          */
    int  checklevel;             /* Core -checklevel: 0..4 (def 3)           */
    long stopatheight;           /* Core -stopatheight: stop at this height,
                                  * 0 = run forever (def 0)                  */
} node_config_t;

extern node_config_t g_cfg;

/* Fill g_cfg with compiled defaults, then overlay <path> if it exists.
 * Returns the number of keys applied from the file (0 if absent/empty).
 * Never fails: an unreadable or malformed file leaves defaults in place. */
long node_config_load(const char* path);

/* One line per group, so the resolved config is visible in the log at boot
 * rather than having to be inferred from behaviour. */
void node_config_log(void);

/* Resolve the config path: $BITCOIN_CONF, else <datadir>/bitcoin.conf, else
 * ../config/bitcoin.conf relative to the datadir (where this repo keeps it). */
const char* node_config_path(const char* datadir, char* buf, unsigned long cap);

/* True if <ip> was named by the operator via addnode= or connect=. Such peers
 * are MANUAL connections: Core never auto-evicts them and neither do we --
 * otherwise the dead-weight eviction pass would ban the very nodes the
 * operator pinned, and a connect= node list would empty itself. */
int node_config_is_manual(const char* ip);

#endif
