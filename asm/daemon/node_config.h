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
    int  blocksonly;             /* Core -blocksonly: no tx relay            */
    char bind_addr[64];          /* Core -bind: listen address (empty = any) */
    int  par;                    /* Core -par: worker threads, 0 = auto      */
    int  maxrecvbuffer_kb;       /* Core -maxreceivebuffer: n*1000 bytes     */
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

#endif
