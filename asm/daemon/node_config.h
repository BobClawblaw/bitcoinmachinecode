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
    int  port_explicit;          /* 1 = port= appeared in the config file, so
                                    chain selection must NOT re-default it   */
    char chain[16];              /* Core -chain: "main" (default), "regtest".
                                    Stored here; main.c passes it to
                                    chainparams_select() (daemon/chainparams.c
                                    -- node_config.c itself stays free of that
                                    link dependency, it is compiled into many
                                    tools that never select a chain).        */
    int  listen;                 /* Core -listen                             */
    /* bmc.bootcatchup: run the parallel downloader (dl_catchup) synchronously
     * at boot when the archive is behind the header chain. Default 1. 0 skips
     * it, leaving the running worker's far-behind trigger to do the same job
     * later -- which is what the trigger's live test needs, and what an
     * operator wants when a fast restart matters more than a full archive. */
    int  boot_catchup;
    int  addrindex;              /* EXTENSION (no Core equivalent): live
                                    address index, daemon/addr_index_tail.c.
                                    Default 0; must be on before IBD.        */
    int  blocksonly;
    char signer[512];   /* external signer command (Core -signer / HWI); "" = none */             /* Core -blocksonly: no tx relay            */
    /* Core -zmqpub<topic>=<address>. One address per topic; topics sharing an
     * address share one socket, as in Core. Empty = that topic is not
     * published. See daemon/zmq_pub.c. */
    char zmq_hashblock[64];
    char zmq_hashtx[64];
    char zmq_rawblock[64];
    char zmq_rawtx[64];
    char bind_addr[64];          /* Core -bind: listen address (empty = any) */
    /* ---- anonymity networks (2026-08-28). Core's names and defaults. ---- */
    char proxy[64];              /* -proxy=ip:port   SOCKS5 for every network that has no more specific proxy */
    char onion_proxy[64];        /* -onion=ip:port   SOCKS5 for .onion (default: proxy) */
    char torcontrol[64];         /* -torcontrol=ip:port (default 127.0.0.1:9051) */
    char torpassword[128];       /* -torpassword (else cookie auth) */
    int  listenonion;            /* -listenonion: create an onion service (default 1 when torcontrol is reachable) */
    char i2psam[64];             /* -i2psam=ip:port  SAM bridge; empty = i2p disabled */
    int  i2pacceptincoming;      /* -i2pacceptincoming (default 1) */
    int  cjdnsreachable;         /* -cjdnsreachable */
    int  proxyrandomize;         /* -proxyrandomize (default 1): per-connection SOCKS5 credentials */
    char onlynet[6][8];          /* -onlynet (repeatable); empty list = all networks */
    int  n_onlynet;
    /* Core -dns: may hostnames be looked up with the system resolver? With
     * a proxy configured, a local DNS lookup tells the resolver (and anyone
     * on the path to it) exactly which peers this node is about to talk to,
     * which is the leak running behind Tor is meant to close. Core routes
     * names through the proxy instead; so do we. Default 1. */
    int  dns;
    /* Core -discover: learn our own address from peers / interfaces and
     * announce it. Behind Tor this is the switch that stops the node
     * telling the network its clearnet address. Default 1. */
    int  discover;
    char externalip[80];         /* Core -externalip: announce THIS instead   */
    int  onion_only_announce;    /* derived: onlynet excludes clearnet        */
    /* ---- 2026-08-29: Core parity, tier one ------------------------------
     * Each of these is WIRED, not merely parsed. A setting that is accepted
     * and then ignored is worse than one that is absent -- that was the
     * externalip defect earlier today, and the rule now holds for the whole
     * config surface. */
    unsigned char minchainwork[32];  /* -minimumchainwork, big-endian; all-zero = no floor */
    int  have_minchainwork;          /* 0 when neither config nor chain default set one   */
    long bantime;                    /* -bantime seconds (Core default 86400)             */
    int  blockfilterindex;           /* -blockfilterindex (default 1: keep current behaviour) */
    int  coinstatsindex;             /* -coinstatsindex   (default 1: keep current behaviour) */
    char rpccookiefile[256];         /* -rpccookiefile; empty = <datadir>/.cookie          */
    int  rpccookie;                  /* derived: emit and accept a cookie (default 1)      */
    /* ---- batch two ------------------------------------------------------ */
    int  permitbaremultisig;         /* -permitbaremultisig (Core default 1)              */
    int  networkactive;              /* -networkactive (Core default 1): start with the
                                      * network on, or dead until setnetworkactive        */
    int  forcednsseed;               /* -forcednsseed: query the seeds even with peers    */
    char pidfile[256];               /* -pid: write our pid here (empty = none)           */
    /* Core -*notify hooks. Empty = not configured. "%s" is replaced by the
     * event's value (block hash, txid, message), sanitised -- see notify.c. */
    char blocknotify[512];
    char alertnotify[512];
    char startupnotify[512];
    char shutdownnotify[512];
    long maxtxfee_sat;               /* -maxtxfee, satoshis (0 = no cap)                  */
    char rpcauth[8][256];            /* -rpcauth, repeatable: user:salt$hash */
    int  n_rpcauth;
    char asmap[512];                 /* -asmap: AS map file; empty = /16 bucketing        */
    int  maxsendbuffer_kb;           /* -maxsendbuffer: n*1000 bytes (Core default 1000)  */
    int  zmq_hwm[5];                 /* -zmqpub<topic>hwm, in the order of the topics
                                      * below: hashblock, hashtx, rawblock, rawtx,
                                      * sequence. Core default 1000.                      */
    int  par;                    /* Core -par: worker threads, 0 = auto      */
    int  maxrecvbuffer_kb;       /* Core -maxreceivebuffer: n*1000 bytes     */
    long maxmempool_mb;          /* Core -maxmempool (MB, 0 = built-in 2MiB) */
    long mempoolexpiry_h;        /* Core -mempoolexpiry (hours, 0 = never)   */
    long maxuploadtarget_mb;     /* Core -maxuploadtarget (MB, 0 = no limit) */
    /* mempool policy limits (Core exposes each of these). Fees are stored in
     * sat/vByte (Core's config is BTC/kvB; parsed at the boundary). */
    long minrelaytxfee_satkvb;    /* Core -minrelaytxfee, sat/kvB (Core v30 default 100 = 0.1 sat/vB) */
    long incrementalrelayfee_satkvb; /* Core -incrementalrelayfee, sat/kvB (default 100)          */
    long limitancestorcount;     /* Core -limitancestorcount (default 25)    */
    long limitancestorsize_kvb;  /* Core -limitancestorsize (kvB, default 101)*/
    long limitdescendantcount;   /* Core -limitdescendantcount (default 25)  */
    long limitdescendantsize_kvb;/* Core -limitdescendantsize (kvB, def 101) */
    int  mempoolfullrbf;
    long dustrelayfee_satkvb;    /* Core -dustrelayfee (sat/kvB, def 3000)   */
    int  datacarrier;            /* Core -datacarrier (def 1)                */
    long datacarriersize;        /* Core -datacarriersize (vbytes, v31:100000)*/
    int  acceptnonstdtxn;        /* Core -acceptnonstdtxn (def 0)            */         /* Core -mempoolfullrbf (default 1)         */

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
    /* Per-entry P2P port from a "host:port" value, 0 when the entry named no
     * port (dial the chain default). Kept PARALLEL to the host arrays rather
     * than folded into the strings on purpose: those strings flow into
     * inet_pton()/address-book paths that must keep seeing a bare host. Look
     * one up with node_config_peer_port(). */
    unsigned short seednode_port[CFG_MAX_NODES];
    unsigned short addnode_port [CFG_MAX_NODES];
    unsigned short connectn_port[CFG_MAX_NODES];

    /* ---- chain / storage (Core -prune/-checkblocks/-checklevel/
     *                       -stopatheight) ---- */
    long prune_mib;              /* Core -prune: 0 off, 1 manual-only, else
                                  * target block-data size in MiB (min 550)  */
    long checkblocks;            /* Core -checkblocks: trailing blocks to
                                  * verify at boot; 0 = all (def 6)          */
    int  checklevel;             /* Core -checklevel: 0..4 (def 3)           */
    long stopatheight;           /* Core -stopatheight: stop at this height,
                                  * 0 = run forever (def 0)                  */
    /* ---- chainstate rebuild (Core -reindex-chainstate) ---- */
    int  reindex_chainstate;     /* drop the UTXO set at boot so it rebuilds
                                  * from the archive (def 0; one-shot)      */

    /* ---- mempool persistence (Core -persistmempool) ---- */
    int  persistmempool;         /* save mempool.dat at shutdown and reload it
                                  * at boot (def 1, as in Core)             */

    /* ---- wallet passphrase source (audit finding 2) ---- */
    /* Core -signetchallenge: the block challenge script, as hex. Only
     * meaningful with chain=signet, where it also determines the network
     * magic -- so two signets with different challenges cannot talk to each
     * other. Empty = the default (public) signet. */
    /* Core -rpcbind / -rpcallowip. rpcbind is IGNORED unless at least one
     * rpcallowip is given, exactly as Core does -- see daemon/rpc_acl.h. */
    char rpcbind[64];
    char rpcallowip[16][64];
    int  n_rpcallowip;
    char signetchallenge[2048];
    char walletpassfile[256];    /* absolute path, OUTSIDE the datadir, to a
                                  * root-owned 0640 file holding the wallet
                                  * passphrase. Empty = none; the daemon no
                                  * longer reads <store>.pass.              */

    /* ---- BIP324 v2 encrypted transport (Core -v2transport) ---- */
    int  v2transport;            /* accept inbound v2 and attempt it outbound;
                                  * def 1, as in Core                        */
    int  bytespersigop;          /* Core -bytespersigop (def 20): feerate is
                                  * judged against max(vsize, sigops*this/4) */
    int  disablewallet;          /* Core -disablewallet: do not load a wallet  */
    int  reindex;                /* Core -reindex: ONE-SHOT rebuild of the block
                                  * index from the blk files (archive_reindex.c) */
    char walletdir[256];         /* Core -walletdir: where wallet files live;
                                  * empty = the chain directory                */
    char debuglogfile[256];      /* Core -debuglogfile: the daemon's own log
                                  * (def logs/bitcoind.log in the chain dir;
                                  * "0" = no file log)                       */
    unsigned char assumevalid[32]; int assumevalid_mode;   /* 0 = the chain default (Core defaultAssumeValid), 1 = this hash (wire order), 2 = assumevalid=0: evaluate every script */
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

/* The P2P port configured for a named peer via "host:port" in bitcoin.conf,
 * or 0 when that entry named no port (callers dial the chain default). Any
 * port is honoured -- restricting named peers to a chain's default port made
 * pointing this node at a scratch peer impossible, and it failed SILENTLY
 * (the entry was dropped and the node then sat at tip=0 with peers=0/0). */
int node_config_peer_port(const char* host);

/* hex -> 32 big-endian bytes, right-aligned (Core's uint256 spelling) */
int nodecfg_hex32_be(const char* s, unsigned char out[32]);

/* -conf=<path>: overrides the datadir search in node_config_path(). */
void node_config_set_conf_path(const char* path);

/* 1 when `key` is a Bitcoin Core option this node does not implement. Used to
 * warn instead of silently accepting it. */
int nodecfg_unimplemented(const char* key);

#endif
