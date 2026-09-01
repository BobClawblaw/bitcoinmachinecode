/* daemon/main.c -- thin CLI driver over the assembly Bitcoin node core.
 *
 *   daemon sync  <dir>                : init store in <dir>, connect to the
 *                                       loopback test peer, handshake, run IBD
 *                                       (node_sync), report resulting height.
 *   daemon serve <dir> <port> [nwant] [catchup_workers]
 *                                     : init store in <dir>, listen on port,
 *                                       accept a peer, handshake, then serve
 *                                       stored blocks to getdata / reply to
 *                                       ping. The node IE (connect/handshake/
 *                                       IBD/serve-block) is all assembly
 *                                       (bitcoind.asm); this is only the main
 *                                       loop over sockets. nwant (default 3)
 *                                       is the steady-state outbound leg
 *                                       count; catchup_workers (default 16)
 *                                       is the dl_catchup chunk-claiming
 *                                       worker count for the self-healing
 *                                       boot-time catch-up pass.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "log_ts.h"
#include "log_phase.h"
#include "utxo_walk.h"   /* utxo_walk_read_varint, for tx-count in [block] stored logs */
#include "../version_gen.h"  /* GENERATED from version.inc: our wire identity (protocol/UA/version) */
#include "reorg.h"       /* STAGE B: fork choice / chain reorganisation */
#include "notify.h"      /* Core -*notify hooks */
#include "torcontrol.h"  /* inbound: our own onion service */
#include "asmap.h"       /* -asmap: AS-level address bucketing */
#include "node_config.h"
#include "archive_reindex.h" /* durable, file-backed tuning (bitcoin.conf) */
#include "netperm.h"   /* -whitelist peer permissions */
#include "subnet.h"    /* one CIDR matcher, shared with the ban list */
#include "rpc_acl.h"   /* -rpcallowip / -rpcbind */
#include "v2transport.h"  /* BIP324 v2 encrypted transport */
#include "wallet_pass.h"   /* wallet passphrase source (audit finding 2) */
#include "chainparams.h" /* runtime chain selection (main / regtest)   */

/* The node log path, chain-tagged so an aggregated view can never confuse
 * chains: logs/bitcoind.log on mainnet, logs/bitcoind.<chain>.log otherwise
 * (all under the per-chain datadir's own logs/). Set at boot right after
 * chainparams_select; the static default covers every tool-mode caller. */
static char g_logpath[256] = "logs/bitcoind.log";   /* debuglogfile= overrides (0 = /dev/null) */
#include "../rpc_server.h"   /* embedded JSON-RPC server (docs/RPC_LIVE_NODE.md) */
#include "../rpc_chain.h"
#include "../rpc_wallet_ops.h"
#include "../rpc_node.h"     /* node_status_t + live-node RPC dispatch */
static rpc_wallet     g_rpc_wallet;   /* zeroed: wallet RPCs report "not configured" */
static node_status_t* g_node_status;  /* MAP_SHARED live status, NULL if mmap failed */

/* Pre-mux outbound catch-up bounds (used by outbound_catchup below and the
 * serve handler). CATCHUP_MAX caps the number of blocks pulled synchronously;
 * CATCHUP_MAX_SECS caps the catch-up wall-clock. Both keep the mux loop (the
 * long-running stays-current mechanism) from being delayed indefinitely by a
 * far-from-tip store. */
#define CATCHUP_MAX 10000L
#define CATCHUP_MAX_SECS 60.0
/* Per-rotation wall-clock budget for ONE outbound do_outbound_sync leg inside
 * the mux poll loop. A far-behind store (or a slow seed building a large
 * getheaders catch-up) would otherwise let a single blocking node_sync soak the
 * loop for tens of seconds to minutes, starving inbound accepts (the kernel
 * accepts the TCP connection into the listen backlog but the loop never calls
 * accept(), so the version handshake never starts and every inbound probe
 * times out). Bounding each leg's sync time makes serve_mux return to poll() +
 * accept() promptly, so "serve stays live to inbound while downloading" holds
 * at any store scale. Kept well above the at-tip round-trip cost (~hundreds of
 * ms) so a caught-up node is never interrupted. */
#define MUX_SYNC_BUDGET_SECS 2.0

/* Per-leg sync wall-clock budget for the download WORKER (dedicated multi-peer
 * downloader, never serves inbound). Because it does not serve, each leg may
 * sync for a LONG window so far-from-tip stores close aggressively; a caught-up
 * leg returns in milliseconds and does not hold the rotation. Kept well above a
 * single leg's per-pass round-trip cost. */
#define DL_BUDGET_SECS 60.0
/* Blocks the archive may run ahead of the applied UTXO height before the
 * download worker stops syncing legs and applies instead. At the tip the
 * backlog is 0-2; a from-scratch or long-gap restart is tens of thousands. */
#define DL_APPLY_FIRST_BACKLOG 500L
/* STAGE B: minimum gap between fork probes across all outbound legs. A probe
 * is one extra getheaders round trip on an already-idle leg, so this only has
 * to be short enough to notice a competing chain promptly (a mainnet reorg is
 * resolved in minutes, not seconds) and long enough that it is noise against
 * the per-leg sync traffic. */
#define REORG_PROBE_INTERVAL_MS 30000L
/* Backoff for a catch-up that keeps failing even after in-place recovery.
 * We retry forever (capped interval) instead of disabling UTXO tracking:
 * running blind indefinitely is worse than retrying a failing operation. */
#define UTXO_RETRY_BASE_MS 5000L
#define UTXO_RETRY_MAX_MS  300000L
#define DL_HEARTBEAT_MS 60000L   /* periodic [dl] heartbeat so the log stays
                                  * visibly alive between block/peer events */

/* --- assembly node core (bitcoind.asm / bitcoin_*.asm) --- */
extern long node_handshake(int fd);
extern unsigned char g_peer_version_payload[256]; /* bitcoind.asm: raw capture, see its header comment */
extern long g_peer_version_len;
extern long node_accept_handshake(int fd);
extern long g_peer_wants_addrv2;   /* bitcoind.asm: peer sent sendaddrv2 before verack (per handshake) */

/* NODE_WITNESS (service bit 0x8) gate, checked right after every OUTBOUND
 * handshake that can lead to fetching blocks or transactions. A peer without
 * the bit serves everything witness-STRIPPED no matter what getdata type we
 * send -- the wire behaviour that silently stripped the whole segwit-era
 * archive (incident #10). The BIP141 commitment check now rejects such
 * blocks loudly, so a non-witness peer can no longer corrupt the archive --
 * but it can still waste a leg failing every fetch, so refuse at dial time.
 * A version payload too short to carry services is refused the same way:
 * unknown is not "probably fine" on the path that feeds the archive. */
static int peer_has_witness(const char* who){
    unsigned long long services = 0;
    if (g_peer_version_len >= 12)
        memcpy(&services, g_peer_version_payload + 4, 8);
    if (services & 0x8ULL) return 1;
    fprintf(stderr, "[dial] %s lacks NODE_WITNESS (services=0x%llx) -- dropping\n",
            who ? who : "?", services);
    return 0;
}
extern long node_sync(int fd, void* st, void* locator, void* buf, long buflen, long* out_count);
/* STAGE B: the real multi-hash-locator entry point. node_sync is now a
 * count==1 shim over this (see bitcoind.asm). A single-hash locator is what
 * made fork DISCOVERY impossible: a peer whose chain diverged below our tip
 * recognises none of it and answers from its own genesis. */
extern long node_sync_multi(int fd, void* st, void* locator, long loc_count,
                            void* buf, long buflen, long* out_count);
extern long locator_build(void* store_buf, unsigned char* out_hashes); /* daemon/locator_build.c */
extern long node_serve_block(void* st, long height, void* out, long cap);
extern long node_serve_block_by_hash(void* st, const void* hash32, void* out, long cap);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern long node_announce_tip(int fd, void* st, void* ht_idx, long use_headers);
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long store_init(void* st);
extern long store_reload(void* st);
extern int  utxo_live_init(const char* dir);           /* daemon/utxo_live.c */
extern long utxo_live_catchup(void* store_buf);        /* daemon/utxo_live.c */
extern void utxo_live_set_shutdown_flag(const volatile sig_atomic_t* flag); /* daemon/utxo_live.c */
extern long utxo_live_count(void);                      /* daemon/utxo_live.c */
/* Clamp the DISPLAYED live-UTXO count at 0. Backstop only: the count itself
 * is now kept accurate across restarts by the manifest persist/restore in
 * bitcoin_utxo_lsm.asm (this replaced the WAL-tail-only reload seed that let
 * live_utxo go negative, e.g. -2610837). This just guarantees a future
 * accounting drift can never surface a nonsensical negative in the logs. */
static long live_utxo_disp(void){ long c = utxo_live_count(); return c < 0 ? 0 : c; }
extern long utxo_live_applied_height(void);              /* daemon/utxo_live.c */
extern long utxo_live_recover(void);                     /* daemon/utxo_live.c */
extern int  archive_verify_and_repair(void* store_buf, int repair); /* daemon/archive_verify.c */
extern long archive_drop_utxo_state(void);                /* daemon/archive_verify.c */
#include "archive_verify.h"                               /* archive_* + prune verdict */
extern int  store_set_prune(void* st, int h);             /* bitcoin_store.asm       */
extern int  store_prune(void* st, int h);                 /* bitcoin_store.asm       */
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
extern long p2p_getheaders(void* out, const void* locator, int count, const void* stop);
extern int  node_log_open(const char* path);
extern void node_log_event(int fd, int kind, unsigned a, unsigned b, unsigned c);
extern void node_log_str(int fd, int kind, const char* s, long len);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
extern int  amr_init(void* ab);
/* ---- address book, version 2 (daemon/addrbook.c, peers2.dat): every BIP155
 * network. The legacy amr_* (peers.dat, IPv4 only) is migrated on first open
 * and no longer written. addr_book() is the worker's read-write handle
 * (daemon/addr_ingest.c). */
#include "netaddr.h"
#include "addrbook.h"
#include "dialer.h"
#include "net6.h"
extern ab2_t* addr_book(void);
static int book_add_ipv4(unsigned ip_netorder, int port){
    bmc_addr_t a; memset(&a, 0, sizeof a);
    a.net = BMC_NET_IPV4; a.len = 4; memcpy(a.addr, &ip_netorder, 4); a.port = (unsigned short)port;
    ab2_t* b = addr_book(); if(!b) return -1;
    return ab2_add(b, &a, 1, (unsigned)time(NULL));
}
extern long amr_count(void* ab);
extern int  amr_get_i(void* ab, long i, void* out);
extern long p2p_addr_v1(void* out, const void* src, long n);
/* peer-discovery externs (bitcoin_addrmgr.asm): amr_* is the persisted address
 * manager ("peers.dat" book), p2p_addr_count parses an `addr` payload. The DNS
 * seeds are used ONLY as BOOTSTRAPS -- we getaddr from them, ingest discovered
 * peers into the amr book, then download across DISCOVERED peers (not seeds). */
extern int  amr_add(void* ab, unsigned ip, unsigned short port, unsigned long long svc, unsigned lastseen);
extern long addr_replenish(void* ab, char peers[][64], int npeers, int max_try, int wait_s, long target); /* daemon/addr_ingest.c */
extern long addr_gather_from(void* ab, const char* ip_str, int wait_s);              /* daemon/addr_ingest.c */
extern int  mempool_configure(void);                     /* daemon/mempool_cfg.c */
extern long mempool_expire_now(void);                    /* daemon/mempool_cfg.c */
extern long      upload_note_and_check(long bytes_added); /* daemon/upload_cap.c */
extern long long upload_proc_wchar(int pid);              /* daemon/upload_cap.c */
extern long long upload_bytes_this_window(void);          /* daemon/upload_cap.c */
extern int  net_handshake_relay(const char* ip_str, int relay, int rcv_secs);  /* daemon/net_policy.c */
extern int  net_feeler_probe(const char* ip_str);                             /* daemon/net_policy.c */
extern unsigned net_netgroup_v4(unsigned ip);                                 /* daemon/net_policy.c */
extern long p2p_addr_count(const void* pl, long plen);
extern long store_append(void* st, const unsigned char* hash32, const void* blk, long len);
extern long store_get_tip(void* st, long out_meta[3]);   /* -> 1 ok / -1 empty; a one-arg call SEGVs (2026-09-01 r boot) */
extern int  store_get_tip_hash(void* st, unsigned char out[32]);   /* bitcoin_store.asm */
/* ZMQ notifications: publisher (daemon/zmq_pub.c) + the cross-process
 * staging ring (daemon/zmq_notify.c). The publisher owns sockets and so runs
 * in the download worker ONLY; the ring is what lets the serve children
 * contribute the transactions they accept. */
extern int  zmqpub_add(const char* topic, const char* addr);
extern int  zmqpub_start(void);
extern int  zmqpub_active(void);
extern void zmqpub_poll(void);
extern void txit_boot(void* store_buf);                                       /* daemon/tx_index_tail.c */
extern void axt_boot(void* store_buf);                                        /* daemon/addr_index_tail.c (EXTENSION index) */
extern void axt_on_block(void* store_buf, long h, const unsigned char* blk, long blen);
extern int  axt_active(void);
extern int  txit_active(void);
extern void tsp_boot(void* store_buf);                                        /* daemon/txosp_tail.c */
extern int  tsp_active(void);
extern void tsp_on_block(void* store_buf, long h, const unsigned char* blk, long blen);
extern void txit_on_block(void* store_buf, long h, const unsigned char* blk, long blen);
extern void bfi_on_block(void* store_buf, long h, const unsigned char* blk, unsigned long blen);  /* daemon/bfilter_index.c */
typedef int (*bfi_undo_cb_t)(void*, const unsigned char*, unsigned int, unsigned long long,
                             unsigned int, unsigned char, const unsigned char*, unsigned short);
extern void bfi_set_undo_replay(long (*fn)(long, bfi_undo_cb_t, void*));
extern void bfi_on_truncate(long new_tip);
extern void zmqpub_notify(const char* topic, const void* body, unsigned long blen);
extern void zmqn_set_status(node_status_t* st);
extern int  zmqn_drain(void);
extern long store_read_at(void* st, unsigned long h, void* out, long cap);
extern long node_ibd(int fd, void* st, void* hst, void* buf, long buflen); /* bitcoind.asm */
extern long node_drain(int fd, void* st, void* buf, long buflen);          /* bitcoind.asm */
extern long node_sync(int fd, void* st, void* locator, void* buf, long buflen, long* out_count); /* bitcoind.asm */
extern int  hst_init(void* hst);
extern long hst_count(void* hst);
extern int  hst_get_at(void* hst, unsigned long long height, void* out);
/* built-in catch-up engine externs (bitcoind.asm / bitcoin_headers.asm) --
 * same primitives the standalone unified_ibd.c tool already uses. */
extern long node_ibd_headers(int fd, void* hst, void* locator32, void* buf, unsigned long buflen);
extern long node_ibd_blocks_s(int fd, void* st, void* hst, long lo_real, long nloc,
                              void* buf, unsigned long buflen, void* scratch, unsigned cap);
extern int  hst_reload(void* hst);
extern int  hst_append(void* hst, const unsigned char hdr[80], const unsigned char hash[32]);

#define L_HDRS   2
#define L_BLOCK  3
#define L_STORE  5
#define L_ERROR  6
#define L_SERVE  7

static unsigned char store_buf[4096];

/* ---- block hash -> height index (for O(1) getdata/by-hash serving). ----
 * The table itself is 100% assembly (asm/bitcoin_idx.asm: idx_init/idx_put/
 * idx_get/idx_count, an open-addressing hash table with full 32-byte keys).
 * The build loop here is thin file orchestration over index.dat. This lets us
 * serve a requested block by hash in O(1) instead of a linear height scan. */
#define HT_SLOTS (8u<<20)
static unsigned char* ht_idx;            /* 24 + HT_SLOTS*48 bytes */
static unsigned char out_buf[1<<20];     /* serve-loop output scratch */
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern int  idx_get(void* idx, const unsigned char hash[32], long* height);
extern long idx_count(void* idx);
extern long idx_build_from_file(void* idx, const char* path);

/* bitcoin_idxscan.asm -- buffered index.dat positional scans, replacing the
 * dlc_* stdio versions below (kept as reference/fallback docs in comments
 * at each call site; see asm/bitcoin_idxscan.asm for the perf rationale). */
extern long idxscan_tip(void);
extern long idxscan_first_hole(long tip);
extern long idxscan_all_present(long lo, long hi);
extern void idxscan_progress(long* out_tip, long* out_present);
/* asm/bitcoin_idx.asm:idx_build_from_file -- buffered pread64 bulk loader,
 * replacing the per-record fread+reverse+idx_put loop that used to live
 * here. Drops the periodic "[hashidx] N/M" progress print: the whole build
 * is now a small fraction of a second on the real archive (was ~186s), so
 * there's nothing left to show progress on. */
/* Heights already folded into ht_idx. The boot build covers [0, this), and
 * serve_idx_topup carries it forward from there. */
static long g_htidx_next;

static long htidx_file_heights(void){
    struct stat sb;
    if (stat("index.dat", &sb) != 0) return 0;
    return (long)(sb.st_size / 48);
}

static int build_hash_index(void){
    ht_idx=malloc(24 + (size_t)HT_SLOTS*48 + 64);   /* last slot may need a full --- actually over-allocate */
    if(!ht_idx){ fprintf(stderr,"alloc idx failed\n"); return -1; }
    idx_init(ht_idx, HT_SLOTS);
    if(idx_build_from_file(ht_idx, "index.dat")<0){ fprintf(stderr,"no index.dat for hash index\n"); return -1; }
    g_htidx_next = htidx_file_heights();
    fprintf(stderr,"[hashidx] indexed %ld stored heights\n", (long)idx_count(ht_idx));
    return 0;
}

/* serve_height_of_hash -- the height for a block hash, from the serve path's
 * own hash index. Behind daemon/serve_cfilters.c, which needs to turn a
 * BIP157 request's stop_hash into a height and has no business reaching into
 * ht_idx itself. Returns -1 when the hash is unknown. */
long serve_height_of_hash(const unsigned char hash[32]){
    if (!ht_idx) return -1;
    long h = 0;
    if (idx_get(ht_idx, hash, &h) != 1) return -1;
    return h;
}

/* serve_idx_topup -- fold every height index.dat has gained since this
 * process last looked into the serve path's hash index.
 *
 * WHY THIS EXISTS: the hash index the serve path answers `getdata` from was
 * built ONCE, at boot. New blocks are appended by the DOWNLOAD WORKER, which
 * is a different process, so neither the serve parent nor any serve child
 * forked from it ever learned about them. The result, found 2026-08-28 by
 * validation/p2p_inbound_probe.py: a block that was in the archive at
 * startup is served, and a block downloaded during the run is answered with
 * silence -- so this node never helped propagate RECENT blocks, which is the
 * only propagation that matters. Block serving had been verified the day
 * before and passed, because a caught-up node mostly answers for historical
 * blocks and those WERE in the archive at boot.
 *
 * This is the same incremental top-up rpc_chain.c's refresh() already does
 * for the RPC side, which is why the RPC layer never had the bug.
 *
 * Cheap when nothing is new: one stat(2), then a return. Called from
 * bitcoin_serve.asm at the top of getdata handling, so a long-lived
 * connection cannot go stale either. */
long serve_idx_topup(void){
    if (!ht_idx) return 0;
    long have = htidx_file_heights();
    if (have <= g_htidx_next) return 0;
    int fd = open("index.dat", O_RDONLY);
    if (fd < 0) return 0;
    long added = 0;
    unsigned char rec[48];
    for (long h = g_htidx_next; h < have; h++){
        if (pread(fd, rec, 48, (off_t)h * 48) != 48) break;
        /* an all-zero record is a hole -- a height the store has not filled
         * yet. Indexing it would map the zero hash to a height. */
        int present = 0;
        for (int i = 0; i < 32; i++) if (rec[i]){ present = 1; break; }
        if (present && idx_put(ht_idx, rec, h) == 2){
            /* index full: stop, and do NOT advance the cursor past the
             * height we failed to add */
            fprintf(stderr,"[hashidx] WARNING: hash index full at height %ld; "
                           "blocks above it cannot be served until restart\n", h);
            break;
        }
        g_htidx_next = h + 1;
        if (present) added++;
    }
    close(fd);
    if (added)
        fprintf(stderr,"[hashidx] +%ld height(s) now servable (through %ld)\n",
                added, g_htidx_next - 1);   /* parent-side; a child normally adds 0 */
    return added;
}

/* STAGE B: rebuild the hash index in place after a reorg truncated the store.
 * Deliberately reuses build_hash_index's EXACT construction (idx_init +
 * idx_build_from_file) rather than re-deriving keys some other way, so a
 * post-reorg index is byte-identical to a fresh boot's -- reorg.c does not
 * guess at this, it calls back through reorg_set_index_rebuild. Reuses the
 * already-allocated buffer instead of mallocing a new one each time (a reorg
 * can happen repeatedly over a process's lifetime). */
static void rebuild_hash_index_after_reorg(void){
    if(!ht_idx) return;
    idx_init(ht_idx, HT_SLOTS);
    g_htidx_next = 0;             /* the rebuild re-reads the file from 0 */
    if(idx_build_from_file(ht_idx, "index.dat")<0)
        fprintf(stderr,"[reorg] WARNING: hash index rebuild failed; block-by-hash serving is degraded until restart\n");
    else {
        g_htidx_next = htidx_file_heights();
        fprintf(stderr,"[reorg] hash index rebuilt: %ld heights\n", (long)idx_count(ht_idx));
    }
    /* the txid-index tail's covered-height watermark must follow a
     * truncation too, or the reconnected blocks would be skipped as
     * already-indexed (fires with tip == fork height on the mid-reorg
     * invocation; the post-reconnect invocation is a no-op) */
    { extern void txit_on_truncate(void*); txit_on_truncate(store_buf); }
    { extern void tsp_on_truncate(void*); tsp_on_truncate(store_buf); }
    { extern void axt_on_truncate(void*); axt_on_truncate(store_buf); }
    { extern void bfi_on_truncate(long); bfi_on_truncate(*(int*)(store_buf+24)); }
}

/* Build the hash->height index from the IN-MEMORY store (used where the chain
 * lives only in store_buf, e.g. the socketpair server-test, not on disk yet).
 * Iterates heights 0..tip, serves each block via node_serve_block, hashes its
 * header with block_hash, and idx_put -> same O(1) hash index disk mode builds. */
static int build_inmem_hash_index(void){
    ht_idx=malloc(24 + (size_t)HT_SLOTS*48 + 64);
    if(!ht_idx){ fprintf(stderr,"alloc idx failed\n"); return -1; }
    idx_init(ht_idx, HT_SLOTS);
    int tip = *(int*)(store_buf+24);        /* same tip source the rest of main.c uses */
    static unsigned char sb[8<<20];
    int hashed = 0;
    for(int h=0; h<=tip; h++){
        long L = node_serve_block(store_buf, h, sb, sizeof sb);
        if(L<80){ continue; }                /* hole: skip, don't abandon the range */
        unsigned char bhash[32]; block_hash(bhash, sb);
        if(idx_put(ht_idx, bhash, h)) hashed++;
    }
    fprintf(stderr,"[inmem idx] indexed %d stored heights (tip %d)\n", hashed, tip);
    return 0;
}

/* The onion service's target. Core binds 127.0.0.1:<port+1> and tags anything
 * arriving there as an incoming Tor connection -- classification by ACCEPTING
 * SOCKET, never by source address, because tor forwards from 127.0.0.1 and a
 * source-address heuristic cannot tell an onion peer from a local one.
 *
 * Loopback-only and deliberately NOT bindable elsewhere: this socket exists
 * for tor to connect to. Core additionally marks its onion bind
 * BF_DONT_ADVERTISE so the loopback address is never gossiped as ours; here
 * the equivalent is that addr_self never sees this listener at all. */
/* Core -maxreceivebuffer / -maxsendbuffer, both in units of 1000 bytes.
 *
 * -maxreceivebuffer was PARSED AND READ NOWHERE: the option existed in the
 * config surface and did nothing, which is the defect this codebase keeps
 * reproducing. Both are applied here, to every peer socket in both
 * directions, so a peer cannot make this node buffer without bound.
 *
 * Core enforces its limits in userspace against its own message queues; this
 * node has no such queue -- it reads and writes the socket directly -- so the
 * kernel's own buffer IS the queue and the setting sizes it. Stated rather
 * than pretended: the effect is the same bound on memory per peer, reached by
 * a different mechanism. */
static void peer_sock_buffers(int fd){
    if (fd < 0) return;
    if (g_cfg.maxrecvbuffer_kb > 0){
        int v = g_cfg.maxrecvbuffer_kb * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v);
    }
    if (g_cfg.maxsendbuffer_kb > 0){
        int v = g_cfg.maxsendbuffer_kb * 1000;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
    }
}

static int lsock_onion(int want_port, int* got_port){
    int l = socket(AF_INET,SOCK_STREAM,0);
    if(l < 0) return -1;
    int one=1; setsockopt(l,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    /* Core's default is chain default port + 1, so try that first for
     * familiarity. But nothing REQUIRES a particular local port: ADD_ONION
     * tells tor where to forward, so any free loopback port works. Rather
     * than fail when the preferred one is taken -- a smoke test hit exactly
     * that, port+1 landing on the configured rpcport -- fall back to an
     * ephemeral port and tell tor the one we actually got. */
    a.sin_port = htons((unsigned short)want_port);
    if(bind(l,(struct sockaddr*)&a,sizeof a) < 0){
        fprintf(stderr,"[tor] 127.0.0.1:%d is taken (%s) -- using an ephemeral port instead\n",
                want_port, strerror(errno));
        a.sin_port = 0;
        if(bind(l,(struct sockaddr*)&a,sizeof a) < 0){
            fprintf(stderr,"[tor] onion listener bind failed: %s\n", strerror(errno));
            close(l); return -1;
        }
    }
    socklen_t al = sizeof a;
    if(getsockname(l,(struct sockaddr*)&a,&al) != 0){ close(l); return -1; }
    if(listen(l,8)<0){
        fprintf(stderr,"[tor] onion listener listen failed: %s\n", strerror(errno));
        close(l); return -1;
    }
    if(got_port) *got_port = ntohs(a.sin_port);
    return l;
}

static int lsock(int port){
    int l = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons((unsigned short)port);
    /* Core -bind: listen on one address instead of every interface. Empty (the
     * default) keeps the previous INADDR_ANY behaviour. A malformed value is
     * refused rather than silently widening the bind to every interface --
     * failing closed is the safe direction for a listen address. */
    if(g_cfg.bind_addr[0]){
        if(inet_pton(AF_INET, g_cfg.bind_addr, &a.sin_addr) != 1){
            fprintf(stderr,"[net] bind=%s is not a valid IPv4 address -- refusing to listen\n", g_cfg.bind_addr);
            close(l); return -1;
        }
    } else a.sin_addr.s_addr=htonl(INADDR_ANY);
    int one=1; setsockopt(l,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    if(bind(l,(struct sockaddr*)&a,sizeof a)<0){ fprintf(stderr,"[net] bind failed: %s\n", strerror(errno)); return -1; }
    if(listen(l,8)<0){ fprintf(stderr,"[net] listen failed: %s\n", strerror(errno)); return -1; }
    return l;
}
/* -whitebind listeners. One socket per entry, bound to the exact address and
 * port the operator named -- NOT sharing the main listener, because a peer's
 * permissions here come from which socket accepted it, and a shared socket
 * would grant them to everyone.
 *
 * Failure to bind one is FATAL rather than a warning. An operator who wrote
 * whitebind expects those peers to be unbannable; silently not listening
 * there would look identical to listening and would fail only when a
 * misbehaviour score eventually disconnected a peer that was supposed to be
 * exempt -- long after the cause. */
static int g_wb_fd[NETPERM_MAX_BIND];
static int g_wb_n;

static void wb_listen_open(void){
    g_wb_n = 0;
    for(int i = 0; i < netperm_whitebind_count(); i++){
        const char* addr = netperm_whitebind_addr(i);
        int port = netperm_whitebind_port(i);
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if(fd < 0){ fprintf(stderr,"[net] FATAL: whitebind socket: %s\n", strerror(errno)); exit(1); }
        struct sockaddr_in a; memset(&a,0,sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons((unsigned short)port);
        if(inet_pton(AF_INET, addr, &a.sin_addr) != 1){
            fprintf(stderr,"[net] FATAL: whitebind address %s is not valid\n", addr); exit(1); }
        int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        if(bind(fd,(struct sockaddr*)&a,sizeof a) < 0){
            fprintf(stderr,"[net] FATAL: whitebind %s:%d: %s\n", addr, port, strerror(errno));
            exit(1);
        }
        if(listen(fd,8) < 0){
            fprintf(stderr,"[net] FATAL: whitebind listen %s:%d: %s\n", addr, port, strerror(errno));
            exit(1);
        }
        netperm_bind_fd(fd, netperm_whitebind_flags(i));
        g_wb_fd[g_wb_n++] = fd;
        fprintf(stderr,"[net] whitebind listening on %s:%d (grants noban)\n", addr, port);
    }
}

/* The IPv6 half of the listener (2026-08-28). Separate socket, v6-only, so
 * it cannot collide with the IPv4 one above; -1 when the host has no IPv6,
 * which is not an error -- the node simply serves v4 only. A CJDNS peer
 * reaches us here, on the fc00::/8 address of the tun interface. */
static int lsock_v6(int port){
    unsigned char any[16]; memset(any, 0, 16);
    const unsigned char* bindaddr = NULL;
    if(g_cfg.bind_addr[0]){
        bmc_addr_t b;
        if(bmc_addr_from_string(&b, g_cfg.bind_addr) && (b.net == BMC_NET_IPV6 || b.net == BMC_NET_CJDNS)){
            memcpy(any, b.addr, 16); bindaddr = any;
        } else return -1;            /* bind= names a v4 address: no v6 listener */
    }
    int l = lsock6(bindaddr, port, 8);
    if(l >= 0) fprintf(stderr,"[net] listening on IPv6 %s:%d (cjdns peers arrive here)\n",
                       bindaddr ? g_cfg.bind_addr : "[::]", port);
    return l;
}

/* ---- BEST-EFFORT OUTBOUND CATCH-UP (stays-up-to-date on boot) ----
 * The serve loop is inbound-only; without an outbound connection the node can
 * never pull missed blocks. On serve startup we try real mainnet seeds (via the
 * verified asm tcp_connect_ip + node_handshake) and run the verified asm
 * node_drain per-peer download loop to catch up the store to the chain tip.
 * It is deliberately best-effort and non-fatal: any seed/network failure falls
 * straight through to serving (the node still serves whatever it has, and the
 * new bitcoin_serve.asm `.do_block` keep-up path stores any block a peer later
 * pushes). Returns the count of blocks added on success, 0/-1 on no-network.
 * Sieve out peers that hang: a 10s recv timeout + per-seed cap. */
/* DNS seed hostnames come from the SELECTED CHAIN (daemon/chainparams.c owns
 * the per-chain lists, mainnet's being the set that always lived here).
 * These two are set right after chainparams_select() in main(); the static
 * defaults keep every pre-chain-selection tool path on mainnet behaviour. */
static const char* const catchup_seeds_default[] = { "seed.bitcoin.sipa.be" };
static const char* const* g_seed_hosts = catchup_seeds_default;
static int g_n_seed_hosts = 1;
static void anchor_locator(unsigned char loc[32]);   /* fwd decl (defined below) */
/* Wall-clock alarm handler: raise SIGALRM after CATCHUP_MAX_SECS so the
 * synchronous node_sync catch-up (blocking on a real seed) is interrupted and
 * the mux loop can start. node_sync's blocking p2p_read is interrupted by the
 * signal (EINTR), so it returns and the parent proceeds to the mux loop. */
static void catchup_alarm(int sig){ (void)sig; }
/* Bounded boot catch-up. Runs ONE node_sync pass (the verified asm download->
 * validate->store path) against the first reachable seed, anchored at the
 * stored tip, to close any small gap before the mux starts. A wall-clock alarm
 * (CATCHUP_MAX_SECS) bounds the synchronous window: if the gap is large the
 * alarm fires, node_sync returns, and the mux loop takes over closing the rest
 * gradually WHILE SERVING (the mux is the long-running stays-current
 * mechanism). Returns # blocks pulled. */
static long outbound_catchup(long max_blocks){
    static unsigned char cbuf[4<<20];
    long total=0;
    /* This path dials the DNS seed hostnames directly, so it IS dns seeding:
     * -dnsseed=0 and -connect must suppress it or the node would quietly
     * contact seeds the operator disabled. Under -connect the configured
     * nodes are used instead. */
    const char* clist[CFG_MAX_NODES];
    const char** srcs = (const char**)g_seed_hosts;
    size_t nsrcs = (size_t)g_n_seed_hosts;
    if(g_cfg.connect_only){
        for(int i=0;i<g_cfg.n_connect;i++) clist[i]=g_cfg.connectn[i];
        srcs = clist; nsrcs = (size_t)g_cfg.n_connect;
        if(nsrcs==0){ fprintf(stderr,"[catchup] connect=0 -- no outbound catch-up\n"); return 0; }
    } else if(!g_cfg.dnsseed){
        fprintf(stderr,"[catchup] dnsseed=0 -- skipping seed-based boot catch-up\n");
        return 0;
    }
    if(dialer_dns_blocked()){
        fprintf(stderr,"[catchup] a proxy is configured (or dns=0) -- not resolving seed names\n");
        return 0;
    }
    for(size_t s=0; s<nsrcs; s++){
        const char* host=srcs[s];
        struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
        if(getaddrinfo(host,NULL,&h,&res)!=0) continue;
        unsigned ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(res);
        int fd=tcp_connect_ip(ip,(unsigned short)htons((unsigned short)g_chainp->default_port));
        if(fd<0) continue;
        struct timeval tv; tv.tv_sec=10; tv.tv_usec=0;
        setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
        /* this path speaks v1 only; clear any flag a recycled fd may carry */
        bmc_v2_close(fd);
        if(node_handshake(fd)!=1 || !peer_has_witness(host)){ close(fd); continue; }
        static unsigned char loc[32];
        /* Anchor from the STORED TIP index record (index-hash read, robust to a
         * transiently-unreadable tip body -- avoiding the live-found genesis
         * re-download duplicate-tail corruption) or a zero locator when empty. */
        anchor_locator(loc);
        /* Wall-clock cap: alarm after CATCHUP_MAX_SECS so a large gap does not
         * block the mux start. node_sync's blocking reads see the SIGALRM as
         * EINTR and return; we then proceed to the mux loop. */
        struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=catchup_alarm;
        sigaction(SIGALRM,&sa,NULL);
        alarm(CATCHUP_MAX_SECS);
        long cnt=0;
        long ok=node_sync(fd, store_buf, loc, cbuf, (long)sizeof cbuf, &cnt);
        alarm(0);
        int tip=*(int*)(store_buf+24);
        fprintf(stderr,"[catchup] %-28s sync ok=%ld new=%ld tip=%d\n", host, ok, cnt, tip);
        close(fd);
        total=cnt;
        break;   /* one bounded pass; the mux loop closes the rest */
    }
    return total>max_blocks?max_blocks:total;
}

static unsigned char fake_blocks[8][4096]; static long fake_blen[8]; static unsigned char fake_bh[8][32]; static int fake_NB=0;
static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}
extern void sha256d(unsigned char o[32],const void*m,long l);
extern int  pow_check(const unsigned char h[80]);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
static void build_fake_chain(void){
    /* build an 8-block coinbase chain up front. fake_NB starts at 2 and grows by
     * 1 per getheaders in the growing peer; full_serve bumps it to 8 to expose
     * the whole chain. */
    static int built=0;
    if(built) return;
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<8;i++){
        unsigned char* b=fake_blocks[i]; unsigned char* o=b; unsigned char t[200]; memset(t,0,200); unsigned char* q=t;
        put_u32(q,1);q+=4; q[0]=1;q+=1; memset(q,0,32);q+=32; put_u32(q,0xffffffff);q+=4;
        q[0]=3; q[1]=(unsigned char)i; q[2]=0; q[3]=0; q+=4; put_u32(q,0xffffffff);q+=4;
        q[0]=1;q+=1; put_u64(q,8*1000000);q+=8; q[0]=1;q[1]=0x51;q+=2; put_u32(q,0);q+=4;
        long tl=q-t; unsigned char mr[32]; sha256d(mr,t,tl);
        put_u32(o,1);o+=4; memcpy(o,prev,32);o+=32; memcpy(o,mr,32);o+=32;
        put_u32(o,1300000000u);o+=4; put_u32(o,0x207fffff);o+=4; put_u32(o,0);o+=4;
        o[0]=1; o+=1;                /* tx-count varint (1 tx) -- REQUIRED wire field */
        memcpy(o,t,tl);o+=tl; fake_blen[i]=o-b;
        unsigned nz=0; while(!pow_check(fake_blocks[i])){ nz++; put_u32(fake_blocks[i]+76,nz); }
        block_hash(fake_bh[i],fake_blocks[i]); memcpy(prev,fake_bh[i],32);
    }
    fake_NB=2;
    built=1;
}
static void fake_serve(int cfd){
    /* build an 8-block chain up front, but only expose the first `fake_NB`.
     * fake_NB grows by 1 on each getheaders, so a client that keeps re-syncing
     * observes new blocks being mined over time (realtime keep-up demo). */
    build_fake_chain();
    char cmd[12]; unsigned char pl[65536]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); /* client version */
    unsigned char v[102]; memset(v,0,sizeof v); v[4]=9; p2p_write(cfd,"version",7,v,86);
    p2p_write(cfd,"verack",6,"",0);
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); /* client verack */
    for(int n=0;n<64;n++){
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return; cmd[11]=0;
        if(strncmp(cmd,"getheaders",10)==0){
            if(fake_NB<8) fake_NB++;          /* a new block is "mined" */
            int zero=1; for(int z=0;z<32;z++) if(pl[5+z]){zero=0;break;}
            int from=0; if(zero) from=0; else { from=fake_NB; for(int i=0;i<fake_NB;i++) if(memcmp(pl+5,fake_bh[i],32)==0) from=i+1; }
            int cnt=fake_NB-from; if(cnt<0)cnt=0;
            if(cnt>0){ unsigned char hp[300]; hp[0]=cnt; int p=1; for(int i=from;i<fake_NB;i++){memcpy(hp+p,fake_blocks[i],80);hp[p+80]=0;p+=81;} p2p_write(cfd,"headers",7,hp,p);}
            else p2p_write(cfd,"headers",7,"\x00",1);
        } else if(strncmp(cmd,"getdata",7)==0){
            int found=-1; for(int i=0;i<fake_NB;i++) if(memcmp(pl+5,fake_bh[i],32)==0) found=i;
            if(found>=0) p2p_write(cfd,"block",5,fake_blocks[found],(unsigned)fake_blen[found]);
            else p2p_write(cfd,"block",5,"",0);
        } else if(strncmp(cmd,"ping",4)==0){
            p2p_write(cfd,"pong",4, pl, (plen>=8)?8:0);
        }
    }
}
/* whole-chain peer for the `ibd` mode: serves ALL fake_NB=8 stored blocks and
 * their headers (no growth) so the full machine-code node_ibd pass can pull the
 * entire persisted chain in one go -- the daemon-side analogue of test_ibd_full. */
static void full_serve(int cfd){
    build_fake_chain();
    fake_NB=8;                                   /* expose the WHOLE chain now */
    char cmd[12]; unsigned char pl[65536]; unsigned plen=0;
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); /* client version */
    unsigned char v[102]; memset(v,0,sizeof v); v[4]=9; p2p_write(cfd,"version",7,v,86);
    p2p_write(cfd,"verack",6,"",0);
    plen=0; p2p_read(cfd,cmd,pl,sizeof pl,&plen); /* client verack */
    int gd=0;
    for(int n=0;n<64;n++){
        plen=0; if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0) return; cmd[11]=0;
        if(strncmp(cmd,"getheaders",10)==0){
            int zero=1; for(int z=0;z<32;z++) if(pl[5+z]){zero=0;break;}
            int from=0; if(!zero){ from=fake_NB; for(int i=0;i<fake_NB;i++) if(memcmp(pl+5,fake_bh[i],32)==0){from=i+1;break;} }
            int cnt=fake_NB-from; if(cnt<0)cnt=0;
            if(cnt>0){ unsigned char hp[300]; hp[0]=cnt; int p=1; for(int i=from;i<fake_NB;i++){memcpy(hp+p,fake_blocks[i],80);hp[p+80]=0;p+=81;} p2p_write(cfd,"headers",7,hp,p);}
            else p2p_write(cfd,"headers",7,"\x00",1);
        } else if(strncmp(cmd,"getdata",7)==0){
            int found=-1; for(int i=0;i<fake_NB;i++) if(memcmp(pl+5,fake_bh[i],32)==0) found=i; gd++;
            fprintf(stderr,"[full_serve] getdata#%d found=%d\n", gd, found);
            if(found>=0) p2p_write(cfd,"block",5,fake_blocks[found],(unsigned)fake_blen[found]);
            else p2p_write(cfd,"block",5,"",0);
        } else if(strncmp(cmd,"ping",4)==0){
            p2p_write(cfd,"pong",4, pl, (plen>=8)?8:0);
        }
    }
}
static int serve_loop(int fd, int lfd){
    char cmd[12]; static unsigned char pl[8<<20]; unsigned plen=0; static unsigned char out[8<<20];
    int served=0;
    for(int n=0; n<10000; n++){
        plen=0;
        int r=p2p_read(fd,cmd,pl,sizeof pl,&plen);
        if(r<=0) break;                                  /* eof/err */
        cmd[11]=0;
        if(memcmp(cmd,"ping",4)==0){
            p2p_write(fd,"pong",4, pl, (plen>=8)?8:0);   /* echo nonce */
        } else if(memcmp(cmd,"getaddr",7)==0){
            /* the same reply the asm serve loop gives (daemon/serve_addr.c,
             * from the version-2 book); this test-mode loop never learns the
             * peer's BIP155 preference, so legacy addr */
            extern long serve_getaddr(int, int);
            serve_getaddr(fd, 0);
        } else if(memcmp(cmd,"getdata",7)==0){
            /* payload: count varint then per item: [type int32 LE][hash32].
             * The wire inventory `type` is a 4-byte little-endian int32
             * (verified byte-exact vs p2p_oracle.py and LIVE: this is what the
             * reference client and real nodes send). One MSG_BLOCK inventory is
             * [count=0x01][type=0x02 0000][hash at +5] = 37 bytes total.
             * Match the requested hash against each stored block's header hash
             * (via the verified block_hash asm) and serve the exact block. */
            if(plen>=37){
                unsigned cnt = pl[0];                       /* count varint (1B here) */
                if(cnt>=1 && 1+cnt*36 <= plen){
                    int tip = *(int*)(store_buf+24);
                    for(unsigned item=0; item<cnt; item++){
                        size_t off = 1 + item*36;           /* [type 4B][hash 32] */
                        unsigned int type = pl[off]|pl[off+1]<<8|pl[off+2]<<16|pl[off+3]<<24;
                        if(type!=2 || off+32>=plen) continue;
                        long gl=-1;
                        long fh;
                        if(idx_get(ht_idx, pl+off+4, &fh)){
                            static unsigned char sb[8<<20];
                            long L = node_serve_block(store_buf, fh, sb, sizeof sb);
                            if(L>0){ gl=L; memcpy(out,sb,(size_t)L); }
                        }
                        if(gl>0){ p2p_write(fd,"block",5,out,(unsigned)gl); served++;
                                  node_log_event(lfd, L_SERVE, (unsigned)gl, 0, 1); }
                    }
                }
            }
        } else if(memcmp(cmd,"getheaders",10)==0){
            /* headers payload: key_count(1) hash_count(1) hashes[] stop(32).
             * First locator hash at +5. Respond with headers for the blocks
             * AFTER that locator (headers msg = count varint + per-hdr 81B). */
            int from=-1;
            if(plen>=5){ int tip = *(int*)(store_buf+24);
                long fh;
                if(idx_get(ht_idx, pl+5,&fh)){ from=(int)fh+1; }
                if(from<0 && tip>0) from=0;   /* unknown locator: from genesis */
            }
            if(from>=0){ int tip=*(int*)(store_buf+24); unsigned char hp[2000*81+4]; int p=1;
                int n=0; for(int h=from; h<=tip && n<2000; h++,n++){ static unsigned char sb[8<<20];
                    long L=node_serve_block(store_buf,h,sb,sizeof sb); if(L<0)break;
                    memcpy(hp+p, sb, 80); hp[p+80]=0; p+=81;                  /* hdr + tx-count */
                }
                hp[0]=(unsigned char)(n&0xff);                                 /* count varint */
                p2p_write(fd,"headers",7,hp,p);
                node_log_event(lfd, L_HDRS, (unsigned)n, (unsigned)from, 0);
            } else {
                p2p_write(fd,"headers",7,"\x00",1);
            }
        } else if(memcmp(cmd,"inv",3)==0){
            /* Peer announced new blocks: inv = count(1) [type u32 LE + hash32].
             * Request each MSG_BLOCK(2) we don't already store, receive the
             * block, cons_verify, and store_append -> realtime keep-up driven by
             * peer push (event-driven), not polling. */
            if(plen>=5){ unsigned n=pl[0];
                for(unsigned i=0;i<n && i<50;i++){
                    size_t off=1+i*36;
                    unsigned int type=pl[off]|pl[off+1]<<8|pl[off+2]<<16|pl[off+3]<<24;
                    if(type==2 && off+32<plen){
                        /* duplicate check via O(1) hash index */
                        long fh; int have = idx_get(ht_idx, pl+off+4, &fh)?1:0;
                        if(!have){
                            /* build real getdata payload with the hash */
                            static unsigned char gd[37]; gd[0]=1; gd[1]=2; gd[2]=0; gd[3]=0; gd[4]=0;
                            memcpy(gd+5, pl+off+4, 32);
                            p2p_write(fd,"getdata",7,gd,37);
                            char c2[12]; static unsigned char blk[8<<20]; unsigned bl=0;
                            int rr=p2p_read(fd,c2,blk,sizeof blk,&bl);
                            if(rr>0 && strncmp(c2,"block",5)==0){
                                static unsigned char scratch[2048];
                                if(cons_verify(blk,bl,scratch,64)==1){
                                    unsigned char hdr[32]; block_hash(hdr,blk);
                                    store_append(store_buf,hdr,blk,bl);
                                    node_log_event(lfd, L_BLOCK, (unsigned)bl, 1, i);
                                }
                            }
                        }
                    }
                }
            }
        } else if(memcmp(cmd,"verack",6)==0){
            /* already handshaken; ignore */
        }
    }
    return served;
}

/* ============================================================================
 * OUTBOUND MULTIPLEXER (stays-current-while-serving).
 *
 * The serve loop above is inbound-only (fork-per-peer). This block adds the
 * persistent OUTBOUND legs the node needs to stay current on its own: N
 * long-lived connections to real seeds, multiplexed with the listening socket
 * in ONE poll() loop. On each rotation pass we run the now-hardened asm
 * node_sync (getheaders-from-stored-tip -> cons_verify -> store_append ->
 * advance locator) to pull any newly mined blocks, then maintain the hash
 * index and announce the new tip back to the peer (node_announce_tip, BIP130
 * honored by the peer's own negotiation). Inbound connections are still forked
 * off to node_serve_loop children so concurrent serving is unaffected.
 *
 * The outbound legs are NOT forked -- they are multiplexed inline in the one
 * parent loop, so the node simultaneously serves AND downloads. Each outbound
 * fd carries a short SO_RCVTIMEO so a node_sync pass returns promptly when the
 * peer is already at the chain tip (empty headers page) instead of blocking
 * the accept loop.
 * ========================================================================== */
/* ---- connection budget, matching Bitcoin Core's shape -------------------
 *   full-relay        8   ordinary outbound: tx + block relay, addr gossip
 *   block-relay-only  2   headers/blocks only (relay=0), never addr-gossiped
 *   feeler            1   short-lived liveness probe, ~every 2 minutes
 *   -------------------
 *   outbound         11, leaving MAX_CONNECTIONS-11 inbound slots.
 *
 * There was previously NO inbound limit at all: the accept loop forked a
 * child per connection with nothing bounding it, so an attacker could open
 * connections until the host ran out of processes or memory. */
/* These are HARD BOUNDS (array sizing). The live values come from g_cfg,
 * loaded from bitcoin.conf at boot and clamped to these -- see
 * daemon/node_config.c. An array cannot be sized from a runtime value, so the
 * ceiling stays compiled while the operator tunes underneath it. */
#define MAX_BLOCK_RELAY_ONLY       8         /* ceiling; g_cfg picks the live count */
#define CFG_INBOUND_LIMIT() \
    (g_cfg.max_connections - g_cfg.max_outbound - g_cfg.max_block_relay_only - g_cfg.max_feeler)

/* -shrinkdebugfile (2026-09-01): Core truncates a debug.log over 10 MB to
 * its last 200 KB at start-up. This node's own leveled log is g_logpath;
 * the stderr stream systemd appends is that unit's file, not ours. */
static void log_shrink(const char* path){
    struct stat sb;
    if (!path || !*path || !strcmp(path, "/dev/null") || stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) return;
    if (sb.st_size <= 10L * 1000 * 1000) return;
    FILE* f = fopen(path, "rb"); if (!f) return;
    static char tail[200000];
    fseek(f, -(long)sizeof tail, SEEK_END);
    size_t n = fread(tail, 1, sizeof tail, f); fclose(f);
    f = fopen(path, "wb"); if (!f) return;
    fwrite(tail, 1, n, f); fclose(f);
    fprintf(stderr, "[boot] shrinkdebugfile: %s was %ld bytes -- kept the last %zu\n", path, (long)sb.st_size, n);
}
/* -walletnotify (2026-09-01): run the command with %s = txid for every
 * transaction that concerns the wallet -- on mempool acceptance (txsub and
 * the relay legs) and again when it confirms (walletnotify_block). */
static long wn_varint(const unsigned char* p, long n, unsigned long long* v){
    if (n < 1) return 0;
    if (p[0] < 0xfd){ *v = p[0]; return 1; }
    if (p[0] == 0xfd){ if (n < 3) return 0; *v = p[1] | (p[2] << 8); return 3; }
    if (p[0] == 0xfe){ if (n < 5) return 0; *v = p[1] | (p[2]<<8) | ((unsigned long long)p[3]<<16) | ((unsigned long long)p[4]<<24); return 5; }
    if (n < 9) return 0; *v = 0; for (int i = 0; i < 8; i++) *v |= (unsigned long long)p[1+i] << (8*i); return 9;
}
/* serialized length of the tx at p (segwit-aware); 0 if malformed */
static long wn_tx_len(const unsigned char* p, long n){
    long q = 4; unsigned long long v; long k; int segwit = 0;
    if (q + 2 <= n && p[q] == 0x00 && p[q+1] == 0x01){ segwit = 1; q += 2; }
    if (!(k = wn_varint(p + q, n - q, &v))) return 0; q += k; unsigned long long nin = v;
    for (unsigned long long i = 0; i < nin; i++){
        q += 36; if (q > n) return 0;
        if (!(k = wn_varint(p + q, n - q, &v))) return 0; q += k + (long)v + 4; if (q > n) return 0;
    }
    if (!(k = wn_varint(p + q, n - q, &v))) return 0; q += k; unsigned long long nout = v;
    for (unsigned long long i = 0; i < nout; i++){
        q += 8; if (q > n) return 0;
        if (!(k = wn_varint(p + q, n - q, &v))) return 0; q += k + (long)v; if (q > n) return 0;
    }
    if (segwit) for (unsigned long long i = 0; i < nin; i++){
        if (!(k = wn_varint(p + q, n - q, &v))) return 0; q += k;
        for (unsigned long long j = 0; j < v; j++){ unsigned long long l;
            if (!(k = wn_varint(p + q, n - q, &l))) return 0; q += k + (long)l; if (q > n) return 0; }
    }
    q += 4;
    return q <= n ? q : 0;
}
static void walletnotify_tx(const unsigned char* tx, long len){
    if (!g_cfg.walletnotify[0] || !g_rpc_wallet.seed || len < 10) return;
    if (!rpc_wops_tx_touches_wallet(&g_rpc_wallet, tx, (unsigned long)len)) return;
    extern int tx_txid(unsigned char* out, const unsigned char* tx, unsigned long txlen, unsigned char* scratch, unsigned long scratchcap);
    unsigned char id[32]; unsigned char* scratch = malloc((size_t)len + 64); if (!scratch) return;
    tx_txid(id, tx, (unsigned long)len, scratch, (unsigned long)len + 64); free(scratch);
    char hx[65]; for (int b = 0; b < 32; b++) snprintf(hx + b*2, 3, "%02x", id[31-b]);
    notify_run(g_cfg.walletnotify, hx, "walletnotify");
}
static void walletnotify_block(const unsigned char* blk, long blen){
    if (blen < 81) return;
    unsigned long long ntx; long p = 80, k = wn_varint(blk + p, blen - p, &ntx);
    if (!k) return; p += k;
    for (unsigned long long i = 0; i < ntx && p < blen; i++){
        long tl = wn_tx_len(blk + p, blen - p);
        if (tl <= 0) return;
        walletnotify_tx(blk + p, tl);
        p += tl;
    }
}
static void txr_walletnotify_hook(const unsigned char* txid, const unsigned char* tx, unsigned long len){ (void)txid; walletnotify_tx(tx, (long)len); }
/* BIP324 v2 transport. Off means the node behaves exactly as it did before
 * this existed: p2p_read/p2p_write never register an fd, so their dispatch
 * falls straight through to v1. */
#define CFG_V2TRANSPORT() (g_cfg.v2transport)
/* Core -persistmempool: reload mempool.dat at boot, write it at shutdown. */
#define CFG_PERSISTMEMPOOL() (g_cfg.persistmempool)
/* Core -reindex-chainstate: rebuild the UTXO set from the archive. One-shot. */
#define CFG_REINDEX_CHAINSTATE() (g_cfg.reindex_chainstate)
#define CFG_BRO_N() \
    (g_cfg.max_block_relay_only < MAX_BLOCK_RELAY_ONLY ? g_cfg.max_block_relay_only : MAX_BLOCK_RELAY_ONLY)
/* Array capacity for outbound legs. The TARGET is g_cfg.max_outbound
 * (bitcoin.conf `bmc.maxoutbound`, Core's 8 full-relay by default); this is
 * only the ceiling those arrays can hold, and must be >= the knob's clamp.
 *
 * Until 2026-08-23 this was 8 AND the dial loops carried a literal 8 beside
 * it, so g_cfg.max_outbound -- which has existed and been parseable all along
 * -- reached nothing except the inbound budget calculation. Setting it did
 * nothing. Two numbers for one concept, in four places. */
#define MUX_MAX_OUT 64
/* The live target, clamped to what the arrays can hold. */
#define MUX_WANT_OUT() ((int)(g_cfg.max_outbound > MUX_MAX_OUT ? MUX_MAX_OUT : \
                              (g_cfg.max_outbound < 1 ? 1 : g_cfg.max_outbound)))
static int   mux_out_fd[MUX_MAX_OUT];       /* persistent outbound seed fds  */
/* per-leg BIP155 verdict from the handshake: 1 = the peer sent sendaddrv2,
 * so it gets addrv2-encoded self-announcements (daemon/addr_self.c) */
static unsigned char mux_out_wants_v2[MUX_MAX_OUT];
/* each leg's BMC_NET_*, derived from its host string. We announce ONE
 * address -- this node's clearnet IPv4 -- and telling an onion or i2p peer
 * that address links the two, which is exactly what running over those
 * networks is meant to prevent. Core's GetLocal has the same guard.
 * (2026-08-28 pre-deploy review.) */
static unsigned char mux_out_net[MUX_MAX_OUT];
static unsigned char mux_out_loc[MUX_MAX_OUT][32];  /* per-peer locator (tip) */
static char  mux_out_host[MUX_MAX_OUT][128]   /* "host:port" of a v3 onion is 67 bytes; 64 truncated it and broke the top-up dedupe (2026-09-01) */;
static int   g_in_dial_helper = 0;          /* set in a dial-helper child: no book writes, no shared-status writes */
static int   mux_n_out = 0;
static int   mux_out_peer[MUX_MAX_OUT];     /* index into the peer pool (for re-dial rotation) */
static long long mux_out_nextretry[MUX_MAX_OUT];
/* consecutive failed sync passes per leg; surfaced in the heartbeat as
 * sync_failing=N and used to drop a leg that will not answer (see
 * do_outbound_sync). */
static int g_sync_fail_streak[MUX_MAX_OUT]; /* monotonic ms deadline before the next re-dial attempt */
#define REDIAL_BACKOFF_MS 30000L             /* min gap between re-dial tries on a dead slot */

/* ---- runtime peer control (RPC ctl_* channel) ---------------------------
 * The worker owns the legs, so it owns these. The parent asks; this decides.
 * The runtime addnode list is SEPARATE from g_cfg.addnode (the operator's
 * bitcoin.conf list): `addnode ... remove` must be able to drop a runtime
 * addition without editing the config, and getaddednodeinfo reports the
 * config list, so conflating them would make `remove` appear to fail. */
#define CTL_MAX_ADDNODE 32
static char g_ctl_addnode[CTL_MAX_ADDNODE][64];
static int  g_ctl_n_addnode = 0;

/* Is `ip` covered by a ban entry? Entries are either a bare address or
 * a.b.c.d/LEN; matching is on the textual prefix for a bare address and on
 * the leading octets for a /8, /16 or /24, which is what an operator
 * realistically bans. A subnet form this cannot express is REFUSED at
 * setban rather than silently stored and never enforced -- a ban that does
 * not ban is worse than an error. */
/* Was a dotted-decimal STRING comparison, which rejected every prefix that
 * was not a whole number of octets (/28, /12, /20 matched nothing) and did
 * not handle IPv6 at all -- so `setban 2001:db8::/32` was accepted, stored,
 * listed by listbanned, and never matched a peer. A ban that silently does
 * nothing is worse than a refused one: the operator believes the peer is
 * gone. daemon/subnet.c is the one implementation now, shared with the
 * -whitelist matcher that needed the same rule. */
static int ctl_ban_covers(const char* entry, const char* ip){
    return subnet_covers_str(entry, ip);
}

/* 1 if this address is currently banned. Called before every dial. */
/* -alertnotify delivery. Named and non-static so reorg can be handed it
 * without reorg.c learning about the config. */
void bmc_alert_deliver(const char* msg){
    fprintf(stderr,"[alert] %s\n", msg ? msg : "?");
    if (g_cfg.alertnotify[0]) notify_run(g_cfg.alertnotify, msg, "alertnotify");
}

int ctl_is_banned(const char* ip){
    if(!g_node_status) return 0;
    long long now = (long long)time(NULL);
    for(int i = 0; i < RPC_MAX_BANS; i++){
        if(!g_node_status->bans[i].until) continue;
        if(g_node_status->bans[i].until <= now){
            g_node_status->bans[i].until = 0;      /* lazily expire */
            continue;
        }
        if(ctl_ban_covers((const char*)g_node_status->bans[i].subnet, ip)) return 1;
    }
    return 0;
}

/* ---- automatic banning (Core's Misbehaving()) -----------------------------
 * setban/listbanned/clearbanned already existed, but NOTHING drove them: a
 * peer could send malformed message after malformed message and the node
 * would keep talking to it. Core scores misbehaviour and bans at 100 points.
 *
 * The ban list lives in shared status memory and is read by every process
 * (ctl_is_banned), so an automatic ban is written the same way a manual one
 * is. Scores, by contrast, are per-process and deliberately NOT shared: a
 * score is a local heuristic about one connection, and losing it on a fork
 * is harmless, while sharing it would need locking on a hot path. */
#define MISBEHAVIOR_BAN_THRESHOLD 100
#define MISBEHAVIOR_SLOTS 64
_Static_assert(MISBEHAVIOR_SLOTS == RPC_MISBEHAVIOR_SLOTS,
              "the local and shared misbehaviour tables must be the same size");
/* Fallback table, used only when the shared region is unavailable (test
 * binaries that link main.c without mmapping a node_status_t, and the
 * degraded path if the mmap failed at boot). The real one lives in shared
 * memory -- see node_status_t.misbehavior. */
static struct { char ip[64]; int score; } g_misbehavior[MISBEHAVIOR_SLOTS];

/* Cross-process spinlock around the shared table. Held for a handful of
 * string compares, never across I/O, so spinning is cheaper than any
 * alternative and cannot deadlock a child against itself. */
/* The misbehaviour table's cross-process lock.
 *
 * It used to be an UNBOUNDED spin on a 0/1 flag with no record of who held it:
 *
 *     while (__sync_lock_test_and_set(&st->mis_lock, 1)) nanosleep(1ms);
 *
 * This daemon forks a serve child per inbound connection, and every one of
 * them scores misbehaviour into this shared table. If any holder DIES while
 * holding it -- the OOM killer, a crash, an operator's kill -9 -- the flag
 * stays 1 forever and every surviving process wedges permanently the next time
 * it scores a peer. There is no recovery short of a restart, and nothing says
 * what happened.
 *
 * That is not hypothetical: it happened on 2026-08-31, when a stale co-resident
 * daemon was SIGKILLed and the survivor stopped applying blocks on the spot,
 * silently, while still answering RPC.
 *
 * So the lock now HOLDS THE OWNER'S PID instead of 1 (0 = free), and a waiter
 * that has spun for ~2s checks whether that pid still exists. If it does not,
 * it reclaims the lock and says so. Stealing is safe here in a way it would
 * not be for a general lock: the protected data is a fixed 64-slot array of
 * {score, ip} with no pointers and no allocation, so the worst case of a
 * reclaim mid-update is one garbled misbehaviour score -- a heuristic that is
 * already approximate -- rather than a corrupted structure.
 *
 * The pid fits: mis_lock is an int and this is Linux, where pid_max is well
 * under INT_MAX. */
static void mis_lock_acquire(node_status_t* st){
    const int me = (int)getpid();
    for (int spins = 0; ; spins++) {
        if (st->mis_lock == 0 &&
            __sync_bool_compare_and_swap(&st->mis_lock, 0, me)) return;
        struct timespec ts = { 0, 1000 * 1000 };   /* 1 ms */
        nanosleep(&ts, NULL);
        if (spins >= 2000) {                        /* ~2s of contention */
            int owner = st->mis_lock;
            if (owner != 0 && owner != me &&
                kill((pid_t)owner, 0) != 0 && errno == ESRCH) {
                if (__sync_bool_compare_and_swap(&st->mis_lock, owner, me)) {
                    fprintf(stderr, "[ban] misbehaviour lock was held by dead "
                                    "pid %d -- reclaimed\n", owner);
                    return;
                }
            }
            spins = 0;                              /* live holder: keep waiting */
        }
    }
}
static void mis_lock_release(node_status_t* st){ __sync_lock_release(&st->mis_lock); }

/* ---- protocol-violation reporting from the asm serve loop ----------------
 * (audit 2026-08-29 finding 7)
 *
 * peer_misbehaving() has existed for a while with a 100-point threshold, /32
 * auto-ban and lowest-score eviction -- and, until now, ZERO call sites. The
 * comment "a peer could send malformed message after malformed message and
 * the node would keep talking to it" was literally true.
 *
 * bitcoin_serve.asm calls back here when p2p_read reports -3, an announced
 * message length above P2P_MAX_MSG. No conforming implementation produces
 * that -- Core treats an oversized header as fatal for the connection -- so
 * it is scored at the full threshold and the peer is banned rather than
 * merely dropped.
 *
 * HONEST LIMITATION: g_misbehavior is a process-local array and the serve
 * loop runs in a forked child, so scores do NOT accumulate across
 * connections. What makes this bite anyway is that crossing the threshold
 * calls ctl_ban_add(), which writes the SHARED, file-backed ban list that
 * both the dial path and the inbound accept path consult. So a single
 * violation bans the peer for real; repeat offences across reconnects are not
 * tracked, and that remains a gap worth closing separately. */
static char g_cur_peer_ip[64];
extern void (*g_serve_violation_hook)(const char*);
/* Declared, because it is DEFINED below this call. Without it C assumes
 * `int peer_misbehaving()` with unspecified arguments -- which happens to work
 * for these types under the SysV ABI, which is exactly why the warning had
 * been ignored. It is a warning about a real missing prototype. */
int peer_misbehaving(const char* ip, int points, const char* reason);
static void serve_violation_report(const char* reason){
    if(!g_cur_peer_ip[0]) return;
    peer_misbehaving(g_cur_peer_ip, 100, reason ? reason : "protocol violation");
}

/* Add `subnet` to the shared ban list until `until`. 1 if newly banned. */
int ctl_ban_add(const char* subnet, long long until){
    if(!g_node_status || !subnet || !*subnet) return 0;
    int slot = -1;
    for(int i = 0; i < RPC_MAX_BANS; i++){
        if(g_node_status->bans[i].until &&
           !strcmp((const char*)g_node_status->bans[i].subnet, subnet)) return 0;  /* already */
        if(!g_node_status->bans[i].until && slot < 0) slot = i;
    }
    if(slot < 0) return 0;                       /* list full: no silent evict */
    snprintf((char*)g_node_status->bans[slot].subnet, 64, "%s", subnet);
    g_node_status->bans[slot].created = (long long)time(NULL);
    __sync_synchronize();
    g_node_status->bans[slot].until = until;     /* published last */
    return 1;
}

/* Score a peer for a protocol violation. Returns 1 if this call banned it,
 * in which case the caller should drop the connection. */
/* Permissions granted by the listener this connection arrived on (-whitebind).
 * Set in the forked child before it serves, so it is per-connection without
 * any shared table: the node forks per inbound connection, exactly as the
 * onion path already establishes "this is an onion peer" from which socket
 * accepted it. Zero in the parent and on every non-whitebind connection. */
unsigned g_conn_perms = 0;

int peer_misbehaving(const char* ip, int points, const char* reason){
    if(!ip || !*ip || points <= 0) return 0;
    /* Core: a peer with NetPermissionFlags::NoBan is never disconnected or
     * discouraged for misbehaviour. Checked BEFORE scoring, not just before
     * banning -- a score that can never reach the threshold is bookkeeping
     * that would evict a real offender from the table. */
    unsigned perms = netperm_for(ip) | g_conn_perms;
    if(perms & NP_NOBAN){
        fprintf(stderr,"[ban] %s misbehaving +%d: %s -- NOT scored (%s noban)\n",
                ip, points, reason ? reason : "?",
                (g_conn_perms & NP_NOBAN) ? "whitebind" : "whitelist");
        return 0;
    }
    /* Score into the SHARED table when we have one, so a peer that misbehaves
     * once per connection across many forked serve children still adds up.
     * The process-local array is the fallback for binaries with no shared
     * region (see its comment). */
    node_status_t* st = g_node_status;
    if (st) mis_lock_acquire(st);
    int slot = -1, free_slot = -1;
    for(int i = 0; i < MISBEHAVIOR_SLOTS; i++){
        const char* sip = st ? (const char*)st->misbehavior[i].ip : g_misbehavior[i].ip;
        if(sip[0] && !strcmp(sip, ip)){ slot = i; break; }
        if(!sip[0] && free_slot < 0) free_slot = i;
    }
    if(slot < 0){
        /* table full: forget the lowest scorer rather than ignore this one */
        if(free_slot < 0){
            int lo = 0;
            for(int i = 1; i < MISBEHAVIOR_SLOTS; i++){
                int a = st ? st->misbehavior[i].score  : g_misbehavior[i].score;
                int b = st ? st->misbehavior[lo].score : g_misbehavior[lo].score;
                if(a < b) lo = i;
            }
            free_slot = lo;
        }
        slot = free_slot;
        if (st){
            snprintf((char*)st->misbehavior[slot].ip, sizeof st->misbehavior[slot].ip, "%s", ip);
            st->misbehavior[slot].score = 0;
        } else {
            snprintf(g_misbehavior[slot].ip, sizeof g_misbehavior[slot].ip, "%s", ip);
            g_misbehavior[slot].score = 0;
        }
    }
    int total;
    if (st){ st->misbehavior[slot].score += points; total = st->misbehavior[slot].score; }
    else   { g_misbehavior[slot].score  += points; total = g_misbehavior[slot].score;  }
    if(total < MISBEHAVIOR_BAN_THRESHOLD){
        if (st) mis_lock_release(st);
        fprintf(stderr,"[ban] %s misbehaving +%d (%d/%d): %s\n",
                ip, points, total, MISBEHAVIOR_BAN_THRESHOLD, reason ? reason : "?");
        return 0;
    }
    long long until = (long long)time(NULL) + (g_cfg.bantime > 0 ? g_cfg.bantime : 86400);
    char subnet[80]; snprintf(subnet, sizeof subnet, "%s/32", ip);
    if (st){ st->misbehavior[slot].score = 0; mis_lock_release(st); }  /* banned; start clean */
    else     g_misbehavior[slot].score = 0;
    ctl_ban_add(subnet, until);
    fprintf(stderr,"[ban] %s reached %d points (%s) -- banned for %lds\n",
            ip, total, reason ? reason : "?", g_cfg.bantime > 0 ? g_cfg.bantime : 86400);
    return 1;
}

/* strip ":port" so a ban on the address matches a leg recorded as ip:port */
static void ctl_ip_only(const char* hostport, char* out, size_t cap){
    snprintf(out, cap, "%s", hostport ? hostport : "");
    char* c = strrchr(out, ':');
    if(c) *c = 0;
}

/* ---- graceful shutdown --------------------------------------------------
 * Previously SIGTERM/SIGINT had no handler at all (only SIGPIPE/SIGCHLD,
 * both ignored) -- every stop was a bare kill with zero shutdown log line,
 * ever, regardless of how the process actually died. The handler itself
 * only sets a flag (async-signal-safe, matches this file's own existing
 * mux_budget_alarm/SIGALRM pattern) -- the actual logging/cleanup happens
 * in each main loop's own next iteration, never inside the handler. */
static volatile sig_atomic_t g_shutdown_requested = 0;
/* Live inbound serve children. SIGCHLD was SIG_IGN (kernel auto-reap), which
 * is tidy but gives no way to know when a child exits -- so we reap manually
 * and keep the count. If this ever drifts it drifts LOW (the download worker
 * exiting also fires SIGCHLD), which fails open by allowing an extra
 * connection rather than locking inbound out entirely. */
/* Block-relay-only legs (Core: MAX_BLOCK_RELAY_ONLY_CONNECTIONS). relay=0,
 * and deliberately never fed into addr gossip, so an attacker enumerating the
 * network cannot discover or crowd them out. These carry headers/blocks only
 * and exist so an eclipse of the ordinary legs still leaves us a true view of
 * the best chain -- which matters now that Stage B acts on peer chainwork. */
static int  bro_fd[MAX_BLOCK_RELAY_ONLY];
static char bro_host[MAX_BLOCK_RELAY_ONLY][64];

/* Serve children we are metering for -maxuploadtarget. The parent samples
 * each child's /proc/<pid>/io rather than counting inside the asm serve loop
 * -- same technique dl_catchup uses on download workers, and it measures what
 * the kernel actually sent. */
#define UPL_MAX_TRACK 256
static int       upl_pid[UPL_MAX_TRACK];
static long long upl_last[UPL_MAX_TRACK];
static int       upl_n = 0;

static void upl_track(int pid){
    if(upl_n >= UPL_MAX_TRACK) return;
    upl_pid[upl_n]=pid; upl_last[upl_n]=0; upl_n++;
}
/* Sample every tracked child, add the delta, and drop the dead ones. */
static void upl_sample(void){
    long added=0;
    for(int i=0;i<upl_n;i++){
        long long w = upload_proc_wchar(upl_pid[i]);
        if(w < 0){ upl_pid[i]=upl_pid[upl_n-1]; upl_last[i]=upl_last[upl_n-1]; upl_n--; i--; continue; }
        if(w > upl_last[i]){ added += (long)(w - upl_last[i]); upl_last[i]=w; }
    }
    if(added>0) upload_note_and_check(added);
}

/* ==== gettxout IPC: the RPC asks the download worker =======================
 * The RPC server runs in the SERVE PARENT, which holds no handle on the live
 * UTXO set -- the download worker owns it in another process. gettxout used
 * to answer null there, which does not mean "I cannot say", it means "that
 * output is spent": the node was asserting that about every coin in
 * existence.
 *
 * Building a read-only view in the parent was measured and rejected:
 * utxo_lsm_reload_ro costs 60-83 s on the real 165M-entry set and every new
 * block invalidates it (FEATURE_GAPS.md). So the parent ASKS the worker,
 * which already has the set open and answers utxo_lsm_get in microseconds.
 *
 * WHY A POLLED SERVICE POINT AND NOT A THREAD IN THE WORKER: utxo_lsm_get is
 * thread-safe on its own (lsm_get_scratch is TLS), but this module's
 * architecture guarantees get() and flush() never overlap "by construction" --
 * a query thread racing the worker's own writes would break exactly that
 * guarantee. So the worker answers only at a quiescent point in its loop,
 * after the catch-up call, where no put/del/flush is in flight.
 *
 * Failure is always a REFUSAL, never a guess: no worker, a timeout, a short
 * read, a dead socket -- every one of them returns -1 and gettxout says it
 * cannot answer. The one thing this must never do is fall back to null. */
#define TXOQ_MAGIC   0x51584f54u          /* "TOXQ" */
#define TXOQ_SPK_CAP 16384u
#define TXOQ_TIMEOUT_MS 2000              /* a tip-height block apply is ~0.1s */
typedef struct { unsigned int magic, vout; unsigned char txid[32]; } txoq_req;
/* The response ECHOES the outpoint it answers. Without that, a query that
 * timed out would leave its response sitting in the socket and the NEXT query
 * would read it -- a perfectly well-formed reply about the WRONG coin. Magic
 * alone cannot catch that. With the echo, a stale reply is recognised, drained
 * and skipped. */
typedef struct { unsigned int magic; int found; unsigned long long value;
                 unsigned long height; unsigned int is_coinbase, spklen;
                 unsigned char txid[32]; unsigned int vout; } txoq_resp;
static int g_txoq_parent = -1;            /* parent end (RPC side) */
static int g_txoq_worker = -1;            /* worker end */
static pthread_mutex_t g_txoq_lock = PTHREAD_MUTEX_INITIALIZER;

/* read exactly n bytes unless the deadline passes; 1 ok, 0 timeout/short */
static int txoq_read_all(int fd, void* buf, size_t n, int timeout_ms){
    unsigned char* p = (unsigned char*)buf; size_t got = 0;
    while(got < n){
        struct pollfd pf = { fd, POLLIN, 0 };
        int pr = poll(&pf, 1, timeout_ms);
        if(pr <= 0) return 0;                          /* timeout or error */
        ssize_t r = read(fd, p + got, n - got);
        if(r <= 0){ if(r < 0 && errno == EINTR) continue; return 0; }
        got += (size_t)r;
    }
    return 1;
}

/* The RPC-side query. Returns 1 found / 0 absent / -1 cannot answer.
 * Serialised: there is one channel and the RPC server is threaded. */
static long txoq_query(const unsigned char txid_wire[32], unsigned int vout,
                       unsigned long long* value, unsigned long* height,
                       unsigned long* is_coinbase,
                       unsigned char* spk, unsigned long spk_cap, unsigned long* spk_len){
    if(g_txoq_parent < 0) return -1;
    long rc = -1;
    pthread_mutex_lock(&g_txoq_lock);
    txoq_req q; q.magic = TXOQ_MAGIC; q.vout = vout; memcpy(q.txid, txid_wire, 32);
    if(send(g_txoq_parent, &q, sizeof q, MSG_NOSIGNAL) != (ssize_t)sizeof q) goto out;
    txoq_resp rp;
    unsigned char body[TXOQ_SPK_CAP];
    /* Skip any replies left over from an earlier timed-out query. Bounded so a
     * pathologically backed-up channel cannot spin here. */
    for(int skip = 0; ; skip++){
        if(skip > 8) goto out;                         /* still desynced: refuse */
        if(!txoq_read_all(g_txoq_parent, &rp, sizeof rp, TXOQ_TIMEOUT_MS)) goto out;
        if(rp.magic != TXOQ_MAGIC) goto out;           /* framing lost: refuse, never guess */
        if(rp.spklen > TXOQ_SPK_CAP) goto out;
        if(rp.spklen && !txoq_read_all(g_txoq_parent, body, rp.spklen, TXOQ_TIMEOUT_MS)) goto out;
        if(rp.vout == vout && memcmp(rp.txid, txid_wire, 32) == 0) break;   /* ours */
        /* else: a stale reply about a different outpoint -- drained, try again */
    }
    if(rp.spklen > spk_cap) goto out;                  /* cannot deliver: refuse */
    if(rp.found != 1){ rc = 0; goto out; }             /* genuinely not unspent */
    if(rp.spklen) memcpy(spk, body, rp.spklen);
    *value = rp.value; *height = rp.height;
    *is_coinbase = rp.is_coinbase; *spk_len = rp.spklen;
    rc = 1;
out:
    pthread_mutex_unlock(&g_txoq_lock);
    return rc;
}

/* Worker side: answer every pending query, then return. Called ONLY from the
 * quiescent point in the worker loop. Never blocks -- a parent that went away
 * or a partial request just ends the round. */
extern long utxo_live_lsm_get(const unsigned char txid_wire[32], unsigned int vout,
                              unsigned long long* value, unsigned long* height,
                              unsigned long* is_coinbase,
                              const unsigned char** script, unsigned long* slen);
static void txoq_service(void){
    if(g_txoq_worker < 0) return;
    for(int guard = 0; guard < 64; guard++){
        struct pollfd pf = { g_txoq_worker, POLLIN, 0 };
        if(poll(&pf, 1, 0) <= 0) return;               /* nothing pending */
        txoq_req q;
        if(!txoq_read_all(g_txoq_worker, &q, sizeof q, 50)) return;
        if(q.magic != TXOQ_MAGIC) return;              /* desynced: stop, do not guess */
        txoq_resp rp; memset(&rp, 0, sizeof rp);
        rp.magic = TXOQ_MAGIC; rp.found = 0;
        memcpy(rp.txid, q.txid, 32); rp.vout = q.vout;   /* echo: see txoq_resp */
        const unsigned char* script = NULL; unsigned long slen = 0;
        unsigned long long value = 0; unsigned long h = 0, cb = 0;
        if(utxo_live_lsm_get(q.txid, q.vout, &value, &h, &cb, &script, &slen) == 1
           && slen <= TXOQ_SPK_CAP){
            rp.found = 1; rp.value = value; rp.height = h;
            rp.is_coinbase = (unsigned int)cb; rp.spklen = (unsigned int)slen;
        }
        if(send(g_txoq_worker, &rp, sizeof rp, MSG_NOSIGNAL) != (ssize_t)sizeof rp) return;
        if(rp.spklen && send(g_txoq_worker, script, rp.spklen, MSG_NOSIGNAL) != (ssize_t)rp.spklen) return;
    }
}

static volatile sig_atomic_t g_inbound_n = 0;
static pid_t g_dl_worker_pid = -1;       /* set by main() right after fork(); parent forwards SIGTERM here */
static volatile sig_atomic_t g_dl_worker_exited = 0, g_dl_worker_status = 0;
static void reap_children(int sig){
    (void)sig; int st; pid_t p;
    while((p = waitpid(-1,&st,WNOHANG)) > 0){
        /* The download worker is a child too. Before 2026-08-22 its death was
         * silently reaped here and the serve parent lived on with no worker
         * (block 481827: worker segfaulted, unit stayed "active" for 13 min).
         * Remember it; serve_mux exits non-zero so systemd restarts the unit. */
        if (g_dl_worker_pid > 0 && p == g_dl_worker_pid){ g_dl_worker_exited = 1; g_dl_worker_status = st; }
        else if(g_inbound_n > 0) g_inbound_n--;
    }
}
/* Set only while the worker is inside utxo_live_init()'s UTXO reload. That
 * reload is a tight assembly loop (utxo_lsm_reload -> the WAL-tail replay)
 * which never consults a shutdown flag, and on a large tail it runs for
 * minutes -- long enough that systemd sits in final-sigterm until
 * TimeoutStopSec (15 min here) and then SIGKILLs. Observed 2026-08-23.
 *
 * Exiting straight from the handler is safe in this window specifically:
 * the reload replays the WAL into MEMORY and commits nothing. The only file
 * it opens for write is utxo.idx, which is a rebuildable index. Every
 * durable object -- the WAL itself, the manifest, the runs,
 * utxo_applied_height.dat -- is untouched until the first block is applied,
 * which cannot happen until the reload returns. So an immediate _exit here
 * leaves exactly the on-disk state the previous clean shutdown left, and is
 * strictly better than being SIGKILLed at the same point 15 minutes later. */
static volatile sig_atomic_t g_in_utxo_reload = 0;
static void handle_shutdown_signal(int sig){
    g_shutdown_requested = sig;
    if (g_in_utxo_reload) _exit(0);
}

/* Connect + handshake one outbound seed, returning a long-lived fd (or -1).
 * The handshake reads the seed's version/verack plus its post-verack chatter
 * (sendheaders/sendaddrv2/feefilter/addr), which can take longer than the
 * tight per-pass recv bound -- so give the handshake a generous 6s timeout,
 * then clamp the socket to the short per-pass timeout for node_sync. */
/* Shared wall-clock-budget signal state. Defined here (rather than just above
 * do_outbound_sync_bounded, where it used to live) because outbound_connect
 * below now arms the same budget around its dial, and needs it in scope. */
static volatile sig_atomic_t mux_sync_budget_fired = 0;
/* The socket the budgeted pass is reading. The handler SHUTS IT DOWN.
 *
 * Setting a flag was not enough, and this is a live-node bug found on
 * 2026-08-31: a far-behind signet worker sat in ONE leg's node_sync for 47
 * minutes, downloading at 500 KB/s, while UTXO catch-up, the heartbeat and
 * every other leg starved. mux_sync_budget_fired was 1 in the live process --
 * the alarm HAD fired, once, at 60s. Its only effect was EINTR on the blocked
 * read, which fd_read_full reports as -1, and node_sync_multi (since incident
 * #33) RETRIES on -1 because -1 also means a 3s SO_RCVTIMEO tick from a peer
 * with sparse chatter. alarm() is one-shot, so after that single swallowed
 * EINTR nothing ever interrupts the pass again. Two fixes that were each
 * right alone and incompatible together.
 *
 * shutdown(2) is async-signal-safe and makes the pending read return 0 --
 * EOF -- which every layer already treats as "connection genuinely done"
 * (fd_read_full short-returns, p2p_read reports .eof_or_err, node_sync_multi
 * returns). The caller then sees the flag and re-dials the leg, which it
 * already did on budget expiry; the peer loses nothing but a half-read frame
 * we were going to discard anyway. */
static volatile int mux_budget_fd = -1;
static void mux_budget_alarm(int sig){
    (void)sig;
    mux_sync_budget_fired = 1;
    int fd = mux_budget_fd;
    if (fd >= 0) shutdown(fd, SHUT_RDWR);
}

/* Wall-clock budget for ONE dial (blocking connect + handshake). SO_RCVTIMEO
 * alone is NOT sufficient here and this is a real production hang, not a
 * hypothetical: it bounds each INDIVIDUAL read(), so a peer that trickles the
 * version/verack bytes a few at a time resets the timer on every partial read
 * and node_handshake never returns -- the download worker's whole rotation
 * loop then sits in that one read() forever (no heartbeat, no other leg
 * serviced, SIGTERM not even checked). Observed twice on 2026-08-18: the
 * worker wedged in tcp_recvmsg for 60+ minutes right after a leg-fill round,
 * and had to be SIGKILLed. tcp_connect_ip's connect() has no connect-phase
 * timeout either, which this same budget also covers.
 *
 * The rest of this file already solves exactly this problem the same way --
 * see do_outbound_sync_bounded and the dlc chunk worker, whose comment spells
 * out the trickle-resets-SO_RCVTIMEO mechanism. outbound_connect was simply
 * never given the same treatment, even though every one of its callers (the
 * steady-state leg fill and mux_next_peer) runs OUTSIDE any enclosing alarm. */
#define OUTBOUND_DIAL_BUDGET_SECS 20

/* ---- why the last dial failed -------------------------------------------
 * tcp_connect_ip (bitcoin_net.asm) deliberately returns the raw -errno "for
 * diagnosis", and outbound_connect used to throw it away with `return -1`, so
 * every caller could say no more than "unreachable". On 2026-08-27 a host
 * freeze took all 8 legs down and then EVERY redial failed for 8 minutes
 * straight; the log could not distinguish a dead network (ENETUNREACH) from
 * fd exhaustion (EMFILE) from a peer refusing us (ECONNREFUSED) -- the
 * difference between "the box is sick" and "the node is leaking descriptors".
 * The information already existed, it was just discarded. Set on every
 * failure path here, read by dial_fail_reason() at the call sites. */
static char g_dial_fail[96] = "";
static const char* dial_fail_reason(void){
    return g_dial_fail[0] ? g_dial_fail : "unknown";
}
/* -rc is the raw -errno from tcp_connect_ip; render it, falling back to the
 * number when it is not a value strerror knows. */
static void dial_fail_errno(const char* what, int rc){
    int e = -rc;
    const char* m = (e > 0 && e < 200) ? strerror(e) : NULL;
    if(m) snprintf(g_dial_fail, sizeof g_dial_fail, "%s: %s", what, m);
    else  snprintf(g_dial_fail, sizeof g_dial_fail, "%s: rc=%d", what, rc);
}

/* Does this peer advertise NODE_P2P_V2?
 *
 * Core only dials v2 when it does -- net.cpp:
 * `addrConnect.nServices & GetLocalServices() & NODE_P2P_V2` -- and that is
 * not merely an optimisation. An initiator cannot fall back in place (it has
 * already sent 64 random bytes a v1 peer rejects as a bad magic), so a blind
 * attempt costs an extra TCP connection against EVERY v1-only peer. Worse,
 * plenty of peers accept exactly one connection and simply are not there for
 * the redial -- which is precisely how tests/test_outbound_mux caught this.
 *
 * The address book already carries each peer's service bits, so the question
 * is answerable before we dial. An unknown peer answers "no" and gets a
 * single v1 connection, exactly as before this feature existed. */
static int peer_advertises_v2(const char* host, int out_port){
    if(!CFG_V2TRANSPORT()) return 0;
    bmc_addr_t a;
    if(!bmc_addr_from_string_port(&a, host, (unsigned short)out_port)) return 0;
    ab2_t* b = ab2_open(".", 0);
    if(!b) return 0;
    long i = ab2_find(b, &a);
    int yes = 0;
    if(i >= 0){
        ab2_rec_t r;
        if(ab2_get(b, i, &r)) yes = (r.services & BMC_NODE_P2P_V2) != 0;
    }
    ab2_close(b);
    return yes;
}

static int outbound_connect(const char* host, int rcv_ms, int out_port){
    g_dial_fail[0] = 0;
    /* ---- any BIP155 network (2026-08-28) ----------------------------------
     * A host that parses as a Tor/I2P/CJDNS/IPv6 address goes to its
     * transport (daemon/dialer.c); anything else is the IPv4 path below,
     * unchanged, including DNS names (seeds, addnode=, connect=), which only
     * the resolver can turn into an address. */
    { bmc_addr_t da;
      /* accepts "1.2.3.4", "1.2.3.4:8333", "[fc00::1]:8333", "<56>.onion:8333"
       * and the bare forms; a DNS name falls through to the resolver below */
      if (bmc_addr_from_string_port(&da, host, (unsigned short)out_port)){
          { int cp = node_config_peer_port(host); if(cp) da.port = (unsigned short)cp; }
          if (da.net != BMC_NET_IPV4){
              const char* why = "";
              if (!dialer_net_reachable(da.net)){
                  snprintf(g_dial_fail, sizeof g_dial_fail, "%s unreachable: no transport configured", bmc_net_name(da.net));
                  return -1;
              }
              int dfd = dialer_connect(&da, g_cfg.connect_timeout_ms > 0 ? g_cfg.connect_timeout_ms : 15000, &why);
              if (dfd < 0){ snprintf(g_dial_fail, sizeof g_dial_fail, "%s dial: %.60s", bmc_net_name(da.net), why); return -1; }
              struct timeval tv; tv.tv_sec = 30; tv.tv_usec = 0;   /* onion/i2p round trips are slow */
              setsockopt(dfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
              if (node_handshake(dfd) != 1 || !peer_has_witness(host)){
                  snprintf(g_dial_fail, sizeof g_dial_fail, "%s handshake failed", bmc_net_name(da.net));
                  close(dfd); return -1;
              }
              { extern void addrself_note_peer_view(const unsigned char*, long);
                addrself_note_peer_view(g_peer_version_payload, g_peer_version_len); }
              struct timeval t2; t2.tv_sec = rcv_ms/1000; t2.tv_usec = (rcv_ms%1000)*1000;
              setsockopt(dfd, SOL_SOCKET, SO_RCVTIMEO, &t2, sizeof t2);
              fprintf(stderr, "[dial] %s connected via %s transport\n", host, bmc_net_name(da.net));
              return dfd;
          }
      } }
    /* a named peer configured as "host:port" is dialled on ITS port, not the
     * chain default (node_config.c keeps the host bare and the port beside
     * it). 0 = nothing configured for this host. */
    { int cp = node_config_peer_port(host); if(cp) out_port = cp; }
    /* A literal IPv4 (with or without ":port") needs no resolver at all, so
     * the DNS gate below must not refuse it. Parse it HERE but DIAL IT IN THE
     * BUDGETED PATH below: the first cut of this fix (2026-08-29) dialled it
     * right here, which stepped outside the SIGALRM dial budget -- a
     * trickling peer held the dial 46s against a 20s budget -- and flattened
     * the connect errno to a bare "connect failed". test_dial_budget caught
     * both; a shortcut around a bound is not a shortcut. */
    unsigned lit_ip = 0; int have_lit = 0;
    { bmc_addr_t lit;
      if(bmc_addr_from_string_port(&lit, host, (unsigned short)out_port) && lit.net == BMC_NET_IPV4){
          if(lit.port) out_port = lit.port;
          memcpy(&lit_ip, lit.addr, 4);       /* network order, like sin_addr.s_addr */
          have_lit = 1;
      } }
    /* By here the address was not a literal of any network, so it is a name
     * -- and an anonymity-network name must reach its transport, never DNS. */
    if(strstr(host,".onion") || strstr(host,".i2p")){
        snprintf(g_dial_fail,sizeof g_dial_fail,"%s peer needs its transport configured",
                 strstr(host,".onion") ? "onion" : "i2p");
        return -1;
    }
    /* With a proxy configured, hand the NAME to the proxy (SOCKS5 ATYP
     * DOMAINNAME) instead of resolving it here: a local lookup would tell
     * the resolver exactly which peers this node is about to contact, which
     * is precisely the correlation a proxy exists to prevent. Core does the
     * same with its name_proxy. */
    /* Only a NAME needs this: an IPv4 literal was already handled above and
     * needs no resolver, so blocking DNS must not block it. And dns=0 with
     * NO proxy has nowhere to send a name -- refuse it with that reason
     * rather than a confusing proxy error. (2026-08-29 pre-deploy review.) */
    if(!have_lit && dialer_dns_blocked()){
        const char* why = "";
        int nfd = dialer_connect_name(host, out_port, g_cfg.connect_timeout_ms > 0 ? g_cfg.connect_timeout_ms : 15000, &why);
        if(nfd < 0){ snprintf(g_dial_fail,sizeof g_dial_fail,"cannot dial the name \"%.40s\": %.50s", host, why); return -1; }
        struct timeval tv; tv.tv_sec=30; tv.tv_usec=0; setsockopt(nfd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
        if(node_handshake(nfd)!=1 || !peer_has_witness(host)){ close(nfd); snprintf(g_dial_fail,sizeof g_dial_fail,"handshake failed (via proxy)"); return -1; }
        { extern void addrself_note_peer_view(const unsigned char*, long);
          addrself_note_peer_view(g_peer_version_payload, g_peer_version_len); }
        struct timeval t2; t2.tv_sec=rcv_ms/1000; t2.tv_usec=(rcv_ms%1000)*1000;
        setsockopt(nfd,SOL_SOCKET,SO_RCVTIMEO,&t2,sizeof t2);
        return nfd;
    }
    unsigned ip;
    if(have_lit) ip = lit_ip;                 /* already parsed; the resolver never sees it */
    else {
        struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
        if(getaddrinfo(host,NULL,&h,&res)!=0){
            snprintf(g_dial_fail,sizeof g_dial_fail,"getaddrinfo failed");
            return -1;
        }
        ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(res);
    }

    /* Arm the dial budget around BOTH the blocking connect and the handshake.
     * SA_RESTART is deliberately left clear (memset) so the signal makes the
     * in-flight syscall fail with EINTR instead of silently resuming. */
    struct sigaction sa, old; memset(&sa,0,sizeof sa);
    sa.sa_handler=mux_budget_alarm; sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM,&sa,&old);
    sig_atomic_t saved_fired = mux_sync_budget_fired;   /* don't clobber an outer pass's flag */
    mux_sync_budget_fired = 0;
    alarm(OUTBOUND_DIAL_BUDGET_SECS);

    /* Through the proxy when one is configured -- a raw connect here would go
     * direct and defeat it. Inside the alarm either way, so the budget bounds
     * the proxied dial too. */
    const char* pwhy = "";
    int proxied = dialer_proxy_configured();
    int fd = -1;
    int hk = 0;
    const char* v2res = "v1";
    /* Only peers that advertise NODE_P2P_V2 get a v2 dial; everyone else is
     * one plain v1 connection, as before. See peer_advertises_v2 above. */
    const int want_v2 = peer_advertises_v2(host, out_port);
    for(int attempt = 0; attempt < 2; attempt++){
        if(proxied){
            bmc_addr_t pa; memset(&pa,0,sizeof pa);
            pa.net = BMC_NET_IPV4; pa.len = 4; memcpy(pa.addr, &ip, 4);
            pa.port = (unsigned short)out_port;
            fd = dialer_connect(&pa, g_cfg.connect_timeout_ms > 0 ? g_cfg.connect_timeout_ms : 15000, &pwhy);
        } else fd = tcp_connect_ip(ip,(unsigned short)htons((unsigned short)out_port));
        if(fd < 0) break;
        { struct timeval tv; tv.tv_sec=6; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv); }
        if(attempt == 0 && want_v2){
            int v2 = bmc_v2_handshake(fd, 1, 5000);
            if(v2 == 1){ v2res = "v2"; break; }
            /* It advertised v2 and did not deliver -- a stale book entry, or
             * a peer that changed its mind. Redial and speak v1. */
            fprintf(stderr,"[dial] %s advertised v2 but the handshake failed -- retrying as v1\n", host);
            close(fd); fd = -1;
            continue;
        }
        break;
    }
    if(fd>=0) hk = node_handshake(fd);

    alarm(0);
    int fired = mux_sync_budget_fired;
    mux_sync_budget_fired = saved_fired;
    sigaction(SIGALRM,&old,NULL);

    if(fd<0){
        if(proxied) snprintf(g_dial_fail,sizeof g_dial_fail,"ipv4 dial via proxy: %.60s", pwhy);
        else dial_fail_errno("connect", fd);
        return -1;
    }
    peer_sock_buffers(fd);
    if(fired || hk!=1 || !peer_has_witness(host)){
        if(fired){
            snprintf(g_dial_fail,sizeof g_dial_fail,"dial budget %ds exceeded",
                     OUTBOUND_DIAL_BUDGET_SECS);
            fprintf(stderr,"[dial] %s exceeded %ds dial budget; dropping\n",
                    host, OUTBOUND_DIAL_BUDGET_SECS);
        } else if(hk!=1){
            snprintf(g_dial_fail,sizeof g_dial_fail,"handshake failed (rc=%d)", hk);
        } else {
            snprintf(g_dial_fail,sizeof g_dial_fail,"peer lacks NODE_WITNESS");
        }
        bmc_v2_close(fd); close(fd);
        return -1;
    }
    fprintf(stderr,"[dial] %s connected over %s\n", host, v2res);
    /* Record what this peer ACTUALLY offers.
     *
     * Until now every address this node added itself was stored with a
     * hardcoded services=1 (NODE_NETWORK), and only gossiped addresses
     * carried real bits. That made outbound v2 inert in practice: the peers
     * we dial are the ones we have connected to before, so they all read as
     * services=1, peer_advertises_v2 said no every time, and the node
     * happily reported "8341 of 14825 known peers advertise v2" while
     * dialling v1 to every single one of them.
     *
     * The version message has just told us the truth, so store it. From the
     * next dial onwards the v2 gate has something real to read. */
    { unsigned long long svc = 0;
      if (g_peer_version_len >= 12) memcpy(&svc, g_peer_version_payload + 4, 8);
      if (svc && !g_in_dial_helper){       /* a helper child never writes the book */
          bmc_addr_t pa;
          if (bmc_addr_from_string_port(&pa, host, (unsigned short)out_port)){
              ab2_t* b = addr_book();
              if (b) ab2_add(b, &pa, svc, (unsigned)time(NULL));
          }
      } }
    /* the peer's version told us how it sees US -- feed the self-address
     * tally (daemon/addr_self.c) */
    { extern void addrself_note_peer_view(const unsigned char*, long);
      addrself_note_peer_view(g_peer_version_payload, g_peer_version_len); }
    /* handshake done: tighten the recv bound so each node_sync pass returns
     * promptly when the peer is already at the chain tip */
    struct timeval t2; t2.tv_sec=rcv_ms/1000; t2.tv_usec=(rcv_ms%1000)*1000;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t2,sizeof t2);
    return fd;
}

/* ---- refuse to run one chain's node against another chain's archive ------
 * Until 2026-08-29 the ONLY thing separating chains was directory layout:
 * mainnet uses the datadir itself, every other chain a subdirectory of it
 * (chainparams_datadir). Nothing verified that an archive already on disk
 * belonged to the chain being started.
 *
 * That is thinner than it looks. Every frame is written [len][magic] with the
 * chain's network magic, but nothing ever compares that magic on the way back
 * in -- it is written and never read. So pointing -datadir at another chain's
 * directory (say <base>/regtest while running mainnet) appended mainnet
 * blocks to a regtest archive without a word of complaint, and -datadir,
 * added the same day, makes that easier to do by accident.
 *
 * Block 0's hash is the cheapest possible check and it is unambiguous: it is
 * already sitting in index.dat record 0, so this costs one 32-byte read and
 * no parsing. An EMPTY archive is fine -- that is a fresh datadir, which is
 * exactly how a new chain legitimately starts.
 *
 * Refusing to start is the right failure. Continuing would interleave two
 * chains' blocks in one file, which no later check could untangle. */
static int chain_archive_matches(void* store_buf){
    int  fd  = *(int*)((char*)store_buf + 8);    /* idx_fd  */
    long len = *(long*)((char*)store_buf + 16);  /* idx_len */
    if (fd < 0 || len < 48) return 1;            /* empty archive: nothing to contradict */
    unsigned char have[32];
    if (lseek(fd, 0, SEEK_SET) < 0 || read(fd, have, 32) != 32){
        fprintf(stderr, "[boot] cannot read block 0 from index.dat -- refusing to start "
                        "rather than guess which chain this archive belongs to\n");
        return 0;
    }
    const unsigned char* want = g_chainp->genesis_hash;
    if (!want) return 1;
    if (!memcmp(have, want, 32)) return 1;
    char hh[65], wh[65];
    for (int i = 0; i < 32; i++){                /* display order */
        snprintf(hh + i*2, 3, "%02x", have[31-i]);
        snprintf(wh + i*2, 3, "%02x", want[31-i]);
    }
    fprintf(stderr,
        "[boot] WRONG CHAIN FOR THIS DATADIR -- refusing to start.\n"
        "[boot]   chain=%s expects genesis %s\n"
        "[boot]   this archive's block 0 is  %s\n"
        "[boot] Running on would append %s blocks to another chain's archive, which\n"
        "[boot] nothing could untangle afterwards. Point -datadir at the right\n"
        "[boot] directory, or use an empty one.\n",
        g_chainp->name, wh, hh, g_chainp->name);
    return 0;
}

/* Anchor a peer's locator to our CURRENT stored tip hash (zero if empty). */
static void anchor_locator(unsigned char loc[32]){
    /* Anchor the locator to the stored tip's HASH read straight from the index
     * record (idx_len-48 .. idx_len-16), NOT via node_serve_block. A live
     * sustained-ingest finding: node_serve_block on a just-appended tip can
     * transiently return <80 (bd: block body not yet at a readable position),
     * which used to make this helper collapse loc to all-zero (genesis) --
     * the next node_sync then re-downloaded from genesis and store_append
     * appended a duplicate, non-contiguous tail. Reading the tip hash directly
     * from index.dat is always available and cannot misfire. */
    int fd = *(int*)(store_buf+8);          /* idx_fd */
    long len = *(long*)(store_buf+16);      /* idx_len */
    if(fd>=0 && len>=48){
        if(lseek(fd, len-48, SEEK_SET)>=0 && read(fd, loc, 32)==32) return;
    }
    memset(loc,0,32);
}

/* mux_locator/mux_locator_zero (the old per-peer single-hash locator
 * accessors) are gone: do_outbound_sync now derives a real multi-hash
 * locator from the store on every pass -- see build_locator_for_sync. */

/* ---- STAGE B: the REAL block locator ------------------------------------
 * Builds the doubling-gap ancestor list (tip, tip-1, tip-2, tip-4, ...) via
 * daemon/locator_build.c, which reads each ancestor's hash straight out of
 * index.dat by position -- the same "read the index record, not the block
 * body" technique anchor_locator above already uses, and for the same
 * reason (a just-appended tip's body can transiently read short).
 *
 * WHY THIS REPLACES anchor_locator ON THE SYNC PATH: a one-hash locator only
 * ever says "I have exactly this block". A peer on a chain that diverged
 * below our tip recognises nothing in it and answers from its own genesis,
 * so a fork is literally undiscoverable -- which is why every sync pass
 * until now silently assumed the peer was on our chain. With the full list
 * the peer finds the newest block we actually share and answers from there,
 * which is what makes the fork point visible. A peer that IS on our chain is
 * unaffected: it matches the first entry (our tip) immediately, exactly as
 * before.
 *
 * Falls back to the old single-hash anchor if locator_build cannot read the
 * index (returns the hash count, always >= 1). */
static long build_locator_for_sync(unsigned char loc[REORG_LOCATOR_MAX*32]){
    long n = locator_build(store_buf, loc);
    if(n >= 1) return n;
    anchor_locator(loc);
    return 1;
}

/* One bounded download+announce pass on outbound peer i.
 *   - anchor locator at our stored tip (so we only pull the missing tail)
 *   - run node_sync (getheaders -> validate -> store_append) with the fd's
 *     short recv timeout so an idle peer returns fast
 *   - index any newly-stored blocks (node_sync appends but does not idx_put)
 *   - announce the new tip back to the peer via node_announce_tip
 *   - update the per-peer locator to our new tip
 * Returns # blocks stored this pass. */
/* hash32[32] is wire-order (as stored/compared internally); block explorers
 * and RPC display it byte-reversed -- print that convention here so a
 * logged hash can be pasted straight into a lookup. Short form (first 8
 * display bytes = last 8 wire bytes) is enough to eyeball/grep-correlate
 * without bloating every block-stored line to a full 64 hex chars. */
/* format_peer_version_info(out, cap) -> writes a compact human-readable
 * summary of whatever bitcoind.asm's node_handshake/node_accept_handshake
 * last captured into g_peer_version_payload (the OTHER side's `version`
 * message, raw wire bytes -- see that global's header comment). Parses the
 * Bitcoin version-message layout by hand (version u32, services u64,
 * timestamp u64, addr_recv[26], addr_from[26], nonce u64, then a
 * CompactSize-prefixed user-agent string, then start_height u32) since
 * nothing in this codebase already exposes these fields. Empty string if
 * no version was captured (payload too short to be a real version msg) --
 * callers should treat that as "no data," not an error. */
static void format_peer_version_info(char* out, size_t cap){
    out[0] = 0;
    long len = g_peer_version_len;
    const unsigned char* p = g_peer_version_payload;
    if (len < 80) return;               /* fixed prefix alone is 80 bytes */
    unsigned proto = (unsigned)p[0] | ((unsigned)p[1]<<8) | ((unsigned)p[2]<<16) | ((unsigned)p[3]<<24);
    unsigned long long services;
    memcpy(&services, p+4, 8);
    long off = 80;
    unsigned long long ualen;
    if (p[off] < 0xfd) { ualen = p[off]; off += 1; }
    else if (p[off] == 0xfd) { if (off+3 > len) return; ualen = (unsigned)p[off+1] | ((unsigned)p[off+2]<<8); off += 3; }
    else if (p[off] == 0xfe) { if (off+5 > len) return; memcpy(&ualen, p+off+1, 4); off += 5; }
    else { if (off+9 > len) return; memcpy(&ualen, p+off+1, 8); off += 9; }
    if (off + (long)ualen + 4 > len || ualen > 200) return; /* malformed/hostile -- bail, don't overread */
    char ua[201]; memcpy(ua, p+off, (size_t)ualen); ua[ualen] = 0;
    for (unsigned long long k=0;k<ualen;k++) if (ua[k] < 0x20 || ua[k] > 0x7e) ua[k] = '.'; /* printable only */
    off += (long)ualen;
    unsigned height;
    memcpy(&height, p+off, 4);
    snprintf(out, cap, "proto=%u services=0x%llx ua=\"%s\" height=%u", proto, services, ua, height);
}

/* Fill one shared outbound-peer slot from the last-captured version payload
 * (g_peer_version_payload, set by the just-completed handshake) + the host
 * string. Mirrors format_peer_version_info's parse but into structured fields.
 * Safe to call with g_node_status==NULL (no-op). */
static void rpc_fill_peer_slot(int slot, const char* host){
    if (!g_node_status || slot < 0 || slot >= RPC_MAX_PEERS) return;
    rpc_peer_t* pr = &g_node_status->peers[slot];
    memset(pr, 0, sizeof *pr);
    strncpy(pr->addr, host ? host : "", sizeof pr->addr - 1);
    pr->inbound = 0;
    pr->conn_time = (long long)time(NULL);
    long len = g_peer_version_len;
    const unsigned char* p = g_peer_version_payload;
    if (len >= 80){
        pr->proto = (unsigned)p[0] | ((unsigned)p[1]<<8) | ((unsigned)p[2]<<16) | ((unsigned)p[3]<<24);
        unsigned long long services; memcpy(&services, p+4, 8); pr->services = services;
        long off = 80; unsigned long long ualen = 0; int ok = 1;
        if (p[off] < 0xfd) { ualen = p[off]; off += 1; }
        else if (p[off]==0xfd){ if(off+3<=len){ ualen=(unsigned)p[off+1]|((unsigned)p[off+2]<<8); off+=3; } else ok=0; }
        else if (p[off]==0xfe){ if(off+5<=len){ memcpy(&ualen,p+off+1,4); off+=5; } else ok=0; }
        else { if(off+9<=len){ memcpy(&ualen,p+off+1,8); off+=9; } else ok=0; }
        if (ok && ualen <= 90 && off+(long)ualen+4 <= len){
            memcpy(pr->subver, p+off, (size_t)ualen); pr->subver[ualen] = 0;
            for (unsigned long long k=0;k<ualen;k++) if(pr->subver[k]<0x20||pr->subver[k]>0x7e) pr->subver[k]='.';
            off += (long)ualen;
            unsigned height; memcpy(&height, p+off, 4); pr->start_height = (int)height;
        }
    }
    pr->used = 1;   /* publish last: readers see a fully-formed slot */
}

static void log_hash_short(char out[17], const unsigned char hash32[32]){
    static const char hexd[]="0123456789abcdef";
    for(int k=0;k<8;k++){
        unsigned char b=hash32[31-k];
        out[k*2]=hexd[b>>4]; out[k*2+1]=hexd[b&0xf];
    }
    out[16]=0;
}

static long do_outbound_sync(int i){
    /* STAGE B: a REAL multi-hash locator built fresh from our stored chain on
     * every pass, replacing the single-hash anchor. mux_out_loc[i] is still
     * maintained below for the other call sites that read it, but the sync
     * itself no longer depends on it -- the locator is derived from the store,
     * which is the authoritative thing anyway. */
    unsigned char loc[REORG_LOCATOR_MAX*32];
    long nloc = build_locator_for_sync(loc);
    static unsigned char cbuf[6<<20]; long cnt=0;
    int st_tip_before=*(int*)(store_buf+24);
    phase_timer_t sync_pt; phase_start(&sync_pt);
    long ok=node_sync_multi(mux_out_fd[i], store_buf, loc, nloc, cbuf, (long)sizeof cbuf, &cnt);
    double sync_s = phase_elapsed(&sync_pt);
    int st_tip=*(int*)(store_buf+24);
    if(ok!=1 || cnt<=0){
        /* keep the locator fresh even on a no-op so we don't re-request from
         * genesis forever (node_sync advanced it internally only on success) */
        anchor_locator(mux_out_loc[i]);
        if(ok == 1){ g_sync_fail_streak[i] = 0; return 0; }   /* peer had nothing: normal at tip */
        /* Incident #33 made this path log, because its silence hid a total
         * keep-up failure for 14.5 hours. #33 is fixed; what is left here is
         * an OPERATIONAL log, and the first version of it was far too loud --
         * a line per leg per rotation, including the perfectly normal "peer
         * had nothing for us at the tip". Rules now:
         *
         *   ok == 1, cnt == 0   the peer had nothing. This is the NORMAL
         *                       state between blocks. Never logged.
         *   ok != 1             the exchange failed. Logged once when a leg
         *                       STARTS failing and once when it recovers --
         *                       not once per rotation.
         *
         * And a failing leg is now REPLACED rather than retried forever. The
         * common failure here is where=3, the headers-drain timeout, which
         * costs a full ~60 s of the rotation before it gives up; two of those
         * back to back on the same peer means the peer is not going to answer,
         * and every further rotation spends a minute proving it again. */
        /* Incident #33 made this path log, because its silence hid a total
         * keep-up failure for 14.5 hours. #33 is fixed, so what belongs here
         * now is a HEALTH SIGNAL, not a running commentary. Two earlier
         * versions were too loud: one printed a line per leg per rotation
         * (including the entirely normal "peer had nothing at the tip"), and
         * the next printed every leg replacement, which on a pool where many
         * peers do not answer getheaders is its own flood.
         *
         * So: nothing is logged from here at all. The per-leg failure count
         * is exported to the heartbeat, which prints one compact number for
         * the whole node -- an operator sees "sync_failing=2" and can turn on
         * detail if they care, instead of reading the same four lines every
         * rotation. A leg that fails repeatedly is still dropped so the
         * rotation stops burning ~60 s on a peer that will not answer (that
         * is where=3, the headers-drain timeout); the caller's existing
         * dead-slot path re-dials it, rate-limited. */
        g_sync_fail_streak[i]++;
        if(g_sync_fail_streak[i] >= 3){
            bmc_v2_close(mux_out_fd[i]), close(mux_out_fd[i]);
            mux_out_fd[i] = -1;
            g_sync_fail_streak[i] = 0;
        }
        return 0;
    }
    /* index every newly stored height (st_tip_before+1 .. st_tip) into ht_idx,
     * logging each disk-written block individually -- node_sync itself does
     * getheaders+download+validate+store as one opaque pass (no network-vs-
     * disk breakdown available without touching that ASM), so this loop's
     * own re-read of each freshly-stored block is the cheapest place to
     * report per-block write events for troubleshooting. */
    static unsigned char sb[8<<20];
    for(int h=st_tip_before+1; h<=st_tip; h++){
        long L=node_serve_block(store_buf, h, sb, sizeof sb);
        if(L<80) continue;
        unsigned char bhash[32]; block_hash(bhash, sb);
        idx_put(ht_idx, bhash, h);
        char hs[17]; log_hash_short(hs, bhash);
        u64 consumed=0; u64 ntx = L>80 ? utxo_walk_read_varint(sb+80, sb+L, &consumed) : 0;
        if(!consumed) ntx = 0;
        fprintf(stderr,"[block] stored height=%d hash=%s.. bytes=%ld tx=%llu (via %s)\n", h, hs, L, (unsigned long long)ntx, mux_out_host[i]);
    }
    /* STAGE B: keep chainwork.dat in lockstep with index.dat for every block
     * that just landed. This is a CATCH-UP call, not a per-block hook: it
     * appends one cumulative-work record for every height index.dat has and
     * chainwork.dat does not, so it covers blocks this leg just stored AND
     * blocks a sibling inbound serve child appended via .do_block, with one
     * call site instead of two edited assembly write paths. Without this,
     * fork choice has nothing to weigh our own chain with. */
    if(reorg_chainwork_sync(store_buf, 0) < 0)
        fprintf(stderr,"[chainwork] sync failed after storing heights %d..%d -- fork choice is DEGRADED until this recovers\n",
                st_tip_before+1, st_tip);
    /* announce the new tip to this peer (inv; BIP130 headers honored by the
     * peer's sendheaders negotiation is handled downstream on its own leg) */
    node_announce_tip(mux_out_fd[i], store_buf, ht_idx, 0);
    fprintf(stderr,"[mux:%d] broadcast tip height=%d to %s\n", i, st_tip, mux_out_host[i]);
    /* advance this peer's persistent locator to our new stored tip */
    anchor_locator(mux_out_loc[i]);
    fprintf(stderr,"[mux:%d] %-22s sync ok=%ld new=%ld tip=%d (%.2fs)\n", i, mux_out_host[i], ok, cnt, st_tip, sync_s);
    return cnt;
}

/* Re-dial one dead outbound leg: close the socket (if any) and attempt a fresh
 * connect+handshake to a DIFFERENT seed in the pool, rotating so keep-up is not
 * single-seed-limited. This is the peer-pool rotation / retry the soak analysis
 * flagged as missing (D2): the old mux connected N legs once up front and never
 * recovered a leg that died or failed to handshake, leaving keep-up silently
 * single-seed-limited. On success the slot is re-anchored at our stored tip and
 * reused in the poll loop; on failure the slot stays dead (fd -1) and is retried
 * on a later rotation. */ 
/* ---- async dial helper ----------------------------------------------------
 * An anonymity-network dial (Tor rendezvous, I2P tunnel, then the version
 * handshake) takes tens of seconds, and every dial path in this worker runs
 * INLINE in the rotation: three consecutive onion dials starved the
 * heartbeat for three minutes and tripped the deploy guard (2026-09-01).
 * So those dials happen in a forked child that runs the same
 * outbound_connect and hands the CONNECTED socket back over a socketpair
 * with SCM_RIGHTS, together with the handshake facts the leg needs (the
 * peer's version payload, its addrv2 preference). Onion and I2P legs are v1
 * transport, so no cipher state has to cross the process boundary. The
 * worker polls the channel without blocking every rotation and installs the
 * leg exactly as the inline fill would have. Core does the same job with a
 * thread; a child keeps this worker's single-threaded invariants. */
#define DH_MAX 2
typedef struct { int sp; pid_t pid; char host[128]; int net; long long t0; } dh_slot_t;
static dh_slot_t g_dh[DH_MAX];
static long long g_dh_timeout_ms = 120000;
/* g_in_dial_helper is declared with the leg tables above */
typedef struct { int ok; unsigned char wants_addrv2; long vlen; unsigned char vpayload[256]; char why[128]; } dh_result_t;
void dial_helper_test_set_timeout_ms(long long ms){ g_dh_timeout_ms = ms; }
static int leg_net_of(const char* hostport){
    bmc_addr_t a; return bmc_addr_from_string_port(&a, hostport, 0) ? (int)a.net : BMC_NET_IPV4;
}
static int leg_is_anon_net(int net){ return net == BMC_NET_TORV3 || net == BMC_NET_I2P; }
static int dh_inflight_net(int net){ for(int i = 0; i < DH_MAX; i++) if(g_dh[i].pid > 0 && g_dh[i].net == net) return 1; return 0; }
static int dh_inflight_count(void){ int n = 0; for(int i = 0; i < DH_MAX; i++) if(g_dh[i].pid > 0) n++; return n; }
static long long dh_now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec*1000LL + ts.tv_nsec/1000000; }
/* The next candidate of `net` for a reserved-slot dial: a rotating cursor
 * per network, so a failed background dial is followed by the NEXT address
 * rather than the same one every pass (deploy l on 2026-09-01 re-dialled
 * one dead onion every 5 s for the whole watch). Hosts a live leg already
 * holds and banned IPs are skipped. Returns the pool index, or -1. */
static int g_dh_cursor[2];
static int dh_reserved_pick(int an, int net, const char* srcpool[], int nsrc){
    if(nsrc <= 0 || an < 0 || an > 1) return -1;
    for(int step = 0; step < nsrc; step++){
        int ci = (g_dh_cursor[an] + step) % nsrc;
        if(leg_net_of(srcpool[ci]) != net) continue;
        int already = 0; for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0 && !strcmp(mux_out_host[k], srcpool[ci])){ already = 1; break; }
        if(already) continue;
        { char ip[128]; ctl_ip_only(srcpool[ci], ip, sizeof ip); if(ctl_is_banned(ip)) continue; }
        g_dh_cursor[an] = (ci + 1) % nsrc;
        return ci;
    }
    return -1;
}
static int dh_start(const char* host, int out_port){
    int slot = -1; for(int i = 0; i < DH_MAX; i++) if(g_dh[i].pid <= 0){ slot = i; break; }
    if(slot < 0) return 0;
    int sp[2]; if(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return 0;
    pid_t pid = fork();
    if(pid < 0){ close(sp[0]); close(sp[1]); return 0; }
    if(pid == 0){
        close(sp[0]); g_in_dial_helper = 1;
        dh_result_t r; memset(&r, 0, sizeof r);
        int fd = outbound_connect(host, 300, out_port);
        if(fd >= 0){
            r.ok = 1; r.wants_addrv2 = (unsigned char)g_peer_wants_addrv2;
            r.vlen = g_peer_version_len > 0 && g_peer_version_len <= 256 ? g_peer_version_len : 0;
            if(r.vlen) memcpy(r.vpayload, g_peer_version_payload, (size_t)r.vlen);
        } else snprintf(r.why, sizeof r.why, "%s", dial_fail_reason());
        struct iovec iov = { &r, sizeof r };
        char cbuf[CMSG_SPACE(sizeof(int))]; memset(cbuf, 0, sizeof cbuf);
        struct msghdr mh; memset(&mh, 0, sizeof mh); mh.msg_iov = &iov; mh.msg_iovlen = 1;
        if(fd >= 0){
            mh.msg_control = cbuf; mh.msg_controllen = sizeof cbuf;
            struct cmsghdr* cm = CMSG_FIRSTHDR(&mh); cm->cmsg_level = SOL_SOCKET; cm->cmsg_type = SCM_RIGHTS; cm->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(cm), &fd, sizeof fd);
        }
        (void)!sendmsg(sp[1], &mh, 0);
        _exit(0);
    }
    close(sp[1]);
    g_dh[slot].sp = sp[0]; g_dh[slot].pid = pid; g_dh[slot].net = leg_net_of(host); g_dh[slot].t0 = dh_now_ms();
    snprintf(g_dh[slot].host, sizeof g_dh[slot].host, "%s", host);
    fprintf(stderr, "[dial] %s: dialing in the background (%s)\n", host, bmc_net_name(g_dh[slot].net));
    return 1;
}
/* one completed (or timed-out) helper per call: 1 = result in *out (fd_out >= 0 iff ok), 0 = nothing */
static int dh_poll(dh_result_t* out, int* fd_out, char* host_out, size_t hcap){
    for(int i = 0; i < DH_MAX; i++){
        if(g_dh[i].pid <= 0) continue;
        struct iovec iov = { out, sizeof *out };
        char cbuf[CMSG_SPACE(sizeof(int))]; memset(cbuf, 0, sizeof cbuf);
        struct msghdr mh; memset(&mh, 0, sizeof mh); mh.msg_iov = &iov; mh.msg_iovlen = 1; mh.msg_control = cbuf; mh.msg_controllen = sizeof cbuf;
        memset(out, 0, sizeof *out);
        ssize_t n = recvmsg(g_dh[i].sp, &mh, MSG_DONTWAIT);
        if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)){
            if(dh_now_ms() - g_dh[i].t0 > g_dh_timeout_ms){
                fprintf(stderr, "[dial] %s: background dial gave up after %llds\n", g_dh[i].host, g_dh_timeout_ms / 1000);
                kill(g_dh[i].pid, SIGKILL); waitpid(g_dh[i].pid, NULL, 0);
                close(g_dh[i].sp); g_dh[i].pid = 0; g_dh[i].sp = -1;
                out->ok = 0; snprintf(out->why, sizeof out->why, "timeout"); *fd_out = -1;
                snprintf(host_out, hcap, "%s", g_dh[i].host);
                return 1;
            }
            continue;
        }
        *fd_out = -1;
        if(n == (ssize_t)sizeof *out && out->ok){
            for(struct cmsghdr* cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm))
                if(cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS){ memcpy(fd_out, CMSG_DATA(cm), sizeof(int)); break; }
            if(*fd_out < 0) out->ok = 0;
        } else if(n != (ssize_t)sizeof *out){ out->ok = 0; snprintf(out->why, sizeof out->why, "helper exited without a result"); }
        waitpid(g_dh[i].pid, NULL, 0);
        close(g_dh[i].sp); g_dh[i].pid = 0; g_dh[i].sp = -1;
        snprintf(host_out, hcap, "%s", g_dh[i].host);
        return 1;
    }
    return 0;
}
/* install a helper-dialled leg exactly as the inline fill does */
static int dh_install_leg(const char* host, int fd, const dh_result_t* r){
    if(mux_n_out >= MUX_MAX_OUT){ close(fd); return 0; }
    for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0 && !strcmp(mux_out_host[k], host)){ close(fd); return 0; }   /* already a leg */
    g_peer_version_len = r->vlen; if(r->vlen) memcpy(g_peer_version_payload, r->vpayload, (size_t)r->vlen);
    g_peer_wants_addrv2 = r->wants_addrv2;
    strncpy(mux_out_host[mux_n_out], host, 127); mux_out_host[mux_n_out][127] = 0;
    mux_out_fd[mux_n_out] = fd;
    mux_out_wants_v2[mux_n_out] = r->wants_addrv2;
    mux_out_peer[mux_n_out] = 0;
    anchor_locator(mux_out_loc[mux_n_out]);
    mux_out_nextretry[mux_n_out] = 0;
    { char pv[256]; format_peer_version_info(pv, sizeof pv);
      fprintf(stderr, "[dl] filled outbound %d = %s (fd %d) %s addrv2=%d [background dial]\n", mux_n_out, host, fd, pv, (int)r->wants_addrv2); }
    rpc_fill_peer_slot(mux_n_out, host);
    mux_n_out++;
    return 1;
}
static int legs_on_net(int net){ int n = 0; for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0 && leg_net_of(mux_out_host[k]) == net) n++; return n; }
static int legs_anon(void){ int n = 0; for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0 && leg_is_anon_net(leg_net_of(mux_out_host[k]))) n++; return n; }

static void mux_next_peer(int i, const char* peers[], int pool_len, int out_port){
    if(mux_out_fd[i]>=0){ bmc_v2_close(mux_out_fd[i]), close(mux_out_fd[i]); mux_out_fd[i]=-1; }
    /* setnetworkactive false: leave the slot dead rather than re-dialing.
     * This is the ONE place outbound legs are established, so gating here
     * gates every reconnect -- a toggle that only dropped the current legs
     * would be undone by the next rotation. */
    if(g_node_status && !g_node_status->net_active) return;
    /* rotate to the next seed in the pool (wrap); avoids hammering the same dead host */
    int p = (mux_out_peer[i]+1) % (pool_len>0?pool_len:1);
    /* ...and never onto a host another live leg already holds: each leg
     * rotates its own pointer, so two legs could land on one peer (deploy g,
     * 2026-09-01: legs 1 and 2 both on 108.245.166.132). Compared by HOST,
     * so a book carrying one peer under two ports still yields one leg. */
    { char me[128];
      for(int tries = 0; tries < pool_len; tries++){
          ctl_ip_only(peers[p], me, sizeof me);
          int held = leg_is_anon_net(leg_net_of(peers[p]));   /* anonymity dials belong to the helper, never inline */
          for(int k = 0; k < mux_n_out && !held; k++){
              if(k == i || mux_out_fd[k] < 0) continue;
              char other[128]; ctl_ip_only(mux_out_host[k], other, sizeof other);
              if(me[0] && !strcmp(me, other)) held = 1;
          }
          if(!held) break;
          p = (p + 1) % (pool_len > 0 ? pool_len : 1);
      } }
    mux_out_peer[i] = p;
    /* a banned peer is not dialed. Checked HERE for the same reason: this is
     * the only path to a new outbound leg. */
    { char ip[128]; ctl_ip_only(peers[p], ip, sizeof ip);
      if(ctl_is_banned(ip)){
          fprintf(stderr,"[mux:%d] %s is banned -- not dialing\n", i, peers[p]);
          return;
      } }
    int fd = outbound_connect(peers[p], 300, out_port);
    if(fd<0){ fprintf(stderr,"[mux:%d] next peer %s unreachable: %s (leg stays down)\n",
                     i, peers[p], dial_fail_reason()); return; }
    mux_out_fd[i]=fd;
    mux_out_wants_v2[i]=(unsigned char)g_peer_wants_addrv2;
    strncpy(mux_out_host[i], peers[p], 127);
    anchor_locator(mux_out_loc[i]);
    fprintf(stderr,"[mux:%d] leg replaced: connected next pool peer %s (fd %d) addrv2=%d\n", i, peers[p], fd, (int)mux_out_wants_v2[i]);
}

/* ---- per-leg sync wall-clock budget (accept-starve fix, t_7ea57703) ----
 * serve_mux runs ONE poll() loop that services inbound accepts AND the
 * outbound legs INLINE. If a single outbound node_sync pass blocks for a long
 * time (far-behind store / slow seed building a large getheaders catch-up),
 * the loop never returns to poll(), so inbound connections sit in the kernel
 * accept backlog un-accepted and the version handshake never starts -- every
 * inbound probe times out. We bound each leg's sync wall-clock: arm a short
 * SIGALRM around node_sync; if it fires we know the pass was interrupted (the
 * socket may hold a partially-read frame), so we DROP and re-dial a rotated
 * seed (re-using mux_next_peer) and let the next rotation continue the catch-up
 * from the freshly-anchored stored tip. A caught-up node completes node_sync
 * in well under the budget, so it is never interrupted and small-store
 * behavior (test_outbound_mux) is unchanged. */

/* Execute ONE bounded outbound sync pass on leg i. Returns the # blocks stored
 * this pass (as do_outbound_sync) -- but keeps the loop responsive by capping
 * the wall-clock. On budget expiry the leg is dropped and re-dialed (its fd may
 * be mid-frame after the EINTR). Caller still enforces its own re-dial
 * back-off; here we always allow the interrupt-driven redial so catch-up is
 * never blocked behind a stuck leg. */
static long do_outbound_sync_bounded(int i, const char* peers[], int pool_len, int out_port){
    struct sigaction sa, old;
    memset(&sa,0,sizeof sa); sa.sa_handler=mux_budget_alarm; sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM,&sa,&old);
    mux_sync_budget_fired = 0;
    mux_budget_fd = mux_out_fd[i];
    alarm((unsigned)MUX_SYNC_BUDGET_SECS < 1 ? 1 : (unsigned)MUX_SYNC_BUDGET_SECS);
    long n = do_outbound_sync(i);
    alarm(0);                                   /* disarm; return 0 leftover already fired */
    mux_budget_fd = -1;
    sigaction(SIGALRM,&old,NULL);
    if(mux_sync_budget_fired){
        /* The budget alarm interrupted node_sync. The leg's socket may hold a
         * partially-read frame after the EINTR, so it is NOT safe to keep
         * syncing on it -- drop and re-dial a rotated seed. do_outbound_sync
         * already re-anchored the locator at the (possibly advanced) stored
         * tip, so the next pass continues exactly where this one stopped. */
        fprintf(stderr,"[mux:%d] %s sync exceeded %gs budget; re-dialing\n",
                i, mux_out_fd[i]>=0?mux_out_host[i]:"?", MUX_SYNC_BUDGET_SECS);
        mux_next_peer(i, peers, pool_len, out_port);
    }
    return n;
}

/* ---- continuous download worker (serve mode, option 2) -------------------
 * The PRODUCTION `serve <dir> <port>` must BOTH service our client calls AND
 * keep downloading the blockchain to tip -- CONCURRENTLY. Serving must never
 * be delayed by a long sync, and a long sync must not be chopped into 2s
 * slices (which crawls far-from-tip stores). We therefore split the two jobs
 * across processes:
 *
 *   - PARENT: `serve_mux` -- pure serving + the pre-existing mux outbound
 *     legs (best-effort). Inbound connections are forked to node_serve_loop
 *     children, so serving our clients is never blocked by any download work
 *     in the parent. We keep the SMALL per-leg budget here (never delay
 *     accepts) because the heavy lifting is the worker's.
 *
 *   - CHILD (this worker): a dedicated forked process that continuously
 *     downloads. It re-initialises ITS OWN store from disk (fork COW is NOT
 *     safe for a growable store; the child must re-store_reload so its
 *     in-memory idx_len/pos track the archive), then loops: connect to a
 *     seed, anchor the locator at the on-disk tip, node_sync (which appends
 *     blocks), and index any new heights. It repeats until the daemon is
 *     killed.
 *
 * The worker is the ONLY aggressive block writer (the parent runs serve-only
 * with no outbound appends, so plain store_append is safe -- no cross-process
 * writer race). Serving reads block bytes fresh from disk via node_serve_block
 * (store_get_at preads index.dat and seeks the blk file), so whatever the
 * worker appends becomes serve-able once index.dat holds the height; the
 * parent refreshes its in-memory idx_len (store_buf+16) from index.dat at each
 * accept so served tips advance. */

/* ---- peer discovery at boot (seeds are BOOTSTRAPS only) ------------------
 * Real Bitcoin nodes do NOT download from DNS seeds; they use them once to
 * learn reachable peers, then connect to those -- never downloading from the
 * seeds themselves. We resolve each seed-DNS hostname to its A-records (real,
 * current Bitcoin node IPs), fold them into the persisted amr "peers.dat"
 * book, then dial up to 8 of those DISCOVERED peers for download. Fast and
 * reliable: DNS resolution returns dozens of live peer IPs in milliseconds, so
 * we do NOT depend on the flaky getaddr/addrv2 round-trip. */

/* bootstrap: resolve each seed-DNS hostname to its A-records (REAL reachable
 * Bitcoin node IPs) and fold them into the amr book. This is fast (milliseconds)
 * and reliable -- no flaky getaddr round-trip that can block for seconds per
 * seed. We dial these discovered IPs (never the seed hostname itself as a
 * long-lived download source); they are bootstrap peers only. */
/* Resolve a hostname or dotted-quad to ONE dotted-quad IPv4 string. Every
 * peer list downstream (the candidate pool, the workers, addr_gather_from)
 * speaks dotted-quad, so config entries are resolved at the boundary rather
 * than each consumer having to cope with hostnames. Returns 1 on success. */
static int dl_resolve1(const char* host, char out[64]){
    /* A literal needs no resolver, so it leaks nothing and must not be
     * refused: dropping it here removed the operator's own addnode=/connect=
     * from BOTH the book and the catch-up pool, and with the DNS seeds also
     * skipped behind a proxy that left a node with no bootstrap source at
     * all. Parse it before the gate. (2026-08-29 pre-deploy review.) */
    { bmc_addr_t lit;
      if(bmc_addr_from_string(&lit, host) && lit.net == BMC_NET_IPV4){
          bmc_addr_to_string(out, 64, &lit); return 1; } }
    /* a NAME behind a proxy is resolved BY the proxy at dial time, not here */
    if(dialer_dns_blocked()) return 0;
    struct addrinfo h,*res=0; memset(&h,0,sizeof h);
    h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&h,&res)!=0 || !res) return 0;
    struct sockaddr_in* sa=(struct sockaddr_in*)res->ai_addr;
    const char* p = inet_ntop(AF_INET,&sa->sin_addr,out,64);
    freeaddrinfo(res);
    return p?1:0;
}

static long dl_bootstrap(void* ab, const char* peers[], int pool_len){
    long total=0;

    /* Core -connect: these are the ONLY peers. No DNS, no seednode getaddr,
     * no book growth -- discovery of any kind would defeat the point of the
     * option (it exists to pin the node to a known set). */
    if(g_cfg.connect_only){
        fprintf(stderr,"[boot] connect= set -- skipping all peer discovery\n");
        return 0;
    }

    /* Core -addnode: peers the operator named. Folded into the book so every
     * existing consumer sees them, and put at the head of the candidate pool
     * by dl_catchup so they are actually tried first. */
    for(int i=0;i<g_cfg.n_addnode;i++){
        char ipd[64]; unsigned ip;
        if(!dl_resolve1(g_cfg.addnode[i], ipd)){
            fprintf(stderr,"[boot] addnode=%s did not resolve\n", g_cfg.addnode[i]); continue; }
        if(inet_pton(AF_INET,ipd,&ip)!=1) continue;
        if(book_add_ipv4(ip, g_chainp->default_port)>0) total++;
        fprintf(stderr,"[boot] addnode %s -> %s\n", g_cfg.addnode[i], ipd);
    }

    /* Core -seednode: ask for addresses, then drop the connection. Distinct
     * from addnode -- a seednode is a source of peers, not a peer we keep. */
    for(int i=0;i<g_cfg.n_seednode;i++){
        char ipd[64];
        if(!dl_resolve1(g_cfg.seednode[i], ipd)){
            fprintf(stderr,"[boot] seednode=%s did not resolve\n", g_cfg.seednode[i]); continue; }
        long got = addr_gather_from(ab, ipd, 20);
        fprintf(stderr,"[boot] seednode %s (%s) -> +%ld peers (getaddr)\n",
                g_cfg.seednode[i], ipd, got);
        total += got;
    }

    if(!g_cfg.dnsseed && !g_cfg.forcednsseed){
        fprintf(stderr,"[boot] dnsseed=0 -- not querying the DNS seeds\n");
        return total;
    }
    if(g_cfg.forcednsseed && !g_cfg.dnsseed)
        fprintf(stderr,"[boot] forcednsseed=1 overrides dnsseed=0 -- querying the seeds anyway\n");
    if(dialer_dns_blocked()){
        /* the seeds are DNS names; querying them behind a proxy would leak
         * "this host runs a Bitcoin node" to the resolver even though every
         * later connection is proxied */
        fprintf(stderr,"[boot] not querying the DNS seeds: a proxy is configured (or dns=0) -- "
                       "use addnode=/connect= or a seeded peers2.dat\n");
        return total;
    }
    for(int i=0;i<pool_len && i<12;i++){
        struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
        long got=0;
        if(getaddrinfo(peers[i],NULL,&h,&res)==0){
            for(struct addrinfo* ai=res; ai && got<64; ai=ai->ai_next){
                struct sockaddr_in* sa=(struct sockaddr_in*)ai->ai_addr;
                unsigned ip=sa->sin_addr.s_addr;
                if(ip && book_add_ipv4(ip, g_chainp->default_port)>0) got++;
            }
            freeaddrinfo(res);
        }
        if(got>0) fprintf(stderr,"[boot] %s -> +%ld peers (dns)\n", peers[i], got);
        total+=got;
    }
    return total;
}

/* pick up to n distinct public IPv4 endpoints from the amr book into
 * out[i] = "a.b.c.d" (IP only; the downloader dials each on the standard
 * out_port, matching how outbound_connect/serve_mux treat all peers). */
/* ---- known-good peer memory (peers.good) ---------------------------------
 * The address book records that an IP was SEEN, never that it was any use.
 * So every boot re-probed ~2,000 aged entries, kept whichever ~4% happened to
 * answer, and threw away the hard-won knowledge of which peers actually
 * delivered blocks -- the ones that worked last run got no preference at all
 * over long-dead entries. Persist the peers that really produced blocks and
 * try them FIRST next time.
 *
 * Deliberately a plain newline-separated IP text file: it is tiny, trivially
 * inspectable, and a corrupt/missing one degrades to exactly the old
 * behaviour (probe the book) rather than breaking startup. */
/* A pool slot must hold the LONGEST entry. The pool carries "host:port"
 * since the port had to survive the trip from the book, and an onion name is
 * 62 chars -- "<onion>:65535" is 68, so the old 64 truncated every Tor peer
 * to "<onion>:", undialable and still burning a slot. */
#define DL_POOL_SLOT 80
/* The pool's entries are "host:port" ("[v6]:port" for IPv6/CJDNS). Every
 * consumer that used to inet_pton() a bare host MUST split first -- three of
 * them did not, and the node came up with zero outbound legs and skipped its
 * boot catch-up on every restart (2026-08-28 pre-deploy review, caught
 * before this reached the live node). */
static int pool_split(const char* entry, char* host, long cap, int* port){
    bmc_addr_t a;
    if(!bmc_addr_from_string_port(&a, entry, 0)){
        snprintf(host, (size_t)cap, "%s", entry);      /* a DNS name: leave it whole */
        return 0;
    }
    bmc_addr_to_string(host, cap, &a);
    if(port && a.port) *port = a.port;
    return 1;
}
/* the IPv4 of a pool entry (0 if it is not a dialable v4), and its port */
static unsigned pool_ipv4(const char* entry, int* port){
    bmc_addr_t a;
    if(!bmc_addr_from_string_port(&a, entry, 0) || a.net != BMC_NET_IPV4) return 0;
    if(port && a.port) *port = a.port;
    unsigned ip; memcpy(&ip, a.addr, 4); return ip;
}
#define DL_GOODPEERS_FILE "peers.good"
#define DL_GOODPEERS_MAX  256

static int dl_load_good_peers(char out[][DL_POOL_SLOT], int cap){
    FILE* f = fopen(DL_GOODPEERS_FILE, "r");
    if(!f) return 0;
    int n=0; char line[128];
    while(n<cap && fgets(line,sizeof line,f)){
        size_t L=strlen(line);
        while(L && (line[L-1]=='\n'||line[L-1]=='\r')) line[--L]=0;
        if(!L) continue;
        struct in_addr t;
        if(inet_pton(AF_INET,line,&t)!=1) continue;   /* ignore junk lines */
        strncpy(out[n],line,63); out[n][63]=0; n++;
    }
    fclose(f);
    return n;
}

/* Written atomically (tmp+rename) so a crash mid-write cannot leave a
 * truncated list that silently shrinks the next boot's head start. */
static void dl_save_good_peers(char peers[][64], int n){
    if(n<=0) return;
    FILE* f = fopen(DL_GOODPEERS_FILE ".tmp","w");
    if(!f) return;
    for(int i=0;i<n && i<DL_GOODPEERS_MAX;i++) fprintf(f,"%s\n",peers[i]);
    fflush(f); fsync(fileno(f)); fclose(f);
    rename(DL_GOODPEERS_FILE ".tmp", DL_GOODPEERS_FILE);
    fprintf(stderr,"[dlc] recorded %d known-good peer(s) for next boot\n", n<DL_GOODPEERS_MAX?n:DL_GOODPEERS_MAX);
}

/* The dial pool, sampled ACROSS NETWORKS. The book is appended in the order
 * addresses were learned, so "the first 64 dialable entries" was 64 IPv4
 * peers every time: with 2,580 onion and 409 I2P entries in the book the
 * node never dialled either (2026-08-31). Core's addrman picks at random
 * and diversifies by network; this does the same in two passes: a reservoir
 * sample per reachable network, then a layout that gives every reachable
 * network a quota and interleaves them so the rotation (mux_next_peer,
 * feelers, top-ups all walk this pool in order) reaches an onion or I2P
 * peer within a few dials -- while the FIRST slots stay mostly clearnet,
 * because the boot dials are sequential and an anonymity-network circuit
 * takes seconds to build. */
static unsigned long long dl_pool_rng_state;
void dl_pool_test_seed(unsigned long long s){ dl_pool_rng_state = s ? s : 1; }
static unsigned long long dl_pool_rng(void){
    if(!dl_pool_rng_state){
        struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
        dl_pool_rng_state = ((unsigned long long)ts.tv_sec << 32) ^ (unsigned long long)ts.tv_nsec ^ ((unsigned long long)getpid() << 17) ^ 0x9E3779B97F4A7C15ULL;
    }
    unsigned long long x = dl_pool_rng_state; x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    return dl_pool_rng_state = x;
}
#define DL_POOL_NNET 5
#define DL_POOL_V4_WINDOW  4096   /* clearnet candidates: the first entries of the book (see dl_pool_from_book) */
#define DL_POOL_RESERVOIR 8192   /* per-network sample: clearnet must be able to fill the largest catch-up pool (bmc.peerpool <= 8192) */
static int dl_pool_net_slot(int net){
    switch(net){ case BMC_NET_IPV4: return 0; case BMC_NET_IPV6: return 1; case BMC_NET_TORV3: return 2;
                 case BMC_NET_I2P: return 3; case BMC_NET_CJDNS: return 4; default: return -1; }
}
static int dl_pool_from_book(void* ab, char out[][DL_POOL_SLOT], int nitems){
    (void)ab;
    ab2_t* b = addr_book(); if(!b) return 0;
    long cnt = ab2_count(b);
    /* pass 1: a uniform random sample (reservoir) of dialable entries per network */
    static long res[DL_POOL_NNET][DL_POOL_RESERVOIR]; long seen[DL_POOL_NNET] = {0}, have[DL_POOL_NNET] = {0};
    for(long i = 0; i < cnt; i++){
        ab2_rec_t r; if(!ab2_get(b, i, &r)) continue;
        int k = dl_pool_net_slot(r.a.net); if(k < 0) continue;
        /* Clearnet comes from the HEAD of the book only. The book carries no
         * tried/new distinction and gossip refreshes last_seen, so recency
         * cannot tell a once-connected peer from an address a stranger
         * claimed; but the head is the migrated, once-connected set and
         * gossip appends behind it. A uniform sample over all 17k IPv4
         * entries drew mostly dead addresses and odd ports -- one live leg in
         * five minutes (2026-09-01 02:20). */
        if(k == 0 && i >= DL_POOL_V4_WINDOW) continue;
        if(!dialer_net_reachable(r.a.net)) continue;      /* stays in the book, never in the pool */
        if(!bmc_addr_is_routable(&r.a)) continue;
        long n = seen[k]++;
        if(have[k] < DL_POOL_RESERVOIR){ res[k][have[k]++] = i; }
        else { long j = (long)(dl_pool_rng() % (unsigned long long)(n + 1)); if(j < DL_POOL_RESERVOIR) res[k][j] = i; }
    }
    /* shuffle each sample: a reservoir smaller than the network's population
     * holds its elements in book order, and a small deployment would then
     * dial the head of the file forever -- the very thing this replaces */
    for(int k = 0; k < DL_POOL_NNET; k++)
        for(long i = have[k] - 1; i > 0; i--){ long j = (long)(dl_pool_rng() % (unsigned long long)(i + 1)); long t = res[k][i]; res[k][i] = res[k][j]; res[k][j] = t; }
    /* pass 2: quotas -- a floor for every reachable network with anything in
     * the book, the rest clearnet. Onion gets the biggest share: it is the
     * network with the most peers and the one that costs nothing to run. */
    long quota[DL_POOL_NNET] = {0};
    /* The anonymity-network shares are FLOORS sized for the 64-slot leg
     * pool (ipv6 8, onion 12, i2p 6, cjdns 3), not proportions: the 512-slot
     * catch-up pool feeds a throughput-critical parallel downloader, and
     * scaling the floors with it made a quarter of that pool Tor circuits. */
    long want[DL_POOL_NNET] = { 0, 8, 12, 6, 3 };
    if(nitems < 64) for(int k = 1; k < DL_POOL_NNET; k++) want[k] = want[k] * nitems / 64;
    long taken = 0;
    for(int k = 1; k < DL_POOL_NNET; k++){ quota[k] = want[k] < have[k] ? want[k] : have[k]; taken += quota[k]; }
    quota[0] = have[0] < nitems - taken ? have[0] : nitems - taken;
    /* if clearnet cannot fill its share, let the others grow into the room */
    for(int k = 1; k < DL_POOL_NNET && quota[0] + taken < nitems; k++){
        long room = nitems - quota[0] - taken; long extra = have[k] - quota[k];
        if(extra > room) extra = room; if(extra > 0){ quota[k] += extra; taken += extra; }
    }
    /* pass 3: layout. Slots 0..7 (the boot dials) are clearnet except one
     * onion (slot 3) and one ipv6 (slot 6) when available; after that the
     * networks are interleaved so every 4th entry is an anonymity peer. */
    long used[DL_POOL_NNET] = {0}; int got = 0;
    #define POOL_TAKE(k) do{ if(used[k] < quota[k]){ ab2_rec_t r; if(ab2_get(b, res[k][used[k]++], &r) && \
        bmc_addr_to_string_port(out[got], DL_POOL_SLOT, &r.a) > 0) got++; } }while(0)
    static const int early[8] = { 0, 0, 0, 2, 0, 0, 1, 0 };
    static const int cycle[8] = { 0, 2, 0, 1, 0, 3, 0, 4 };
    for(int s = 0; got < nitems && s < 8; s++){
        int k = early[s]; if(used[k] >= quota[k]) k = 0;
        if(used[k] >= quota[k]) break;
        POOL_TAKE(k);
    }
    for(int guard = 0; got < nitems && guard < nitems * 8; guard++){
        int k = cycle[guard % 8];
        if(used[k] >= quota[k]){ int any = 0; for(int t = 0; t < DL_POOL_NNET; t++) if(used[t] < quota[t]){ k = t; any = 1; break; } if(!any) break; }
        POOL_TAKE(k);
    }
    #undef POOL_TAKE
    fprintf(stderr,"[pool] %d peer(s) sampled from the book: ipv4 %ld, ipv6 %ld, onion %ld, i2p %ld, cjdns %ld (book has %ld/%ld/%ld/%ld/%ld dialable)\n",
            got, used[0], used[1], used[2], used[3], used[4], seen[0], seen[1], seen[2], seen[3], seen[4]);
    return got;
}

/* ---- built-in multi-peer catch-up (replaces the external unified_ibd.c /
 * hole_ranges.py / backfill_holes.sh / sync_chain.sh pipeline) ------------
 * Runs SYNCHRONOUSLY before serve mode opens for business (see the caller
 * below): detects any archive hole (a zero-record run below the current
 * on-disk tip) plus whatever's missing up to the real chain tip (tracked in
 * headers.dat), then fills the WHOLE span with a pool of chunk-claiming
 * workers -- same design as the standalone unified_ibd.c tool: a shared
 * mmap'd atomic cursor so an idle worker keeps pulling new 200-block chunks
 * instead of sitting on a static pre-split shard, and a present-check so
 * the SAME invocation can span real holes and already-filled heights
 * without redundant re-download. main() already chdir()s into the resolved
 * data dir before mode dispatch, so paths below are bare relative
 * filenames, matching the rest of this file's convention (e.g. the
 * "append.lock" open just above the serve-mode block). */
/* Optimizing for speed, not just "give every peer a fair shot": on a chunk
 * cut, ALL progress on that chunk is thrown away (the retry path
 * redownloads the whole thing from scratch, no partial resume) -- so the
 * real lever is chunk size, not timeout length. A smaller chunk means a bad
 * peer gets detected and replaced faster in wall-clock terms AND costs less
 * to lose when it does happen; a good peer loses nothing either way since a
 * successful connection is reused back-to-back across many chunks. 200
 * blocks (~250-300MB near the tip) meant a bad-peer cut wasted a lot of
 * work and took minutes to even trigger; 40 blocks (~50-60MB near the tip)
 * with a proportionally shorter budget gives a ~4x faster detect-and-replace
 * cycle at ~4x lower cost per miss. */
#define DLC_CHUNK_BLOCKS 40
/* Draw from the WHOLE address book, not a 512 slice of it. Measured
 * 2026-08-18: the book held 1,974 peers, the pool was capped at 512, the
 * probe tried all 512 and only 22 were reachable (~4% -- normal for an aged
 * book full of long-dead nodes). That left ~1,460 candidates untried and the
 * downloader running on 22 peers, which is also what made peer-banning
 * exhaust the pool. Probing is nearly free -- dead peers refuse instantly,
 * so all 512 were covered in 0.49s -- so there is no reason to sample. */
#define DLC_MAXPOOL 2048
#define DLC_HDR_TRY_PEERS 8
/* wall-clock budget for ONE chunk transfer. At DLC_CHUNK_BLOCKS=40
 * (~50-60MB near the real tip), 120s requires ~467KB/s sustained to
 * survive -- similar bar to the old 480s/200-block combo, but the
 * detect-and-replace cycle for a dead peer is ~4x faster and a miss costs
 * ~4x less redone work. */
#define DLC_CHUNK_BUDGET_SECS 120
/* early-kill thresholds: the parent's status loop already samples each
 * worker's real /proc/<pid>/io bandwidth every 10s for the live display --
 * a connection sustaining under DLC_DEAD_WEIGHT_BPS for
 * DLC_DEAD_WEIGHT_TICKS consecutive ticks (10 ticks = ~100s: deliberately
 * long, to be confident this is a truly dead connection and not a peer
 * that's just momentarily slow before recovering) is treated as dead, so
 * the parent signals that worker to abandon rather than making it sit out
 * the full DLC_CHUNK_BUDGET_SECS on a peer that was never going anywhere. */
/* Retuned 2026-08-18 after watching a real re-sync crawl at ~119KB/s
 * aggregate. The old floor (10KB/s sustained for 10 consecutive 10s ticks)
 * meant a peer trickling 3-9KB/s -- bad, but not bad enough to trip a 10KB/s
 * bar -- burned a FULL 100 SECONDS of a worker slot before being replaced,
 * and most of the pool was doing exactly that. Patience is only a virtue when
 * the peer might recover; when other peers are managing 15KB/s+ on the same
 * link, a slot held by a 5KB/s peer is pure loss. React in ~30s instead, and
 * judge against a floor that reflects what a useful peer actually delivers. */
#define DLC_DEAD_WEIGHT_BPS 32768.0
#define DLC_DEAD_WEIGHT_TICKS 3
/* Never ban the pool down to nothing. Banning is only an optimisation -- a
 * banned peer is worth less than an unbanned one, but ANY peer beats none.
 * The first cut of this had no floor and, against a 22-peer live pool,
 * banned 28 slots: every worker hit "peers exhausted" (logged 20,495 times),
 * the chunked downloader gave up after 24,720 blocks, and the sync fell back
 * to the slow sequential path. Keep a working set alive, and grant amnesty
 * rather than deadlock if we somehow still run dry. */
#define DLC_MIN_USABLE_PEERS 8

/* true iff every height in [lo,hi] already has a non-zero index.dat record.
 * asm/bitcoin_idxscan.asm:idxscan_all_present -- buffered pread64 port,
 * ~44x faster than this stdio version on the real archive (see
 * tests/bench_idxscan.c). */
static int dlc_chunk_all_present(long lo, long hi){
    return idxscan_all_present(lo, hi) != 0;
}

/* highest height h with index.dat[h] non-zero, or -1 if none/empty.
 * asm/bitcoin_idxscan.asm:idxscan_tip -- ~48x faster (see tests/bench_idxscan.c). */
static long dlc_index_tip(void){
    return idxscan_tip();
}

/* first zero-record height in [0,tip], or -1 if none (contiguous).
 * asm/bitcoin_idxscan.asm:idxscan_first_hole -- ~4.5x faster. */
static long dlc_first_hole(long tip){
    return idxscan_first_hole(tip);
}

/* combined hole+extend span: 1 with *start_h/*end_h set, or 0 if the
 * archive is already contiguous through hdr_len-1. chunk_all_present makes
 * it safe for this ONE span to also re-cover already-filled heights between
 * a hole and the current tip, so no separate hole-then-extend passes are
 * needed the way the external CLI tool required (and no tip-1 sentinel
 * juggling -- this is a single internal computation, not a value that gets
 * reinterpreted by a second process's own resume logic). */
static int dlc_span(long hdr_len, long* start_h, long* end_h){
    long true_end = hdr_len-1; if(true_end<0) return 0;
    /* Core -stopatheight: every download path funnels through here, so this is
     * the one place that has to honour it. Clamping the SPAN (rather than
     * checking per block) also means the progress figures and the
     * "already complete" test below speak in terms of the requested stopping
     * point instead of the real chain tip. */
    if(g_cfg.stopatheight > 0 && true_end > g_cfg.stopatheight){
        true_end = g_cfg.stopatheight;
    }
    /* Pruned heights are DELIBERATELY absent, so they must not be treated as
     * holes to refill. Without this floor, enabling prune produces a loop:
     * store_prune deletes the blocks below the gate, the next span sees them
     * missing, downloads them again, and the following boot prunes them
     * again -- forever, at full bandwidth. Nothing exercised this before
     * because nothing ever called store_prune. */
    long prune_h = *(int*)((char*)store_buf + 48);
    if(prune_h < 0) prune_h = 0;

    long tip = dlc_index_tip();
    if(tip<0){ *start_h=prune_h; *end_h=true_end; return prune_h<=true_end; }
    long fh = dlc_first_hole(tip);
    if(fh>=0){
        if(fh < prune_h) fh = prune_h;          /* below the gate: not a hole */
        if(fh <= true_end){ *start_h=fh; *end_h=true_end; return 1; }
        /* every remaining hole is below the prune gate -- nothing to fetch */
    }
    if(tip>=true_end) return 0;
    *start_h = (tip+1 < prune_h) ? prune_h : tip+1;
    *end_h   = true_end;
    return *start_h <= true_end;
}

/* Does the header at position `have` (the first one a peer just appended)
 * extend the header we asked from (`loc`, our previous tip)? A getheaders
 * answer that starts anywhere else is not a continuation of our chain. */
#define DLC_HDR_SANE_MAX 100000L
static int __attribute__((unused)) dlc_headers_sane(long have0, long added){ return have0 <= 0 || added <= DLC_HDR_SANE_MAX; }
static int __attribute__((unused)) dlc_headers_connect_ok(unsigned char* hst, long have, const unsigned char loc[32]){
    unsigned char rec[112];
    if(have <= 0) return 1;                                   /* fresh store: nothing to connect to */
    if(hst_get_at(hst, (unsigned long long)have, rec) != 1) return 0;
    return memcmp(rec + 4, loc, 32) == 0;                     /* header[4..36) = hashPrevBlock */
}
/* drop everything appended past `have`: headers.dat is the store's backing
 * file (112-byte records), so truncate it and reload */
static void dlc_headers_rollback(unsigned char* hst, long have){
    if(truncate("headers.dat", (off_t)have * 112) != 0)
        fprintf(stderr,"[dlc] could not roll headers.dat back to %ld record(s): %s\n", have, strerror(errno));
    hst_init(hst);
    hst_reload(hst);
}

/* ---- boot header fetch, in C (incident 2026-09-01) --------------------------
 * The asm node_ibd_headers took a single-hash locator, appended every page
 * a peer sent without checking that the first one continued the block it
 * asked from, and its return value did not report what it appended (5033
 * for a 961,640-header reply; 0 for the next). Two peers in a row answered
 * from GENESIS on the 12:23 boot -- a peer a block behind does not know our
 * newest hash, and a one-hash locator gives it nothing else to match. This
 * fetch does what Core does: an exponential locator (the last 10 headers,
 * then doubling steps back to genesis), one page at a time, and every page
 * is checked before it is stored:
 *   - the page's first header must extend a header WE HOLD (our tip, or an
 *     earlier locator point -- a peer behind us answers from the last block
 *     it knows);
 *   - headers that overlap what we hold must be IDENTICAL (a peer on a fork
 *     is refused, not merged);
 *   - every header links to the previous one and carries no transactions;
 *   - no more than DLC_HDR_SANE_MAX are accepted from one peer (a node a year
 *     offline is ~52k behind; the incident's reply was 966,669).
 * Appends go through hst_append; on any refusal the store is rolled back to
 * where this fetch started. Returns headers appended, or -1. */
#define DLC_HDR_PAGE 2000
#define DLC_HDR_LOCATOR_MAX 40
static int dlc_locator_build(unsigned char* hst, unsigned char* loc_out /* MAX*32 */, long* heights /* MAX */){
    long have = hst_count(hst); int n = 0;
    if(have <= 0) return 0;
    long h = have - 1, step = 1;
    while(h >= 0 && n < DLC_HDR_LOCATOR_MAX){
        unsigned char rec[112];
        if(hst_get_at(hst, (unsigned long long)h, rec) != 1) break;
        memcpy(loc_out + n * 32, rec + 80, 32); heights[n] = h; n++;
        if(n >= 10) step *= 2;
        if(h == 0) break;
        h -= step; if(h < 0) h = 0;
    }
    return n;
}
static unsigned long dlc_varint(const unsigned char* p, unsigned long avail, unsigned long* used){
    if(avail < 1){ *used = 0; return 0; }
    if(p[0] < 0xfd){ *used = 1; return p[0]; }
    if(p[0] == 0xfd){ if(avail < 3){ *used = 0; return 0; } *used = 3; return (unsigned long)p[1] | ((unsigned long)p[2] << 8); }
    *used = 0; return 0;                       /* a headers count never needs more */
}
static long dlc_fetch_headers(int fd, unsigned char* hst, const char* cand){
    long have0 = hst_count(hst), added = 0;
    static unsigned char page[DLC_HDR_PAGE * 81 + 16];
    static unsigned char msg[2 << 20];
    unsigned char stop[32]; memset(stop, 0, 32);
    for(int round = 0; round < 1000; round++){
        unsigned char loc[DLC_HDR_LOCATOR_MAX * 32]; long lh[DLC_HDR_LOCATOR_MAX];
        int nl = dlc_locator_build(hst, loc, lh);
        if(nl <= 0) return -1;
        long plen = p2p_getheaders(page, loc, nl, stop);
        if(plen <= 0 || p2p_write(fd, "getheaders", 10, page, (unsigned)plen) < 0) return -1;
        /* the reply: skip anything else the peer says first (inv, ping, ...) */
        unsigned mlen = 0; char cmd[12]; int got = 0;
        for(int k = 0; k < 40 && !got; k++){
            int r = p2p_read(fd, cmd, msg, sizeof msg, &mlen);
            if(r <= 0) break;
            if(!strncmp(cmd, "headers", 12)) got = 1;
            else if(!strncmp(cmd, "ping", 12) && mlen == 8) p2p_write(fd, "pong", 4, msg, 8);
        }
        if(!got){ if(added) break; return -1; }
        unsigned long used; unsigned long cnt = dlc_varint(msg, mlen, &used);
        if(!used || cnt > DLC_HDR_PAGE || used + cnt * 81 > mlen) break;   /* malformed: stop here */
        if(cnt == 0) break;
        /* where does this page attach? the first header's prev must be one of
         * the hashes we asked with */
        const unsigned char* first = msg + used;
        int at = -1; for(int q = 0; q < nl; q++) if(!memcmp(first + 4, loc + q * 32, 32)){ at = q; break; }
        if(at < 0){
            fprintf(stderr,"[dlc] headers from %s do not connect to any header we hold (%lu offered) -- discarding\\n", cand, cnt);
            dlc_headers_rollback(hst, have0); return -1;
        }
        long pos = lh[at] + 1;                    /* the height this page's first header would have */
        long have = hst_count(hst);
        unsigned char prev[32]; memcpy(prev, loc + at * 32, 32);
        unsigned long i = 0;
        for(; i < cnt; i++){
            const unsigned char* h = first + i * 81;
            if(h[80] != 0) break;                 /* txn_count must be 0 in a headers message */
            if(memcmp(h + 4, prev, 32) != 0){
                fprintf(stderr,"[dlc] headers from %s break their own chain at %lu -- discarding\\n", cand, i);
                dlc_headers_rollback(hst, have0); return -1;
            }
            unsigned char bh[32]; block_hash(bh, h);
            if(pos + (long)i < have){
                /* overlap with what we hold: must be the same block */
                unsigned char rec[112];
                if(hst_get_at(hst, (unsigned long long)(pos + (long)i), rec) != 1 || memcmp(rec + 80, bh, 32) != 0){
                    fprintf(stderr,"[dlc] headers from %s fork from our chain at height %ld -- discarding\\n", cand, pos + (long)i);
                    dlc_headers_rollback(hst, have0); return -1;
                }
            } else {
                if(added + 1 > DLC_HDR_SANE_MAX){
                    fprintf(stderr,"[dlc] %s offered more than %ld header(s) beyond %ld -- far beyond any plausible gap; discarding\\n", cand, DLC_HDR_SANE_MAX, have0);
                    dlc_headers_rollback(hst, have0); return -1;
                }
                if(hst_append(hst, h, bh) < 0){ dlc_headers_rollback(hst, have0); return -1; }
                added++;
            }
            memcpy(prev, bh, 32);
        }
        if(i < cnt) break;                        /* a non-empty txn_count: stop taking this peer's pages */
        if(cnt < DLC_HDR_PAGE) break;             /* a short page is the peer's tip */
    }
    return added;
}

/* extend headers.dat as far as a discovered peer will serve, resuming from
 * whatever's already on disk (a real locator from the last stored hash) so
 * repeat boots only pull the delta instead of refetching from genesis every
 * time. Returns the new header count, or -1 if nothing served AND nothing
 * was already on disk. */
/* try ONE candidate for the header phase: connect+handshake+node_ibd_headers.
 * Returns added-header-count (>=0) on a completed exchange, -1 if the
 * candidate couldn't even be reached/handshaked. */
/* Why a header try failed, so the loop below can SAY so. Every step used to
 * return a bare -1, and dlc_headers then fell back to whatever headers.dat
 * already held -- silently. The consequence was invisible for days: on
 * 2026-08-31 production's boot log read "[dlc] archive already complete
 * through 964471" while the chain was at 964,8xx, and a fresh signet node
 * read "complete through 0" with 190k blocks to fetch. The parallel boot
 * downloader had been dead since the address book started carrying ports. */
/* The ONE parser for a pool/live entry: "ip[:port]" (what dlc_probe_round
 * and the address book produce). Both dlc sites used inet_pton() on the raw
 * string, which rejects the ":port" suffix -- tests/test_dlc_peer_parse pins
 * this so it cannot quietly regress to that again. 1 ok / 0 unparseable. */
static int dlc_parse_peer(const char* cand, unsigned* ip, int* port){
    int p = 0; unsigned a = pool_ipv4(cand, &p);
    if(!a) return 0;
    *ip = a; *port = p;
    return 1;
}
enum { DLC_HT_PARSE = 1, DLC_HT_CONNECT, DLC_HT_HANDSHAKE, DLC_HT_WITNESS, DLC_HT_FETCH };
static const char* const dlc_ht_name[] = { "?", "unparseable address", "connect", "handshake", "no NODE_WITNESS", "headers fetch" };
static long dlc_headers_try(const char* cand, void* hst, unsigned char loc[32],
                            unsigned char* hdrbuf, size_t hdrbuf_sz, int* why){
    /* Pool entries are "ip[:port]" -- the same form dlc_probe_round parses
     * with pool_ipv4. This used to be inet_pton(cand), which rejects the
     * ":port" suffix outright, so once the book carried ports EVERY candidate
     * failed here before a single connect. */
    int pport = 0; unsigned ip = 0;
    if(!dlc_parse_peer(cand, &ip, &pport)){ *why = DLC_HT_PARSE; return -1; }
    int cport = pport ? pport : node_config_peer_port(cand);
    int fd=tcp_connect_ip(ip,(unsigned short)htons((unsigned short)(cport ? cport : g_chainp->default_port)));
    if(fd<0){ *why = DLC_HT_CONNECT; return -1; }
    struct timeval tv; tv.tv_sec=15; tv.tv_usec=0; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
    bmc_v2_close(fd);      /* v1-only path; see the note at the other one */
    if(node_handshake(fd)!=1){ close(fd); *why = DLC_HT_HANDSHAKE; return -1; }
    if(!peer_has_witness(cand)){ close(fd); *why = DLC_HT_WITNESS; return -1; }
    (void)loc; (void)hdrbuf; (void)hdrbuf_sz;
    long added = dlc_fetch_headers(fd, hst, cand);
    close(fd);
    if(added<0){ *why = DLC_HT_FETCH; return -1; }
    return added;
}

/* live[] must already be confirmed-reachable (via dlc_probe_round below) --
 * dlc_headers_try's tcp_connect_ip() is a plain blocking connect with no
 * connect-phase timeout, so trying an UNCONFIRMED candidate here would carry
 * the same hang risk documented on dlc_worker; deliberately no fallback to
 * raw pool entries. */
/* headers.dat is DERIVED from the archive: append the header of every stored
 * block the mirror lacks, from the blocks themselves. The worker's leg sync
 * stored blocks without touching the mirror, so every boot used to ask peers
 * from a stale point (12 blocks stale on 2026-09-01), and a peer that did not
 * know that block answered from genesis. Stops at the first hole; the peer
 * sync takes over from there. Returns headers appended. */
static long dl_header_mirror_topup(unsigned char* store){
    static unsigned char hst[4096]; hst_init(hst);
    struct stat hs;
    if(stat("headers.dat",&hs)==0 && hs.st_size>=112) hst_reload(hst);
    long have = hst_count(hst); long tip = *(int*)(store + 24); long n = 0;   /* store tip lives at +24 (store_get_tip takes (st, out_meta[3]), not one arg) */
    if(have <= 0 || tip < 0) return 0;               /* an empty mirror is seeded with genesis by dlc_headers */
    for(long h = have; h <= tip; h++){
        static unsigned char hb[4u<<20];   /* store_read_at returns the WHOLE block (a 128-byte stack buffer SEGV-looped the q boot) */
        if(store_read_at(store, (unsigned long)h, hb, sizeof hb) < 80) break;
        unsigned char bh[32]; block_hash(bh, hb);
        if(hst_append(hst, hb, bh) < 0) break;
        n++;
    }
    if(n) fprintf(stderr,"[dl] header mirror +%ld from the archive (now %ld, archive tip %ld)\n", n, hst_count(hst), tip);
    return n;
}

static long dlc_headers(char live[][64], int nlive){
    static unsigned char hst[4096]; hst_init(hst);
    struct stat hs;
    dl_header_mirror_topup(store_buf);
    if(stat("headers.dat",&hs)==0 && hs.st_size>=112) hst_reload(hst);
    long have = hst_count(hst);
    if(have==0){
        /* Fresh mirror: seed the chain's own genesis header at position 0.
         * dlc_span and the chunk workers treat headers.dat POSITION as
         * HEIGHT, and a getheaders response never includes the locator
         * point itself -- without this seed a fresh datadir stored every
         * block one height low (found on the first regtest boot: bmc's
         * h=1 held Core's block 2; the production mainnet mirror predates
         * the genesis-at-index-0 fix and was built with genesis present). */
        unsigned char gh[32]; block_hash(gh, g_chainp->genesis);
        if(hst_append(hst, g_chainp->genesis, gh)>=0) have = hst_count(hst);
    }
    unsigned char loc[32]; memset(loc,0,32);
    if(have>0){
        static unsigned char rec[112];
        if(hst_get_at(hst,(unsigned long long)(have-1),rec)==1) memcpy(loc, rec+80, 32);
    }
    static unsigned char hdrbuf[2<<20];
    int tried=0, failed=0, whys[8]={0};
    for(int i=0;i<nlive && tried<DLC_HDR_TRY_PEERS; i++){
        int why=0;
        long added=dlc_headers_try(live[i], hst, loc, hdrbuf, sizeof hdrbuf, &why);
        if(added<0){ failed++; if(why>=0 && why<8) whys[why]++; continue; }
        tried++;
        /* a genuine peer failure/hiccup can return exactly 0 added headers
         * with nothing wrong at the protocol level (unified_ibd.c's own
         * fork-based header phase treats this the same way: h>0 is the only
         * success signal, not h>=0) -- so 0 added on an EMPTY store means
         * try the next candidate, not "done". 0 added when we already HAD
         * headers is a real, different signal: the peer confirms we're
         * already at its tip, which is legitimate success. */
        if(added>0){ fprintf(stderr,"[dlc] headers +%ld from %s (total %ld)\n", added, live[i], hst_count(hst)); return hst_count(hst); }
        if(added==0 && have>0){ fprintf(stderr,"[dlc] headers: already current per %s (total %ld)\n", live[i], hst_count(hst)); return hst_count(hst); }
    }
    /* Nothing added and nothing confirmed current: the boot downloader is
     * about to be told the archive is "complete" through whatever headers.dat
     * held. That is only true if the header chain is actually current, and we
     * have just failed to check. Say so, with the reasons, every time. */
    if(failed){
        char buf[256]; int n=0;
        for(int k=1;k<6;k++) if(whys[k]) n+=snprintf(buf+n, sizeof buf-(size_t)n, "%s%d x %s", n?", ":"", whys[k], dlc_ht_name[k]);
        fprintf(stderr,"[dlc] headers: %d candidate(s) tried, %d succeeded, %d FAILED (%s) -- header chain held at %ld; boot catch-up cannot see past it\n",
                failed+tried, tried, failed, buf, have);
    }
    return have>0 ? have : -1;
}

/* chunk-claiming worker: pulls DLC_CHUNK_BLOCKS-sized pieces from a SHARED
 * atomic cursor (mmap'd MAP_SHARED across all forked workers) until the
 * whole [.,end_h] span is claimed -- a worker that lands fast peers just
 * keeps claiming more chunks instead of idling once some static "share" is
 * done (same design as unified_ibd.c's worker()). Persistent connection
 * reused across chunks. Peer search is scoped to `live[]` ONLY (candidates
 * the caller already confirmed reachable via a bounded non-blocking probe --
 * see dlc_probe_round below) -- deliberately NOT a fallback to raw
 * unconfirmed pool entries: tcp_connect_ip() is a plain blocking connect()
 * with no connect-phase timeout (SO_RCVTIMEO only bounds reads afterward),
 * so dialing an unconfirmed, possibly-black-holed host can hang for a long
 * time (observed firsthand: a header-phase version of this fallback stalled
 * for 3+ minutes on one bad candidate). `live[]` needs to be reasonably
 * populated by the caller for this to have enough depth. Each worker
 * independently opens append.lock itself -- flock() locks belong to the
 * open file description, so an INHERITED fd would not actually exclude
 * sibling workers from each other. */
/* per-worker live stats, in a MAP_SHARED region so the parent can read them
 * while the workers run -- "what peer is worker N talking to and how much
 * has it pulled" without waiting for the final one-line summary. last_bw_bps
 * is written by the PARENT (it's the one sampling /proc/<pid>/io for the
 * live display) and read by the WORKER itself when it prints a drop message,
 * so "why did we drop this peer" shows the actual measured rate instead of
 * just "budget expired" with no numbers -- the worker has no way to sample
 * its own throughput while blocked inside node_ibd_blocks_s. MAP_ANONYMOUS
 * zero-inits it to 0.0, read as "no reading yet" if a drop somehow happens
 * before the parent's first 10s tick. */
typedef struct { char peer[64]; long chunks; long blocks; long guard; double last_bw_bps; long timeouts; long held_idx; } dlc_stat_t;
static void dlc_fmt_rate(char* buf, size_t cap, double bytes_per_sec); /* fwd decls, defined below */
static void dlc_fmt_bytes(char* buf, size_t cap, double bytes);

static int dlc_worker(int w, long end_h, char live[][64], int nlive,
                      int slot0, volatile long* next_claim, volatile long* done_count,
                      volatile dlc_stat_t* mystat, volatile int* claimed,
                      volatile int* banned){
    /* SIGUSR1 registered for this worker's WHOLE lifetime, not just around
     * the node_ibd_blocks_s call below -- the parent can send it any time
     * it spots sustained near-zero bandwidth, which won't always land while
     * the per-chunk alarm guard (further down) has it re-armed. Left
     * unregistered here, a stray signal landing between chunks would hit
     * the default SIGUSR1 disposition (terminate) and kill this whole
     * worker instead of just its dead connection. The handler only sets a
     * flag either way, so an early/idle delivery is harmless -- the next
     * guarded call resets the flag before it matters. */
    { struct sigaction sa0; memset(&sa0,0,sizeof sa0); sa0.sa_handler=mux_budget_alarm; sigemptyset(&sa0.sa_mask); sigaction(SIGUSR1,&sa0,NULL); }
    int lfd=open("append.lock", O_RDWR|O_CREAT, 0644);
    if(lfd<0){ fprintf(stderr,"[dlc w%d] no lock\n",w); return 1; }
    static unsigned char st[4096]; store_init(st);
    *(int*)((char*)st+40)=lfd;
    *(int*)((char*)st+36)=0xd9b4bef9;   /* magic */
    *(int*)((char*)st+28)=0;            /* cur_file_no=0 */
    *(int*)((char*)st+0)=-1;            /* no blk fd yet */
    static unsigned char buf[24<<20]; static unsigned char scratch[8<<20];
    unsigned cap=(unsigned)(sizeof scratch/32);
    char hp_[64]; snprintf(hp_,sizeof hp_,"/tmp/dlc_hdr_%d.dat",getpid());
    static unsigned char hst[64]; static unsigned char rec[112];
    int slot=slot0; long total=0; long stalled=0;
    int fd=-1; int held=-1;   /* index into live[]/claimed[] currently held, or -1 */
#define DLC_RELEASE() do{ if(held>=0){ claimed[held]=0; held=-1; } }while(0)
    for(;;){
        long lo=__sync_fetch_and_add(next_claim,(long)DLC_CHUNK_BLOCKS);
        if(lo>end_h){ if(fd>=0) close(fd); DLC_RELEASE(); break; }
        long hi=lo+DLC_CHUNK_BLOCKS-1; if(hi>end_h) hi=end_h;
        if(dlc_chunk_all_present(lo,hi)) continue;

        int hfd=open(hp_,O_RDWR|O_CREAT|O_TRUNC,0644);
        if(hfd<0){ if(fd>=0) close(fd); DLC_RELEASE(); break; }
        *(int*)((char*)hst+0)=hfd; *(long*)((char*)hst+8)=0;
        long n=0; FILE* mf=fopen("headers.dat","rb");
        for(long k=lo;k<=hi;k++){
            if(mf && fseek(mf,k*112,SEEK_SET)==0 && fread(rec,1,112,mf)==112){ if(hst_append(hst,rec,rec+80)<0) break; n++; }
            else break;
        }
        if(mf) fclose(mf);
        if(n<=0){ close(hfd); if(fd>=0) close(fd); DLC_RELEASE(); break; }

        int guard=0, chunk_ok=0;
        for(;;){
            if(fd<0){
                int ok=0;
                for(int a=0;a<nlive && !ok;a++){
                    int idx=(slot+a)%nlive;
                    if(banned[idx]) continue;   /* already proved itself useless this run */
                    const char* cand=live[idx];
                    int cp2=0; unsigned ip=0; if(!dlc_parse_peer(cand, &ip, &cp2)) continue;
                    /* claim this peer for exclusive use FIRST -- a real peer
                     * IP is only worth as much as its own bandwidth, so two
                     * workers sharing one starves both instead of using a
                     * second distinct peer that's sitting idle. */
                    if(!__sync_bool_compare_and_swap(&claimed[idx],0,1)) continue;
                    /* the entry's own port when it has one; the chain default is only a
                     * fallback for bare addresses (same rule as the header tries) */
                    int fdc=tcp_connect_ip(ip,(unsigned short)htons((unsigned short)(cp2 ? cp2 : g_chainp->default_port)));
                    if(fdc<0){ claimed[idx]=0; continue; }
                    struct timeval tv; tv.tv_sec=20; tv.tv_usec=0; setsockopt(fdc,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
                    if(node_handshake(fdc)==1 && peer_has_witness(cand)){
                        fd=fdc; ok=1; held=idx; slot=(idx+1)%nlive;
                        mystat->held_idx=idx;   /* so the parent can ban THIS peer on early-kill */
                        strncpy((char*)mystat->peer,cand,63);
                        /* fresh peer -- the displayed chunks/blocks/guard
                         * must reflect THIS connection, not accumulate
                         * across every peer this worker slot has ever
                         * cycled through (that read as "the new peer has
                         * already done N chunks" when really the old, now-
                         * dropped peer did them). */
                        mystat->chunks=0; mystat->blocks=0; mystat->guard=0;
                    }
                    else { claimed[idx]=0; close(fdc); }
                }
                if(!ok){
                    stalled++;
                    /* Could not connect to ANY unbanned peer. Bans are an
                     * optimisation, not a correctness property, so lift them
                     * rather than stall the download: a slow peer beats no
                     * peer, and a permanently-empty pool is how this used to
                     * spin, printing "peers exhausted" 20,495 times while the
                     * sync went nowhere. Amnesty is idempotent and cheap. */
                    if(stalled==10 || stalled==25){
                        int lifted=0;
                        for(int q=0;q<nlive;q++) if(banned[q]){ banned[q]=0; lifted++; }
                        if(lifted) fprintf(stderr,"[dlc w%d] no reachable peer -- amnesty, un-banned %d peer(s)\n", w, lifted);
                    }
                    if(stalled>40){ fprintf(stderr,"[dlc w%d] peers exhausted\n",w); break; }
                    sleep(3); slot=(slot+7)%(nlive>0?nlive:1); continue;
                }
                stalled=0;
            }
            /* budget the WHOLE transfer's wall-clock, not just the socket
             * read timeout -- a peer trickling a few KB/s keeps resetting
             * SO_RCVTIMEO on every partial read and would never trip that,
             * but is still worth dropping in favor of a fresh peer from the
             * pool. Same bounded-call pattern as do_outbound_sync_bounded
             * above: on budget expiry the socket may hold a partial frame,
             * so it is NOT safe to keep using it -- drop unconditionally.
             * SIGUSR1 gets the SAME handler as SIGALRM: the parent's status
             * loop already samples this worker's real /proc/<pid>/io
             * bandwidth every 10s for the live display, so it can spot an
             * OBVIOUSLY dead connection (sustained near-zero, not just slow)
             * well before the flat wall-clock budget would fire, and signal
             * this worker to abandon early instead of sitting out the full
             * DLC_CHUNK_BUDGET_SECS on a peer that was never going anywhere. */
            struct sigaction sa, old; memset(&sa,0,sizeof sa);
            sa.sa_handler=mux_budget_alarm; sigemptyset(&sa.sa_mask);
            sigaction(SIGALRM,&sa,&old);   /* SIGUSR1 already registered for this worker's whole life, above */
            mux_sync_budget_fired=0;
            alarm(DLC_CHUNK_BUDGET_SECS);
            long r=node_ibd_blocks_s(fd, st, hst, lo, n, buf, sizeof buf, scratch, cap);
            alarm(0); sigaction(SIGALRM,&old,NULL);
            store_reload(st);
            guard++;
            if(mux_sync_budget_fired){
                mystat->timeouts++;   /* covers both the flat budget AND an early-kill signal -- same code path */
                char lastbw[16]; dlc_fmt_rate(lastbw,sizeof lastbw,mystat->last_bw_bps);
                fprintf(stderr,"[dlc w%d] %s dead weight (last measured %s, completed %ld chunk(s)/%ld block(s) on this peer); dropping for a fresh peer\n",
                        w, mystat->peer, lastbw, mystat->chunks, mystat->blocks);
                close(fd); fd=-1; DLC_RELEASE();
                slot=(slot+1)%(nlive>0?nlive:1);
                if(guard>400){ fprintf(stderr,"[dlc w%d] reconnect budget [%ld,%ld]\n",w,lo,hi); break; }
                continue;   /* r is unreliable after an EINTR'd read; don't trust it */
            }
            if(r>=0){ chunk_ok=1; break; }   /* clean completion; KEEP fd (and claim) for the next chunk */
            close(fd); fd=-1; DLC_RELEASE();
            slot=(slot+1)%(nlive>0?nlive:1);
            if(guard>400){ fprintf(stderr,"[dlc w%d] reconnect budget [%ld,%ld]\n",w,lo,hi); break; }
        }
        close(hfd);
        if(chunk_ok){
            total+=n; __sync_fetch_and_add(done_count,n);
            mystat->chunks++; mystat->blocks+=n; mystat->guard+=guard;
        } else fprintf(stderr,"[dlc w%d] chunk [%ld,%ld] ABANDONED\n",w,lo,hi);
    }
    fprintf(stderr,"[dlc w%d] done: blocks=%ld\n", w, total);
    close(lfd);
    return 0;
}
#undef DLC_RELEASE

/* orchestrator: bootstrap peers -> header phase -> compute the combined
 * hole+extend span -> a fast non-blocking-connect liveness probe (same
 * technique already used above in serve_download_worker) -> fork
 * >=min_workers chunk-claiming children -> wait -> return blocks written.
 * Self-throttling: if the archive is already caught up, the span/probe/
 * fork overhead is cheap (all local disk reads, no network), so it's safe
 * to call unconditionally on every boot -- this is what makes the node
 * self-healing without any external tooling. */
/* one non-blocking dial+poll round over pool[from..from+ntry), appending any
 * live+handshaked candidates into live[]/*nlive (capped at cap). Never
 * blocks longer than wait_ms regardless of how many candidates in this
 * batch are dead or black-holed -- poll() naturally times out, unlike a
 * blocking connect() to an unreachable host. Same technique as the parallel
 * dial in serve_download_worker above; caps the batch at MUX_MAX_OUT*3 (24)
 * per round to match its proven behavior (trying the WHOLE pool at once in
 * one round measurably tanks the success rate -- observed 1/140 live).
 * Returns how many were promoted this round. */
static int dlc_probe_round(char pool[][DL_POOL_SLOT], int from, int ntry,
                           char live[][64], int* nlive, int cap, int wait_ms){
    if(ntry>MUX_MAX_OUT*3) ntry=MUX_MAX_OUT*3;
    static int cfd[MUX_MAX_OUT*3];
    int nc=0;
    for(int k=0;k<ntry;k++){
        int i=from+k;
        if(dialer_proxy_configured()){ cfd[nc++]=-1; continue; }   /* would bypass the proxy */
        int pport = 0; unsigned ip = pool_ipv4(pool[i], &pport);
        if(!ip){ cfd[nc++]=-1; continue; }        /* not a dialable IPv4 candidate */
        int fd=socket(AF_INET,SOCK_STREAM,0);
        if(fd<0){ cfd[nc++]=-1; continue; }
        int fl=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
        struct sockaddr_in sa; memset(&sa,0,sizeof sa); sa.sin_family=AF_INET;
        sa.sin_addr.s_addr=ip; sa.sin_port=(unsigned short)htons((unsigned short)g_chainp->default_port);
        int rc=connect(fd,(struct sockaddr*)&sa,sizeof sa);
        if(rc!=0 && errno!=EINPROGRESS){ close(fd); cfd[nc++]=-1; continue; }
        cfd[nc++]=fd;
    }
    struct pollfd pol[MUX_MAX_OUT*3]; int nf=0;
    static char prdy[MUX_MAX_OUT*3]; static int pmap[MUX_MAX_OUT*3];
    for(int k=0;k<nc;k++){ if(cfd[k]<0) continue; pol[nf].fd=cfd[k]; pol[nf].events=POLLOUT; pol[nf].revents=0; prdy[nf]=0; pmap[nf]=k; nf++; }
    /* Poll in ROUNDS, not once. poll() returns as soon as the FIRST socket is
     * ready, so a single fast peer made every other candidate in the batch
     * look un-ready and it was closed as dead.
     *
     * The tell is in the historical logs: "84 confirmed-live (86 probe
     * rounds)" and "11 confirmed-live (11 probe rounds)" -- almost exactly ONE
     * peer per round, both times, regardless of batch width. This probe has
     * never measured liveness; it has measured how many times it was called.
     *
     * That matters beyond the peer count: the "book is stale, only ~4% still
     * answer" belief recorded in the addr_replenish comment below, and the
     * gossip that compensates for it, are both conclusions drawn from THIS
     * number. Widening the batch (MUX_MAX_OUT 8 -> 64, so ntry 24 -> 192) did
     * not cause the bug, it made it obvious: losing 23 per round is quiet,
     * losing 191 is not. */
    if(nf>0){
        long long pr_end;
        { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
          pr_end = ts.tv_sec*1000LL + ts.tv_nsec/1000000LL + wait_ms; }
        for(;;){
            long long pr_now;
            { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
              pr_now = ts.tv_sec*1000LL + ts.tv_nsec/1000000LL; }
            int left = (int)(pr_end - pr_now);
            if(left <= 0) break;
            int r = poll(pol,nf,left);
            if(r <= 0) break;
            int pending = 0;
            for(int j=0;j<nf;j++){
                if(pol[j].fd < 0) continue;
                if(pol[j].revents & (POLLOUT|POLLERR|POLLHUP)){
                    if(pol[j].revents & POLLOUT) prdy[j] = 1;
                    pol[j].fd = -pol[j].fd;      /* poll() skips negative fds */
                } else pending++;
                pol[j].revents = 0;
            }
            if(!pending) break;
        }
        for(int j=0;j<nf;j++) if(pol[j].fd < 0) pol[j].fd = -pol[j].fd;   /* restore */
    }
    int got=0;
    for(int k=0;k<nc && *nlive<cap;k++){
        if(cfd[k]<0) continue;
        int ready=0;
        for(int j=0;j<nf;j++) if(pmap[j]==k){ ready=prdy[j]; break; }
        if(!ready){ close(cfd[k]); continue; }
        int soerr=0; socklen_t sl=sizeof soerr;
        if(getsockopt(cfd[k],SOL_SOCKET,SO_ERROR,&soerr,&sl)<0||soerr!=0){ close(cfd[k]); continue; }
        strncpy(live[*nlive],pool[from+k],63); (*nlive)++; got++;
        close(cfd[k]);
    }
    return got;
}

/* read one named field out of /proc/<pid>/io ("rchar:", "write_bytes:", ...).
 * Returns -1 if unavailable (process already gone, field not found, or a
 * non-Linux host without /proc). */
static long dlc_proc_iofield(pid_t pid, const char* field){
    char path[64]; snprintf(path,sizeof path,"/proc/%d/io",(int)pid);
    FILE* f=fopen(path,"r"); if(!f) return -1;
    char line[128]; long v=-1; size_t flen=strlen(field);
    while(fgets(line,sizeof line,f)){
        if(!strncmp(line,field,flen)){ v=atol(line+flen); break; }
    }
    fclose(f);
    return v;
}
/* total bytes a process has read (network + disk + everything -- for a
 * dlc_worker child this is dominated by socket reads), from the kernel's own
 * per-process I/O accounting. Real measured throughput, not an estimate:
 * block-level chunk counters miss a worker that's mid-transfer on a large
 * chunk, but this doesn't. NOTE: this is network-received bytes, NOT the
 * same as disk bytes written -- index.dat's sparse-file block allocation,
 * filesystem journaling, and local header/index re-reads all add disk I/O
 * that never shows up here, which is why "aggregate" read-rate has run
 * measurably behind actual `du` growth on this archive. See dlc_proc_wbytes
 * for the disk-write-side counterpart. */
static long dlc_proc_rchar(pid_t pid){ return dlc_proc_iofield(pid,"rchar:"); }
/* actual bytes written to storage (kernel block-I/O accounting, not just
 * buffered writes) -- the disk-side counterpart to dlc_proc_rchar, so the
 * status log can show network-received and disk-written rates separately
 * instead of one figure trying to represent both. */
static long dlc_proc_wbytes(pid_t pid){ return dlc_proc_iofield(pid,"write_bytes:"); }

/* human-scaled "N.NUNIT/s" into buf (>=16 bytes). */
static void dlc_fmt_rate(char* buf, size_t cap, double bytes_per_sec){
    const char* unit="B"; double v=bytes_per_sec;
    if(v>=1024.0*1024.0*1024.0){ v/=1024.0*1024.0*1024.0; unit="GB"; }
    else if(v>=1024.0*1024.0){ v/=1024.0*1024.0; unit="MB"; }
    else if(v>=1024.0){ v/=1024.0; unit="KB"; }
    snprintf(buf,cap,"%.1f%s/s",v,unit);
}
/* same unit scaling as dlc_fmt_rate but for a plain total, no "/s" suffix --
 * GB tier matters here especially: a multi-hour catch-up at a few MB/s
 * aggregate crosses 1GB cumulative within the first hour or two. */
static void dlc_fmt_bytes(char* buf, size_t cap, double bytes){
    const char* unit="B"; double v=bytes;
    if(v>=1024.0*1024.0*1024.0){ v/=1024.0*1024.0*1024.0; unit="GB"; }
    else if(v>=1024.0*1024.0){ v/=1024.0*1024.0; unit="MB"; }
    else if(v>=1024.0){ v/=1024.0; unit="KB"; }
    snprintf(buf,cap,"%.1f%s",v,unit);
}
/* HH:MM:SS (HH unbounded, not clamped to 24) since catchup_start -- so "how
 * long has this dl_catchup run been going" is readable straight from the
 * log instead of needing `ps -o etime` on the process from outside. */
static void dlc_fmt_elapsed(char* buf, size_t cap, long secs){
    if(secs<0) secs=0;
    long h=secs/3600, m=(secs%3600)/60, s=secs%60;
    snprintf(buf,cap,"%ld:%02ld:%02ld",h,m,s);
}

/* full sequential scan of index.dat: highest non-zero height (tip, -1 if
 * none) and count of non-zero records in [0,tip]. Two genuinely different
 * numbers matter here and are easy to conflate (this bit me in conversation
 * earlier): "% of the range reached so far that's actually filled" (gap-
 * completeness) vs "% of the WHOLE real chain that's done" (overall
 * progress) -- the former can read 99%+ while the latter is still under
 * 60%. A fresh scan every status tick (rather than tracking incrementally)
 * is simplest and correct even though workers claim scattered, non-
 * sequential chunks -- cheap on local NVMe even at 900k+ records. */
/* asm/bitcoin_idxscan.asm:idxscan_progress -- ~4x faster (see
 * tests/bench_idxscan.c). */
static void dlc_scan_progress(long* out_tip, long* out_present){
    idxscan_progress(out_tip, out_present);
}

static long dl_catchup(const char* dir, int min_workers){
    (void)dir; /* CWD is already the data dir; kept for logging/API clarity */
    ab2_t* ab = addr_book();
    if(!ab){ fprintf(stderr,"[dlc] address book unavailable\n"); return 0; }
    long disc=dl_bootstrap(ab, (const char**)g_seed_hosts, g_n_seed_hosts);
    fprintf(stderr,"[dlc] discovered +%ld peers (book now %ld)\n", disc, (long)ab2_count(ab));

    static char pool[DLC_MAXPOOL][DL_POOL_SLOT];
    int npool = 0, ngood = 0, nadd = 0;
    if(g_cfg.connect_only){
        /* Core -connect: the pool IS the configured list. Nothing from the
         * book, nothing from peers.good -- an operator who pins the node to
         * two nodes must not find it downloading from two hundred. */
        for(int i=0;i<g_cfg.n_connect && npool<DLC_MAXPOOL;i++){
            char ipd[64];
            if(!dl_resolve1(g_cfg.connectn[i], ipd)){
                fprintf(stderr,"[dlc] connect=%s did not resolve\n", g_cfg.connectn[i]); continue; }
            strncpy(pool[npool],ipd,63); pool[npool][63]=0; npool++;
        }
        fprintf(stderr,"[dlc] connect= -- pool restricted to %d configured node(s)\n", npool);
    } else {
        /* Order is priority order. addnode entries are operator intent and
         * outrank everything; then peers that actually delivered blocks on a
         * previous run; then the book, which records only that an address was
         * SEEN. Duplicates are harmless (the probe just confirms one twice)
         * and claimed[] already stops two workers sharing a peer. */
        for(int i=0;i<g_cfg.n_addnode && npool<DLC_MAXPOOL;i++){
            char ipd[64];
            if(!dl_resolve1(g_cfg.addnode[i], ipd)) continue;
            strncpy(pool[npool],ipd,63); pool[npool][63]=0; npool++; nadd++;
        }
        ngood = dl_load_good_peers(pool+npool, DLC_MAXPOOL-npool);
        npool += ngood;
        {
            static char book[DLC_MAXPOOL][DL_POOL_SLOT];
            int nbook = dl_pool_from_book(ab, book, DLC_MAXPOOL);
            for(int i=0;i<nbook && npool<DLC_MAXPOOL;i++){
                int dup=0;
                for(int j=0;j<npool;j++) if(!strcmp(book[i],pool[j])){ dup=1; break; }
                if(dup) continue;
                strncpy(pool[npool],book[i],63); pool[npool][63]=0; npool++;
            }
        }
    }
    if(nadd)  fprintf(stderr,"[dlc] %d addnode peer(s) tried first\n", nadd);
    if(ngood) fprintf(stderr,"[dlc] %d known-good peer(s) from a previous run tried first\n", ngood);
    fprintf(stderr,"[dlc] %d candidate peer(s) in pool\n", npool);
    if(npool<=0){ fprintf(stderr,"[dlc] no peers discovered; skipping catch-up\n"); return 0; }

    /* liveness probe: several bounded non-blocking-dial rounds (see
     * dlc_probe_round) instead of one shot, targeting a decently deep
     * confirmed-live pool (>= min_workers*3) before we ever rely on it --
     * real Bitcoin peers often take longer than one short poll to complete
     * a handshake (serve_download_worker's own gradual background leg-fill
     * exists for the same reason), and everything downstream of this
     * (dlc_headers, dlc_worker) deliberately only dials CONFIRMED entries,
     * so under-populating `live[]` here directly costs catch-up depth. */
    static char live[DLC_MAXPOOL][DL_POOL_SLOT]; int nlive=0;
    {
        /* Target a deep live pool: workers*3 was sized before peers could be
         * banned, and left no headroom -- evicting duds then starved the
         * downloader outright. Aim for 6x so eviction has room to work. */
        int want = min_workers*6; if(want>npool) want=npool;
        int from=0, rounds=0;
        /* no arbitrary round cap: keep probing until either `want` is hit or
         * the WHOLE discovered pool has been tried (from<npool already
         * guarantees termination -- a fixed round cap here previously cut
         * the probe off after covering only ~40% of a 481-peer pool,
         * settling for 10 live peers when the target was 48). */
        while(nlive<want && from<npool){
            int ntry=npool-from; if(ntry>MUX_MAX_OUT*3) ntry=MUX_MAX_OUT*3;
            dlc_probe_round(pool, from, ntry, live, &nlive, DLC_MAXPOOL, 8000);
            from+=ntry; rounds++;
        }
        fprintf(stderr,"[dlc] %d confirmed-live peer(s) (%d probe round(s))\n", nlive, rounds);

        /* Ask real peers for more peers. Until now the book only ever grew
         * from DNS seeds at boot, so it decayed as peers died and there was
         * no recovery from exhausting it -- three of the last four boots
         * discovered "+0 peers" against a 1,974-entry book that was only ~4%
         * reachable. A single peer can return up to 1,000 addresses, so we
         * stop as soon as we have a useful haul rather than asking everyone.
         * Best-effort: any failure just leaves the book as it was. */
        /* ONLY when we are actually short. The book is not small -- it is
         * stale: ~1,974 entries of which only ~4% still answer. Fresh
         * addresses from a live peer have a far better hit rate, but asking
         * costs real time (a peer delays its reply well past the socket
         * timeout, so a useful window is ~20s per peer). A node that already
         * probed a healthy live set should pay none of that. Below half the
         * target, top up; otherwise skip entirely. */
        if(g_cfg.connect_only && nlive>0 && nlive < want/2){
            fprintf(stderr,"[addr] only %d live peer(s) but connect= is set -- not asking for more\n", nlive);
        }
        else if(nlive>0 && nlive < want/2){
            fprintf(stderr,"[addr] only %d live peer(s) (target %d) -- asking peers for more\n", nlive, want);
            addr_replenish(ab, live, nlive, 3 /* ask at most 3 */, 20 /* seconds each */, 400);
        }
    }
    if(nlive<=0){ fprintf(stderr,"[dlc] no live peers; skipping catch-up\n"); return 0; }
    int nw = min_workers; if(nlive<nw) nw=nlive; if(nw<1) nw=1; if(nw>64) nw=64;

    long hdr_len = dlc_headers(live, nlive);
    if(hdr_len<=0){ fprintf(stderr,"[dlc] header phase failed; skipping catch-up\n"); return 0; }

    long start_h, end_h;
    if(!dlc_span(hdr_len, &start_h, &end_h)){
        fprintf(stderr,"[dlc] archive already complete through %ld\n", hdr_len-1);
        return 0;
    }
    fprintf(stderr,"[dlc] span [%ld,%ld] (%ld heights)\n", start_h, end_h, end_h-start_h+1);

    /* pre-size index.dat GROW-ONLY, create append.lock */
    {
        int ix=open("index.dat", O_RDWR|O_CREAT, 0644);
        if(ix<0){ fprintf(stderr,"[dlc] open index.dat failed: %s\n", strerror(errno)); return 0; }
        struct stat sb; long cur=0; if(fstat(ix,&sb)==0) cur=sb.st_size;
        long need=(end_h+1)*48; if(need<cur) need=cur;
        if(ftruncate(ix,need)){ fprintf(stderr,"[dlc] ftruncate index.dat failed: %s\n", strerror(errno)); close(ix); return 0; }
        close(ix);
        int lf=open("append.lock", O_RDWR|O_CREAT, 0644); if(lf>=0) close(lf);
    }

    volatile long* next_claim=mmap(NULL,sizeof(long),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    volatile long* done_count=mmap(NULL,sizeof(long),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    volatile dlc_stat_t* stats=mmap(NULL,sizeof(dlc_stat_t)*(size_t)nw,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    /* one claim flag per live[] peer -- __sync_bool_compare_and_swap makes
     * "pick an unclaimed peer" atomic across all forked workers, so no two
     * workers ever share one peer's bandwidth while a distinct live peer
     * sits unused. */
    volatile int* claimed=mmap(NULL,sizeof(int)*(size_t)nlive,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    /* Peers evicted for sustained uselessness are banned for the REST OF THE
     * RUN. Without this the replacement draw is memoryless: a worker killed
     * for trickling at 5KB/s could immediately be handed the same IP again,
     * and with most of the pool being duds that is what kept happening. */
    volatile int* banned=mmap(NULL,sizeof(int)*(size_t)nlive,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(next_claim==MAP_FAILED || done_count==MAP_FAILED || stats==MAP_FAILED || claimed==MAP_FAILED || banned==MAP_FAILED){ fprintf(stderr,"[dlc] mmap failed: %s\n", strerror(errno)); return 0; }
    /* MAP_ANONYMOUS zero-fills, so held_idx would default to 0 -- and a
     * worker that never managed to connect would then make the parent ban
     * live[0], a peer that may be perfectly good. Mark "holding nothing"
     * explicitly. */
    for(int i=0;i<nw;i++) stats[i].held_idx = -1;
    *next_claim=start_h; *done_count=0;
    /* MAP_ANONYMOUS pages come zeroed, so every stats[w].peer/chunks/blocks/
     * guard and every claimed[i] starts at "" / 0 / 0 / 0 / 0 -- no explicit
     * init needed. */

    time_t catchup_start=time(NULL); /* for the elapsed-time display in the status loop below */
    pid_t kids[64]; pid_t opid[64];
    for(int w=0;w<nw;w++){
        pid_t p=fork();
        if(p==0){ _exit(dlc_worker(w, end_h, live, nlive, w, next_claim, done_count, &stats[w], claimed, banned)); }
        kids[w]=p; opid[w]=p;
    }
    /* live peer-stats table: poll every 10s instead of blocking silently on
     * waitpid, so "what are our peers doing right now" is visible in the log
     * for the whole catch-up, not just a one-line summary at the very end.
     * Bandwidth comes from each worker's OWN /proc/<pid>/io (real measured
     * bytes read), not the block/chunk counters -- a worker mid-transfer on
     * one large chunk shows 0 chunks for minutes even while actively
     * downloading at full speed, which the byte counter catches. */
    long prev_blocks[64]={0}; long prev_rchar[64]={0}; long prev_wbytes[64]={0}; int dead_ticks[64]={0};
    long nbanned=0;
    double cumulative_bytes=0.0;       /* running total network-received, across the whole call */
    double cumulative_write_bytes=0.0; /* running total actually written to disk, across the whole call */
    int alive=nw;
    while(alive>0){
        struct timespec ts={10,0}; nanosleep(&ts,NULL);
        if(g_shutdown_requested){
            /* incident 2026-09-01: this loop ignored SIGTERM and the stop hung
             * until a SIGKILL. Workers inherit the flag-only handler, so they
             * are told, given a moment, then killed. */
            fprintf(stderr,"[dlc] shutdown requested -- stopping %d worker(s)\n", alive);
            for(int w=0;w<nw;w++) if(kids[w]) kill(kids[w], SIGTERM);
            { struct timespec g={1,0}; nanosleep(&g,NULL); }
            for(int w=0;w<nw;w++) if(kids[w]){ int stt; if(waitpid(kids[w],&stt,WNOHANG)==0){ kill(kids[w], SIGKILL); waitpid(kids[w],&stt,0); } kids[w]=0; }
            alive=0; break;
        }
        alive=0;
        for(int w=0;w<nw;w++){
            if(kids[w]==0) continue;
            int stt; pid_t r=waitpid(kids[w],&stt,WNOHANG);
            if(r==0) alive++; else kids[w]=0;
        }
        {
            long cur_tip, present;
            dlc_scan_progress(&cur_tip, &present);
            long holes = cur_tip>=0 ? (cur_tip+1-present) : 0;
            double overall_pct = 100.0*(double)present/(double)(end_h+1);
            double span_pct = cur_tip>=0 ? 100.0*(double)present/(double)(cur_tip+1) : 0.0;
            char elapsed[16]; dlc_fmt_elapsed(elapsed,sizeof elapsed,(long)(time(NULL)-catchup_start));
            fprintf(stderr,"[dlc] == elapsed %s | overall: %ld/%ld stored (%.2f%% of real tip) | %ld holes in [0,%ld] reached so far (%.2f%% gap-free) ==\n",
                    elapsed, present, end_h+1, overall_pct, holes, cur_tip, span_pct);
        }
        fprintf(stderr,"[dlc] -- peer status (%d/%d worker(s) active) --\n", alive, nw);
        double tick_total_bytes=0.0, tick_total_write_bytes=0.0;
        for(int w=0;w<nw;w++){
            long b=stats[w].blocks; long blkrate=(b-prev_blocks[w])/10;
            long rc=kids[w]!=0 ? dlc_proc_rchar(opid[w]) : -1;
            long wc=kids[w]!=0 ? dlc_proc_wbytes(opid[w]) : -1;
            char bw[16]="--"; double byte_rate=-1.0;
            if(rc>=0){
                if(prev_rchar[w]>0){
                    double delta=(double)(rc-prev_rchar[w]);
                    tick_total_bytes+=delta;
                    byte_rate=delta/10.0;
                    dlc_fmt_rate(bw,sizeof bw,byte_rate);
                    stats[w].last_bw_bps=byte_rate; /* worker reads this to report why it got dropped */
                }
                prev_rchar[w]=rc;
            }
            if(wc>=0){
                if(prev_wbytes[w]>0) tick_total_write_bytes+=(double)(wc-prev_wbytes[w]);
                prev_wbytes[w]=wc;
            }
            char flag[48]="";
            if(kids[w]!=0 && byte_rate>=0.0){
                if(byte_rate<g_cfg.dead_weight_bps){
                    dead_ticks[w]++;
                    if(dead_ticks[w]>=g_cfg.dead_weight_ticks){
                        long bidx = stats[w].held_idx;
                        /* Three outcomes, and the log line has to say WHICH:
                         * this message read "peer BANNED" unconditionally,
                         * including on the min_usable floor path where no ban
                         * happens, so the log claimed bans that were never
                         * applied. */
                        const char* why = "kept";
                        if(bidx>=0 && bidx<nlive && node_config_is_manual(live[bidx])){
                            /* addnode/connect peers are MANUAL connections:
                             * Core never auto-evicts them, and banning one
                             * would drop a peer the operator pinned -- or,
                             * under connect=, empty the pool outright. Rotate
                             * the worker off it, but leave it selectable. */
                            why = "manual";
                        }
                        else if(bidx>=0 && bidx<nlive && !banned[bidx]){
                            int usable=0; for(int q=0;q<nlive;q++) if(!banned[q]) usable++;
                            if(usable > g_cfg.min_usable_peers){ banned[bidx]=1; nbanned++; why="BANNED"; }
                            /* else: at the floor -- still kill the worker so it
                             * rotates to a different peer, but keep this one
                             * selectable. A slow peer beats no peer. */
                            else why = "floor";
                        }
                        kill(opid[w],SIGUSR1);
                        dead_ticks[w]=0;
                        snprintf(flag,sizeof flag," [early-kill, last %s, peer %s]",bw,why);
                    }
                } else dead_ticks[w]=0;
            }
            /* live progress toward THIS worker's next early-kill -- updates
             * every 10s tick as dead_ticks climbs, so it's visible in real
             * time as a connection starts trending dead, not just after a
             * kill has already happened (a historical per-kill tally only
             * changes once a drop actually fires, which can take a while to
             * show up at all). Resets to nothing once healthy or just cut. */
            char dragbuf[32]="";
            if(dead_ticks[w]>0) snprintf(dragbuf,sizeof dragbuf," (Dragging: %d of %d)",dead_ticks[w],g_cfg.dead_weight_ticks);
            fprintf(stderr,"[dlc]   w%d %-21s chunks=%-4ld blocks=%-6ld (+%ld blk/s, %s)%s%s%s\n",
                    w, stats[w].peer[0]?(const char*)stats[w].peer:"(connecting)",
                    stats[w].chunks, b, blkrate, bw, kids[w]==0?" [done]":"", flag, dragbuf);
            prev_blocks[w]=b;
        }
        {
            cumulative_bytes+=tick_total_bytes;
            cumulative_write_bytes+=tick_total_write_bytes;
            char totbuf[16], aggbuf[16], cumbuf[16], wtotbuf[16], waggbuf[16], wcumbuf[16];
            dlc_fmt_bytes(totbuf,sizeof totbuf,tick_total_bytes);
            dlc_fmt_rate(aggbuf,sizeof aggbuf,tick_total_bytes/10.0);
            dlc_fmt_bytes(cumbuf,sizeof cumbuf,cumulative_bytes);
            dlc_fmt_bytes(wtotbuf,sizeof wtotbuf,tick_total_write_bytes);
            dlc_fmt_rate(waggbuf,sizeof waggbuf,tick_total_write_bytes/10.0);
            dlc_fmt_bytes(wcumbuf,sizeof wcumbuf,cumulative_write_bytes);
            /* two genuinely different numbers, shown separately rather than
             * conflated into one "aggregate": network-received (rchar) is
             * NOT the same as disk-written (write_bytes) -- index.dat's
             * sparse-block allocation, filesystem journaling, and local
             * header/index re-reads all add disk I/O the network figure
             * never sees, so disk growth normally runs ahead of it. */
            fprintf(stderr,"[dlc] -- network recv this tick: %s (%s) | total recv: %s || disk write this tick: %s (%s) | total written: %s --\n",
                    totbuf,aggbuf,cumbuf,wtotbuf,waggbuf,wcumbuf);
            /* the per-tick numbers above are a noisy 10s snapshot -- this is
             * the stable figure: total bytes / total elapsed time since
             * dl_catchup started, so it settles down over the run instead
             * of bouncing with whichever peers happen to be fast or slow
             * in any given 10s window. */
            long elapsed_secs=(long)(time(NULL)-catchup_start); if(elapsed_secs<1) elapsed_secs=1;
            char avgrbuf[16], avgwbuf[16];
            dlc_fmt_rate(avgrbuf,sizeof avgrbuf,cumulative_bytes/(double)elapsed_secs);
            dlc_fmt_rate(avgwbuf,sizeof avgwbuf,cumulative_write_bytes/(double)elapsed_secs);
            fprintf(stderr,"[dlc] -- peers banned this run: %ld of %d --\n", nbanned, nlive);
    fprintf(stderr,"[dlc] -- average since start: %s recv, %s write --\n",avgrbuf,avgwbuf);
        }
    }
    long total=*done_count;
    /* Remember who actually produced blocks. A peer that delivered is worth
     * trying first next boot; the address book alone only records that an IP
     * was once seen, which is why every restart re-probed ~2,000 aged entries
     * and rediscovered the same handful from scratch. Recorded from the live
     * stats, and only for peers with blocks>0 -- being reachable is not the
     * same as being useful.
     *
     * BUG FIX (2026-08-19): this block used to run AFTER the munmap(stats)
     * below, reading stats[w] through an already-unmapped pointer -- a real
     * use-after-unmap. Confirmed against a real production SIGSEGV: dmesg's
     * fault timestamp landed ~1.5s after the final "[dlc]" status tick, and
     * the "[dlc] catch-up done" line below never printed -- exactly what a
     * crash reading unmapped memory right after the loop exits looks like.
     * Must run BEFORE stats (and friends) are unmapped. */
    {
        static char good[64][DL_POOL_SLOT]; int ngood=0;
        for(int w=0; w<nw && ngood<64; w++){
            if(stats[w].blocks<=0) continue;
            const char* ip=(const char*)stats[w].peer;
            if(!ip[0]) continue;
            int dup=0; for(int j=0;j<ngood;j++) if(!strcmp(good[j],ip)){ dup=1; break; }
            if(dup) continue;
            strncpy(good[ngood],ip,63); good[ngood][63]=0; ngood++;
        }
        dl_save_good_peers(good, ngood);
    }
    munmap((void*)next_claim,sizeof(long)); munmap((void*)done_count,sizeof(long));
    munmap((void*)stats,sizeof(dlc_stat_t)*(size_t)nw);
    munmap((void*)claimed,sizeof(int)*(size_t)nlive);
    fprintf(stderr,"[dlc] catch-up done: %ld new blocks written\n", total);
    return total;
}

/* UTXO catch-up health: consecutive post-recovery failures, and the earliest
 * time we may retry. Zero streak == healthy. See the catch-up block below. */
static long      utxo_fail_streak  = 0;
static long long utxo_retry_at_ms  = 0;

/* ---- sendrawtransaction submission channel (worker side) ------------------
 * The RPC parent stages a raw tx into g_node_status->tx_submit_* and bumps
 * tx_submit_seq; the worker picks it up at the top of its loop (see below),
 * validates + mempool-accepts + relays it to its peer legs, and acks. The
 * mempool + UTXO snapshot are lazy-initialized on the first submission so the
 * one-time utxo_lsm_reload cost is never paid during normal sync. */
extern int  tx_dispatch_init(void);
extern int  tx_policy_init(void);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern int  txsub_accept_and_relay(void* mp_area, const unsigned char* tx, unsigned long len,
                                   const int* peer_fds, int n_fds,
                                   char* reason, unsigned long rcap, int* relayed_out);
#define TXSUB_MP_SLOTS 1024
static unsigned char txsub_mp_area[40 + TXSUB_MP_SLOTS*48 + 8];
static unsigned char txsub_mp_blob[2u<<20];
static int           txsub_ready = 0;   /* 0 uninit, 1 ready, -1 init failed */
static unsigned long long txsub_last_seq = 0;
static unsigned long long ctl_last_seq = 0;
static unsigned long long blksub_last_seq = 0;

/* The pool the worker's accepts land in: the cross-process SHARED pool
 * (mempool_configure, pre-fork) when it exists, else the private fallback.
 * Until 2026-08-26 this was unconditionally the private txsub_mp_area --
 * which meant a sendrawtransaction accepted here was INVISIBLE to the
 * parent's getrawmempool/getmempoolinfo (they read mp_ext_area via
 * rpc_mempool_hooks below): the submission path predates the shared pool
 * and was never re-pointed at it. The asm serve children already prefer
 * mp_ext_area (bitcoin_serve.asm's .mp_external); this makes the worker
 * consistent with them. */
static void* txsub_pool(void){
    extern void* mp_ext_area;
    return mp_ext_area ? mp_ext_area : (void*)txsub_mp_area;
}

/* Lazy one-time init of the worker's tx-accept path. Returns 1 ready, 0 not. */
static int txsub_worker_ready(void){
    extern void* mp_ext_area;
    if (txsub_ready) return txsub_ready == 1;
    if (!tx_dispatch_init() || !tx_policy_init()){ txsub_ready = -1; return 0; }
    /* the shared pool was mpool_init'ed pre-fork (mp_ext_inited=1); only
     * the private fallback still needs its init here */
    if (!mp_ext_area)
        mpool_init(txsub_mp_area, TXSUB_MP_SLOTS, txsub_mp_blob, sizeof txsub_mp_blob);
    txsub_ready = 1;
    return 1;
}

/* ==== submitpackage: validate a package, then commit it =====================
 * Core's shape, reduced to what this node can honestly do.
 *
 * TWO PASSES, and the order matters. Pass 1 is a DRY RUN over the package
 * with the in-package overlay installed, so a child can resolve a parent that
 * is not in the mempool yet and every member's real fee and vsize become
 * known WITHOUT inserting anything. Only then is the package feerate known,
 * and only then can pass 2 commit.
 *
 * Doing it the other way round -- insert optimistically, then check the
 * aggregate -- would mean removing transactions that should never have been
 * accepted, and a failure partway through that removal leaves the mempool
 * holding a transaction below the floor. The dry run costs a second
 * validation pass and buys the property that nothing enters the pool until
 * the whole package is known to be acceptable.
 *
 * A member may only be rescued by the package for the TWO fee reasons Core
 * treats as reconsiderable ("min relay fee not met", "mempool min fee not
 * met"). Anything else -- invalid, non-standard, conflicting -- is final: no
 * amount of fee from a child makes an invalid parent valid.
 *
 * Returns 1 if the whole package was accepted, 0 otherwise (per-transaction
 * results are published in the shared block either way).
 *
 * With tx_submit_test set this stops after pass 1 and commits nothing --
 * which is precisely what testmempoolaccept on an array means. Core applies
 * package policy to a multi-transaction testmempoolaccept, and running the
 * SAME dry run the real submission runs is the only way the answer can be
 * trusted: a separate "test" implementation is a second set of rules that
 * will drift from the first. Until this existed, testmempoolaccept checked
 * each member against the mempool as it stood, so a child spending an
 * in-array parent was reported as missing-inputs. */
static int txsub_package(char* msg, unsigned long mcap){
    extern int mpol_package_well_formed(const unsigned char* const*, const unsigned long*,
                                        int, unsigned char*, unsigned long long*, const char**);
    extern void mpol_package_fee_context(unsigned long long, unsigned long long);
    extern void mpol_package_context(const unsigned char* const*, const unsigned long*,
                                     const unsigned char*, int);
    extern void txacc_package_overlay(const unsigned char* const*, const unsigned long*,
                                      const unsigned char*, int);
    extern long tx_accept_test_reason(void*, const unsigned char*, const unsigned char*,
                                      unsigned long, char*, unsigned long, unsigned long long*);
    extern int  tx_parse(void* info, const unsigned char* tx, unsigned long txlen);
    extern int  txacc_fee_reconsiderable(const char* reason);
    node_status_t* st = g_node_status;
    int n = st->tx_submit_pkg_n;
    if (n <= 0 || n > RPC_PKG_MAX){ snprintf(msg, mcap, "package-too-many-transactions"); return 0; }
    if (!txsub_worker_ready()){ snprintf(msg, mcap, "mempool init failed"); return 0; }

    /* walk the concatenated buffer; each transaction is self-delimiting */
    static const unsigned char* txs[RPC_PKG_MAX];
    static unsigned long lens[RPC_PKG_MAX];
    static unsigned char txids[RPC_PKG_MAX*32];
    { const unsigned char* p = (const unsigned char*)st->tx_submit_buf;
      const unsigned char* end = p + st->tx_submit_len;
      for (int i = 0; i < n; i++){
          unsigned char info[64];
          if (tx_parse(info, p, (unsigned long)(end - p)) != 1){
              snprintf(msg, mcap, "package-contains-unparseable-transaction"); return 0; }
          unsigned long long tl; memcpy(&tl, info, 8);
          if (tl == 0 || p + tl > end){
              snprintf(msg, mcap, "package-contains-unparseable-transaction"); return 0; }
          txs[i] = p; lens[i] = (unsigned long)tl; p += tl;
      }
      if (p != end){ snprintf(msg, mcap, "package-contains-unparseable-transaction"); return 0; } }

    st->pkg_replaced_n = 0;
    const int test_only = st->tx_submit_test ? 1 : 0;
    const char* why = "";
    static unsigned long long vsz[RPC_PKG_MAX];
    if (!mpol_package_well_formed(txs, lens, n, txids, vsz, &why)){
        snprintf(msg, mcap, "%s", why);
        /* Core's word for a member that never got its own verdict because the
         * package was rejected as a whole. */
        for (int i = 0; i < n; i++){
            st->pkg_result[i] = 0;
            snprintf((char*)st->pkg_reason[i], sizeof st->pkg_reason[i], "package-not-validated");
        }
        return 0;
    }

    /* ---- pass 1: dry run with the overlay, to learn the real fees -------- */
    unsigned long long tot_fee = 0, tot_vsize = 0;
    int all_ok = 1;
    int truc_violation = 0;
    /* membership as well as prevouts: the overlay lets a child RESOLVE its
     * parent, but TRUC has to know the parent is in the package at all. */
    mpol_package_context(txs, lens, txids, n);
    txacc_package_overlay(txs, lens, txids, n);
    for (int i = 0; i < n; i++){
        char r[128]; r[0] = 0; unsigned long long fee = 0;
        long rc = tx_accept_test_reason(txsub_pool(), txids + i*32, txs[i], lens[i],
                                        r, sizeof r, &fee);
        st->pkg_fee[i] = fee;
        st->pkg_vsize[i] = vsz[i];        /* BIP141 vsize, from the policy walker */
        if (rc == 1){
            st->pkg_result[i] = 1; st->pkg_reason[i][0] = 0;
            tot_fee += fee; tot_vsize += st->pkg_vsize[i];
        } else {
            int fee_only = txacc_fee_reconsiderable(r);
            st->pkg_result[i] = 0;
            snprintf((char*)st->pkg_reason[i], sizeof st->pkg_reason[i], "%s", r);
            if (fee_only){ tot_fee += fee; tot_vsize += st->pkg_vsize[i]; }
            else {
                all_ok = 0;      /* not something a package can rescue */
                /* A TRUC violation is a statement about the package's SHAPE,
                 * so Core rejects the package as a whole and gives no member
                 * an individual verdict. Reporting it against one member
                 * would say the others were fine, which is not what was
                 * decided. */
                if (!strcmp(r, "TRUC-violation")) truc_violation = 1;
            }
        }
    }
    txacc_package_overlay(NULL, NULL, NULL, 0);
    mpol_package_context(NULL, NULL, NULL, 0);

    if (!all_ok){
        mpol_package_fee_context(0, 0);
        st->pkg_eff_fee = tot_fee; st->pkg_eff_vsize = tot_vsize;
        if (truc_violation){
            snprintf(msg, mcap, "TRUC-violation");
            for (int i = 0; i < n; i++){
                st->pkg_result[i] = 0;
                snprintf((char*)st->pkg_reason[i], sizeof st->pkg_reason[i], "package-not-validated");
            }
            return 0;
        }
        snprintf(msg, mcap, "transaction failed");
        return 0;
    }

    /* testmempoolaccept: the answer is a dry run, but it needs BOTH passes.
     * Pass 1 runs without the package fee context -- it has to, since that
     * is where the aggregate is computed -- so a member that only clears the
     * floor because of the package is still marked rejected there. The real
     * submission overwrites that verdict in pass 2, under the context; a
     * test that stopped after pass 1 reported allowed:false for exactly the
     * transaction package validation exists to admit. So pass 2 runs here
     * too, as a test rather than a commit: same overlay, same fee context,
     * nothing inserted and nothing relayed. */
    if (test_only){
        st->pkg_eff_fee = tot_fee; st->pkg_eff_vsize = tot_vsize;
        int all_pass = 1;
        mpol_package_fee_context(tot_fee, tot_vsize);
        mpol_package_context(txs, lens, txids, n);
        txacc_package_overlay(txs, lens, txids, n);
        for (int i = 0; i < n; i++){
            char r[128]; r[0] = 0; unsigned long long fee = 0;
            long rc = tx_accept_test_reason(txsub_pool(), txids + i*32, txs[i], lens[i],
                                            r, sizeof r, &fee);
            if (rc == 1){
                st->pkg_result[i] = 1; st->pkg_reason[i][0] = 0; st->pkg_fee[i] = fee;
            } else {
                st->pkg_result[i] = 0;
                snprintf((char*)st->pkg_reason[i], sizeof st->pkg_reason[i], "%s", r);
                all_pass = 0;
            }
        }
        txacc_package_overlay(NULL, NULL, NULL, 0);
        mpol_package_context(NULL, NULL, NULL, 0);
        mpol_package_fee_context(0, 0);
        snprintf(msg, mcap, "success");   /* package-level verdict; per-member above */
        return all_pass;
    }

    /* ---- pass 2: commit, with the package feerate in effect -------------- */
    int committed = 1;
    mpol_package_fee_context(tot_fee, tot_vsize);
    mpol_package_context(txs, lens, txids, n);
    txacc_package_overlay(txs, lens, txids, n);
    for (int i = 0; i < n; i++){
        char r[128]; r[0] = 0; int relayed = 0;
        int rc = txsub_accept_and_relay(txsub_pool(), txs[i], lens[i],
                                        mux_out_fd, mux_n_out, r, sizeof r, &relayed);
        if (rc == 1){
            st->pkg_result[i] = 1; st->pkg_reason[i][0] = 0;
            walletnotify_tx(txs[i], (long)lens[i]);
            /* whatever THIS member displaced by RBF, folded into the
             * package-wide union Core reports at the top level. Read
             * immediately: the next member's accept overwrites it. */
            extern int mpol_last_replaced(unsigned char* out, int cap);
            unsigned char rep[RPC_PKG_REPLACED_MAX][32];
            int nrep = mpol_last_replaced((unsigned char*)rep, RPC_PKG_REPLACED_MAX);
            for (int k = 0; k < nrep; k++){
                int dup = 0;
                for (int q = 0; q < st->pkg_replaced_n; q++)
                    if (!memcmp((const void*)st->pkg_replaced[q], rep[k], 32)){ dup = 1; break; }
                if (dup) continue;
                if (st->pkg_replaced_n >= RPC_PKG_REPLACED_MAX) break;
                memcpy((void*)st->pkg_replaced[st->pkg_replaced_n++], rep[k], 32);
            }
        }
        else {
            st->pkg_result[i] = 0;
            snprintf((char*)st->pkg_reason[i], sizeof st->pkg_reason[i], "%s", r);
            committed = 0;
        }
    }
    /* ALWAYS cleared: a fee context left set would relax the floor for
     * ordinary single-transaction traffic, and an overlay left set would let
     * an unrelated transaction resolve against a package member. */
    txacc_package_overlay(NULL, NULL, NULL, 0);
    mpol_package_context(NULL, NULL, NULL, 0);
    mpol_package_fee_context(0, 0);

    st->pkg_eff_fee = tot_fee; st->pkg_eff_vsize = tot_vsize;
    snprintf(msg, mcap, "%s", committed ? "success" : "transaction failed");
    if (committed)
        fprintf(stderr, "[dl] submitpackage: %d tx accepted, package fee %llu sat over %llu vB\n",
                n, (unsigned long long)tot_fee, (unsigned long long)tot_vsize);
    return committed;
}

/* ---- far-behind trigger for the RUNNING node ---------------------------------
 * dl_catchup (headers-first + a pool of chunk workers) used to run only at
 * boot. A node that falls far behind while running -- a long outage, a slow
 * link, a boot that skipped it -- was left to the worker's legs, which fetch
 * one block per round trip on one peer at a time (~6 blocks/s measured on
 * signet, against ~50 for the parallel path on the same segment).
 *
 * The decision is a pure function so it can be tested without a network:
 *   - the best height any live outbound peer announced is at least
 *     DL_PARALLEL_GAP blocks past the archive tip (peers' start_height is
 *     what they claimed at handshake; a lying peer costs one wasted run of a
 *     downloader that verifies every block anyway);
 *   - the node is not apply-bound (backlog under DL_APPLY_FIRST_BACKLOG --
 *     otherwise downloading more is pointless, see APPLY FIRST);
 *   - at least DL_PARALLEL_REARM_S since the last run, so a peer set that
 *     keeps announcing heights it cannot serve does not spin us.
 * dl_catchup is synchronous and holds the worker for its duration; the legs
 * idle meanwhile and re-dial afterwards through the normal dead-slot path. */
#define TXSUB_FOLLOW_MS      30       /* worker lingers this long for the next tx submission after acking one */
#define TXSUB_ROTATION_BUDGET 2048   /* submissions serviced per rotation before the main loop runs again */
#define TXSUB_ROTATION_MS     1000   /* ...or this much wall time, whichever comes first */
static long long txsub_now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec*1000LL + ts.tv_nsec/1000000; }
#define DL_PARALLEL_GAP      2000L
#define DL_PARALLEL_REARM_S  600L
static int g_catchup_workers = 16;
static int dl_should_parallel_fetch(long archive_tip, long best_peer_height,
                                    long apply_backlog, long long now_s, long long last_run_s){
    if(best_peer_height <= 0 || archive_tip < 0) return 0;
    if(best_peer_height - archive_tip < DL_PARALLEL_GAP) return 0;
    if(apply_backlog > DL_APPLY_FIRST_BACKLOG) return 0;
    if(last_run_s && now_s - last_run_s < DL_PARALLEL_REARM_S) return 0;
    return 1;
}

static void serve_download_worker(const char* dir, const char* peers[], int pool_len, int out_port){
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, handle_shutdown_signal);
    signal(SIGINT, handle_shutdown_signal);
    /* Let the (multi-hour, during bulk replay) utxo_live_catchup loop see the
     * flag too, so SIGTERM stops it at the next block boundary instead of
     * systemd's 90s TimeoutStopSec SIGKILLing this worker mid-block --
     * which happened on every stop/restart until 2026-08-22 and once landed
     * between a block's WAL writes and its checkpoint (height 318148). */
    utxo_live_set_shutdown_flag(&g_shutdown_requested);
    { extern void rpc_node_set_shutdown_flag(const volatile sig_atomic_t*);
      rpc_node_set_shutdown_flag(&g_shutdown_requested); }   /* the mempool reload must yield to SIGTERM */
    /* Reload a fresh store state rather than inherit the parent's possibly-
     * stale in-memory idx_len/pos (fork COW is not safe for a growable
     * store -- see the unified_ibd comments on re-initialising per
     * process). NOTE: this process is NOT the sole block writer -- an
     * inbound serve child can also append a pushed block via .do_block; both
     * paths go through idxscan_append_locked (flock-guarded, atomic-height-
     * under-lock) so they can't collide, see that function's header comment
     * in bitcoin_idxscan.asm. */
    chdir(dir);
    /* ZMQ publisher binds HERE, in the worker, because a PUB socket's
     * subscriber fds are per-process and only this process can write to them.
     * Binding is non-fatal: a busy port must not stop the node syncing. */
    if (g_cfg.zmq_hashblock[0]) zmqpub_add("hashblock", g_cfg.zmq_hashblock);
    if (g_cfg.zmq_hashtx[0])    zmqpub_add("hashtx",    g_cfg.zmq_hashtx);
    if (g_cfg.zmq_rawblock[0])  zmqpub_add("rawblock",  g_cfg.zmq_rawblock);
    if (g_cfg.zmq_rawtx[0])     zmqpub_add("rawtx",     g_cfg.zmq_rawtx);
    /* Subscriber servicing runs on its own thread from here on, so no hot
     * loop in this worker ever walks the subscriber list (audit finding 8).
     * Non-fatal: if the thread cannot start, publishing still works and the
     * failure is logged -- only new subscribers would fail to connect. */
    { extern int zmqpub_start(void);
      if (zmqpub_active()) zmqpub_start(); }
    fprintf(stderr,"[dl] worker: reloading chain archive...\n");
    phase_timer_t dl_load_pt; phase_start(&dl_load_pt);
    if(store_reload(store_buf)!=1){ fprintf(stderr,"[dl] store_reload failed\n"); _exit(1); }
    fprintf(stderr,"[dl] worker: chain archive reloaded: tip=%d (%.2fs)\n",
            *(int*)(store_buf+24), phase_elapsed(&dl_load_pt));
    /* Single-writer live UTXO instance: this worker is the sole process that
     * ever calls utxo_lsm_put/del (inbound serve children only ever get a
     * read-only utxo_lsm_reload() snapshot). Non-fatal on failure -- block
     * sync/relay must keep working even if UTXO tracking can't start. */
    /* Verify the archive BEFORE any UTXO work. An append-only store cannot
     * notice that a mid-sync locator collapse made a peer re-serve from
     * genesis onto our tail, so a corrupt archive used to flow straight into
     * the UTXO set and be reported as success. Detect it (duplicate block
     * hashes are never valid on a real chain) and self-repair by truncating
     * to the last good height, letting normal sync re-download from there. */
    /* -reindex-chainstate: drop the persisted UTXO set so it is rebuilt from
     * the archive by the normal catch-up path. Runs BEFORE the archive scan
     * because the scan's own repair path may also drop it, and doing it twice
     * would be wasted work rather than harmful.
     *
     * ONE-SHOT. Core treats -reindex-chainstate as a request, not a mode, and
     * so must this: a node left with the flag in bitcoin.conf would wipe and
     * rebuild its UTXO set on EVERY restart -- hours of work, silently, with
     * the operator seeing only a slow start. The flag is consumed by writing
     * a marker, and refused on the next boot unless the operator removes it. */
    if (CFG_REINDEX_CHAINSTATE()){
        struct stat rst;
        if (stat("reindex_chainstate.done", &rst) == 0){
            fprintf(stderr,
                "[reindex] reindex-chainstate is still set in the config but was "
                "already carried out (reindex_chainstate.done exists) -- ignoring. "
                "Remove the option, and delete that marker if you truly want another rebuild.\n");
        } else {
            long dropped = archive_drop_utxo_state();
            fprintf(stderr,"[reindex] reindex-chainstate: dropped %ld UTXO state file(s); "
                           "the set will rebuild from the archive\n", dropped);
            FILE* mk = fopen("reindex_chainstate.done", "w");
            if (mk){ fprintf(mk, "reindex-chainstate carried out\n"); fclose(mk); }
            else fprintf(stderr,"[reindex] WARNING: could not write reindex_chainstate.done -- "
                                "the rebuild would repeat on the next restart\n");
        }
    }

    int archive_ok;
    {
        /* ONE scan: it walks every index record through a ~1M-entry hash
         * table, so this is not something to run twice per boot. */
        int av = archive_verify_and_repair(store_buf, 1 /* repair */);
        archive_ok = (av >= 0);
        if(av == 0){
            /* Truncated: any persisted UTXO applied-height now refers to
             * heights that no longer exist, so the UTXO set must be rebuilt
             * from scratch rather than resumed against a shorter chain. */
            long dropped = archive_drop_utxo_state();
            fprintf(stderr,"[dl] archive was repaired -- dropped %ld UTXO state file(s) so the set rebuilds from a clean slate\n", dropped);
        } else if(av < 0){
            fprintf(stderr,"[dl] archive INTEGRITY CHECK FAILED and was not repaired -- continuing WITHOUT live UTXO tracking\n");
        }
    }

    { extern void addrself_init(unsigned short, int);
      /* -discover=0, or an -onlynet that names only anonymity networks,
       * means this node must not learn or announce its clearnet address at
       * all: that address is exactly what running behind Tor hides. */
      { extern void txrelay_set_status(void*); txrelay_set_status(g_node_status); }
      { extern void zmq_pub_set_hwm(const int*); zmq_pub_set_hwm(g_cfg.zmq_hwm); }
      int may = g_cfg.listen && dialer_may_announce_clearnet();
      addrself_init((unsigned short)g_cfg.port, may);
      /* -externalip: the operator naming the reachable address directly */
      if (may && g_cfg.externalip[0]){
          bmc_addr_t ex;
          extern int addrself_set_external(const unsigned char*);
          if (bmc_addr_from_string(&ex, g_cfg.externalip) && ex.net == BMC_NET_IPV4 && addrself_set_external(ex.addr))
              fprintf(stderr,"[addrself] announcing the configured externalip %s:%u\n", g_cfg.externalip, (unsigned)g_cfg.port);
          else
              fprintf(stderr,"[config] externalip=%s is not a usable IPv4 address -- ignoring\n", g_cfg.externalip);
      }
      if (g_cfg.listen && !may)
          fprintf(stderr,"[addrself] not announcing our address: %s\n",
                  g_cfg.discover ? "onlynet excludes clearnet" : "discover=0"); }
    /* transports for the non-IPv4 networks (SOCKS5 to tor, SAM to i2pd).
     * Cheap and silent when nothing is configured. */
    dialer_init();
    { extern long undo_replay(long, bfi_undo_cb_t, void*);
      bfi_set_undo_replay(undo_replay);
      /* the address index consumes the same undo stream (spent prevout
       * scripts); registered the same way for the same link-layering reason */
      { extern void axt_set_undo_replay(long (*)(long, bfi_undo_cb_t, void*));
        axt_set_undo_replay(undo_replay); } }
    /* txid-index tail: establish coverage and close the gap between the
     * offline base build (or the previous run's tail) and the current tip.
     * After the archive verify -- a repair may have truncated heights the
     * tail would otherwise trust. No base index => logs once and disables. */
    if(archive_ok) txit_boot(store_buf);
    /* txo-spender index tail (Core -txospenderindex): same shape, same rules */
    if(archive_ok) tsp_boot(store_buf);
    /* live address index (EXTENSION -- Core has no such index): only when
     * the operator asked with addrindex=1 */
    if(archive_ok && g_cfg.addrindex) axt_boot(store_buf);

    fprintf(stderr,"[dl] worker: loading live UTXO state...\n");
    phase_timer_t utxo_init_pt; phase_start(&utxo_init_pt);
    g_in_utxo_reload = 1;                       /* see handle_shutdown_signal */
    int utxo_live_ok = archive_ok ? utxo_live_init(dir) : 0;
    g_in_utxo_reload = 0;
    /* Incident #48: mempool prevout resolution in THIS process must query
     * the live writer state, never a boot-latched snapshot of files the
     * writer keeps mutating (misses + garbage script lengths within
     * minutes). Injected before the first tx_accept use (the relay drain
     * and the sendrawtransaction channel both init lazily, later). Without
     * live UTXO tracking there is nothing coherent to resolve against, so
     * validation stays on its (unavailable-shaped) fallback and rejects. */
    if (utxo_live_ok){
        typedef long (*txacc_resolver_t)(const unsigned char*, unsigned long,
                                         unsigned long long*, unsigned long*,
                                         unsigned long*, const unsigned char**,
                                         unsigned long*);
        extern void tx_accept_set_resolver(txacc_resolver_t);
        extern long utxo_live_resolve(const unsigned char*, unsigned long,
                                      unsigned long long*, unsigned long*,
                                      unsigned long*, const unsigned char**,
                                      unsigned long*);
        extern void tx_accept_set_tip(long);
        tx_accept_set_resolver(utxo_live_resolve);
        tx_accept_set_tip(*(int*)(store_buf+24));
        /* Mined-tx pruning happens at the new-block choke point via
         * tx_accept_block_connect (Core removeForBlock: pool + policy graph
         * + conflict eviction + minfee decay gate). The earlier
         * utxo_live_set_mined_cb(serve_mined_prune) registration -- a plain
         * mpool_del that predated the policy-aware path by hours -- was
         * removed at the 2026-08-27 policy-parity merge as subsumed;
         * utxo_live.c keeps the (now unregistered) g_mined_cb plumbing. */

        /* Ghost-run repair BEFORE the coinstats index reads the set as truth
         * (it adopts its persisted state at the checkpoint height, or seeds
         * from a walk; either must see the repaired set). Catch-up used to do
         * this on its first call -- after the index had already looked. */
        { extern long utxo_live_recover_at_boot(void*);
          if (utxo_live_recover_at_boot(store_buf) < 0)
              fprintf(stderr, "[dl] WARNING: ghost-run repair failed at boot -- catch-up will refuse to apply\n"); }
        /* ---- coinstats index: continuous gettxoutsetinfo + a standing
         * cryptographic parity instrument. Observers feed it every coin
         * add/remove on the apply and reorg paths; it persists at the same
         * per-block durability point as the applied height. Seeding costs a
         * full walk (minutes) exactly once -- afterwards the persisted state
         * is adopted instantly on every clean boot. Seeded HERE, before the
         * catch-up loop starts writing, which is what makes the walk's
         * quiescence requirement hold by construction. */
        /* -coinstatsindex: the index has always run unconditionally. An
         * operator who does not want the write amplification had no way to
         * say so; now they do, and getindexinfo stops advertising an index
         * that is deliberately off. */
        if (!g_cfg.coinstatsindex)
            fprintf(stderr,"[dl] coinstatsindex=0 -- not maintaining the coin statistics index\n");
        else {
            typedef void (*coin_fn)(const unsigned char*, unsigned int,
                                    unsigned long long, unsigned long long,
                                    unsigned long long, const unsigned char*,
                                    unsigned long);
            extern void utxo_live_set_coinstats(coin_fn, coin_fn,
                                                void (*)(const char*), void (*)(long));
            extern void undo_set_coin_observer(coin_fn);
            extern void csi_on_add(const unsigned char*, unsigned int,
                                   unsigned long long, unsigned long long,
                                   unsigned long long, const unsigned char*, unsigned long);
            extern void csi_on_remove(const unsigned char*, unsigned int,
                                      unsigned long long, unsigned long long,
                                      unsigned long long, const unsigned char*, unsigned long);
            extern void csi_invalidate(const char*);
            extern void csi_commit(long);
            extern int  csi_boot(long);
            extern int  csi_seed_from_walk(void*, void*, long);
            extern void* utxo_live_lst(void);
            extern void* utxo_live_table(void);
            extern long utxo_live_applied_height(void);
            utxo_live_set_coinstats(csi_on_add, csi_on_remove, csi_invalidate, csi_commit);
            undo_set_coin_observer(csi_on_remove);
            long ah = utxo_live_applied_height();
            if (!csi_boot(ah))
                csi_seed_from_walk(utxo_live_lst(), utxo_live_table(), ah);
        }
    }
    if(!archive_ok) fprintf(stderr,"[dl] refusing to build UTXO state on an archive that failed verification\n");
    if(!utxo_live_ok) fprintf(stderr,"[dl] utxo_live_init failed -- continuing WITHOUT live UTXO tracking\n");
    else fprintf(stderr,"[dl] worker: live UTXO state loaded (%.2fs)\n", phase_elapsed(&utxo_init_pt));

    /* ---- STAGE B: fork choice ------------------------------------------
     * Open chainwork.dat and bring it fully in step with index.dat. The
     * first run on an existing archive is the one-time backfill of every
     * already-stored height (each one costs an index read, an 80-byte header
     * read and one 16-byte record write); every later boot finds the file
     * already complete and this returns immediately. Doing the backfill here
     * rather than as a separate tool means the backfill path and the
     * steady-state path are literally the same tested function, and it is
     * resumable -- an interrupted backfill just continues next boot.
     *
     * A failure here disables reorg handling for this process but must not
     * stop the node: without chainwork we simply cannot compare chains, and
     * refusing to reorg is always the safe direction. */
    int reorg_ok = 0;
    if(reorg_chainwork_open(store_buf) != 1){
        fprintf(stderr,"[dl] chainwork open failed -- fork detection DISABLED for this process\n");
    } else {
        phase_timer_t cw_pt; phase_start(&cw_pt);
        long added = reorg_chainwork_sync(store_buf, 0);
        if(added < 0){
            fprintf(stderr,"[dl] chainwork backfill failed -- fork detection DISABLED for this process\n");
        } else {
            reorg_ok = 1;
            fprintf(stderr,"[dl] worker: chainwork in step with the archive (%ld record(s) backfilled, %.2fs)\n",
                    added, phase_elapsed(&cw_pt));
        }
    }
    /* Reorg handling additionally REQUIRES live UTXO tracking: disconnecting
     * a block means replaying its undo data against the live LSM, and the
     * undo data itself is only written by the live apply path. */
    if(reorg_ok && !utxo_live_ok){
        fprintf(stderr,"[dl] live UTXO tracking is off -- fork detection stays on but REORGS ARE DISABLED (no undo data)\n");
    }
    reorg_set_index_rebuild(rebuild_hash_index_after_reorg);
    /* ---- BOOTSTRAP + DISCOVER (seeds are bootstrap-only) ----
     * Real nodes use DNS seeds once to learn reachable peers, then connect to
     * those -- never downloading from the seeds themselves. We resolve each
     * seed-DNS hostname to its A-records (real, current node IPs), fold the
     * distinct v4 endpoints into the persisted amr book (peers.dat), then dial
     * up to 8 of those DISCOVERED peers for download. */
    ab2_t* ab = addr_book();
    if(ab){
        long disc = dl_bootstrap(ab, peers, pool_len);
        fprintf(stderr,"[boot] discovered +%ld peers (peers2.dat now %ld)\n", disc, (long)ab2_count(ab));
    } else {
        fprintf(stderr,"[boot] address book unavailable; falling back to seed list\n");
    }
    static char dle[64][DL_POOL_SLOT];
    int npool = dl_pool_from_book(ab, dle, 64);
    fprintf(stderr,"[boot] %d public peer candidate(s) in pool\n", npool);
    /* srcpool is the ADDRESS BOOK pool, and it is what every dial in this
     * worker must use -- the initial dial, the top-up, AND the re-dials.
     *
     * Until 2026-08-23 only the first two did. Every mux_next_peer() (then named mux_redial) was handed
     * `peers`/`pool_len`, which serve_download_worker receives from its sole
     * caller as `catchup_seeds` -- the six DNS seed HOSTNAMES. Legs die
     * routinely (peer timeouts, dropped sockets, the per-leg sync budget), and
     * each death replaced a real peer with a seed, so the node CONVERGED onto
     * the seeds the longer it ran. Observed on the first live boot: 217 seed
     * contacts, and log lines like
     *     [dl:3] seed.bitcoin.sipa.be connection dropped; re-dialing
     *     [mux:3] redialed -> dnsseed.bluematt.me
     * while 3,798 known-good peers sat unused in peers.dat.
     *
     * Wrong three ways: DNS seeds are a shared public resource that Core
     * queries only when its address manager is short; a seed hostname is a
     * name server and often not a full node at all, which is why those
     * sockets kept dropping; and a node that drifts onto six fixed hosts is
     * fragile and leaks its identity to them. This file's own header already
     * said "seeds are bootstrap-only ... never downloading from the seeds
     * themselves" -- the redial path just never honoured it. */
    const char* srcpool[64]; int nsrc=0;
    if(g_cfg.connect_only){
        /* connect= means these are the ONLY peers -- verbatim, bypassing the
         * public-IP book filter (which rightly drops loopback/RFC1918 from a
         * gossiped book, but an OPERATOR-NAMED peer may live there: a local
         * regtest Core is 127.0.0.1, and dl_pool_from_book's a==127 skip left
         * this worker permanently offline with 'no reachable connect= peers'
         * while the peer was up -- found on the first regtest live-follow). */
        for(int i=0;i<g_cfg.n_connect && nsrc<64;i++) srcpool[nsrc++]=g_cfg.connectn[i];
    } else {
        for(int i=0;i<npool && nsrc<64;i++) srcpool[nsrc++]=dle[i];
    }
    if(nsrc==0){
        /* Discovery found nothing: DEGRADED fallback so the node still syncs.
         * Normally the seeds are bootstrap-only; this is only an emergency.
         *
         * 2026-08-24: this fallback used to fire even under `connect=`, which
         * is Core's "these are the ONLY peers" switch -- so a node configured
         * connect-only still dialled the hard-coded DNS seeds. That is a
         * privacy leak (it contacts hosts the operator excluded), and it made
         * an OFFLINE benchmark impossible: scripts/bench_tier3.sh sets
         * connect=192.0.2.1 precisely to take the node off the network, and
         * the first real tier-3 run still reached the seeds and appended 567
         * blocks past the truncated tip, invalidating the measurement by the
         * harness's own post-condition. The harness documented the behaviour
         * and worked around it; honouring the flag is the actual fix.
         * With connect= set the correct degraded state is NO outbound peers,
         * which is exactly what the operator asked for. */
        if(g_cfg.connect_only){
            fprintf(stderr,"[dl] no reachable connect= peers; staying offline (connect= means these are the ONLY peers)\n");
        } else {
            if(pool_len > 0){
                fprintf(stderr,"[dl] no discovered peers; temporary seed fallback\n");
                for(int i=0;i<pool_len && nsrc<8;i++){ srcpool[nsrc++]=peers[i]; }
            } else {
                /* a chain with NO seeds (regtest) has no fallback to offer --
                 * say so instead of announcing a fallback that adds nothing */
                fprintf(stderr,"[dl] no peers and this chain has no DNS seeds; staying offline (use connect=/addnode=)\n");
            }
        }
    }
    /* ---- MULTI-PEER DOWNLOAD: establish up to 8 live legs by dialing the
     * discovered candidate pool IN PARALLEL. A DNS seed returns many
     * plausible-but-dead IPs, so a per-candidate sequential dial with timeouts
     * would stall for minutes. Instead we non-blocking-connect ALL candidates
     * at once, poll once for readiness, and promote only the live ones -- dead
     * peers are shed in the same single bounded wait as live ones connect.
     * (We are the sole block writer in ONE process, so rotating bounded sync
     * passes over the shared store_buf is race-free; each leg's node_sync
     * appends via store_append while the others idle. A LONG per-pass budget,
     * DL_BUDGET_SECS, applies because this process does not serve inbound.) */
    long long next_feeler_ms = 0;
    for(int b=0;b<MAX_BLOCK_RELAY_ONLY;b++){ bro_fd[b]=-1; bro_host[b][0]=0; }
    mux_n_out = 0;                                   /* isolate from any parent state */
    {
        int ntry = nsrc; if(ntry>MUX_MAX_OUT*3) ntry=MUX_MAX_OUT*3;   /* cap candidates */
        static int cfd[64];
        int nc=0;
        for(int i=0;i<ntry && nc<64;i++){
            unsigned ip;
            /* With a proxy configured this raw non-blocking connect would
             * go DIRECT, defeating the proxy for every IPv4 peer. Leave those
             * to the sequential path, which dials through the dialer.
             * (2026-08-29 pre-deploy review.) */
            if(dialer_proxy_configured()){ cfd[nc++]=-1; continue; }
            int spport = 0;
            ip = pool_ipv4(srcpool[i], &spport);
            if(!ip){
                struct addrinfo h,*res=0; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
                /* never hand an anonymity-network name to the system
                 * resolver: a DNS lookup for a .onion deanonymises both ends.
                 * Those are dialled through their transport, not here. */
                if(strstr(srcpool[i],".onion") || strstr(srcpool[i],".i2p")){ cfd[nc++]=-1; continue; }
                /* behind a proxy this name must not be resolved here; the
                 * sequential path dials it through the proxy instead */
                if(dialer_dns_blocked()){ cfd[nc++]=-1; continue; }
                if(getaddrinfo(srcpool[i],NULL,&h,&res)!=0){ cfd[nc++]=-1; continue; }
                ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr; freeaddrinfo(res);
            }
            int fd=socket(AF_INET,SOCK_STREAM,0);
            if(fd<0){ cfd[nc++]=-1; continue; }
            int fl=fcntl(fd,F_GETFL,0); fcntl(fd,F_SETFL,fl|O_NONBLOCK);
            struct sockaddr_in sa; memset(&sa,0,sizeof sa); sa.sin_family=AF_INET;
            sa.sin_addr.s_addr=ip;
            sa.sin_port=(unsigned short)htons((unsigned short)(spport ? spport : out_port));
            int rc=connect(fd,(struct sockaddr*)&sa,sizeof sa);
            if(rc!=0 && errno!=EINPROGRESS){ close(fd); cfd[nc++]=-1; continue; }
            /* stash the original flags so we can clear O_NONBLOCK after promote */
            cfd[nc++]=fd;
        }
        /* Bounded wait for them to become writable -- in ROUNDS, not once.
         *
         * This used to be a single poll(pol,nf,2500) and then "whoever has
         * POLLOUT set right now wins". But poll() returns as soon as the FIRST
         * socket is ready, not after the full timeout: one nearby peer
         * answering in 20ms made every slower peer look un-ready, and they
         * were all closed on the spot. Measured 2026-08-23 on the first live
         * boot: 85 candidates confirmed alive by the probe round, exactly ONE
         * promoted here, and the (rot % 8) top-up loop then spent ~95 seconds
         * redoing the work the dial should have done.
         *
         * So: keep polling until the target is met or the budget expires,
         * carrying readiness forward across rounds. A satisfied entry has its
         * fd negated, which makes poll() skip it, so each round waits only on
         * the sockets still pending. Same total budget, just not surrendered
         * to the first responder. */
        struct pollfd pol[64]; int nf=0;
        int   pidx[64];                    /* pol[j] -> cfd[] index */
        char  rdy[64];                     /* accumulated readiness */
        for(int i=0;i<nc;i++){ if(cfd[i]<0) continue; pol[nf].fd=cfd[i]; pol[nf].events=POLLOUT; pol[nf].revents=0; pidx[nf]=i; rdy[nf]=0; nf++; }
        if(nf>0){
            long long dl_end;
            { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
              dl_end = ts.tv_sec*1000LL + ts.tv_nsec/1000000LL + 2500; }
            int nready = 0, want = MUX_WANT_OUT();
            for(;;){
                long long now_ms2;
                { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
                  now_ms2 = ts.tv_sec*1000LL + ts.tv_nsec/1000000LL; }
                int left = (int)(dl_end - now_ms2);
                if(left <= 0 || nready >= want) break;
                int r = poll(pol,nf,left);
                if(r <= 0) break;                    /* timeout, or error */
                for(int j=0;j<nf;j++){
                    if(pol[j].fd < 0) continue;      /* already counted */
                    if(pol[j].revents & (POLLOUT|POLLERR|POLLHUP)){
                        if(pol[j].revents & POLLOUT) { rdy[j]=1; nready++; }
                        pol[j].fd = -pol[j].fd;      /* poll() ignores negative fds */
                    }
                    pol[j].revents = 0;
                }
            }
            fprintf(stderr,"[dl] dial: %d of %d candidate(s) answered within the budget\n", nready, nf);
        }
        for(int i=0;i<nc && mux_n_out<MUX_WANT_OUT() && mux_n_out<MUX_MAX_OUT;i++){
            if(cfd[i]<0) continue;
            int ready=0;
            for(int j=0;j<nf;j++) if(pidx[j]==i){ ready=rdy[j]; break; }
            if(!ready){ close(cfd[i]); continue; }
            int soerr=0; socklen_t sl=sizeof soerr;
            if(getsockopt(cfd[i],SOL_SOCKET,SO_ERROR,&soerr,&sl)<0||soerr!=0){ close(cfd[i]); continue; }
            /* it connected: clear non-blocking, then handshake (bounded recv) */
            int fl=fcntl(cfd[i],F_GETFL,0); fcntl(cfd[i],F_SETFL,fl&~O_NONBLOCK);
            struct timeval tv; tv.tv_sec=6; tv.tv_usec=0; setsockopt(cfd[i],SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
            int hk=node_handshake(cfd[i]);
            if(hk!=1 || !peer_has_witness(srcpool[i])){ close(cfd[i]); continue; }
            { extern void addrself_note_peer_view(const unsigned char*, long);
              addrself_note_peer_view(g_peer_version_payload, g_peer_version_len); }
            struct timeval t2; t2.tv_sec=3; t2.tv_usec=0; setsockopt(cfd[i],SOL_SOCKET,SO_RCVTIMEO,&t2,sizeof t2);
            strncpy(mux_out_host[mux_n_out], srcpool[i], 127);
            mux_out_fd[mux_n_out]=cfd[i];
            mux_out_wants_v2[mux_n_out]=(unsigned char)g_peer_wants_addrv2;
            mux_out_peer[mux_n_out]=i;
            anchor_locator(mux_out_loc[mux_n_out]);
            mux_out_nextretry[mux_n_out]=0;
            { char pv[256]; format_peer_version_info(pv, sizeof pv);
              fprintf(stderr,"[dl] outbound %d = %s (fd %d) %s addrv2=%d\n", mux_n_out, srcpool[i], cfd[i], pv, (int)mux_out_wants_v2[mux_n_out]); }
            rpc_fill_peer_slot(mux_n_out, srcpool[i]);   /* publish peer to getpeerinfo */
            mux_n_out++;
        }
        /* close every candidate fd that was NOT promoted into a live leg */
        for(int i=0;i<nc;i++){
            if(cfd[i]<0) continue;
            int kept=0;
            for(int k=0;k<mux_n_out;k++) if(mux_out_fd[k]==cfd[i]){ kept=1; break; }
            if(!kept) close(cfd[i]);
        }
    }
    fprintf(stderr,"[dl] connected %d/%d peer(s); downloading across them...\n", mux_n_out, MUX_WANT_OUT());
    long long rot=0;
    long long boot_ms = 0;
    { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); boot_ms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
    long long next_heartbeat_ms = boot_ms + DL_HEARTBEAT_MS;
    int last_seen_tip = *(int*)(store_buf+24);   /* new-block announcement baseline (boot tip, so the catch-up burst is announced too) */
    /* STAGE B: next allowed fork probe (see the probe block in the rotation
     * below). Starts armed so a node booting onto a store that is already on
     * a losing branch notices on its first idle rotation rather than after a
     * full interval. */
    long long next_reorg_probe_ms = 0;
    int apply_first_prev = 0;
    long long dl_parallel_last_s = 0;
    for(;;){
        /* publish outbound peer count + tip + peer table for the RPC thread */
        if(g_node_status){ int lp=0; for(int i=0;i<mux_n_out;i++) if(mux_out_fd[i]>=0) lp++;
            g_node_status->n_out = lp; g_node_status->tip_height = *(int*)(store_buf+24);
            long long nows = (long long)time(NULL);
            for(int i=0;i<RPC_MAX_PEERS;i++){
                if(!(i < mux_n_out && mux_out_fd[i] >= 0)){ g_node_status->peers[i].used = 0; continue; }
                /* per-socket byte + last-activity meters from the kernel: no
                 * asm changes, no double counting -- TCP_INFO is authoritative
                 * (getpeerinfo bytessent/bytesrecv/lastsend/lastrecv). The
                 * kernel struct is read by offset into a local mirror of its
                 * stable uapi layout, so this does not depend on the glibc
                 * header's tcp_info version (older ones lack the byte fields). */
                struct bmc_tcp_info {
                    unsigned char  _s[7];                 /* state..wscale/flags */
                    unsigned int   rto, ato, snd_mss, rcv_mss;
                    unsigned int   unacked, sacked, lost, retrans, fackets;
                    unsigned int   last_data_sent, last_ack_sent, last_data_recv, last_ack_recv;
                    unsigned int   pmtu, rcv_ssthresh, rtt, rttvar, snd_ssthresh, snd_cwnd, advmss, reordering;
                    unsigned int   rcv_rtt, rcv_space, total_retrans;
                    unsigned long long pacing_rate, max_pacing_rate, bytes_acked, bytes_received;
                } ti;
                socklen_t tl = sizeof ti;
                if(getsockopt(mux_out_fd[i], IPPROTO_TCP, TCP_INFO, &ti, &tl) == 0){
                    rpc_peer_t* pr = &g_node_status->peers[i];
                    /* byte fields only if the kernel returned a struct large
                     * enough to include them */
                    if(tl >= (socklen_t)((char*)(&ti.bytes_received + 1) - (char*)&ti)){
                        pr->bytes_sent = (long long)ti.bytes_acked;
                        pr->bytes_recv = (long long)ti.bytes_received;
                    }
                    if(tl >= (socklen_t)((char*)(&ti.last_data_recv + 1) - (char*)&ti)){
                        pr->last_send = nows - (long long)(ti.last_data_sent / 1000);
                        pr->last_recv = nows - (long long)(ti.last_data_recv / 1000);
                    }
                }
            } }
        /* peer control: one command per ack, executed HERE because this is the
         * process that holds the legs. Every branch reports what it actually
         * did -- 1 done, 0 no-op/not-found -- so the parent can map a no-op to
         * Core's error rather than reporting a success that changed nothing. */
        if(g_node_status && g_node_status->ctl_seq != ctl_last_seq){
            ctl_last_seq = g_node_status->ctl_seq;
            int op = g_node_status->ctl_op;
            long long num = g_node_status->ctl_num;
            char arg[128];
            snprintf(arg, sizeof arg, "%s", (const char*)g_node_status->ctl_arg);
            int result = 0; char reason[128]; reason[0] = 0;
            if(op == RPC_CTL_SETNETACTIVE){
                g_node_status->net_active = num ? 1 : 0;
                if(!num){
                    /* Core drops every connection when the network goes down;
                     * anything less would leave the node still talking. */
                    for(int i = 0; i < mux_n_out; i++)
                        if(mux_out_fd[i] >= 0){ bmc_v2_close(mux_out_fd[i]), close(mux_out_fd[i]); mux_out_fd[i] = -1; }
                    fprintf(stderr,"[ctl] network DISABLED: dropped all outbound legs\n");
                } else {
                    fprintf(stderr,"[ctl] network enabled\n");
                }
                result = 1;
            } else if(op == RPC_CTL_PING){
                int sent = 0;
                for(int i = 0; i < mux_n_out; i++)
                    if(mux_out_fd[i] >= 0 &&
                       p2p_write(mux_out_fd[i], "ping", 4, "\x11\x22\x33\x44\x55\x66\x77\x88", 8) > 0)
                        sent++;
                fprintf(stderr,"[ctl] ping queued to %d leg(s)\n", sent);
                result = 1;
            } else if(op == RPC_CTL_DISCONNECT){
                char want[128]; ctl_ip_only(arg, want, sizeof want);
                for(int i = 0; i < mux_n_out; i++){
                    if(mux_out_fd[i] < 0) continue;
                    char have[128]; ctl_ip_only(mux_out_host[i], have, sizeof have);
                    int hit = (want[0] && !strcmp(have, want)) ||
                              (!want[0] && num == (long long)i);
                    if(!hit) continue;
                    fprintf(stderr,"[ctl] disconnecting %s (leg %d)\n", mux_out_host[i], i);
                    bmc_v2_close(mux_out_fd[i]), close(mux_out_fd[i]); mux_out_fd[i] = -1;
                    if(g_node_status) g_node_status->peers[i].used = 0;
                    result = 1; break;
                }
            } else if(op == RPC_CTL_ADDNODE){
                if(num == 1){                                  /* remove */
                    for(int i = 0; i < g_ctl_n_addnode; i++)
                        if(!strcmp(g_ctl_addnode[i], arg)){
                            memmove(g_ctl_addnode[i], g_ctl_addnode[g_ctl_n_addnode - 1], 64);
                            g_ctl_n_addnode--;
                            result = 1; break;
                        }
                } else if(g_ctl_n_addnode < CTL_MAX_ADDNODE){
                    int dup = 0;
                    for(int i = 0; i < g_ctl_n_addnode; i++)
                        if(!strcmp(g_ctl_addnode[i], arg)) dup = 1;
                    if(!dup && num == 0){
                        snprintf(g_ctl_addnode[g_ctl_n_addnode++], 64, "%s", arg);
                        fprintf(stderr,"[ctl] addnode: %s (runtime list now %d)\n",
                                arg, g_ctl_n_addnode);
                    }
                    result = 1;      /* onetry and duplicate-add are both "done" */
                } else {
                    result = -1;
                    snprintf(reason, sizeof reason,
                             "the runtime addnode list is full (%d)", CTL_MAX_ADDNODE);
                }
            } else if(op == RPC_CTL_ADDPEERADDRESS){
                /* one address into the version-2 book (any BIP155 network);
                 * the worker is the book's only writer, which is why this
                 * crosses the channel instead of the RPC thread writing */
                bmc_addr_t a;
                /* port 0 is legal and is I2P's canonical form (Core's
                 * I2P_SAM31_PORT is 0), so the ctl argument carries the port
                 * separately after the last ':' and 0 is accepted */
                char host[128]; long pnum = -1;
                { const char* c = strrchr(arg, ':');
                  host[0] = 0;
                  if (c && c > arg){
                      long hl = c - arg;
                      const char* hs = arg;
                      if (arg[0] == '[' && c[-1] == ']'){ hs = arg + 1; hl -= 2; }   /* [v6]:port */
                      if (hl > 0 && (size_t)hl < sizeof host){
                          memcpy(host, hs, (size_t)hl); host[hl] = 0; pnum = atol(c + 1); }
                  } }
                if(!host[0] || pnum < 0 || pnum > 65535 || !bmc_addr_from_string(&a, host)){
                    result = -8; snprintf(reason, sizeof reason, "Invalid address");
                } else if(!bmc_addr_is_routable(&a)){
                    result = 0;                                /* Core: not added, success=false */
                } else {
                    a.port = (unsigned short)pnum;
                    ab2_t* b = addr_book();
                    int rc = b ? ab2_add(b, &a, 1, (unsigned)time(NULL)) : -1;
                    result = rc == 1 ? 1 : 0;
                    if(rc == 1) fprintf(stderr,"[ctl] addpeeraddress: %s -> book (%s)\n", arg, bmc_net_name(a.net));
                }
            } else if(op == RPC_CTL_SETBAN){
                if(num == 0){                                  /* remove */
                    for(int i = 0; i < RPC_MAX_BANS; i++)
                        if(g_node_status->bans[i].until &&
                           !strcmp((const char*)g_node_status->bans[i].subnet, arg)){
                            g_node_status->bans[i].until = 0;
                            result = 1; break;
                        }
                } else {
                    /* refuse a subnet form the matcher cannot enforce */
                    const char* sl = strchr(arg, '/');
                    if(sl && (atoi(sl+1) % 8 || atoi(sl+1) < 8 || atoi(sl+1) > 32)){
                        result = -1;
                        snprintf(reason, sizeof reason,
                                 "this node enforces only /8, /16, /24 and /32 subnets; "
                                 "a prefix it cannot match would be stored and never enforced");
                    } else {
                        int dup = 0, slot = -1;
                        for(int i = 0; i < RPC_MAX_BANS; i++){
                            if(g_node_status->bans[i].until &&
                               !strcmp((const char*)g_node_status->bans[i].subnet, arg)) dup = 1;
                            if(!g_node_status->bans[i].until && slot < 0) slot = i;
                        }
                        if(dup) result = 0;
                        else if(slot < 0){
                            result = -1;
                            snprintf(reason, sizeof reason, "the ban list is full (%d)", RPC_MAX_BANS);
                        } else {
                            snprintf((char*)g_node_status->bans[slot].subnet, 64, "%s", arg);
                            g_node_status->bans[slot].created = (long long)time(NULL);
                            __sync_synchronize();
                            g_node_status->bans[slot].until = num;   /* published last */
                            /* drop any live leg the new ban now covers */
                            for(int i = 0; i < mux_n_out; i++){
                                if(mux_out_fd[i] < 0) continue;
                                char ip[128]; ctl_ip_only(mux_out_host[i], ip, sizeof ip);
                                if(ctl_ban_covers(arg, ip)){
                                    fprintf(stderr,"[ctl] ban %s drops live leg %s\n", arg, mux_out_host[i]);
                                    bmc_v2_close(mux_out_fd[i]), close(mux_out_fd[i]); mux_out_fd[i] = -1;
                                    g_node_status->peers[i].used = 0;
                                }
                            }
                            fprintf(stderr,"[ctl] banned %s until %lld\n", arg, num);
                            result = 1;
                        }
                    }
                }
            } else if(op == RPC_CTL_CLEARBANNED){
                for(int i = 0; i < RPC_MAX_BANS; i++) g_node_status->bans[i].until = 0;
                fprintf(stderr,"[ctl] ban list cleared\n");
                result = 1;
            } else {
                result = -1;
                snprintf(reason, sizeof reason, "unknown control op %d", op);
            }
            snprintf((char*)g_node_status->ctl_reason, sizeof g_node_status->ctl_reason, "%s", reason);
            g_node_status->ctl_result = result;
            __sync_synchronize();
            g_node_status->ctl_ack = ctl_last_seq;
        }
        /* sendrawtransaction: pick up a staged submission from the RPC parent,
         * validate + mempool-accept + relay to peer legs, then ack the seq. */
        /* Transaction submissions (sendrawtransaction, testmempoolaccept, and the
         * boot-time mempool.dat reload) arrive one at a time through the shared
         * region and are acked here. A submitter waits for the ack before sending
         * the next, so servicing ONE per rotation made a stream crawl at the
         * rotation period: deploy `a` on 2026-08-31 needed 13 minutes to reload
         * 353 saved transactions, with RPC dark the whole time. After an ack,
         * linger briefly for a follow-up; a reload then streams at tx_accept
         * speed, and an idle node pays at most TXSUB_FOLLOW_MS once. */
        if(g_node_status){
            int follow = 0;
            /* ...but the linger must not become residence: a mempool.dat
             * reload (thousands of entries, each acked and followed by the
             * next within the window, plus its retry passes) kept the worker
             * in this loop for MINUTES -- no heartbeat, no leg polling, no
             * block sync, and every blocking dial or write it hit inside
             * looked like a wedge (2026-08-31 21:20; 2026-09-01 00:31, 00:51,
             * 01:10, all a few minutes after boot). Bound the stay per
             * rotation by count and by time; the submitter tolerates a
             * rotation gap (it waits 90 s per entry). */
            int budget = TXSUB_ROTATION_BUDGET;
            long long t_enter = txsub_now_ms();
            for(;;){
                if(g_node_status->tx_submit_seq == txsub_last_seq){
                    if(follow <= 0 || g_shutdown_requested) break;
                    struct timespec ts = {0, 500*1000}; nanosleep(&ts, NULL); follow--;
                    continue;
                }
                if(--budget < 0 || txsub_now_ms() - t_enter > TXSUB_ROTATION_MS) break;   /* back to the main loop; next rotation continues */
                txsub_last_seq = g_node_status->tx_submit_seq;
            int result; char reason[128]; reason[0]=0;
            if(g_node_status->tx_submit_pkg_n > 0){
                result = txsub_package(reason, sizeof reason);
            }
            else if(txsub_worker_ready()){
                unsigned long tlen = g_node_status->tx_submit_len;
                if(tlen==0 || tlen>RPC_TXSUBMIT_MAX){ result=-22; snprintf(reason,sizeof reason,"TX decode failed"); }
                else if(g_node_status->tx_submit_test){
                    /* testmempoolaccept: same checks, no insertion, no relay */
                    extern long tx_accept_test_reason(void*, const unsigned char*,
                                     const unsigned char*, unsigned long, char*,
                                     unsigned long, unsigned long long*);
                    extern int tx_txid(unsigned char[32], const unsigned char*, unsigned long,
                                       unsigned char*, unsigned long);
                    static unsigned char tscratch[2000*81 + 8];
                    unsigned char tid[32];
                    unsigned long long fee = 0;
                    if(!tx_txid(tid, (const unsigned char*)g_node_status->tx_submit_buf, tlen,
                                tscratch, sizeof tscratch)){
                        result=-22; snprintf(reason,sizeof reason,"TX decode failed");
                    } else {
                        result = (int)tx_accept_test_reason(txsub_pool(), tid,
                                     (const unsigned char*)g_node_status->tx_submit_buf, tlen,
                                     reason, sizeof reason, &fee);
                    }
                    g_node_status->tx_submit_fee = fee;
                }
                else { int relayed=0;
                    result = txsub_accept_and_relay(txsub_pool(),
                                 (const unsigned char*)g_node_status->tx_submit_buf, tlen,
                                 mux_out_fd, mux_n_out, reason, sizeof reason, &relayed);
                    /* every mempool.dat reload streams through this channel:
                     * 4,470 lines in two minutes after deploy j. One line per
                     * 5 s; the count rides along. */
                    if(result==1){
                        static long srt_last, srt_muted;
                        long now_s = (long)time(NULL);
                        if(now_s - srt_last >= 300){   /* 1/5min: reload streams made 1/5s a metronome */
                            fprintf(stderr,"[dl] sendrawtransaction accepted, relayed to %d/%d legs%s\n",
                                    relayed, mux_n_out,
                                    srt_muted ? " (repeats muted; +N shows in the tx_accept summary)" : "");
                            srt_last = now_s; srt_muted = 1;
                        }
                    }
                }
            } else { result=-4; snprintf(reason,sizeof reason,"mempool init failed"); }
            snprintf((char*)g_node_status->tx_submit_reason, sizeof g_node_status->tx_submit_reason, "%s", reason);
            g_node_status->tx_submit_result = result;
            __sync_synchronize();
            g_node_status->tx_submit_ack = txsub_last_seq;
                follow = TXSUB_FOLLOW_MS * 2;           /* 0.5 ms polls */
            }
        }
        /* submitblock channel: evaluate against the chain state this worker
         * owns (daemon/blk_submit.c). This slice never connects a block --
         * consensus-clean submissions answer "inconclusive" (BIP22's honest
         * word for it) until the UTXO dry-run slice lands. */
        if(g_node_status && g_node_status->blk_submit_seq != blksub_last_seq){
            blksub_last_seq = g_node_status->blk_submit_seq;
            extern long blk_submit_evaluate_ex(const unsigned char*, unsigned long,
                                               const unsigned char*, long, int, char*, unsigned long);
            char reason[64]; reason[0]=0;
            unsigned char tiph[32]; int have_tip = store_get_tip_hash(store_buf, tiph) == 1;
            long tip = *(int*)(store_buf+24);
            const unsigned char* sblk = (const unsigned char*)g_node_status->blk_submit_buf;
            unsigned long slen = g_node_status->blk_submit_len;
            int accepted = 0;
            int proposal = g_node_status->blk_submit_proposal;
            /* BIP23 proposal: prev must be OUR TIP or the answer is Core's
             * "inconclusive-not-best-prevblk"; PoW is NOT checked (the
             * template is unmined -- Core TestBlockValidity fCheckPOW=false);
             * and nothing is ever connected. */
            if (proposal && (!have_tip || slen < 81 || memcmp(sblk + 4, tiph, 32) != 0)){
                snprintf(reason, sizeof reason, "inconclusive-not-best-prevblk");
                fprintf(stderr,"[dl] proposal: %s (len=%lu tip=%ld)\n", reason, (unsigned long)slen, tip);
                snprintf((char*)g_node_status->blk_submit_reason, sizeof g_node_status->blk_submit_reason, "%s", reason);
                g_node_status->blk_submit_result = 0;
                __sync_synchronize();
                g_node_status->blk_submit_ack = blksub_last_seq;
                continue;
            }
            long ev = blk_submit_evaluate_ex(sblk, slen, have_tip ? tiph : 0, tip,
                                             proposal ? 0 : 1, reason, sizeof reason);
            if (ev == 1){
                /* consensus-clean + tip-extending. CONNECT path: contextual
                 * checks (correct next bits, timestamp window), the UTXO
                 * dry run (the SAME verification phases a real apply runs,
                 * stopped at the first mutation), then append + apply
                 * through the normal catch-up pipeline + relay. Only a
                 * fully-synced UTXO state can be dry-run against: mid
                 * catch-up the honest answer stays "inconclusive". */
                extern long utxo_live_dryrun_block(const unsigned char*, unsigned long long, long);
                extern const char* utxo_live_last_reject(void);
                extern unsigned int rpc_chain_retarget(unsigned int, long);
                long applied = utxo_live_ok ? utxo_live_applied_height() : -1;
                static unsigned char hb[4u<<20];   /* store_read_at scratch */
                if (applied != tip){
                    snprintf(reason, sizeof reason, "inconclusive");
                } else {
                    /* next-work check: a block whose header meets its OWN bits
                     * but not the CHAIN's required bits must not connect. */
                    unsigned int want_bits = 0, blk_bits =
                        (unsigned)sblk[72] | ((unsigned)sblk[73]<<8) | ((unsigned)sblk[74]<<16) | ((unsigned)sblk[75]<<24);
                    unsigned int tip_time = 0;
                    if (store_read_at(store_buf, (u64)tip, hb, sizeof hb) >= 80){
                        unsigned int tip_bits = (unsigned)hb[72]|((unsigned)hb[73]<<8)|((unsigned)hb[74]<<16)|((unsigned)hb[75]<<24);
                        tip_time = (unsigned)hb[68]|((unsigned)hb[69]<<8)|((unsigned)hb[70]<<16)|((unsigned)hb[71]<<24);
                        if ((tip + 1) % 2016 != 0) want_bits = tip_bits;
                        else if (store_read_at(store_buf, (u64)(tip - 2015), hb, sizeof hb) >= 80){
                            unsigned int first_time = (unsigned)hb[68]|((unsigned)hb[69]<<8)|((unsigned)hb[70]<<16)|((unsigned)hb[71]<<24);
                            want_bits = rpc_chain_retarget(tip_bits, (long)tip_time - (long)first_time);
                        }
                    }
                    /* median time past of the last 11 headers */
                    unsigned int mtp = 0;
                    { unsigned int tt[11]; int nn = 0;
                      for (long h2 = tip; h2 >= 0 && nn < 11; h2--){
                          if (store_read_at(store_buf, (u64)h2, hb, sizeof hb) < 80) break;
                          tt[nn++] = (unsigned)hb[68]|((unsigned)hb[69]<<8)|((unsigned)hb[70]<<16)|((unsigned)hb[71]<<24);
                      }
                      for (int a2=0; a2<nn; a2++) for (int b2=a2+1; b2<nn; b2++)
                          if (tt[b2] < tt[a2]){ unsigned int sw=tt[a2]; tt[a2]=tt[b2]; tt[b2]=sw; }
                      if (nn) mtp = tt[nn/2]; }
                    unsigned int blk_time = (unsigned)sblk[68]|((unsigned)sblk[69]<<8)|((unsigned)sblk[70]<<16)|((unsigned)sblk[71]<<24);
                    if (!want_bits || blk_bits != want_bits){
                        snprintf(reason, sizeof reason, "bad-diffbits");
                    } else if (blk_time <= mtp){
                        snprintf(reason, sizeof reason, "time-too-old");
                    } else if ((long long)blk_time > (long long)time(NULL) + 7200){
                        snprintf(reason, sizeof reason, "time-too-new");
                    } else if (utxo_live_dryrun_block(sblk, slen, tip + 1) != 1){
                        const char* rr = utxo_live_last_reject();
                        snprintf(reason, sizeof reason, "%s", (rr && rr[0]) ? rr : "rejected");
                    } else if (proposal){
                        /* valid proposal: report success, NEVER connect */
                        accepted = 1;
                    } else {
                        /* CONNECT: append, then apply through the normal
                         * catch-up pipeline (full re-verify -- deterministic
                         * pass after the dry run; same undo/checkpoint
                         * crash-safety as any network block). */
                        unsigned char bh[32]; sha256d(bh, sblk, 80);
                        if (store_append(store_buf, bh, sblk, (long)slen) < 0){
                            snprintf(reason, sizeof reason, "rejected");
                            fprintf(stderr,"[dl] submitblock: store_append FAILED\n");
                        } else {
                            long ar = utxo_live_catchup(store_buf);
                            if (ar < 0){
                                /* should be unreachable after a dry-run pass;
                                 * scream, and let the existing recovery paths
                                 * own the state (same as a bad network block). */
                                fprintf(stderr,"[dl] submitblock: APPLY FAILED AFTER CLEAN DRY-RUN -- investigate\n");
                                snprintf(reason, sizeof reason, "rejected");
                            } else {
                                /* headers.dat: keep the header mirror current
                                 * (readers self-heal via header sync anyway) */
                                { static unsigned char hstate[128];
                                  if (hst_init(hstate) == 1 && hst_reload(hstate) >= 0)
                                      hst_append(hstate, sblk, bh); }
                                /* announce to the outbound legs (inv MSG_BLOCK) */
                                { unsigned char inv[37]; inv[0]=1;
                                  inv[1]=2; inv[2]=0; inv[3]=0; inv[4]=0;   /* MSG_BLOCK */
                                  memcpy(inv+5, bh, 32);
                                  int announced = 0;
                                  for (int i2=0; i2<mux_n_out; i2++)
                                      if (mux_out_fd[i2] >= 0 &&
                                          p2p_write(mux_out_fd[i2], "inv", 3, inv, 37) > 0) announced++;
                                  fprintf(stderr,"[dl] submitblock: CONNECTED h=%ld, announced to %d/%d legs\n",
                                          tip + 1, announced, mux_n_out); }
                                accepted = 1;
                            }
                        }
                    }
                }
            }
            fprintf(stderr,"[dl] %s: %s (len=%lu tip=%ld)\n",
                    proposal ? "proposal" : "submitblock",
                    accepted ? (proposal ? "valid" : "accepted") : reason, (unsigned long)slen, tip);
            snprintf((char*)g_node_status->blk_submit_reason, sizeof g_node_status->blk_submit_reason, "%s", reason);
            g_node_status->blk_submit_result = accepted;
            __sync_synchronize();
            g_node_status->blk_submit_ack = blksub_last_seq;
        }
        if(g_shutdown_requested){
            int live_peers=0; for(int i=0;i<mux_n_out;i++) if(mux_out_fd[i]>=0) live_peers++;
            long long stop_ms; { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); stop_ms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
            char upbuf[UPTIME_BUF];
            fprintf(stderr,"[dl] shutting down (signal %d): tip=%d peers=%d txouts=%ld uptime=%s\n",
                    (int)g_shutdown_requested, *(int*)(store_buf+24), live_peers,
                    utxo_live_ok?live_utxo_disp():-1L,
                    fmt_uptime(upbuf, (stop_ms-boot_ms)/1000));
            /* fee_estimates.dat (Core Flush()) -- weak: the dial/sync test
             * harnesses that link this file do not carry daemon/fee_hooks.c */
            { extern void fest_shutdown_flush(void); fest_shutdown_flush(); }
            _exit(0);
        }
        long long now_ms = 0;
        { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); now_ms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
        int did=0;
        /* APPLY FIRST WHEN FAR BEHIND. The rotation below syncs every leg for
         * up to DL_BUDGET_SECS each before the UTXO catch-up step gets a turn
         * -- ~10 minutes with 7 legs and re-dials. That is the right order at
         * the tip, where every rotation fetches a block or two and applies
         * them. It is exactly wrong when the ARCHIVE is already far ahead of
         * the applied height: the blocks are on disk, downloading more helps
         * nothing, and the only useful work is apply -- which sat waiting for
         * a rotation to finish (2026-08-31, signet: 106k blocks on disk,
         * applied height frozen for the whole rotation).
         *
         * So when the backlog exceeds DL_APPLY_FIRST_BACKLOG the legs are NOT
         * synced this rotation: they keep their cheap liveness poll and the
         * tx-relay drain (which answers the peer's pings, so idle legs stay
         * connected), and the loop goes straight to catch-up. Normal
         * behaviour resumes the moment the backlog is under the threshold,
         * which at the tip is always. */
        long apply_backlog = 0;
        if(utxo_live_ok){
            long ah = utxo_live_applied_height();
            if(ah >= 0) apply_backlog = (long)(*(int*)(store_buf+24)) - ah;
        }
        int apply_first = apply_backlog > DL_APPLY_FIRST_BACKLOG;
        {
            long best = 0;
            if(g_node_status)
                for(int i=0;i<mux_n_out && i<RPC_MAX_PEERS;i++)
                    if(mux_out_fd[i]>=0 && g_node_status->peers[i].start_height > best)
                        best = g_node_status->peers[i].start_height;
            long atip = (long)(*(int*)(store_buf+24));
            long long nows = (long long)time(NULL);
            if(dl_should_parallel_fetch(atip, best, apply_backlog, nows, dl_parallel_last_s)){
                fprintf(stderr,"[dl] archive at %ld, peers announce %ld: %ld blocks behind -- running the parallel downloader (%d workers)\n",
                        atip, best, best-atip, g_catchup_workers);
                dl_parallel_last_s = nows;
                long got = dl_catchup(dir, g_catchup_workers);
                store_reload(store_buf);
                fprintf(stderr,"[dl] parallel downloader wrote %ld block(s); archive now %d\n", got, *(int*)(store_buf+24));
                continue;                  /* re-evaluate: apply-first will take over */
            }
        }
        if(apply_first != apply_first_prev){
            fprintf(stderr, apply_first
                ? "[dl] %ld blocks on disk ahead of the UTXO set -- applying before syncing legs\n"
                : "[dl] UTXO backlog %ld -- resuming normal leg rotation\n", apply_backlog);
            apply_first_prev = apply_first;
        }
        for(int i=0;i<mux_n_out;i++){
            if(g_shutdown_requested) break;   /* don't wait for a full rotation through every leg */
            if(mux_out_fd[i]<0){
                /* dead slot: re-dial (rate-limited), same logic as serve_mux */
                if(now_ms>=mux_out_nextretry[i]){ mux_next_peer(i, srcpool, nsrc, out_port); mux_out_nextretry[i]=now_ms+REDIAL_BACKOFF_MS; }
                continue;
            }
            /* Cheap liveness check BEFORE syncing: a peer that cleanly closed
             * or reset the connection shows up here as POLLHUP/POLLERR/POLLNVAL
             * with a zero timeout (non-blocking -- never delays the rotation).
             * Without this, do_outbound_sync's node_sync would just keep
             * returning ok!=1 on the dead fd forever with no log and no
             * re-dial (only a genuinely HUNG peer trips the SIGALRM budget
             * below) -- this is the serve_mux parent's own POLLHUP/POLLERR/
             * POLLNVAL pattern (see the accept loop above), mirrored here so
             * the download worker's peer drops are equally visible/handled. */
            struct pollfd pf = { mux_out_fd[i], POLLIN, 0 };
            if(poll(&pf, 1, 0) > 0 && (pf.revents & (POLLHUP|POLLERR|POLLNVAL))){
                fprintf(stderr,"[dl:%d] %s connection dropped (revents 0x%x); re-dialing\n",
                        i, mux_out_host[i], pf.revents);
                mux_next_peer(i, srcpool, nsrc, out_port);
                mux_out_nextretry[i]=now_ms+REDIAL_BACKOFF_MS;
                continue;
            }
            /* ---- transaction relay (receive side) -------------------------
             * Peers announce txs on these full-relay legs (we advertise
             * relay=1) and node_sync_multi's drains discard every inv
             * unexamined -- so until 2026-08-26 the production mempool had
             * never held a single P2P transaction. Drain the leg's buffered
             * messages here, BEFORE this rotation's sync pass: everything
             * the peer sent since the last rotation is sitting in the
             * socket buffer, and running the sync first would feed it all
             * into .hdr_drain's discard (the first deploy ran the drain
             * after the sync and accepted ~1 tx per 10 minutes; the invs
             * were being eaten a rotation later). Announced txs are
             * requested as MSG_WITNESS_TX -- type 1 would hand back
             * witness-stripped serializations, incident #10's exact bug
             * shape -- and replies run through the same tx_accept_validate
             * the inbound path uses, into the SHARED pool so the parent's
             * mempool RPCs see them. Cost when nothing is buffered: one
             * empty poll(2). */
            if(mux_out_fd[i]>=0 && txsub_worker_ready()){
                extern long txrelay_poll_leg(int fd, void* mp, int max_ms);
                long acc = txrelay_poll_leg(mux_out_fd[i], txsub_pool(), 250);
                { extern void txrelay_publish_orphans(void); txrelay_publish_orphans(); }
                if(acc>0){
                    /* per-leg attribution, ONE line a minute for all legs:
                     * the per-poll line was ~35 lines/min of the log with
                     * nothing the 30s tx_accept summary did not already
                     * total (2026-08-31 quiet rounds). */
                    static long leg_acc[MUX_MAX_OUT]; static long leg_last; static long leg_total;
                    if(i >= 0 && i < MUX_MAX_OUT) leg_acc[i] += acc;
                    leg_total += acc;
                    long now_s = (long)time(NULL);
                    if(leg_last == 0) leg_last = now_s;
                    if(now_s - leg_last >= 60){
                        extern long mpool_count(void*);
                        char parts[MUX_MAX_OUT*40]; int pn = 0; parts[0] = 0;
                        for(int k = 0; k < MUX_MAX_OUT && k < mux_n_out; k++){
                            if(leg_acc[k] <= 0) continue;
                            pn += snprintf(parts + pn, sizeof parts - (size_t)pn, "%s%d:%s +%ld",
                                           pn ? ", " : "", k, mux_out_host[k], leg_acc[k]);
                            if((size_t)pn >= sizeof parts - 1) break;
                        }
                        fprintf(stderr,"[txrelay] last %lds: +%ld tx accepted via legs [%s] (mempool %ld)\n",
                                now_s - leg_last, leg_total, parts, mpool_count(txsub_pool()));
                        memset(leg_acc, 0, sizeof leg_acc); leg_total = 0; leg_last = now_s;
                    }
                }
            }
            if(apply_first) continue;        /* see APPLY FIRST above */
            /* A sync pass on this leg would feed any reply still owed to the
             * relay layer into .drain's discard. Skip it while replies are
             * pending (bounded: the relay layer forgets after 1.5 s). */
            { extern int txrelay_replies_pending(int); extern void txrelay_note_sync_deferred(void);
              if(mux_out_fd[i]>=0 && txrelay_replies_pending(mux_out_fd[i])){ txrelay_note_sync_deferred(); continue; } }
            /* bounded sync pass on this leg (DL_BUDGET_SECS wall-clock) */
            struct sigaction sa, old; memset(&sa,0,sizeof sa);
            sa.sa_handler=mux_budget_alarm; sigemptyset(&sa.sa_mask);
            sigaction(SIGALRM,&sa,&old);
            mux_sync_budget_fired=0;
            mux_budget_fd = mux_out_fd[i];
            alarm((unsigned)DL_BUDGET_SECS);
            long n = do_outbound_sync(i);
            alarm(0); mux_budget_fd = -1; sigaction(SIGALRM,&old,NULL);
            if(mux_sync_budget_fired){
                fprintf(stderr,"[dl:%d] %s exceeded %gs budget; re-dialing\n",
                        i, mux_out_fd[i]>=0?mux_out_host[i]:"?", DL_BUDGET_SECS);
                mux_next_peer(i, srcpool, nsrc, out_port);
            }
            did |= (n>0)?1:0;
            /* ---- STAGE B: periodic fork probe -----------------------------
             * Runs only on a leg that just returned NOTHING, which is exactly
             * the situation a fork hides in: if the peer is on a competing
             * branch, node_sync stores nothing and looks indistinguishable
             * from "we are caught up". The probe re-asks with the same real
             * multi-hash locator and evaluates the answer with the full
             * validate -> locate fork -> compare work -> download -> verify
             * pipeline; every step before the destructive one can bail out
             * with the node completely unchanged.
             *
             * Rate-limited to ONE leg per REORG_PROBE_INTERVAL_MS so the
             * extra getheaders round trip is negligible against the per-leg
             * sync traffic, and bounded by the same SIGALRM budget the sync
             * pass uses so a stalled peer cannot hold the rotation.
             * Gated on BOTH chainwork (needed to compare) and live UTXO
             * tracking (needed for undo data). */
            if(reorg_ok && utxo_live_ok && n<=0 && mux_out_fd[i]>=0 && now_ms>=next_reorg_probe_ms){
                next_reorg_probe_ms = now_ms + REORG_PROBE_INTERVAL_MS;
                struct sigaction psa, pold; memset(&psa,0,sizeof psa);
                psa.sa_handler=mux_budget_alarm; sigemptyset(&psa.sa_mask);
                sigaction(SIGALRM,&psa,&pold);
                mux_sync_budget_fired=0;
                mux_budget_fd = mux_out_fd[i];
                alarm((unsigned)DL_BUDGET_SECS);
                long pr = reorg_probe_peer(mux_out_fd[i], store_buf, mux_out_host[i]);
                alarm(0); mux_budget_fd = -1; sigaction(SIGALRM,&pold,NULL);
                if(mux_sync_budget_fired){
                    fprintf(stderr,"[reorg] probe of %s exceeded %gs budget; re-dialing\n", mux_out_host[i], DL_BUDGET_SECS);
                    mux_next_peer(i, srcpool, nsrc, out_port);
                } else if(pr == 1){
                    /* The chain moved under us: re-anchor this leg and force
                     * a UTXO catch-up pass this rotation. */
                    anchor_locator(mux_out_loc[i]);
                    did = 1;
                } else if(pr < 0){
                    fprintf(stderr,"[reorg] probe of %s rejected a candidate chain (no action taken)\n", mux_out_host[i]);
                }
            }
            /* brief yield so we don't spin a CPU core when all legs are idle */
            if((i&1)==1){ usleep(20000); }
        }
        /* propagate this rotation's relay accepts: one inv per leg covering
         * everything accepted since the last rotation (never back to a tx's
         * own source); peers fetch with getdata, which the drain answers
         * from the pool */
        if(txsub_worker_ready()){
            extern long txrelay_announce(const int* fds, int nfds);
            txrelay_announce(mux_out_fd, mux_n_out);
        }
        { extern long addrself_maybe_announce_nets(const int*, const unsigned char*, const unsigned char*, int);
          for(int k=0;k<mux_n_out && k<MUX_MAX_OUT;k++){
              bmc_addr_t la;
              mux_out_net[k] = bmc_addr_from_string(&la, mux_out_host[k]) ? la.net : BMC_NET_IPV4;
          }
          addrself_maybe_announce_nets(mux_out_fd, mux_out_wants_v2, mux_out_net, mux_n_out); }
        rot++;
        /* Real-time UTXO catch-up: its OWN step, decoupled from any single
         * leg's do_outbound_sync return value. A per-leg local diff would
         * only ever see blocks THIS worker just synced; comparing the
         * store's true on-disk tip against the persisted applied-height
         * (utxo_live_catchup's own job) also picks up a sibling inbound
         * child's .do_block writes, which land in the shared archive
         * independently of any leg here. */
        /* STAGE B: same argument as the UTXO catch-up directly below --
         * chainwork must track the store's TRUE on-disk tip, not just what
         * this worker's own legs happened to store, because an inbound serve
         * child's .do_block writes land in the shared archive independently.
         * A no-op (one lseek) when already in step. */
        /* ---- block-relay-only legs (relay=0, no addr gossip) -------------
         * Kept topped up alongside the full-relay legs. Chosen from a
         * DIFFERENT netgroup than any existing leg where possible: two peers
         * in the same /16 are far more likely to be the same operator, which
         * defeats the point of having them. */
        for(int b=0; b<CFG_BRO_N(); b++){
            if(bro_fd[b] >= 0) continue;
            if((rot % 16) != 0) break;             /* rate-limit re-dials */
            for(int ci=0; ci<nsrc; ci++){
                if(dialer_proxy_configured()) continue;            /* would bypass the proxy */
                unsigned cip = pool_ipv4(srcpool[ci], NULL); if(!cip) continue;
                int clash=0;
                for(int k=0;k<mux_n_out;k++){
                    unsigned oip; if(inet_pton(AF_INET,mux_out_host[k],&oip)!=1) continue;
                    if(net_netgroup_v4(oip)==net_netgroup_v4(cip)){ clash=1; break; }
                }
                for(int k=0;k<CFG_BRO_N() && !clash;k++){
                    if(bro_fd[k]<0) continue;
                    unsigned oip; if(inet_pton(AF_INET,bro_host[k],&oip)!=1) continue;
                    if(net_netgroup_v4(oip)==net_netgroup_v4(cip)) clash=1;
                }
                if(clash) continue;
                int f = net_handshake_relay(srcpool[ci], 0 /* relay=0 */, 6);
                if(f>=0){
                    bro_fd[b]=f; strncpy(bro_host[b],srcpool[ci],63); bro_host[b][63]=0;
                    fprintf(stderr,"[net] block-relay-only %d = %s (fd %d, relay=0)\n", b, bro_host[b], f);
                    break;
                }
            }
        }

        /* ---- feeler: one short-lived probe every ~2 minutes ---------------
         * Validates a book entry and drops it. This is what keeps the address
         * book from rotting -- without it we only discover the rot at boot,
         * as happened on 2026-08-18 (1,974 entries, ~4% still answering). */
        if(g_cfg.max_feeler > 0 && now_ms >= next_feeler_ms && nsrc > 0){
            next_feeler_ms = now_ms + g_cfg.feeler_interval_ms;
            int pick = (int)((unsigned)rot * 2654435761u % (unsigned)nsrc);
            int alive = net_feeler_probe(srcpool[pick]);
            fprintf(stderr,"[net] feeler %s -> %s\n", srcpool[pick], alive?"alive":"dead");
        }

        if(reorg_ok) reorg_chainwork_sync(store_buf, 0);
        /* A catch-up failure is RECOVERABLE, not terminal. It used to set
         * utxo_live_ok=0, which left the node serving blocks with no UTXO
         * tracking at all -- silently, until a human noticed and restarted
         * it. That happened twice on 2026-08-18. The usual cause (a full
         * manifest) is cleared by a compaction, so: try recovery, retry
         * once, and on repeated failure back off and RETRY LATER rather
         * than giving up for the life of the process. */
        if(utxo_live_ok && now_ms >= utxo_retry_at_ms){
            phase_timer_t utxo_ct_pt; phase_start(&utxo_ct_pt);
            long ar = utxo_live_catchup(store_buf);
            if(ar < 0){
                fprintf(stderr,"[dl] utxo_live_catchup FAILED at height %ld -- attempting in-place recovery\n",
                        utxo_live_applied_height());
                long rounds = utxo_live_recover();
                ar = utxo_live_catchup(store_buf);
                if(ar >= 0){
                    utxo_fail_streak = 0;
                    fprintf(stderr,"[dl] utxo recovery SUCCEEDED (%ld compaction round(s)) -- tracking continues at height %ld\n",
                            rounds, utxo_live_applied_height());
                } else {
                    if(utxo_fail_streak < 30) utxo_fail_streak++;
                    long shift = utxo_fail_streak - 1; if(shift > 6) shift = 6;
                    long backoff = UTXO_RETRY_BASE_MS << shift;
                    if(backoff > UTXO_RETRY_MAX_MS) backoff = UTXO_RETRY_MAX_MS;
                    utxo_retry_at_ms = now_ms + backoff;
                    fprintf(stderr,"[dl] utxo STILL failing after recovery (streak=%ld) -- DEGRADED (no UTXO tracking), retrying in %lds\n",
                            utxo_fail_streak, backoff/1000);
                }
            } else if(utxo_fail_streak){
                fprintf(stderr,"[dl] utxo tracking healthy again after %ld failed attempt(s)\n", utxo_fail_streak);
                utxo_fail_streak = 0;
            }
            if(ar > 0){
                fprintf(stderr,"[dl] updating utxo: applied %ld block(s), now at height %ld, live=%ld (%.2fs)\n",
                        ar, utxo_live_applied_height(), live_utxo_disp(), phase_elapsed(&utxo_ct_pt));
            }
        }
        /* QUIESCENT POINT: catch-up has returned, so no put/del/flush is in
         * flight and a point query cannot race the writer. This is the only
         * place the worker answers gettxout. */
        txoq_service();
        /* new-block announcement: one choke point watching the store's tip,
         * so it fires no matter which path appended (mux keep-up leg,
         * realtime getdata loop, catch-up). Hash read straight from the
         * index record (store_get_tip_hash), printed big-endian like Core
         * logs it, so a line here greps against a Core debug.log. */
        {
            int now_tip = *(int*)(store_buf+24);
            if(last_seen_tip >= 0 && now_tip > last_seen_tip){
                unsigned char th[32]; char hex[65];
                if(store_get_tip_hash(store_buf, th) == 1){
                    for(int b=0;b<32;b++) sprintf(hex+b*2, "%02x", th[31-b]);
                    fprintf(stderr,"[dl] new block: height=%d hash=%s (+%d)\n",
                            now_tip, hex, now_tip-last_seen_tip);
                } else {
                    fprintf(stderr,"[dl] new block: height=%d (+%d)\n",
                            now_tip, now_tip-last_seen_tip);
                }
                dl_header_mirror_topup(store_buf);   /* keep the derived header mirror at the archive tip, whichever path appended */
                /* ZMQ hashblock/rawblock + the txid-index tail, from this
                 * same choke point for the same reason the log line is: it
                 * fires no matter which path appended the block.
                 *
                 * EVERY new block is handled, not just the tip. A catch-up
                 * burst advances the tip by many blocks at once, and a
                 * subscriber that received only the last one would silently
                 * miss the rest -- Core notifies per connected block, so this
                 * must too. The loop is bounded by the burst size and reads
                 * each block ONCE from the archive it was just written to,
                 * feeding both consumers. */
                if (zmqpub_active() || txit_active() || 1 /* bfi probes cheaply */){
                    static unsigned char zb[RPC_BLKSUBMIT_MAX];
                    for (int zh = last_seen_tip + 1; zh <= now_tip; zh++){
                        long bl = store_read_at(store_buf, (unsigned long)zh, zb, (long)sizeof zb);
                        if (bl <= 0){
                            fprintf(stderr,"[zmq] block %d unreadable; not published\n", zh);
                            continue;
                        }
                        /* txindex tail: append this block's txid records so
                         * getrawtransaction-by-txid keeps up with the tip
                         * (idempotent by height -- a replayed height is a
                         * no-op) */
                        txit_on_block(store_buf, zh, zb, bl);
                        tsp_on_block(store_buf, zh, zb, bl);
                        /* filter index tail: adopt/append (cheap probe when
                         * the backfill has not closed in yet) */
                        if (g_cfg.blockfilterindex)
                            bfi_on_block(store_buf, zh, zb, (unsigned long)bl);
                        /* address index (extension): ADDs from the block,
                         * DELs/TOUCHes from its undo records */
                        axt_on_block(store_buf, zh, zb, bl);
                        /* -blocknotify: after the indexes have taken the
                         * block, so a hook that queries us sees it. */
                        if (g_cfg.blocknotify[0]){
                            unsigned char bh[32]; char hx[65];
                            block_hash(bh, zb);
                            for (int _i = 0; _i < 32; _i++)
                                snprintf(hx + _i*2, 3, "%02x", bh[31-_i]);  /* display order */
                            notify_run(g_cfg.blocknotify, hx, "blocknotify");
                        }
                        /* -walletnotify: one run per transaction in this block
                         * that spends or pays this wallet (Core fires it on
                         * confirmation as well as on mempool arrival) */
                        if (g_cfg.walletnotify[0] && g_rpc_wallet.seed) walletnotify_block(zb, (long)bl);
                        /* mempool reconciliation (Core removeForBlock):
                         * confirmed txs leave pool+policy graph, txs
                         * CONFLICTING with this block's spends leave with
                         * their descendants, and the rolling minfee floor
                         * may decay again. Before this call nothing removed
                         * mined txs at all -- they lingered until
                         * -mempoolexpiry (LOG.md 2026-08-27 survey #1).
                         * This SUBSUMES mining-polish's plain mined-tx
                         * mpool_del callback (it also cleans the policy
                         * graph and counts conflicts) -- that callback path
                         * was removed at the 2026-08-27 policy-parity merge. */
                        { extern long tx_accept_block_connect_h(void*, const unsigned char*, unsigned long, long);
                          extern void tx_accept_set_tip_time(long, long);
                          extern void* mp_ext_area;
                          /* fee estimation's "chainstate is current": this block's time */
                          { unsigned int bt; memcpy(&bt, zb + 68, 4); tx_accept_set_tip_time((long)bt, -1); }
                          if (txsub_worker_ready() && mp_ext_area){
                              long mr = tx_accept_block_connect_h(mp_ext_area, zb, (unsigned long)bl, (long)zh);
                              if (mr > 0)
                                  fprintf(stderr,"[mempool] block %d: removed %ld pool tx (confirmed/conflicted)\n", zh, mr);
                          } }
                        if (!zmqpub_active()) continue;
                        /* The block HASH is sha256d over the 80-byte
                         * header, REVERSED: Core's notifier flips the bytes
                         * (data[31-i] = hash.begin()[i]) so the hashblock
                         * topic carries the DISPLAY-order hash getblockhash
                         * prints. Verified against real archived blocks by
                         * tests/zmq_realblock_check. */
                        unsigned char bh[32], bhr[32];
                        sha256d(bh, zb, 80);
                        for (int zi = 0; zi < 32; zi++) bhr[zi] = bh[31 - zi];
                        zmqpub_notify("hashblock", bhr, 32);
                        zmqpub_notify("rawblock", zb, (unsigned long)bl);
                    }
                }
            }
            /* keep mempool admission's maturity/flag anchor on the tip --
             * unconditionally, not only when a publisher is active */
            { extern void tx_accept_set_tip(long); tx_accept_set_tip(now_tip); }
            last_seen_tip = now_tip;
        }
        /* Drain transactions staged by the serve children (and by this
         * worker's own sendrawtransaction path) and service subscriber
         * handshakes. Both are cheap no-ops when ZMQ is unconfigured. */
        /* audit finding 8: subscriber servicing has its own thread now
         * (daemon/zmq_pub.c), so this loop -- whose job is block download --
         * no longer walks the subscriber list at all. Only the staged-tx
         * drain remains, which is a cheap no-op when ZMQ is unconfigured.
         * This is the shape Core has for free: libzmq services subscribers on
         * its own I/O thread and Core's hot paths never touch them. */
        if (zmqpub_active()) zmqn_drain();
        if(now_ms >= next_heartbeat_ms){
            int live_peers=0; for(int i=0;i<mux_n_out;i++) if(mux_out_fd[i]>=0) live_peers++;
            char upbuf[UPTIME_BUF];
            int failing=0; for(int k=0;k<mux_n_out;k++) if(g_sync_fail_streak[k]) failing++;
            char failbuf[32]; failbuf[0]=0;
            if(failing) snprintf(failbuf, sizeof failbuf, " sync_failing=%d", failing);
            fprintf(stderr,"[dl] heartbeat: tip=%d peers=%d/%d txouts=%ld uptime=%s%s%s\n",
                    *(int*)(store_buf+24), live_peers, mux_n_out,
                    utxo_live_ok?live_utxo_disp():-1L,
                    fmt_uptime(upbuf, (now_ms-boot_ms)/1000), failbuf,
                    utxo_fail_streak ? "  [UTXO DEGRADED -- retrying]" : "");
            if(g_cfg.maxuploadtarget_mb > 0)
                fprintf(stderr,"[dl] upload: %lldMB of %ldMB this 24h window\n",
                        upload_bytes_this_window()>>20, g_cfg.maxuploadtarget_mb);
            /* Relay-pool health. Silent when nothing has been parked, so a
             * node with no orphan traffic prints nothing extra. */
            { extern long txrelay_stats(long*,long*,long*,long*,long*,long*);
              long pk=0, rs=0, dr=0, ok=0, fl=0, held=0;
              if(txrelay_stats(&pk,&rs,&dr,&ok,&fl,&held))
                  fprintf(stderr,"[txrelay] orphans: %ld held, %ld parked, %ld resolved, "
                                 "%ld dropped; 1p1c: %ld accepted, %ld failed\n",
                          held, pk, rs, dr, ok, fl);
              { extern void txrelay_stats2(long*,long*,long*,long*,long*,long*);
                long t_ttl, t_ev, t_rj, t_pr, t_nf, t_rf; txrelay_stats2(&t_ttl,&t_ev,&t_rj,&t_pr,&t_nf,&t_rf);
                extern long txrelay_sync_deferred_count(void);
                extern void txrelay_stats3(long*,long*,long*);
                long t_ro, t_gu, t_wa; txrelay_stats3(&t_ro, &t_gu, &t_wa);
                if (dr || t_pr)
                    fprintf(stderr,"[txrelay] orphan drops: %ld ttl, %ld evicted, %ld rejected | parents requested %ld, notfound %ld, re-requested after timeout %ld, retried on another peer %ld (gave up %ld, in flight %ld), sync deferred %ld\n",
                            t_ttl, t_ev, t_rj, t_pr, t_nf, t_rf, t_ro, t_gu, t_wa, txrelay_sync_deferred_count()); } }
            next_heartbeat_ms = now_ms + DL_HEARTBEAT_MS;
        }
        if(!did){ usleep(200000); }   /* all idle: rest before next rotation */
        /* background leg-fill: gradually acquire live legs toward MUX_MAX_OUT
         * from the discovered candidate pool. Boot rarely lands all 8 at once
         * on a variable network, so keep trying to add a leg occasionally
         * (rate-limited) instead of giving up at the initial dial. Uses the
         * proven outbound_connect path (works for reachable peers). */
        /* background dials: install whatever completed since the last rotation */
        { dh_result_t dr; int dfd; char dhost[128];
          while(dh_poll(&dr, &dfd, dhost, sizeof dhost)){
              if(dr.ok && dfd >= 0){ if(!dh_install_leg(dhost, dfd, &dr)) fprintf(stderr, "[dial] %s: background dial landed but the leg was not installed\n", dhost); }
              else fprintf(stderr, "[dial] %s: background dial failed: %s\n", dhost, dr.why[0] ? dr.why : "?");
          } }
        /* reserved slots: at least ONE leg per reachable anonymity network,
         * dialled in the background, on top of the clearnet legs (Core keeps
         * an extra network-specific outbound for the same reason) */
        if((rot % 8)==0 && g_node_status && g_node_status->net_active && mux_n_out < MUX_WANT_OUT() + 2 && mux_n_out < MUX_MAX_OUT){
            static const int anon_nets[2] = { BMC_NET_TORV3, BMC_NET_I2P };
            for(int an = 0; an < 2 && dh_inflight_count() < DH_MAX; an++){
                int net = anon_nets[an];
                if(!dialer_net_reachable(net) || legs_on_net(net) > 0 || dh_inflight_net(net)) continue;
                int ci = dh_reserved_pick(an, net, srcpool, nsrc);
                if(ci >= 0) dh_start(srcpool[ci], out_port);
            }
        }
        if(mux_n_out - legs_anon() < MUX_WANT_OUT() && (rot % 8)==0){
            /* ONE summary line per pass, not one per candidate: this loop walks
             * the whole live pool (up to nsrc) when nothing connects, so a
             * per-candidate log would flood exactly when the node is sickest. */
            int topup_fail = 0; char topup_why[160] = "";
            /* ONE leg per pass, and at most a few failed dials: this loop runs
             * inline in the worker, and an anonymity-network dial costs tens of
             * seconds (circuit + handshake). Filling three empty slots with
             * onion peers in one pass starved the heartbeat for three minutes
             * (2026-09-01 01:34) and tripped the deploy guard; the next pass
             * (8 rotations later) fills the next slot. */
            int topup_filled = 0;
            for(int ci=0; ci<nsrc && mux_n_out - legs_anon() < MUX_WANT_OUT() && mux_n_out<MUX_MAX_OUT; ci++){
                if(topup_filled >= 1 || topup_fail >= 4) break;
                if(leg_is_anon_net(leg_net_of(srcpool[ci]))) continue;   /* the helper owns those */
                int already=0;
                for(int k=0;k<mux_n_out;k++) if(!strcmp(mux_out_host[k],srcpool[ci])){ already=1; break; }
                if(already) continue;
                int nfd=outbound_connect(srcpool[ci], 300, out_port);
                if(nfd>=0){
                    strncpy(mux_out_host[mux_n_out], srcpool[ci], 127);
                    mux_out_fd[mux_n_out]=nfd;
                    mux_out_wants_v2[mux_n_out]=(unsigned char)g_peer_wants_addrv2;
                    mux_out_peer[mux_n_out]=ci;
                    anchor_locator(mux_out_loc[mux_n_out]);
                    mux_out_nextretry[mux_n_out]=0;
                    { char pv[256]; format_peer_version_info(pv, sizeof pv);
                      fprintf(stderr,"[dl] filled outbound %d = %s (fd %d) %s addrv2=%d\n", mux_n_out, srcpool[ci], nfd, pv, (int)mux_out_wants_v2[mux_n_out]); }
                    rpc_fill_peer_slot(mux_n_out, srcpool[ci]);   /* publish peer to getpeerinfo */
                    mux_n_out++; topup_filled++;
                }
                else { if(!topup_fail++) snprintf(topup_why,sizeof topup_why,"%s: %s",
                                                  srcpool[ci], dial_fail_reason()); }
                /* if outbound_connect to this one hung/refused, move on to next */
            }
            if(topup_fail)
                fprintf(stderr,"[dl] outbound top-up: %d dial(s) failed, first %s\n",
                        topup_fail, topup_why);
        }
    }
}

/* The outbound multiplexer: ONE poll() loop over the listen socket + all N
 * outbound seed fds. Inbound accepts are forked to node_serve_loop children
 * (preserved behavior); outbound legs run inline (node_sync + announce).
 * `peers` = host names (pool of `pool_len`); `nwant` of them are connected on
 * entry at `out_port` (best effort), and dead legs are re-dialed by rotating
 * through the pool (D2 fix).
 *
 * IMPORTANT: the listener socket is created FIRST, before any outbound
 * connect. The outbound legs are best-effort; if they all fail the mux still
 * serves inbound from the listener. Creating the listener up front also
 * means `serve` is live to inbound peers immediately (the listener exists
 * even while the outbound legs are still connecting), which the old order
 * (connect-all-outbound-then-listen) did not guarantee. */
/* ---- embedded JSON-RPC server (docs/RPC_LIVE_NODE.md) --------------------
 * The serve daemon hosts the same rpc_server as bitcoin_rpcd so it can answer
 * LIVE-node RPCs (getconnectioncount/getnetworkinfo, later peers/mempool) that
 * a read-only process cannot. The live counts cross the fork boundary via a
 * MAP_SHARED node_status_t (g_node_status) allocated before the worker fork:
 * the download worker publishes n_out/tip_height, the parent publishes
 * n_inbound, and the parent's RPC thread reads it. (Includes + g_node_status /
 * g_rpc_wallet are declared near the top of the file so serve_download_worker,
 * defined earlier, can publish into the shared status.) */

/* Parse rpcport/rpcuser/rpcpassword out of the daemon's config file (node_config
 * treats them as foreign keys, so we read them here). */
static void serve_rpc_read_creds(const char* cfgpath, int* port,
                                 char* user, size_t ucap, char* pass, size_t pcap){
    *port = g_chainp->default_rpc_port;   /* 8332 main / 18443 regtest */
    user[0] = 0; pass[0] = 0;
    if (!cfgpath) return;
    FILE* f = fopen(cfgpath, "r"); if (!f) return;
    char line[1024];
    while (fgets(line, sizeof line, f)){
        char* p = line; while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || !*p) continue;
        char* eq = strchr(p, '='); if (!eq) continue; *eq = 0;
        char* k = p; char* v = eq + 1;
        size_t vl = strlen(v); while (vl && (v[vl-1]=='\n'||v[vl-1]=='\r'||v[vl-1]==' '||v[vl-1]=='\t')) v[--vl] = 0;
        size_t kl = strlen(k); while (kl && (k[kl-1]==' '||k[kl-1]=='\t')) k[--kl] = 0;
        if      (!strcmp(k, "rpcport"))     *port = atoi(v);
        else if (!strcmp(k, "rpcuser"))     { strncpy(user, v, ucap-1); user[ucap-1] = 0; }
        else if (!strcmp(k, "rpcpassword")) { strncpy(pass, v, pcap-1); pass[pcap-1] = 0; }
    }
    fclose(f);
}

/* Start the embedded RPC server in the serve parent (non-blocking: rpc_server
 * runs its own accept thread). No-op with a log line if creds are absent. */
/* getblocktemplate per-tx "sigops" (sigop COST units): the legacy count x4
 * (WITNESS_SCALE_FACTOR). Core additionally counts P2SH-redeem and witness
 * sigops, which need the prevout scripts -- a UTXO view this path does not
 * resolve. A LOWER BOUND, documented in PARITY_PLAN; never fabricated. */
static long gbt_sigops_legacy4(const unsigned char* tx, unsigned long len){
    extern long tx_legacy_sigops(const unsigned char*, unsigned long);
    return tx_legacy_sigops(tx, len) * 4;
}

/* wallet-encryption glue: the live seed the RPC wallet points at, and the
 * loaded mnemonic encryptwallet seals. Installed/read via the extern hooks
 * wallet_enc_state.c and rpc_wallet_ops.c call. */
static unsigned char g_wallet_seed[64];
static char g_wallet_mnemonic[768];
static char g_wallet_bip39pass[256];
static void wenc_install_seed(const unsigned char* s){
    if (s){ memcpy(g_wallet_seed, s, 64); g_rpc_wallet.seed = g_wallet_seed; }
    else  { memset(g_wallet_seed, 0, 64); g_rpc_wallet.seed = 0; }
}
/* Registered with wallet_enc_state.c as its mnemonic provider (see
 * wenc_set_mnemonic_provider). wenc_current_mnemonic() lives there so the RPC
 * layer and unit tests link against the state module, not this file. */
static int provide_wallet_mnemonic(char* out, long cap, char* pass_out, long pcap){
    if (!g_wallet_mnemonic[0]) return 0;
    snprintf(out, (size_t)cap, "%s", g_wallet_mnemonic);
    snprintf(pass_out, (size_t)pcap, "%s", g_wallet_bip39pass);
    return 1;
}

/* -persistmempool reload on its own thread (see serve_start_rpc). */
static pthread_t g_mempool_reload_thread;
static volatile int g_mempool_reload_started;
static void* mempool_reload_thread(void* arg){
    (void)arg;
    extern long rpc_node_mempool_load(const char* path);
    long acc = rpc_node_mempool_load("mempool.dat");
    if(acc < 0) fprintf(stderr,"[mempool] mempool.dat present but could not be read -- starting empty\n");
    return NULL;
}
/* Called from the shutdown path before the dump: a reload still running
 * aborts on the flag within milliseconds (mpd_import_one polls it every
 * 3 ms and then drains the file without waiting), and the dump must not
 * race its last submission. */
static void mempool_reload_join(void){
    if(g_mempool_reload_started){ pthread_join(g_mempool_reload_thread, NULL); g_mempool_reload_started = 0; }
}

static void serve_start_rpc(const char* dir, const char* cfgpath){
    static char user[128], pass[256]; int port;
    serve_rpc_read_creds(cfgpath, &port, user, sizeof user, pass, sizeof pass);
    /* Start on ANY usable credential, not just rpcuser/rpcpassword.
     *
     * This used to bail out whenever those two were absent, which meant
     * deleting a plaintext password from the config -- the thing the security
     * audit asked for -- silently turned the whole RPC server off. Cookie
     * authentication was already implemented, enabled by default and
     * verified working; it just never got the chance to run, because the
     * server never started.
     *
     * Core's behaviour is the right one: the cookie IS the default
     * credential, and rpcuser/rpcpassword are the legacy alternative. So the
     * server starts if a cookie will be emitted, or an rpcauth entry exists,
     * or a user/password pair is configured -- and only refuses when there
     * is genuinely no way to authenticate, which would otherwise be an open
     * RPC port. */
    if (!user[0] || !pass[0]){
        if (!g_cfg.rpccookie && g_cfg.n_rpcauth == 0){
            fprintf(stderr, "[rpc] no rpcuser/rpcpassword, no rpcauth and rpccookie=0 "
                            "-- nothing could authenticate, so the embedded RPC server "
                            "is disabled\n");
            return;
        }
        fprintf(stderr, "[rpc] no rpcuser/rpcpassword -- using %s%s%s\n",
                g_cfg.rpccookie ? "cookie authentication" : "",
                (g_cfg.rpccookie && g_cfg.n_rpcauth) ? " and " : "",
                g_cfg.n_rpcauth ? "rpcauth credentials" : "");
    }
    (void)dir;   /* the daemon has already chdir'd into the datadir */
    if (rpc_chain_open(NULL))
        fprintf(stderr, "[rpc] block archive opened (chain RPCs live)\n");
    else
        fprintf(stderr, "[rpc] no archive index -- chain RPCs will report -28 until built\n");
    /* chain identity + rules for the RPC layer (regtest: halving 150,
     * fPowNoRetargeting; mainnet values are rpc_chain's own defaults) */
    rpc_chain_set_chainparams(g_chainp->name, g_chainp->halving_interval,
                              g_chainp->pow_no_retargeting,
                              g_chainp->allow_min_difficulty,
                              g_chainp->pow_limit_bits,
                              g_chainp->enforce_bip94);
    /* getblocktemplate proposal mode evaluates through the worker's
     * submit channel (rpc_node.c owns the staging) */
    { extern long rpc_node_submit_proposal(const char*, char*, unsigned long);
      rpc_chain_set_proposal(rpc_node_submit_proposal); }
    rpc_node_set_status_rw(g_node_status);   /* writable: enables sendrawtransaction staging */
    /* getnetworkinfo tells the truth about the transports: reachability from
     * the dialer, our i2p destination, and (once the tor listener is up,
     * below in tor_onion_listener) the onion hostname. */
    { extern int dialer_net_reachable(int);
      extern const char* dialer_i2p_b32(void);
      extern void rpc_node_set_net_hooks(int (*)(int), const char* (*)(void));
      rpc_node_set_net_hooks(dialer_net_reachable, dialer_i2p_b32); }
    /* Core -walletdir: every wallet file lives there (absolute, or relative
     * to the chain directory we are in). Created 0700 if absent; the RPC
     * wallet layer learns it through its setter, never from node_config. */
    /* wallet policy defaults from the config (2026-09-01) -- independent of walletdir */
    { rpc_wops_defaults wd;
      wd.addresstype = rpc_wops_type_from_name(g_cfg.addresstype); if(wd.addresstype < 0) wd.addresstype = WOT_BECH32;
      wd.changetype  = g_cfg.changetype[0] ? rpc_wops_type_from_name(g_cfg.changetype) : -1;
      wd.txconfirmtarget = g_cfg.txconfirmtarget; wd.walletrbf = g_cfg.walletrbf; wd.walletbroadcast = g_cfg.walletbroadcast;
      wd.mintxfee_satkvb = g_cfg.mintxfee_satkvb; wd.fallbackfee_satkvb = g_cfg.fallbackfee_satkvb;
      wd.discardfee_satkvb = g_cfg.discardfee_satkvb; wd.consolidatefeerate_satkvb = g_cfg.consolidatefeerate_satkvb;
      wd.maxapsfee_sat = g_cfg.maxapsfee_sat; wd.avoidpartialspends = g_cfg.avoidpartialspends;
      wd.spendzeroconfchange = g_cfg.spendzeroconfchange;
      rpc_wops_set_defaults(&wd); }
    if(g_cfg.walletdir[0]){
        struct stat wsb;
        if(stat(g_cfg.walletdir, &wsb) != 0){
            if(mkdir(g_cfg.walletdir, 0700) == 0) fprintf(stderr, "[wallet] created walletdir %s\n", g_cfg.walletdir);
            else fprintf(stderr, "[wallet] walletdir %s: cannot create (%s) -- wallet files will fail to open\n", g_cfg.walletdir, strerror(errno));
        } else if(!S_ISDIR(wsb.st_mode)) fprintf(stderr, "[wallet] walletdir %s is not a directory\n", g_cfg.walletdir);
        extern void rpc_wops_set_walletdir(const char*);
        rpc_wops_set_walletdir(g_cfg.walletdir);
        fprintf(stderr, "[wallet] walletdir=%s\n", g_cfg.walletdir);
    }
    /* Wallet bootstrap: if the CLI's own wallet store is present in the
     * datadir, load it (BMC_WALLET_PASS env or <store>.pass file, exactly the
     * CLI's own resolution order) and hand the RPC layer the seed --
     * getnewaddress/getwalletinfo etc. then serve the REAL wallet. Absent
     * store = wallet RPCs stay unconfigured, exactly as before. */
    /* wallet encryption (daemon/wallet_enc_state.c): the seed installer lets
     * walletpassphrase/walletlock flip the live RPC seed at runtime, and the
     * mnemonic provider lets encryptwallet seal the loaded wallet. If an
     * ENCRYPTED store exists, adopt it locked and skip the plaintext load. */
    if(g_cfg.disablewallet){
        fprintf(stderr, "[rpc] wallet disabled (disablewallet=1) -- wallet RPCs report no wallet\n");
    } else
    { extern void wenc_set_seed_installer(void (*)(const unsigned char*));
      extern void wenc_set_mnemonic_provider(int (*)(char*, long, char*, long));
      extern void rpc_wops_set_seed_installer(void (*)(const unsigned char*));
      extern int  wenc_boot(const char*);
      wenc_set_seed_installer(wenc_install_seed);
      wenc_set_mnemonic_provider(provide_wallet_mnemonic);
      /* multi-wallet (rpc_wallet_ops.c): loadwallet/createwallet install the
       * switched-to wallet's seed through the SAME installer the encryption
       * unlock path uses -- one seed slot, one way to write it. */
      rpc_wops_set_seed_installer(wenc_install_seed);
      char wd[512]; snprintf(wd, sizeof wd, "%s", dir ? dir : ".");
      if (g_cfg.walletdir[0] ? wenc_boot(g_cfg.walletdir) : (wenc_boot(".") || wenc_boot(wd))){
          /* An encrypted wallet boots LOCKED, as Core's does. If the operator
           * has configured a passphrase source (walletpassfile= or
           * $BMC_WALLET_PASS) unlock it here, so moving from the weak v2 store
           * to this container does not silently turn the wallet RPCs off --
           * the key still lives outside the datadir either way. With no
           * passphrase source the wallet simply stays locked until
           * walletpassphrase, which is the correct default. */
          extern int wenc_unlock(const char*, long, long);
          char boot_pass[256];
          if (wallet_pass_load(boot_pass, (int)sizeof boot_pass, 0)
              && wenc_unlock(boot_pass, (long)strlen(boot_pass), 0) == 1){
              fprintf(stderr, "[rpc] encrypted wallet adopted and unlocked from the configured passphrase source\n");
          } else {
              fprintf(stderr, "[rpc] encrypted wallet adopted (locked -- use walletpassphrase)\n");
          }
          memset(boot_pass, 0, sizeof boot_pass);
      } else {
    { extern int wallet_store_load(const char*, char*, int, char*, int);
      extern long wallet_mnemonic_seed(unsigned char seed[64], const char* mn,
                                       const char* pass, long passlen);
      static char mn[768], wpass[256];
      char wdc[512]; snprintf(wdc, sizeof wdc, "%s/bmcwallet.dat", g_cfg.walletdir[0] ? g_cfg.walletdir : ".");
      const char* cand[3] = { g_cfg.walletdir[0] ? wdc : "bmcwallet.dat", "bmcwallet.dat", "data/bmcwallet.dat" };
      for (int wi = (g_cfg.walletdir[0] ? 0 : 1); wi < 3; wi++){
          struct stat wsb;
          if (stat(cand[wi], &wsb) != 0) continue;
          wpass[0] = 0;
          /* audit finding 2: the passphrase comes from the environment or a
           * root-owned file OUTSIDE the datadir -- never from <store>.pass,
           * which put the key in the same directory (and the same backup) as
           * the ciphertext it protects. */
          wallet_pass_load(wpass, (int)sizeof wpass, 0);
          wallet_pass_warn_legacy(cand[wi]);
          if (wallet_store_load(cand[wi], mn, (int)sizeof mn, wpass, (int)sizeof wpass) == 0){
              wallet_mnemonic_seed(g_wallet_seed, mn, wpass[0] ? wpass : NULL,
                                   wpass[0] ? (long)strlen(wpass) : 0);
              g_rpc_wallet.seed = g_wallet_seed;
              /* keep the mnemonic available so encryptwallet can seal it */
              snprintf(g_wallet_mnemonic, sizeof g_wallet_mnemonic, "%s", mn);
              snprintf(g_wallet_bip39pass, sizeof g_wallet_bip39pass, "%s", wpass);
              memset(mn, 0, sizeof mn);
              fprintf(stderr, "[rpc] wallet store %s loaded (wallet RPCs live)\n", cand[wi]);
          } else {
              fprintf(stderr, "[rpc] wallet store %s present but not loadable "
                              "(encrypted? set BMC_WALLET_PASS or walletpassfile=)\n", cand[wi]);
          }
          break;
      } } } }
    /* Hand the RPC layer the SHARED mempool (allocated pre-fork by
     * mempool_configure, written by the worker + inbound children) so
     * getrawmempool/getmempoolinfo report the real pool. All-null when the
     * static per-process fallback is in play (maxmempool=0). */
    { extern void* mp_ext_area; extern void* mp_ext_polstate; extern void* mp_ext_feeest;
      extern unsigned long mp_ext_blobcap;
      extern void mp_lock(void); extern void mp_unlock(void);
      extern long mempool_time_of(const unsigned char*);
      extern long mpool_policy_entry(void*, const unsigned char*,
                                     unsigned long long*, unsigned long long*);
      extern long mpool_policy_entry_info(void*, const unsigned char*, struct mp_entry_info*);
      extern long mpool_policy_estimate(void*, unsigned long long*, unsigned long long*);
      extern unsigned long long mpool_policy_min_fee(void*);
      extern long mpool_count(void*);
      extern const unsigned char* mpool_get(void*, const unsigned char*, unsigned long*);
      rpc_mempool_hooks h = {
          .mp = mp_ext_area, .polstate = mp_ext_polstate,
          .maxbytes = (long long)mp_ext_blobcap,
          .count = mpool_count, .get = mpool_get,
          .lock = mp_lock, .unlock = mp_unlock,
          .time_of = mempool_time_of,
          .pol_entry = mpool_policy_entry,
          .pol_entry_info = mpool_policy_entry_info,
          .estimate = mpool_policy_estimate,
          /* main.c's existing extern types the length as long; the hooks
           * member says unsigned long -- ABI-identical on x86-64 SysV. */
          .sha256d = (void(*)(unsigned char*, const void*, unsigned long))sha256d,
          .min_fee = mpool_policy_min_fee,
          .feeest = mp_ext_feeest,
          .min_relay_satkvb = g_cfg.minrelaytxfee_satkvb > 0 ? (unsigned long long)g_cfg.minrelaytxfee_satkvb : 100ULL };
      rpc_node_set_mempool(&h);
      /* getblocktemplate reads the same pool through rpc_chain */
      rpc_chain_set_mempool(&h, gbt_sigops_legacy4); }
    /* gettxoutsetinfo: the tool-derived reader (daemon/utxo_setinfo_rpc.c) */
    { extern long utxo_setinfo_rpc_run(int, void*, char*, unsigned long);
      rpc_chain_set_utxosetinfo((long (*)(int, void*, char*, unsigned long))utxo_setinfo_rpc_run);
      { extern long csi_rpc_run(int, void*, char*, unsigned long);
        extern long csi_file_height(void);
        extern void rpc_chain_set_coinstats(long (*)(int, void*, char*, unsigned long));
        extern void rpc_chain_set_coinstats_height(long (*)(void));
        rpc_chain_set_coinstats(csi_rpc_run);
        rpc_chain_set_coinstats_height(csi_file_height); } }
    { extern long utxo_dump_rpc_run(const char*, int (*)(long, unsigned char*),
                                    long*, unsigned long long*, char*, unsigned long);
      rpc_chain_set_utxodump(utxo_dump_rpc_run); }
    { extern long utxo_scan_rpc_run(const unsigned char*, const unsigned int*, int, void*,
                                    long, long*, long*, unsigned long long*, unsigned long long*,
                                    int*, char*, unsigned long);
      rpc_chain_set_utxoscan(utxo_scan_rpc_run); }
    /* getnodeaddresses / getaddrmaninfo read the persistent address book.
     * Its own handle, opened here: the download worker runs in the FORKED
     * child and its handle is not reachable from the parent's RPC thread.
     * amr_* re-reads peers.dat per call, so two handles see the same file. */
    { extern void rpc_node_set_addrbook_dir(const char*);
      /* always: even with connect= the book is real (addpeeraddress writes
       * it, getnodeaddresses reads it); the old gate hid it behind
       * connect_only for no reason that survives the v2 book */
      rpc_node_set_addrbook_dir(".");
      if (0)
          fprintf(stderr, "[rpc] address book unavailable; "
                          "getnodeaddresses/getaddrmaninfo will report empty\n"); }
    /* the external signer command, when the operator configured one */
    { extern void rpc_signer_set_cmd(const char*);
      rpc_signer_set_cmd(g_cfg.signer[0] ? g_cfg.signer : NULL); }
    { extern void rpc_chain_set_gbt_policy(long, long, long, int, int);
      extern void rpc_chain_set_maxtipage(long);
      rpc_chain_set_gbt_policy(g_cfg.blockmaxweight, g_cfg.blockreservedweight, g_cfg.blockmintxfee_satkvb,
                               g_cfg.blockversion, g_cfg.printpriority);
      rpc_chain_set_maxtipage(g_cfg.maxtipage); }
    { extern void (*txr_on_accept)(const unsigned char*, const unsigned char*, unsigned long);
      txr_on_accept = g_cfg.walletnotify[0] ? txr_walletnotify_hook : 0; }
    /* -wallet=<name>: Core loads every named wallet at start-up. This node
     * serves ONE active wallet, so the first name is loaded and the rest are
     * named as skipped (loadwallet switches between them at run time). */
    for(int wi = 0; wi < g_cfg.n_wallet_names; wi++){
        if(wi > 0){ fprintf(stderr,"[wallet] wallet=%s: not loaded -- this node serves one active wallet at a time (loadwallet switches)\n", g_cfg.wallet_names[wi]); continue; }
        rj_val* p = rj_arr(); rj_arr_push(p, rj_str(g_cfg.wallet_names[wi]));
        rj_val* r = NULL; long ec = 0; const char* em = NULL;
        int ok = rpc_dispatch("loadwallet", p, &g_rpc_wallet, &r, &ec, &em);
        fprintf(stderr,"[wallet] wallet=%s: %s%s\n", g_cfg.wallet_names[wi], ok == 1 ? "loaded" : "NOT loaded: ", ok == 1 ? "" : (em ? em : "?"));
        if(r) rj_free(r); rj_free(p);
    }
    /* getaddednodeinfo reports the operator's addnode= list verbatim. */
    rpc_node_set_addednodes(g_cfg.n_addnode ? (const char (*)[64])g_cfg.addnode : NULL,
                            g_cfg.n_addnode);
    rpc_node_set_zmq(g_cfg.zmq_hashblock, g_cfg.zmq_hashtx,
                     g_cfg.zmq_rawblock, g_cfg.zmq_rawtx);
    /* getblockfilter reads spent-prevout scripts from undo_<h>.dat */
    { extern long undo_replay(long, int (*)(void*, const unsigned char*, unsigned int,
                                            unsigned long long, unsigned int, unsigned char,
                                            const unsigned char*, unsigned short), void*);
      rpc_chain_set_undo((long (*)(long, int (*)(void*, const unsigned char*, unsigned int,
                                                 unsigned long long, unsigned int, unsigned char,
                                                 const unsigned char*, unsigned short), void*))undo_replay); }
    /* the wallet rescan reads the archive through rpc_chain's store handle */
    { static unsigned char rescan_buf[4*1024*1024];   /* one max-size block */
      rpc_wops_set_scanner(rpc_chain_read_block_at, rescan_buf, (long)sizeof rescan_buf,
                           rpc_chain_tip_height); }
    /* Core InitHTTPAllowList: 127.0.0.0/8 and ::1 are always allowed, then
     * each -rpcallowip. A malformed subnet is fatal there and here -- an ACL
     * typo that silently allows LESS is a support call; one that silently
     * allows MORE is an incident, and refusing avoids having to work out
     * which happened. */
    { extern void mpool_policy_set_bytespersigop(unsigned long long);
      mpool_policy_set_bytespersigop((unsigned long long)g_cfg.bytespersigop); }
    { extern void rpc_node_set_relay_floors(unsigned long long, unsigned long long);
      rpc_node_set_relay_floors((unsigned long long)g_cfg.minrelaytxfee_satkvb,
                                (unsigned long long)g_cfg.incrementalrelayfee_satkvb); }
    rpc_acl_reset();
    for(int i = 0; i < g_cfg.n_rpcallowip; i++){
        if(!rpc_acl_add(g_cfg.rpcallowip[i])){
            fprintf(stderr, "[rpc] FATAL: rpcallowip=%s is not a valid address "
                            "or subnet -- refusing to start\n", g_cfg.rpcallowip[i]);
            exit(1);
        }
    }
    const char* bindaddr = g_cfg.rpcbind;
    if(bindaddr[0] && rpc_acl_configured() == 0){
        /* Core httpserver.cpp:225, verbatim in intent. */
        fprintf(stderr, "[rpc] Option -rpcbind was ignored because -rpcallowip "
                        "was not specified, refusing to allow everyone to connect\n");
        bindaddr = "";
    }
    if(rpc_acl_configured() > 0)
        fprintf(stderr, "[rpc] allow list: loopback + %d configured subnet(s); "
                        "binding %s\n", rpc_acl_configured(),
                        bindaddr[0] ? bindaddr : "127.0.0.1 (loopback)");

    rpc_server_cfg cfg = {0}; cfg.port = port; cfg.user = user; cfg.pass = pass; cfg.wallet = &g_rpc_wallet;
    cfg.bind_addr = bindaddr; cfg.allows = rpc_acl_allows;
    cfg.threads = g_cfg.rpcthreads; cfg.workqueue = g_cfg.rpcworkqueue; cfg.timeout_s = g_cfg.rpcservertimeout;
    rpc_cookie_set_perms(g_cfg.rpccookieperms);
    rpc_whitelist_clear();
    for(int wi = 0; wi < g_cfg.n_rpcwhitelist; wi++)
        if(!rpc_whitelist_add(g_cfg.rpcwhitelist[wi]))
            fprintf(stderr,"[rpc] rpcwhitelist=%s rejected (expected <user>:<rpc1>,<rpc2>,...)\n", g_cfg.rpcwhitelist[wi]);
    rpc_whitelist_set_default(g_cfg.rpcwhitelistdefault);
    if(g_cfg.n_rpcwhitelist)
        fprintf(stderr,"[rpc] %d rpcwhitelist entr%s; users without one may call %s\n", g_cfg.n_rpcwhitelist,
                g_cfg.n_rpcwhitelist == 1 ? "y" : "ies", g_cfg.rpcwhitelistdefault == 0 ? "anything" : "nothing (rpcwhitelistdefault)");
    int actual = 0; char err[256];
    if (rpc_server_start(&cfg, &actual, err, sizeof err) != 0){
        fprintf(stderr, "[rpc] server start failed: %s\n", err);
        return;
    }
    fprintf(stderr, "[rpc] JSON-RPC server on %s:%d (live-node + chain, user=%s)\n",
            bindaddr[0] ? bindaddr : "127.0.0.1", actual, user);
    /* -rpccookiefile, else <datadir>/.cookie -- Core's default auth method.
     * The daemon has already chdir'd into the (per-chain) datadir, so the
     * bare relative name lands in the right place on every chain. */
    /* -pid: Core writes bitcoind.pid so an init script can find the process.
     * Written after the RPC port is bound, i.e. once the node is actually
     * up, so the file's existence means something. */
    if (g_cfg.pidfile[0]){
        FILE* pf = fopen(g_cfg.pidfile, "w");
        if (pf){ fprintf(pf, "%d\n", (int)getpid()); fclose(pf);
                 fprintf(stderr,"[boot] pid %d written to %s\n", (int)getpid(), g_cfg.pidfile); }
        else     fprintf(stderr,"[boot] could not write -pid=%s: %s\n", g_cfg.pidfile, strerror(errno));
    }
    if (g_cfg.startupnotify[0]) notify_run(g_cfg.startupnotify, "", "startupnotify");
    /* -rpcauth: hashed credentials, so a fixed password need not sit in the
     * config in plaintext. A malformed entry is REPORTED, never dropped. */
    for (int i = 0; i < g_cfg.n_rpcauth; i++){
        if (!rpc_auth_add(g_cfg.rpcauth[i]))
            fprintf(stderr,"[rpc] rpcauth entry %d is malformed (want user:salt$hash) -- ignored\n", i + 1);
    }
    if (rpc_auth_count())
        fprintf(stderr,"[rpc] %d rpcauth credential(s) loaded\n", rpc_auth_count());
    if (g_cfg.rpccookie){
        const char* cpath = g_cfg.rpccookiefile[0] ? g_cfg.rpccookiefile : ".cookie";
        if (rpc_cookie_write(cpath))
            fprintf(stderr, "[rpc] cookie authentication enabled (%s, mode 0600)\n", cpath);
        else
            fprintf(stderr, "[rpc] could not write the cookie file %s: %s -- "
                            "rpcuser/rpcpassword remains the only way in\n", cpath, strerror(errno));
    }
    /* -persistmempool: reload the dump the previous run left behind. Same
     * code the importmempool RPC uses, so the two cannot drift apart on the
     * format. A missing file is the ordinary case -- a fresh datadir, or a
     * node that has never saved one -- and is not an error. Runs AFTER the RPC
     * server is listening (2026-08-31): it used to gate it, and a reload of a
     * few hundred transactions kept RPC dark for 13 minutes. The RPC thread
     * answers meanwhile; getrawmempool is briefly partial, as in Core. */
    if(CFG_PERSISTMEMPOOL()){
        struct stat mst;
        if(stat("mempool.dat", &mst) == 0){
            /* The reload must yield to SIGTERM in THIS process, not only in
             * the worker: the hook was installed in the worker alone, so the
             * serve parent ignored systemd's SIGTERM until two 90 s
             * validation timeouts aborted the import (184 s on 2026-09-01
             * 08:22; SIGKILLed by the deploy escalation at 08:38, with no
             * mempool.dat saved). And it runs on a thread: inline, it kept
             * the serve loop -- inbound accept, the legs, the shutdown
             * check -- from starting for the 10-20 minutes a ten-thousand-
             * entry dump takes at the worker's rotation budget. */
            { extern void rpc_node_set_shutdown_flag(const volatile sig_atomic_t*);
              rpc_node_set_shutdown_flag(&g_shutdown_requested); }
            if(pthread_create(&g_mempool_reload_thread, NULL, mempool_reload_thread, NULL) == 0)
                g_mempool_reload_started = 1;
            else mempool_reload_thread(NULL);
        } else {
            fprintf(stderr,"[mempool] no mempool.dat to reload (persistmempool=1)\n");
        }
    }
}


/* ---- inbound over Tor ----------------------------------------------------
 * Three things have to line up: a loopback socket for tor to forward to, an
 * onion service pointing at it, and a control connection held open for the
 * lifetime of the process.
 *
 * That last one is not optional. ADD_ONION without the Detach flag ties the
 * service to the control connection, so closing it destroys the service. That
 * is the behaviour we want -- a dead node should not leave a reachable
 * address behind -- but it means the torctl_t is deliberately never closed.
 *
 * The virtual port is the CHAIN DEFAULT, not our local port: Core notes that
 * using anything else fingerprints the node, since a peer dialling the onion
 * sees the port. The local target may be any free loopback port; Core uses
 * default+1 and so do we. */
static torctl_t g_torctl = { .fd = -1 };

static int tor_onion_listener(int port){
    if(!g_cfg.listen){ fprintf(stderr,"[tor] listen=0 -- no onion service\n"); return -1; }
    if(!g_cfg.listenonion) { fprintf(stderr,"[tor] listenonion=0 -- no onion service\n"); return -1; }

    /* Core's default is the CHAIN default port + 1 (mainnet 8334), not our
     * configured port + 1 -- those differ whenever port= is set, and using
     * ours collided with rpcport in testing. */
    int target_port = g_chainp->default_port + 1;
    int lo = lsock_onion(target_port, &target_port);
    if(lo < 0) return -1;

    char ctrl_ip[64] = "127.0.0.1"; int ctrl_port = 9051;
    if(g_cfg.torcontrol[0]){
        const char* c = strrchr(g_cfg.torcontrol, ':');
        if(c){ long n = (long)(c - g_cfg.torcontrol);
               if(n > 0 && n < (long)sizeof ctrl_ip){ memcpy(ctrl_ip, g_cfg.torcontrol, (size_t)n); ctrl_ip[n]=0; }
               ctrl_port = atoi(c+1); }
        else snprintf(ctrl_ip, sizeof ctrl_ip, "%s", g_cfg.torcontrol);
    }
    char target[64]; snprintf(target, sizeof target, "127.0.0.1:%d", target_port);
    if(!torctl_add_onion(&g_torctl, ctrl_ip, ctrl_port,
                         g_cfg.torpassword[0] ? g_cfg.torpassword : NULL, NULL,
                         g_chainp->default_port, target, "onion_v3_private_key", 20000)){
        fprintf(stderr,"[tor] no onion service: %s\n", g_torctl.err[0] ? g_torctl.err : "unknown");
        fprintf(stderr,"[tor] (outbound onion is unaffected; only INBOUND needs the control port)\n");
        close(lo);
        return -1;
    }
    fprintf(stderr,"[tor] onion service %s:%d -> %s (key onion_v3_private_key)\n",
            g_torctl.onion, g_chainp->default_port, target);
    { extern int addrself_set_onion(const char*, unsigned short);
      if(addrself_set_onion(g_torctl.onion, (unsigned short)g_chainp->default_port))
          fprintf(stderr,"[tor] announcing %s:%d to onion peers\n",
                  g_torctl.onion, g_chainp->default_port); }
    { extern void rpc_node_set_onion_local(const char*, int);
      rpc_node_set_onion_local(g_torctl.onion, g_chainp->default_port); }
    return lo;
}

/* ---- inbound over I2P ----------------------------------------------------
 * Core's i2p.cpp: an inbound I2P connection is a SAM "STREAM ACCEPT" on our
 * session -- a blocking request that completes when a peer connects, at
 * which point THAT SAM socket carries the peer's bytes. There is no
 * listening socket to poll, so an acceptor thread sits in STREAM ACCEPT and
 * hands each completed stream (fd + the caller's .b32.i2p) to the serve loop
 * over a pipe, which the loop polls beside its listeners. The stream then
 * takes the same inbound path as a TCP or onion accept: capacity check,
 * fork, handshake. Its network is i2p by construction (the socket came from
 * SAM), exactly as an onion inbound is onion by which listener accepted it.
 * The session itself belongs to the dialer (dialer_init, before the worker
 * fork), and SAM lets any number of stream sockets reference it. */
typedef struct { int fd; char b32[80]; } i2p_inbound_t;
static int g_i2p_pipe[2] = {-1, -1};
static void* i2p_accept_thread(void* arg){
    (void)arg;
    extern int dialer_i2p_accept(char* peer_b32, long cap, int timeout_ms);
    for(;;){
        if(g_shutdown_requested) break;
        char b32[80]; b32[0] = 0;
        int fd = dialer_i2p_accept(b32, sizeof b32, 600000);   /* no caller in 10 min: re-arm */
        if(fd < 0){ if(g_shutdown_requested) break; sleep(5); continue; }   /* a SAM hiccup: back off, re-arm */
        i2p_inbound_t m; m.fd = fd; snprintf(m.b32, sizeof m.b32, "%s", b32);
        if(write(g_i2p_pipe[1], &m, sizeof m) != (ssize_t)sizeof m) close(fd);
    }
    return NULL;
}
/* returns the pipe's read end for the serve loop to poll, or -1 when
 * inbound I2P is off (listen=0, i2pacceptincoming=0, or no SAM session) */
static int i2p_inbound_start(void){
    extern int dialer_i2p_ready(void);
    extern const char* dialer_i2p_b32(void);
    if(!g_cfg.listen || !g_cfg.i2pacceptincoming || !dialer_i2p_ready()) return -1;
    if(pipe(g_i2p_pipe) != 0) return -1;
    pthread_t th;
    if(pthread_create(&th, NULL, i2p_accept_thread, NULL) != 0){
        close(g_i2p_pipe[0]); close(g_i2p_pipe[1]); g_i2p_pipe[0] = g_i2p_pipe[1] = -1; return -1; }
    pthread_detach(th);
    fprintf(stderr,"[i2p] accepting inbound streams on %s (SAM STREAM ACCEPT)\n", dialer_i2p_b32());
    return g_i2p_pipe[0];
}

static int serve_mux(int port, const char* peers[], int nwant, int pool_len, int out_port, int l, int l6, int lo, int li2p){
    /* Prefer the persisted ADDRESS BOOK over whatever pool the caller passed.
     *
     * The sole non-`-connect` caller passes `catchup_seeds` -- the six DNS
     * seed HOSTNAMES -- so before 2026-08-23 every dial and every re-dial in
     * this loop went to a seed, forever, while peers.dat held thousands of
     * real peers. See the long note in serve_download_worker for what that
     * looked like in production and why it is wrong. Seeds stay as the
     * emergency fallback they are documented to be: used only when the book
     * yields nothing, which is a genuinely fresh node. */
    static char mux_dle[64][DL_POOL_SLOT];
    const char* bookpool[64]; int nbook = 0;
    if(!g_cfg.connect_only && addr_book()){
        int np = dl_pool_from_book(NULL, mux_dle, 64);
        for(int i=0;i<np && nbook<64;i++) bookpool[nbook++] = mux_dle[i];
    }
    if(nbook > 0){
        fprintf(stderr,"[mux] using %d peer(s) from the address book (seeds are bootstrap-only)\n", nbook);
        peers = bookpool; pool_len = nbook;
    } else if(!g_cfg.connect_only){
        fprintf(stderr,"[mux] address book empty -- falling back to the seed list\n");
    }
    /* connect up to nwant outbound peers up front (the listener `l` is already
     * live and passed in, so inbound serving is available even while the
     * outbound legs are still connecting). Clamped to pool_len so we never
     * read past the pool (it may be smaller than nwant). */
    for(int i=0;i<nwant && i<pool_len && i<MUX_MAX_OUT;i++){
        int fd=outbound_connect(peers[i], 300, out_port);
        if(fd<0){ fprintf(stderr,"[mux] outbound %s failed: %s\n", peers[i], dial_fail_reason()); continue; }
        strncpy(mux_out_host[mux_n_out], peers[i], 127);
        mux_out_fd[mux_n_out]=fd;
        mux_out_wants_v2[mux_n_out]=(unsigned char)g_peer_wants_addrv2;
        mux_out_peer[mux_n_out]=i;
        anchor_locator(mux_out_loc[mux_n_out]);
        fprintf(stderr,"[mux] outbound %d = %s (fd %d) addrv2=%d\n", mux_n_out, peers[i], fd, (int)mux_out_wants_v2[mux_n_out]);
        mux_n_out++;
    }
    fprintf(stderr, "serving on port %d (%d outbound peer(s))...\n", port, mux_n_out);
    long long rot=0;
    /* pfds[0] is the listener, and is -1 when listen=0. poll() ignores a
     * negative fd and returns revents==0 for it, so the accept branch below
     * is naturally dead in outbound-only mode -- no separate code path. */
    /* +NETPERM_MAX_BIND for the -whitebind listeners, which sit after the
     * onion slot and before the legs. The leg offset is DERIVED below, so
     * adding these cannot reintroduce the off-by-one that once made every leg
     * read the previous leg's revents. */
    struct pollfd pfds[MUX_MAX_OUT+4+NETPERM_MAX_BIND];   /* +1: the I2P acceptor pipe */
    for(;;){
        if(g_node_status) g_node_status->n_inbound = (int)g_inbound_n;   /* for the RPC thread */
        int nfds=0;
        pfds[nfds].fd=l;     pfds[nfds].events=POLLIN; pfds[nfds].revents=0; nfds++;
        /* the IPv6 listener sits beside it; -1 when the host has no IPv6,
         * and poll() ignores a negative fd, so this is dead weight then */
        int v6slot = nfds;
        pfds[nfds].fd=l6;    pfds[nfds].events=POLLIN; pfds[nfds].revents=0; nfds++;
        /* the onion service's loopback target; -1 when listenonion is off or
         * tor is unreachable, and poll() ignores a negative fd */
        int onionslot = nfds;
        pfds[nfds].fd=lo;    pfds[nfds].events=POLLIN; pfds[nfds].revents=0; nfds++;
        /* the I2P acceptor thread's pipe; -1 when inbound I2P is off */
        int i2pslot = nfds;
        pfds[nfds].fd=li2p;  pfds[nfds].events=POLLIN; pfds[nfds].revents=0; nfds++;
        /* -whitebind listeners: peers arriving here carry that entry's
         * permissions, decided by WHICH socket accepted them. */
        int wbslot = nfds;
        for(int wi = 0; wi < g_wb_n; wi++){
            pfds[nfds].fd=g_wb_fd[wi]; pfds[nfds].events=POLLIN; pfds[nfds].revents=0; nfds++;
        }
        /* WHERE THE LEGS BEGIN, derived rather than written down. This used to
         * be a hardcoded 2, and when the IPv6 listener took pfds[1] the leg
         * loop kept starting at 1 -- every leg then read the PREVIOUS leg's
         * revents. Deriving it means adding a listener cannot reintroduce
         * that, which is the only reason this variable exists. */
        const int legs_start = nfds;
        for(int i=0;i<mux_n_out;i++){ if(mux_out_fd[i]<0) continue; pfds[nfds].fd=mux_out_fd[i]; pfds[nfds].events=POLLIN; pfds[nfds].revents=0; nfds++; }
        if(g_dl_worker_exited && !g_shutdown_requested){
            int st = (int)g_dl_worker_status;
            if (WIFSIGNALED(st)) fprintf(stderr,"[serve] FATAL: download worker pid %d died on signal %d -- exiting so systemd restarts the unit\n", (int)g_dl_worker_pid, WTERMSIG(st));
            else fprintf(stderr,"[serve] FATAL: download worker pid %d exited with status %d -- exiting so systemd restarts the unit\n", (int)g_dl_worker_pid, WEXITSTATUS(st));
            _exit(1);
        }
        if(g_shutdown_requested){
            fprintf(stderr,"[serve] shutting down (signal %d): tip=%d outbound_legs=%d\n",
                    (int)g_shutdown_requested, *(int*)(store_buf+24), mux_n_out);
            /* -persistmempool: dump BEFORE the worker is signalled, while the
             * shared pool is still quiescent and nothing is evicting under
             * the writer. */
            mempool_reload_join();
            if(CFG_PERSISTMEMPOOL()){
                long w = rpc_node_mempool_save("mempool.dat");
                if(w >= 0) fprintf(stderr,"[mempool] saved %ld transaction(s) to mempool.dat\n", w);
                else       fprintf(stderr,"[mempool] could not save mempool.dat\n");
            }
            if(g_dl_worker_pid>0){
                kill(g_dl_worker_pid, SIGTERM);
                fprintf(stderr,"[serve] forwarded SIGTERM to download worker pid %d\n", (int)g_dl_worker_pid);
            }
            /* run BEFORE the credential and pidfile go, so a hook that
             * wants to read either still can */
            if(g_cfg.shutdownnotify[0]) notify_run(g_cfg.shutdownnotify, "", "shutdownnotify");
            /* a dead node must not leave a usable credential on disk, nor a
             * pidfile pointing at a pid that is about to be reused */
            rpc_cookie_remove();
            if(g_cfg.pidfile[0]) unlink(g_cfg.pidfile);
            _exit(0);
        }
        int pr=poll(pfds, nfds, 300);
        if(pr<0){ if(errno==EINTR) continue; break; }
        /* -mempoolexpiry sweep. Bounded scan of a fixed table, so running it
         * once a minute costs nothing measurable and keeps the pool from
         * accumulating transactions no one will ever mine. */
        /* -maxuploadtarget: meter what we have actually served, and refuse new
         * inbound once over budget. Existing connections are left alone --
         * cutting a peer mid-block would just make it retry. */
        { static long long next_upl_ms = 0;
          long long ums; { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
                           ums = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
          if(ums >= next_upl_ms){ next_upl_ms = ums + 5000L; upl_sample(); } }

        { static long long next_expiry_ms = 0;
          long long nms; { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
                           nms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
          if(nms >= next_expiry_ms){ next_expiry_ms = nms + 60000L; mempool_expire_now(); } }
        /* inbound accept -> fork a serve child (unchanged semantics).
         * Either listener can be ready; the v6 one carries cjdns peers. */
        int ready_v4 = (pfds[0].revents & (POLLIN|POLLHUP|POLLERR)) != 0;
        int ready_v6 = (l6 >= 0 && (pfds[v6slot].revents & (POLLIN|POLLHUP|POLLERR)) != 0);
        int ready_on = (lo >= 0 && (pfds[onionslot].revents & (POLLIN|POLLHUP|POLLERR)) != 0);
        int ready_i2p = (li2p >= 0 && (pfds[i2pslot].revents & POLLIN) != 0);
        int wb_ready = -1;                       /* index into g_wb_fd, or -1 */
        for(int wi = 0; wi < g_wb_n; wi++)
            if(pfds[wbslot+wi].revents & (POLLIN|POLLHUP|POLLERR)){ wb_ready = wi; break; }
        if(ready_v4 || ready_v6 || ready_on || ready_i2p || wb_ready >= 0){
            struct sockaddr_in6 ca6; socklen_t cal6 = sizeof ca6;
            struct sockaddr_in ca; socklen_t cal=sizeof ca;
            int c;
            char peerdesc[80];
            unsigned accepted_perms = 0;
            if(wb_ready >= 0){
                /* Same rule as the onion listener above: the property comes
                 * from the socket, not the source address. That is what makes
                 * whitebind usable for a peer whose address you cannot
                 * predict. */
                int wfd = g_wb_fd[wb_ready];
                c = accept(wfd,(struct sockaddr*)&ca,&cal);
                accepted_perms = netperm_for_fd(wfd);
                snprintf(peerdesc, sizeof peerdesc, "%s:%d", inet_ntoa(ca.sin_addr), ntohs(ca.sin_port));
                if(c >= 0)
                    fprintf(stderr,"[serve] inbound on whitebind listener from %s (noban)\n", peerdesc);
            } else if(ready_i2p){
                /* Handed over by the SAM acceptor thread: the socket is the
                 * SAM stream itself, past STREAM STATUS RESULT=OK, carrying
                 * the peer's raw bytes from here on. */
                i2p_inbound_t m;
                if(read(li2p, &m, sizeof m) == (ssize_t)sizeof m){
                    c = m.fd;
                    snprintf(peerdesc, sizeof peerdesc, "%s:0", m.b32);
                    fprintf(stderr,"[serve] inbound over i2p from %s\n", m.b32);
                } else c = -1;
            } else if(ready_on){
                /* Arrived on the onion service's loopback target, so it IS an
                 * onion peer -- established by WHICH SOCKET accepted it, not
                 * by looking at the source address, which is always
                 * 127.0.0.1 here and would be indistinguishable from a local
                 * connection. This is Core's rule (net.cpp: inbound_onion is
                 * a membership test on the onion bind list).
                 *
                 * The peer's real address is unknowable by construction --
                 * that is what the onion service provides -- so it is neither
                 * ban-checked by address nor eligible for address-based
                 * whitelisting. Core makes the same exemption explicitly. */
                c = accept(lo,(struct sockaddr*)&ca,&cal);
                snprintf(peerdesc, sizeof peerdesc, "onion-inbound");
                if(c >= 0) fprintf(stderr,"[serve] inbound over onion (via the local tor service)\n");
            } else if(ready_v4){
                c = accept(l,(struct sockaddr*)&ca,&cal);
                snprintf(peerdesc, sizeof peerdesc, "%s:%d", inet_ntoa(ca.sin_addr), ntohs(ca.sin_port));
                /* A ban has to cover INBOUND too. ctl_is_banned guarded only
                 * the dial path, so a banned peer could simply connect to us
                 * and be served -- which makes setban look enforced while it
                 * is half enforced. */
                if(c >= 0 && !ready_on){
                    char bip[64]; snprintf(bip, sizeof bip, "%s", inet_ntoa(ca.sin_addr));
                    if(ctl_is_banned(bip)){
                        fprintf(stderr,"[serve] refused inbound from banned %s\n", peerdesc);
                        close(c); c = -1;
                    }
                }
            } else {
                c = accept(l6,(struct sockaddr*)&ca6,&cal6);
                bmc_addr_t pa; memset(&pa, 0, sizeof pa);
                pa.len = 16; memcpy(pa.addr, &ca6.sin6_addr, 16);
                pa.net = (pa.addr[0] == 0xfc) ? BMC_NET_CJDNS : BMC_NET_IPV6;
                pa.port = ntohs(ca6.sin6_port);
                bmc_addr_to_string_port(peerdesc, sizeof peerdesc, &pa);
                if(c >= 0) fprintf(stderr,"[serve] inbound %s (%s)\n", peerdesc, bmc_net_name(pa.net));
            }
            /* Fold new heights into the PARENT's index before forking, so
             * the child inherits a current one and its own top-up is a
             * no-op. Without this each child re-scans everything appended
             * since boot, and says so in the log once per connection. */
            if(c>=0) peer_sock_buffers(c);
            if(c>=0) serve_idx_topup();
            if(c>=0 && upload_note_and_check(0)){
                /* over -maxuploadtarget for this 24h window */
                close(c); c = -1;
            }
            if(c>=0 && g_inbound_n >= CFG_INBOUND_LIMIT()){
                /* At capacity: accept and close immediately so the connection
                 * is refused cleanly rather than sitting in the backlog, and
                 * do NOT fork. Rate-limited log -- under a flood this would
                 * otherwise be the loudest line in the file. */
                static long long last_full_log_ms = 0;
                long long nms; { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
                                 nms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
                if(nms - last_full_log_ms > 10000){
                    fprintf(stderr,"[serve] inbound at capacity (%d/%d) -- refusing new connections\n",
                            (int)g_inbound_n, CFG_INBOUND_LIMIT());
                    last_full_log_ms = nms;
                }
                close(c);
                c = -1;
            }
            if(c>=0){
                /* Refresh our in-memory store extent from the on-disk archive
                 * so this (and each forked child) serves blocks the download
                 * WORKER appended since boot -- serving reads block bytes fresh
                 * from disk, but the tip bound comes from store_buf+16, which
                 * only advances if we re-read index.dat's real size here. */
                struct stat st;
                if(stat("index.dat",&st)==0 && st.st_size>0 && st.st_size>=48){
                    long real = st.st_size;
                    long mine = *(long*)(store_buf+16);
                    if(real>mine) *(long*)(store_buf+16)=real;
                }
                pid_t w=fork();
                if(w==0){
                    close(l);
                    /* This child serves exactly one peer, so the permissions
                     * its listener granted are simply this process's. No
                     * shared table, no fd keying, nothing to clean up when the
                     * connection ends. */
                    g_conn_perms = accepted_perms;
                    /* -inboundrelaypercent: past that share of the inbound
                     * budget we answer with fRelay=0, as Core does, so the
                     * peer sends us no transactions (blocks and addrs still
                     * flow). Counted over all inbound connections, which is
                     * Core's count of relaying inbound peers when every
                     * earlier peer relays. */
                    { extern unsigned char node_relay_flag;
                      long lim = CFG_INBOUND_LIMIT();
                      node_relay_flag = (lim > 0 && (long)g_inbound_n * 100 > lim * g_cfg.inboundrelaypercent) ? 0 : 1; }
                    for(int wi = 0; wi < g_wb_n; wi++) close(g_wb_fd[wi]);
                    /* BIP324 first, if enabled. A v1 peer is detected in-band
                     * -- it opens with magic + "version" + five NULs, and any
                     * mismatch in those 16 bytes proves v2 -- and detection
                     * PEEKS, so a v1 peer's version message is left on the
                     * socket for the v1 path below. Once a session is up,
                     * node_accept_handshake and the whole serve loop run
                     * UNCHANGED: p2p_read/p2p_write route by file descriptor.
                     * This runs in the child, so a failure cannot affect the
                     * parent or any other peer. */
                    const char* v2res = "v1";
                    if(CFG_V2TRANSPORT()){
                        int v2 = bmc_v2_handshake(c, 0, 8000);
                        if(v2 < 0){
                            fprintf(stderr,"[serve] inbound %s v2 handshake failed -- dropping\n", peerdesc);
                            close(c); _exit(0);
                        }
                        v2res = v2 == 1 ? "v2" : "v1";
                    }
                    /* record who this is and arm the violation callback
                     * before any peer bytes are dispatched */
                    { const char* q = strrchr(peerdesc, ':');
                      size_t n = q ? (size_t)(q - peerdesc) : strlen(peerdesc);
                      if(n >= sizeof g_cur_peer_ip) n = sizeof g_cur_peer_ip - 1;
                      memcpy(g_cur_peer_ip, peerdesc, n); g_cur_peer_ip[n] = 0; }
                    g_serve_violation_hook = serve_violation_report;
                    int hok = node_accept_handshake(c);
                    char pv[256]; pv[0]=0; if(hok==1) format_peer_version_info(pv, sizeof pv);
                    close(l6 >= 0 ? l6 : l);
                    fprintf(stderr,"[serve] inbound %s %s [%s] (pid %d) %s\n", peerdesc,
                            hok==1?"connected":"handshake failed", v2res, getpid(), pv);
                    if(hok==1)
                        node_serve_loop(c, (mkdir("logs", 0755), node_log_open(g_logpath)), store_buf, ht_idx, out_buf, (long)sizeof out_buf);
                    close(c); _exit(0);
                }
                close(c);
                if(w > 0){ g_inbound_n++; upl_track(w); }
                fprintf(stderr,"[serve] inbound %s accepted -> child pid %d (%d/%d inbound)\n",
                        peerdesc, w, (int)g_inbound_n, CFG_INBOUND_LIMIT());
            }
        }
        /* outbound: on rotation, pull from each peer (periodic getheaders-from-
         * tip keeps us current); also pull immediately if a peer fd is readable
         * (it sent data we should react to). Round-robin spreads the load so
         * idle peers each get polled roughly once per mux_n_out iterations. */
        rot++;
        /* pfds[0] = IPv4 listener, pfds[1] = IPv6 listener, legs from 2.
         * This started at 1 and was NOT shifted when the v6 slot was
         * inserted, so every leg read the PREVIOUS leg's revents and the
         * last leg's was never examined (2026-08-28 pre-deploy review). */
        int poll_idx=legs_start;
        long long now_ms = (long long)(clock() * 1000.0 / CLOCKS_PER_SEC);
        for(int i=0;i<mux_n_out;i++){
            if(mux_out_fd[i]<0){                          /* dead slot: re-dial (rate-limited) */
                if(now_ms >= mux_out_nextretry[i]){ mux_next_peer(i, peers, pool_len, out_port); mux_out_nextretry[i]=now_ms+REDIAL_BACKOFF_MS; }
                continue;
            }
            short ev = pfds[poll_idx].revents;
            /* A permanent peer-side error/hangup/INVAL means the leg is dead:
             * close and re-dial a rotated seed (D2 fix) instead of syncing on a
             * broken socket forever. */
            if(ev & (POLLHUP|POLLERR|POLLNVAL)){
                fprintf(stderr,"[mux:%d] %s dropped (revents 0x%x); re-dialing\n", i, mux_out_host[i], ev);
                mux_next_peer(i, peers, pool_len, out_port);
                mux_out_nextretry[i]=now_ms+REDIAL_BACKOFF_MS;
                poll_idx++;
                continue;
            }
            bool due=(rot % mux_n_out)==(long long)i;     /* periodic */
            if(ev & POLLIN) due=true;                     /* data */
            /* Bounded: each leg's node_sync must not starve inbound accepts.
             * do_outbound_sync_bounded caps the wall-clock and re-dials the
             * leg if it exceeds the budget, so the loop always returns to
             * poll()+accept() promptly even at large store scale. */
            if(due) do_outbound_sync_bounded(i, peers, pool_len, out_port);
            poll_idx++;
        }
    }
    return 0;
}


int main(int argc, char** argv){
    signal(SIGPIPE, SIG_IGN);   /* broken peer connections must not kill the node */
    /* counting reaper instead of SIG_IGN: we must know how many inbound
     * children are live to enforce MAX_INBOUND (see the budget above). */
    { struct sigaction sc; memset(&sc,0,sizeof sc); sc.sa_handler=reap_children;
      sigemptyset(&sc.sa_mask); sc.sa_flags=SA_RESTART|SA_NOCLDSTOP;
      sigaction(SIGCHLD,&sc,NULL); }
    signal(SIGTERM, handle_shutdown_signal);
    signal(SIGINT, handle_shutdown_signal);
    /* Launch banner -- an unmistakable marker so a restart is obvious when
     * scrolling one continuously-appended production log (the unit uses
     * StandardOutput=append:). Built with snprintf + fputs, not the
     * timestamp-wrapped fprintf, so the ===== rules stay clean; the banner
     * carries its own explicit UTC clock. First output of the process. */
    {
        time_t _bt = time(0); struct tm _g; gmtime_r(&_bt, &_g);
        char _ts[32]; strftime(_ts, sizeof _ts, "%Y-%m-%d %H:%M:%S UTC", &_g);
        char _b[512];
        snprintf(_b, sizeof _b,
            "\n"
            "======================================================================\n"
            "===== bmc-bitcoind  LOG START: %s\n"
            "=====   pid %d  v%d.%d.%d  built %s %s  mode=%s\n"
            "======================================================================\n",
            _ts, (int)getpid(), NODE_VERSION_MAJOR, NODE_VERSION_MINOR, NODE_VERSION_PATCH,
            __DATE__, __TIME__, argc>=2?argv[1]:"?");
        fputs(_b, stderr); fflush(stderr);
    }
    /* ---- -datadir= / -conf= (Core's spelling) -----------------------------
     * The datadir was positional and the config file was found by searching
     * relative to it, so every other node tool's habit -- `-datadir=`,
     * `-conf=` -- simply did not work here. Both are accepted now, anywhere
     * on the command line, and the positional form still works so nothing
     * that already runs this binary changes.
     *
     * Flags are stripped out first; what remains keeps the old positional
     * meaning, so `bitcoind -datadir=/x serve` and `bitcoind serve /x` are
     * the same invocation. */
    const char* flag_datadir = NULL; const char* flag_conf = NULL;
    { static char* pos[16]; int np = 0;
      for(int i = 0; i < argc; i++){
          if(i > 0 && !strncmp(argv[i], "-datadir=", 9)){ flag_datadir = argv[i] + 9; continue; }
          if(i > 0 && !strncmp(argv[i], "-conf=", 6)){    flag_conf    = argv[i] + 6; continue; }
          if(np < 16) pos[np++] = argv[i];
      }
      argv = pos; argc = np; }
    if(flag_conf){
        node_config_set_conf_path(flag_conf);
        if(access(flag_conf, R_OK) != 0){
            fprintf(stderr,"[boot] -conf=%s is not readable: %s\n", flag_conf, strerror(errno));
            return 2;
        }
    }
    if(argc < 2 || (argc < 3 && !flag_datadir)){
        fprintf(stderr,"usage: %s [-datadir=<dir>] [-conf=<file>] sync <dir> | ibd <dir> | follow <dir> | serve <dir> <port> | server-test <dir>\n", argv[0]);
        return 2; }
    const char* mode = argv[1];
    const char* dir = flag_datadir ? flag_datadir : argv[2];
    /* Resolve <dir> to an ABSOLUTE path before chdir so the store opens in the
     * right directory regardless of the caller's cwd (soak analysis found a
     * caller-relative chdir silently opened the wrong store when the node was
     * launched from another directory). realpath fails only if <dir> does not
     * exist, which chdir would reject anyway. */
    char absp[4096];
    if(!realpath(dir, absp)){ fprintf(stderr,"[boot] realpath(%s) failed: %s\n", dir, strerror(errno)); return 1; }
    if(chdir(absp)!=0){ fprintf(stderr,"[boot] chdir(%s) failed: %s\n", absp, strerror(errno)); return 1; }
    /* Load durable tuning BEFORE anything reads it -- and before the fork, so
     * the download worker inherits the same resolved values. */
    { char cfgpath[512];
      node_config_load(node_config_path(absp, cfgpath, sizeof cfgpath));
      /* -logtimestamps/-logtimemicros/-logthreadnames/-logsourcelocations take
       * effect from the config echo onward (weak globals in log_ts.h) */
      g_log_timestamps = g_cfg.logtimestamps; g_log_timemicros = g_cfg.logtimemicros;
      g_log_threadnames = g_cfg.logthreadnames; g_log_sourcelocations = g_cfg.logsourcelocations;
      if(g_cfg.debuglogfile[0])
          snprintf(g_logpath, sizeof g_logpath, "%s",
                   !strcmp(g_cfg.debuglogfile, "0") ? "/dev/null" : g_cfg.debuglogfile);
      node_config_log();
      /* Join the config to the passphrase module HERE. Neither side may
       * reference the other: node_config.o is linked into targets with no
       * wallet, and wallet_pass.o is linked (via RPCLIBS) into 31 targets
       * with no config. main.c is the only place that has both -- pushing the
       * value across here is what keeps both link sets independent. */
      wallet_pass_set_file(g_cfg.walletpassfile); }
    /* ---- 2026-09-01 option-surface completion: push the config into the
     * subsystems that own each behaviour (none of them include node_config.h) */
    if(g_cfg.shrinkdebugfile) log_shrink(g_logpath);
    { /* -uacomment: Core renders "/Name:ver(c1; c2)/" */
      extern unsigned char node_ua_buf[256]; extern unsigned long long node_ua_len;
      char ua[256]; int n = snprintf(ua, sizeof ua, "%s", NODE_UA_STRING);
      if(g_cfg.n_uacomment && n > 1 && ua[n-1] == '/'){
          n--; ua[n] = 0;                                   /* drop the closing slash */
          n += snprintf(ua + n, sizeof ua - n, "(");
          for(int i = 0; i < g_cfg.n_uacomment && n < (int)sizeof ua - 4; i++)
              n += snprintf(ua + n, sizeof ua - n, "%s%s", i ? "; " : "", g_cfg.uacomment[i]);
          if(n > (int)sizeof ua - 3) n = (int)sizeof ua - 3;
          n += snprintf(ua + n, sizeof ua - n, ")/");
      }
      if(n > 255) n = 255;
      memcpy(node_ua_buf, ua, (size_t)n); node_ua_len = (unsigned long long)n;
      rpc_node_set_user_agent(ua);
      if(g_cfg.n_uacomment) fprintf(stderr,"[boot] user agent: %s\n", ua); }
    { extern void serve_cfilters_set_enabled(int); serve_cfilters_set_enabled(g_cfg.peerblockfilters); }
    /* Advertise NODE_P2P_V2 once the config is known, as Core does in
     * init.cpp. A peer has no other way to learn that we will accept a
     * BIP324 handshake, and nothing on the wire reveals it. */
    { extern unsigned long long node_services;
      if(g_cfg.peerblockfilters) node_services |= (1ULL << 6);   /* NODE_COMPACT_FILTERS: -peerblockfilters */
      if(CFG_V2TRANSPORT()){
          node_services |= BMC_NODE_P2P_V2;
          /* Report how many known peers we could actually dial over v2. This
           * is not decoration: outbound v2 is gated on the address book, the
           * book is opened by RELATIVE path, and if that ever failed the
           * feature would go silently inert with every test still passing --
           * which is exactly how a relative `asmap` path once disabled itself
           * on regtest. A zero here, with a non-empty book, is the symptom. */
          long known = 0, cap = 0;
          { ab2_t* b = ab2_open(".", 0);
            if(b){
                long n = ab2_count(b);
                for(long i = 0; i < n; i++){
                    ab2_rec_t r;
                    if(!ab2_get(b, i, &r)) continue;
                    known++;
                    if(r.services & BMC_NODE_P2P_V2) cap++;
                }
                ab2_close(b);
            } }
          fprintf(stderr,"[net] BIP324 v2 transport enabled (services=0x%llx); "
                         "%ld of %ld known peers advertise v2\n",
                  node_services, cap, known);
      } else {
          fprintf(stderr,"[net] BIP324 v2 transport disabled by config -- v1 only\n");
      } }
    /* Chain selection (daemon/chainparams.c). bitcoin.conf lives at -- and
     * was just read from -- the BASE datadir; each non-main chain gets its
     * own SUBDIRECTORY of it (Core's layout: <datadir>/regtest), so chains
     * can never share block/UTXO/wallet state. Everything below this point
     * operates on the cwd, so the chdir into the per-chain dir isolates all
     * of it at once. Must run before mempool_configure/store_init (their
     * files land in the per-chain dir) and before any socket (net_magic). */
    /* A custom signet challenge must be set BEFORE selection: it determines
     * the network magic, so selecting first would briefly install the public
     * signet's magic and then change it under whatever had already read it. */
    if(g_cfg.signetchallenge[0]){
        if(!chainparams_set_signet_challenge(g_cfg.signetchallenge)){
            fprintf(stderr, "[chain] FATAL: signetchallenge is not valid hex "
                            "(or is empty/too long); refusing to start\n");
            return 1;
        }
        if(strcmp(g_cfg.chain, "signet") != 0)
            fprintf(stderr, "[chain] warning: signetchallenge is set but "
                            "chain=%s -- it will be ignored\n", g_cfg.chain);
    }
    if(netperm_count() > 0){
        fprintf(stderr, "[config] whitelist: %d entr%s, granting noban\n",
                netperm_count(), netperm_count() == 1 ? "y" : "ies");
        if(netperm_has_implicit())
            fprintf(stderr, "[config] whitelist: an entry gave no explicit "
                            "permissions -- Core would grant its implicit set; "
                            "this node enforces ONLY noban\n");
    }
    if(!chainparams_select(g_cfg.chain)) return 1;
    { extern void wallet_set_chain(const char*, unsigned char, unsigned char);
      wallet_set_chain(g_chainp->bech32_hrp, g_chainp->p2pkh_version, g_chainp->p2sh_version); }
    if(g_chainp->dns_seed_hosts && g_chainp->n_dns_seed_hosts > 0){
        g_seed_hosts = g_chainp->dns_seed_hosts; g_n_seed_hosts = g_chainp->n_dns_seed_hosts;
    } else { g_n_seed_hosts = 0; }   /* regtest: no seeds, ever */
    /* nBits schedule enforcement (bad-diffbits): arm the shared rule engine
     * (bitcoin_pow_rules.c) in the apply path with the selected chain's
     * knobs. Only the daemon arms it -- hermetic suites build synthetic
     * chains with arbitrary bits and never call this. Proven against every
     * real mainnet + testnet4 header before wiring (validation/pow_replay). */
    { extern void utxo_live_set_pow_rules(int, int, int, unsigned int);
      extern void reorg_set_pow_rules(int, int, int, unsigned int);
      utxo_live_set_pow_rules(g_chainp->pow_no_retargeting,
                              g_chainp->allow_min_difficulty,
                              g_chainp->enforce_bip94,
                              g_chainp->pow_limit_bits);
      reorg_set_pow_rules(g_chainp->pow_no_retargeting,
                          g_chainp->allow_min_difficulty,
                          g_chainp->enforce_bip94,
                          g_chainp->pow_limit_bits);
      /* SAY SO. The check is injected and default-off, so an inert one is
       * indistinguishable from a working one by observing accepted blocks --
       * every block is accepted either way. test_reorg proves the wiring in
       * the suite; this line is the same evidence for a running node, and it
       * prints the knobs so a wrong-chain arming is visible too. */
      fprintf(stderr,"[config] pow  : nBits schedule enforcement ON"
                     " (no_retarget=%d min_diff=%d bip94=%d powlimit=%08x)\n",
              g_chainp->pow_no_retargeting, g_chainp->allow_min_difficulty,
              g_chainp->enforce_bip94, g_chainp->pow_limit_bits);
      /* -minimumchainwork: config wins, else the chain's own Core value.
       * Announce it for the same reason as the nBits line above -- an inert
       * floor and an enforced one look identical from accepted blocks. */
      { unsigned char mw[32]; const char* src;
        if (g_cfg.have_minchainwork){ memcpy(mw, g_cfg.minchainwork, 32); src = "config"; }
        else { memset(mw, 0, 32);
               if (g_chainp->min_chain_work_hex && g_chainp->min_chain_work_hex[0])
                   nodecfg_hex32_be(g_chainp->min_chain_work_hex, mw);
               src = "chain default"; }
        reorg_set_min_chain_work(mw);
        { extern void bmc_alert_deliver(const char*);
          reorg_set_alert_fn(bmc_alert_deliver); }
        if (reorg_min_chain_work_unrepresentable())
            fprintf(stderr,"[config] work : minimumchainwork EXCEEDS this node's 128-bit "
                           "work accumulator -- every chain will be refused. Lower it.\n");
        else if (reorg_min_chain_work_set()){
            char hx[65]; for(int i=0;i<32;i++) snprintf(hx+i*2,3,"%02x",mw[i]);
            fprintf(stderr,"[config] work : minimumchainwork=%s (%s)\n", hx, src);
        } else
            fprintf(stderr,"[config] work : minimumchainwork not set -- no low-work floor\n");
      } }
    static char effdir[4200];                    /* the PER-CHAIN datadir */
    chainparams_datadir(absp, effdir, sizeof effdir);   /* <datadir>/<chain>, main included (2026-08-31) */
    /* EVERY chain chdirs into its own directory now. The old != CHAIN_MAIN
     * guard left main's PARENT at the datadir root after the layout change:
     * the worker used effdir and found data/main/, but the parent wrote the
     * RPC cookie to data/.cookie and looked for mempool.dat one level up --
     * caught on the first migrated boot (cookie "enabled" yet unreadable to
     * the CLI, and the 10k-entry mempool.dat silently not reloaded). */
    if(chdir(effdir)!=0){ fprintf(stderr,"[boot] chdir(%s) failed: %s\n", effdir, strerror(errno)); return 1; }
    if(g_chainp->id != CHAIN_MAIN){
        if(!g_cfg.port_explicit) g_cfg.port = g_chainp->default_port;
        if(!g_chainp->dns_seeds) g_cfg.dnsseed = 0;
    }
    /* -asmap AFTER the per-chain chdir. A relative path must resolve against
     * the directory the node actually runs in; loading it earlier looked for
     * regtest's map in the BASE datadir and silently fell back to /16, which
     * is exactly the "configured but not in effect" failure this config
     * surface keeps producing. Still before anything buckets an address --
     * the group key changes meaning once a map is loaded. */
    if (g_cfg.asmap[0]){
        if (asmap_load(g_cfg.asmap))
            fprintf(stderr,"[config] asmap: %s (%lu bytes) -- bucketing peers by AS, not /16\n",
                    g_cfg.asmap, asmap_size());
        else
            fprintf(stderr,"[config] asmap: %s could not be loaded -- falling back to /16 bucketing\n",
                    g_cfg.asmap);
    }
    {
        fprintf(stderr, "[boot] chain=%s datadir=%s port=%d dnsseed=%d\n",
                g_chainp->name, effdir, g_cfg.port, g_cfg.dnsseed);
    }
    /* Size the relay mempool from -maxmempool BEFORE any serve loop runs, and
     * before the fork, so every child inherits the same region rather than
     * each falling back to the 2 MiB static. */
    mempool_configure();
    /* Open the read-only UTXO snapshot the tx-validation path needs ONCE,
     * here, PRE-FORK -- for exactly the reason the mempool above is done
     * pre-fork. bitcoin_serve.asm used to do it lazily per CONNECTION, and
     * utxo_lsm_reload costs 60-83 s on the real set: every inbound peer waited
     * that long before we sent so much as a feefilter, so in practice we
     * served nobody. Bitcoin Core opens its coins view once in LoadChainstate
     * and shares it across peer threads; children here inherit this one
     * copy-on-write, which also stops each peer mapping its own copy.
     * Non-fatal: on failure the serve path drops inbound tx rather than
     * accepting unvalidated ones, exactly as before. */
    { extern int serve_txdv_preinit(void);
      phase_timer_t txdv_pt; phase_start(&txdv_pt);
      int ok = serve_txdv_preinit();
      fprintf(stderr, "[boot] tx-validation snapshot %s (%.2fs) -- inbound peers inherit it\n",
              ok ? "ready" : "UNAVAILABLE (inbound tx will be dropped, not accepted)",
              phase_elapsed(&txdv_pt)); }
    /* Each chain keeps its own logs under <chain-datadir>/logs/ -- the asm
     * logger (node_log_open) writes there via the cwd, so a regtest run can
     * never interleave with the mainnet log. */
    mkdir("logs", 0755);
    if(g_chainp->id != CHAIN_MAIN)
        ;   /* logs/bitcoind.log inside the CHAIN's directory -- per-chain by
             * location now that every chain (main included) has its own
             * subdirectory; the old bitcoind.<chain>.log suffix is redundant */
    /* `dir` is the EFFECTIVE (per-chain) datadir from here on: the forked
     * download worker re-chdir()s into it and utxo_live opens its files
     * there -- on the first regtest boot the worker's chdir(absp) put the
     * UTXO store and chainwork in the BASE dir while the archive lived in
     * regtest/, splitting one chain's state across two dirs. absp keeps the
     * BASE for the config path (bitcoin.conf stays shared at the root). */
    /* Core -reindex: rebuild index.dat, headers.dat and chainwork.dat from the
     * blk files (daemon/archive_reindex.c), then drop the chain state and the
     * height-positional indexes so they rebuild against the new heights.
     * ONE-SHOT, exactly like -reindex-chainstate: a request, not a mode. Runs
     * BEFORE store_init so the store opens the rebuilt index, and after the
     * chdir into the per-chain directory, where the files live. */
    if(g_cfg.reindex){
        struct stat rst;
        if(stat("reindex.done", &rst) == 0){
            fprintf(stderr,"[reindex] reindex=1 is still set in the config but was already carried out "
                           "(reindex.done exists) -- ignoring. Remove the option, and delete that marker "
                           "if you truly want another rebuild.\n");
        } else {
            archive_reindex_stats rs; char rerr[256] = {0};
            fprintf(stderr,"[reindex] rebuilding the block index from the blk files...\n");
            if(archive_reindex(".", g_chainp->genesis_hash, BMC_FRAME_MAGIC, &rs, rerr, sizeof rerr) != 0){
                fprintf(stderr,"[reindex] FAILED: %s -- nothing was replaced; not starting\n", rerr);
                return 1;
            }
            fprintf(stderr,"[reindex] rebuilt: tip=%ld from %ld frame(s) in %ld file(s); %ld duplicate(s), "
                           "%ld orphan(s), %ld stale fork block(s), %ld bad-PoW frame(s), %ld junk byte(s)%s\n",
                    rs.tip, rs.frames, rs.files, rs.duplicates, rs.orphans, rs.stale, rs.bad_pow, rs.junk_bytes,
                    rs.tip_reappended ? "; tip frame re-appended for append safety" : "");
            { long dropped = archive_drop_utxo_state();
              fprintf(stderr,"[reindex] dropped %ld UTXO state file(s); the set will rebuild from the archive\n", dropped); }
            { const char* dz[] = {"txindex.dat","txindex.tail","addr_index.dat","bfilters.dat","bfilters.idx","coinstats.dat",0};
              int nd = 0; for(int i = 0; dz[i]; i++) if(unlink(dz[i]) == 0) nd++;
              if(nd) fprintf(stderr,"[reindex] removed %d height-positional index file(s); filters and coinstats rebuild "
                                    "on their own, txindex needs build_tx_index\n", nd); }
            FILE* mk = fopen("reindex.done", "w");
            if(mk){ fprintf(mk, "reindex carried out\n"); fclose(mk); }
            else fprintf(stderr,"[reindex] WARNING: could not write reindex.done -- the rebuild would repeat on the next restart\n");
        }
    }
    dir = effdir;
    /* derived files must not outrun the archive (incident 2026-09-01): trim
     * an empty index tail and over-long headers/chainwork before the store
     * reads its tip from index.dat's length */
    { long tr = archive_trim_derived_tails();
      if(tr < 0) fprintf(stderr,"[boot] WARNING: could not trim the derived files past the tip: %s\n", strerror(errno)); }
    if(store_init(store_buf)!=1){ fprintf(stderr,"store_init failed\n"); return 1; }
    /* A fresh non-main datadir self-seeds its own genesis at index 0 (the
     * mainnet archive got genesis by a one-time injection, 5f36dee -- a
     * regtest dir is created empty every time, so the daemon must do it).
     * Everything downstream (locator build, catch-up, script-flag heights,
     * the UTXO walk's skip-genesis-coinbase rule) already assumes index ==
     * height with genesis at 0. */
    if(g_chainp->id != CHAIN_MAIN && *(int*)(store_buf+24) == -1){
        unsigned char gh[32]; block_hash(gh, g_chainp->genesis);
        if(store_append(store_buf, gh, g_chainp->genesis, (unsigned long)g_chainp->genesis_len) < 0){  /* returns new height (0) or -1 */
            fprintf(stderr,"[boot] failed to seed the %s genesis block\n", g_chainp->name); return 1; }
        fprintf(stderr,"[boot] %s genesis seeded at height 0\n", g_chainp->name);
    }

    if(strcmp(mode,"sync")==0){
        /* Connect to a built-in loopback fake peer (forked in-process), exactly
         * like the verified tests/test_bitcoind_sync harness, so the IBD
         * exchange matches node_sync cadence. */
        int lfd = (mkdir("logs", 0755), node_log_open(g_logpath));   /* all-asm leveled logger */
        node_log_str(lfd, 0, "node start (sync mode)", 22);
        int ls=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
        listen(ls,2);
        pid_t pid=fork();
        if(pid==0){ int c=accept(ls,0,0); fake_serve(c); _exit(0); }
        int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
        if(fd<0){ fprintf(stderr,"connect failed\n"); return 1; }
        if(node_handshake(fd)!=1){ fprintf(stderr,"handshake failed\n"); return 1; }
        node_log_event(lfd, 1, NODE_PROTOCOL_VER, 1, 0);        /* HSHK protocol services */
        static unsigned char gen[32]; memset(gen,0,32);
        static unsigned char buf[65536]; long cnt=0;
        long ok = node_sync(fd, store_buf, gen, buf, sizeof buf, &cnt);
        int tip = *(int*)(store_buf+24);
        node_log_event(lfd, L_BLOCK, (unsigned)(ok?cnt:0), 0, 0);   /* BLOCK n downloaded */
        node_log_event(lfd, L_STORE, (unsigned)(tip+1), (unsigned)tip, 0); /* STORE count height */
        if(!ok) node_log_str(lfd, L_ERROR, "node_sync failed", 16);
        close(fd); waitpid(pid,0,0); close(ls);
        printf("sync: ok=%ld blocks=%ld height=%d (store in %s, log bitcoind.log)\n", ok, cnt, tip, dir);
        return (ok==1 && cnt>=1)?0:1;
    }

    if(strcmp(mode,"ibd")==0){
        /* FULL Initial-Block-Download as ONE assembly pass (node_ibd =
         * node_ibd_headers + node_ibd_blocks) over a single connection to a
         * peer that serves the WHOLE chain. This is the runnable daemon wired
         * to the same 100%-asm IBD machine proven by tests/test_ibd_full.c: it
         * persists the whole header chain (header store), then walks every
         * stored header, getdata's its block body, validates with cons_verify +
         * a re-derived-hash guard, and store_appends into the block store. */
        static unsigned char hstb[256];
        if(hst_init(hstb)!=1){ fprintf(stderr,"hst_init failed\n"); return 1; }
        int lfd = (mkdir("logs", 0755), node_log_open(g_logpath));
        node_log_str(lfd, 0, "node start (ibd mode)", 21);
        int ls=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
        listen(ls,2);
        pid_t pid=fork();
        if(pid==0){ int c=accept(ls,0,0); full_serve(c); _exit(0); }
        int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
        if(fd<0){ fprintf(stderr,"connect failed\n"); return 1; }
        if(node_handshake(fd)!=1){ fprintf(stderr,"handshake failed\n"); return 1; }
        static unsigned char ibuf[1<<22];            /* >= 2MB shared scratch */
        long nblk = node_ibd(fd, store_buf, hstb, ibuf, sizeof ibuf);
        close(fd); waitpid(pid,0,0); close(ls);
        long nhdr = hst_count(hstb);
        int tip = *(int*)(store_buf+24);
        node_log_event(lfd, L_BLOCK, (unsigned)(nblk>0?nblk:0), 0, 0);
        node_log_event(lfd, L_STORE, (unsigned)(tip+1), (unsigned)tip, 0);
        printf("ibd: blocks=%ld headers=%ld height=%d (store in %s; all-asm node_ibd pass)\n", nblk, nhdr, tip, dir);
        return (nblk>=1 && nhdr>=1 && tip==(int)nhdr-1 && (long)nhdr==8)?0:1;
    }

    if(strcmp(mode,"follow")==0){
        /* REALTIME keep-up: stay on one connection and re-run node_sync
         * (getheaders from our advancing tip) so we pick up blocks the peer
         * mines after we synchronized. Logs tip growth each pass. This is the
         * live synchronization loop over the verified asm IB D core. */
        store_reload(store_buf);            /* continue from persisted tip */
        int lfd = (mkdir("logs", 0755), node_log_open(g_logpath));
        node_log_str(lfd, 0, "node start (follow mode)", 23);
        int ls=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls,(struct sockaddr*)&a,sizeof a); socklen_t al=sizeof a; getsockname(ls,(struct sockaddr*)&a,&al);
        listen(ls,2);
        pid_t pid=fork();
        if(pid==0){ int c=accept(ls,0,0); fake_serve(c); _exit(0); }
        int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
        if(fd<0){ fprintf(stderr,"connect failed\n"); return 1; }
        if(node_handshake(fd)!=1){ fprintf(stderr,"handshake failed\n"); return 1; }
        static unsigned char gen[32]; memset(gen,0,32);
        static unsigned char buf[65536];
        int last=-1, same=0;
        for(int pass=1; pass<=8; pass++){
            long cnt=0;
            long ok = node_sync(fd, store_buf, gen, buf, sizeof buf, &cnt);
            int tip = *(int*)(store_buf+24);
            /* announce new tip to the peer via inv (proactive relay keep-up):
             * if we synced new blocks, send inv for the new tip block hash
             * (wire/LE order) so the peer knows our chain advanced. */
            if(cnt>0){
                static unsigned char hd[80], th[32], le[32], invm[37];
                long L = node_serve_block(store_buf, tip, hd, sizeof hd);
                if(L>=80){
                    block_hash(th, hd);
                    for(int k=0;k<32;k++) le[k]=th[31-k];   /* display->LE wire */
                    invm[0]=1; invm[1]=2; invm[2]=0; invm[3]=0; invm[4]=0;
                    memcpy(invm+5, le, 32);
                    p2p_write(fd, "inv", 3, invm, sizeof invm);
                }
            }
            node_log_event(lfd, L_BLOCK, (unsigned)(ok?cnt:0), (unsigned)tip, (unsigned)pass);
            printf("follow pass %d: ok=%ld new=%ld height=%d\n", pass, ok, cnt, tip); fflush(stdout);
            if(tip==last) same++; else same=0;
            if(same>=2 && cnt==0){ node_log_str(lfd, 0, "caught up to chain tip", 22); break; }
            last=tip;
            if(ok==0) break;
        }
        close(fd); waitpid(pid,0,0); close(ls);
        printf("follow done (store in %s)\n", dir);
        return 0;
    }

    if(strcmp(mode,"server-test")==0){
        /* End-to-end server test: sync a chain into store, then run serve_loop
         * against a socketpair CLIENT that issues getdata/getheaders/inv and
         * checks the server answers correctly (boundary getheaders-serving +
         * event-driven inv->block keep-up). */
        int failures=0;
        /* 1) download an 8-block chain from the growing fake peer */
        int ls=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in aa; memset(&aa,0,sizeof aa); aa.sin_family=AF_INET; aa.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        bind(ls,(struct sockaddr*)&aa,sizeof aa); socklen_t al=sizeof aa; getsockname(ls,(struct sockaddr*)&aa,&al);
        listen(ls,2);
        pid_t pid=fork();
        if(pid==0){ int c=accept(ls,0,0); fake_serve(c); _exit(0); }
        int fd=tcp_connect_ip(htonl(INADDR_LOOPBACK), aa.sin_port);
        if(fd<0){ printf("FAIL connect\n"); return 1; }
        if(node_handshake(fd)!=1){ printf("FAIL handshake\n"); return 1; }
        static unsigned char gen[32]; memset(gen,0,32); static unsigned char bigbuf[65536]; long cnt=0;
        long ok=node_sync(fd, store_buf, gen, bigbuf, sizeof bigbuf, &cnt);
        close(fd); waitpid(pid,0,0); close(ls);
        int tip=*(int*)(store_buf+24);
        printf("[server-test] synced ok=%ld blocks=%ld tip=%d\n", ok, cnt, tip);
        if(ok!=1||tip<6){ printf("TESTS FAILED (no chain)\n"); return 1; }
        /* the chain lives in-memory only (not yet on disk), so build the O(1)
         * hash->height index directly from store_buf rather than from disk */
        if(build_inmem_hash_index()!=0){ printf("TESTS FAILED (hash index)\n"); return 1; }

        /* 2) socketpair: parent = server(serve_loop), child = test client */
        int sv[2]; if(socketpair(AF_UNIX,SOCK_STREAM,0,sv)!=0){ fprintf(stderr,"socketpair failed: %s\n", strerror(errno)); return 1; }
        pid=fork();
        if(pid==0){
            close(sv[0]);
            int cfd=sv[1]; char cmd[12]; unsigned char pl[100]; unsigned plen=0;
            /* serve_loop does NOT handshake (assumes already done), so go
             * straight to issuing requests. */
            /* getdata for block0's hash -> server must return EXACT block0 */
            static unsigned char bh0[2048]; long gl=node_serve_block(store_buf,0,bh0,2048);
            unsigned char h0[32]; block_hash(h0,bh0);
            unsigned char gd[37]; gd[0]=1; gd[1]=2; gd[2]=0; gd[3]=0; gd[4]=0; memcpy(gd+5,h0,32);
            p2p_write(cfd,"getdata",7,gd,37);
            unsigned char blk[65536]; unsigned bl=0;
            if(p2p_read(cfd,cmd,blk,sizeof blk,&bl)<=0 || strncmp(cmd,"block",5)!=0){ printf("FAIL getdata->block\n"); exit(2); }
            int ok0=(bl==(unsigned)gl && memcmp(blk,bh0,gl)==0);
            /* getheaders locator=block0 -> server should return headers for 1..tip
             * (payload: version[4] count[1] hash[32] stop[32] = 69 bytes) */
            unsigned char gh[69]; gh[0]=0x00; gh[1]=0x11; gh[2]=0x01; gh[3]=0x00; gh[4]=1;
            memcpy(gh+5,h0,32); memset(gh+37,0,32);
            p2p_write(cfd,"getheaders",10,gh,69);
            unsigned char hp[5000]; unsigned hp_len=0;
            if(p2p_read(cfd,cmd,hp,sizeof hp,&hp_len)<=0 || strncmp(cmd,"headers",7)!=0){ printf("FAIL getheaders->headers\n"); exit(2); }
            int okh=(hp_len>81 && (int)hp[0]>=1);
            /* inv announce block0 -> server fetches+stores (already have) -> must NOT error */
            unsigned char invm[37]; invm[0]=1; invm[1]=2; invm[2]=0; invm[3]=0; invm[4]=0; memcpy(invm+5,h0,32);
            p2p_write(cfd,"inv",3,invm,37);
            p2p_write(cfd,"ping",4,"\x11\x22\x33\x44\x55\x66\x77\x88",8);
            if(p2p_read(cfd,cmd,pl,sizeof pl,&plen)<=0 || strncmp(cmd,"pong",4)!=0){ printf("FAIL ping->pong\n"); exit(2); }
            printf("[server-test] getdata-exact=%d getheaders-n=%d (%d blocked)\n", ok0, okh, (int)hp_len);
            exit((ok0&&okh)?0:2);
        }else{
            int lfd=(mkdir("logs", 0755), node_log_open(g_logpath));
            close(sv[1]);
            int svo=serve_loop(sv[0], lfd);
            int st; waitpid(pid,&st,0); close(sv[0]);
            printf("server served %d msg(s); client rc=%d\n", svo, WEXITSTATUS(st));
            failures = (WEXITSTATUS(st)!=0)?1:0;
        }
        printf("\n%s\n", failures?"TESTS FAILED":"ALL TESTS PASSED");
        return failures?1:0;
    }

    if(strcmp(mode,"serve")==0 && argc>=3){
        /* Port precedence: CLI arg > bitcoin.conf `port` > Core default 8333.
         * The CLI arg is now OPTIONAL so the config file can genuinely own
         * the node's network identity -- previously it was required, so the
         * file's `port` was parsed and then always overridden. */
        int port = (argc>=4) ? atoi(argv[3]) : g_cfg.port;
        if(port<1 || port>65535){
            fprintf(stderr,"[boot] invalid port %d -- refusing to start\n", port);
            return 2;
        }
        /* # outbound peers is optional 4th arg (default 3). */
        int nwant = (argc>=5)? atoi(argv[4]) : 3;
        if(nwant<0) nwant=0; if(nwant>MUX_MAX_OUT) nwant=MUX_MAX_OUT;
        /* # dl_catchup chunk-claiming workers is optional 5th arg (default
         * 16 -- tried both 8 and 16 against the real archive; 16 gave a
         * modest throughput bump once the liveness probe was fixed to
         * actually find enough live peers to support it). dl_catchup itself
         * clamps this down to however many confirmed-live peers it finds
         * (and up to 64 max), so an over-large request here just becomes a
         * ceiling, not a guarantee. */
        /* Core -par semantics: 0 == auto (use the machine), negative == leave
         * that many cores free. CLI arg still wins when given. `par` is the
         * closest Core equivalent to this node's chunk-claiming worker count;
         * dl_catchup already clamps the result down to however many
         * confirmed-live peers it finds, so this is a ceiling, not a promise. */
        int catchup_workers;
        if(argc>=6) catchup_workers = atoi(argv[5]);
        else {
            long ncpu = sysconf(_SC_NPROCESSORS_ONLN); if(ncpu<1) ncpu=4;
            if(g_cfg.par > 0)      catchup_workers = g_cfg.par;
            else if(g_cfg.par < 0) catchup_workers = (int)(ncpu + g_cfg.par);  /* leave |par| free */
            else                   catchup_workers = 16;                       /* auto: prior default */
        }
        if(catchup_workers<1) catchup_workers=1;
        if(catchup_workers>64) catchup_workers=64;
        fprintf(stderr,"[boot] config: datadir=%s port=%d (%s) listen=%d nwant=%d catchup_workers=%d (%s)\n",
                dir, port, (argc>=4)?"cli":"bitcoin.conf", g_cfg.listen, nwant,
                catchup_workers, (argc>=6)?"cli":"par");
        phase_timer_t boot_pt; phase_start(&boot_pt);
        fprintf(stderr,"[boot] loading chain archive from disk...\n");
        phase_timer_t load_pt; phase_start(&load_pt);
        store_reload(store_buf);            /* load the persisted chain from disk */
        fprintf(stderr,"[boot] chain archive loaded: tip=%d (%.2fs)\n",
                *(int*)(store_buf+24), phase_elapsed(&load_pt));
        /* Does this archive belong to the chain we were told to run? Checked
         * HERE and not right after store_init: store_init opens index.dat but
         * does not populate idx_len, so a check there sees length 0 and
         * concludes "empty archive, nothing to contradict" every single time.
         * The first cut of this guard did exactly that and silently passed a
         * regtest archive to a mainnet node. */
        if(!chain_archive_matches(store_buf)) return 1;
        /* Core -checkblocks/-checklevel. Read-only, and deliberately BEFORE
         * anything opens the archive for writing. It reports problems and does
         * not act on them: archive_verify_and_repair is the only thing allowed
         * to change the archive, and it runs on its own much narrower and
         * better-understood trigger. */
        if(g_cfg.checklevel > 0){
            phase_timer_t chk_pt; phase_start(&chk_pt);
            long probs = archive_check(g_cfg.checkblocks, g_cfg.checklevel);
            if(probs > 0)
                fprintf(stderr,"[boot] archive check found %ld problem(s) in %.2fs -- see [check] lines above\n",
                        probs, phase_elapsed(&chk_pt));
            else if(probs == 0)
                fprintf(stderr,"[boot] archive check clean (%.2fs)\n", phase_elapsed(&chk_pt));
        } else {
            fprintf(stderr,"[boot] checklevel=0 -- skipping archive verification\n");
        }
        /* shared-append flock fd: open append.lock once so any concurrent-safe
         * store_append_shared writes (and the boot catch-up) serialize. */
        int apfd=open("append.lock", O_RDWR|O_CREAT, 0644);
        if(apfd>=0) *(int*)((char*)store_buf+40)=apfd;
        /* LISTENER FIRST: bind+listen the inbound socket before the (possibly
         * long) catch-up so the node is live to inbound peers immediately.
         * The mux loop will poll it once the catch-up returns. */
        /* Core -listen=0: outbound-only. Skip binding entirely rather than
         * binding and refusing every connection, which is what the flag
         * actually means. */
        int l = g_cfg.listen ? lsock(port) : -1;
        wb_listen_open();
        if(!g_cfg.listen) fprintf(stderr,"[boot] listen=0 -- not accepting inbound connections\n");
        /* Only a listener we ASKED for and failed to get is fatal. Under
         * listen=0 the -1 is the intended result, and this check used to
         * abort on it ("lsock: Invalid argument") -- so listen=0 killed the
         * node instead of running it outbound-only, and by implication so did
         * connect=, which sets listen=0. serve_mux polls `l` and nothing
         * else, and poll() ignores a negative fd (POSIX: revents is set to 0),
         * so the accept branch simply never fires. */
        if(g_cfg.listen && l<0){ fprintf(stderr,"[boot] lsock failed: %s\n", strerror(errno)); return 1; }
        /* Core -prune. The primitive (store_prune) has existed and been
         * tested since the store was written but nothing ever called it, so
         * pruning was configurable in theory only.
         *
         * The decision of WHETHER and HOW FAR to prune lives in
         * archive_prune_decide (daemon/archive_verify.c) so it can be tested
         * against synthetic archives; this code only acts on the verdict.
         * Every refusal still persists the GATE, which touches no block data,
         * so a later run can complete the sync and prune then. A node that
         * keeps too many blocks is merely over budget; one that deletes blocks
         * it still needed is unrecoverable. */
        if(g_cfg.prune_mib > 1){
            long ph = 0, detail = -1;
            archive_prune_verdict_t v =
                archive_prune_decide((long long)g_cfg.prune_mib * 1048576LL, &ph, &detail);
            switch(v){
            case ARCHIVE_PRUNE_ERROR:
                fprintf(stderr,"[prune] could not compute a prune height -- pruning skipped\n");
                break;
            case ARCHIVE_PRUNE_NOTHING:
                fprintf(stderr,"[prune] budget %ld MiB covers the whole archive -- nothing to prune\n",
                        g_cfg.prune_mib);
                break;
            case ARCHIVE_PRUNE_REFUSE_LAYOUT: {
                /* store_prune's in-place compaction assumes a single
                 * (file_no, data_pos) boundary, which a non-monotonic
                 * archive breaks -- but whole-file-granularity pruning
                 * (archive_prune_file_granular) doesn't need that
                 * assumption, so try it before giving up. Deliberately does
                 * NOT call store_set_prune: that gate is store_get_at's
                 * single-threshold "everything below here is gone" check,
                 * which would be WRONG here -- file-granular pruning can
                 * leave still-live heights below `ph` (whichever file they
                 * share with a not-yet-safe height stays whole), so those
                 * heights must keep reading normally, not report -3. */
                long nfiles = archive_prune_file_granular(ph);
                if(nfiles > 0)
                    fprintf(stderr,"[prune] archive not laid out monotonically (first break at %ld) -- "
                                   "used whole-file-granular pruning instead: %ld file(s) below height %ld removed\n",
                                   detail, nfiles, ph);
                else if(nfiles == 0)
                    fprintf(stderr,"[prune] archive not laid out monotonically (first break at %ld) -- "
                                   "whole-file-granular pruning found nothing safely prunable yet below height %ld\n",
                                   detail, ph);
                else
                    fprintf(stderr,"[prune] archive not laid out monotonically (first break at %ld) AND "
                                   "whole-file-granular pruning failed -- no data deleted\n", detail);
                break;
            }
            case ARCHIVE_PRUNE_REFUSE_HOLE:
                fprintf(stderr,"[prune] REFUSING to prune to height %ld: archive has a hole at height %ld "
                               "(sync incomplete). Gate persisted, no data deleted.\n", ph, detail);
                store_set_prune(store_buf, (int)ph);
                break;
            case ARCHIVE_PRUNE_OK:
                fprintf(stderr,"[prune] budget %ld MiB -> retaining from height %ld; deleting below it\n",
                        g_cfg.prune_mib, ph);
                if(store_prune(store_buf, (int)ph) == 1)
                    fprintf(stderr,"[prune] done: block data below height %ld removed\n", ph);
                else
                    fprintf(stderr,"[prune] store_prune FAILED -- archive left as it was\n");
                break;
            }
        } else if(g_cfg.prune_mib == 1){
            fprintf(stderr,"[prune] prune=1 (manual-only) -- no automatic pruning\n");
        }

        /* DUPLICATE-HASH REPAIR BEFORE THE CATCH-UP, and unconditional (runs
         * every boot, not behind -checklevel): a duplicate-hash height is
         * never a false positive (see archive_repair_duplicates' own header
         * comment) and left alone it silently feeds a wrong block into
         * script/UTXO validation forever, since nothing else in the boot
         * path re-checks a height that's already "present". Zeroing it marks
         * it as an ordinary hole, and the catch-up call right below -- which
         * already, unconditionally, re-fills any hole plus whatever's
         * missing up to the real tip -- does the actual re-fetch with zero
         * new fetch logic. This is the "on boot, before serving other
         * clients" health check + fix (2026-08-19): previously this
         * corruption could only be found by hand (a one-off scan) and only
         * repaired via archive_verify_and_repair's truncate-based path,
         * which refuses outright on a non-monotonic archive -- exactly the
         * state this archive was already in. */
        {
            long rep = archive_repair_duplicates();
            if(rep > 0) store_reload(store_buf);   /* our copy predates the zeroed records */
            else if(rep < 0)
                fprintf(stderr,"[boot] duplicate-hash repair scan failed -- continuing without it\n");
        }

        /* PRUNE BEFORE THE CATCH-UP, not after.
         *
         * This block originally sat after the catch-up completed, which made
         * it unreachable in practice: every boot re-syncs the header chain and
         * then fills the archive, so a disk budget was only applied once that
         * finished -- exactly backwards, since the point of a budget is to
         * bound the space the download is about to consume. It also never
         * printed anything in a bounded test run, which is how the placement
         * was noticed at all. */
        fprintf(stderr,"[boot] checking for archive gaps / missing blocks...\n");
        phase_timer_t catchup_pt; phase_start(&catchup_pt);
        /* BUILT-IN MULTI-PEER CATCH-UP (SYNCHRONOUS, self-healing): detect
         * any archive holes plus whatever's missing up to the real chain
         * tip, and fill the whole span with a pool of chunk-claiming
         * workers before this node ever opens for service -- replaces the
         * old single-peer, 60s-capped outbound_catchup() with the same
         * multi-peer engine already proven in the standalone unified_ibd.c
         * tool. On a large gap this can take a long time; the node will not
         * respond to any peer until it returns (deliberate: simplest
         * correct behavior, no writer-coordination needed with the
         * steady-state download worker below since they never run at the
         * same time). Self-throttling: a caught-up node returns almost
         * instantly (pure disk reads, no network) so it's safe to run on
         * every boot. */
        g_catchup_workers = catchup_workers;   /* the running worker re-uses it */
        long caught = g_cfg.boot_catchup ? dl_catchup(dir, catchup_workers) : 0;
        if(!g_cfg.boot_catchup) fprintf(stderr,"[boot] bmc.bootcatchup=0 -- skipping the boot catch-up; the worker's far-behind trigger will run it if needed\n");
        fprintf(stderr,"[boot] catch-up check done: %ld block(s) written (%.2fs)\n",
                caught, phase_elapsed(&catchup_pt));
        if(g_shutdown_requested){
            /* 2026-09-01 12:29: a stop during the boot catch-up returned here
             * and the boot went ON -- hash index, worker, UTXO engine sized
             * against an index the catch-up had just polluted -- and the
             * worker's start under the pending SIGTERM left utxo.idx empty
             * (a full UTXO rebuild followed). A stop is a stop. */
            fprintf(stderr,"[boot] shutdown requested during the catch-up -- exiting before the worker starts\n");
            _exit(0);
        }
        if(caught>0){
            store_reload(store_buf);        /* our copy predates dl_catchup's writes */
            fprintf(stderr,"[catchup] store now tips at height %d\n", *(int*)(store_buf+24));
        }
        fprintf(stderr,"[boot] building hash index...\n");
        phase_timer_t hidx_pt; phase_start(&hidx_pt);
        build_hash_index();                 /* hash->height for O(1) getdata serving */
        fprintf(stderr,"[boot] hash index build done (%.2fs)\n", phase_elapsed(&hidx_pt));

        int lfd = (mkdir("logs", 0755), node_log_open(g_logpath));   /* all-asm leveled logger */
        node_log_str(lfd, 0, "node start (serve mode / download worker)", 42);
        /* Serve-as-full-node (option 2): SERVICE our client calls instantly
         * (fork-based inbound serving in the parent) AND continuously download
         * the chain to tip (a dedicated forked DOWNLOAD-WORKER child; see
         * serve_download_worker). The parent runs serve_mux as a PURE inbound
         * server (nwant=0 -> no outbound appends), so:
         *   - serving our clients is NEVER blocked by (or chopped by) a long
         *     sync -- there is no sync in the parent;
         *   - the worker grinds continuously from the on-disk tip to mainnet.
         * NOTE: the worker is NOT the sole block writer -- an inbound serve
         * child can also append a block pushed to it (bitcoin_serve.asm
         * .do_block, reachable via an unsolicited inv or our own
         * .do_inv-triggered getdata, regardless of nwant=0 here). Both the
         * worker's node_sync and .do_block now go through
         * idxscan_append_locked (flock-guarded, atomic-height-under-lock),
         * so concurrent writers from either path can't collide on or
         * clobber each other's height slot; see idxscan_append_locked's
         * header comment in bitcoin_idxscan.asm for the full rationale.
         * Each forked serve child re-syncs its index length from index.dat so
         * blocks the worker appends become serve-able (fresh disk reads). */
        /* Shared live-node status: MAP_SHARED so the download worker (peer
         * counts, tip) and the parent (inbound count) can both publish and the
         * parent's RPC thread can read across the fork. Allocated BEFORE the
         * fork so the child inherits the same mapping. */
        g_node_status = mmap(NULL, sizeof(node_status_t), PROT_READ|PROT_WRITE,
                             MAP_SHARED|MAP_ANONYMOUS, -1, 0);
        if (g_node_status == MAP_FAILED){ g_node_status = NULL; }
        else { g_node_status->n_out = 0; g_node_status->n_inbound = 0;
               g_node_status->tip_height = *(int*)(store_buf+24);
               g_node_status->start_time = (long long)time(NULL);
               /* MUST be set explicitly: the status block is zeroed shared
                * memory, and net_active == 0 means "networking disabled" --
                * leaving it at the zero default would gate every dial and
                * silently produce a node that never connects. */
               /* -networkactive=0 starts the node with networking OFF, the
                * same state setnetworkactive false produces at runtime. */
               g_node_status->net_active = g_cfg.networkactive ? 1 : 0;
               g_node_status->permit_bare_multisig = g_cfg.permitbaremultisig ? 1 : 0;
               if(!g_cfg.networkactive)
                   fprintf(stderr,"[config] net  : networkactive=0 -- starting with networking DISABLED\n"); }

        /* Hand the ZMQ notification ring the shared block BEFORE the fork, so
         * the download worker AND every inbound serve child inherit the same
         * pointer -- a child that staged into its own private copy would
         * publish nothing and report no error. */
        zmqn_set_status(g_node_status);

        /* gettxout IPC channel, created BEFORE the fork so both sides inherit
         * it: the RPC in this parent asks the worker, which owns the live
         * UTXO set. If the socketpair cannot be made we simply do not install
         * the query hook and gettxout keeps refusing -- degraded, never
         * wrong. */
        { int sv[2];
          if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0){ g_txoq_parent = sv[0]; g_txoq_worker = sv[1]; }
          else fprintf(stderr,"[serve] gettxout IPC unavailable (socketpair: %s) -- gettxout will refuse\n", strerror(errno)); }

        pid_t dl = fork();
        if(dl==0){
            if(g_txoq_parent >= 0){ close(g_txoq_parent); g_txoq_parent = -1; }
            serve_download_worker(dir, (const char**)g_seed_hosts, g_n_seed_hosts, g_chainp->default_port);
            _exit(0);
        }
        if(g_txoq_worker >= 0){ close(g_txoq_worker); g_txoq_worker = -1; }
        g_dl_worker_pid = dl;   /* so serve_mux's shutdown handling can forward SIGTERM to it */
        fprintf(stderr,"[serve] download worker pid %d\n", (int)dl);
        fprintf(stderr,"[boot] boot phase complete (%.2fs total)\n", phase_elapsed(&boot_pt));
        /* Embedded JSON-RPC server (parent), non-blocking own accept thread. */
        if(g_txoq_parent >= 0){
            extern void rpc_commands_set_txo_query(long (*)(const unsigned char[32], unsigned int,
                                                            unsigned long long*, unsigned long*,
                                                            unsigned long*, unsigned char*,
                                                            unsigned long, unsigned long*));
            rpc_commands_set_txo_query(txoq_query);
            fprintf(stderr,"[rpc] gettxout answers via the download worker (IPC)\n");
        }
        { char rpccfg[512]; serve_start_rpc(dir, node_config_path(absp, rpccfg, sizeof rpccfg)); }
        /* PURE-INBOUND serving: nwant=0 -> serve_mux adds no outbound legs, so
         * it only accepts+forks serve children (never blocks on sync). */
        return serve_mux(port, (const char**)g_seed_hosts, 0, g_n_seed_hosts, g_chainp->default_port, l, g_cfg.listen ? lsock_v6(port) : -1, tor_onion_listener(port), i2p_inbound_start());
    }

    if(strcmp(mode,"serve-test")==0 && argc>=6){
        /* LOOPBACK variant of the outbound multiplexer used by test_outbound_mux:
         * the outbound legs connect to a LOCAL peer (host@out_port) instead of
         * real seeds, so the whole accept+outbound-pull loop is exercised in
         * isolation (no network dependency). Same ONE poll() loop, same
         * node_sync-from-tip + node_announce_tip outbound legs, same forked
         * inbound serving. */
        int port = atoi(argv[3]);
        const char* peer[] = { argv[4] };
        int out_port = atoi(argv[5]);
        int nwant = (argc>=7)? atoi(argv[6]) : 1;
        if(nwant<1) nwant=1; if(nwant>1) nwant=1;   /* one loopback peer */
        store_reload(store_buf);
        int apfd=open("append.lock", O_RDWR|O_CREAT, 0644);
        if(apfd>=0) *(int*)((char*)store_buf+40)=apfd;
        build_hash_index();
        int lfd = (mkdir("logs", 0755), node_log_open(g_logpath));
        node_log_str(lfd, 0, "serve-test outbound mux", 22);
        int l = lsock(port);
        wb_listen_open();
        if(l<0){ fprintf(stderr,"lsock failed: %s\n", strerror(errno)); return 1; }
        return serve_mux(port, peer, nwant, 1, out_port, l, g_cfg.listen ? lsock_v6(port) : -1, tor_onion_listener(port), i2p_inbound_start());
    }
    return 2;
}
