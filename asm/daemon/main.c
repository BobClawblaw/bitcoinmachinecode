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
#include <dirent.h>
#include <sys/file.h>          /* DMN-1: flock() for the datadir lock */
#include "secure_zero.h"    /* WAL-3: a memset the optimiser may not delete */
#include "hdrrules.h"          /* VAL-5: ContextualCheckBlockHeader rules */
#include "peer_timeout.h"      /* CC-7: -peertimeout, the handshake deadline */
#include "txann.h"             /* CC-1: tx announcement to and from inbound peers */
#include "inbound_evict.h"     /* CC-3: Core AttemptToEvictConnection */
#include "../mempool_slot.h"    /* the structural mempool's slot layout (80-byte slots) */
#include "anchors.h"           /* CC-4: block-relay-only legs + anchors.dat */
#include "hdr_lowwork.h"
#include "archive_seed.h"
#include "ibd_pipeline.h"      /* the whole chunk in one getdata, not one block per round trip */       /* slot 0 is genesis on EVERY chain: a shifted archive reads every height one block high */       /* CC-5: hold low-work header pages until the chain proves its work */
#include "banlist.h"          /* the ban list survives a restart, as Core's does */       /* slot 0 is genesis on EVERY chain: a shifted archive reads every height one block high */       /* CC-5: hold low-work header pages until the chain proves its work */
#include "invalid_set.h"       /* CC-10: invalidateblock / reconsiderblock */
#include "cmpct_recv.h"        /* CC-2: BIP152 compact block receive */
/* VAL-5 / MEM-1: the generated per-height script-flag mask
 * (bitcoin_script_flags.asm, from validation/gen_script_flags.py). */
extern unsigned long long script_flags_for_block(unsigned long long height,
                                                 const unsigned char blockhash[32]);

/* MEM-1: defined below, called from the tip-change hook above it. */
static void mempool_refresh_seqlocks(void* store_buf, long now_tip);
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
/* Core's -debuglogfile default, exactly: "debug.log" (logging.cpp:23,
 * DEFAULT_DEBUGLOGFILE), relative to the NET-SPECIFIC datadir. Every chain
 * here already has its own directory and the daemon chdir()s into it, so a
 * bare "debug.log" lands at <chain-datadir>/debug.log -- the same file, in
 * the same place, as Core. (This was logs/bitcoind.log until 2026-09-06.) */
static char g_logpath[256] = "debug.log";   /* debuglogfile= overrides (0 = /dev/null) */
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
 * backlog is 0-2; a from-scratch or long-gap restart is tens of thousands.
 *
 * RECOVERY PATH since step 1 of UTXO_INLINE_BUILD_PERF_SCOPE (2026-09-06):
 * the parallel downloader now connects the UTXO set INSIDE its monitor loop
 * (dl_catchup), so on the worker's own runs the backlog only grows past this
 * line if connect is SLOWER than the download, or after a boot-time catch-up
 * (which runs in the parent, before the UTXO engine exists) hands the worker
 * a full archive. Both are exactly the cases this rule was written for:
 * stop syncing legs, apply. It stays in place, unchanged. */
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
extern unsigned char g_peer_version_payload[512]; /* bitcoind.asm: raw capture, see its header comment (NET-13: 512) */
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
/* ---- remember who lacks NODE_WITNESS (2026-09-06) --------------------------
 * A peer without NODE_WITNESS is useless to us forever -- the bit does not
 * come and go -- but nothing recorded that, so the dialler kept picking the
 * same addresses out of the pool and re-handshaking them. Measured on a live
 * benchmark: 7,891 of 8,630 log lines in nine minutes were this one message,
 * 91% of the log, from 28 distinct addresses, one of them dialled 819 times.
 * That is a wasted handshake each time, not just noise.
 *
 * So: a small per-run set of addresses already known to lack the bit. The
 * message is printed ONCE per address; after that the peer is skipped before
 * the socket is opened, and a periodic line reports the running count so the
 * behaviour stays visible without drowning the log. Not persisted -- a node
 * may be upgraded between runs, and Core re-learns services on every
 * connection too. */
#define NOWIT_MAX 512
/* The download forks 16 helpers, so a per-process set is learned 16 times over
 * and the message still repeats once per helper (measured: exactly 16). The
 * set therefore lives in a MAP_SHARED page the parent creates before the fork,
 * alongside claimed[] and banned[]; when it is absent (the parent's own dials
 * before any download) the process-local arrays below are used instead. */
typedef struct { volatile int n; char a[NOWIT_MAX][64]; volatile unsigned long long skips; } nowit_set_t;
static nowit_set_t* g_nowit_sh = 0;
void peer_nowit_attach(void* shared){ g_nowit_sh = (nowit_set_t*)shared; }
/* 2026-09-09: what every dial attempt taught us (daemon/dial_memory.h) --
 * MAP_SHARED so the dial helpers and the worker consult one table */
#include "dial_memory.h"
#define DIALMEM_CAP 4096
static dm_table_t* g_dialmem = 0;
static long long dialmem_now(void){ return (long long)time(NULL); }
unsigned long peer_nowit_bytes(void){ return (unsigned long)sizeof(nowit_set_t); }
static char  g_nowit[NOWIT_MAX][64];
static int   g_nowit_n = 0;
static unsigned long long g_nowit_skips = 0;
static void nowit_key(char* out, unsigned long n, const char* who){
    snprintf(out, n, "%s", who ? who : "?");
    char* c = strrchr(out, ':'); if (c && strchr(out, '.')) *c = 0;   /* strip :port, keep IPv6 */
}
/* 1 if this address already failed the witness check in this run */
static int nowit_lookup(const char* k){
    if (g_nowit_sh){
        int n = g_nowit_sh->n; if (n > NOWIT_MAX) n = NOWIT_MAX;
        for (int i = 0; i < n; i++) if (!strcmp(g_nowit_sh->a[i], k)) return 1;
        return 0;
    }
    for (int i = 0; i < g_nowit_n; i++) if (!strcmp(g_nowit[i], k)) return 1;
    return 0;
}
int peer_known_no_witness(const char* who){
    char k[64]; nowit_key(k, sizeof k, who);
    if (!nowit_lookup(k)) return 0;
    if (g_nowit_sh) __sync_fetch_and_add(&g_nowit_sh->skips, 1ULL); else g_nowit_skips++;
    return 1;
}
unsigned long long peer_no_witness_skips(void){ return g_nowit_sh ? g_nowit_sh->skips : g_nowit_skips; }
int peer_no_witness_count(void){
    if (!g_nowit_sh) return g_nowit_n;
    int n = g_nowit_sh->n; return n > NOWIT_MAX ? NOWIT_MAX : n;
}
static void nowit_remember(const char* who){
    char k[64]; nowit_key(k, sizeof k, who);
    if (nowit_lookup(k)) return;
    if (g_nowit_sh){
        /* a duplicate here is harmless (the lookup is a scan), so a plain
         * atomic claim of the next slot is enough -- no lock on a dial path. */
        int slot = __sync_fetch_and_add(&g_nowit_sh->n, 1);
        if (slot < NOWIT_MAX) snprintf(g_nowit_sh->a[slot], sizeof g_nowit_sh->a[0], "%s", k);
        else __sync_fetch_and_sub(&g_nowit_sh->n, 1);
        return;
    }
    if (g_nowit_n < NOWIT_MAX) snprintf(g_nowit[g_nowit_n++], sizeof g_nowit[0], "%s", k);
}
static int peer_has_witness(const char* who){
    unsigned long long services = 0;
    if (g_peer_version_len >= 12)
        memcpy(&services, g_peer_version_payload + 4, 8);
    if (services & 0x8ULL) return 1;
    char k[64]; nowit_key(k, sizeof k, who);
    int known = nowit_lookup(k);
    if (!known)
        fprintf(stderr, "[dial] %s lacks NODE_WITNESS (services=0x%llx) -- dropping, and not dialling it again this run\n",
                who ? who : "?", services);
    nowit_remember(who);
    if (g_dialmem) dialmem_note_failure(g_dialmem, who, DM_NO_WITNESS, dialmem_now());
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
extern long utxo_live_catchup_bounded(void* store_buf, long max_ms, int stop_at_hole);   /* step 1: the interleaved connect */
extern long utxo_live_last_stop_reason(void);           /* why the last catch-up call returned (UTXO_STOP_*) */
extern long utxo_live_call_rejected_height(void);       /* 3.3: the height the last call rejected, or -1 */
extern void utxo_live_set_shutdown_flag(const volatile sig_atomic_t* flag); /* daemon/utxo_live.c */
extern long utxo_live_count(void);                      /* daemon/utxo_live.c */
extern long utxo_live_recovery_applicable(void);         /* daemon/utxo_live.c: incident 2026-09-01 */
extern long utxo_live_verify_after_recovery(long count_before);
extern long utxo_live_halted(void);
extern long utxo_live_last_fail_kind(void);
extern const char* utxo_live_fail_kind_name(long k);
extern const char* utxo_live_last_reject(void);
/* Clamp the DISPLAYED live-UTXO count at 0. Backstop only: the count itself
 * is now kept accurate across restarts by the manifest persist/restore in
 * bitcoin_utxo_lsm.asm (this replaced the WAL-tail-only reload seed that let
 * live_utxo go negative, e.g. -2610837). This just guarantees a future
 * accounting drift can never surface a nonsensical negative in the logs. */
static long live_utxo_disp(void){ long c = utxo_live_count(); return c < 0 ? 0 : c; }
extern long utxo_live_applied_height(void);              /* daemon/utxo_live.c */
extern long utxo_live_public_tip(void* store_buf, long live);   /* daemon/utxo_live.c (3.1) */
extern long utxo_live_persisted_height(void);            /* daemon/utxo_live.c (3.1) */
extern long utxo_live_recover(void);                     /* daemon/utxo_live.c */
/* ---- 3.1 (UTXO_INLINE_CONNECT_SCOPE, 2026-09-06): the node's tip is the
 * CONNECTED tip. Until this, every outward-facing site read *(int*)(store+24)
 * -- the ARCHIVE's high-water mark, which the parallel downloader runs
 * hundreds of thousands of blocks past the last block this node has actually
 * validated against its UTXO set. Core announces, serves and reports only
 * what ActivateBestChain has connected; so does this node now, through this
 * one function: min(stored, applied) while live UTXO tracking is on, the
 * stored tip when it is off (the "continuing WITHOUT live UTXO tracking"
 * degraded mode -- the pre-3.1 behaviour, kept as the negative control).
 * g_utxo_live_on mirrors the worker's utxo_live_ok (set at init, cleared at
 * the two HALT sites). The store's own tip remains what the downloader and
 * the header mirror key on. */
static int g_utxo_live_on = 0;
static long node_public_tip(void* st){ return utxo_live_public_tip(st, g_utxo_live_on); }
/* Publish the connected tip for the two other processes that speak for this
 * node: the parent's chain RPCs (rpc_chain refresh) and the inbound serve
 * children (serve_public_tip). Called at the rotation top and from the
 * catch-up apply hook, so a long catch-up call keeps it fresh per block. */
static void dl_publish_connected_tip(void){
    if(!g_node_status) return;
    g_node_status->connected_tip = g_utxo_live_on ? utxo_live_applied_height() : NODE_TIP_UNTRACKED;
}
static long rpc_public_tip(void){ return g_node_status ? (long)g_node_status->connected_tip : (long)NODE_TIP_UNTRACKED; }
extern int  archive_verify_and_repair(void* store_buf, int repair); /* daemon/archive_verify.c */
extern long archive_repair_bad_bodies(long nblocks, int level);  /* STO-11 */
extern long archive_drop_utxo_state(void);                /* daemon/archive_verify.c */
#include "archive_verify.h"                               /* archive_* + prune verdict */
extern int  store_set_prune(void* st, int h);             /* bitcoin_store.asm       */
extern int  store_prune(void* st, int h);                 /* bitcoin_store.asm       */
extern long p2p_write(int fd,const char*cmd,unsigned cmdlen,const void*pl,unsigned plen);
extern int  p2p_read(int fd,char cmd[12],void*pl,unsigned cap,unsigned*len);
/* 2026-09-09: what a peer that hung up left unread in the socket -- the
 * message types, in order, and a reject's text. Bounded: at most 12
 * messages, and a hung-up socket answers every read at once. */
static void leg_drain_unread(int fd, char* out, unsigned long cap){
    static unsigned char buf[1 << 20]; char cmd[12]; unsigned len = 0; unsigned long o = 0; int n = 0;
    out[0] = 0;
    for(; n < 12; n++){
        struct pollfd pf = { fd, POLLIN, 0 };
        if(poll(&pf, 1, 0) <= 0 || !(pf.revents & POLLIN)) break;
        int r = p2p_read(fd, cmd, buf, sizeof buf, &len);
        if(r != 1) break;
        char c[13]; memcpy(c, cmd, 12); c[12] = 0;
        for(int k = 0; k < 12; k++) if(c[k] && (c[k] < 0x20 || c[k] > 0x7e)) c[k] = '.';
        int w = snprintf(out + o, cap - o, "%s%s", o ? " " : "", c); if(w < 0 || (unsigned long)w >= cap - o) break; o += (unsigned long)w;
        if(!strncmp(cmd, "reject", 12) && len > 1){ unsigned ml = buf[0]; unsigned p = 1 + ml; if(p < len){ unsigned rl = buf[p]; p += 2; if(p + rl <= len){ w = snprintf(out + o, cap - o, "(%.*s)", rl > 60 ? 60 : rl, (const char*)buf + p); if(w > 0 && (unsigned long)w < cap - o) o += (unsigned long)w; } } }
    }
    if(!o) snprintf(out, cap, "%s", n == 0 ? "(nothing)" : "(nothing readable)");
}
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
/* STO-5: the CONCURRENT-SAFE appender. store_append above is single-writer
 * only -- it seeks to a cached cur_file_pos and takes no flock -- so every
 * live writer in this daemon uses this one instead. Returns the height, -1 on
 * error, or -2 when the block does not link to the current tip (which means
 * another writer stored one first). */
extern long idxscan_append_locked(void* st, const unsigned char hash32[32],
                                  const void* raw, long len);
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
    /* ---- STO-9 (audit 2026-09-03): rewind headers.dat too ----
     * Nothing here touched the header mirror, so after a reorg it kept the
     * LOSING branch's headers at fork+1..old_tip, and dl_header_mirror_topup
     * only ever appends above hst_count -- so the new blocks landed above the
     * stale ones, with a prev that does not link to the record beneath them.
     * archive_trim_derived_tails repairs it on the NEXT BOOT, which means a
     * long-running node carries a mirror that disagrees with its own archive
     * until it restarts.
     *
     * Truncating the file is enough: the top-up re-derives everything above
     * what remains. Only the file is touched, not a mirror buffer -- unlike
     * dlc_headers_rollback below, which also reloads the download worker's
     * hst, and which this path has no handle for.
     *
     * The store tip IS the fork height on the mid-reorg invocation (the same
     * property the watermark comment below relies on), so (tip+1)*112 is the
     * record count to keep. Guarded by a size check so the post-reconnect
     * invocation, where the mirror is already shorter, does nothing.
     *
     * Same process as the top-up and the connect path, so no writer races
     * this truncate. */
    { long rtip = (long)*(int*)((char*)store_buf + 24);
      if (rtip >= 0){
          off_t want = (off_t)(rtip + 1) * 112;
          struct stat hst_stt;
          if (stat("headers.dat", &hst_stt) == 0 && hst_stt.st_size > want){
              if (truncate("headers.dat", want) != 0)
                  fprintf(stderr, "[reorg] WARNING: could not roll headers.dat back to %ld records: %s -- the mirror keeps the losing branch until the next boot's self-heal\n",
                          rtip + 1, strerror(errno));
              else
                  fprintf(stderr, "[reorg] headers.dat rolled back to %ld records (dropped %lld bytes of the losing branch)\n",
                          rtip + 1, (long long)(hst_stt.st_size - want));
          }
      } }

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

/* ---------------------------------------------------------------- NET-3
 * An inactivity bound on an ACCEPTED socket.
 *
 * An accepted socket had no SO_RCVTIMEO, no alarm, and no per-child deadline,
 * and fd_read_full (bitcoin_net.asm) blocks in read(2) with no poll. So a
 * peer that completed the version handshake and then went silent held its
 * inbound slot and its forked child forever. CFG_INBOUND_LIMIT() such
 * connections -- 189 by default -- and the parent logs "inbound at capacity"
 * and refuses every honest peer until the attacker closes. The cost to the
 * attacker is 189 idle sockets.
 *
 * Core's CConnman::InactivityCheck uses TIMEOUT_INTERVAL, 20 minutes, and
 * that is what this mirrors. It is safe against real peers precisely because
 * Core PINGS every 2 minutes: any live peer resets the timer an order of
 * magnitude before it expires. Our serve loop answers pings but never
 * initiates them (bitcoin_serve.asm), so this bound is what stands in for the
 * liveness check we do not perform.
 *
 * fd_read_full returns -1 on any read error, EAGAIN included, and does not
 * retry -- so the timeout propagates as a read failure and the child exits
 * its serve loop. No change is needed in the assembly.
 *
 * SO_SNDTIMEO too: a peer that stops reading stalls us in write(2) exactly
 * the same way, and holds the same slot.
 *
 * INBOUND ONLY. Applying this to outbound would be wrong: an outbound sync
 * leg is legitimately quiet while waiting on blocks, and dropping it would
 * damage the thing that keeps this node following the chain.
 *
 * BMC_PEER_IDLE_SECS overrides it, following the BMC_LSM_MMAP /
 * BMC_ECDSA_GLV kill-switch idiom, so tests can drive the path in seconds.
 * Note this is NOT Core's -peertimeout, which bounds the HANDSHAKE: that one
 * is g_cfg.peer_timeout_s, applied by peer_handshake_deadline() from socket
 * open until verack (CC-7, 2026-09-06; it was parsed and unread before --
 * DMN-14). Once the handshake completes this idle bound takes over. */
#define PEER_IDLE_SECS_DEFAULT 1200      /* Core TIMEOUT_INTERVAL, 20 minutes */
static void peer_inbound_deadline(int fd){
    if (fd < 0) return;
    long secs = PEER_IDLE_SECS_DEFAULT;
    const char* e = getenv("BMC_PEER_IDLE_SECS");
    if (e && *e){
        long v = atol(e);
        if (v > 0) secs = v;
    }
    struct timeval tv;
    tv.tv_sec = (time_t)secs;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

static int lsock_onion(int want_port, int* got_port){
    int l = socket(AF_INET,SOCK_STREAM,0);
    /* DMN-14 (audit 2026-09-03): socket() was never checked. On failure `l` is
     * -1, bind(-1) fails with EBADF, and the operator is told "bind failed" --
     * a diagnosis pointing at the address and port when the real cause is fd
     * exhaustion or an unavailable address family. Two minutes of the wrong
     * investigation, for one branch. */
    if (l < 0){ fprintf(stderr,"[net] socket() failed: %s\n", strerror(errno)); return -1; }
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
    /* DMN-14 (audit 2026-09-03): socket() was never checked. On failure `l` is
     * -1, bind(-1) fails with EBADF, and the operator is told "bind failed" --
     * a diagnosis pointing at the address and port when the real cause is fd
     * exhaustion or an unavailable address family. Two minutes of the wrong
     * investigation, for one branch. */
    if (l < 0){ fprintf(stderr,"[net] socket() failed: %s\n", strerror(errno)); return -1; }
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
                                    /* STO-5 (audit 2026-09-03): this is a forked
                                     * serve CHILD appending to the shared archive,
                                     * so it must use the locked appender like every
                                     * other live writer. store_append seeks to the
                                     * in-memory cur_file_pos and takes NO flock, so
                                     * two writers that both believe the tip is T
                                     * write the same file offset -- and if one block
                                     * is larger, its tail overruns the next frame and
                                     * that height's index record points at rubbish.
                                     * -2 means the block does not link to the current
                                     * tip, which here just means somebody else got
                                     * there first: not an error, nothing to log. */
                                    long ar = idxscan_append_locked(store_buf,hdr,blk,bl);
                                    if (ar >= 0) node_log_event(lfd, L_BLOCK, (unsigned)bl, 1, i);
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
    if (n < 9) return 0;
    *v = 0; for (int i = 0; i < 8; i++) *v |= (unsigned long long)p[1+i] << (8*i); return 9;
}
/* serialized length of the tx at p (segwit-aware); 0 if malformed */
static long wn_tx_len(const unsigned char* p, long n){
    long q = 4; unsigned long long v; long k; int segwit = 0;
    if (q + 2 <= n && p[q] == 0x00 && p[q+1] == 0x01){ segwit = 1; q += 2; }
    if (!(k = wn_varint(p + q, n - q, &v))) return 0;
    q += k; unsigned long long nin = v;
    for (unsigned long long i = 0; i < nin; i++){
        q += 36;
        if (q > n) return 0;
        if (!(k = wn_varint(p + q, n - q, &v))) return 0;
        q += k + (long)v + 4;
        if (q > n) return 0;
    }
    if (!(k = wn_varint(p + q, n - q, &v))) return 0;
    q += k; unsigned long long nout = v;
    for (unsigned long long i = 0; i < nout; i++){
        q += 8;
        if (q > n) return 0;
        if (!(k = wn_varint(p + q, n - q, &v))) return 0;
        q += k + (long)v;
        if (q > n) return 0;
    }
    if (segwit) for (unsigned long long i = 0; i < nin; i++){
        if (!(k = wn_varint(p + q, n - q, &v))) return 0;
        q += k;
        for (unsigned long long j = 0; j < v; j++){ unsigned long long l;
            if (!(k = wn_varint(p + q, n - q, &l))) return 0;
            q += k + (long)l;
            if (q > n) return 0; }
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
    if (!k) return;
    p += k;
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
static unsigned char mux_out_kind[MUX_MAX_OUT];         /* CC-4: LEG_FULL / LEG_BLOCK_ONLY */
static unsigned char mux_out_cmpct[MUX_MAX_OUT];        /* CC-2: the peer sent sendcmpct on this leg */
/* 2026-09-10, Core's shape at the tip: a block announced on the leg since its
 * last pass (inv, or a pushed `headers`: we send sendheaders), and whether the
 * leg is one of the three high-bandwidth compact-block sources */
static unsigned char mux_out_announced[MUX_MAX_OUT];
static unsigned char mux_out_hb[MUX_MAX_OUT];
static long long     mux_out_hb_since[MUX_MAX_OUT];
/* Core sends getheaders only with cause (a new peer, a header that does not
 * connect); a synced node is told of blocks. Ours sent one per leg per
 * rotation. A leg now gets a pass when a block was announced on it, else at
 * most every LEG_PASS_EVERY_MS as the safety net (inventory row 1). */
static long long     mux_out_lastpass_ms[MUX_MAX_OUT];
#define LEG_PASS_EVERY_MS 30000LL
extern void* g_cmpct_hook_cmpct;                        /* bitcoind.asm: non-NULL once the receive side is installed */
extern long  g_peer_sendcmpct;                          /* bitcoind.asm: set by the sync drains when the peer sends sendcmpct */
extern void* g_sync_mp;                                 /* bitcoind.asm: the mempool node_sync_multi reconstructs from */
static void* txsub_pool(void);                           /* defined with the tx-submit worker below */
static int   txsub_worker_ready(void);
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
extern void txrelay_leg_reset(int fd);   /* a (re)dialled leg starts its own announce timer */
static int   mux_out_peer[MUX_MAX_OUT];     /* index into the peer pool (for re-dial rotation) */
static int   g_reorg_ok = 0;                /* the worker opened chainwork: the reorg module is usable (2026-09-09) */
static void  dl_after_gate_rewind(long back);   /* defined with the choke-point state below */
static long long mux_out_nextretry[MUX_MAX_OUT];
/* consecutive failed sync passes per leg; surfaced in the heartbeat as
 * sync_failing=N and used to drop a leg that will not answer (see
 * do_outbound_sync). */
static int g_sync_fail_streak[MUX_MAX_OUT]; /* consecutive failing sync passes of the leg in the slot (reset per peer) */
static long long mux_out_since[MUX_MAX_OUT];      /* 2026-09-09: when the leg in the slot connected (epoch s) */
/* 2026-09-09: one request per block across the legs (daemon/inflight.h); the
 * sync loop asks g_block_fetch_hook before every getdata */
#include "inflight.h"
static inflight_t g_inflight; static int g_sync_leg = -1;
extern void* g_block_fetch_hook;
static long block_fetch_gate(const unsigned char* hash){
    long h;
    if(ht_idx && idx_get(ht_idx, hash, &h)) { g_inflight.refused++; return 0; }   /* already stored (a sibling leg landed it): nothing to fetch */
    return inflight_claim(&g_inflight, hash, g_sync_leg, (long long)time(NULL));
}
/* 2026-09-09: we ping every leg, as Core does (2 min), and a leg that has not
 * answered in 20 min is closed. Until now a dead peer was found only when a
 * pass failed, and we had no ping time to offer an inbound-full node's
 * eviction protection. */
static long long dh_now_ms(void);   /* defined with the dial helper below */
#define LEG_PING_EVERY_S 120L
#define LEG_PING_TIMEOUT_S 1200L
static long long mux_out_ping_sent[MUX_MAX_OUT], mux_out_pong_at[MUX_MAX_OUT]; static unsigned long long mux_out_ping_nonce[MUX_MAX_OUT]; static long mux_out_ping_ms[MUX_MAX_OUT];
static long long mux_out_ping_sent_ms[MUX_MAX_OUT];
static int leg_ping_due(long long now, long long sent){ return sent == 0 || now - sent >= LEG_PING_EVERY_S; }
static int leg_ping_timed_out(long long now, long long sent, long long pong_at){ return sent != 0 && pong_at < sent && now - sent >= LEG_PING_TIMEOUT_S; }
static unsigned char mux_out_good[MUX_MAX_OUT];   /* it lived DM_GOOD_S: its address's failure streak was cleared */
extern int sync_fail_code;                        /* bitcoind.asm: where the last node_sync_multi pass failed */
/* a new peer in the slot: its own clock, its own streak. Before 2026-09-09 the
 * streak was never reset when the slot changed hands, so a fresh leg whose
 * first pass failed was closed on the spot -- silently -- as the third
 * strike of two predecessors (production, 16:30-16:42Z: eight legs closed by
 * us within 50-160 s, none logged). */
static void leg_note_installed(int i){
    mux_out_since[i] = (long long)time(NULL); mux_out_good[i] = 0; g_sync_fail_streak[i] = 0; mux_out_ping_sent[i] = 0; mux_out_pong_at[i] = 0; mux_out_ping_ms[i] = -1;
    mux_out_announced[i] = 0; mux_out_hb[i] = 0; mux_out_hb_since[i] = 0; mux_out_lastpass_ms[i] = 0;
    /* 2026-09-10: Core sends sendheaders after verack so peers PUSH new
     * headers instead of announcing by inv; the sweep acts on either. Only
     * with the receive side installed, like sendcmpct: the sync harnesses'
     * fake peers depend on the bare stream. */
    if(mux_out_fd[i] >= 0 && g_cmpct_hook_cmpct) p2p_write(mux_out_fd[i], "sendheaders", 11, 0, 0);
}
static long long leg_age_s(int i){ return mux_out_since[i] ? (long long)time(NULL) - mux_out_since[i] : -1; }
static int legs_live(void){ int n = 0; for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0) n++; return n; }
/* every deliberate close of a leg says so: "closed ours/<reason>", never a
 * later "connection dropped" that reads as the peer's doing (a socket we
 * shutdown() ourselves presents POLLIN|POLLERR|POLLHUP to our own poll) */
/* 2026-09-09 (second leg batch, from the first hour of labels on production):
 * a leg's socket keeps the 300 ms read timeout of its dial, so the sync
 * drains' tick counts -- 8 for headers, 20 for a block, designed as 3 s
 * ticks (24 s / 60 s) -- gave a peer 2.4 s to answer getheaders; seven
 * legs in twenty minutes were closed as "no headers" (where=3 in 2.4s).
 * After the handshake the socket ticks at 3 s. */
#define LEG_READ_TICK_S 3
static void leg_settle_socket(int fd){ struct timeval tv = { LEG_READ_TICK_S, 0 }; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); }
#ifndef POLLRDHUP
#define POLLRDHUP 0x2000
#endif
/* Has the peer hung up? A half-close (FIN, the common Core disconnect)
 * raises POLLRDHUP, not POLLHUP: eight legs in twenty minutes sat dead for
 * three rotations after the peer's FIN, each pass failing at once with
 * where=4 (EOF), until the streak retired them as "ours". */
static int leg_peer_hung_up(int fd, short* revents_out){
    struct pollfd pf = { fd, POLLIN | POLLRDHUP, 0 };
    int r = poll(&pf, 1, 0);
    if(revents_out) *revents_out = pf.revents;
    return r > 0 && (pf.revents & (POLLHUP | POLLERR | POLLNVAL | POLLRDHUP)) ? 1 : 0;
}
static void leg_close_ours(int i, const char* reason, const char* detail){
    fprintf(stderr,"[dl:%d] %s connection closed ours/%s after %llds%s%s\n", i, mux_out_host[i][0] ? mux_out_host[i] : "?", reason, leg_age_s(i),
            detail && detail[0] ? " -- " : "", detail ? detail : "");
    if(mux_out_fd[i] >= 0){ bmc_v2_close(mux_out_fd[i]), close(mux_out_fd[i]); mux_out_fd[i] = -1; }
}
static void leg_close_theirs(int i, const char* how, const char* unread){
    long long age = leg_age_s(i);
    fprintf(stderr,"[dl:%d] %s connection closed theirs (%s) after %llds; unread: %s\n", i, mux_out_host[i][0] ? mux_out_host[i] : "?", how, age, unread ? unread : "(nothing)");
    if(g_dialmem && age >= 0 && age <= DM_EARLY_S) dialmem_note_failure(g_dialmem, mux_out_host[i], age <= DM_REFUSED_S ? DM_REFUSED : DM_EARLY_DROP, dialmem_now());
    if(mux_out_fd[i] >= 0){ bmc_v2_close(mux_out_fd[i]), close(mux_out_fd[i]); mux_out_fd[i] = -1; }
    mux_out_nextretry[i] = 0;   /* re-dial on the next rotation */
}
extern long p2p_ping(unsigned char* out, unsigned long long nonce);
static void leg_on_pong(int fd, const unsigned char nonce[8]){
    for(int k = 0; k < mux_n_out; k++){
        if(mux_out_fd[k] != fd) continue;
        unsigned long long n; memcpy(&n, nonce, 8);
        if(n != mux_out_ping_nonce[k]) return;
        mux_out_pong_at[k] = (long long)time(NULL);
        mux_out_ping_ms[k] = (long)(dh_now_ms() - mux_out_ping_sent_ms[k]);
        return;
    }
}
/* once per rotation per leg: close a leg 20 min without a pong, else send the next ping when due */
static void leg_ping_tick(int k, long long now){
    if(mux_out_fd[k] < 0) return;
    if(leg_ping_timed_out(now, mux_out_ping_sent[k], mux_out_pong_at[k])){
        leg_close_ours(k, "ping-timeout", "no pong in 20 min");
        if(g_dialmem) dialmem_note_failure(g_dialmem, mux_out_host[k], DM_EARLY_DROP, dialmem_now());
        mux_out_nextretry[k] = 0;
        return;
    }
    if(!leg_ping_due(now, mux_out_ping_sent[k])) return;
    unsigned char pl[8]; unsigned long long nonce = ((unsigned long long)dh_now_ms() << 20) ^ ((unsigned long long)k << 8) ^ (unsigned long long)getpid();
    p2p_ping(pl, nonce);
    if(p2p_write(mux_out_fd[k], "ping", 4, pl, 8) > 0){ mux_out_ping_nonce[k] = nonce; mux_out_ping_sent[k] = now; mux_out_ping_sent_ms[k] = dh_now_ms(); }
}
#define REDIAL_BACKOFF_MS 30000L             /* min gap between re-dial tries on a dead slot */

/* ---- runtime peer control (RPC ctl_* channel) ---------------------------
 * The worker owns the legs, so it owns these. The parent asks; this decides.
 * The runtime addnode list is SEPARATE from g_cfg.addnode (the operator's
 * bitcoin.conf list): `addnode ... remove` must be able to drop a runtime
 * addition without editing the config, and getaddednodeinfo reports the
 * config list, so conflating them would make `remove` appear to fail. */
#define CTL_MAX_ADDNODE 32
#include "ctl_dial.h"   /* 2026-09-09: the runtime list is a DIAL QUEUE now -- it had been stored and never dialed */
static int ctl_dial_is_leg(const char* host){ for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0 && !strcmp(mux_out_host[k], host)) return 1; return 0; }

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
#include "relay_policy.h"
#include "private_broadcast.h"
#include "../bmc_thread.h"   /* 2026-09-01: the mempool-reload and i2p-accept threads ran on glibc-default stacks; with ~12 MB of static TLS that is a few KB of real stack, and the one-write logging buffer (8 KB) overflowed it the moment a reused datadir had a mempool.dat to reload (fault addr == rsp in log_vfprintf_at, reproduced by validation/relay_policy_core_diff.sh run B twice) */
extern unsigned g_conn_perms;                     /* whitebind permissions of this child (defined below) */
/* ---- relay policy per inbound connection (2026-09-01; daemon/relay_policy.c)
 * The serve child sets these once the peer's version is in hand (the asm
 * handshake calls g_accept_version_hook between capturing the peer's
 * version and building ours), and the serve loop's C gates read them. */
extern void (*g_accept_version_hook)(void);      /* bitcoind.asm node_accept_handshake */
extern unsigned char node_relay_flag;            /* bitcoind.asm: fRelay byte of OUR version */
extern unsigned node_start_height;               /* bitcoind.asm: start_height of OUR version (2026-09-09: was 0) */
extern unsigned short node_listen_port_be;       /* bitcoind.asm: the port in OUR version's address fields, big-endian (was 8333) */
static void version_tell_the_truth(void){ node_start_height = (unsigned)(*(int*)(store_buf+24) > 0 ? *(int*)(store_buf+24) : 0); node_listen_port_be = htons((unsigned short)g_cfg.port); }
extern unsigned char g_serve_send_feefilter;     /* bitcoin_serve.asm: send `feefilter` at connect */
static unsigned g_conn_perms_all;                /* whitelist | whitebind, this connection */
static int      g_peer_relays_txs = 1;           /* the peer's version fRelay */
static int      g_inbound_slot = -1;             /* our entry in the shared peer table */
/* inbound peers that negotiated tx relay in both directions (the share Core
 * counts: m_relays_txs on inbound peers), read from the shared table */
static long inbound_relaying_now(void){
    if(!g_node_status) return 0;
    long n = 0;
    for(int i = MUX_MAX_OUT; i < RPC_MAX_PEERS; i++){
        const rpc_peer_t* q = &g_node_status->peers[i];
        if(!q->used || !q->inbound || !q->relaytxes) continue;
        if(q->pid > 0 && kill((pid_t)q->pid, 0) != 0 && errno == ESRCH) continue;
        n++;
    }
    return n;
}
static void serve_on_peer_version(void){
    unsigned perms = netperm_for(g_cur_peer_ip) | g_conn_perms;
    g_conn_perms_all = perms;
    int fr = rp_version_frelay(g_peer_version_payload, g_peer_version_len);
    g_peer_relays_txs = fr != 0;
    int exhausted = rp_inbound_share_exhausted(inbound_relaying_now(), CFG_INBOUND_LIMIT(), g_cfg.inboundrelaypercent);
    node_relay_flag = (unsigned char)rp_our_frelay(perms, RP_CONN_INBOUND, exhausted);
    g_serve_send_feefilter = (unsigned char)rp_send_feefilter(perms);
}
/* the serve loop's gates (bitcoin_serve.asm calls these): 0 go on, 1 drop
 * the message quietly, -1 protocol violation (the loop disconnects) */
int serve_tx_gate(void){
    if(rp_reject_incoming_txs(g_conn_perms_all, RP_CONN_INBOUND)) return -1;   /* Core: "transaction sent in violation of protocol" */
    if(!node_relay_flag) return 1;                                              /* we asked for no relay (inbound share): not relaying */
    return 0;
}
int serve_inv_gate(const unsigned char* pl, long plen){
    extern int serve_inv_bounds(const unsigned char*, long, unsigned long long*, long*);
    unsigned long long n = 0; long off = 0;
    if(serve_inv_bounds(pl, plen, &n, &off) != 1) return 0;
    for(unsigned long long i = 0; i < n; i++){
        const unsigned char* e = pl + off + i*36;
        unsigned t = (unsigned)e[0] | ((unsigned)e[1]<<8) | ((unsigned)e[2]<<16) | ((unsigned)e[3]<<24);
        if(t == 1 || t == 5 || t == 0x40000001u){                                /* MSG_TX / MSG_WTX / MSG_WITNESS_TX */
            if(rp_reject_incoming_txs(g_conn_perms_all, RP_CONN_INBOUND)) return -1;
            return 0;
        }
    }
    return 0;
}
/* `mempool` (BIP35): Core answers only with NODE_BLOOM (never advertised
 * here) or the `mempool` permission, and disconnects anyone else unless
 * noban. The reply is one inv(MSG_TX) per pool entry, MAX_INV_SZ per message. */
int serve_mempool_msg(int fd, void* mp){
    if(!(g_conn_perms_all & NP_MEMPOOL)) return (g_conn_perms_all & NP_NOBAN) ? 1 : -1;
    if(!mp) return 1;
    unsigned char* m = (unsigned char*)mp;
    unsigned long long mask; memcpy(&mask, m+8, 8);
    static unsigned char inv[3 + 50000*36]; unsigned n = 0; long sent = 0;
    for(unsigned long long i = 0; i <= mask; i++){
        unsigned char* sl = MPOOL_SLOT_AT(m, i);
        unsigned long long len; memcpy(&len, sl, 8);
        if(len == MPOOL_SLOT_EMPTY) continue;
        unsigned char* e = inv + 3 + n*36; e[0]=1; e[1]=0; e[2]=0; e[3]=0; memcpy(e+4, sl+MPOOL_SLOT_TXID, 32); n++;
        if(n == 50000){ inv[0]=0xfd; inv[1]=(unsigned char)n; inv[2]=(unsigned char)(n>>8); p2p_write(fd, "inv", 3, inv, 3 + n*36); sent += n; n = 0; }
    }
    if(n){ if(n < 0xfd){ inv[2]=(unsigned char)n; p2p_write(fd, "inv", 3, inv+2, 1 + n*36); }
           else { inv[0]=0xfd; inv[1]=(unsigned char)n; inv[2]=(unsigned char)(n>>8); p2p_write(fd, "inv", 3, inv, 3 + n*36); } sent += n; }
    fprintf(stderr,"[serve] mempool request from %s (mempool permission): %ld inv entries\n", g_cur_peer_ip, sent);
    return 1;
}
/* a relay-policy violation: Core disconnects without scoring (fDisconnect) */
void serve_policy_disconnect_log(const char* reason){
    fprintf(stderr,"[serve] %s: %s -- disconnecting\n", g_cur_peer_ip[0] ? g_cur_peer_ip : "peer", reason ? reason : "protocol violation");
}
/* claim a shared peer-table slot for this inbound child (64..127; a dead
 * child's slot is reused) and publish what getpeerinfo shows */
static void rpc_fill_peer_slot(int slot, const char* host);
static void rpc_fill_peer_slot_ex(int slot, const char* host, int already_claimed);
static unsigned netgroup_of_hostport(const char* hostport);   /* CC-3: defined with txr_source_group_fd below */
static int inbound_slot_claim(const char* peerdesc){
    if(!g_node_status) return -1;
    for(int i = RPC_MAX_PEERS - 1; i >= MUX_MAX_OUT; i--){
        rpc_peer_t* q = &g_node_status->peers[i];
        if(q->used && q->inbound && q->pid > 0 && kill((pid_t)q->pid, 0) != 0 && errno == ESRCH)
            __sync_bool_compare_and_swap(&q->used, 1, 0);
        if(q->used) continue;
        if(!__sync_bool_compare_and_swap(&q->used, 0, 1)) continue;
        /* RPC-13 (audit 2026-09-03): the slot is ALREADY CLAIMED -- the CAS
         * above took it 0 -> 1. rpc_fill_peer_slot's memset zeroes the whole
         * record including `used`, which handed the slot back to any sibling
         * child scanning for a free one; the loser's later `used = 0` would
         * then free the winner's entry and getpeerinfo would under-report.
         * The _ex form preserves the claim across the memset. */
        rpc_fill_peer_slot_ex(i, peerdesc, 1);
        q->inbound = 1; q->pid = (int)getpid(); q->perms = g_conn_perms_all;
        q->relaytxes = node_relay_flag && g_peer_relays_txs;
        q->net_group = netgroup_of_hostport(peerdesc);          /* CC-3 */
        q->last_tx_time = 0; q->last_block_time = 0; q->min_ping_us = 0; q->evict_requested = 0;
        return i;
    }
    return -1;
}
/* Declared, because it is DEFINED below this call. Without it C assumes
 * `int peer_misbehaving()` with unspecified arguments -- which happens to work
 * for these types under the SysV ABI, which is exactly why the warning had
 * been ignored. It is a warning about a real missing prototype. */
int peer_misbehaving(const char* ip, int points, const char* reason);
static void serve_violation_report(const char* reason){
    if(!g_cur_peer_ip[0]) return;
    peer_misbehaving(g_cur_peer_ip, 100, reason ? reason : "protocol violation");
}
/* audit 2026-09-02 N3: the download worker's legs report by fd (tx_relay.c
 * declares this weak; the daemon supplies it). Map the fd to its leg's
 * "host:port", strip the port, and score it like a serve-side violation. */
static void ctl_ip_only(const char* hostport, char* out, size_t cap);   /* defined below */
extern unsigned net_netgroup_v4(unsigned ip);                          /* daemon/net_policy.c */

/* NET-10: which source netgroup is the peer on this fd? Same fd -> leg
 * "host:port" map the violation hook below uses. IPv4 gets Core's /16
 * grouping (net_netgroup_v4); anything else -- onion, i2p, cjdns, or a host
 * we cannot parse -- gets a hash of the host string with the top bit set, so
 * it is stable per source and cannot collide with a /16 value. 0 means
 * "unknown", which ab2_add_from never caps. */
/* CC-3: the Core /16 grouping of a "host:port" string (NET-10's rule for
 * onion/i2p/cjdns: a stable hash with the top bit set, which cannot collide
 * with a /16). 0 = unknown. Same logic as txr_source_group_fd below. */
static unsigned netgroup_of_hostport(const char* hostport){
    char ip[128]; ctl_ip_only(hostport, ip, sizeof ip);
    if(!ip[0]) return 0;
    unsigned o0, o1, o2, o3;
    if(sscanf(ip, "%u.%u.%u.%u", &o0, &o1, &o2, &o3) == 4 && o0 < 256 && o1 < 256 && o2 < 256 && o3 < 256){
        unsigned v4 = o0 | (o1 << 8) | (o2 << 16) | (o3 << 24);
        unsigned g = net_netgroup_v4(v4);
        return g ? g : 1u;
    }
    unsigned h = 2166136261u;
    for(const char* p = ip; *p; p++){ h ^= (unsigned char)*p; h *= 16777619u; }
    return h | 0x80000000u;
}
unsigned txr_source_group_fd(int fd){
    for(int k = 0; k < mux_n_out; k++){
        if(mux_out_fd[k] != fd) continue;
        char ip[128]; ctl_ip_only(mux_out_host[k], ip, sizeof ip);
        if(!ip[0]) return 0;
        unsigned o0, o1, o2, o3;
        if(sscanf(ip, "%u.%u.%u.%u", &o0, &o1, &o2, &o3) == 4 && o0 < 256 && o1 < 256 && o2 < 256 && o3 < 256){
            unsigned v4 = o0 | (o1 << 8) | (o2 << 16) | (o3 << 24);   /* byte 0 = first octet */
            unsigned g = net_netgroup_v4(v4);
            return g ? g : 1u;                 /* never hand back 0 = "unknown" */
        }
        unsigned h = 2166136261u;
        for(const char* p = ip; *p; p++){ h ^= (unsigned char)*p; h *= 16777619u; }
        return h | 0x80000000u;
    }
    return 0;
}

/* "host:port" / "[v6]:port" -> the bare address the misbehaviour table keys on */
static void host_strip_port(char* host){
    if(host[0] == '['){ char* e = strchr(host, ']'); if(e) *e = 0; memmove(host, host + 1, strlen(host)); }
    else { char* c = strrchr(host, ':'); if(c && c == strchr(host, ':')) *c = 0; }   /* exactly one ':' = host:port; a bare IPv6 has several and no port */
}
void txr_report_violation_fd(int fd, const char* reason){
    for(int k = 0; k < mux_n_out; k++){
        if(mux_out_fd[k] != fd) continue;
        char host[128]; snprintf(host, sizeof host, "%s", mux_out_host[k]);
        host_strip_port(host);
        if(!host[0]) return;
        peer_misbehaving(host, 100, reason ? reason : "protocol violation");
        return;
    }
}

/* ---- 3.3 (UTXO_INLINE_CONNECT_SCOPE, 2026-09-06): who delivered a block ----
 * A block is connected long after it was stored, by a different code path;
 * when it fails to connect the worker needs to know which peer handed it
 * over to score the consensus violation (Core: Misbehaving(100) from
 * MaybePunishNodeForBlock, then disconnect). The leg sync knows (it logs
 * "[block] stored height=N ... (via host)"), so it notes the host here, in
 * a ring keyed by height. Blocks from the parallel downloader's chunk
 * workers (separate processes, many peers per pass) and from an inbound
 * child's .do_block are NOT noted: their source is logged as unknown. */
#define BLK_SRC_RING 4096
static struct { long h; char host[64]; } g_blk_src[BLK_SRC_RING];
static void blk_src_note(long h, const char* host){
    if(h < 0 || !host) return;
    g_blk_src[h % BLK_SRC_RING].h = h;
    snprintf(g_blk_src[h % BLK_SRC_RING].host, sizeof g_blk_src[0].host, "%s", host);
}
static const char* blk_src_lookup(long h){
    if(h < 0) return NULL;
    return g_blk_src[h % BLK_SRC_RING].h == h && g_blk_src[h % BLK_SRC_RING].host[0] ? g_blk_src[h % BLK_SRC_RING].host : NULL;
}
/* The reject hook utxo_live_catchup calls for a block that FAILED VALIDATION
 * (never for a store error -- see utxo_live.c's classification): the same
 * invalidate path the operator's invalidateblock takes (chain_invalidate_block:
 * invalid.dat mark, archive truncated to h-1 through the reorg module's
 * disconnect, headers.dat rolled back to h), then the delivering peer, when
 * known, is scored 100 for a consensus violation. The worker's next rotation
 * fetches headers from its peers and takes the heavier chain that avoids the
 * mark: the chain moves on, no restart, no operator. */
static void dlc_stop_workers_for_reject(long h);   /* defined with dl_catchup below */
static long dl_reject_block(void* st, long h, const unsigned char hash[32], const char* reason){
    extern long chain_invalidate_block(void*, long, const unsigned char[32]);
    /* Step 1 (the interleaved connect, UTXO_INLINE_BUILD_PERF_SCOPE): when
     * the parallel downloader's helpers are running, they are stopped FIRST.
     * chain_invalidate_block truncates the archive to h-1 and rolls
     * headers.dat back to h; helpers still writing would re-create the
     * rejected chain above h in the truncated archive (every remaining chunk
     * of theirs comes from the header chain that includes h), and the next
     * connect pass would reject h again -- which the burst guard then refuses
     * to invalidate. Stopping them is also what lets the chain move on:
     * dl_catchup returns, the rotation's legs fetch headers and take the
     * heavier chain that avoids the mark, and the far-behind trigger runs the
     * parallel download again on THAT chain. A no-op when no helper is
     * running (the rotation's own drain, the boot-time parent). */
    dlc_stop_workers_for_reject(h);
    long r = chain_invalidate_block(st, h, hash);
    if(r != 1) return r;
    const char* src = blk_src_lookup(h);
    char why[160]; snprintf(why, sizeof why, "block %ld failed to connect: %s", h, reason && reason[0] ? reason : "consensus reject");
    if(src){
        char host[128]; snprintf(host, sizeof host, "%s", src); host_strip_port(host);
        fprintf(stderr,"[chain] rejected block %ld was delivered by %s -- scoring a consensus violation\n", h, src);
        if(host[0]) peer_misbehaving(host, 100, why);
    } else {
        fprintf(stderr,"[chain] rejected block %ld: delivering peer unknown (parallel downloader or inbound push) -- no peer scored\n", h);
    }
    return 1;
}

/* ---- the ban list survives a restart (2026-09-06) -------------------------
 * Core writes <datadir>/banlist.json whenever the list changes and at
 * shutdown, and loads it at startup (banman.cpp). This node banned only in
 * memory, so every restart forgave every ban -- a peer banned for a consensus
 * violation returned the moment the node did. The register carried it as
 * PARTIAL: "scored ... not persisted across restart".
 *
 * Called after every mutation of g_node_status->bans[]; cheap (64 entries)
 * and rare (a ban, an unban, a clear). */
static void banlist_persist(void)
{
    if (!g_node_status) return;
    static ban_entry_t snap[RPC_MAX_BANS];
    int n = 0;
    for (int i = 0; i < RPC_MAX_BANS; i++){
        if (!g_node_status->bans[i].until) continue;
        snprintf(snap[n].subnet, sizeof snap[n].subnet, "%s", (const char*)g_node_status->bans[i].subnet);
        snap[n].until   = g_node_status->bans[i].until;
        snap[n].created = g_node_status->bans[i].created;
        n++;
    }
    if (banlist_save(snap, n) != 0)
        fprintf(stderr, "[ban] WARNING: could not write banlist.json -- bans will not survive a restart\n");
}
/* the loader's sink: same table, same rules, no RPC round trip */
int ctl_ban_add(const char* subnet, long long until);   /* defined just below */
static int banlist_restore_one(const char* subnet, long long until, long long created)
{
    if (!ctl_ban_add(subnet, until)) return 0;
    for (int i = 0; i < RPC_MAX_BANS; i++)
        if (g_node_status->bans[i].until == until &&
            !strcmp((const char*)g_node_status->bans[i].subnet, subnet)){
            if (created > 0) g_node_status->bans[i].created = created;   /* keep Core's ban_created */
            break;
        }
    return 1;
}
/* Add `subnet` to the shared ban list until `until`. 1 if newly banned. */
int ctl_ban_add(const char* subnet, long long until){
    if(!g_node_status || !subnet || !*subnet) return 0;
    /* NET-17 (audit 2026-09-03): refuse a key enforcement can never match.
     *
     * An onion or I2P inbound sets g_cur_peer_ip from the peer DESCRIPTOR --
     * "onion-inbound", or a base32 address -- and a protocol violation then
     * called this with that string. subnet_parse rejects it wherever bans are
     * ENFORCED, so the entry could never ban anything; but it occupied one of
     * RPC_MAX_BANS slots, and once the list is full this function returns 0
     * silently ("list full: no silent evict" below). Onion violations could
     * therefore crowd out REAL IP bans -- the list filling with entries that
     * do nothing, while the ones that would have worked are refused.
     *
     * Gated on the same parser enforcement uses, so the two cannot disagree
     * about what is bannable. */
    { subnet_t probe;
      if(!subnet_parse(subnet, &probe)){
          fprintf(stderr, "[ban] not an IP or subnet, so nothing could enforce it: %s "
                          "(onion/I2P peers are dropped on violation, not banned)\n", subnet);
          return 0;
      } }
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
    banlist_persist(); return 1;
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
    { const char* src = hostport ? hostport : ""; size_t l = strnlen(src, cap - 1); memcpy(out, src, l); out[l] = 0; }
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
#define TXOQ_MAGIC_MARK 0x4b52414du   /* CC-10: same framing, a different magic: vout = op, txid = block hash */
static void dlc_headers_rollback(unsigned char* hst, long have);   /* defined with the boot header fetch below */
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
/* CC-10: RPC side of invalidateblock (op 1) / reconsiderblock (op 2). */
static long txoq_block_mark(const unsigned char hash_wire[32], int op, long* height, char* err, unsigned long errcap){
    if(g_txoq_parent < 0){ snprintf(err, errcap, "no download worker channel"); return -1; }
    pthread_mutex_lock(&g_txoq_lock);
    txoq_req q; q.magic = TXOQ_MAGIC_MARK; q.vout = (unsigned int)op; memcpy(q.txid, hash_wire, 32);
    long r = -1;
    if(send(g_txoq_parent, &q, sizeof q, MSG_NOSIGNAL) == (ssize_t)sizeof q){
        txoq_resp rp;
        for(int guard = 0; guard < 8; guard++){
            if(!txoq_read_all(g_txoq_parent, &rp, sizeof rp, 30000)){ snprintf(err, errcap, "worker did not answer in 30 s"); break; }
            if(rp.magic == TXOQ_MAGIC_MARK && !memcmp(rp.txid, hash_wire, 32)){ r = rp.found; *height = (long)rp.height; if(r < 0) snprintf(err, errcap, "the worker could not disconnect the block; see its log"); break; }
            if(rp.spklen){ unsigned char skip[4096]; unsigned long left = rp.spklen; while(left){ unsigned long n = left > sizeof skip ? sizeof skip : left; if(!txoq_read_all(g_txoq_parent, skip, n, 1000)) break; left -= n; } }   /* a stale gettxout reply: drain */
        }
    } else snprintf(err, errcap, "worker channel write failed");
    pthread_mutex_unlock(&g_txoq_lock);
    return r;
}
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
/* CC-10: the worker side of invalidateblock / reconsiderblock. The block is
 * located by scanning headers.dat from the top (an operator command; a tenth
 * of a second at 965k headers); if it is at or below the store's tip the
 * chain is DISCONNECTED down to its parent through the reorg module's own
 * unapply path, then headers.dat is rolled back so the header fetch does
 * not re-offer the branch; the hash goes into invalid.dat, which the fetch
 * and the reorg analyzer consult from then on. reconsiderblock removes the
 * mark; the next header fetch takes the branch again. */
static long txoq_mark_block(void* store_buf, const unsigned char hash[32], int op, long* out_h){
    *out_h = -1;
    if(op == 2){ int r = invset_remove(hash); invset_save("invalid.dat"); fprintf(stderr, "[chain] reconsiderblock: %s\n", r ? "mark removed" : "not marked"); return 1; }
    static unsigned char hb[4096]; hst_init(hb);
    long n = hst_count(hb), h = -1; unsigned char rec[112];
    for(long k = n - 1; k >= 0; k--){ if(hst_get_at(hb, (unsigned long long)k, rec) != 1) break; if(!memcmp(rec + 80, hash, 32)){ h = k; break; } }
    if(h < 0) return 0;
    /* 3.3: the mark + disconnect + headers rollback is chain_invalidate_block
     * (daemon/reorg.c) -- the same path the node takes on its own when a
     * block fails to connect, so invalidateblock is that path invoked by the
     * operator rather than a second implementation of it. */
    extern long chain_invalidate_block(void*, long, const unsigned char[32]);
    long r = chain_invalidate_block(store_buf, h, hash);
    if(r != 1) return -1;
    fprintf(stderr, "[chain] invalidateblock: marked height %ld; headers rolled back to %ld; the chain stays below it until a heavier chain avoids it\n", h, h);
    *out_h = h; return 1;
}
static void* g_txoq_store = NULL;                 /* CC-10: set by the worker before its rotation */
static void txoq_service(void);
/* The catch-up loop's between-block hook: publish the connected tip (3.1) so
 * the parent's RPCs and the serve children follow a long catch-up call block
 * by block, then answer pending gettxout queries (a no-op without the IPC). */
static void dl_apply_hook(void){ dl_publish_connected_tip(); txoq_service(); }
static void txoq_service(void){
    if(g_txoq_worker < 0) return;
    for(int guard = 0; guard < 64; guard++){
        struct pollfd pf = { g_txoq_worker, POLLIN, 0 };
        if(poll(&pf, 1, 0) <= 0) return;               /* nothing pending */
        txoq_req q;
        if(!txoq_read_all(g_txoq_worker, &q, sizeof q, 50)) return;
        if(q.magic == TXOQ_MAGIC_MARK){                /* CC-10: invalidateblock / reconsiderblock */
            txoq_resp mr; memset(&mr, 0, sizeof mr); mr.magic = TXOQ_MAGIC_MARK; memcpy(mr.txid, q.txid, 32); mr.vout = q.vout;
            long hh = -1; long r = txoq_mark_block(g_txoq_store, q.txid, (int)q.vout, &hh);
            mr.found = (int)r; mr.height = hh < 0 ? 0 : (unsigned long)hh;
            if(send(g_txoq_worker, &mr, sizeof mr, MSG_NOSIGNAL) != (ssize_t)sizeof mr) return;
            continue;
        }
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
static volatile sig_atomic_t mux_sync_budget_sig = 0;   /* WHICH signal: SIGALRM (stall) or SIGUSR1 (parent early-kill) */
static void mux_budget_alarm(int sig){
    mux_sync_budget_sig = sig;
    mux_sync_budget_fired = 1;
    int fd = mux_budget_fd;
    if (fd >= 0) shutdown(fd, SHUT_RDWR);
}
/* 2026-09-09: the pass budget for a leg. Recycling the ONLY path to the
 * network every 60 s was a starvation loop (bmcmonitor: connections median
 * 1, sub-minute flicker); a sole leg gets four times the budget before it is
 * replaced. The alarm still ends the pass either way (a trickling peer resets
 * SO_RCVTIMEO on every partial read and the pass would never return). */
#define DL_BUDGET_ONLY_LEG_MULT 4
static unsigned leg_budget_secs(int live_legs){ return (unsigned)(live_legs <= 1 ? DL_BUDGET_SECS * DL_BUDGET_ONLY_LEG_MULT : DL_BUDGET_SECS); }

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
    /* 2026-09-09: tcp_connect_ip's connect() is BLOCKING under a 10 s
     * SO_SNDTIMEO; when that expires the kernel reports EINPROGRESS, and
     * "Operation now in progress" was read as an attempt abandoned in flight
     * (1,575 lines in a day). It is a connect that timed out: say so. */
    if(e == EINPROGRESS || e == ETIMEDOUT){ snprintf(g_dial_fail, sizeof g_dial_fail, "%s timed out (10s)", what); return; }
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

static int outbound_connect_raw(const char* host, int rcv_ms, int out_port){
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
              struct timeval tv; tv.tv_sec = (time_t)peer_handshake_secs(g_cfg.peer_timeout_s); tv.tv_usec = 0;   /* CC-7: -peertimeout bounds the handshake (60 s default; onion/i2p round trips are slow) */
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
        if(nfd < 0){ snprintf(g_dial_fail,sizeof g_dial_fail,"cannot dial the name \"%.30s\": %.40s", host, why); return -1; }
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
        } else { dial_gate_wait(); fd = tcp_connect_ip(ip,(unsigned short)htons((unsigned short)out_port)); }
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
    if(fd>=0){ version_tell_the_truth(); hk = node_handshake(fd); }

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
    leg_settle_socket(fd);
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
    /* 2026-09-09: this used to re-apply the dial's 300 ms read bound AFTER the
     * handshake ("so each node_sync pass returns promptly at the tip"), which
     * undid leg_settle_socket above and gave the drains 2.4 s where their tick
     * counts were written for 24 s / 60 s -- production on snapshot k still
     * showed "where=3 in 2.4s". A peer at the tip answers getheaders at once,
     * so the tick only matters for a silent peer, and a silent peer now costs
     * 24 s a pass and three passes, then the dial memory holds it off. Core
     * waits minutes for headers. The socket stays at LEG_READ_TICK_S. */
    (void)rcv_ms;
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
/* CC-4: the hosts we hold (or intend) as block-relay-only legs. Core keeps 2
 * such connections: fRelay=0 in our version, no transaction announcements,
 * addr gossip ignored -- an attacker who owns every full-relay peer still
 * cannot hide a block from us. On shutdown they are written to anchors.dat
 * (Core's format) and dialled first on the next start. */
static char g_bo_hosts[MAX_BLOCK_RELAY_ONLY][128];
static int  g_bo_n = 0;
static int host_is_block_only(const char* host){
    for(int i = 0; i < g_bo_n; i++) if(!strcmp(g_bo_hosts[i], host)) return 1;
    return 0;
}
static int bo_want(void){ return g_cfg.max_block_relay_only < MAX_BLOCK_RELAY_ONLY ? g_cfg.max_block_relay_only : MAX_BLOCK_RELAY_ONLY; }
static void bo_add(const char* host){ if(g_bo_n < MAX_BLOCK_RELAY_ONLY && !host_is_block_only(host)) snprintf(g_bo_hosts[g_bo_n++], sizeof g_bo_hosts[0], "%s", host); }
static int legs_block_only(void){ int n = 0; for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0 && mux_out_kind[k] == LEG_BLOCK_ONLY) n++; return n; }
/* every outbound dial funnels through here: a block-only host gets fRelay=0
 * in the version we send (the byte is per-connection already; see feelers) */
static int outbound_connect(const char* host, int rcv_ms, int out_port){
    unsigned char saved = node_relay_flag;
    if(host_is_block_only(host)) node_relay_flag = 0;
    int fd = outbound_connect_raw(host, rcv_ms, out_port);
    node_relay_flag = saved;
    return fd;
}
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
/* RPC-13: `already_claimed` says the caller has ALREADY won this slot with a
 * CAS on `used` (the inbound path). The two callers genuinely want different
 * behaviour here, which is why this is a parameter and not a blanket change:
 *
 *   inbound  -- the slot was claimed 0 -> 1 before the fill. Zeroing `used`
 *               mid-fill advertises it as free again, so a sibling child can
 *               claim the same slot; the loser's later `used = 0` then frees
 *               the WINNER's entry. Keeping the claim closes that window, at
 *               the cost of a reader briefly seeing a partly-filled record --
 *               display-only, where the race corrupts ownership.
 *   outbound -- the slot at mux_n_out is not claimed by CAS at all; the fill
 *               IS the claim. Zeroing `used` first is what keeps a reader
 *               from seeing a half-filled record, and must stay.
 *
 * Either way `pr->used = 1` at the end remains the publication point. */
static void rpc_fill_peer_slot(int slot, const char* host){
    /* NET-10: an OUTBOUND leg we established is a peer we have actually
     * connected to -- Core's `tried`. Marking it here is what makes rule 2
     * mean anything on a node with no legacy book to migrate: without it
     * nothing would ever be tried, and eviction would have nothing to
     * protect. Every caller of THIS wrapper is an outbound fill (the
     * background dial, the initial pool fill, and the top-up).
     *
     * Deliberately NOT in rpc_fill_peer_slot_ex: the inbound path claims its
     * slot through _ex directly, and marking an inbound peer tried would let
     * anyone who dials US immunise their own address against eviction --
     * exactly the capability NET-10 exists to remove. */
    { ab2_t* b = addr_book();
      if(b){
          bmc_addr_t a;
          if(bmc_addr_from_string_port(&a, host, 0) && bmc_addr_is_routable(&a))
              ab2_mark_tried(b, &a);
      } }
    rpc_fill_peer_slot_ex(slot, host, 0);
}
/* parse the captured `version` message into a peer record's proto, services,
 * subver and start_height -- shared by the legs and, since 2026-09-08, the
 * download workers (getpeerinfo) */
static void rpc_peer_from_version(rpc_peer_t* pr, const unsigned char* p, long len){
    if (len < 80) return;
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
static void rpc_fill_peer_slot_ex(int slot, const char* host, int already_claimed){
    if (!g_node_status || slot < 0 || slot >= RPC_MAX_PEERS) return;
    rpc_peer_t* pr = &g_node_status->peers[slot];
    int keep_used = already_claimed ? pr->used : 0;   /* RPC-13: `used` is a volatile int */
    memset(pr, 0, sizeof *pr);
    pr->used = keep_used;
    strncpy(pr->addr, host ? host : "", sizeof pr->addr - 1);
    pr->inbound = 0;
    pr->conn_time = (long long)time(NULL);
    long len = g_peer_version_len;
    const unsigned char* p = g_peer_version_payload;
    pr->dl_worker = -1; pr->inflight_lo = 1; pr->inflight_hi = 0;
    rpc_peer_from_version(pr, p, len);
    { extern int rp_version_frelay(const unsigned char*, long);
      pr->relaytxes = rp_version_frelay(p, len) != 0; }   /* Core relaytxes: the peer's fRelay */
    /* RPC-3: a fresh, never-reused id for this connection. Assigned before
     * `used` so a reader that sees the slot live always sees a real id. */
    pr->nodeid = __sync_fetch_and_add(&g_node_status->next_nodeid, 1);
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

/* ---- Core's shape at the tip (2026-09-10) ----------------------------------
 * Measured on production against the Core oracle on the same box: our tip
 * moved 5-20 s after Core's. Three costs, each a divergence: a block was
 * learned of only when its leg's rotation turn sent getheaders (the sweep
 * discarded the peer's inv); every block cost a round trip before the
 * reconstruction could start (low-bandwidth compact blocks only); and a
 * stored block waited for the rest of the rotation before the apply ran.
 * Now: the sweep's hooks (tx_relay.c) mark a leg ANNOUNCED on a block inv or
 * a pushed header for a block we do not have, and the rotation runs that
 * leg's pass next; the three legs that most recently delivered a block get
 * sendcmpct high-bandwidth (Core's MaybeSetPeerAsAnnouncingHeaderAndIDs) and
 * their pushed cmpctblock is reconstructed and stored from the sweep, on
 * our tip, through the same evaluator submitblock uses; and a store breaks
 * the rotation so the apply runs at once. */
static int g_stored_now = 0;                            /* a pushed block was stored during this rotation's sweeps */
/* row 5's measurement, one line per block that went through the compact
 * receiver: what the mempool supplied and where the rest had gone */
extern void cmpct_recv_last_block(unsigned long*, unsigned long*, unsigned long*, unsigned long*, unsigned long*, unsigned long cls[5]);
static void cmpct_overlap_line(long height, const char* host){
    unsigned long ntx, pool, pre, miss, mb, cls[5]; cmpct_recv_last_block(&ntx, &pool, &pre, &miss, &mb, cls);
    if(!ntx) return;
    fprintf(stderr,"[cmpct] block %ld (%s): %lu tx: %lu from the mempool (%.1f%%), %lu prefilled, %lu fetched by getblocktxn (%lu KB): %lu never announced, %lu announced not requested, %lu requested no reply, %lu orphans, %lu rejected by policy\n",
            height, host, ntx, pool, ntx ? 100.0 * (double)pool / (double)ntx : 0.0, pre, miss, mb / 1024,
            cls[0], cls[1], cls[2], cls[3], cls[4]);
}
static long g_announce_inv_n, g_announce_hdr_n, g_push_n, g_push_stored_n, g_push_skipped_n;
static int leg_of_fd(int fd){ for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0 && mux_out_fd[k] == fd) return k; return -1; }
static unsigned char mux_out_announced_hash[MUX_MAX_OUT][32];
static void leg_on_block_announce(int fd, const unsigned char hash[32], const char* how){
    int k = leg_of_fd(fd); if(k < 0) return;
    long h; if(ht_idx && idx_get(ht_idx, hash, &h)) return;         /* already stored */
    if(mux_out_announced[k] && !memcmp(mux_out_announced_hash[k], hash, 32)) return;   /* the same block, again */
    mux_out_announced[k] = 1; memcpy(mux_out_announced_hash[k], hash, 32);
    fprintf(stderr,"[tip] %s announced block %02x%02x%02x%02x.. by %s: its pass runs next\n", mux_out_host[k], hash[31], hash[30], hash[29], hash[28], how);
}
static void leg_on_block_inv(int fd, const unsigned char hash[32]){ g_announce_inv_n++; leg_on_block_announce(fd, hash, "inv"); }
static void leg_on_headers(int fd, const unsigned char* hdrs, unsigned long n){
    unsigned char bh[32]; sha256d(bh, hdrs + (n - 1) * 81, 80); g_announce_hdr_n++;
    leg_on_block_announce(fd, bh, "headers");
}
/* the rotation asks: is a leg other than `except` announced? (clears the mark) */
static int leg_announced_pick(int except){
    for(int a = 0; a < mux_n_out; a++) if(a != except && mux_out_announced[a]){ mux_out_announced[a] = 0; if(mux_out_fd[a] >= 0) return a; }
    return -1;
}
#define LEG_HB_MAX 3
static void leg_send_sendcmpct(int k, int hb){
    unsigned char pl[9] = {0}; pl[0] = (unsigned char)hb; pl[1] = 2;    /* high_bandwidth, version 2 (u64 LE) */
    if(mux_out_fd[k] >= 0) p2p_write(mux_out_fd[k], "sendcmpct", 9, pl, 9);
    mux_out_hb[k] = (unsigned char)hb; mux_out_hb_since[k] = hb ? dh_now_ms() : 0;
}
/* Core: the peer that just gave us a block joins the high-bandwidth set; the
 * set holds three, and the one that delivered longest ago goes back to low */
static void leg_hb_note_block(int k){
    if(!g_cmpct_hook_cmpct || k < 0 || mux_out_fd[k] < 0) return;
    if(mux_out_hb[k]){ mux_out_hb_since[k] = dh_now_ms(); return; }
    int n = 0, oldest = -1;
    for(int j = 0; j < mux_n_out; j++) if(mux_out_fd[j] >= 0 && mux_out_hb[j]){ n++; if(oldest < 0 || mux_out_hb_since[j] < mux_out_hb_since[oldest]) oldest = j; }
    if(n >= LEG_HB_MAX && oldest >= 0){
        leg_send_sendcmpct(oldest, 0);
        fprintf(stderr,"[cmpct] %s back to low-bandwidth compact blocks (the high-bandwidth set holds %d)\n", mux_out_host[oldest], LEG_HB_MAX);
    }
    leg_send_sendcmpct(k, 1);
    fprintf(stderr,"[cmpct] %s delivered a block: high-bandwidth compact blocks from this leg from now on (Core: the last %d block sources)\n", mux_out_host[k], LEG_HB_MAX);
}
extern long blk_submit_evaluate_ex(const unsigned char*, unsigned long, const unsigned char*, long, int, char*, unsigned long);
extern long cmpct_recv_cmpctblock(int fd, void* mp, const unsigned char* pl, unsigned long plen, unsigned char* out, unsigned long cap, const unsigned char want[32]);
extern long cmpct_recv_blocktxn(int fd, const unsigned char* pl, unsigned long plen, unsigned char* out, unsigned long cap);
static unsigned char g_push_blk[4u << 20];
static unsigned char g_push_hash[32]; static int g_push_pending = 0, g_push_leg = -1;
/* a block that arrived through the sweep: on our tip, PoW and consensus
 * through the evaluator submitblock uses (the same cons_verify the pass runs),
 * then the locked append; the apply follows at once (the rotation breaks) */
static long dl_store_pushed_block(int k, const unsigned char* blk, unsigned long len, const unsigned char bh[32], const char* how){
    unsigned char tiph[32]; long tip = *(int*)(store_buf + 24);
    if(store_get_tip_hash(store_buf, tiph) != 1 || memcmp(blk + 4, tiph, 32) != 0){ g_push_skipped_n++; leg_on_block_announce(mux_out_fd[k], bh, "a push off our tip"); return 0; }   /* not on our tip: the pass sorts it out */
    char reason[64]; reason[0] = 0;
    if(blk_submit_evaluate_ex(blk, len, tiph, tip, 1, reason, sizeof reason) != 1){
        fprintf(stderr,"[cmpct] %s from %s refused: %s -- the leg's pass fetches it in full\n", how, mux_out_host[k], reason);
        leg_on_block_announce(mux_out_fd[k], bh, "a refused push"); return -1;
    }
    long r = idxscan_append_locked(store_buf, bh, blk, (long)len);
    if(r == -2){ g_push_skipped_n++; return 0; }                        /* the tip moved under us: a sibling stored it first */
    if(r < 0){ fprintf(stderr,"[cmpct] %s from %s: locked append FAILED\n", how, mux_out_host[k]); return -1; }
    g_push_stored_n++; g_stored_now = 1;
    { char hs[17]; for(int j = 0; j < 8; j++) sprintf(hs + 2*j, "%02x", bh[31 - j]);
      fprintf(stderr,"[block] stored height=%ld hash=%s.. bytes=%lu (%s from %s)\n", tip + 1, hs, len, how, mux_out_host[k]); }
    if(how[0] == 'p' && how[7] == 'c') cmpct_overlap_line(tip + 1, mux_out_host[k]);   /* "pushed compact block..." */
    leg_hb_note_block(k);
    return 1;
}
static long leg_on_cmpctblock(int fd, const unsigned char* pl, unsigned long plen){
    int k = leg_of_fd(fd); if(k < 0 || plen < 88) return -1;
    unsigned char bh[32]; sha256d(bh, pl, 80); g_push_n++;
    long h; if(ht_idx && idx_get(ht_idx, bh, &h)){ g_push_skipped_n++; return 0; }
    unsigned char tiph[32];
    if(store_get_tip_hash(store_buf, tiph) != 1 || memcmp(pl + 4, tiph, 32) != 0){ leg_on_block_announce(fd, bh, "a compact block off our tip"); return 0; }   /* behind, or a fork: the pass sorts it out */
    if(!inflight_claim(&g_inflight, bh, k, (long long)time(NULL))) return 0;   /* another leg is fetching it */
    if(g_push_pending){ inflight_release_leg(&g_inflight, g_push_leg); g_push_pending = 0; }   /* an older push never completed */
    long n = cmpct_recv_cmpctblock(fd, txsub_worker_ready() ? txsub_pool() : NULL, pl, plen, g_push_blk, sizeof g_push_blk, bh);
    if(n > 0){ long r = dl_store_pushed_block(k, g_push_blk, (unsigned long)n, bh, "pushed compact block"); inflight_release_leg(&g_inflight, k); return r; }
    if(n == 0){ g_push_pending = 1; g_push_leg = k; memcpy(g_push_hash, bh, 32); return 0; }   /* getblocktxn (or a full-block getdata) is out; the reply comes through the sweep */
    inflight_release_leg(&g_inflight, k); return -1;
}
static long leg_on_blocktxn(int fd, const unsigned char* pl, unsigned long plen){
    int k = leg_of_fd(fd); if(k < 0 || !g_push_pending || k != g_push_leg) return -1;
    long n = cmpct_recv_blocktxn(fd, pl, plen, g_push_blk, sizeof g_push_blk);
    if(n > 0){ g_push_pending = 0; long r = dl_store_pushed_block(k, g_push_blk, (unsigned long)n, g_push_hash, "pushed compact block + blocktxn"); inflight_release_leg(&g_inflight, k); return r; }
    if(n == 0) return 0;                                                /* the receiver fell back to a full-block getdata: the `block` comes through the sweep */
    g_push_pending = 0; inflight_release_leg(&g_inflight, k); return -1;
}
static long leg_on_block(int fd, const unsigned char* pl, unsigned long plen){
    int k = leg_of_fd(fd); if(k < 0 || plen < 81) return -1;
    unsigned char bh[32]; sha256d(bh, pl, 80);
    if(g_push_pending && !memcmp(bh, g_push_hash, 32)){ g_push_pending = 0; }
    long h; if(ht_idx && idx_get(ht_idx, bh, &h)){ inflight_release_leg(&g_inflight, k); g_push_skipped_n++; return 0; }
    long r = dl_store_pushed_block(k, pl, plen, bh, "pushed full block");
    inflight_release_leg(&g_inflight, k);
    return r;
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
    /* CC-2: this leg's compact-block state rides in two asm globals around the
     * call -- whether the peer sent sendcmpct (the drains set it) and the pool
     * the reconstruction draws on. Read back after: the peer may have sent
     * sendcmpct during this very sync. */
    g_peer_sendcmpct = mux_out_cmpct[i]; g_sync_mp = txsub_worker_ready() ? txsub_pool() : NULL;
    g_sync_leg = i;
    long ok=node_sync_multi(mux_out_fd[i], store_buf, loc, nloc, cbuf, (long)sizeof cbuf, &cnt);
    inflight_release_leg(&g_inflight, i); g_sync_leg = -1;   /* the claims live with the pass */
    if(g_peer_sendcmpct && !mux_out_cmpct[i]){ mux_out_cmpct[i] = 1; fprintf(stderr, "[cmpct] %s accepts compact blocks: requesting MSG_CMPCT_BLOCK on this leg from now on\n", mux_out_host[i]); }
    { static unsigned long p_r, p_n, p_f; unsigned long r, n, f; cmpct_recv_stats(&r, &n, &f);
      if(r != p_r || n != p_n || f != p_f){ fprintf(stderr, "[cmpct] reconstructed %lu block(s) from the mempool (%lu needed a getblocktxn round trip, %lu fell back to a full block)\n", r, n, f); p_r = r; p_n = n; p_f = f;
                                              cmpct_overlap_line((long)*(int*)(store_buf+24), mux_out_host[i]); } }
    double sync_s = phase_elapsed(&sync_pt);
    int st_tip=*(int*)(store_buf+24);
    /* 2026-09-09: blocks this leg stored off the best header chain came from a
     * peer on a lighter branch; retain them, rewind, and let the reorg probe
     * and the parallel downloader follow the best chain instead */
    if(ok == 1 && cnt > 0 && st_tip > st_tip_before && g_reorg_ok && g_utxo_live_on){
        extern long reorg_gate_best_header(void*, long);
        long back = reorg_gate_best_header(store_buf, st_tip_before);
        if(back >= 0){
            fprintf(stderr,"[dl] leg %s extended onto a branch lighter than the best header chain -- rewound to %ld; not taking its blocks\n", mux_out_host[i], back);
            store_reload(store_buf); st_tip = *(int*)(store_buf+24); anchor_locator(mux_out_loc[i]);
            dl_after_gate_rewind(back);
            return 0;
        }
    }
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
        if(sync_fail_code == 4 && sync_s < 0.5){   /* EOF before the peer said anything: it hung up */
            leg_close_theirs(i, "EOF on the first read", "(nothing)");
            g_sync_fail_streak[i] = 0;
            return 0;
        }
        g_sync_fail_streak[i]++;
        if(g_sync_fail_streak[i] >= 3){
            char d[96]; snprintf(d, sizeof d, "3 failing sync passes, last where=%d in %.1fs", sync_fail_code, sync_s);
            leg_close_ours(i, "sync-failed-3x", d);
            /* 2026-09-09 (LAN capture, 19:00-19:14Z): the legs we retire this
             * way are a handful of cloud-hosted listeners that complete the
             * handshake and never answer a getheaders -- one was dialled seven
             * times in fifteen minutes because this close alone was not fed to
             * the dial memory. A peer that served nothing three times is
             * remembered like an early drop: 10 min, doubling to 6 h. */
            if(g_dialmem) dialmem_note_failure(g_dialmem, mux_out_host[i], DM_EARLY_DROP, dialmem_now());
            g_sync_fail_streak[i] = 0;
            mux_out_nextretry[i] = 0;   /* re-dial on the next rotation, not after the dead-slot backoff */
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
        blk_src_note(h, mux_out_host[i]);   /* 3.3: remembered for the reject hook */
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
    /* 3.1: NOT announced here. The block is stored, not connected; the
     * announcement (inv to every outbound leg) fires from the worker's
     * new-block choke point once utxo_live_catchup has connected it -- the
     * same rotation in steady state, never ahead of validation. */
    fprintf(stderr,"[mux:%d] stored tip height=%d from %s (announced on connect)\n", i, st_tip, mux_out_host[i]);
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
/* 2026-09-10: every outbound dial runs in a helper now -- the clearnet
 * re-dial and the top-up used outbound_connect inline, and a candidate that
 * black-holes costs the 10 s connect timeout, four of them 40 s, during
 * which the worker reads no leg: the first block on snapshot t was stored
 * 27 s after the oracle because the loop sat in a top-up. Core's message
 * loop never blocks on a connect. want_slot: the leg slot a re-dial fills
 * when it lands (-1: append, the top-up's case). */
#define DH_MAX 4
typedef struct { int sp; pid_t pid; char host[128]; int net; long long t0; int want_slot; } dh_slot_t;
static dh_slot_t g_dh[DH_MAX];
static long long g_dh_timeout_ms = 120000;
/* g_in_dial_helper is declared with the leg tables above */
/* NET-13: vpayload MUST match g_peer_version_payload -- a smaller field here
 * silently truncates the capture across the dial-helper socketpair. */
typedef struct { int ok; unsigned char wants_addrv2; long vlen; unsigned char vpayload[512]; char why[128]; } dh_result_t;
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
        if(g_dialmem && !dialmem_allowed(g_dialmem, srcpool[ci], dialmem_now())) continue;   /* 2026-09-09: under backoff */
        g_dh_cursor[an] = (ci + 1) % nsrc;
        return ci;
    }
    return -1;
}
static int dh_inflight_for(int want_slot){ for(int i = 0; i < DH_MAX; i++) if(g_dh[i].pid > 0 && g_dh[i].want_slot == want_slot) return 1; return 0; }
static int g_dh_last_slot = -1;   /* the want_slot of the result dh_poll just returned */
static int dh_start_slot(const char* host, int out_port, int want_slot);
static int dh_start(const char* host, int out_port){ return dh_start_slot(host, out_port, -1); }
static int dh_start_slot(const char* host, int out_port, int want_slot){
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
    g_dh[slot].sp = sp[0]; g_dh[slot].pid = pid; g_dh[slot].net = leg_net_of(host); g_dh[slot].t0 = dh_now_ms(); g_dh[slot].want_slot = want_slot;
    snprintf(g_dh[slot].host, sizeof g_dh[slot].host, "%s", host);
    if(want_slot >= 0) fprintf(stderr, "[dial] %s: dialing in the background for leg %d (%s)\n", host, want_slot, bmc_net_name(g_dh[slot].net));
    else fprintf(stderr, "[dial] %s: dialing in the background (%s)\n", host, bmc_net_name(g_dh[slot].net));
    return 1;
}
/* ---- -privatebroadcast (Core v30): the worker's side -----------------------
 * The queue and the wire exchange are daemon/private_broadcast.c. Here: which
 * network and which address, one forked helper child per connection (the same
 * shape as the background dials above -- the child dials, runs the whole
 * inv/getdata/tx/ping/pong conversation and reports over a socketpair, so
 * the rotation loop never blocks on Tor), the reattempt clock, the "received
 * back from the network" check, the RPC snapshot and the abort op. */
static unsigned long long dl_pool_rng(void);
static void* txsub_pool(void);
static int   txsub_worker_ready(void);
extern const unsigned char* mpool_get(void* mp, const unsigned char txid[32], unsigned long* out_len);
typedef struct { int rc; char why[128]; } pbh_result_t;
typedef struct { pid_t pid; int sp; int tx_index; int peer_slot; long long t0; char host[128]; } pbh_slot_t;   /* 128: a "host:port" as mux_out_host holds it */
static pbh_slot_t g_pbh[PB_MAX_CONNECTIONS];
static long      g_pb_num_to_open = 0;          /* Core CConnman::PrivateBroadcast::m_num_to_open */
static long long g_pb_next_reattempt_s = 0;
static int       g_pb_dirty = 1;
static long      g_pb_sent = 0, g_pb_confirmed = 0, g_pb_received_back = 0, g_pb_given_up = 0;
static long long pb_wall_s(void){ return (long long)time(NULL); }
static int pbh_inflight(void){ int n = 0; for(int i = 0; i < PB_MAX_CONNECTIONS; i++) if(g_pbh[i].pid > 0) n++; return n; }
static int pb_reachable_now(void){ return dialer_net_reachable(BMC_NET_TORV3) || dialer_net_reachable(BMC_NET_I2P); }
/* a random routable address of `net` from the book, not a live leg, not banned */
static int pb_pick_addr(int net, bmc_addr_t* out){
    ab2_t* b = addr_book(); if(!b) return 0;
    long cnt = ab2_count(b), n = 0, chosen = -1;
    for(long i = 0; i < cnt; i++){
        ab2_rec_t r; if(!ab2_get(b, i, &r)) continue;
        if((int)r.a.net != net || !bmc_addr_is_routable(&r.a)) continue;
        n++;
        if((long)(dl_pool_rng() % (unsigned long long)n) == 0) chosen = i;   /* reservoir of one */
    }
    if(chosen < 0) return 0;
    ab2_rec_t r; if(!ab2_get(b, chosen, &r)) return 0;
    char hp[128]; if(!bmc_addr_to_string_port(hp, sizeof hp, &r.a)) return 0;
    for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0 && !strcmp(mux_out_host[k], hp)) return 0;
    { char ip[128]; ctl_ip_only(hp, ip, sizeof ip); if(ctl_is_banned(ip)) return 0; }
    *out = r.a; return 1;
}
static int pbh_start(int tx_index, int peer_slot, const bmc_addr_t* a, const char* hp){
    const pb_tx_t* t = pb_queue_at(tx_index); if(!t) return 0;
    int slot = -1; for(int i = 0; i < PB_MAX_CONNECTIONS; i++) if(g_pbh[i].pid <= 0){ slot = i; break; }
    if(slot < 0) return 0;
    int sp[2]; if(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return 0;
    pid_t pid = fork();
    if(pid < 0){ close(sp[0]); close(sp[1]); return 0; }
    if(pid == 0){
        close(sp[0]); g_in_dial_helper = 1;
        pbh_result_t r; memset(&r, 0, sizeof r);
        const char* why = "";
        int fd = dialer_connect_private(a, 60000, &why);
        if(fd < 0){ r.rc = -1; snprintf(r.why, sizeof r.why, "dial: %s", why); }
        else { r.rc = pb_exchange(fd, t->tx, t->len, t->txid, PB_CONN_LIFETIME_S, r.why, sizeof r.why); close(fd); }
        (void)!write(sp[1], &r, sizeof r);
        _exit(0);
    }
    close(sp[1]);
    g_pbh[slot].pid = pid; g_pbh[slot].sp = sp[0]; g_pbh[slot].tx_index = tx_index; g_pbh[slot].peer_slot = peer_slot; g_pbh[slot].t0 = pb_wall_s();
    snprintf(g_pbh[slot].host, sizeof g_pbh[slot].host, "%s", hp);
    fprintf(stderr, "[privbcast] connecting to %s (%s) to deliver one transaction\n", hp, bmc_net_name(a->net));
    return 1;
}
static void pbh_poll(void){
    for(int i = 0; i < PB_MAX_CONNECTIONS; i++){
        if(g_pbh[i].pid <= 0) continue;
        pbh_result_t r; memset(&r, 0, sizeof r);
        ssize_t n = recv(g_pbh[i].sp, &r, sizeof r, MSG_DONTWAIT);
        if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)){
            if(pb_wall_s() - g_pbh[i].t0 > PB_CONN_LIFETIME_S + 90){
                kill(g_pbh[i].pid, SIGKILL); r.rc = 0; snprintf(r.why, sizeof r.why, "helper gave up");
            } else continue;
        } else if(n != (ssize_t)sizeof r){ r.rc = 0; snprintf(r.why, sizeof r.why, "helper exited without a result"); }
        waitpid(g_pbh[i].pid, NULL, 0); close(g_pbh[i].sp); g_pbh[i].pid = 0; g_pbh[i].sp = -1;
        if(r.rc == 2){ pb_queue_mark_received(g_pbh[i].tx_index, g_pbh[i].peer_slot, pb_wall_s()); g_pb_sent++; g_pb_confirmed++;
            fprintf(stderr, "[privbcast] %s acknowledged the transaction (pong)\n", g_pbh[i].host); }
        else if(r.rc == 1){ g_pb_sent++; fprintf(stderr, "[privbcast] %s took the transaction but sent no pong (%s)\n", g_pbh[i].host, r.why[0] ? r.why : "timeout"); }
        else {
            /* Core: a private connection that closes without confirming asks for one more */
            pb_queue_unpick(g_pbh[i].tx_index, g_pbh[i].peer_slot);
            if(pb_queue_at(g_pbh[i].tx_index)) g_pb_num_to_open++;
            fprintf(stderr, "[privbcast] %s: %s -- will try another peer\n", g_pbh[i].host, r.why[0] ? r.why : "failed");
        }
        g_pb_dirty = 1;
    }
}
static void pb_publish(void){
    if(!g_node_status) return;
    pb_queue_snapshot((char*)g_node_status->pb_info, RPC_PB_INFO_CAP);
    __sync_synchronize(); g_node_status->pb_info_seq++;
    g_pb_dirty = 0;
}
/* one rotation of the driver: open what is owed, poll what is running,
 * notice what came back, reattempt what went stale, publish the snapshot */
static void pb_rotation(void){
    if(!g_cfg.privatebroadcast || !g_node_status) return;
    pbh_poll();
    /* received back from the network? our own submission never entered the
     * mempool, so a queued txid that is now in the pool arrived via a peer */
    if(txsub_worker_ready()){
        for(int i = 0; i < PB_MAX_TX; i++){
            const pb_tx_t* t = pb_queue_at(i); if(!t) continue;
            unsigned long l = 0;
            if(mpool_get(txsub_pool(), t->txid, &l)){
                long acks = pb_queue_remove(t->txid); g_pb_received_back++; g_pb_dirty = 1;
                if(acks >= 0 && acks < PB_NUM_PER_TX){ g_pb_num_to_open -= PB_NUM_PER_TX - acks; if(g_pb_num_to_open < 0) g_pb_num_to_open = 0; }
                fprintf(stderr, "[privbcast] received our privately broadcast transaction back from the network (%ld peer(s) had acknowledged it) -- stopping\n", acks);
            }
        }
    }
    if(!pb_queue_has_pending()) g_pb_num_to_open = 0;
    /* Core ReattemptPrivateBroadcast: every 2-3 min, stale entries are re-tested
     * against the mempool and re-broadcast, or dropped with the reason */
    long long now = pb_wall_s();
    if(g_pb_next_reattempt_s == 0) g_pb_next_reattempt_s = now + PB_REATTEMPT_MIN_S + (long long)(dl_pool_rng() % PB_REATTEMPT_JITTER_S);
    if(now >= g_pb_next_reattempt_s && txsub_worker_ready()){
        int st[PB_MAX_TX]; int ns = pb_queue_stale(now, st, PB_MAX_TX);
        for(int k = 0; k < ns; k++){
            const pb_tx_t* t = pb_queue_at(st[k]); if(!t) continue;
            extern long tx_accept_test_reason(void*, const unsigned char*, const unsigned char*, unsigned long, char*, unsigned long, unsigned long long*, unsigned long long*);
            char reason[128]; reason[0] = 0; unsigned long long fee = 0;
            long ok = tx_accept_test_reason(txsub_pool(), t->txid, t->tx, t->len, reason, sizeof reason, &fee, NULL);
            if(ok == 1){ g_pb_num_to_open++; fprintf(stderr, "[privbcast] reattempting broadcast of a stale transaction (%d peer(s) so far)\n", t->npeers); }
            else { fprintf(stderr, "[privbcast] giving up broadcast attempts: %s\n", reason[0] ? reason : "no longer acceptable"); pb_queue_remove(t->txid); g_pb_given_up++; }
            g_pb_dirty = 1;
        }
        g_pb_next_reattempt_s = now + PB_REATTEMPT_MIN_S + (long long)(dl_pool_rng() % PB_REATTEMPT_JITTER_S);
    }
    /* open what is owed */
    int bad = 0;
    while(g_pb_num_to_open > 0 && pbh_inflight() < PB_MAX_CONNECTIONS && pb_queue_has_pending() && bad < 8){
        int net = dialer_pb_pick_network();
        if(!net){ static long said; if(now - said > 300){ said = now; fprintf(stderr, "[privbcast] cannot open connections: neither Tor nor I2P is reachable\n"); } break; }
        bmc_addr_t a; if(!pb_pick_addr(net, &a)){ bad++; continue; }
        char hp[128]; bmc_addr_to_string_port(hp, sizeof hp, &a);
        int slot = -1; int ti = pb_queue_pick(hp, now, &slot);
        if(ti < 0) break;
        if(!pbh_start(ti, slot, &a, hp)){ pb_queue_unpick(ti, slot); break; }
        g_pb_num_to_open--; g_pb_dirty = 1;
    }
    if(g_pb_dirty) pb_publish();
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
                close(g_dh[i].sp); g_dh[i].pid = 0; g_dh[i].sp = -1; g_dh_last_slot = g_dh[i].want_slot;
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
        close(g_dh[i].sp); g_dh[i].pid = 0; g_dh[i].sp = -1; g_dh_last_slot = g_dh[i].want_slot;
        snprintf(host_out, hcap, "%s", g_dh[i].host);
        return 1;
    }
    return 0;
}
/* install a helper-dialled leg exactly as the inline fill does */
static int dh_install_leg(const char* host, int fd, const dh_result_t* r){
    for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0 && !strcmp(mux_out_host[k], host)){ close(fd); return 0; }   /* already a leg */
    g_peer_version_len = r->vlen; if(r->vlen) memcpy(g_peer_version_payload, r->vpayload, (size_t)r->vlen);
    g_peer_wants_addrv2 = r->wants_addrv2;
    int s = g_dh_last_slot; g_dh_last_slot = -1;
    if(s >= 0 && s < mux_n_out && mux_out_fd[s] < 0){                       /* a re-dial: the leg it was for is still down */
        snprintf(mux_out_host[s], sizeof mux_out_host[s], "%s", host);
        mux_out_fd[s] = fd; txrelay_leg_reset(fd); leg_note_installed(s);
        mux_out_kind[s] = host_is_block_only(host) ? LEG_BLOCK_ONLY : LEG_FULL; mux_out_cmpct[s] = 0;
        mux_out_wants_v2[s] = r->wants_addrv2;
        anchor_locator(mux_out_loc[s]); mux_out_nextretry[s] = 0;
        fprintf(stderr,"[mux:%d] leg replaced: connected next pool peer %s (fd %d) addrv2=%d [background dial]\n", s, host, fd, (int)r->wants_addrv2);
        rpc_fill_peer_slot(s, host);
        return 1;
    }
    if(mux_n_out >= MUX_MAX_OUT){ close(fd); return 0; }
    snprintf(mux_out_host[mux_n_out], sizeof mux_out_host[mux_n_out], "%s", host);
    mux_out_fd[mux_n_out] = fd; leg_note_installed(mux_n_out);
    mux_out_kind[mux_n_out] = host_is_block_only(host) ? LEG_BLOCK_ONLY : LEG_FULL;   /* CC-4 */ mux_out_cmpct[mux_n_out] = 0;
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
          if(!held && g_dialmem && !dialmem_allowed(g_dialmem, peers[p], dialmem_now())) held = 1;   /* 2026-09-09: under backoff */
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
    /* 2026-09-10: in a helper, never inline (Core's loop never blocks on a
     * connect). The leg stays down until the helper lands; dh_install_leg
     * fills THIS slot. One helper per slot; the caller's backoff stamp keeps
     * the slot from asking again before the helper has answered. */
    if(dh_inflight_for(i)) return;
    if(!dh_start_slot(peers[p], out_port, i)) fprintf(stderr,"[mux:%d] no dial helper free for %s -- the leg stays down until the next retry\n", i, peers[p]);
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
        { unsigned short ap = g_cfg.addnode_port[i] ? g_cfg.addnode_port[i] : g_chainp->default_port;   /* Core: addnode=host:port keeps its port */
          if(book_add_ipv4(ip, ap)>0) total++;
          fprintf(stderr,"[boot] addnode %s -> %s:%u\n", g_cfg.addnode[i], ipd, (unsigned)ap); }
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
/* the IPv4 of a pool entry (0 if it is not a dialable v4), and its port */
static unsigned pool_ipv4(const char* entry, int* port){
    bmc_addr_t a;
    if(!bmc_addr_from_string_port(&a, entry, 0) || a.net != BMC_NET_IPV4) return 0;
    if(port && a.port) *port = a.port;
    unsigned ip; memcpy(&ip, a.addr, 4); return ip;
}
#define DL_GOODPEERS_FILE "peers.good"
#define DL_GOODPEERS_MAX  256

/* EMA speed file format (PEER_PLAN item 4): "ip\t<ema_kbps>" -- int kilobits
 * per second, rounded (0 allowed, meaning "we knew this peer but never saw
 * it pull weight"). ema_kbps/1000.0 == bytes/s exactly. dl_load_good_peers
 * ALSO accepts the legacy bare-ip form (old files stay valid, no header
 * change); ema_out[i] is then 0 for those entries, which downstream means
 * "no speed knowledge -- plain rotation", i.e. exactly today's behaviour. */
static int dl_load_good_peers_ema(char (*out)[DL_POOL_SLOT], double* ema_out, int cap){
    FILE* f = fopen(DL_GOODPEERS_FILE, "r");
    if(!f) return 0;
    int n=0; char line[256];
    while(n<cap && fgets(line,sizeof line,f)){
        size_t L=strlen(line);
        while(L && (line[L-1]=='\n'||line[L-1]=='\r')) line[--L]=0;
        if(!L) continue;
        char* tab = strchr(line,'\t');
        double ema = 0.0;
        if(tab){
            *tab = 0;
            char* end = NULL;
            double v = strtod(tab+1, &end);        /* kilobits/s on this line */
            if(!end || end==tab+1 || v<0.0) v = 0.0;
            ema = v/1000.0;                        /* -> bytes/s */
        }
        struct in_addr t;
        if(inet_pton(AF_INET,line,&t)!=1) continue;   /* ignore junk lines (ip:port is not a bare IPv4 -- same rule as the pre-EMA loader: the pool keeps the entry string, the dial paths parse the port themselves via dlc_parse_peer) */
        snprintf(out[n],sizeof out[n],"%s",line);
        if(ema_out) ema_out[n]=ema;
        n++;
    }
    fclose(f);
    return n;
}
/* Written atomically (tmp+rename) so a crash mid-write cannot leave a
 * truncated list that silently shrinks the next boot's head start.
 *
 * IMPORTANT: log_ts.h (included at the top of this file) #defines `fprintf`
 * into its stderr-timestamping wrapper for the whole TU, and that wrapper is
 * stream-agnostic -- `fprintf(f,...)` on a DATA file gets a wall-clock
 * prefix stamped onto every line. peers.good is data, not a log: a prefixed
 * line fails inet_pton on load, so the entire list silently stops loading
 * (this is why the write path below builds each line with snprintf into a
 * buffer and uses fputs -- plain fprintf(f,...) here wrote
 * "2026-09-04 14:47:38.341 6.6.6.6\\t..." and every boot lost its memory). */
static void dl_save_good_peers_ema(char (*peers)[DL_POOL_SLOT], const double* ema_bps, int n){   /* stride must match the caller's good[][] (was [][64]: read the wrong entries -- 2026-09-02) */
    if(n<=0) return;
    FILE* f = fopen(DL_GOODPEERS_FILE ".tmp","w");
    if(!f) return;
/* NOTE: log_ts.h (included above) #defines fprintf -> its stderr-timestamping
 * wrapper for the rest of this TU. A data file is not a log: use fputs with
 * an explicit buffer so peers.good lines never grow a timestamp prefix (a
 * prefixed line silently fails inet_pton and the whole file loads as empty).
 * It is also -Werror=format-nonliteral safe, unlike an fprintf(f,fmt) pass-
 * through. */
#define DL_GOOD_LINE 256
    for(int i=0;i<n && i<DL_GOODPEERS_MAX;i++){
        char ln[DL_GOOD_LINE];
        /* Load side divides by 1000 to recover bytes/s (dl_load_good_peers_ema),
         * so the stored integer is bytes/s * 1000 -- the label "kbps" in
         * PEER_PLAN means the value at that scale, not bits. Rounding, 0
         * allowed (written as a bare ip). Built via snprintf+fputs because
         * log_ts.h redefines fprintf TU-wide as a stderr timestamping
         * wrapper: a formatted write to this FILE* would prefix every line
         * with a timestamp and silently poison next boot's parse. */
        double bps = (ema_bps && ema_bps[i] > 0.0) ? ema_bps[i] : 0.0;
        long kbits = (bps > 0.0) ? (long)(bps*1000.0 + 0.5) : 0;
        if(kbits>0) snprintf(ln,sizeof ln,"%.*s\t%ld\n",DL_POOL_SLOT-32,peers[i],kbits);
        else       snprintf(ln,sizeof ln,"%.*s\n",DL_POOL_SLOT-1,peers[i]);
        fputs(ln,f);
    }
    fflush(f); fsync(fileno(f)); fclose(f);
    rename(DL_GOODPEERS_FILE ".tmp", DL_GOODPEERS_FILE);
    fprintf(stderr,"[dlc] recorded %d known-good peer(s) for next boot\n", n<DL_GOODPEERS_MAX?n:DL_GOODPEERS_MAX);
}

/* Claim-order chooser (PEER_PLAN item 4): "the fastest peer nobody holds".
 * One linear scan over live[] (nlive<=2048) picks the HIGHEST-EMA
 * unclaimed/unbanned peer; ties broken by lowest index so the choice is
 * deterministic. When no ema is given -- or every candidate's ema is 0, the
 * fresh-sync case where the parent's 10s tick has never populated anything
 * -- this falls back to EXACTLY the old (slot+a)%nlive rotation, so a run
 * with no speed knowledge behaves as today. The caller's loop runs this per
 * attempt and keeps doing CAS claims, so a lost race simply re-asks and the
 * now-claimed top peer drops out of the scan.
 *
 * `bar` (2026-09-07): the boundary-rotation bar, half the pool median, or 0
 * when unknown. Without it, a worker that had just dropped a slow peer at a
 * chunk boundary got the SAME peer back: every never-tried peer has ema 0,
 * so the highest-ema rule ranked the known-slow one above all of them, and
 * a scratch node rotated 269 times among the same 16 addresses in five
 * minutes with its mean slot rate never moving. With a bar, the order is:
 * the fastest measured peer AT OR ABOVE the bar; else someone never tried;
 * else the fastest measured peer even below the bar (never stall); else the
 * plain rotation. bar 0 is exactly the old rule. */
#define DLC_EMA_DEAD_MARK 1.0   /* dlc_ema_after_failure's mark for "tried, delivered nothing" (bytes/s) */
static int dlc_pick_peer(int nlive, int slot, const volatile double* ema,
                         const volatile int* claimed, const volatile int* banned, double bar){
    if(ema){
        int best=-1; double bv=0.0;
        for(int a=0;a<nlive;a++){
            int idx=(slot+a)%nlive;
            if(banned[idx]||claimed[idx]) continue;
            double v=ema[idx];
            if(v>bv){ bv=v; best=idx; }
        }
        /* 2026-09-09 (run 19, stalled at block 560): a peer whose only
         * history is failure carries the dead mark (1.0, or less after more
         * failures) and must never clear a bar -- not even the unknown bar
         * (0) of a fresh sync, where it outranked every untried peer and two
         * workers went back 200 times to the two peers that closed on them. */
        if(best>=0 && bv > DLC_EMA_DEAD_MARK && (bar<=0.0 || bv>=bar)) return best;   /* someone has MEASURED speed, and it clears the bar */
        if(best>=0){                                          /* the best known is under the bar: prefer someone untried */
            for(int a=0;a<nlive;a++){
                int idx=(slot+a)%nlive;
                if(banned[idx]||claimed[idx]) continue;
                if(ema[idx]<=0.0) return idx;
            }
            return best;                                      /* nobody untried: the best there is, rather than no peer */
        }
    }
    for(int a=0;a<nlive;a++){                       /* rotation, identical to the pre-EMA loop:
                                                     * banned and claimed both skip */
        int idx=(slot+a)%nlive;
        if(banned[idx]) continue;                   /* already proved itself useless this run */
        if(claimed[idx]) continue;
        return idx;
    }
    return -1;                                      /* exhausted */
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
        if(extra > room) extra = room;
        if(extra > 0){ quota[k] += extra; taken += extra; }
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
#include "dlc_rules.h"
static long g_live_announced[DLC_MAXPOOL];   /* each ranked live peer's start_height (aligned with live[] after the sort; 0 = unknown) */
#define DLC_HDR_TRY_PEERS 8
/* STALL budget: the longest a worker waits for the NEXT block of a chunk
 * before dropping the peer. Re-armed from the pipeline's progress hook on
 * every wanted block that arrives.
 *
 * Until 2026-09-07 this was the wall-clock budget for the WHOLE chunk, and
 * the comment here said so plainly: "at 40 blocks (~50-60MB near the tip),
 * 120s requires ~467KB/s sustained to survive". That is an absolute rate
 * bar in disguise (docs/ENGINEERING_RULES.md rule 11), and it does not even
 * hold still -- it rises with block size. Seven hours into the 2026-09-07
 * fresh-sync benchmark it had dropped 429 peers whose measured rate was
 * ABOVE the pool-relative floor (one had served 1,560 blocks; a 424 KB/s
 * peer at height 600k simply cannot finish 60 MB in 120 s), discarding
 * ~10.7 GB of half-received chunks, while the real dead-weight rule found
 * 3. Per-block, 120 s is ~12 KB/s for a 1.5 MB block: a stall detector,
 * below the 32 KB/s absolute floor, so the pool-relative rule -- not this
 * constant -- is what decides who is slow. Core's own per-block download
 * timeout is 10 minutes (BLOCK_DOWNLOAD_TIMEOUT_BASE); this is stricter,
 * as before. */
#define DLC_CHUNK_BUDGET_SECS 120
#define DLC_STR_(x) #x
#define DLC_STR(x) DLC_STR_(x)     /* the stall line prints the constant, not a copy of it */
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

/* combined hole+extend span: 1 with *start_h / *end_h set, or 0 if the
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
/* DLC_HDR_SANE_MAX: how far BELOW our header tip a peer's answer may attach.
 * The 2026-09-01 incident was a reply that attached at genesis while we held
 * 965k headers -- a wholesale replacement dressed as a continuation. What
 * makes that implausible is the DEPTH of the fork (a year is ~52k blocks),
 * not the number of headers that follow: a fresh node, or one restarted in
 * the middle of its first sync, legitimately takes hundreds of thousands
 * of headers in one session. The first version of this guard capped the
 * count instead and rolled the whole session back at 100,001 -- so a node
 * starting from genesis could never get past 100k (found by the
 * fresh-install acceptance test, 2026-09-02). */
#define DLC_HDR_SANE_MAX 100000L
static int dlc_headers_sane(long have0, long pos){ return have0 - pos <= DLC_HDR_SANE_MAX; }

/* Is a download worker dead weight this tick? Two rules, either one binds.
 *
 * 1. The block floor: a worker must hand over at least
 *    DLC_DEAD_WEIGHT_MIN_BLOCKS blocks per 10-second tick. Ten blocks a
 *    second is the minimum a useful peer delivers at ANY chain depth --
 *    early-chain blocks are a few hundred bytes, so a bytes-only rule
 *    cannot see a peer that is slow in blocks; a peer serving 5 blocks/s
 *    of tiny early blocks looks exactly like one serving 5 MB/s near the
 *    tip on the byte counter.
 * 2. The byte floor (dead_weight_bps, 32 KB/s): calibrated for megabyte
 *    blocks, so near the tip it is the binding rule -- and it must stay
 *    live at every depth. 2026-09-02's fix (93fab72) joined the two with
 *    AND to stop the false bans that rule caused early in the chain
 *    (85 of 121 peers banned in eight minutes). That cured the false
 *    positive and created the far worse false negative: in the first
 *    ~150k blocks a peer delivering 6-9 blocks/s clears the block check
 *    while trickling under 32 KB/s, so NOTHING could evict it. The
 *    fresh-install run of 2026-09-04 sat at 77 KB/s aggregate with 22/22
 *    workers under the byte floor and zero kills in 20 minutes -- 3 days
 *    projected for a sync the byte-only rule finished in 4 hours.
 *
 * The correct shape of the 2026-09-02 lesson is an OR with a floor that is
 * honest about depth: low bytes AND low blocks is clearly useless (early
 * or late); low blocks ALONE is useless whatever the bytes; low bytes ALONE
 * is useless once blocks are big -- and the byte floor alone never hurt a
 * healthy early-chain peer that keeps its block rate, which is exactly the
 * peer 93fab72 was protecting. Measured against a real 30k-block hole on
 * the same datadir and peer pool: byte floor only 1.4 MB/s, current AND
 * rule 77 KB/s dead, OR rule 1.3+ MB/s with the early-chain false-positive
 * still avoided (a healthy tiny-block peer passes the block check and
 * never trips the byte check -- the AND was never needed to protect it). */
#define DLC_DEAD_WEIGHT_MIN_BLOCKS 10L
/* ---- the floor is RELATIVE to what the pool is achieving (2026-09-06) --------
 * The absolute byte floor (32 KB/s) was calibrated for megabyte blocks. At
 * height 50,000 a block is ~200 bytes and a serial fetch is bounded by the
 * round trip, so a perfectly healthy worker moves ~9 KB/s -- and the floor
 * declared every one of them dead. Measured on a fresh sync: 655 evictions
 * in 30 minutes, 478 of them under 5 KB/s, 195 of them after ZERO chunks,
 * with the whole 16-worker pool receiving 143 KB per tick. That is not
 * finding bad peers, it is killing the pool for being early in the chain.
 *
 * So the floor is the smaller of the configured absolute floor and a quarter
 * of the pool's median rate last tick. Early, when everyone is round-trip
 * bound, only a worker far below its peers dies; later, when the median is
 * hundreds of KB/s, the absolute floor takes over and the rule is what it
 * was. A worker with no reading, or a pool with no median yet, is never
 * killed on bytes -- the chunk budget still bounds a genuinely dead socket. */
static double dlc_effective_floor(double median_bps){
    double f = (double)g_cfg.dead_weight_bps;
    if (median_bps > 0.0 && 0.25 * median_bps < f) f = 0.25 * median_bps;
    if (f < 512.0) f = 512.0;                                        /* a truly dead socket still dies */
    return f;
}
/* ---- monotonic download window + retry ring (2026-09-07) -----------------
 * "Write out monotonically, like Core does." Core's downloader keeps a
 * BLOCK_DOWNLOAD_WINDOW of 1024 blocks above the last connected block and
 * never requests past it, so a missing block is always re-requested before
 * the download runs ahead of it, and a peer that blocks the window is the
 * one that gets kicked. Ours had 16 workers claiming 40-block chunks from
 * a counter that only ever went up: a chunk a worker gave up on became a
 * hole that nothing revisited until the next catch-up pass, and on run 10
 * a per-worker "stalled" counter that was never reset per chunk made a
 * worker abandon every chunk it claimed after 40 connect failures --
 * 21,676 abandoned chunks in eleven minutes, the connect stuck at 45,160.
 *
 * The control block next_claim points at is now [claim counter, retry
 * head, retry tail, first hole (published by the parent each tick), ring].
 * A worker (1) pops the retry ring before claiming anything new; (2) does
 * not claim a chunk more than DLC_DOWNLOAD_WINDOW blocks above the first
 * hole -- it waits, re-checking the ring, and after DLC_WINDOW_HELP_SECS
 * takes the first hole's own chunk itself (a duplicate fetch; the store's
 * appends are idempotent, test_shared_stress) so a dead worker can never
 * deadlock the window; (3) pushes any chunk it abandons onto the ring. */
/* Core's BLOCK_DOWNLOAD_WINDOW is 1024 blocks against ~8 outbound peers x
 * 16 blocks in flight (MAX_BLOCKS_IN_TRANSIT_PER_PEER): six to eight times
 * its in-flight count. Ours is 16 workers x 40-block chunks = 640 in
 * flight, so 1024 was only 1.6x -- run 11 and the scratch node after it
 * spent most of their time at the window (523 waits in six minutes, 45k
 * blocks against run 9's 86k). 4096 is the same slack Core gives itself;
 * the archive is still consolidated behind it (holes bounded, the connect
 * never more than the window behind the download). */
/* 2026-09-10: the window is now dlc_window_blocks(nw, DLC_CHUNK_BLOCKS) --
 * six times what is in flight, never under 4,096 -- and anchored to the
 * CONNECTED tip (dlc_window_anchor), Core's shape. */
static long g_dlc_window = DLC_WINDOW_MIN;
/* Core's BLOCK_STALLING_TIMEOUT_DEFAULT: when the window is full and one
 * peer blocks it, Core re-requests from another peer after 2 s. Same here:
 * a worker idle at a full window for 2 s fetches the blocking chunk itself
 * (one helper at a time, claimed through DLC_CTL_HELPING). */
/* (2026-09-10: the worker-side help -- an idle worker fetching the
 * blocking chunk itself, a duplicate -- is gone. The parent now evicts the
 * peer holding the window's tail, Core's rule, and the chunk goes to the
 * retry ring for the next claim; the committer's cursor help remains the
 * safety net for a chunk nobody holds.) */
#define DLC_RETRY_MAX 4096L
enum { DLC_CTL_CLAIM = 0, DLC_CTL_RETRY_HEAD = 1, DLC_CTL_RETRY_TAIL = 2, DLC_CTL_FIRST_HOLE = 3, DLC_CTL_HELPING = 4,
       DLC_CTL_WANT_ANCHOR = 5,           /* a worker blocked at the window asks the PARENT for a fresh first hole */
       /* per-event counters the workers bump and the parent prints ONCE per
        * tick, in place of a line per event (2026-09-07: the rotation and
        * window lines alone were 540 lines in six minutes of run 13) */
       DLC_CTL_N_ROTATE = 6, DLC_CTL_N_WAIT = 7, DLC_CTL_N_HELP = 8, DLC_CTL_N_FAIL = 9, DLC_CTL_N_ABANDON = 10,
       DLC_CTL_SPAN_START = 11,           /* the pass's first height: the claim grid is start + k*DLC_CHUNK_BLOCKS */
       /* the in-order committer (2026-09-08): the committed contiguous tip it
        * publishes, the staged-not-yet-committed chunk gauge, the chunks it
        * has appended, and the parent's "workers are gone: drain and exit" */
       DLC_CTL_COMMIT_TIP = 12, DLC_CTL_STAGED = 13, DLC_CTL_N_COMMIT = 14, DLC_CTL_STOP_COMMIT = 15,
       /* the chunk the committer has been waiting on for DLC_CURSOR_HELP_SECS
        * (or -1): a worker picks it up at its next claim without waiting for
        * the window to fill. Run 18 (2026-09-08) sat six minutes at 484,201
        * behind one trickling peer while 85 chunks above it were staged. */
       DLC_CTL_CURSOR_WANT = 16, DLC_CTL_N_CURSOR_HELP = 17,
       /* Core's shape (2026-09-10): the connected tip + 1 (-1: no engine in
        * this process), the count of unclaimed usable peers (a replacement
        * exists), the stall evictions */
       DLC_CTL_APPLIED = 18, DLC_CTL_FREE_PEERS = 19, DLC_CTL_N_STALL = 20,
       DLC_CTL_RING = 21 };
#define DLC_CURSOR_HELP_SECS 30
/* ...and only when the pool has moved on without it: at least this many
 * chunks staged above the cursor. A 40-block chunk is 40 MB at height
 * 490,000 and takes a worker a minute; a bare clock fires duplicate
 * downloads of chunks whose owner is still delivering them. */
#define DLC_CURSOR_HELP_MIN_STAGED 32
/* (2026-09-08, later the same day: 10 s and 8 chunks fired 39 helps in 21
 * minutes of run 18 at height 500,000 -- most of them on chunks whose owner
 * was still delivering. A third of the window staged above the cursor and
 * half a minute is a stall; anything less is a slow chunk.) */
static long g_dlc_cursor_help_ms = DLC_CURSOR_HELP_SECS * 1000L;   /* test seam */
/* Run 14 (2026-09-07) stalled for two minutes at 82,565: every worker
 * reconnected to the SAME peer -- one that accepted the handshake and
 * dropped us ~100 ms later -- because a failed fetch never lowered the
 * peer's standing and the picker handed it straight back; 12 reconnects a
 * second across the pool, 4,274 failed attempts in nine minutes. Three
 * rules, all pure so the test can pin them:
 *  - a failed fetch HALVES the peer's shared rate (three failures put it
 *    under any bar; the parent's next tick restores it if it delivers);
 *  - a growing pause after each failure on one chunk: 200 ms x attempts,
 *    capped at 2 s, so 400 attempts take 13 minutes, not 45 seconds;
 *  - the help chunk lies on the CLAIM grid (start + k*40), not on
 *    multiples of 40 from zero -- the pass starts at 1 when genesis is
 *    seeded, and a misaligned help straddled two owners' chunks. */
static double dlc_ema_after_failure(double ema){ return ema > 0.0 ? ema * 0.5 : DLC_EMA_DEAD_MARK; }
static long dlc_fail_backoff_ms(int attempt){ long ms = 200L * (attempt < 1 ? 1 : attempt); return ms > 2000 ? 2000 : ms; }
static long dlc_help_chunk_lo(long first_hole, long span_start){
    if(first_hole < span_start) return span_start;
    return span_start + ((first_hole - span_start) / DLC_CHUNK_BLOCKS) * DLC_CHUNK_BLOCKS;
}
/* The anchor is scanned by the parent only. The first cut had a blocked
 * worker rescan index.dat itself, and those reads landed in the worker's
 * /proc io rchar -- the counter the parent's per-worker rate, the pool
 * median, the dead-weight floor and the rotation bar are all built from.
 * Run 12 printed an "average since start" of 263 MB/s on an 11 MB/s link
 * and rotated on nearly every chunk. Workers now only raise a flag. */
static void dlc_publish_anchor(volatile long* ctl, long start_h){
    long tip = dlc_index_tip(); long fh = tip>=0 ? dlc_first_hole(tip) : -1;
    if(fh<0) fh = tip>=0 ? tip+1 : start_h;
    if(fh > ctl[DLC_CTL_FIRST_HOLE]) ctl[DLC_CTL_FIRST_HOLE] = fh;      /* monotonic: a stale reader never moves it back */
    ctl[DLC_CTL_WANT_ANCHOR] = 0;
}
#define DLC_CTL_BYTES ((size_t)(DLC_CTL_RING + DLC_RETRY_MAX) * sizeof(long))
/* single-producer-per-push, multi-consumer ring: push reserves a slot with a
 * CAS on head, pop reserves with a CAS on tail; entries are chunk `lo`s. */
static int dlc_retry_push(volatile long* ctl, long lo){
    for(;;){
        long h = ctl[DLC_CTL_RETRY_HEAD], t = ctl[DLC_CTL_RETRY_TAIL];
        if(h - t >= DLC_RETRY_MAX) return 0;                                   /* full: the next pass will find the hole */
        if(__sync_bool_compare_and_swap(&ctl[DLC_CTL_RETRY_HEAD], h, h + 1)){ ctl[DLC_CTL_RING + (h % DLC_RETRY_MAX)] = lo; return 1; }
    }
}
static long dlc_retry_pop(volatile long* ctl){
    for(;;){
        long t = ctl[DLC_CTL_RETRY_TAIL], h = ctl[DLC_CTL_RETRY_HEAD];
        if(t >= h) return -1;
        long lo = ctl[DLC_CTL_RING + (t % DLC_RETRY_MAX)];
        if(lo < 0) continue;                                                    /* the push reserved the slot but has not written it yet */
        if(__sync_bool_compare_and_swap(&ctl[DLC_CTL_RETRY_TAIL], t, t + 1)){ ctl[DLC_CTL_RING + (t % DLC_RETRY_MAX)] = -1; return lo; }
    }
}

/* ---- the in-order committer (2026-09-08) ----------------------------------
 * "WHY IS THE BLOCK DATA STILL NOT MONOTONIC FOR US?!" Sixteen workers
 * appended chunks to the archive in ARRIVAL order, so the index's
 * (file, offset) did not increase with height -- the boot check said so at
 * height 41 of every node this download built, and in-place pruning and the
 * physical truncation refused to run on it. The monotonic-download work
 * (#77) made the WINDOW monotonic, not the layout.
 *
 * Now a worker never touches the archive. It writes the chunk it has
 * fetched and verified (cons_verify, header hash, prev link -- unchanged)
 * to a staging file, records in ascending height order, and renames it
 * complete. ONE committer process appends staged chunks to the archive
 * strictly from the first hole upward, deletes each as it goes, and
 * publishes the first hole itself. The archive therefore never has a hole
 * and grows in height order from a single writer; a staging file that
 * lives a few seconds never reaches the disk. A chunk missing at the
 * cursor is what the workers' help path (2 s at the window) already
 * fetches; the committer just waits for it. Stale staging files from an
 * earlier run are discarded at start (they are re-fetched; the archive is
 * the durable state). Everything below is pure enough for
 * tests/test_dialhelper to run it on a scratch directory. */
#define DLC_STAGE_DIR "stage"
#define DLC_STAGE_REC_HDR 44u                 /* [u64 height][u32 len][hash 32] then the raw block */
#define DLC_STAGE_MAX_BYTES ((size_t)DLC_CHUNK_BLOCKS * ((4u << 20) + DLC_STAGE_REC_HDR) + 4096)
extern long store_append_shared(void* st, long height, const unsigned char hash[32], const unsigned char* raw, unsigned len);   /* bitcoin_store.asm */
static int g_stage_fd = -1;                   /* the worker's open staging file, per process */
static pid_t g_dlc_committer = 0;             /* the committer's pid while dl_catchup runs */
static int dlc_write_all(int fd, const void* p, size_t n){
    const unsigned char* q = (const unsigned char*)p;
    while(n){ ssize_t w = write(fd, q, n); if(w < 0){ if(errno == EINTR) continue; return -1; } q += w; n -= (size_t)w; }
    return 0;
}
static long dlc_stage_sink(void* st, long height, const unsigned char hash[32], const unsigned char* raw, unsigned len){
    (void)st; unsigned char h[DLC_STAGE_REC_HDR];
    memcpy(h, &height, 8); memcpy(h + 8, &len, 4); memcpy(h + 12, hash, 32);
    if(g_stage_fd < 0 || dlc_write_all(g_stage_fd, h, sizeof h) < 0 || dlc_write_all(g_stage_fd, raw, len) < 0) return -1;
    return height;
}
static void dlc_stage_path(char* buf, size_t cap, long lo){ snprintf(buf, cap, DLC_STAGE_DIR "/c%ld.chunk", lo); }
static int  dlc_stage_exists(long lo){ char p[64]; dlc_stage_path(p, sizeof p, lo); return access(p, F_OK) == 0; }
static int  dlc_stage_open_tmp(char* tmp, size_t cap, long lo){
    snprintf(tmp, cap, DLC_STAGE_DIR "/c%ld.w%d.tmp", lo, (int)getpid()); unlink(tmp);
    return open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
}
/* mkdir + discard whatever an earlier run left; returns how many were discarded */
static long dlc_stage_wipe(void){
    mkdir(DLC_STAGE_DIR, 0700);
    DIR* d = opendir(DLC_STAGE_DIR); if(!d) return 0;
    struct dirent* e; long n = 0;
    while((e = readdir(d))){
        if(e->d_name[0] != 'c') continue;
        char p[320]; snprintf(p, sizeof p, DLC_STAGE_DIR "/%s", e->d_name);
        if(unlink(p) == 0) n++;
    }
    closedir(d);
    return n;
}
/* Staged files wholly below the cursor are stale: a chunk's owner finished
 * after a helper had already delivered it (run 18 held six of them, and they
 * inflated the staged gauge that gates the cursor help). Sweep them, then
 * make the gauge the directory's truth: the count of published chunks. */
static long dlc_stage_sweep(long cursor, volatile long* ctl){
    DIR* d = opendir(DLC_STAGE_DIR); if (!d) return 0;
    struct dirent* e; long removed = 0, kept = 0;
    while ((e = readdir(d))){
        long lo; if (sscanf(e->d_name, "c%ld.chunk", &lo) != 1 || strstr(e->d_name, ".tmp")) continue;
        char p[320]; snprintf(p, sizeof p, DLC_STAGE_DIR "/%s", e->d_name);
        if (lo + DLC_CHUNK_BLOCKS - 1 < cursor){ if (unlink(p) == 0) removed++; }
        else kept++;
    }
    closedir(d);
    if (ctl) ctl[DLC_CTL_STAGED] = kept;
    return removed;
}
typedef long (*dlc_append_fn)(void* st, long height, const unsigned char hash[32], const unsigned char* raw, unsigned len);
typedef int  (*dlc_present_fn)(long height);
static int dlc_index_present(long h){ return idxscan_all_present(h, h) != 0; }
/* Commit ONE staged chunk file. Its records must start at or below *cursor
 * and run contiguously upward from there; heights already present are
 * skipped. Two passes -- validate the whole file, then append -- so a torn
 * or misordered file commits nothing and is discarded (-2). -3: no such
 * file yet. -1: the archive append failed (the file is kept for a retry).
 * >= 0: blocks appended; *cursor is past the file's last height and the
 * file is gone. */
static long dlc_commit_chunk(void* st, const char* path, long* cursor,
                             dlc_append_fn append, dlc_present_fn present,
                             unsigned char* buf, size_t cap){
    int fd = open(path, O_RDONLY | O_NOFOLLOW); if(fd < 0) return -3;
    struct stat sb; if(fstat(fd, &sb) < 0){ close(fd); return -3; }
    size_t sz = (size_t)sb.st_size;
    if(sz == 0 || sz > cap){ close(fd); unlink(path); return -2; }
    size_t got = 0;
    while(got < sz){ ssize_t r = pread(fd, buf + got, sz - got, (off_t)got); if(r < 0 && errno == EINTR) continue; if(r <= 0) break; got += (size_t)r; }
    close(fd);
    if(got != sz){ unlink(path); return -2; }
    /* pass 1: every record whole, heights contiguous from the first, the first at or below the cursor */
    size_t off = 0; long nrec = 0, expect = 0;
    while(off < sz){
        if(sz - off < DLC_STAGE_REC_HDR){ unlink(path); return -2; }
        long h; unsigned len; memcpy(&h, buf + off, 8); memcpy(&len, buf + off + 8, 4);
        if(len < 81 || sz - off - DLC_STAGE_REC_HDR < len){ unlink(path); return -2; }
        if(nrec == 0){ if(h > *cursor || h < 0){ unlink(path); return -2; } }
        else if(h != expect){ unlink(path); return -2; }
        expect = h + 1; off += DLC_STAGE_REC_HDR + len; nrec++;
    }
    if(nrec == 0){ unlink(path); return -2; }
    /* pass 2: append in order */
    off = 0; long n = 0;
    while(off < sz){
        long h; unsigned len; memcpy(&h, buf + off, 8); memcpy(&len, buf + off + 8, 4);
        const unsigned char* hash = buf + off + 12; const unsigned char* raw = buf + off + DLC_STAGE_REC_HDR;
        if(h >= *cursor){
            if(!(present && present(h))){ if(append(st, h, hash, raw, len) < 0) return -1; n++; }
            *cursor = h + 1;
        }
        off += DLC_STAGE_REC_HDR + len;
    }
    unlink(path);
    return n;
}
/* The committer's loop: from the first hole, commit the staged chunk at the
 * cursor whenever it exists, skip heights that are already present, publish
 * the first hole after each. Exits when the cursor passes end_h, when the
 * parent has set STOP and the chunk at the cursor is not staged (the workers
 * are gone: what is not here is not coming), on shutdown, or when orphaned.
 * poll_ms is the wait between looks when nothing is staged. */
static int dlc_committer_run(volatile long* ctl, long start_h, long end_h, void* st,
                             dlc_append_fn append, dlc_present_fn present, long poll_ms, pid_t parent,
                             void (*synced)(void* st)){
    unsigned char* buf = mmap(0, DLC_STAGE_MAX_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if(buf == MAP_FAILED){ fprintf(stderr, "[dlc committer] cannot map the chunk buffer\n"); return 1; }
    long fh = ctl[DLC_CTL_FIRST_HOLE]; if(fh < start_h) fh = start_h;
    while(fh <= end_h && present && present(fh)) fh++;
    if(fh > ctl[DLC_CTL_FIRST_HOLE]) ctl[DLC_CTL_FIRST_HOLE] = fh;
    ctl[DLC_CTL_COMMIT_TIP] = fh - 1;
    int rc = 0; long wait_lo = -1, wait_ms = 0;
    for(;;){
        if(g_shutdown_requested) break;
        if(parent > 0 && getppid() != parent) break;          /* orphaned: the download is over */
        if(fh > end_h) break;
        long lo = dlc_help_chunk_lo(fh, start_h);
        char path[64]; dlc_stage_path(path, sizeof path, lo);
        long r = dlc_commit_chunk(st, path, &fh, append, present, buf, DLC_STAGE_MAX_BYTES);
        if(r >= 0){
            if(ctl[DLC_CTL_CURSOR_WANT] == lo) ctl[DLC_CTL_CURSOR_WANT] = -1;
            if(synced && r > 0) synced(st);                       /* one journal commit per chunk, not per block */
            while(fh <= end_h && present && present(fh)) fh++;
            if(fh > ctl[DLC_CTL_FIRST_HOLE]) ctl[DLC_CTL_FIRST_HOLE] = fh;
            ctl[DLC_CTL_COMMIT_TIP] = fh - 1;
            __sync_fetch_and_add(&ctl[DLC_CTL_N_COMMIT], 1L);
            dlc_stage_sweep(fh, ctl);                              /* stale files below the cursor go; the gauge is the directory */
            continue;
        }
        if(r == -2){
            fprintf(stderr, "[dlc committer] staged chunk %s is malformed -- discarded; the window's help fetches it again\n", path);
            dlc_stage_sweep(fh, ctl);
            continue;
        }
        if(r == -1){
            fprintf(stderr, "[dlc committer] archive append FAILED at height %ld -- retrying in 1 s\n", fh);
            rc = 2; sleep(1); continue;
        }
        if(ctl[DLC_CTL_STOP_COMMIT]) break;                    /* -3 and the workers are gone */
        /* not staged yet: after DLC_CURSOR_HELP_SECS on the same chunk, ask
         * for a helper; a fresh chunk resets the clock */
        if(lo != wait_lo){ wait_lo = lo; wait_ms = 0; ctl[DLC_CTL_CURSOR_WANT] = -1; }
        else if(wait_ms >= g_dlc_cursor_help_ms && ctl[DLC_CTL_STAGED] >= DLC_CURSOR_HELP_MIN_STAGED && ctl[DLC_CTL_CURSOR_WANT] != lo) ctl[DLC_CTL_CURSOR_WANT] = lo;
        wait_ms += poll_ms;
        { struct timespec ts = { poll_ms / 1000, (poll_ms % 1000) * 1000000L }; nanosleep(&ts, NULL); }
    }
    ctl[DLC_CTL_CURSOR_WANT] = -1;
    munmap(buf, DLC_STAGE_MAX_BYTES);
    return rc;
}
/* the process: the worker's store setup, then store_reload so the first
 * append goes to the NEWEST blk file (store_init says file 0, and an append
 * there would fill the end of blk00000.dat -- one more way to a
 * non-monotonic layout) */
/* Run 18 (2026-09-08), first minutes: 103 chunks staged, the committer at
 * 96 blocks/s in jbd2_log_wait_commit -- store_append_shared does an
 * fdatasync per block (STO-11: bytes durable before the record), and with
 * one sequential writer that is one journal commit per block. The workers
 * had the same limit under the lock; the committer is the one place that
 * can batch it: the per-block sync is off in THIS process only (a fork:
 * the switch is a per-process global) and the chunk's blk and index fds
 * are fdatasync'd once after its appends. ext4 data=ordered keeps the
 * STO-11 order at the commit boundary (extending writes are flushed before
 * the commit that names them), a crash loses at most the last chunk's
 * appends, and the boot check cuts the index at the first record whose
 * body is missing. */
extern void store_set_sync(int on);
static void dlc_store_sync_chunk(void* st){
    int bfd = *(int*)((char*)st + 0), ifd = *(int*)((char*)st + 8);
    if(bfd >= 0) fdatasync(bfd);
    if(ifd >= 0) fdatasync(ifd);
}
static int dlc_committer_main(volatile long* ctl, long start_h, long end_h, pid_t parent){
    int lfd = open("append.lock", O_RDWR | O_CREAT, 0644);
    if(lfd < 0){ fprintf(stderr, "[dlc committer] no lock\n"); return 1; }
    static unsigned char st[4096]; store_init(st);
    *(int*)((char*)st + 40) = lfd;
    { extern unsigned int net_magic; *(int*)((char*)st + 36) = (int)net_magic; }
    *(int*)((char*)st + 28) = 0; *(int*)((char*)st + 0) = -1;
    store_reload(st);
    store_set_sync(0);                                       /* this process only; synced per chunk below */
    int r = dlc_committer_run(ctl, start_h, end_h, st, store_append_shared, dlc_index_present, 20, parent, dlc_store_sync_chunk);
    close(lfd);
    return r;
}
/* every worker has exited, so every chunk that will ever be staged is
 * staged: tell the committer to drain and stop at the first chunk it does
 * not find (the next pass's hole scan owns that one). Called at the loop's
 * last reap, BEFORE the final status tick, so that tick shows the archive
 * the committer finished, not the one it was still writing. */
static void dlc_drain_committer(volatile long* ctl){
    if(g_dlc_committer<=0) return;
    ctl[DLC_CTL_STOP_COMMIT]=1;
    int cst; long waited_ms=0;
    while(waitpid(g_dlc_committer,&cst,WNOHANG)==0){
        if(g_shutdown_requested){ kill(g_dlc_committer,SIGTERM); waitpid(g_dlc_committer,&cst,0); break; }
        struct timespec ts={0,50000000L}; nanosleep(&ts,NULL); waited_ms+=50;
        if(waited_ms%10000==0) fprintf(stderr,"[dlc] waiting for the committer: %ld staged chunk(s) left\n", ctl[DLC_CTL_STAGED]);
    }
    g_dlc_committer=0;
    fprintf(stderr,"[dlc] committer: %ld chunk(s) appended in height order; committed tip %ld\n",
            ctl[DLC_CTL_N_COMMIT], ctl[DLC_CTL_COMMIT_TIP]);
}
static void dlc_stop_committer(void){
    if(g_dlc_committer <= 0) return;
    int stt; kill(g_dlc_committer, SIGTERM);
    { struct timespec g = {1, 0}; nanosleep(&g, NULL); }
    if(waitpid(g_dlc_committer, &stt, WNOHANG) == 0){ kill(g_dlc_committer, SIGKILL); waitpid(g_dlc_committer, &stt, 0); }
    g_dlc_committer = 0;
}
/* ---- boundary rotation (2026-09-07) --------------------------------------
 * A worker KEEPS its peer after a clean chunk. Once the flat chunk budget
 * became a stall clock (PR #68), nothing removed a delivering-but-slow peer:
 * the dead-weight floor is min(32 KB/s, median/4) = 32 KB/s at the tail, so
 * a 250 KB/s peer against an 800 KB/s median held its slot for the rest of
 * the run, and slots drifted toward the slow end of the pool as fast peers
 * disconnected and slow ones never left. Run 9's flat budget had purged
 * those by accident -- at the cost of the partial chunk every time.
 *
 * So: judge at the CHUNK BOUNDARY, when nothing is in flight. A worker whose
 * rate over the chunk it just completed was under half the pool median
 * closes the socket and takes a fresh peer (dlc_pick_peer: the fastest
 * unclaimed one). Nothing is discarded; the log prints the rate and the bar.
 * The bar is relative at every depth (ENGINEERING_RULES rule 11). */
#define DLC_ROTATE_FRACTION 0.5
static int dlc_rotate_after_chunk(double chunk_bps, double median_bps){
    if (chunk_bps < 0.0 || median_bps <= 0.0) return 0;      /* nothing measured, or no pool view yet */
    return chunk_bps < DLC_ROTATE_FRACTION * median_bps;
}
/* ETA to the tip from the block rate over the status loop's recent window.
 * Blocks grow toward the tip, so on the tail this is optimistic; it says
 * "at the last ten minutes' rate", nothing more. -1 = no rate yet. */
static long dlc_eta_secs(long remaining, long delta_blocks, double delta_secs){
    if (remaining <= 0) return 0;
    if (delta_blocks <= 0 || delta_secs <= 0.0) return -1;
    double s = (double)remaining / ((double)delta_blocks / delta_secs);
    if (s > 99.0 * 86400.0) s = 99.0 * 86400.0;
    return (long)(s + 0.5);
}
static void dlc_fmt_eta(char* buf, size_t cap, long secs){               /* DD:HH:MM:SS */
    if (secs < 0){ snprintf(buf, cap, "--:--:--:--"); return; }
    int d = (int)(secs / 86400), h = (int)((secs % 86400) / 3600), m = (int)((secs % 3600) / 60), s = (int)(secs % 60);
    char tmp[48];                                        /* four ints cannot exceed 47 chars: no truncation possible */
    snprintf(tmp, sizeof tmp, "%02d:%02d:%02d:%02d", d, h, m, s);
    size_t n = strlen(tmp); if (n >= cap) n = cap ? cap - 1 : 0;
    memcpy(buf, tmp, n); if (cap) buf[n] = 0;
}
/* the pipeline's progress hook: every wanted block that arrives restarts the
 * stall clock, so a peer that keeps delivering is never dropped by it. */
static void dlc_chunk_progress(void* arg){ (void)arg; alarm(DLC_CHUNK_BUDGET_SECS); }
static void dlc_chunk_bytes(long n){ dl_gate_account(n); }   /* bmc.downloadratelimit */
extern void (*g_p2p_write_hook)(int fd, unsigned plen);      /* bitcoin_net.asm: called before every p2p_write */
static void p2p_upload_pace(int fd, unsigned plen){ (void)fd; ul_gate_account((long)plen); }   /* bmc.uploadratelimit */
static int dlc_dead_weight(double byte_rate, long blocks_this_tick, double floor_bps){
    if (byte_rate < 0.0) return 0;                                   /* no reading yet */
    if (byte_rate < floor_bps) return 1;                             /* under the pool-relative floor */
    if (blocks_this_tick < DLC_DEAD_WEIGHT_MIN_BLOCKS
        && byte_rate < 2.0 * floor_bps) return 1;                    /* marginal bytes AND stalled blocks */
    return 0;
}
/* ---------------------------------------------------------------- VAL-5
 * The parent's median time past, read from the header store.
 *
 * Core's GetMedianTimePast is the median nTime of the up-to-11 blocks ending
 * at `height`. The store keeps 112-byte records whose first 80 bytes are the
 * raw header, so nTime is at record offset 68.
 *
 * Returns 0 when any record in the window is unreadable. The caller then
 * SKIPS the timestamp floor for that header rather than evaluating it against
 * a partial window -- an incomplete median is not a weaker rule, it is a
 * different one, and at the start of a fetch it would reject honest headers. */
static int hst_median_time_past(void* hst, long height, unsigned long* out){
    unsigned int ts[11];
    int n = 0;
    for (long k = height; k > height - 11 && k >= 0; k--){
        unsigned char rec[112];
        if (hst_get_at(hst, (unsigned long long)k, rec) != 1) return 0;
        memcpy(&ts[n++], rec + 68, 4);
    }
    if (n == 0) return 0;
    for (int i = 1; i < n; i++){
        unsigned int v = ts[i]; int j = i - 1;
        while (j >= 0 && ts[j] > v){ ts[j+1] = ts[j]; j--; }
        ts[j+1] = v;
    }
    *out = (unsigned long)ts[n / 2];
    return 1;
}

/* BIP34's activation height for the running chain. Core keys one of the
 * legacy-version rules on it, and unlike BIP66/BIP65 it has no script flag to
 * read it from -- BIP34 is not a script rule. Mainnet's is 227,931; every
 * other chain in this tree activates it at or before genesis, which the
 * comparison `height >= h` then satisfies for every block. */
static long dlc_bip34_height(void){
    extern const chainparams_t* g_chainp;
    if (g_chainp && g_chainp->id == CHAIN_MAIN) return 227931L;
    return 0L;
}

static int __attribute__((unused)) dlc_headers_connect_ok(unsigned char* hst, long have, const unsigned char loc[32]){
    unsigned char rec[112];
    if(have <= 0) return 1;                                   /* fresh store: nothing to connect to */
    if(hst_get_at(hst, (unsigned long long)have, rec) != 1) return 0;
    return memcmp(rec + 4, loc, 32) == 0;                     /* header[4..36) = hashPrevBlock */
}
/* drop everything appended past `have`: headers.dat is the store's backing
 * file (112-byte records), so truncate it and reload */
/* the reorg handoff (daemon/reorg.c): the archive was rewound to the fork
 * point; headers.dat must follow, or the next header sync reads the stale
 * mirror as "already current" and the downloader never asks for the
 * replacement (2026-09-09). The next dlc run re-reads the file. */
static int g_dl_parallel_now = 0;
/* the mirror as the best header chain, for the reorg module: one loaded copy,
 * refreshed when the file's size changes (an append here, a fetch elsewhere) */
static unsigned char g_mirror_hst[4096]; static off_t g_mirror_size = -1;
static int dl_mirror_load(void){
    struct stat s; if(stat("headers.dat", &s) != 0) return 0;
    if(s.st_size != g_mirror_size){ hst_init(g_mirror_hst); hst_reload(g_mirror_hst); g_mirror_size = s.st_size; }
    return 1;
}
static int dl_mirror_hash_at(long height, unsigned char out[32]){
    if(height < 0 || !dl_mirror_load() || height >= hst_count(g_mirror_hst)) return 0;
    unsigned char rec[112]; if(hst_get_at(g_mirror_hst, (unsigned long long)height, rec) != 1) return 0;
    memcpy(out, rec + 80, 32); return 1;
}
static int dl_mirror_append(const unsigned char hdr80[80], long height){
    if(!dl_mirror_load() || hst_count(g_mirror_hst) != height) return 0;   /* only a continuation of the mirror's tip */
    unsigned char bh[32]; block_hash(bh, hdr80);
    if(hst_append(g_mirror_hst, hdr80, bh) < 0) return 0;
    struct stat s; if(stat("headers.dat", &s) == 0) g_mirror_size = s.st_size;
    return 1;
}
/* a header page the fetch refused because it forks below our tip: retained
 * in the fork tree with its work from the fork base (Core keeps every valid
 * header; a probe decides whether it is heavier) */
static long dl_retain_page(const unsigned char* first, unsigned long cnt, long pos){
    extern int hdrtree_add(const unsigned char*, long, const unsigned char*);
    extern int store_chainwork_get_at(void*, long, unsigned char*);
    extern void block_work(unsigned char*, unsigned); extern void chainwork_add(unsigned char*, const unsigned char*, const unsigned char*);
    unsigned char cum[16]; memset(cum, 0, 16);
    if(pos > 0 && store_chainwork_get_at(store_buf, pos - 1, cum) != 1) return 0;
    long n = 0;
    for(unsigned long j = 0; j < cnt; j++){
        const unsigned char* h = first + j * 81; unsigned bits; memcpy(&bits, h + 72, 4);
        unsigned char w[16]; block_work(w, bits); chainwork_add(cum, cum, w);
        if(hdrtree_add(h, pos + (long)j, cum) == 1) n++;
    }
    return n;
}
static void dl_headers_truncate_to(long keep){
    struct stat s;
    if(stat("headers.dat", &s) != 0 || s.st_size <= (off_t)keep * 112) return;
    if(truncate("headers.dat", (off_t)keep * 112) == 0)
        fprintf(stderr,"[dl] header mirror rolled back to %ld record(s) for the reorg handoff\n", keep);
    else fprintf(stderr,"[dl] could not roll headers.dat back to %ld record(s): %s\n", keep, strerror(errno));
    g_dl_parallel_now = 1;
}
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
 *   - the page may not attach more than DLC_HDR_SANE_MAX headers below our
 *     tip (a node a year offline is ~52k behind; the incident's reply
 *     attached at genesis). How many headers FOLLOW is not limited: from
 *     genesis, or restarted mid-sync, the honest answer is the whole chain.
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
/* CC-5: one page of headers, validated and appended exactly as before --
 * linkage, overlap-must-match, PoW, the VAL-5 contextual rules -- factored
 * out so a page HELD below -minimumchainwork can be taken later, in order.
 * Returns the number of headers consumed (< cnt stops the peer's pages), or
 * -1 after rolling the store back to have0. */
static long dlc_take_page(void* hst, const unsigned char* first, unsigned long cnt, long pos,
                          unsigned char prev[32], const char* cand, long have0, long* added){
long have = hst_count(hst);
unsigned long i = 0;
for(; i < cnt; i++){
        const unsigned char* h = first + i * 81;
        if(h[80] != 0) break;                 /* txn_count must be 0 in a headers message */
        if(memcmp(h + 4, prev, 32) != 0){
            fprintf(stderr,"[dlc] headers from %s break their own chain at %lu -- discarding\n", cand, i);
            dlc_headers_rollback(hst, have0); return -1;
        }
        unsigned char bh[32]; block_hash(bh, h);
        if(pos + (long)i < have){
            /* overlap with what we hold: must be the same block */
            unsigned char rec[112];
            if(hst_get_at(hst, (unsigned long long)(pos + (long)i), rec) != 1 || memcmp(rec + 80, bh, 32) != 0){
                long kept = dl_retain_page(first + i * 81, cnt - i, pos + (long)i);   /* 2026-09-09: Core keeps every header; a probe weighs it */
                fprintf(stderr,"[dlc] headers from %s fork from our chain at height %ld -- not taken (%ld retained in the fork tree)\n", cand, pos + (long)i, kept);
                dlc_headers_rollback(hst, have0); return -1;
            }
        } else {
            /* VAL-5 (audit 2026-09-03): this used to append whatever a
             * peer sent after only checking linkage -- no pow_check at
             * all, so up to 2,000 x 1,000 headers of garbage from the
             * first live peer landed in headers.dat by height, and the
             * block downloader then requested blocks for hashes nothing
             * ever revalidates. Core validates CheckProofOfWork on every
             * header before storing. The nBits range/PoW check runs
             * BEFORE hst_append (pow_check carries the VAL-11 nBits
             * range gates + the armed chain powLimit), and VAL-5's
             * remaining rules -- ContextualCheckBlockHeader's timestamp
             * floor, its 2-hour ceiling and the legacy-version rules --
             * run right after it, from daemon/hdrrules.h. */
            if(!pow_check(h)){
                fprintf(stderr,"[dlc] header at height %ld from %s fails its own PoW -- discarding the page\n",
                        pos + (long)i, cand);
                dlc_headers_rollback(hst, have0); return -1;
            }
            /* ---- VAL-5: the non-PoW header rules -------------------
             * The timestamp FLOOR needs the parent's median-time-past.
             * At the very start of a fetch the parent is whatever the
             * store already holds; within a page it is the window this
             * loop has just appended. hst_median_time_past reads the
             * store, so it is only consulted for a height whose 11
             * ancestors are already there -- otherwise the floor is
             * skipped for that header rather than evaluated against a
             * window that does not exist. The ceiling and the version
             * rules need no ancestors and always run. */
            { long hh = pos + (long)i;
              const char* why = "?";
              unsigned long pmtp = 0;
              if (hh >= 11) (void)hst_median_time_past(hst, hh - 1, &pmtp);
              unsigned long long hflags =
                  script_flags_for_block((unsigned long long)hh, bh);
              if(!hdr_contextual_ok(hh, h, pmtp, (long)time(NULL),
                                    hflags, dlc_bip34_height(), &why)){
                  fprintf(stderr,"[dlc] header at height %ld from %s rejected: %s -- discarding the page\n",
                          hh, cand, why);
                  dlc_headers_rollback(hst, have0); return -1;
              } }
            if(invset_has(bh)){                       /* CC-10: the operator invalidated this block */
                fprintf(stderr,"[dlc] headers from %s reach a block the operator invalidated at height %ld -- refusing this chain\n", cand, pos + (long)i);
                dlc_headers_rollback(hst, have0); return -1;
            }
            if(hst_append(hst, h, bh) < 0){ dlc_headers_rollback(hst, have0); return -1; }
            (*added)++;
        }
        memcpy(prev, bh, 32);
    }
    return (long)i;
}
static lowwork_t g_lw;                                   /* CC-5 hold: 48 KB of bookkeeping; the page scratch is mmap'd per fetch */
static int dlc_lw_get_at(void* hst, unsigned long long h, void* out){ return hst_get_at(hst, h, out); }
extern int reorg_min_chain_work_set(void);
static long long dlc_now_ms(void); static void dlc_fmt_rate(char* buf, size_t cap, double bytes_per_sec);   /* defined below; the progress line needs them here */
static long dlc_fetch_headers(int fd, unsigned char* hst, const char* cand){
    long have0 = hst_count(hst), added = 0; int lw_started = 0; lowwork_clear(&g_lw);
    long long fetch_t0 = dlc_now_ms(); unsigned long held_bytes = 0;   /* for the held-region progress line */
    static unsigned char page[DLC_HDR_PAGE * 81 + 16];
    static unsigned char msg[2 << 20];
    unsigned char stop[32]; memset(stop, 0, 32);
    for(int round = 0; round < 1000; round++){
        unsigned char loc[DLC_HDR_LOCATOR_MAX * 32]; long lh[DLC_HDR_LOCATOR_MAX];
        int nl = dlc_locator_build(hst, loc, lh);
        if(nl <= 0) return -1;
        { unsigned char th[32]; long tht;                        /* CC-5: ask onward from the held tail */
          if(lowwork_tail(&g_lw, th, &tht)){
              if(nl >= DLC_HDR_LOCATOR_MAX) nl = DLC_HDR_LOCATOR_MAX - 1;
              memmove(loc + 32, loc, (size_t)nl * 32); memmove(lh + 1, lh, (size_t)nl * sizeof lh[0]);
              memcpy(loc, th, 32); lh[0] = tht; nl++;
          } }
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
        dl_gate_account((long)mlen);                                  /* bmc.downloadratelimit: a header page is bytes too */
        unsigned long used; unsigned long cnt = dlc_varint(msg, mlen, &used);
        if(!used || cnt > DLC_HDR_PAGE || used + cnt * 81 > mlen) break;   /* malformed: stop here */
        if(cnt == 0) break;
        /* where does this page attach? the first header's prev must be one of
         * the hashes we asked with */
        const unsigned char* first = msg + used;
        int at = -1; for(int q = 0; q < nl; q++) if(!memcmp(first + 4, loc + q * 32, 32)){ at = q; break; }
        if(at < 0){
            fprintf(stderr,"[dlc] headers from %s do not connect to any header we hold (%lu offered) -- discarding\n", cand, cnt);
            dlc_headers_rollback(hst, have0); return -1;
        }
        long pos = lh[at] + 1;                    /* the height this page's first header would have */
        if(!dlc_headers_sane(have0, pos)){
            fprintf(stderr,"[dlc] headers from %s attach at height %ld while we hold %ld -- a fork deeper than %ld is not a continuation; discarding\n", cand, pos, have0, DLC_HDR_SANE_MAX);
            dlc_headers_rollback(hst, have0); return -1;
        }
        unsigned char prev[32]; memcpy(prev, loc + at * 32, 32);
        /* ---- a peer BEHIND us (2026-09-08) ------------------------------------
         * A peer answers from the deepest locator hash it knows. One that is
         * behind our tip knows only a deep entry and sends the 2,000 headers
         * after it -- every one a header we hold. dlc_take_page verified the
         * overlap and appended nothing, the full page counted as progress,
         * the locator (rebuilt from our unchanged tip) asked the same question
         * and the peer gave the same page: production walked 415 identical
         * pages (67 MB, 25 minutes) from a node ~100k blocks behind, the tip
         * loop waiting the whole time. A page that ends below what we hold
         * offers nothing; the peer is behind us, and the next candidate is
         * tried. */
        { long have_now = hst_count(hst);
          if(pos + (long)cnt <= have_now){
              fprintf(stderr,"[dlc] headers from %s attach at height %ld and end at %ld, below the %ld we hold -- the peer is behind us; trying another\n",
                      cand, pos, pos + (long)cnt - 1, have_now);
              lowwork_clear(&g_lw);
              return added > 0 ? added : -1;
          } }
        /* ---- CC-5: is this chain worth storing yet? ------------------------
         * Core (24.0 presync) stores nothing from a peer until the chain's
         * total work clears -minimumchainwork; this node appended every
         * PoW-valid header regardless, so a peer could fill headers.dat with
         * an arbitrarily long valid-PoW low-work chain. Full pages below the
         * floor are HELD (linkage + PoW checked, nothing stored) and released
         * in order once the chain crosses it; a chain that stays below for
         * LOWWORK_HOLD_PAGES full pages is abandoned. */
        if(!lw_started){ unsigned char cum[16]; lowwork_cum_from_store(cum, hst, pos - 1, dlc_lw_get_at); lowwork_begin(&g_lw, cum, reorg_min_chain_work_set()); lw_started = 1; }
        { unsigned char lasth[32]; block_hash(lasth, first + (cnt - 1) * 81);
          int lwv = lowwork_page(&g_lw, first, cnt, pos, prev, lasth);
          if(lwv == LOWWORK_ABANDON){
              fprintf(stderr,"[dlc] headers from %s: %d full pages (%lu headers, the hold's memory bound) and still below -minimumchainwork -- abandoning this chain (nothing was stored)\n", cand, LOWWORK_HOLD_PAGES, (unsigned long)LOWWORK_HOLD_PAGES * LOWWORK_PAGE_MAX);
              lowwork_clear(&g_lw); dlc_headers_rollback(hst, have0); return -1;
          }
          if(lwv == LOWWORK_HOLD){
              for(unsigned long j = 0; j < cnt; j++){
                  const unsigned char* h = first + j * 81;
                  if(h[80] != 0 || memcmp(h + 4, prev, 32) != 0 || !pow_check(h)){
                      fprintf(stderr,"[dlc] held page from %s fails linkage or PoW at %lu -- discarding\n", cand, j);
                      lowwork_clear(&g_lw); dlc_headers_rollback(hst, have0); return -1;
                  }
                  block_hash(prev, h);
              }
              held_bytes += cnt * 81;
              if(g_lw.held == 1) fprintf(stderr,"[dlc] headers from %s are below -minimumchainwork so far -- holding %lu, storing none until the chain proves its work\n", cand, cnt);
              /* 2026-09-07: an honest mainnet chain is below the floor for
               * its first ~880,000 headers (~71 MB of pages), and this loop
               * said nothing for all of it. A scratch node sharing its link
               * with a benchmark held for 35 minutes at 133 KB/s and was
               * mistaken for a hang. Say how far, how fast, every 50 pages. */
              else if(g_lw.held % 50 == 0){
                  double secs = (double)(dlc_now_ms() - fetch_t0) / 1000.0; if(secs < 1.0) secs = 1.0;
                  char rate[16]; dlc_fmt_rate(rate, sizeof rate, (double)held_bytes / secs);
                  fprintf(stderr,"[dlc] headers from %s: still below -minimumchainwork after %d held page(s) (%lu headers, %.1f MB) in %.0fs -- %s\n",
                          cand, g_lw.held, (unsigned long)g_lw.held * cnt, (double)held_bytes / 1048576.0, secs, rate);
              }
              continue;
          }
          if(lwv == LOWWORK_RELEASE){
              fprintf(stderr,"[dlc] chain from %s crossed -minimumchainwork -- storing %d held page(s)\n", cand, g_lw.held);
              for(int j = 0; j < g_lw.held; j++){
                  const unsigned char* hp; unsigned long hc; long hpos; const unsigned char* hprev; unsigned char pv[32];
                  lowwork_held(&g_lw, j, &hp, &hc, &hpos, &hprev); memcpy(pv, hprev, 32);
                  if(dlc_take_page(hst, hp, hc, hpos, pv, cand, have0, &added) < 0){ lowwork_clear(&g_lw); return -1; }
              }
              lowwork_clear(&g_lw);
          } }
        unsigned long i;
        { long took = dlc_take_page(hst, first, cnt, pos, prev, cand, have0, &added);
          if(took < 0) return -1;
          i = (unsigned long)took; }
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
    /* already known to lack NODE_WITNESS this run: do not spend a socket and a
     * handshake to be told again (2026-09-06). */
    if(peer_known_no_witness(cand)){ *why = DLC_HT_WITNESS; return -1; }
    dial_gate_wait();
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

static long dlc_headers(char live[][DL_POOL_SLOT], int nlive){
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
    long announced = dlc_announced_height(g_live_announced, nlive);   /* 2026-09-09: the pool's claim, from the ranking handshakes */
    int short_i = -1; long short_tip = -1;                             /* the longest chain that still fell short, in case every candidate does */
    for(int i=0;i<nlive && tried<DLC_HDR_TRY_PEERS; i++){
        int why=0;
        long added=dlc_headers_try(live[i], hst, loc, hdrbuf, sizeof hdrbuf, &why);
        if(added<0){ failed++; if(why>=0 && why<8) whys[why]++; continue; }
        tried++;
        { long tip_now = hst_count(hst) - 1;
          if((added>0 || have>0) && dlc_chain_falls_short(tip_now, announced)){
            /* the bench took a stuck peer's stale branch, 4,500 blocks short of
             * what every other peer announced, and synced to its end (2026-09-09) */
            fprintf(stderr,"[dlc] headers from %s end at %ld while the pool announces %ld -- the peer is behind or on a stale branch; trying another\n", live[i], tip_now, announced);
            if(tip_now > short_tip){ short_tip = tip_now; short_i = i; }
            if(added>0) dlc_headers_rollback(hst, have);
            continue;
          } }
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
    if(short_i >= 0){
        /* every candidate fell short of the announcement: take the longest of
         * them rather than nothing (the announcement may be the liar, or every
         * reachable peer may be behind) -- and say so */
        int why=0; long added=dlc_headers_try(live[short_i], hst, loc, hdrbuf, sizeof hdrbuf, &why);
        fprintf(stderr,"[dlc] no candidate reached the announced %ld; taking the longest, %s at %ld (total %ld)\n", announced, live[short_i], short_tip, hst_count(hst));
        if(added>=0 && hst_count(hst)>0) return hst_count(hst);
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
typedef struct { char peer[64]; long chunks; long blocks; long guard; double last_bw_bps; long timeouts; long held_idx;
                 double pool_median_bps;   /* written by the parent each tick: the pool's median rate, read by the worker for boundary rotation */
                 /* 2026-09-08, for getpeerinfo: the handshake's facts (worker), the chunk in flight (worker), bytes on this peer (parent) */
                 unsigned proto; unsigned long long services; char subver[96]; int start_height; long long conn_time;
                 long cur_lo, cur_hi; long long bytes_peer;
                 int kill_reason;          /* set by the parent before SIGUSR1: 0 dead weight, 1 stalling the window (2026-09-10) */
               } dlc_stat_t;
static long long dlc_now_ms(void); static long dlc_proc_rchar(pid_t pid);   /* fwd decls: the worker judges its own chunk before these are defined */
static void dlc_fmt_rate(char* buf, size_t cap, double bytes_per_sec); /* fwd decls, defined below */
static void dlc_fmt_bytes(char* buf, size_t cap, double bytes);

static int dlc_worker(int w, long end_h, char live[][DL_POOL_SLOT], int nlive,
                      int slot0, volatile long* next_claim, volatile long* done_count,
                      volatile dlc_stat_t* mystat, volatile int* claimed,
                      volatile int* banned, volatile double* ema){
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
    /* NET-15 (audit 2026-09-03): this hardcoded MAINNET's magic into every
     * frame the catch-up worker wrote, on every chain, while every other
     * writer uses net_magic -- so a testnet4/signet/regtest archive carried
     * mainnet frames. The frame magic is never read back today (see the note
     * at the store's own frame writer), so it was an inconsistency rather
     * than a fault, but it is exactly what a future frame-magic check or an
     * external reindex tool would trip over. */
    { extern unsigned int net_magic; *(int*)((char*)st+36) = (int)net_magic; }
    *(int*)((char*)st+28)=0;            /* cur_file_no=0 */
    *(int*)((char*)st+0)=-1;            /* no blk fd yet */
    static unsigned char buf[24<<20]; static unsigned char scratch[8<<20];
    unsigned cap=(unsigned)(sizeof scratch/32);
    /* ---- DMN-8 (audit 2026-09-03): the per-chunk header scratch ----
     * This was "/tmp/dlc_hdr_<pid>.dat", opened O_RDWR|O_CREAT|O_TRUNC with
     * no O_EXCL and no O_NOFOLLOW, and never unlinked: a classic symlink race
     * in a world-writable directory, plus a file left behind on every boot.
     * PrivateTmp=yes hides it on the live host, but not for the runbook's
     * manual invocation or any other host.
     *
     * It now lives in the DATADIR -- main() has already chdir'd there, which
     * is why headers.dat below opens relatively -- so no other user can
     * pre-create the path. It is created exclusively, never followed through
     * a symlink, and unlinked IMMEDIATELY after the open: the fd is all this
     * code ever uses, so from that point the file is anonymous, cannot be
     * opened by anyone else, and cannot survive the process. The unlink
     * before the open clears a stale file from a crashed run that happened to
     * hold this pid. */
    char hp_[64]; snprintf(hp_,sizeof hp_,"dlc_hdr_%d.dat",getpid());
    static unsigned char hst[64]; static unsigned char rec[112];
    int slot=slot0; long total=0; long stalled=0;
    int fd=-1; int held=-1;   /* index into live[]/claimed[] currently held, or -1 */
#define DLC_RELEASE() do{ if(held>=0){ claimed[held]=0; held=-1; } }while(0)
    for(;;){
        stalled=0;                          /* per CHUNK: run 10's cascade was this counter surviving into the next chunk */
        /* the claim, in Core's order: a chunk that needs retrying first;
         * else the next new chunk, but only inside the download window
         * above the first hole; while the window is blocked, keep checking
         * the ring, and after DLC_WINDOW_HELP_SECS fetch the blocking chunk
         * ourselves rather than wait on a worker that may be gone. */
        int helping=0;
        long lo=dlc_retry_pop(next_claim);
        if(lo<0){
            /* the committer's stalled cursor chunk, before anything new: one
             * helper (the CAS on HELPING), and not a chunk that is already
             * staged (the owner finished in the meantime) */
            long want=next_claim[DLC_CTL_CURSOR_WANT];
            if(want>=0 && !dlc_stage_exists(want)){
                long cur=next_claim[DLC_CTL_HELPING];
                if(cur!=want && __sync_bool_compare_and_swap(&next_claim[DLC_CTL_HELPING], cur, want)){
                    lo=want; helping=1;
                    __sync_fetch_and_add(&next_claim[DLC_CTL_N_CURSOR_HELP], 1L);
                }
            }
        }
        if(lo<0){
            int waited_ticks=0;                 /* 200 ms each */
            for(;;){
                long peek=next_claim[DLC_CTL_CLAIM], fh=next_claim[DLC_CTL_FIRST_HOLE];
                long anchor=dlc_window_anchor(next_claim[DLC_CTL_APPLIED], fh);   /* the CONNECTED tip when the engine is here (2026-09-10) */
                if(peek>end_h || dlc_window_allows(peek, anchor, g_dlc_window)) break;
                /* The published anchor is up to one 10 s tick old. On the
                 * early chain the window drains in a couple of seconds, so
                 * run 11 (2026-09-07) sat idle between ticks: 32,241 blocks
                 * at five minutes against run 9's 86,000, 512 waits. Blocked
                 * on a stale anchor, ask the parent for a fresh one; wait
                 * only when the frontier really is where the anchor says.
                 * A worker waiting here never fetches the blocking chunk
                 * itself any more: the parent evicts its holder when it
                 * stalls the window (dlc_stall_tick) and the chunk comes
                 * through the retry ring, which this loop keeps checking. */
                next_claim[DLC_CTL_WANT_ANCHOR]=1;   /* the parent rescans within 200 ms; our own reads must not touch our io counters */
                lo=dlc_retry_pop(next_claim); if(lo>=0) break;
                if(waited_ticks==0) __sync_fetch_and_add(&next_claim[DLC_CTL_N_WAIT], 1L);
                usleep(200000); waited_ticks++;
            }
            if(lo<0) lo=__sync_fetch_and_add(next_claim,(long)DLC_CHUNK_BLOCKS);
        }
        if(lo>end_h){ if(fd>=0) close(fd); DLC_RELEASE(); break; }
        long hi=lo+DLC_CHUNK_BLOCKS-1; if(hi>end_h) hi=end_h;
        if(dlc_chunk_all_present(lo,hi)) continue;
        mystat->cur_lo=lo; mystat->cur_hi=hi;                          /* getpeerinfo's inflight */

        unlink(hp_);                       /* DMN-8: stale file from a crashed run */
        int hfd=open(hp_,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
        if(hfd<0){ if(fd>=0) close(fd); DLC_RELEASE(); break; }
        unlink(hp_);                       /* DMN-8: anonymous from here on */
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
                /* ONE linear scan per attempt (dlc_pick_peer): the
                 * highest-EMA unclaimed/unbanned peer when the parent has
                 * speed knowledge, else exactly the old (slot+a)%nlive
                 * rotation. Losing a CAS race simply re-asks -- the peer the
                 * other worker won is now claimed and drops out of the scan. */
                for(int q=0;q<nlive && !ok;q++){
                    int idx=dlc_pick_peer(nlive, slot, ema, claimed, banned, mystat->pool_median_bps*DLC_ROTATE_FRACTION);
                    if(idx<0) break;
                    const char* cand=live[idx];
                    int cp2=0; unsigned ip=0; if(!dlc_parse_peer(cand, &ip, &cp2)) continue;
                    /* claim this peer for exclusive use FIRST -- a real peer
                     * IP is only worth as much as its own bandwidth, so two
                     * workers sharing one starves both instead of using a
                     * second distinct peer that's sitting idle. */
                    if(!__sync_bool_compare_and_swap(&claimed[idx],0,1)) continue;
                    /* the entry's own port when it has one; the chain default is only a
                     * fallback for bare addresses (same rule as the header tries) */
                    { int cpc = cp2 ? cp2 : node_config_peer_port(cand); if(!cpc) cpc = g_chainp->default_port;   /* addnode=host:port keeps its port here too */
                      cp2 = cpc; }
                    if(peer_known_no_witness(cand)){ if(ema[idx]<=0.0) ema[idx]=1.0; claimed[idx]=0; slot=(idx+1)%nlive; continue; }   /* no witness bit: skip before the socket; and no longer "untried" to the picker */
                    dial_gate_wait();
                    int fdc=tcp_connect_ip(ip,(unsigned short)htons((unsigned short)cp2));
                    if(fdc<0){ if(ema[idx]<=0.0) ema[idx]=1.0; claimed[idx]=0; continue; }   /* tried, unreachable: the picker must not offer it as untried again */
                    struct timeval tv; tv.tv_sec=20; tv.tv_usec=0; setsockopt(fdc,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
                    /* 2026-09-06: a getdata is small and is the ONLY thing
                     * standing between this worker and the peer's reply, so
                     * Nagle can only delay it -- and p2p_write sends a message
                     * as more than one segment, which is exactly the shape
                     * that waits for the peer's delayed ACK. Measured on a
                     * loopback fixture: ~45 ms per getdata without, ~5 ms
                     * with the peer ACKing immediately. */
                    { int one=1; setsockopt(fdc,IPPROTO_TCP,TCP_NODELAY,&one,sizeof one); }
                    if(node_handshake(fdc)==1 && peer_has_witness(cand)){
                        fd=fdc; ok=1; held=idx; slot=(idx+1)%nlive;
                        mystat->held_idx=idx;   /* so the parent can ban THIS peer on early-kill */
                        strncpy((char*)mystat->peer,cand,63);
                        { rpc_peer_t v; memset(&v,0,sizeof v); rpc_peer_from_version(&v, g_peer_version_payload, g_peer_version_len);   /* for getpeerinfo */
                          mystat->proto=v.proto; mystat->services=v.services; mystat->start_height=v.start_height;
                          memcpy((char*)mystat->subver, v.subver, sizeof mystat->subver); mystat->conn_time=(long long)time(NULL); mystat->bytes_peer=0; }
                        /* fresh peer -- the displayed chunks/blocks/guard
                         * must reflect THIS connection, not accumulate
                         * across every peer this worker slot has ever
                         * cycled through (that read as "the new peer has
                         * already done N chunks" when really the old, now-
                         * dropped peer did them). */
                        mystat->chunks=0; mystat->blocks=0; mystat->guard=0;
                    }
                    else { if(ema[idx]<=0.0) ema[idx]=1.0; claimed[idx]=0; close(fdc); }   /* handshake or witness failed: same */
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
            mux_sync_budget_fired=0; mux_sync_budget_sig=0;
            ibd_pipeline_set_progress(dlc_chunk_progress, 0);   /* each arriving block re-arms this */
            ibd_pipeline_set_bytes(dlc_chunk_bytes);
            alarm(DLC_CHUNK_BUDGET_SECS);
            /* 2026-09-06: the whole chunk in ONE getdata, blocks placed by
             * hash as they arrive (daemon/ibd_pipeline.c). node_ibd_blocks_s
             * asked for one block and waited for it before asking for the
             * next, so every block cost a full round trip: 16 helpers against
             * 16 real peers moved 0.23-1.2 MB/s each on the fresh-sync
             * benchmark. Core keeps 16 blocks in flight per peer for the same
             * reason. Same validation per block, block for block. */
            long long chunk_t0 = dlc_now_ms(); long chunk_r0 = dlc_proc_rchar(getpid());   /* for the boundary-rotation verdict */
            /* 2026-09-08: the chunk goes to a staging file, not the archive;
             * the committer appends it in height order (see dlc_commit_chunk) */
            char stmp[96]; int sfd=dlc_stage_open_tmp(stmp,sizeof stmp,lo);
            if(sfd<0){ fprintf(stderr,"[dlc w%d] stage: cannot create %s (%s)\n", w, stmp, strerror(errno)); close(fd); fd=-1; DLC_RELEASE(); break; }
            g_stage_fd=sfd; ibd_pipeline_set_sink(dlc_stage_sink);
            long r=ibd_fetch_chunk_pipelined(fd, st, hst, lo, n, buf, (unsigned)sizeof buf, scratch, cap);
            alarm(0); sigaction(SIGALRM,&old,NULL);
            close(sfd); g_stage_fd=-1;
            if(r>=0 && !mux_sync_budget_fired){
                char sfin[64]; dlc_stage_path(sfin,sizeof sfin,lo);
                if(hi <= next_claim[DLC_CTL_COMMIT_TIP]) unlink(stmp);          /* a helper delivered it first: already committed, nothing to publish */
                else if(rename(stmp,sfin)!=0){ fprintf(stderr,"[dlc w%d] stage: cannot publish %s (%s)\n", w, sfin, strerror(errno)); unlink(stmp); r=IBD_FAIL_STORE; }
                else __sync_fetch_and_add(&next_claim[DLC_CTL_STAGED],1L);
            } else unlink(stmp);
            store_reload(st);
            guard++;
            if(mux_sync_budget_fired){
                mystat->timeouts++;   /* covers both the flat budget AND an early-kill signal -- same code path */
                char lastbw[16]; dlc_fmt_rate(lastbw,sizeof lastbw,mystat->last_bw_bps);
                /* the line says WHICH rule fired: the parent's pool-relative
                 * dead-weight verdict (SIGUSR1), or this worker's own stall
                 * clock (SIGALRM: no block for DLC_CHUNK_BUDGET_SECS). Before
                 * 2026-09-07 both printed "dead weight", and 429 of 432 such
                 * lines in one run were the alarm, not the verdict. */
                fprintf(stderr,"[dlc w%d] %s %s (last measured %s, completed %ld chunk(s)/%ld block(s) on this peer); dropping for a fresh peer\n",
                        w, mystat->peer,
                        mux_sync_budget_sig==SIGUSR1 ? (mystat->kill_reason==1 ? "stalling the window (held its oldest missing chunk while it was full)" : "dead weight")
                                                     : "stalled: no block for " DLC_STR(DLC_CHUNK_BUDGET_SECS) "s",
                        lastbw, mystat->chunks, mystat->blocks);
                mystat->kill_reason=0;
                close(fd); fd=-1; DLC_RELEASE();
                slot=(slot+1)%(nlive>0?nlive:1);
                if(guard>400){ fprintf(stderr,"[dlc w%d] reconnect budget [%ld,%ld]\n",w,lo,hi); break; }
                continue;   /* r is unreliable after an EINTR'd read; don't trust it */
            }
            if(r>=0){
                chunk_ok=1;
                /* clean completion. KEEP fd (and claim) for the next chunk --
                 * unless this peer ran under half the pool median over the
                 * chunk, in which case rotate NOW, with nothing in flight and
                 * nothing to discard (see dlc_rotate_after_chunk). Chunks
                 * under 2 s (the early chain) are not judged: round-trip
                 * bound, and the rate would be noise. */
                double secs = (double)(dlc_now_ms() - chunk_t0) / 1000.0;
                long chunk_r1 = dlc_proc_rchar(getpid());
                double chunk_bps = (secs >= 2.0 && chunk_r0 >= 0 && chunk_r1 >= chunk_r0) ? (double)(chunk_r1 - chunk_r0) / secs : -1.0;
                double med = mystat->pool_median_bps;
                if(dlc_rotate_after_chunk(chunk_bps, med) && dlc_replace_allowed((int)next_claim[DLC_CTL_FREE_PEERS])){   /* 2026-09-10: no free peer, no rotation -- the window's tail judges */
                    __sync_fetch_and_add(&next_claim[DLC_CTL_N_ROTATE], 1L);   /* counted on the tick line; nothing is discarded, so no line per event */
                    /* hand the verdict's number to the picker: the parent's
                     * tick-EMA lags (alpha 0.5 over 10 s ticks), and a peer
                     * whose EMA still read above the bar was re-picked 17
                     * times in five minutes on the 2026-09-07 scratch node. */
                    { long hi = mystat->held_idx; if(hi>=0 && hi<nlive) ema[hi] = chunk_bps; }
                    close(fd); fd=-1; DLC_RELEASE();
                    slot=(slot+1)%(nlive>0?nlive:1);
                }
                break;
            }
            /* the chunk failed on this peer. Say WHY -- the first three times
             * and every hundredth after: run 10 (2026-09-07) had a worker
             * fail 400 chunks in 45 s and abandon the chunk with no line
             * between the rotation before it and "reconnect budget". */
            __sync_fetch_and_add(&next_claim[DLC_CTL_N_FAIL], 1L);
            { long hi_=mystat->held_idx; if(hi_>=0 && hi_<nlive) ema[hi_]=dlc_ema_after_failure(ema[hi_]); }   /* the picker must move on */
            if(guard==3 || guard%100==0)      /* one peer failing once is normal; three in a row on one chunk is worth a line */
                fprintf(stderr,"[dlc w%d] %s: chunk [%ld,%ld] attempt %d failed after %ld ms: %s (code %ld)\n",
                        w, mystat->peer, lo, hi, guard, (long)(dlc_now_ms()-chunk_t0), ibd_pipeline_fail_name((int)r), r);
            close(fd); fd=-1; DLC_RELEASE();
            slot=(slot+1)%(nlive>0?nlive:1);
            if(guard>400){ fprintf(stderr,"[dlc w%d] reconnect budget [%ld,%ld]\n",w,lo,hi); break; }
            usleep((useconds_t)(dlc_fail_backoff_ms(guard)*1000));   /* do not hammer the pool: 12 reconnects/s was run 14's stall */
        }
        close(hfd);
        if(helping) __sync_bool_compare_and_swap(&next_claim[DLC_CTL_HELPING], lo, -1L);   /* the help is over, whichever way */
        if(chunk_ok){
            total+=n; __sync_fetch_and_add(done_count,n);
            mystat->chunks++; mystat->blocks+=n; mystat->guard+=guard;
        } else {
            int q=dlc_retry_push(next_claim, lo);
            __sync_fetch_and_add(&next_claim[DLC_CTL_N_ABANDON], 1L);
            fprintf(stderr,"[dlc w%d] chunk [%ld,%ld] ABANDONED -> %s\n",w,lo,hi, q ? "retry ring (another worker will take it)" : "retry ring FULL; left for the next pass");
        }
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
 * live+handshaked candidates into live[] / *nlive (capped at cap). Never
 * blocks longer than wait_ms regardless of how many candidates in this
 * batch are dead or black-holed -- poll() naturally times out, unlike a
 * blocking connect() to an unreachable host. Same technique as the parallel
 * dial in serve_download_worker above; caps the batch at MUX_MAX_OUT*3 (24)
 * per round to match its proven behavior (trying the WHOLE pool at once in
 * one round measurably tanks the success rate -- observed 1/140 live).
 * Returns how many were promoted this round. */
static int dlc_probe_round(char pool[][DL_POOL_SLOT], int from, int ntry,
                           char live[][DL_POOL_SLOT], int* nlive, int cap, int wait_ms){
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
        { int cp = pport ? pport : node_config_peer_port(pool[i]);   /* addnode=host:port / connect=host:port keep their port */
          sa.sin_addr.s_addr=ip; sa.sin_port=(unsigned short)htons((unsigned short)(cp ? cp : g_chainp->default_port)); }
        dial_gate_wait();
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
        snprintf(live[*nlive],sizeof live[*nlive],"%s",pool[from+k]); (*nlive)++; got++;
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

/* ---- Step 1 of docs/audits/UTXO_INLINE_BUILD_PERF_SCOPE.md (2026-09-06):
 * the knobs of the interleaved connect, and the helper-stop used by both the
 * shutdown path and a mid-download rejection. Plain statics rather than
 * config: the budget/idle pair is a scheduling detail of one loop, and the
 * tests (tests/test_dlc_interleave, which includes this TU) set them. */
#define DLC_CONNECT_BUDGET_MS 8000L   /* one connect pass: the scope's ~8 s */
#define DLC_IDLE_MS           2000L   /* nothing connectable: the scope's ~2 s */
#define DLC_STATUS_MS        10000L   /* the peer-status table's cadence (was the loop's nanosleep) */
#define DLC_CONNECT_RETRY_MS 30000L   /* after a connect FAILURE (not a hole): keep downloading, retry later */
static int  g_dlc_interleave        = 1;                     /* test seam: 0 = the pre-step-1 loop */
static long g_dlc_connect_budget_ms = DLC_CONNECT_BUDGET_MS;
static long g_dlc_idle_ms           = DLC_IDLE_MS;
static pid_t* g_dlc_kids = NULL;   /* dl_catchup's helper pids while it runs; NULL otherwise */
static int    g_dlc_nw   = 0;
static void dl_new_block_choke(void);   /* the 3.1 choke point, defined with the worker below */
static long long dlc_now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return ts.tv_sec*1000LL + ts.tv_nsec/1000000LL; }
/* Tell every live helper to stop, give it a moment, then kill and reap it.
 * Workers inherit the flag-only SIGTERM handler, so SIGTERM is advisory and
 * the SIGKILL a second later is what actually ends a helper blocked in a
 * socket read. kids[w] is zeroed for every stopped helper. */
static void dlc_stop_workers(pid_t* kids, int nw, const char* why){
    int n = 0; for(int w=0;w<nw;w++) if(kids[w]) n++;
    if(!n) return;
    fprintf(stderr,"[dlc] %s -- stopping %d worker(s)\n", why, n);
    for(int w=0;w<nw;w++) if(kids[w]) kill(kids[w], SIGTERM);
    { struct timespec g={1,0}; nanosleep(&g,NULL); }
    for(int w=0;w<nw;w++) if(kids[w]){ int stt; if(waitpid(kids[w],&stt,WNOHANG)==0){ kill(kids[w], SIGKILL); waitpid(kids[w],&stt,0); } kids[w]=0; }
    dlc_stop_committer();                       /* before anything truncates the archive under it */
}
/* The reject hook's half (see dl_reject_block): a no-op unless dl_catchup is
 * running in this process right now. */
static void dlc_stop_workers_for_reject(long h){
    if(!g_dlc_kids || g_dlc_nw <= 0) return;
    char why[96]; snprintf(why, sizeof why, "block %ld rejected mid-download", h);
    dlc_stop_workers(g_dlc_kids, g_dlc_nw, why);
}

/* ---- rank the live pool by a measured throughput sample (2026-09-06) --------
 * dlc_probe_round measures ONE thing: whether a TCP connect succeeds. Every
 * "confirmed-live" peer is then equal, and the 16 workers claim them in
 * whatever order the DNS seeds happened to return. Measured on a fresh sync:
 * 119 live peers, the first eviction at 249 s, hundreds of evictions after --
 * four minutes of the phase that decides the wall clock, spent discovering
 * by trial that most of the pool trickles at 2 KB/s. Being impatient about
 * evicting was tried first and made it WORSE (4x fewer blocks in the same
 * time): churn costs a handshake and abandons partial chunk work every time.
 *
 * So measure once, up front. Each live peer gets one getheaders for the
 * 2,000 headers after genesis -- ~162 KB from any synced peer -- timed from
 * request to reply; the pool is then sorted fastest-first, so the worker
 * slots start on the best peers instead of finding them by elimination.
 * Forked probes, 32 at a time, each under its own alarm(), writing into a
 * shared page: the same shape dlc_worker uses, and nothing the parent does
 * can hang on a silent peer. A peer that does not answer ranks last, which
 * is where a peer that does not answer belongs. */
#define RANK_BATCH 32
#define RANK_TIMEOUT_S 10
static void dlc_rank_by_throughput(char live[][DL_POOL_SLOT], int nlive){
    if (nlive < 2) return;
    double* rate = mmap(NULL, sizeof(double) * (size_t)nlive, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (rate == MAP_FAILED) return;
    long* ann = mmap(NULL, sizeof(long) * (size_t)nlive, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);   /* announced heights, from the same handshakes (2026-09-09) */
    if (ann == MAP_FAILED){ munmap(rate, sizeof(double) * (size_t)nlive); return; }
    for (int i = 0; i < nlive; i++){ rate[i] = -1.0; ann[i] = 0; }
    unsigned char stop[32]; memset(stop, 0, 32);
    struct timespec t_all0; clock_gettime(CLOCK_MONOTONIC, &t_all0);
    for (int base = 0; base < nlive; base += RANK_BATCH){
        int n = nlive - base; if (n > RANK_BATCH) n = RANK_BATCH;
        pid_t kids[RANK_BATCH];
        for (int k = 0; k < n; k++){
            int i = base + k;
            pid_t pid = fork();
            if (pid < 0){ kids[k] = 0; continue; }
            if (pid == 0){
                alarm(RANK_TIMEOUT_S);                          /* nothing below may outlive this */
                int pport = 0; unsigned ip = pool_ipv4(live[i], &pport);
                if (!ip) _exit(0);
                int cp = pport ? pport : node_config_peer_port(live[i]); if (!cp) cp = g_chainp->default_port;
                dial_gate_wait();
                int fd = tcp_connect_ip(ip, (unsigned short)htons((unsigned short)cp));
                if (fd < 0) _exit(0);
                struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
                if (node_handshake(fd) != 1) _exit(0);
                { rpc_peer_t v; memset(&v, 0, sizeof v); rpc_peer_from_version(&v, g_peer_version_payload, g_peer_version_len); if (v.start_height > 0) ann[i] = v.start_height; }   /* the announced height, parsed as getpeerinfo does (the relay byte follows it) */
                static unsigned char page[4096]; static unsigned char msg[2 << 20]; char cmd[12]; unsigned mlen = 0;
                long plen = p2p_getheaders(page, g_chainp->genesis_hash, 1, stop);
                struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
                if (plen <= 0 || p2p_write(fd, "getheaders", 10, page, (unsigned)plen) < 0) _exit(0);
                long bytes = 0;
                for (int q = 0; q < 40; q++){
                    int r = p2p_read(fd, cmd, msg, sizeof msg, &mlen);
                    if (r <= 0) break;
                    if (!strncmp(cmd, "headers", 12)){ bytes = (long)mlen; break; }
                    if (!strncmp(cmd, "ping", 12) && mlen == 8) p2p_write(fd, "pong", 4, msg, 8);
                }
                clock_gettime(CLOCK_MONOTONIC, &t1);
                double secs = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
                if (bytes > 0 && secs > 0.0) rate[i] = (double)bytes / secs;
                close(fd); _exit(0);
            }
            kids[k] = pid;
        }
        for (int k = 0; k < n; k++) if (kids[k] > 0){ int st; waitpid(kids[k], &st, 0); }
    }
    /* sort fastest first; a peer with no sample ranks last, ties keep order */
    static int idx[DLC_MAXPOOL]; for (int i = 0; i < nlive; i++) idx[i] = i;
    for (int i = 1; i < nlive; i++){
        int v = idx[i]; int j = i - 1;
        while (j >= 0 && rate[idx[j]] < rate[v]){ idx[j + 1] = idx[j]; j--; }
        idx[j + 1] = v;
    }
    static char sorted[DLC_MAXPOOL][DL_POOL_SLOT];
    for (int i = 0; i < nlive; i++) memcpy(sorted[i], live[idx[i]], DL_POOL_SLOT);
    for (int i = 0; i < nlive; i++) memcpy(live[i], sorted[i], DL_POOL_SLOT);
    { static long sorted_ann[DLC_MAXPOOL]; for (int i = 0; i < nlive; i++) sorted_ann[i] = ann[idx[i]]; for (int i = 0; i < nlive; i++) g_live_announced[i] = sorted_ann[i]; for (int i = nlive; i < DLC_MAXPOOL; i++) g_live_announced[i] = 0;
      long announced = dlc_announced_height(g_live_announced, nlive); int claimed = 0; for (int i = 0; i < nlive; i++) if (g_live_announced[i] > 0) claimed++;
      fprintf(stderr, "[dlc] the pool announces height %ld (%d of %d peers claimed one; the median claim counts)\n", announced, claimed, nlive);
      munmap(ann, sizeof(long) * (size_t)nlive); }
    int answered = 0; double best = 0.0, worst_answered = 0.0;
    for (int i = 0; i < nlive; i++) if (rate[idx[i]] >= 0.0){ answered++; if (best == 0.0) best = rate[idx[i]]; worst_answered = rate[idx[i]]; }
    double median = answered ? rate[idx[answered / 2]] : 0.0;
    struct timespec t_all1; clock_gettime(CLOCK_MONOTONIC, &t_all1);
    fprintf(stderr, "[dlc] ranked %d live peer(s) by a 2000-header sample in %.1fs: %d answered, best %.0f KB/s, median %.0f KB/s, slowest answering %.0f KB/s; the %d silent rank last\n",
            nlive, (double)(t_all1.tv_sec - t_all0.tv_sec) + (double)(t_all1.tv_nsec - t_all0.tv_nsec) / 1e9,
            answered, best / 1024.0, median / 1024.0, worst_answered / 1024.0, nlive - answered);
    for (int i = 0; i < nlive && i < 3; i++)
        fprintf(stderr, "[dlc]   #%d %-22s %.0f KB/s\n", i + 1, live[i], rate[idx[i]] > 0 ? rate[idx[i]] / 1024.0 : 0.0);
    munmap(rate, sizeof(double) * (size_t)nlive);
}
/* ---- Core's stall rule (2026-09-10) ----------------------------------------
 * The one judge of slowness in Core's downloader: when the window is full
 * (nothing more can be requested above the connected tip) and one peer
 * holds the OLDEST missing block, that peer has the stall timeout -- 2 s,
 * doubling to 64 s when evictions come fast, easing back as the tail moves
 * -- before it is disconnected and its block re-requested elsewhere. Here
 * the tail is the committer's cursor chunk (the archive's first hole, on
 * the claim grid); it is stalled only while the window is full, the chunk
 * is not staged, and a live worker holds it. The eviction is the same
 * SIGUSR1 the rate floor used, labelled; the abandoned chunk goes to the
 * retry ring, which the workers idle at the window are already polling.
 * Every 200 ms from the parent's idle steps and once per connect pass. */
static long g_dlc_stall_timeout_s = DLC_STALL_TIMEOUT_MIN_S;
static void dlc_stall_tick(volatile long* ctl, volatile dlc_stat_t* stats, pid_t* kids, pid_t* opid, int nw,
                           long start_h, long end_h, long long now_ms){
    static long tail = -1; static long long since = 0; static int holder = -1;
    long fh = ctl[DLC_CTL_FIRST_HOLE];
    if(fh > end_h){ tail = -1; holder = -1; return; }
    long lo = dlc_help_chunk_lo(fh, start_h);
    long anchor = dlc_window_anchor(ctl[DLC_CTL_APPLIED], fh);
    long claim = ctl[DLC_CTL_CLAIM];
    int full = claim <= end_h && !dlc_window_allows(claim, anchor, g_dlc_window);
    if(lo != tail){                                            /* the tail moved: the timeout eases (Core: on a block received) */
        if(tail >= 0) g_dlc_stall_timeout_s = dlc_stall_timeout_after(g_dlc_stall_timeout_s, 0);
        tail = lo; holder = -1; since = now_ms;
    }
    if(!full || dlc_stage_exists(lo)){ holder = -1; since = now_ms; return; }   /* not a stall: room to request, or the chunk is already here */
    int w = -1; for(int i = 0; i < nw; i++) if(kids[i] && stats[i].cur_lo == lo){ w = i; break; }
    if(w < 0){ holder = -1; since = now_ms; return; }        /* nobody holds it: it is in the retry ring or the cursor help's */
    if(w != holder){ holder = w; since = now_ms; return; }   /* a new holder gets a fresh clock */
    if(!dlc_tail_stalled(full, (long)(now_ms - since), g_dlc_stall_timeout_s)) return;
    stats[w].kill_reason = 1;
    kill(opid[w], SIGUSR1);
    __sync_fetch_and_add(&ctl[DLC_CTL_N_STALL], 1L);
    fprintf(stderr,"[dlc] w%d %s is stalling the window: chunk [%ld,%ld] is the oldest missing and the window (%ld above %ld) is full -- dropped after %ld s (next timeout %ld s)\n",
            w, stats[w].peer[0] ? (const char*)stats[w].peer : "(connecting)", lo, lo + DLC_CHUNK_BLOCKS - 1, g_dlc_window, anchor,
            (long)((now_ms - since) / 1000), dlc_stall_timeout_after(g_dlc_stall_timeout_s, 1));
    g_dlc_stall_timeout_s = dlc_stall_timeout_after(g_dlc_stall_timeout_s, 1);
    holder = -1; since = now_ms;
}
/* the window's anchor: the connected tip + 1 when the engine is in this process */
static void dlc_publish_applied(volatile long* ctl){
    ctl[DLC_CTL_APPLIED] = g_utxo_live_on ? utxo_live_applied_height() + 1 : -1;
}
static long dl_catchup(const char* dir, int min_workers){
    (void)dir; /* CWD is already the data dir; kept for logging/API clarity */
    ab2_t* ab = addr_book();
    if(!ab){ fprintf(stderr,"[dlc] address book unavailable\n"); return 0; }
    long disc=dl_bootstrap(ab, (const char**)g_seed_hosts, g_n_seed_hosts);
    fprintf(stderr,"[dlc] discovered +%ld peers (book now %ld)\n", disc, (long)ab2_count(ab));

    static char pool[DLC_MAXPOOL][DL_POOL_SLOT];
    static double good_ema[DLC_MAXPOOL];
    for(int i=0;i<DLC_MAXPOOL;i++) good_ema[i]=0.0;
    int npool = 0, ngood = 0, nadd = 0;
    if(g_cfg.connect_only){
        /* Core -connect: the pool IS the configured list. Nothing from the
         * book, nothing from peers.good -- an operator who pins the node to
         * two nodes must not find it downloading from two hundred. */
        for(int i=0;i<g_cfg.n_connect && npool<DLC_MAXPOOL;i++){
            char ipd[64];
            if(!dl_resolve1(g_cfg.connectn[i], ipd)){
                fprintf(stderr,"[dlc] connect=%s did not resolve\n", g_cfg.connectn[i]); continue; }
            snprintf(pool[npool],sizeof pool[npool],"%s",ipd); npool++;
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
            snprintf(pool[npool],sizeof pool[npool],"%s",ipd); npool++; nadd++;
        }
        ngood = dl_load_good_peers_ema(pool+npool, good_ema+npool, DLC_MAXPOOL-npool);
        npool += ngood;
        {
            static char book[DLC_MAXPOOL][DL_POOL_SLOT];
            int nbook = dl_pool_from_book(ab, book, DLC_MAXPOOL);
            for(int i=0;i<nbook && npool<DLC_MAXPOOL;i++){
                int dup=0;
                for(int j=0;j<npool;j++) if(!strcmp(book[i],pool[j])){ dup=1; break; }
                if(dup) continue;
                { size_t l = strnlen(book[i], sizeof pool[npool] - 1); memcpy(pool[npool], book[i], l); pool[npool][l] = 0; } npool++;   /* full slot: a v3 onion host:port is 67 bytes, 63 cut it */
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
        int want = min_workers*2; if(want>npool) want=npool;   /* 2026-09-10: every live peer downloads, so the pool need not be six deep per worker */
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
            /* addr_replenish (daemon/addr_ingest.c) reads a [][64] table; live[] is
             * [][DL_POOL_SLOT], so hand it a copy with the stride it expects */
            { static char rep[DLC_MAXPOOL][64];
              for(int i=0;i<nlive;i++){ size_t l = strnlen(live[i], 63); memcpy(rep[i], live[i], l); rep[i][l] = 0; }
              addr_replenish(ab, rep, nlive, 3 /* ask at most 3 */, 20 /* seconds each */, 400); }
        }
    }
    if(nlive<=0){ fprintf(stderr,"[dlc] no live peers; skipping catch-up\n"); return 0; }
    dlc_rank_by_throughput(live, nlive);      /* fastest first: the workers claim from the top */
    /* Core's shape (2026-09-10): every live peer downloads, up to the cap
     * (bmc.catchupworkers, default 64) -- a fixed 16 against 124 live peers
     * carried 11 MB/s on a 2.5 Gbit link, the sum of 16 peers at 250-600
     * KB/s. The window scales with what is in flight and is anchored to the
     * connected tip; the parent evicts a peer that stalls the window's
     * tail; rotation and the rate floor act only while a free peer exists. */
    int nw = dlc_workers_for(nlive, min_workers);
    g_dlc_window = dlc_window_blocks(nw, DLC_CHUNK_BLOCKS);
    g_dlc_stall_timeout_s = DLC_STALL_TIMEOUT_MIN_S;
    fprintf(stderr,"[dlc] Core's shape: %d of %d live peer(s) download at once (cap %d), window %ld blocks above the connected tip, stall timeout %ld s\n",
            nw, nlive, min_workers, g_dlc_window, g_dlc_stall_timeout_s);

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

    volatile long* next_claim=mmap(NULL,DLC_CTL_BYTES,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);   /* the control block: see DLC_CTL_* */
    volatile long* done_count=mmap(NULL,sizeof(long),PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    volatile dlc_stat_t* stats=mmap(NULL,sizeof(dlc_stat_t)*(size_t)nw,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    /* one claim flag per live[] peer -- __sync_bool_compare_and_swap makes
     * "pick an unclaimed peer" atomic across all forked workers, so no two
     * workers ever share one peer's bandwidth while a distinct live peer
     * sits unused. */
    /* the no-NODE_WITNESS set, shared with every forked helper so the bit is
     * learned ONCE for the whole download rather than once per helper
     * (2026-09-06: 16 helpers meant 16 identical log lines per address). */
    { void* nw = mmap(NULL, peer_nowit_bytes(), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
      if (nw != MAP_FAILED){ memset(nw, 0, peer_nowit_bytes()); peer_nowit_attach(nw); }
      void* dm = mmap(NULL, dialmem_bytes(DIALMEM_CAP), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
      if (dm != MAP_FAILED){ dialmem_init(dm, DIALMEM_CAP); g_dialmem = (dm_table_t*)dm; } }
    volatile int* claimed=mmap(NULL,sizeof(int)*(size_t)nlive,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    /* Peers evicted for sustained uselessness are banned for the REST OF THE
     * RUN. Without this the replacement draw is memoryless: a worker killed
     * for trickling at 5KB/s could immediately be handed the same IP again,
     * and with most of the pool being duds that is what kept happening. */
    volatile int* banned=mmap(NULL,sizeof(int)*(size_t)nlive,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    /* Per-peer EMA of measured bytes/s (PEER_PLAN item 4). The parent's 10s
     * status tick already samples every worker's /proc io for the live
     * display and threw the number away; this is where it accumulates
     * (alpha 0.5, half-life ~20s). dlc_worker reads it to claim the FASTEST
     * free peer instead of the next slot in rotation. MAP_SHARED so all
     * forked workers see the parent's writes; MAP_ANONYMOUS zero-init means
     * "no speed knowledge yet" == today's rotation. */
    volatile double* ema=mmap(NULL,sizeof(double)*(size_t)nlive,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(next_claim==MAP_FAILED || done_count==MAP_FAILED || stats==MAP_FAILED || claimed==MAP_FAILED || banned==MAP_FAILED || ema==MAP_FAILED){ fprintf(stderr,"[dlc] mmap failed: %s\n", strerror(errno)); return 0; }
    /* seed the EMA from the previous run's recorded speeds (peers.good
     * "ip\tema_kbps"): run N+1 starts with run N's knowledge. live[] keeps
     * pool[] ORDER (dlc_probe_round appends from `pool` in sequence -- a
     * dedup here would misalign the indexes), so the first `ngood` pool
     * entries after the addnode block are exactly the loaded ones; every
     * other live entry stays 0 == rotation until measured. */
    if(ngood>0){
        int seed=0;
        for(int i=0;i<nlive;i++){
            for(int j=0;j<ngood;j++){
                int k = nadd + j; if(k>=npool) continue;
                if(!strcmp(live[i],pool[k])){ ema[i]=good_ema[j]; seed++; break; }
            }
        }
        if(seed) fprintf(stderr,"[dlc] seeded EMA speed for %d of %d live peer(s) from the previous run\n", seed, nlive);
    }
    /* MAP_ANONYMOUS zero-fills, so held_idx would default to 0 -- and a
     * worker that never managed to connect would then make the parent ban
     * live[0], a peer that may be perfectly good. Mark "holding nothing"
     * explicitly. */
    for(int i=0;i<nw;i++) stats[i].held_idx = -1;
    *next_claim=start_h; *done_count=0;
    next_claim[DLC_CTL_RETRY_HEAD]=0; next_claim[DLC_CTL_RETRY_TAIL]=0; next_claim[DLC_CTL_FIRST_HOLE]=start_h; next_claim[DLC_CTL_HELPING]=-1; next_claim[DLC_CTL_WANT_ANCHOR]=0; next_claim[DLC_CTL_SPAN_START]=start_h;   /* window starts at the span start; nobody helping */
    for(long i=0;i<DLC_RETRY_MAX;i++) next_claim[DLC_CTL_RING+i]=-1;   /* -1 = empty slot (0 is a real chunk) */
    for(int i=DLC_CTL_N_ROTATE;i<=DLC_CTL_N_ABANDON;i++) next_claim[i]=0;
    next_claim[DLC_CTL_COMMIT_TIP]=start_h-1; next_claim[DLC_CTL_STAGED]=0; next_claim[DLC_CTL_N_COMMIT]=0; next_claim[DLC_CTL_STOP_COMMIT]=0;
    next_claim[DLC_CTL_CURSOR_WANT]=-1; next_claim[DLC_CTL_N_CURSOR_HELP]=0;
    next_claim[DLC_CTL_APPLIED]=-1; next_claim[DLC_CTL_FREE_PEERS]=0; next_claim[DLC_CTL_N_STALL]=0;
    { long stale=dlc_stage_wipe(); if(stale) fprintf(stderr,"[dlc] stage: discarded %ld file(s) an earlier run left; their chunks are fetched again\n", stale); }
    { pid_t cp=fork(); if(cp==0){ _exit(dlc_committer_main(next_claim, start_h, end_h, getppid())); } g_dlc_committer=cp; }
    /* MAP_ANONYMOUS pages come zeroed, so every stats[w].peer/chunks/blocks/
     * guard and every claimed[i] starts at "" / 0 / 0 / 0 / 0 -- no explicit
     * init needed. */

    time_t catchup_start=time(NULL); /* for the elapsed-time display in the status loop below */
    pid_t kids[64]; pid_t opid[64];
    for(int w=0;w<nw;w++){
        pid_t p=fork();
        if(p==0){ _exit(dlc_worker(w, end_h, live, nlive, w, next_claim, done_count, &stats[w], claimed, banned, ema)); }
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
    enum { ETA_W = 61 };                     /* 61 ticks of 10 s: the ETA's ten-minute rate window */
    long eta_present[ETA_W]; long long eta_ms[ETA_W]; int eta_n=0, eta_i=0;
    long nbanned=0;
    double cumulative_bytes=0.0;       /* running total network-received, across the whole call */
    double cumulative_write_bytes=0.0; /* running total actually written to disk, across the whole call */
    /* ---- Step 1 of docs/audits/UTXO_INLINE_BUILD_PERF_SCOPE.md (2026-09-06):
     * connect INSIDE the download loop. This loop used to nanosleep(10 s) and
     * print for the whole download (19.5 h on the 2026-09-04 bench) while the
     * 4.5 h of UTXO connect waited for it to return. Now each pass, when this
     * process owns the UTXO set, connects the contiguous prefix the helpers
     * have delivered -- utxo_live_catchup_bounded with a DLC_CONNECT_BUDGET_MS
     * budget, stopping at the first hole -- and idles DLC_IDLE_MS only when
     * nothing was connectable. Every block goes through the same loop body
     * as the unbounded call (verify workers, LSM, checkpoint cadence, the
     * apply hook that publishes the connected tip, the shutdown flag), and
     * the new-block choke point fires after each pass, so announcements,
     * ZMQ, the index tails and the mempool follow the CONNECTED tip during
     * the download. The peer-status table, the dead-weight kills and the EMA
     * keep their 10 s cadence (DLC_STATUS_MS) whatever a connect pass took,
     * with every per-tick rate divided by the tick's REAL length.
     *
     * SINGLE WRITER, unchanged. The helpers write blocks and index records
     * (store_append_shared under append.lock) and never touch the UTXO set;
     * this process -- the download worker, the one and only utxo_lsm_put/del
     * caller -- is what connects. The read side is a pread by height of a
     * record a helper has already published under the lock, and the
     * contiguous-prefix rule means no height is read while a helper is still
     * writing it. The boot-time PARENT has no UTXO engine (utxo_live_init
     * runs in the worker; g_utxo_live_on is 0 here), so a boot catch-up
     * (bmc.bootcatchup=1) still connects afterwards through the worker's
     * drain; the far-behind trigger's run in the worker interleaves.
     * g_dlc_interleave is the test seam (test_dlc_interleave's control).
     *
     * A block REJECTED mid-download (3.3): the reject hook stops the helpers
     * BEFORE chain_invalidate_block truncates the archive under them (see
     * dl_reject_block), this loop reaps them and returns, the rotation's legs
     * take the heavier chain that avoids the mark, and the far-behind trigger
     * re-runs the parallel download on it if the node is still DL_PARALLEL_GAP
     * behind. A connect FAILURE that is not a rejection (a store error, the
     * halt) does NOT stop the download: connect backs off DLC_CONNECT_RETRY_MS
     * and the rotation's recovery path owns the failure once the download is
     * done, exactly as it did when connect only ran afterwards. */
    int interleave = g_dlc_interleave && g_utxo_live_on;
    g_dlc_kids = kids; g_dlc_nw = nw;
    long conn_total = 0;                       /* blocks connected by this call's passes */
    long long last_status_ms = dlc_now_ms(), connect_retry_ms = 0;
    int alive=nw;
    int dlc_table_this_tick = 1;
    while(alive>0){
        long done = 0;
        if(next_claim[DLC_CTL_WANT_ANCHOR]) dlc_publish_anchor(next_claim, start_h);   /* before a connect call that may run for seconds */
        dlc_stall_tick(next_claim, stats, kids, opid, nw, start_h, end_h, dlc_now_ms());   /* Core's rule, every pass (2026-09-10) */
        if(interleave && dlc_now_ms() >= connect_retry_ms){
            /* (store_reload is the bounded call's first act, so it sees the
             * helpers' appends; a second one here would be redundant.) */
            done = utxo_live_catchup_bounded(store_buf, g_dlc_connect_budget_ms, 1);
            dlc_publish_applied(next_claim);                          /* the window's anchor moves with the connected tip */
            if(done > 0){ conn_total += done; dl_new_block_choke(); }
            if(utxo_live_call_rejected_height() >= 0){
                fprintf(stderr,"[dlc] block at height %ld REJECTED (%s) and invalidated mid-download -- helpers stopped, connected %ld; "
                               "the rotation fetches the chain that avoids it\n",
                        utxo_live_call_rejected_height(), utxo_live_last_reject(), utxo_live_applied_height());
            } else if(done < 0){
                fprintf(stderr,"[dlc] connect FAILED at height %ld (%s) -- the download continues; connect retries in %lds, "
                               "the rotation's recovery path owns it after the download\n",
                        utxo_live_applied_height()+1, utxo_live_fail_kind_name(utxo_live_last_fail_kind()), DLC_CONNECT_RETRY_MS/1000);
                connect_retry_ms = dlc_now_ms() + DLC_CONNECT_RETRY_MS;
            }
        }
        if(done <= 0){
            long ms = interleave ? g_dlc_idle_ms : 10000L;   /* the pre-step-1 loop: sleep 10 s, print */
            /* sleep in 200 ms steps so a worker blocked at the window gets a
             * fresh anchor without waiting for the 10 s tick */
            for(long slept=0; slept<ms; slept+=200){
                if(next_claim[DLC_CTL_WANT_ANCHOR]) dlc_publish_anchor(next_claim, start_h);
                dlc_stall_tick(next_claim, stats, kids, opid, nw, start_h, end_h, dlc_now_ms());
                long step = ms-slept < 200 ? ms-slept : 200;
                struct timespec ts={step/1000,(step%1000)*1000000L}; nanosleep(&ts,NULL);
            }
        }
        if(g_shutdown_requested){
            /* incident 2026-09-01: this loop ignored SIGTERM and the stop hung
             * until a SIGKILL. Workers inherit the flag-only handler, so they
             * are told, given a moment, then killed. */
            dlc_stop_workers(kids, nw, "shutdown requested");
            alive=0; break;
        }
        if(g_dlc_committer>0){                 /* the committer died under us: restart it (its state is the archive itself) */
            int cst; if(waitpid(g_dlc_committer,&cst,WNOHANG)>0){
                fprintf(stderr,"[dlc] committer exited unexpectedly (status %d) -- restarting it\n", cst);
                pid_t cp=fork(); if(cp==0){ _exit(dlc_committer_main(next_claim, start_h, end_h, getppid())); } g_dlc_committer=cp;
            }
        }
        alive=0;
        for(int w=0;w<nw;w++){
            if(kids[w]==0) continue;
            int stt; pid_t r=waitpid(kids[w],&stt,WNOHANG);
            if(r==0) alive++; else kids[w]=0;
        }
        if(alive==0) dlc_drain_committer(next_claim);   /* the final tick below shows the finished archive */
        /* everything below is the 10 s status tick; a connect pass that
         * returned early (a hole, or the idle sleep) does not add a tick */
        long long now_ms = dlc_now_ms();
        if(alive > 0 && now_ms - last_status_ms < DLC_STATUS_MS) continue;
        double tick_s = (double)(now_ms - last_status_ms) / 1000.0; if(tick_s < 1.0) tick_s = 1.0;
        last_status_ms = now_ms;
        {
            long cur_tip, present;
            dlc_scan_progress(&cur_tip, &present);
            long holes = cur_tip>=0 ? (cur_tip+1-present) : 0;
            /* "holes" was the wrong word (2026-09-07): with 16 workers on
             * 40-block chunks a few hundred heights are always claimed and
             * not yet landed -- that is the download's work in progress,
             * bounded by the window, not blocks nobody will fetch. The
             * line now says "in flight", and separately how long the
             * OLDEST gap has been the first hole: a gap that outlives the
             * window's help timeout many times over is the one to read
             * about, and it is printed as STRANDED. */
            long fh0 = cur_tip>=0 ? dlc_first_hole(cur_tip) : -1;          /* the window's anchor, for the workers */
            next_claim[DLC_CTL_FIRST_HOLE] = fh0>=0 ? fh0 : (cur_tip>=0 ? cur_tip+1 : start_h);
            static long gap_h = -1; static long long gap_since_ms = 0; long gap_age_s = 0;
            if(fh0 != gap_h){ gap_h = fh0; gap_since_ms = now_ms; }
            if(fh0 >= 0) gap_age_s = (long)((now_ms - gap_since_ms)/1000);
            char gapbuf[96];
            if(fh0 < 0) snprintf(gapbuf, sizeof gapbuf, "no gap");
            else if(gap_age_s >= 60) snprintf(gapbuf, sizeof gapbuf, "STRANDED: height %ld has been the oldest gap for %lds", fh0, gap_age_s);
            else snprintf(gapbuf, sizeof gapbuf, "oldest gap %lds at %ld", gap_age_s, fh0);
            double overall_pct = 100.0*(double)present/(double)(end_h+1);
            double span_pct = cur_tip>=0 ? 100.0*(double)present/(double)(cur_tip+1) : 0.0;
            char elapsed[32]; dlc_fmt_elapsed(elapsed,sizeof elapsed,(long)(time(NULL)-catchup_start));
            /* ETA (DD:HH:MM:SS) at the block rate of the last ten minutes:
             * the oldest entry in the ring is the one about to be overwritten */
            char etabuf[24];
            { long eta = -1;
              if(eta_n >= 2){ int oldest = eta_n < ETA_W ? 0 : eta_i;
                              eta = dlc_eta_secs(end_h+1-present, present-eta_present[oldest], (double)(now_ms-eta_ms[oldest])/1000.0); }
              eta_present[eta_i] = present; eta_ms[eta_i] = now_ms;
              eta_i = (eta_i+1) % ETA_W; if(eta_n < ETA_W) eta_n++;
              dlc_fmt_eta(etabuf,sizeof etabuf,eta); }
            /* applied = the connected tip; lag = blocks on disk in the
             * contiguous prefix that connect has not reached yet (the only
             * lag connect could close -- a hole is the download's, not ours) */
            char connbuf[128];
            if(g_utxo_live_on){
                long applied = utxo_live_applied_height();
                long fh = cur_tip>=0 ? dlc_first_hole(cur_tip) : -1;
                long prefix = fh>=0 ? fh-1 : cur_tip;
                long lag = prefix - applied; if(lag < 0) lag = 0;
                snprintf(connbuf,sizeof connbuf," | applied=%ld lag=%ld%s", applied, lag, interleave ? "" : " (interleave off)");
            } else snprintf(connbuf,sizeof connbuf," | connect deferred (no UTXO engine in this process)");
            fprintf(stderr,"[dlc] == elapsed %s | eta %s | overall: %ld/%ld stored (%.2f%% of real tip) | in flight %ld of window %ld through %ld (%s, %.2f%% landed)%s ==\n",
                    elapsed, etabuf, present, end_h+1, overall_pct, holes, g_dlc_window, cur_tip, gapbuf, span_pct, connbuf);
        }
        /* 2026-09-08: the tick's seven dashed lines became ONE, printed at the
         * end of the tick when every number exists (recv, write, floor,
         * median, bans, events); run 16 wrote 17,000 of those lines in
         * eight hours. The peer table prints every 30th tick (5 min). */
        long d_ro=0, d_wa=0, d_he=0, d_fa=0, d_ab=0, t_ro=0, t_wa=0, t_he=0, t_fa=0, t_ab=0;
        { static long tick_no = 0; tick_no++;
          t_ro=next_claim[DLC_CTL_N_ROTATE]; t_wa=next_claim[DLC_CTL_N_WAIT]; t_he=next_claim[DLC_CTL_N_HELP]; t_fa=next_claim[DLC_CTL_N_FAIL]; t_ab=next_claim[DLC_CTL_N_ABANDON];
          static long p_ro=0, p_wa=0, p_he=0, p_fa=0, p_ab=0;
          d_ro=t_ro-p_ro; d_wa=t_wa-p_wa; d_he=t_he-p_he; d_fa=t_fa-p_fa; d_ab=t_ab-p_ab;
          p_ro=t_ro; p_wa=t_wa; p_he=t_he; p_fa=t_fa; p_ab=t_ab;
          dlc_table_this_tick = (tick_no % 30 == 1);
        }
        if(dlc_table_this_tick) fprintf(stderr,"[dlc] -- peer status (%d/%d worker(s) active) --\n", alive, nw);
        double tick_total_bytes=0.0, tick_total_write_bytes=0.0;
        /* the pool's median rate from LAST tick, for the relative floor: one
         * tick of lag is nothing against a 10 s tick and a 3-tick streak */
        double median_bps = 0.0;
        { double v[64]; int nv = 0;
          for(int w=0;w<nw;w++) if(kids[w]!=0 && prev_rchar[w] > 0) v[nv++] = stats[w].last_bw_bps;   /* only workers with a real reading */
          for(int i=1;i<nv;i++){ double x=v[i]; int j=i-1; while(j>=0 && v[j]>x){ v[j+1]=v[j]; j--; } v[j+1]=x; }
          if(nv > 0) median_bps = v[nv/2]; }
        double floor_bps = dlc_effective_floor(median_bps);
        for(int w=0;w<nw;w++) stats[w].pool_median_bps = median_bps;   /* published for the workers' boundary rotation */
        /* a replacement exists? (2026-09-10: rotation and the rate floor act only then) */
        int free_peers = 0; for(int q=0;q<nlive;q++) if(!claimed[q] && !banned[q]) free_peers++;
        next_claim[DLC_CTL_FREE_PEERS] = free_peers;
        /* publish the workers' peers for getpeerinfo / getnettotals (2026-09-08) */
        if(g_node_status){
            int nd = nw > 64 ? 64 : nw;
            for(int w=0; w<nd; w++){
                rpc_peer_t* d = &g_node_status->dlpeers[w];
                if(kids[w]==0 || !stats[w].peer[0]){ d->used = 0; continue; }
                strncpy(d->addr, (const char*)stats[w].peer, sizeof d->addr - 1); d->addr[sizeof d->addr - 1] = 0;
                d->proto = stats[w].proto; d->services = stats[w].services; d->start_height = stats[w].start_height;
                memcpy(d->subver, (const char*)stats[w].subver, sizeof d->subver); d->subver[sizeof d->subver - 1] = 0;
                d->conn_time = stats[w].conn_time; d->bytes_recv = stats[w].bytes_peer; d->bytes_sent = 0;
                d->last_recv = d->last_send = (long long)time(NULL);
                d->inflight_lo = stats[w].cur_lo; d->inflight_hi = stats[w].cur_hi; d->dl_worker = w; d->inbound = 0;
                d->used = 1;
            }
            g_node_status->n_dlpeers = nd;
            g_node_status->dl_bytes_total = (long long)cumulative_bytes;
        }
        for(int w=0;w<nw;w++){
            long b=stats[w].blocks; long blkrate=(long)((double)(b-prev_blocks[w])/tick_s);
            long rc=kids[w]!=0 ? dlc_proc_rchar(opid[w]) : -1;
            long wc=kids[w]!=0 ? dlc_proc_wbytes(opid[w]) : -1;
            char bw[16]="--"; double byte_rate=-1.0;
            if(rc>=0){
                if(prev_rchar[w]>0){
                    double delta=(double)(rc-prev_rchar[w]);
                    tick_total_bytes+=delta;
                    byte_rate=delta/tick_s;
                    dlc_fmt_rate(bw,sizeof bw,byte_rate);
                    stats[w].last_bw_bps=byte_rate; /* worker reads this to report why it got dropped */
                    stats[w].bytes_peer += (long long)delta;   /* the worker zeroes it when it changes peer */
                    /* EMA speed for the peer this worker HOLDS (alpha 0.5,
                     * half-life ~20s). held_idx is the same index the ban
                     * path uses; -1 means the worker never connected, and a
                     * first sample (prev_rchar==0) is skipped -- delta from 0
                     * would be the whole lifetime, not a 10s rate. */
                    long hi=stats[w].held_idx;
                    if(hi>=0 && hi<nlive && prev_rchar[w]>0)
                        ema[hi] = 0.5*ema[hi] + 0.5*byte_rate;
                }
                prev_rchar[w]=rc;
            }
            if(wc>=0){
                if(prev_wbytes[w]>0) tick_total_write_bytes+=(double)(wc-prev_wbytes[w]);
                prev_wbytes[w]=wc;
            }
            char flag[48]="";
            if(kids[w]!=0 && byte_rate>=0.0){
                if(median_bps > 0.0 && dlc_replace_allowed(free_peers) && dlc_dead_weight(byte_rate, b-prev_blocks[w], floor_bps)){
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
                        /* The kill itself means this peer failed the speed
                         * test, banned or not (manual/floor keeps it
                         * selectable). Decay its EMA hard -- *0.25 -- so a
                         * re-scan (amnesty included, or next run via the
                         * persisted file) sees it degraded, not still fast. */
                        if(bidx>=0 && bidx<nlive) ema[bidx] = ema[bidx]*0.25;
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
            char dragbuf[48]="";
            if(dead_ticks[w]>0) snprintf(dragbuf,sizeof dragbuf," (Dragging: %d of %d)",dead_ticks[w],g_cfg.dead_weight_ticks);
            if(dlc_table_this_tick) fprintf(stderr,"[dlc]   w%d %-21s chunks=%-4ld blocks=%-6ld (+%ld blk/s, %s)%s%s%s\n",
                    w, stats[w].peer[0]?(const char*)stats[w].peer:"(connecting)",
                    stats[w].chunks, b, blkrate, bw, kids[w]==0?" [done]":"", flag, dragbuf);
            prev_blocks[w]=b;
        }
        {
            cumulative_bytes+=tick_total_bytes;
            cumulative_write_bytes+=tick_total_write_bytes;
            char totbuf[16], aggbuf[16], cumbuf[16], wtotbuf[16], waggbuf[16], wcumbuf[16];
            dlc_fmt_bytes(totbuf,sizeof totbuf,tick_total_bytes);
            dlc_fmt_rate(aggbuf,sizeof aggbuf,tick_total_bytes/tick_s);
            dlc_fmt_bytes(cumbuf,sizeof cumbuf,cumulative_bytes);
            dlc_fmt_bytes(wtotbuf,sizeof wtotbuf,tick_total_write_bytes);
            dlc_fmt_rate(waggbuf,sizeof waggbuf,tick_total_write_bytes/tick_s);
            dlc_fmt_bytes(wcumbuf,sizeof wcumbuf,cumulative_write_bytes);
            /* two genuinely different numbers, shown separately rather than
             * conflated into one "aggregate": network-received (rchar) is
             * NOT the same as disk-written (write_bytes) -- index.dat's
             * sparse-block allocation, filesystem journaling, and local
             * header/index re-reads all add disk I/O the network figure
             * never sees, so disk growth normally runs ahead of it. */
            (void)totbuf; (void)cumbuf; (void)wtotbuf; (void)wcumbuf;   /* folded into the one dashed line below */
            /* the per-tick numbers above are a noisy 10s snapshot -- this is
             * the stable figure: total bytes / total elapsed time since
             * dl_catchup started, so it settles down over the run instead
             * of bouncing with whichever peers happen to be fast or slow
             * in any given 10s window. */
            long elapsed_secs=(long)(time(NULL)-catchup_start); if(elapsed_secs<1) elapsed_secs=1;
            char avgrbuf[16], avgwbuf[16];
            dlc_fmt_rate(avgrbuf,sizeof avgrbuf,cumulative_bytes/(double)elapsed_secs);
            dlc_fmt_rate(avgwbuf,sizeof avgwbuf,cumulative_write_bytes/(double)elapsed_secs);
            /* floor and median: on the one dashed line below */
            /* nbanned counts ban EVENTS, and the workers' amnesty path clears
             * banned[] without decrementing it -- so this used to print
             * "715 of 119", more bans than peers. Report both truthfully:
             * how many are banned RIGHT NOW (scan the shared array the workers
             * actually read) and how many ban events there have been. */
            long cur = 0; for(int q = 0; q < nlive; q++) if(banned[q]) cur++;
            { extern int peer_no_witness_count(void); extern unsigned long long peer_no_witness_skips(void);
              static int last_nowit = 0; int nw_now = peer_no_witness_count();
              if(nw_now != last_nowit){ last_nowit = nw_now;              /* only when the count changes */
                  fprintf(stderr,"[dlc] -- %d peer(s) dropped for lacking NODE_WITNESS; %llu redial(s) skipped since --\n", nw_now, peer_no_witness_skips()); } }
            fprintf(stderr,"[dlc] -- recv %s (avg %s) | write %s (avg %s) | floor %.1f KB/s (median %.1f) | banned %ld/%d%s | free peers %d | staged %ld commit %ld cursorhelp %ld | stall evictions %ld (timeout %ld s) | events %ld rot %ld wait %ld help %ld fail %ld abandon (run %ld/%ld/%ld/%ld/%ld) --\n",
                    aggbuf, avgrbuf, waggbuf, avgwbuf, floor_bps/1024.0, median_bps/1024.0, cur, nlive,
                    nbanned == cur ? "" : " (amnesty active)", free_peers, next_claim[DLC_CTL_STAGED], next_claim[DLC_CTL_N_COMMIT], next_claim[DLC_CTL_N_CURSOR_HELP],
                    next_claim[DLC_CTL_N_STALL], g_dlc_stall_timeout_s, d_ro, d_wa, d_he, d_fa, d_ab, t_ro, t_wa, t_he, t_fa, t_ab);
        }
    }
    dlc_drain_committer(next_claim);            /* a no-op when the loop's last reap already drained it */
    g_dlc_kids = NULL; g_dlc_nw = 0;            /* the reject hook's stop is a no-op again */
    if(g_node_status){ g_node_status->n_dlpeers = 0; }   /* the download is over: its peers leave getpeerinfo (the byte total stays) */
    /* One more pass now that every helper has exited: the blocks that landed
     * between the last connect pass and the last reap (up to a chunk per
     * helper) are connected here, budget-bounded like any pass, so the lag
     * at the download gate is what one pass leaves, not a tick's worth of
     * download. The rotation's drain still owns whatever remains. */
    if(interleave && !g_shutdown_requested){
        long done = utxo_live_catchup_bounded(store_buf, g_dlc_connect_budget_ms, 1);
        if(done > 0){ conn_total += done; dl_new_block_choke(); }
    }
    if(interleave) fprintf(stderr,"[dlc] connected %ld block(s) during the download; connected tip %ld (the rotation drains the rest)\n",
                           conn_total, utxo_live_applied_height());
    long total=*done_count;
    /* Remember who actually produced blocks. A peer that delivered is worth
     * trying first next boot; the address book alone only records that an IP
     * was once seen, which is why every restart re-probed ~2,000 aged entries
     * and rediscovered the same handful from scratch. Recorded from the live
     * stats, and only for peers with blocks>0 -- being reachable is not the
     * same as being useful.
     *
     * The worker's held_idx is live[]'s index; EMA is indexed the same way,
     * and live[i]==pool[k] via the probe's own k order (see the comment at
     * the probe loop), so the speed figure travels back out with the peer
     * into peers.good as "ip\tema_kbps" -- run N+1 seeds its EMA from it.
     *
     * BUG FIX (2026-08-19): this block used to run AFTER the munmap(stats)
     * below, reading stats[w] through an already-unmapped pointer -- a real
     * use-after-unmap. Confirmed against a real production SIGSEGV: dmesg's
     * fault timestamp landed ~1.5s after the final "[dlc]" status tick, and
     * the "[dlc] catch-up done" line below never printed -- exactly what a
     * crash reading unmapped memory right after the loop exits looks like.
     * Must run BEFORE stats (and friends) are unmapped. */
    {
        /* Persist the good list (pool[nadd..nadd+ngood), the entries loaded
         * from last run's peers.good) that survived the liveness probe, each
         * with its measured EMA.
         *
         * The deliverer criterion (some worker holds this peer and delivered
         * blocks>0, i.e. the old stats[w].peer rule) is only SOUND when there
         * is exactly one pool entry per live IP: claimed[] guarantees a worker
         * never shares a peer, but a bare-ip pool entry and the same ip:port
         * from the book are TWO live slots, and a worker could hold A while
         * the credit landed on entry B. So the EMA attached to a good peer is
         * taken from EVERY live slot with the same IP, worst case: if the
         * worker holding that IP was rotated off it (held_idx moved on), the
         * seed value from last run is re-emitted instead of a made-up number.
         * (An IP-based match is right wherever a slot matches: a banned slot
         * can never be a worker's held slot, and the same IP elsewhere in
         * live[] is either the same peer under a second port or dead.) */
        static char good[64][DL_POOL_SLOT]; static double good_e[64]; int ng=0;
        for(int j=0;j<ngood && ng<64;j++){
            const char* gi=pool[nadd+j];
            int ip4=0; unsigned gip=pool_ipv4(gi,&ip4);
            if(!gip) continue;                          /* not a dialable IPv4 -- cannot track EMA */
            long bi=-1; int held_delivered=0;
            for(int i=0;i<nlive;i++){
                int p2=0; unsigned ip=0;
                if(!dlc_parse_peer(live[i],&ip,&p2) || ip!=gip) continue;
                if(bi<0) bi=i;
                for(int w=0; w<nw; w++)
                    if(stats[w].held_idx==i && stats[w].blocks>0){ held_delivered=1; break; }
            }
            if(bi<0) continue;                          /* did not survive the probe: not live this run */
            good_e[ng] = held_delivered ? ema[bi] : good_ema[nadd+j];  /* fresh reading, else carry last run's seed */
            strncpy(good[ng],gi,63); good[ng][63]=0; ng++;
        }
        dl_save_good_peers_ema(good, good_e, ng);
    }
    munmap((void*)next_claim,DLC_CTL_BYTES); munmap((void*)done_count,sizeof(long));
    munmap((void*)stats,sizeof(dlc_stat_t)*(size_t)nw);
    munmap((void*)claimed,sizeof(int)*(size_t)nlive);
    munmap((void*)banned,sizeof(int)*(size_t)nlive);
    munmap((void*)ema,sizeof(double)*(size_t)nlive);
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
static unsigned char txsub_mp_area[MPOOL_AREA_BYTES(TXSUB_MP_SLOTS)];
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
                                      unsigned long, char*, unsigned long, unsigned long long*,
                                      unsigned long long*);
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
        char r[128]; r[0] = 0; unsigned long long fee = 0, avs = 0;
        long rc = tx_accept_test_reason(txsub_pool(), txids + i*32, txs[i], lens[i],
                                        r, sizeof r, &fee, &avs);
        st->pkg_fee[i] = fee;
        /* The SIGOP-ADJUSTED vsize, which is what Core's package feerate is
         * computed over: its members are mempool entries and an entry's size
         * IS the adjusted figure. vsz[] comes from the structural walker,
         * which cannot count sigops -- those need the UTXO view -- so it is
         * only the fallback for a member rejected before the policy layer
         * ran, and such a member never joins the total below. */
        st->pkg_vsize[i] = avs ? avs : vsz[i];
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
                                            r, sizeof r, &fee, NULL);
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
/* The backlog the apply-first rule looks at is what the connect can ACTUALLY
 * apply: the contiguous prefix above the applied height, i.e. up to the
 * first hole. Until 2026-09-08 it was archive tip minus applied height, and
 * on a restart mid-sync that counted the in-flight chunks the stopped run
 * left as holes: 523 on the first continuity test, over the 500 line, so
 * the trigger said "apply first" while the connect sat on the hole at
 * 135,639 that only the downloader could fill. A deadlock, once a second,
 * forever. first_hole < 0 means no hole. */
static long dl_apply_backlog(long archive_tip, long first_hole, long applied){
    if(applied < 0) return 0;
    long top = (first_hole >= 0 && first_hole - 1 < archive_tip) ? first_hole - 1 : archive_tip;
    return top > applied ? top - applied : 0;
}
/* The height the far-behind trigger believes: the second-highest of the
 * connected peers' announced start heights (the highest with one peer). A
 * single peer's claim, honest or not, never starts the parallel downloader
 * on its own; two agreeing peers do. */
static long dl_trigger_height(const long* hs, int n){
    if(n <= 0) return 0;
    long top = 0, second = 0;
    for(int i=0;i<n;i++){ if(hs[i] > top){ second = top; top = hs[i]; } else if(hs[i] > second) second = hs[i]; }
    return n >= 2 ? second : top;
}
static int dl_should_parallel_fetch(long archive_tip, long best_peer_height,
                                    long apply_backlog, long long now_s, long long last_run_s){
    if(best_peer_height <= 0 || archive_tip < 0) return 0;
    if(best_peer_height - archive_tip < DL_PARALLEL_GAP) return 0;
    if(apply_backlog > DL_APPLY_FIRST_BACKLOG) return 0;
    if(last_run_s && now_s - last_run_s < DL_PARALLEL_REARM_S) return 0;
    return 1;
}

/* ---- the new-block choke point (3.1), as ONE function ---------------------
 * Fires from two places now: the worker's rotation, once per pass, and the
 * parallel downloader's monitor loop after every bounded connect (step 1 of
 * UTXO_INLINE_BUILD_PERF_SCOPE, 2026-09-06) -- so a block connected while the
 * helpers are still downloading is announced, published to ZMQ, folded into
 * the index tails and reconciled against the mempool the moment it connects,
 * not hours later when dl_catchup returns. The baseline (g_dl_last_seen_tip)
 * is the worker's: set to the connected tip at the rotation top, rewound to
 * the fork height by a reorg (STO-7), -1 in the boot-time parent, where the
 * downloader runs before any UTXO engine exists and this is never called. */
static int g_dl_last_seen_tip = -1;
static void dl_after_gate_rewind(long back){
    g_dl_parallel_now = 1;
    if(back < (long)g_dl_last_seen_tip) g_dl_last_seen_tip = (int)back;
}
/* new-block choke point (3.1: watching the CONNECTED tip, not the
 * store's). Everything the node says or does about a "new block"
 * -- the log line, the outbound-leg announce, ZMQ hashblock/rawblock,
 * the index tails, -blocknotify, the mempool's removeForBlock and
 * its tip anchor -- fires here, once per block that utxo_live has
 * connected. Before 3.1 this watched *(int*)(store+24) and every one
 * of those consumers saw blocks this node had stored but never
 * validated. Hash printed big-endian like Core logs it, so a line
 * here greps against a Core debug.log. The tip can also go DOWN here
 * (a reorg, a rejected block truncating the archive): nothing is
 * announced for that, the baseline just follows. */
/* Core relays no blocks while it is in initial block download
 * (PeerManagerImpl gates block announcement on !IsInitialBlockDownload(),
 * whose main clause is "the tip is older than -maxtipage"). This node
 * announced every connected tip to its outbound legs regardless, and on
 * the 2026-09-07 benchmark those legs were dead twenty minutes in -- the
 * peers' inactivity timeout, because the serve worker is inside the
 * parallel catch-up and never services them -- so the log carried one
 * "announced tip ... to 0/4 legs" per block for the rest of the run.
 * Same rule as Core now, and the same rule the RPC's
 * "initialblockdownload" field already uses. */
static int dl_announce_allowed(unsigned long tip_time, long long now, long maxtipage){
    return now - (long long)tip_time <= maxtipage;      /* a tip in the future is fine: not IBD */
}
/* the Core rule again, for the history repair: the tip is older than maxtipage */
static int dl_tip_is_ibd(void){
    static unsigned char hb[8u<<20]; long tip = *(int*)(store_buf+24); if (tip < 0) return 1;
    if (store_read_at(store_buf, (unsigned long)tip, hb, (long)sizeof hb) < 80) return 1;
    unsigned long tip_time = (unsigned long)hb[68] | ((unsigned long)hb[69]<<8) | ((unsigned long)hb[70]<<16) | ((unsigned long)hb[71]<<24);
    return !dl_announce_allowed(tip_time, (long long)time(NULL), g_cfg.maxtipage > 0 ? g_cfg.maxtipage : 86400);
}
static void dl_new_block_choke(void){
    int now_tip = (int)node_public_tip(store_buf);
    if(g_dl_last_seen_tip >= 0 && now_tip > g_dl_last_seen_tip){
        static unsigned char thb[8u<<20]; unsigned char th[32]; char hex[65];
        /* 2026-09-08: during initial block download (Core's rule: the tip is
         * older than maxtipage) neither this line nor the announcement below
         * is printed -- the catch-up's status line already carries the
         * applied height every ten seconds, and run 16 wrote 5,161 of these.
         * At the tip, one line per block, as before. */
        int in_ibd = 0; static int ibd_said = 0;
        if(store_read_at(store_buf, (unsigned long)now_tip, thb, (long)sizeof thb) >= 80){
            unsigned long tip_time = (unsigned long)thb[68] | ((unsigned long)thb[69]<<8) | ((unsigned long)thb[70]<<16) | ((unsigned long)thb[71]<<24);
            in_ibd = !dl_announce_allowed(tip_time, (long long)time(NULL), g_cfg.maxtipage > 0 ? g_cfg.maxtipage : 86400);
            if(in_ibd){ if(!ibd_said){ ibd_said = 1; fprintf(stderr,"[dl] per-block lines and tip announcements are off while the tip is older than maxtipage (initial block download; Core relays no blocks in IBD) -- they resume at the tip\n"); } }
            else {
                ibd_said = 0;
                block_hash(th, thb);
                for(int b=0;b<32;b++) sprintf(hex+b*2, "%02x", th[31-b]);
                fprintf(stderr,"[dl] new block: height=%d hash=%s (+%d)%s\n",
                        now_tip, hex, now_tip-g_dl_last_seen_tip,
                        now_tip < *(int*)(store_buf+24) ? " [connected; archive is ahead]" : "");
            }
        } else {
            fprintf(stderr,"[dl] new block: height=%d (+%d)\n",
                    now_tip, now_tip-g_dl_last_seen_tip);
        }
        /* announce the CONNECTED tip to every outbound leg (inv
         * MSG_BLOCK; node_announce_tip reads the public tip itself).
         * This replaces the per-leg announce that used to fire at
         * store time in the leg sync. */
        if(!in_ibd){
            int announced = 0, legs = 0;
            for(int i2=0; i2<mux_n_out; i2++){
                if(mux_out_fd[i2] < 0) continue;
                legs++;
                if(node_announce_tip(mux_out_fd[i2], store_buf, ht_idx, 0) == 1) announced++;
            }
            if(legs) fprintf(stderr,"[dl] announced tip height=%d to %d/%d legs\n", now_tip, announced, legs);
        }
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
            for (int zh = g_dl_last_seen_tip + 1; zh <= now_tip; zh++){
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
    mempool_refresh_seqlocks(store_buf, now_tip);   /* MEM-1 */
    g_dl_last_seen_tip = now_tip;
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
    if(chdir(dir) != 0){ fprintf(stderr,"[dlc] FATAL: cannot chdir to the datadir %s: %s\n", dir, strerror(errno)); _exit(2); }
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
    { long ni = invset_load("invalid.dat"); if(ni) fprintf(stderr, "[chain] invalid.dat: %ld operator-invalidated block(s)\n", ni);   /* CC-10 */
      reorg_set_invalid_fn(invset_has); g_txoq_store = store_buf; }
    { extern void* g_cmpct_hook_type; extern void* g_cmpct_hook_cmpct; extern void* g_cmpct_hook_blocktxn;   /* CC-2: bitcoind.asm reaches the receive side through these */
      /* 2026-09-09: bmc.cmpctrecv is gone -- a compact block that reconstructs badly falls back to a full one, as Core, so no valve is needed */
      g_cmpct_hook_type = (void*)cmpct_getdata_type; g_cmpct_hook_cmpct = (void*)cmpct_recv_cmpctblock; g_cmpct_hook_blocktxn = (void*)cmpct_recv_blocktxn; }
      { extern void* g_cmpct_hook_fallback; extern void cmpct_recv_note_fallback(void); g_cmpct_hook_fallback = (void*)cmpct_recv_note_fallback; }
      { extern void (*txrelay_on_pong)(int, const unsigned char*); txrelay_on_pong = leg_on_pong; inflight_init(&g_inflight); g_block_fetch_hook = (void*)block_fetch_gate; }
      { extern void (*txrelay_on_block_inv)(int, const unsigned char*); extern void (*txrelay_on_headers)(int, const unsigned char*, unsigned long);
        extern long (*txrelay_on_cmpctblock)(int, const unsigned char*, unsigned long); extern long (*txrelay_on_blocktxn)(int, const unsigned char*, unsigned long); extern long (*txrelay_on_block)(int, const unsigned char*, unsigned long);
        txrelay_on_block_inv = leg_on_block_inv; txrelay_on_headers = leg_on_headers; txrelay_on_cmpctblock = leg_on_cmpctblock; txrelay_on_blocktxn = leg_on_blocktxn; txrelay_on_block = leg_on_block; }   /* 2026-09-10: Core's shape at the tip */
      { extern int txrelay_classify_missing(const unsigned char*, unsigned long); extern void cmpct_recv_set_classifier(int (*)(const unsigned char*, unsigned long));
        cmpct_recv_set_classifier(txrelay_classify_missing); }   /* row 5: where the block's missing transactions went */   /* 2026-09-09: pings and one request per block */   /* 2026-09-09: the full-block fallback is counted on the [cmpct] line */
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
    /* -privatebroadcast (Core v30 init.cpp): refuse to run it without a way to
     * reach Tor or I2P, or alongside connect= (it must dial random peers); warn
     * when proxyrandomize=0 would let circuits be correlated. */
    if (g_cfg.privatebroadcast){
        int tor = dialer_net_reachable(BMC_NET_TORV3), i2p = dialer_net_reachable(BMC_NET_I2P);
        if (!tor && !i2p && !g_cfg.listenonion){
            fprintf(stderr, "[config] FATAL: private broadcast of own transactions requested (privatebroadcast=1), but none of Tor or I2P networks is reachable -- set onion=/proxy= or i2psam=, or drop the option\n");
            exit(1);
        }
        if (g_cfg.n_connect > 0)
            /* Core refuses this pairing because its private dials go through the
             * same connection budget connect= restricts. Ours dial the address
             * book directly, so the pairing works here; it is still worth a
             * loud note because the operator has restricted this node's peers
             * on purpose and private broadcast will talk to peers outside that
             * list. */
            fprintf(stderr, "[config] WARNING: privatebroadcast=1 with connect= (Core refuses this pairing): private broadcast connections go to randomly chosen Tor/I2P peers from the address book, outside the connect= list\n");
        if (!g_cfg.proxyrandomize)
            fprintf(stderr, "[config] WARNING: privatebroadcast=1 with proxyrandomize=0: Tor circuits for private broadcast connections may be correlated to other connections over Tor; set proxyrandomize=1 for maximum privacy\n");
        pb_queue_init();
        fprintf(stderr, "[privbcast] enabled: sendrawtransaction goes out over %s%s%sshort-lived connections, %d per transaction, and stays out of the mempool until heard back\n",
                tor ? "tor " : "", i2p ? "i2p " : "", (tor && dialer_proxy_configured()) ? "clearnet-via-proxy " : "", PB_NUM_PER_TX);
    }
    if (g_node_status){ g_node_status->pb_enabled = g_cfg.privatebroadcast ? 1 : 0; g_node_status->pb_reachable = pb_reachable_now() ? 1 : 0; g_node_status->pb_info[0] = 0; }
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
    /* the live address index (EXTENSION) boots AFTER the UTXO engine below:
     * its backfill replays undo, which exists only for applied blocks */

    fprintf(stderr,"[dl] worker: loading live UTXO state...\n");
    phase_timer_t utxo_init_pt; phase_start(&utxo_init_pt);
    g_in_utxo_reload = 1;                       /* see handle_shutdown_signal */
    int utxo_live_ok = archive_ok ? utxo_live_init(dir) : 0;
    g_in_utxo_reload = 0;
    g_utxo_live_on = utxo_live_ok;             /* 3.1: node_public_tip() switches on this */
    dl_publish_connected_tip();
    /* live address index (EXTENSION -- Core has no such index): only when
     * the operator asked with addrindex=1. 2026-09-08: after the engine, and
     * capped at its applied height -- the archive is ahead of it at every
     * boot (a stop lands blocks it does not connect), and a backfill aimed at
     * the archive tip read undo the engine had not written yet and disabled
     * the index for the session, four boots in a row on production. */
    if(archive_ok && g_cfg.addrindex){
        extern void axt_set_applied_height(long (*)(void));
        if(utxo_live_ok) axt_set_applied_height(utxo_live_applied_height);
        axt_boot(store_buf);
    }
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
            { extern void csi_set_chain(long, int); csi_set_chain(g_chainp->halving_interval, !strcmp(g_chainp->name, "main")); }
            /* 2026-09-08: the history base repairs itself. The builder lives
             * beside this executable; the supervisor ticks at the heartbeat. */
            { extern void csi_hist_repair_configure(const char*, const char*, const char*, int, int);
              char exe[512], builder[600]; ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
              if (n > 0){ exe[n] = 0; char* sl = strrchr(exe, '/'); if (sl) *sl = 0; snprintf(builder, sizeof builder, "%s/bmc_build_coinstats_hist", exe); }
              else snprintf(builder, sizeof builder, "bmc_build_coinstats_hist");
              csi_hist_repair_configure(builder, dir, g_chainp->name, g_cfg.coinstatshist_workers, g_cfg.coinstatshist_repair); }
            utxo_live_set_coinstats(csi_on_add, csi_on_remove, csi_invalidate, csi_commit);
            { extern void csi_on_block(long); extern void utxo_live_set_coinstats_block(void (*)(long)); utxo_live_set_coinstats_block(csi_on_block); }
            undo_set_coin_observer(csi_on_remove);
            long ah = utxo_live_applied_height();
            /* 2026-09-10: Core's shape in every mode. Core's coinstatsindex
             * folds each connected block off the validation thread; the
             * fold worker is that. The 2026-09-06 bulk-mode deferral (leave
             * the index invalid, seed it from one walk at the downshift)
             * predates the worker: it was written when the fold ran ON the
             * connect thread (~3 h of a fresh sync at 1.66 us an element).
             * Through the ring the connect thread pays a memcpy a coin and
             * the worker folds on its own core; the index and its history
             * rows exist from block 0, so a fresh sync ends with the
             * history base built, not with a walk and a rebuild. */
            extern int csi_worker_start(void);
            if (!csi_boot(ah))
                csi_seed_from_walk(utxo_live_lst(), utxo_live_table(), ah);
            csi_worker_start();
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
            reorg_ok = 1; g_reorg_ok = 1;
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
    { extern void reorg_set_headers_truncate(void (*)(long)); reorg_set_headers_truncate(dl_headers_truncate_to);   /* 2026-09-09: the handoff rewinds the mirror too */
      extern void reorg_set_mirror_append(int (*)(const unsigned char*, long)); reorg_set_mirror_append(dl_mirror_append);
      extern void reorg_set_mirror_hash_at(int (*)(long, unsigned char*)); reorg_set_mirror_hash_at(dl_mirror_hash_at);
      extern int hdrtree_open(void); hdrtree_open(); }   /* the fork tree, from headers_forks.dat in the chain dir */
    reorg_set_index_rebuild(rebuild_hash_index_after_reorg);
    /* 3.3: a block that fails VALIDATION in catch-up is rejected through
     * dl_reject_block, not left in the archive as a fatal retry loop */
    { extern void utxo_live_set_reject_fn(long (*)(void*, long, const unsigned char[32], const char*));
      utxo_live_set_reject_fn(dl_reject_block); }
    /* STO-7: hand reorg.c the SHARED mempool and the accept path's own policy
     * objects, so a completed reorg rebuilds the pool against the new branch
     * instead of leaving it holding transactions the new branch invalidated.
     * Deliberately after tx_policy_init has had a chance to run: if the policy
     * layer is not up (maxmempool=0, or the static per-process fallback with
     * no shared area) nothing is registered and reorg.c says so in its log
     * rather than reconciling against a half-built pool. */
    { extern void* mp_ext_area;
      extern int tx_accept_policy_view(void**, void**, unsigned*);
      static reorg_mempool_t rmp;
      void* pol = 0; void* pst = 0; unsigned pn = 0;
      if (mp_ext_area && tx_accept_policy_view(&pol, &pst, &pn)){
          rmp.mp = mp_ext_area; rmp.pol = pol; rmp.pol_state = pst; rmp.pol_n = pn;
          /* mempool_resolve_confirmed_utxo ignores this argument -- same
           * placeholder daemon/tx_accept.c passes on the accept path. */
          rmp.utxo_arg = (void*)1;
          reorg_set_mempool(&rmp);
          fprintf(stderr,"[reorg] mempool reconciliation armed (shared pool, policy capacity %u)\n", pn);
      } else {
          fprintf(stderr,"[reorg] mempool reconciliation NOT armed: no shared mempool/policy state in this process\n");
      }
    }
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
    /* CC-4: Core anchors.dat -- the block-relay-only peers of the last run are
     * dialled first, as block-only again; the file is deleted on read. */
    { char anc[MAX_BLOCK_RELAY_ONLY][128]; long na = anchors_read("anchors.dat", anc, MAX_BLOCK_RELAY_ONLY, g_chainp->magic);
      if(na > 0){
          for(long i = na - 1; i >= 0; i--){
              if(nsrc >= 64) break;
              for(int k = nsrc; k > 0; k--) srcpool[k] = srcpool[k-1];
              bo_add(anc[i]); srcpool[0] = g_bo_hosts[g_bo_n - 1]; nsrc++;
          }
          fprintf(stderr, "[dial] anchors.dat: %ld block-relay-only peer(s) from the last run dialled first\n", na);
      } else if(na < 0) fprintf(stderr, "[dial] anchors.dat: unreadable -- ignored and removed\n"); }
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
            dial_gate_wait();
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
            mux_out_fd[mux_n_out]=cfd[i]; leg_note_installed(mux_n_out); mux_out_kind[mux_n_out] = host_is_block_only(srcpool[i]) ? LEG_BLOCK_ONLY : LEG_FULL;   /* CC-4 */ mux_out_cmpct[mux_n_out] = 0;
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
    g_dl_last_seen_tip = (int)node_public_tip(store_buf);   /* new-block choke-point baseline: the CONNECTED tip at boot (3.1), so the catch-up burst is published too */
    int last_seen_stored = *(int*)(store_buf+24);          /* archive high-water mark: keys the header mirror top-up only */
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
            g_node_status->n_out = lp; g_node_status->tip_height = node_public_tip(store_buf);   /* 3.1: the CONNECTED tip */
            dl_publish_connected_tip();
            long long nows = (long long)time(NULL);
            for(int i=0;i<RPC_MAX_PEERS;i++){
                if(i >= MUX_MAX_OUT) continue;                      /* inbound children own 64..127 */
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
            g_node_status->ctl_out[0] = 0;
            if(op == RPC_CTL_PB_ABORT){
                unsigned char id[32]; int okhex = strlen(arg) == 64;
                for(int i = 0; okhex && i < 32; i++){ unsigned v; if(sscanf(arg + i*2, "%2x", &v) != 1){ okhex = 0; break; } id[31 - i] = (unsigned char)v; }
                if(!okhex){ result = -8; snprintf(reason, sizeof reason, "id must be a 64-character hex txid or wtxid"); }
                else {
                    static unsigned char rt[PB_MAX_TX][32], rw[PB_MAX_TX][32];
                    long n = pb_queue_abort(id, rt, rw, PB_MAX_TX);
                    long o = 0; static const char* HX = "0123456789abcdef";
                    for(long k = 0; k < n && k < PB_MAX_TX && o + 132 < (long)sizeof g_node_status->ctl_out; k++){
                        char* out = (char*)g_node_status->ctl_out;
                        for(int i = 0; i < 32; i++){ out[o++] = HX[rt[k][31-i] >> 4]; out[o++] = HX[rt[k][31-i] & 15]; }
                        out[o++] = ' ';
                        for(int i = 0; i < 32; i++){ out[o++] = HX[rw[k][31-i] >> 4]; out[o++] = HX[rw[k][31-i] & 15]; }
                        out[o++] = '\n'; out[o] = 0;
                    }
                    result = (int)n; pb_publish();
                    if(n > 0) fprintf(stderr, "[privbcast] aborted %ld queued transaction(s) on request\n", n);
                }
            } else if(op == RPC_CTL_SETNETACTIVE){
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
                /* ---- RPC-3 (audit 2026-09-03) ----
                 *
                 * This matched `num` against the raw outbound leg index i,
                 * while getpeerinfo published a COUNTER over live slots. The
                 * two agree only while every slot below is occupied and no
                 * inbound slot precedes, so after any churn (slot 1 free,
                 * slots 0/2/3 live) the operator's chosen id named a
                 * different peer -- and the RPC still returned success.
                 * Inbound peers could not be disconnected at all: the loop
                 * ran to mux_n_out, and the address branch compared only
                 * outbound hosts.
                 *
                 * Both sides now key on rpc_peer_t.nodeid, which is unique
                 * for the life of the process, and the search covers every
                 * slot. An inbound slot is a forked serve child, so it is
                 * dropped with SIGTERM on its published pid -- the same
                 * signal the parent uses at shutdown. */
                char want[128]; ctl_ip_only(arg, want, sizeof want);
                if(g_node_status) for(int i = 0; i < RPC_MAX_PEERS; i++){
                    rpc_peer_t* q = &g_node_status->peers[i];
                    if(!q->used) continue;
                    char have[128]; ctl_ip_only(q->addr, have, sizeof have);
                    int hit = (want[0] && !strcmp(have, want)) ||
                              (!want[0] && num == (long long)q->nodeid);
                    if(!hit) continue;
                    if(q->inbound){
                        if(q->pid > 0 && kill((pid_t)q->pid, SIGTERM) == 0){
                            fprintf(stderr,"[ctl] disconnecting inbound %s (nodeid %lld, pid %d)\n",
                                    q->addr, (long long)q->nodeid, q->pid);
                            q->used = 0; result = 1;
                        } else {
                            fprintf(stderr,"[ctl] inbound %s (nodeid %lld) has no live child to signal\n",
                                    q->addr, (long long)q->nodeid);
                        }
                        break;
                    }
                    if(i >= mux_n_out || mux_out_fd[i] < 0){
                        fprintf(stderr,"[ctl] outbound nodeid %lld (slot %d) is no longer connected\n",
                                (long long)q->nodeid, i);
                        q->used = 0; break;
                    }
                    fprintf(stderr,"[ctl] disconnecting %s (nodeid %lld, leg %d)\n",
                            mux_out_host[i], (long long)q->nodeid, i);
                    bmc_v2_close(mux_out_fd[i]), close(mux_out_fd[i]); mux_out_fd[i] = -1;
                    q->used = 0;
                    result = 1; break;
                }
            } else if(op == RPC_CTL_ADDNODE){
                /* 2026-09-09: `add` and `onetry` used to answer "done" and dial
                 * nothing (the list had no reader). They queue a manual dial
                 * now; the pass below the top-up makes it, every rotation. */
                if(num == 1){                                  /* remove */
                    result = ctl_dial_remove(arg);
                } else {
                    int q = ctl_dial_add(arg, num == 0, (long long)time(NULL));
                    if(q < 0){ result = -1; snprintf(reason, sizeof reason, "the runtime addnode list is full (%d)", CTL_DIAL_MAX); }
                    else { result = 1; fprintf(stderr,"[ctl] addnode %s: %s (queue %d)\n", num == 0 ? "add" : "onetry", arg, ctl_dial_count()); }
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
                    if(result == 1) banlist_persist();
                } else {
                    /* ---- RPC-8 (audit 2026-09-03) ----
                     * This used to refuse any prefix that was not a multiple
                     * of 8 in [8,32], claiming the matcher could not enforce
                     * it. That was true of the OLD string-comparing matcher
                     * and has been false since subnet.c landed:
                     * subnet_parse/subnet_covers handle any prefix 0..128 for
                     * both families, and ctl_ban_covers is a one-line
                     * passthrough to them. tests/test_subnet.c already proves
                     * /28, /12, /20 and IPv6 including ::/0.
                     *
                     * Worse, the rule read the prefix without looking at the
                     * family, so it ACCEPTED 2001:db8::/32 while refusing
                     * ::1/128 and 2001:db8::/64 -- the exact inversion the
                     * comment above ctl_ban_covers says was fixed.
                     *
                     * Now: parse it. An unparseable spec is refused (Core
                     * raises -30 at the RPC, which cmd_setban also does now);
                     * anything the matcher can actually evaluate is allowed. */
                    subnet_t sn_probe;
                    if(!subnet_parse(arg, &sn_probe)){
                        result = -1;
                        snprintf(reason, sizeof reason,
                                 "not a valid IP or subnet: %s", arg);
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
                banlist_persist();
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
                                     unsigned long, unsigned long long*,
                                     unsigned long long*);
                    extern int tx_txid(unsigned char* out, const unsigned char* tx, unsigned long txlen, unsigned char* scratch, unsigned long scratchcap);
                    static unsigned char tscratch[2000*81 + 8];
                    unsigned char tid[32];
                    unsigned long long fee = 0;
                    if(!tx_txid(tid, (const unsigned char*)g_node_status->tx_submit_buf, tlen,
                                tscratch, sizeof tscratch)){
                        result=-22; snprintf(reason,sizeof reason,"TX decode failed");
                    } else {
                        result = (int)tx_accept_test_reason(txsub_pool(), tid,
                                     (const unsigned char*)g_node_status->tx_submit_buf, tlen,
                                     reason, sizeof reason, &fee, NULL);
                    }
                    g_node_status->tx_submit_fee = fee;
                }
                else if(g_node_status->tx_submit_private){
                    g_node_status->tx_submit_private = 0;
                    if(!g_cfg.privatebroadcast){ result = -1; snprintf(reason, sizeof reason, "private broadcast is not enabled"); }
                    else if(!pb_reachable_now()){ result = -1; snprintf(reason, sizeof reason, "-privatebroadcast is enabled, but none of the Tor or I2P networks is reachable"); }
                    else {
                        /* Core BroadcastTransaction(NO_MEMPOOL_PRIVATE_BROADCAST): test-accept
                         * first (its rejection is the RPC's), then queue -- never the mempool */
                        extern long tx_accept_test_reason(void*, const unsigned char*, const unsigned char*, unsigned long, char*, unsigned long, unsigned long long*, unsigned long long*);
                        extern int tx_txid(unsigned char* out, const unsigned char* tx, unsigned long txlen, unsigned char* scratch, unsigned long scratchcap);
                        static unsigned char pscratch[2000*81 + 8]; unsigned char tid[32]; unsigned long long fee = 0;
                        if(!tx_txid(tid, (const unsigned char*)g_node_status->tx_submit_buf, tlen, pscratch, sizeof pscratch)){ result = -22; snprintf(reason, sizeof reason, "TX decode failed"); }
                        else {
                            result = (int)tx_accept_test_reason(txsub_pool(), tid, (const unsigned char*)g_node_status->tx_submit_buf, tlen, reason, sizeof reason, &fee, NULL);
                            if(result == 1){
                                int ar = pb_queue_add((const unsigned char*)g_node_status->tx_submit_buf, tlen, pb_wall_s());
                                if(ar == 1){ g_pb_num_to_open += PB_NUM_PER_TX; pb_publish();   /* the RPC's next getprivatebroadcastinfo must already see it */
                                    fprintf(stderr, "[privbcast] queued a transaction for private broadcast (%d connections requested; not in the mempool)\n", PB_NUM_PER_TX); }
                                else if(ar == 0){ /* already queued: Core ignores the duplicate request */ }
                                else { result = -1; snprintf(reason, sizeof reason, "private broadcast queue is full (cap=%d)", PB_MAX_TX); }
                            }
                        }
                    }
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
                            fprintf(stderr,"[dl] sendrawtransaction accepted, queued for announcement to %d/%d legs%s\n",
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
                long applied = utxo_live_ok ? utxo_live_applied_height() : -1;
                static unsigned char hb[4u<<20];   /* store_read_at scratch */
                if (applied != tip){
                    snprintf(reason, sizeof reason, "inconclusive");
                } else {
                    /* VAL-14 (audit 2026-09-03): there used to be a next-work
                     * pre-check here -- rpc_chain_retarget(tip_bits, span) with
                     * a bare `(tip+1) % 2016` -- i.e. MAINNET'S schedule only:
                     * no testnet4 20-minute min-difficulty walk-back, no BIP94
                     * first-block base. On testnet4 a valid min-difficulty block
                     * submitted here was answered "bad-diffbits"; on a BIP94
                     * boundary the expected bits were simply wrong. The dry run
                     * below already runs pow_check_bits with THIS chain's rules
                     * (utxo_live_set_pow_rules, armed after chainparams_select)
                     * and answers the same "bad-diffbits", so the pre-check was
                     * a second, less correct opinion. Removed; the timestamp
                     * rules that follow are chain-agnostic and stay. */
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
                    if (blk_time <= mtp){
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
                        /* STO-5 (audit 2026-09-03): the miner's block goes in
                         * through the SAME locked appender the worker legs and
                         * the inbound serve children use. store_append writes
                         * at a cached cur_file_pos without taking append.lock,
                         * so a serve child that appended network block T+1 a
                         * moment earlier -- while this worker still believed
                         * the tip was T -- had its frame overwritten, and a
                         * larger submitted block overran the frame after it.
                         *
                         * -2 is its own answer, not a generic failure: the
                         * block no longer links to the tip, meaning the chain
                         * moved under us between the dry run and here. That is
                         * exactly the race, and saying so beats "rejected". */
                        long ar_sb = idxscan_append_locked(store_buf, bh, sblk, (long)slen);
                        if (ar_sb == -2){
                            snprintf(reason, sizeof reason, "inconclusive");
                            fprintf(stderr,"[dl] submitblock: the tip moved between the dry run and the append "
                                           "(another writer stored a block first) -- not connecting\n");
                        } else if (ar_sb < 0){
                            snprintf(reason, sizeof reason, "rejected");
                            fprintf(stderr,"[dl] submitblock: locked append FAILED\n");
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
            /* ---- DMN-5 (audit 2026-09-03): close the UTXO layer -----------
             * utxo_live_close() checkpoints a pending batch, shuts the
             * background compaction child down, and closes the LSM. It had no
             * caller here at all, so the ONLY shutdown-aware code in the UTXO
             * path was utxo_live_catchup's own block-boundary checkpoint. A
             * SIGTERM anywhere else in the worker's rotation -- leg sync,
             * relay drain, txsub linger, heartbeat -- exited with blocks
             * applied but un-checkpointed and a compaction child still
             * merging and writing run files behind the exiting parent.
             *
             * The un-checkpointed tail is safe (the WAL is the truth) but the
             * next boot replays it, which main.c's own note measures in
             * MINUTES on a large tail. The orphaned child is the worse half:
             * it keeps writing into a datadir whose owner has gone.
             *
             * Weak-linked like fest_shutdown_flush above, and for the same
             * reason: several dial/sync harnesses link this file without
             * daemon/utxo_live.c. */
            { extern void utxo_live_close(void) __attribute__((weak));
              if (utxo_live_close) utxo_live_close(); }
            /* utxo_live_close's checkpoint pushed the last commit marker;
             * now a STOP marker behind it and wait for the fold worker to
             * persist coinstats.dat (bounded; a kill only costs a re-seed). */
            { extern void csi_worker_stop(void) __attribute__((weak));
              if (csi_worker_stop) csi_worker_stop(); }
            _exit(0);
        }
        long long now_ms = 0;
        { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); now_ms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
        int did=0;
        int stored_break = 0; g_stored_now = 0;       /* 2026-09-10: a store ends the rotation early so the apply runs at once */
        static int leg_start = 0;
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
            long atip0 = (long)(*(int*)(store_buf+24));
            if(ah >= 0) apply_backlog = dl_apply_backlog(atip0, atip0 >= 0 ? dlc_first_hole(atip0) : -1, ah);
        }
        int apply_first = apply_backlog > DL_APPLY_FIRST_BACKLOG;
        {
            /* 2026-09-08: the trigger height is the SECOND-highest announce
             * (dl_trigger_height), so one peer claiming 969,817 on a 966,063
             * chain cannot start the parallel downloader -- production ran
             * its two-minute header phase every ten minutes on exactly that
             * peer, wrote nothing, and paused this loop each time. An
             * announce that produced no blocks is not retried while the
             * archive stands still. */
            long hs[RPC_MAX_PEERS]; int nh = 0;
            if(g_node_status)
                for(int i=0;i<mux_n_out && i<RPC_MAX_PEERS;i++)
                    if(mux_out_fd[i]>=0 && g_node_status->peers[i].start_height > 0)
                        hs[nh++] = g_node_status->peers[i].start_height;
            long best = dl_trigger_height(hs, nh);
            long atip = (long)(*(int*)(store_buf+24));
            long long nows = (long long)time(NULL);
            static long noop_best = -1, noop_tip = -1;
            if(g_dl_parallel_now){ g_dl_parallel_now = 0; noop_best = -1; noop_tip = -1; dl_parallel_last_s = 0; }   /* a reorg handoff: fetch now */
            if(best == noop_best && atip == noop_tip) best = atip;        /* the same claim already came to nothing at this tip */
            if(dl_should_parallel_fetch(atip, best, apply_backlog, nows, dl_parallel_last_s)){
                fprintf(stderr,"[dl] archive at %ld, peers announce %ld: %ld blocks behind -- running the parallel downloader (%d workers)\n",
                        atip, best, best-atip, g_catchup_workers);
                dl_parallel_last_s = nows;
                long got = dl_catchup(dir, g_catchup_workers);
                store_reload(store_buf);
                if(got <= 0){ noop_best = best; noop_tip = atip; }
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
        for(int n_=0;n_<mux_n_out;n_++){
            int i = (leg_start + n_) % mux_n_out;
            /* 2026-09-10: a leg whose peer announced a block we do not have
             * goes first (its pass fetches it); this slot is revisited */
            int announced_now = 0;
            { int a = leg_announced_pick(-1); if(a >= 0){ announced_now = 1; if(a != i){ i = a; n_--; } } }
            if(g_shutdown_requested){
                /* CC-4: remember the live block-relay-only legs for the next start */
                const char* bo[MAX_BLOCK_RELAY_ONLY]; int nb = 0;
                for(int k = 0; k < mux_n_out && nb < MAX_BLOCK_RELAY_ONLY; k++) if(mux_out_fd[k] >= 0 && mux_out_kind[k] == LEG_BLOCK_ONLY) bo[nb++] = mux_out_host[k];
                if(nb > 0){ long w = anchors_write("anchors.dat", bo, nb, g_chainp->magic, 0x409ULL, (unsigned)time(NULL)); fprintf(stderr, "[dial] anchors.dat: %ld block-relay-only peer(s) saved\n", w); }
                break;   /* don't wait for a full rotation through every leg */
            }
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
            if(leg_peer_hung_up(mux_out_fd[i], &pf.revents)){
                /* 2026-09-09: the peer's doing (every close of ours is labelled
                 * before it reaches here). Read what it left in the socket --
                 * its last words, if any -- and remember the address: an
                 * inbound-full node evicting its newest peer, or a listener
                 * that hangs up after a minute, is not worth the next dial. */
                char unread[200]; leg_drain_unread(mux_out_fd[i], unread, sizeof unread);
                long long age = leg_age_s(i);
                fprintf(stderr,"[dl:%d] %s connection closed theirs (revents 0x%x) after %llds; unread: %s\n",
                        i, mux_out_host[i], pf.revents, age, unread);
                if(g_dialmem && age >= 0 && age <= DM_EARLY_S)
                    dialmem_note_failure(g_dialmem, mux_out_host[i], age <= DM_REFUSED_S ? DM_REFUSED : DM_EARLY_DROP, dialmem_now());
                if(ctl_dial_listed(mux_out_host[i])) ctl_dial_report(mux_out_host[i], 0, (long long)time(NULL));   /* addnode add: back in the queue */
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
            if(mux_out_fd[i]>=0 && mux_out_kind[i] != LEG_BLOCK_ONLY && txsub_worker_ready()){   /* CC-4: block-only legs neither relay nor take addr */
                extern long txrelay_poll_leg(int fd, void* mp, int max_ms);
                long acc = txrelay_poll_leg(mux_out_fd[i], txsub_pool(), 250);
                if(acc == -2){
                    /* Core: "transaction sent in violation of protocol" -- we told
                     * this peer fRelay=0 (-blocksonly) and it relayed anyway */
                    leg_close_ours(i, "blocksonly-violation", "the peer relayed transactions after we sent fRelay=0");
                    mux_next_peer(i, peers, pool_len, out_port);
                    /* DMN-7 (audit 2026-09-03): clock() is process CPU time,
                     * not wall time. Compared against now_ms (CLOCK_MONOTONIC,
                     * a much larger number) this retry stamp was already in
                     * the past the moment it was written, so there was NO
                     * backoff: on a -blocksonly node a peer that relayed a tx
                     * was disconnected and the slot re-dialled immediately,
                     * over and over. dh_now_ms() is the monotonic clock every
                     * other timestamp here uses. */
                    mux_out_nextretry[i] = dh_now_ms() + REDIAL_BACKOFF_MS;
                    continue;
                }
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
            if(mux_out_fd[i]>=0 && mux_out_kind[i] == LEG_BLOCK_ONLY){ extern long txrelay_poll_block_only_leg(int); (void)txrelay_poll_block_only_leg(mux_out_fd[i]); }   /* 2026-09-10: block announcements from block-relay-only legs too */
            if(g_stored_now) stored_break = 1;
            if(apply_first) continue;        /* see APPLY FIRST above */
            if(!announced_now && mux_out_lastpass_ms[i] && now_ms - mux_out_lastpass_ms[i] < LEG_PASS_EVERY_MS) continue;   /* 2026-09-10: no polling for headers between announcements */
            mux_out_lastpass_ms[i] = now_ms;
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
            unsigned budget_s = leg_budget_secs(legs_live());
            alarm(budget_s);
            long n = do_outbound_sync(i);
            alarm(0); mux_budget_fd = -1; sigaction(SIGALRM,&old,NULL);
            if(mux_sync_budget_fired){
                char d[80]; snprintf(d, sizeof d, "the pass exceeded %us%s (where=%d)", budget_s, budget_s > (unsigned)DL_BUDGET_SECS ? ", the only-leg budget" : "", sync_fail_code);
                leg_close_ours(i, "sync-budget", d);
                fprintf(stderr,"[dl:%d] %s exceeded %gs budget; re-dialing\n",
                        i, mux_out_fd[i]>=0?mux_out_host[i]:"?", DL_BUDGET_SECS);
                mux_next_peer(i, srcpool, nsrc, out_port);
            }
            did |= (n>0)?1:0;
            mux_out_announced[i] = 0;                          /* the pass consumed whatever was announced on this leg */
            if(n>0){ leg_hb_note_block(i); stored_break = 1; }   /* 2026-09-10: a block landed -- apply now, the rest of the rotation waits */
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
                    leg_close_ours(i, "probe-budget", "the reorg probe exceeded its budget");
                    fprintf(stderr,"[reorg] probe of %s exceeded %gs budget; re-dialing\n", mux_out_host[i], DL_BUDGET_SECS);
                    mux_next_peer(i, srcpool, nsrc, out_port);
                } else if(pr == 1){
                    /* The chain moved under us: re-anchor this leg and force
                     * a UTXO catch-up pass this rotation. */
                    anchor_locator(mux_out_loc[i]);
                    did = 1;
                    /* STO-7: rewind the new-block choke-point baseline to the
                     * fork. The replacement blocks can sit at or below the old
                     * tip -- and a same-height replacement leaves now_tip ==
                     * last_seen_tip, firing nothing at all -- so without this
                     * the pool never sees the connects that should evict the
                     * transactions the new branch just confirmed. */
                    { long fh = reorg_last_fork_height();
                      if(fh >= 0 && fh < (long)g_dl_last_seen_tip){
                          fprintf(stderr,"[dl] reorg to fork height %ld: replaying the new-block choke point from %ld (was %d)\n",
                                  fh, fh + 1, g_dl_last_seen_tip);
                          g_dl_last_seen_tip = (int)fh;
                      } }
                } else if(pr == 3){
                    /* handed off: the archive is at the fork point; the far-behind
                     * check runs the parallel downloader on the next rotation */
                    for(int k=0;k<mux_n_out;k++) if(mux_out_fd[k]>=0) anchor_locator(mux_out_loc[k]);
                    did = 1; dl_parallel_last_s = 0;
                    { extern long reorg_last_handoff_fork(void); long fh = reorg_last_handoff_fork();
                      if(fh >= 0 && fh < (long)g_dl_last_seen_tip) g_dl_last_seen_tip = (int)fh; }
                } else if(pr < 0){
                    fprintf(stderr,"[reorg] probe of %s rejected a candidate chain (no action taken)\n", mux_out_host[i]);
                }
            }
            /* 2026-09-09: service every OTHER leg's buffered messages now --
             * a ping used to wait for its leg's turn in the rotation (75 s
             * measured; Core's eviction protects its lowest-ping peers, and a
             * peer that never got a pong ranks last at an inbound-full node).
             * Nothing outstanding means only what is already buffered is read. */
            { long long nowsec = (long long)time(NULL);
              for(int k = 0; k < mux_n_out; k++){
                  if(k == i || mux_out_fd[k] < 0) continue;
                  if(mux_out_kind[k] != LEG_BLOCK_ONLY && txsub_worker_ready()){ extern long txrelay_poll_leg(int, void*, int); (void)txrelay_poll_leg(mux_out_fd[k], txsub_pool(), 0); }
                  else if(mux_out_kind[k] == LEG_BLOCK_ONLY){ extern long txrelay_poll_block_only_leg(int); (void)txrelay_poll_block_only_leg(mux_out_fd[k]); }
                  if(!mux_out_good[k] && mux_out_since[k] && nowsec - mux_out_since[k] >= DM_GOOD_S){ mux_out_good[k] = 1; if(g_dialmem) dialmem_note_success(g_dialmem, mux_out_host[k]); }
                  leg_ping_tick(k, nowsec);
              }
              leg_ping_tick(i, nowsec); }
            /* brief yield so we don't spin a CPU core when all legs are idle */
            if(g_stored_now) stored_break = 1;
            if(stored_break){ leg_start = (i + 1) % mux_n_out; break; }   /* 2026-09-10: to the apply; the rotation resumes after this leg */
            if((i&1)==1){ usleep(20000); }
        }
        /* propagate this rotation's relay accepts: one inv per leg covering
         * everything accepted since the last rotation (never back to a tx's
         * own source); peers fetch with getdata, which the drain answers
         * from the pool */
        if(txsub_worker_ready()){
            extern long txrelay_announce(const int* fds, int nfds);
            /* CC-1: transactions accepted by inbound serve children are on the
             * shared ring; hand them to the outbound announcer so they reach
             * the outbound legs too (the worker's own accepts are already
             * queued by tx_relay.c and are skipped by the drain). */
            { extern void txrelay_announce_own(const unsigned char txid[32]);
              txann_worker_drain(txrelay_announce_own); }
            { int rfds[MUX_MAX_OUT]; legs_relay_fds(mux_out_fd, mux_out_kind, mux_n_out, rfds);   /* CC-4 */
              txrelay_announce(rfds, mux_n_out); }
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
            unsigned char saved_relay = node_relay_flag; node_relay_flag = 0;   /* Core: feelers get fRelay=0 */
            int alive = net_feeler_probe(srcpool[pick]);
            node_relay_flag = saved_relay;
            fprintf(stderr,"[net] feeler %s -> %s\n", srcpool[pick], alive?"alive":"dead");
        }
        pb_rotation();

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
            { extern long utxo_live_call_rejected_height(void);
              long rj = utxo_live_call_rejected_height();
              if(rj >= 0)
                  fprintf(stderr,"[dl] block at height %ld REJECTED (%s) and invalidated -- archive at %d, connected %ld; the next rotation fetches the chain that avoids it\n",
                          rj, utxo_live_last_reject(), *(int*)(store_buf+24), utxo_live_applied_height()); }
            if(ar < 0){
                /* Incident 2026-09-01: recovery is no longer blind. Compaction
                 * runs ONLY when utxo_live says the failure is a store error
                 * with a full manifest; a consensus reject or any other
                 * failure backs off and retries WITHOUT touching the runs
                 * (the block is re-applied from the checkpoint; if the
                 * archive is repaired meanwhile it will pass, otherwise it
                 * fails the same way and stays DEGRADED -- visibly). After a
                 * compaction the whole set is walked and must equal the
                 * pre-recovery count, or UTXO tracking halts for good. */
                long rounds = -1;
                if(utxo_live_halted()){
                    /* a spend found its coin absent right after verification resolved
                     * it: the store is lying and nothing downstream can be trusted */
                    utxo_live_ok = 0; g_utxo_live_on = 0; dl_publish_connected_tip();
                    fprintf(stderr,"[dl] UTXO TRACKING HALTED at height %ld: store lookup inconsistency during apply (incident 2026-09-01 class). "
                                   "Blocks keep flowing without UTXO tracking; operator must drop and rebuild the UTXO state.\n",
                            utxo_live_applied_height());
                } else if(utxo_live_recovery_applicable()){
                    long count_before = utxo_live_count();
                    fprintf(stderr,"[dl] utxo_live_catchup FAILED at height %ld with a full manifest -- compacting in place (pre-recovery count %ld)\n",
                            utxo_live_applied_height(), count_before);
                    rounds = utxo_live_recover();
                    if(!utxo_live_verify_after_recovery(count_before)){
                        utxo_live_ok = 0; g_utxo_live_on = 0; dl_publish_connected_tip();
                        fprintf(stderr,"[dl] UTXO TRACKING HALTED at height %ld: the set is inconsistent after recovery. "
                                       "Blocks keep flowing without UTXO tracking; operator must drop and rebuild the UTXO state.\n",
                                utxo_live_applied_height());
                        ar = -1;
                    } else {
                        ar = utxo_live_catchup(store_buf);
                    }
                } else {
                    fprintf(stderr,"[dl] utxo_live_catchup FAILED at height %ld: %s%s%s -- recovery refused (not a full manifest); will retry from the checkpoint\n",
                            utxo_live_applied_height() + 1,
                            utxo_live_fail_kind_name(utxo_live_last_fail_kind()),
                            utxo_live_last_fail_kind() == 1 ? ": " : "",
                            utxo_live_last_fail_kind() == 1 ? utxo_live_last_reject() : "");
                }
                if(ar >= 0){
                    utxo_fail_streak = 0;
                    fprintf(stderr,"[dl] utxo recovery SUCCEEDED (%ld compaction round(s), post-recovery walk verified) -- tracking continues at height %ld\n",
                            rounds, utxo_live_applied_height());
                } else if(!utxo_live_ok){
                    /* halted: no backoff, no retry -- the heartbeat carries the marker */
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
        /* The header mirror follows the ARCHIVE (it is derived from stored
         * blocks and feeds the downloader's own header fetch), so it keeps
         * its own watcher on the stored tip -- whichever path appended. */
        {
            int now_stored = *(int*)(store_buf+24);
            if(now_stored != last_seen_stored){
                if(now_stored > last_seen_stored) dl_header_mirror_topup(store_buf);
                last_seen_stored = now_stored;
            }
        }
        dl_new_block_choke();   /* the 3.1 choke point; shared with the parallel downloader (step 1) */
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
            char storedbuf[40]; storedbuf[0]=0;
            { long pt = node_public_tip(store_buf), stt = *(int*)(store_buf+24);
              if(stt != pt) snprintf(storedbuf, sizeof storedbuf, " stored=%ld", stt); }
            if(g_dialmem) fprintf(stderr,"[dial] memory: %d address(es) remembered, %llu candidate(s) skipped under backoff; blocks: %lu claimed, %lu duplicate fetch(es) avoided\n", dialmem_count(g_dialmem), (unsigned long long)g_dialmem->skips, g_inflight.claims, g_inflight.refused);
            fprintf(stderr,"[dl] heartbeat: tip=%ld%s peers=%d/%d txouts=%ld uptime=%s%s%s\n",
                    node_public_tip(store_buf), storedbuf, live_peers, mux_n_out,
                    utxo_live_ok?live_utxo_disp():-1L,
                    fmt_uptime(upbuf, (now_ms-boot_ms)/1000), failbuf,
                    utxo_live_halted() ? "  [UTXO HALTED -- inconsistent after recovery; drop and rebuild]"
                    : utxo_fail_streak ? "  [UTXO DEGRADED -- retrying]" : "");
            if(g_cfg.maxuploadtarget_mb > 0)
                fprintf(stderr,"[dl] upload: %lldMB of %ldMB this 24h window\n",
                        upload_bytes_this_window()>>20, g_cfg.maxuploadtarget_mb);
            { extern long hdrtree_prune_below(long); long ptip = (long)*(int*)(store_buf+24); if(ptip > 20000) hdrtree_prune_below(ptip - 20000); }   /* the fork tree keeps the recent past */
            /* the coinstats history's health and repair, once a heartbeat (2026-09-08) */
            if(g_cfg.coinstatsindex){
                extern int csi_hist_repair_tick(long, int, long long);
                long target = utxo_live_ok ? utxo_live_applied_height() : (long)*(int*)(store_buf+24);
                csi_hist_repair_tick(target, dl_tip_is_ibd(), (long long)time(NULL));
            }
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
              else { long bo = g_dialmem ? dialmem_note_failure(g_dialmem, dhost, strstr(dr.why, "handshake") ? DM_REFUSED : DM_CONNECT_FAIL, dialmem_now()) : 0;
                     fprintf(stderr, "[dial] %s: background dial failed: %s (not dialled again for %ld min)\n", dhost, dr.why[0] ? dr.why : "?", bo / 60); }
          } }
        /* reserved slots: at least ONE leg per reachable anonymity network,
         * dialled in the background, on top of the clearnet legs (Core keeps
         * an extra network-specific outbound for the same reason) */
        /* CC-4: keep bo_want() block-relay-only legs on clearnet, dialled in the
         * background like the anonymity-network reserved legs below. The host is
         * registered as block-only BEFORE the dial so the version carries fRelay=0. */
        if((rot % 8)==0 && legs_block_only() < bo_want() && mux_n_out < MUX_MAX_OUT && dh_inflight_count() < DH_MAX){
            for(int ci = 0; ci < nsrc; ci++){
                int net = leg_net_of(srcpool[ci]);
                if(net != BMC_NET_IPV4 && net != BMC_NET_IPV6) continue;
                int already = 0; for(int k = 0; k < mux_n_out; k++) if(mux_out_fd[k] >= 0 && !strcmp(mux_out_host[k], srcpool[ci])){ already = 1; break; }
                if(already || host_is_block_only(srcpool[ci])) continue;
                { char ip[128]; ctl_ip_only(srcpool[ci], ip, sizeof ip); if(ctl_is_banned(ip)) continue; }
                bo_add(srcpool[ci]);
                fprintf(stderr, "[dial] %s: dialing as block-relay-only (%d of %d)\n", srcpool[ci], legs_block_only() + 1, bo_want());
                dh_start(srcpool[ci], out_port);
                break;
            }
        }
        if((rot % 8)==0 && g_node_status && g_node_status->net_active && mux_n_out < MUX_WANT_OUT() + 2 && mux_n_out < MUX_MAX_OUT){
            static const int anon_nets[2] = { BMC_NET_TORV3, BMC_NET_I2P };
            for(int an = 0; an < 2 && dh_inflight_count() < DH_MAX; an++){
                int net = anon_nets[an];
                if(!dialer_net_reachable(net) || legs_on_net(net) > 0 || dh_inflight_net(net)) continue;
                int ci = dh_reserved_pick(an, net, srcpool, nsrc);
                if(ci >= 0) dh_start(srcpool[ci], out_port);
            }
        }
        /* CC-6: Core CheckForStaleTipAndEvictPeers -- when no block has arrived
         * for 30 minutes and we are not catching up, want ONE extra full-relay
         * leg so a partition is noticed (Core's m_try_another_outbound_peer).
         * The extra leg is not torn down when the tip is fresh again: the
         * want simply drops back and normal leg churn absorbs it. */
        extern int tx_accept_stale_tip_extra(long now);
        int stale_extra = tx_accept_stale_tip_extra((long)time(NULL));
        { static int prev_stale = 0;
          if(stale_extra != prev_stale){ fprintf(stderr, "[dial] tip %s: wanting %d outbound\n", stale_extra ? "stale for 30 min (no block seen)" : "fresh again", MUX_WANT_OUT() + stale_extra); prev_stale = stale_extra; } }
        if(mux_n_out - legs_anon() - legs_block_only() < MUX_WANT_OUT() + stale_extra && (rot % 8)==0){
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
            for(int ci=0; ci<nsrc && mux_n_out - legs_anon() - legs_block_only() < MUX_WANT_OUT() + stale_extra && mux_n_out<MUX_MAX_OUT; ci++){
                if(topup_filled >= 1 || topup_fail >= 4) break;
                if(leg_is_anon_net(leg_net_of(srcpool[ci]))) continue;   /* the helper owns those */
                int already=0;
                for(int k=0;k<mux_n_out;k++) if(!strcmp(mux_out_host[k],srcpool[ci])){ already=1; break; }
                if(already) continue;
                if(g_dialmem && !dialmem_allowed(g_dialmem, srcpool[ci], dialmem_now())) continue;   /* 2026-09-09: under backoff */
                /* 2026-09-10: one background dial per top-up tick; the result
                 * appends a leg through dh_install_leg when it lands. Never an
                 * inline connect in the loop that reads the legs. */
                if(dh_inflight_for(-1)) break;                       /* a top-up dial is already out */
                if(dh_start_slot(srcpool[ci], out_port, -1)) topup_filled++;
                else { if(!topup_fail++) snprintf(topup_why,sizeof topup_why,"%s: no dial helper free", srcpool[ci]); }
            }
            if(topup_fail)
                fprintf(stderr,"[dl] outbound top-up: %d dial(s) not started, first %s\n",
                        topup_fail, topup_why);
        }

        /* manual connections (addnode add / onetry): one dial per rotation,
         * inline like the top-up (an IP dial is milliseconds), whether or not
         * the node "wants" more outbound -- Core's manual peers are extra to
         * the target. A persistent entry that drops is re-queued at the drop
         * site with backoff; a onetry entry is consumed here. */
        if(mux_n_out < MUX_MAX_OUT){
            long long nowsec = (long long)time(NULL);
            const char* mh = ctl_dial_next(nowsec, ctl_dial_is_leg);
            if(mh && !leg_is_anon_net(leg_net_of(mh))){
                char host[64]; snprintf(host, sizeof host, "%s", mh);
                int nfd = outbound_connect(host, 300, out_port);
                if(nfd >= 0){
                    strncpy(mux_out_host[mux_n_out], host, 127);
                    mux_out_fd[mux_n_out] = nfd; txrelay_leg_reset(nfd); leg_note_installed(mux_n_out); mux_out_kind[mux_n_out] = host_is_block_only(host) ? LEG_BLOCK_ONLY : LEG_FULL;
                    mux_out_wants_v2[mux_n_out] = (unsigned char)g_peer_wants_addrv2;
                    mux_out_peer[mux_n_out] = 0;
                    anchor_locator(mux_out_loc[mux_n_out]);
                    mux_out_nextretry[mux_n_out] = 0;
                    { char pv[256]; format_peer_version_info(pv, sizeof pv);
                      fprintf(stderr,"[dl] filled outbound %d = %s (fd %d) %s addrv2=%d [manual: addnode]\n", mux_n_out, host, nfd, pv, (int)mux_out_wants_v2[mux_n_out]); }
                    rpc_fill_peer_slot(mux_n_out, host);
                    mux_n_out++;
                    ctl_dial_report(host, 1, nowsec);
                } else {
                    fprintf(stderr,"[dl] addnode %s: dial failed (%s)%s\n", host, dial_fail_reason(), ctl_dial_listed(host) ? "; retrying with backoff" : "");
                    ctl_dial_report(host, 0, nowsec);
                }
            }
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
    long n = tx_legacy_sigops(tx, len);
    /* SCR-10: -1 means the transaction did not parse. Every transaction in a
     * template came from the mempool and was parsed to get there, so this is
     * unreachable; it is clamped rather than propagated because "sigops" is a
     * COUNT in the template JSON and a negative one would be a worse lie than
     * a zero. The clamp is about the field's type, not a judgment that the
     * transaction is fine. */
    return n < 0 ? 0 : n * 4;
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
/* WAL-3 (audit 2026-09-03): registered with wallet_enc_state.c and called once
 * encryptwallet has sealed the mnemonic AND verified the container opens. From
 * that moment the container is the source of truth -- wenc_unlock re-derives
 * the seed from it -- so these two must not outlive it. They used to sit here
 * for the life of the process: `walletlock` zeroed the seed and reported a
 * locked wallet while the provider went on serving the mnemonic and its BIP39
 * passphrase, both readable from /proc/<pid>/mem, a swap partition or a
 * hibernation image. secure_zero, because a plain memset on a buffer that is
 * dead afterwards is exactly the store -O2 may delete. */
static void forget_wallet_mnemonic(void){
    secure_zero(g_wallet_mnemonic, sizeof g_wallet_mnemonic);
    secure_zero(g_wallet_bip39pass, sizeof g_wallet_bip39pass);
    fprintf(stderr, "[wallet] mnemonic sealed and verified: plaintext copy cleared from memory\n");
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
    rpc_chain_set_public_tip_fn(rpc_public_tip);   /* 3.1: every chain RPC's tip is the CONNECTED tip */
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
      { extern void wenc_set_mnemonic_forget(void (*)(void));
        wenc_set_mnemonic_forget(forget_wallet_mnemonic); }
    /* WAL-3 (rest): the wallet secrets are statics that live for the life of
     * the process, so lock them out of swap and out of any core file before
     * anything is written into them. Said out loud either way: an operator
     * whose RLIMIT_MEMLOCK is too low should know the seed can reach swap,
     * and a line saying it succeeded is the only evidence that it did. */
    { int a = secure_lock(g_wallet_seed, sizeof g_wallet_seed);
      int b = secure_lock(g_wallet_mnemonic, sizeof g_wallet_mnemonic);
      int c = secure_lock(g_wallet_bip39pass, sizeof g_wallet_bip39pass);
      extern int wenc_lock_secrets(void);
      int d = wenc_lock_secrets();
      if (a && b && c && d)
          fprintf(stderr,"[wallet] seed, mnemonic and passphrase locked into RAM "
                         "(mlock) and excluded from core dumps\n");
      else
          fprintf(stderr,"[wallet] WARNING: could not lock wallet secrets into RAM "
                         "(seed=%d mnemonic=%d passphrase=%d container=%d) -- they may "
                         "reach swap or a hibernation image. Raise RLIMIT_MEMLOCK "
                         "(LimitMEMLOCK= in the unit file) to fix.\n", a, b, c, d);
    }

      /* multi-wallet (rpc_wallet_ops.c): loadwallet/createwallet install the
       * switched-to wallet's seed through the SAME installer the encryption
       * unlock path uses -- one seed slot, one way to write it. */
      rpc_wops_set_seed_installer(wenc_install_seed);
      char wd[4200]; snprintf(wd, sizeof wd, "%s", dir ? dir : ".");   /* the datadir path: PATH_MAX-sized like g_cfg's */
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
              secure_zero(mn, sizeof mn);      /* WAL-3 */
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
      extern const unsigned char* mpool_get(void* mp, const unsigned char txid[32], unsigned long* out_len);
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
        { extern int csi_hist_query(long, int, void*); extern long csi_hist_first(void), csi_hist_last(void);
          extern void rpc_chain_set_coinstats_hist(int (*)(long, int, void*), long (*)(void), long (*)(void)) __attribute__((weak));   /* the test rules that compile this file without rpc_chain.o (link-check) */
          if (rpc_chain_set_coinstats_hist) rpc_chain_set_coinstats_hist(csi_hist_query, csi_hist_first, csi_hist_last);
          { extern const char* csi_hist_status(void);
            extern void rpc_chain_set_coinstats_hist_status(const char* (*)(void)) __attribute__((weak));
            if (rpc_chain_set_coinstats_hist_status) rpc_chain_set_coinstats_hist_status(csi_hist_status); } }
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
      { extern void rpc_chain_set_mine_on_demand(int);
        /* Core: MineBlocksOnDemand() == consensus.fPowNoRetargeting -- so
         * -blockversion is honoured on regtest and nowhere else. */
        rpc_chain_set_mine_on_demand(g_chainp->pow_no_retargeting); }
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
        if(r) rj_free(r);
        rj_free(p);
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
    /* RPC-15 (audit 2026-09-03): CREDENTIALS BEFORE THE LISTENER.
     * These two blocks used to run AFTER rpc_server_start, leaving a window in
     * which the port was accepting but no rpcauth entry was registered and no
     * cookie had been written -- so a client with valid rpcauth credentials
     * got 401, and only rpcuser/rpcpassword worked. Fail-closed, but wrong.
     *
     * It also removes a data race for free: g_rpcauth[] was being written
     * while worker threads could already be reading it, unsynchronised. With
     * the writes before the server starts, no worker exists yet.
     *
     * This is Core's own order -- InitRPCAuthentication() (cookie generation
     * and rpcauth loading) runs at the top of StartHTTPRPC(), before
     * RegisterHTTPHandler. The pidfile and startupnotify stay AFTER the bind,
     * deliberately: their whole point is to signal that the node is up. */
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

    int actual = 0; char err[256];
    if (rpc_server_start(&cfg, &actual, err, sizeof err) != 0){
        fprintf(stderr, "[rpc] server start failed: %s\n", err);
        return;
    }
    if (g_cfg.rest){
        /* weak: the test rules that compile this file without rpc_server.o (link-check) */
        extern void rpc_rest_enable(int) __attribute__((weak));
        if (rpc_rest_enable){ rpc_rest_enable(1); fprintf(stderr, "[rpc] REST interface on the RPC listener (rest=1; unauthenticated, like Core's)\n"); }
    }
    /* 2026-09-08: the Esplora facade (mempool.space's BACKEND esplora) */
    if (g_cfg.esplora_port > 0){
        extern int rpc_esplora_start(const char*, int, char*, size_t);
        char eerr[256] = "";
        if (rpc_esplora_start(g_cfg.esplora_bind, g_cfg.esplora_port, eerr, sizeof eerr) == 0)
            fprintf(stderr, "[rpc] Esplora facade on %s:%d (bmc.esploraport; no auth: keep it on loopback or behind a proxy)\n", g_cfg.esplora_bind, g_cfg.esplora_port);
        else fprintf(stderr, "[rpc] Esplora facade NOT started: %s\n", eerr);
    }
    fprintf(stderr, "[rpc] JSON-RPC server on %s:%d (live-node + chain, user=%s)\n",
            bindaddr[0] ? bindaddr : "127.0.0.1", actual, user);
    /* -rpccookiefile, else <datadir>/.cookie -- Core's default auth method.
     * The daemon has already chdir'd into the (per-chain) datadir, so the
     * bare relative name lands in the right place on every chain. */
    /* -pid: Core writes bitcoind.pid so an init script can find the process;
     * ours defaults to bmcbitcoind.pid (the discussed divergence, node_config.c).
     * Written after the RPC port is bound, i.e. once the node is actually
     * up, so the file's existence means something. */
    if (g_cfg.pidfile[0]){
        FILE* pf = fopen(g_cfg.pidfile, "w");
        if (pf){ fprintf(pf, "%d\n", (int)getpid()); fclose(pf);
                 fprintf(stderr,"[boot] pid %d written to %s\n", (int)getpid(), g_cfg.pidfile); }
        else     fprintf(stderr,"[boot] could not write -pid=%s: %s\n", g_cfg.pidfile, strerror(errno));
    }
    if (g_cfg.startupnotify[0]) notify_run(g_cfg.startupnotify, "", "startupnotify");
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
            if(bmc_pthread_create(&g_mempool_reload_thread, mempool_reload_thread, NULL) == 0)
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
    if(bmc_pthread_create(&th, i2p_accept_thread, NULL) != 0){
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
        mux_out_fd[mux_n_out]=fd; txrelay_leg_reset(fd); mux_out_kind[mux_n_out] = host_is_block_only(peers[i]) ? LEG_BLOCK_ONLY : LEG_FULL;   /* CC-4 */ mux_out_cmpct[mux_n_out] = 0;
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
                    snprintf(peerdesc, sizeof peerdesc, "%.60s:0", m.b32);   /* a b32 name is 60 chars */
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
            if(c>=0) peer_handshake_deadline(c, g_cfg.peer_timeout_s);   /* CC-7: -peertimeout until verack; the NET-3 idle bound is armed after the handshake */
            if(c>=0 && g_shutdown_requested){
                /* SC1 (2026-09-05, /mnt/2tbssd bmc-vs-Core benchmark): the
                 * stop sequence was observed forking a child into a parent
                 * that was already tearing down -- the accept fired in the
                 * window between SIGTERM and the listener closing, and the
                 * child inherited a half-torn-down address space. Core
                 * closes its listeners first, then drains; we now refuse at
                 * the accept the same way: one clean close, no fork, the
                 * peer reconnects to whatever comes up next. Rate-limited:
                 * a shutdown racing a connect flood must not flood the log. */
                static long long last_stop_log_ms = 0;
                long long nms; { struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
                                 nms = ts.tv_sec*1000L + ts.tv_nsec/1000000L; }
                if(nms - last_stop_log_ms > 1000){
                    fprintf(stderr,"[serve] shutting down -- refusing inbound %s\n", peerdesc);
                    last_stop_log_ms = nms;
                }
                close(c); c = -1;
            }
            if(c>=0) serve_idx_topup();
            if(c>=0 && upload_note_and_check(0)){
                /* over -maxuploadtarget for this 24h window -- unless the
                 * peer has the `download` permission (Core: served regardless) */
                char ipb[64]; const char* q = strrchr(peerdesc, ':'); size_t n = q ? (size_t)(q - peerdesc) : strlen(peerdesc);
                if(n >= sizeof ipb) n = sizeof ipb - 1;
                memcpy(ipb, peerdesc, n); ipb[n] = 0;
                if(!(netperm_for(ipb) & NP_DOWNLOAD)){ close(c); c = -1; }
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
                    /* DMN-6 (audit 2026-09-03): drop the RPC listener too.
                     * A serve child inherited it across fork and kept the
                     * port bound after the parent exited, so the NEXT
                     * instance's rpc_server_start failed with "bind() failed"
                     * -- and that failure is non-fatal, so the new node ran
                     * with no RPC and no cookie until the last old child
                     * died. Weak-linked: several harnesses link main.c
                     * without rpc_server.c. */
                    { extern void rpc_server_close_listener_in_child(void) __attribute__((weak));
                      if (rpc_server_close_listener_in_child)
                          rpc_server_close_listener_in_child(); }
                    /* ...and take the default SIGTERM disposition back. The
                     * parent installed a flag-setting handler that nothing in
                     * bitcoin_serve.asm ever reads, so a child ignored
                     * shutdown entirely and was stopped only by its peer
                     * hanging up or by SIGKILL -- which is why a stop with N
                     * inbound peers waited for all N (systemd: up to 900 s). */
                    signal(SIGTERM, SIG_DFL);
                    signal(SIGINT,  SIG_DFL);
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
                    /* decided per peer once its version is in hand (relay policy, share) */
                    g_accept_version_hook = serve_on_peer_version;
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
                    version_tell_the_truth();
                    int hok = node_accept_handshake(c);
                    if(hok==1) peer_inbound_deadline(c);      /* NET-3: handshake done -> the 20-minute idle bound */
                    if(hok==1) g_inbound_slot = inbound_slot_claim(peerdesc);
                    /* CC-1: this child's accepts are tagged with its slot (so it never
                     * announces a tx back to the peer that sent it) and it starts
                     * announcing to the peer if the peer negotiated relay. */
                    /* CC-3 (Core AttemptToEvictConnection): every inbound slot is taken.
                     * Before this, the child SERVED ANYWAY, unrecorded -- the node neither
                     * evicted nor refused, and getpeerinfo under-reported. Now: pick a
                     * victim by Core's protection rounds, ask it to leave (its txann_wait
                     * sees the flag within a second and exits cleanly, freeing the slot),
                     * claim the slot, and if every peer is protected, refuse as Core does. */
                    if(hok==1 && g_inbound_slot < 0 && g_node_status){
                        int v = inbound_select_victim(g_node_status, (long long)time(NULL), MUX_MAX_OUT, RPC_MAX_PEERS - 1);
                        if(v >= 0){
                            g_node_status->peers[v].evict_requested = 1;
                            fprintf(stderr, "[serve] inbound slots full: evicting slot %d (%s) to admit %s\n", v, g_node_status->peers[v].addr, peerdesc);
                            for(int w = 0; w < 25 && g_inbound_slot < 0; w++){ usleep(100000); g_inbound_slot = inbound_slot_claim(peerdesc); }
                        }
                        if(g_inbound_slot < 0){
                            fprintf(stderr, "[serve] inbound slots full and every peer protected: refusing %s\n", peerdesc);
                            close(c); _exit(0);
                        }
                    }
                    if(hok==1){ txann_set_my_slot(g_inbound_slot); txann_child_init(g_inbound_slot, node_relay_flag && g_peer_relays_txs); }
                    char pv[256]; pv[0]=0; if(hok==1) format_peer_version_info(pv, sizeof pv);
                    close(l6 >= 0 ? l6 : l);
                    fprintf(stderr,"[serve] inbound %s %s [%s] (pid %d) %s\n", peerdesc,
                            hok==1?"connected":"handshake failed", v2res, getpid(), pv);
                    if(hok==1)
                        node_serve_loop(c, (mkdir("logs", 0755), node_log_open(g_logpath)), store_buf, ht_idx, out_buf, (long)sizeof out_buf);
                    if(g_inbound_slot >= 0 && g_node_status) g_node_status->peers[g_inbound_slot].used = 0;
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
        /* DMN-7: clock() is CPU time, which in the mux parent advances at a
         * small fraction of wall time -- REDIAL_BACKOFF_MS (30 s) became a
         * 30-CPU-second gap, i.e. minutes of wall clock. Monotonic, like
         * every other timestamp in this file. */
        long long now_ms = dh_now_ms();
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


/* ---------------------------------------------------------------- DMN-1
 * Single-instance guard on the per-chain datadir (audit 2026-09-03).
 *
 * Core takes an exclusive lock on <datadir>/.lock in LockDataDirectory()
 * before touching anything, and aborts with "Cannot obtain a lock on data
 * directory". This daemon had no equivalent. append.lock is flock'ed only
 * around individual appends, never held for the process lifetime, and the
 * only thing that could fail on a co-resident instance was the P2P bind --
 * and only with listen=1 on the same port. The RPC bind failure is
 * deliberately non-fatal, so the second instance simply carried on.
 *
 * The audit reproduced two full boots on one datadir. That is not a
 * theoretical race: boot runs archive_trim_derived_tails, which truncate()s
 * the index.dat / headers.dat / chainwork.dat tails computed from a snapshot
 * of the index, then zeroes duplicate records, then forks a worker that owns
 * the single-writer LSM UTXO set. Instance B doing that under instance A's
 * writer is how 2026-08-31's "a stale co-resident daemon was SIGKILLed and
 * the survivor stopped applying blocks" (main.c's own note) happens.
 *
 * The fd is deliberately LEAKED for the process lifetime -- that is what
 * holds the lock. It is not FD_CLOEXEC and it is not closed on any path:
 *   - forked children (the download worker, inbound serve children, the
 *     compaction child) share the same open file description, so they hold
 *     the same lock rather than contending for it. An ORPHANED worker
 *     therefore keeps the datadir locked, which is correct: it is still
 *     writing to it, and that orphan is one of the ways the audit's failure
 *     arises.
 *   - the kernel releases it when the last holder exits, so a SIGKILLed
 *     daemon leaves no stale lock to clean up.
 * Called after the per-chain chdir, so ".lock" lands in <datadir>/<chain>,
 * which is the directory that actually gets written. */
static int datadir_lock_fd = -1;
/* ---------------------------------------------------------------- MEM-1
 * Chain context for the mempool's finality rules, refreshed on every tip
 * change beside tx_accept_set_tip.
 *
 * Core's PreChecks evaluates CheckFinalTxAtTip and CheckSequenceLocks against
 * the NEXT block's height and the tip's median time past (BIP113). The policy
 * layer cannot read headers or the UTXO set, so both are pushed in from here:
 * the MTP through the same 11-header window pow_check_bits already relies on,
 * and the prevout heights through a resolver that reads the live LSM.
 *
 * A transaction whose parent is still in the MEMPOOL has no confirmation
 * height; mpol_add_core substitutes the next block's height for those, which
 * is where such a parent would confirm. */
extern int  utxo_live_median_time_past(long height, unsigned long* out);
extern long utxo_live_lsm_get(const unsigned char txid_wire[32], unsigned int vout,
                              unsigned long long* value, unsigned long* height,
                              unsigned long* is_coinbase, const unsigned char** script,
                              unsigned long* slen);
static void* g_seq_store;
static long mempool_seq_height(const unsigned char txid[32], unsigned long index,
                               unsigned long long* out_height){
    unsigned long long value = 0; unsigned long h = 0, cb = 0, sl = 0;
    const unsigned char* spk = 0;
    if (utxo_live_lsm_get(txid, (unsigned)index, &value, &h, &cb, &spk, &sl) != 1)
        return 0;
    *out_height = (unsigned long long)h;
    return 1;
}
static void mempool_refresh_seqlocks(void* store_buf, long now_tip){
    extern void mpool_policy_set_seqlocks(long, unsigned long, int,
                                          long (*)(const unsigned char*, unsigned long,
                                                   unsigned long long*));
    g_seq_store = store_buf;
    unsigned long mtp = 0;
    if (!utxo_live_median_time_past(now_tip, &mtp)){
        /* No readable header window: leave the rules UNCONFIGURED rather than
         * enforce against a zero time, which would reject every transaction
         * carrying a time-based nLockTime. */
        mpool_policy_set_seqlocks(-1, 0, 0, 0);
        return;
    }
    unsigned char bh[32]; int csv = 0;
    { memset(bh, 0, 32);
      csv = (int)((script_flags_for_block((unsigned long long)(now_tip + 1), bh) >> 10) & 1ULL); }
    mpool_policy_set_seqlocks(now_tip + 1, mtp, csv, mempool_seq_height);
}

static int datadir_lock_acquire(const char* effdir){
    datadir_lock_fd = open(".lock", O_RDWR|O_CREAT, 0600);
    if(datadir_lock_fd < 0){
        fprintf(stderr,"[boot] FATAL: cannot open %s/.lock: %s\n", effdir, strerror(errno));
        return 0;
    }
    if(flock(datadir_lock_fd, LOCK_EX|LOCK_NB) != 0){
        if(errno == EWOULDBLOCK)
            fprintf(stderr,"[boot] FATAL: cannot obtain a lock on data directory %s. "
                           "bmcbitcoind is probably already running.\n", effdir);
        else
            fprintf(stderr,"[boot] FATAL: cannot lock %s/.lock: %s\n", effdir, strerror(errno));
        close(datadir_lock_fd); datadir_lock_fd = -1;
        return 0;
    }
    return 1;
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
            "===== bmcbitcoind  LOG START: %s\n"
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
     * meaning, so `bmcbitcoind -datadir=/x serve` and `bmcbitcoind serve /x` are
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
    /* ---- DMN-10 (audit 2026-09-03): validate the MODE before doing work ----
     * `bmcbitcoind -datadir=/x serve` is documented as equivalent to the
     * positional form, and it is not: stripping the flag leaves argc == 2, the
     * usage check below passes on flag_datadir, and the serve branch far below
     * is gated on argc >= 3 -- so the process resolved the datadir, chdir'd,
     * loaded the config, trimmed derived tails, opened the store and
     * self-seeded genesis, and only THEN fell off the end and returned 2 with
     * no message. An unknown mode did the same.
     *
     * Checking the mode here costs nothing and turns both into an immediate,
     * explained exit. The serve branch's own argc gate is widened to accept
     * the flag form separately; everything it reads past argv[2] is already
     * guarded by its own argc checks. */
    { static const char* const MODES[] = {
          "sync", "ibd", "follow", "serve", "server-test", "serve-test" };
      int known = 0;
      for (unsigned mi = 0; mi < sizeof MODES / sizeof MODES[0]; mi++)
          if (!strcmp(mode, MODES[mi])){ known = 1; break; }
      if (!known){
          fprintf(stderr, "%s: unknown mode \"%s\"\n", argv[0], mode);
          fprintf(stderr,"usage: %s [-datadir=<dir>] [-conf=<file>] sync <dir> | ibd <dir> | follow <dir> | serve <dir> <port> | server-test <dir>\n", argv[0]);
          return 2;
      } }
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
      { extern int (*g_serve_tx_gate)(void); extern int (*g_serve_inv_gate)(const unsigned char*, long);
        extern int (*g_serve_mempool_hook)(int, void*); extern void (*g_serve_policy_log)(const char*);
        g_serve_tx_gate = serve_tx_gate; g_serve_inv_gate = serve_inv_gate;
        g_serve_mempool_hook = serve_mempool_msg; g_serve_policy_log = serve_policy_disconnect_log; }
      { extern void rp_set_blocksonly(int); extern void rpc_node_set_localrelay(int);
        rp_set_blocksonly(g_cfg.blocksonly);
        node_relay_flag = g_cfg.blocksonly ? 0 : 1;          /* fRelay of every version we send (per-peer overrides in the serve child) */
        rpc_node_set_localrelay(!g_cfg.blocksonly);
        if(g_cfg.blocksonly) fprintf(stderr,"[config] -blocksonly: no tx relay from peers (relay permission excepted); RPC submissions still relay\n"); }
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
    /* shrinkdebugfile moved after the chdir into the chain directory (2026-09-08): with the default relative
     * "debug.log" it used to shrink whatever debug.log sat in the directory the daemon was started from */
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
      /* VAL-5 (rest): the same arming for ContextualCheckBlockHeader's trio
       * on the reorg path. The boot header fetch and block connect already
       * enforce them; reorg_analyze checked PoW, linkage and the nBits
       * schedule but not time-too-old / time-too-new / bad-version, so a
       * candidate chain carrying such a header was judged on work alone and,
       * if it won, every one of its blocks was connected. */
      { extern void reorg_set_header_rules(long);
        reorg_set_header_rules(dlc_bip34_height()); }
      /* NET-5: the same rules on the INBOUND-BLOCK path. bitcoin_serve.asm's
       * .do_block appended a peer-pushed block after cons_verify (context-
       * free) and a prev-hash check only, so a header Core rejects at
       * ContextualCheckBlockHeader became the durable archive tip at a
       * height it can never connect at. One call arms all four rules there;
       * see serve_block_ctx_ok in daemon/tx_accept.c. */
      { extern void serve_set_header_rules(int, int, int, unsigned int, long);
        serve_set_header_rules(g_chainp->pow_no_retargeting,
                               g_chainp->allow_min_difficulty,
                               g_chainp->enforce_bip94,
                               g_chainp->pow_limit_bits,
                               dlc_bip34_height()); }
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
    /* DMN-1: before ANYTHING touches the datadir -- archive_trim_derived_tails
     * truncates, genesis seeding writes, the worker fork owns the LSM. */
    if(!datadir_lock_acquire(effdir)) return 1;
    /* 2026-09-08: from here on the log goes where Core's goes. The lines
     * above this point (config echo, chain selection, lock failures) reach
     * whatever launched us, as Core's early lines do. */
    if(g_cfg.shrinkdebugfile) log_shrink(g_logpath);
    if(log_sink_open(g_logpath, g_cfg.printtoconsole))
        fprintf(stderr,"[boot] logging to %s/%s (debuglogfile)%s\n", effdir, g_logpath, g_cfg.printtoconsole ? " and to the console (printtoconsole=1)" : "");
    else
        fprintf(stderr,"[boot] WARNING: could not open %s/%s for logging (%s) -- logging to stderr as launched\n", effdir, g_logpath, strerror(errno));
    /* DMN-1: before ANYTHING touches the datadir -- archive_trim_derived_tails
     * truncates, genesis seeding writes, the worker fork owns the LSM. */
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
    /* Each chain logs into its OWN directory -- the asm logger
     * (node_log_open) writes via the cwd, which is the chain datadir, so a
     * regtest run can never interleave with the mainnet log. The file is
     * debug.log, as Core's is, and Core separates chains the same way: by
     * directory, not by filename. logs/ is still created because the
     * benchmark and soak harnesses put their own files there. */
    mkdir("logs", 0755);
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
    { extern void par_set(int); par_set(g_cfg.par); }   /* -par: script-verification threads (Core semantics) */
    if(store_init(store_buf)!=1){ fprintf(stderr,"store_init failed\n"); return 1; }
    /* A fresh non-main datadir self-seeds its own genesis at index 0 (the
     * mainnet archive got genesis by a one-time injection, 5f36dee -- a
     * regtest dir is created empty every time, so the daemon must do it).
     * Everything downstream (locator build, catch-up, script-flag heights,
     * the UTXO walk's skip-genesis-coinbase rule) already assumes index ==
     * height with genesis at 0.
     *
     * 2026-09-06: this used to skip CHAIN_MAIN, because THIS box's mainnet
     * archive had genesis from a one-time injection. Every OTHER fresh
     * mainnet datadir then built an archive shifted by one -- the serial leg
     * appends the first block a peer sends, and no peer relays genesis. See
     * archive_seed.h. */
    /* the ban list, before anything dials or accepts: a restart must not
     * forgive a ban (Core loads banlist.json at startup and sweeps expiries). */
    { int nb = banlist_load((long long)time(NULL), banlist_restore_one);
      if (nb < 0) fprintf(stderr, "[ban] banlist.json could not be read -- starting with no bans\n"); }
    { int sd = archive_seed_genesis_if_empty(store_buf, g_chainp->genesis, (unsigned long)g_chainp->genesis_len);
      if(sd < 0){ fprintf(stderr,"[boot] failed to seed the %s genesis block\n", g_chainp->name); return 1; }
      if(sd == 1) fprintf(stderr,"[boot] %s genesis seeded at height 0 (empty archive)\n", g_chainp->name); }

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

    /* DMN-10: `-datadir=<dir> serve` leaves argc == 2, so the flag form has to
     * be accepted here too. The port and worker counts below already default
     * from g_cfg / argc, and every argv[3..] read is guarded by its own argc
     * check, so nothing downstream needs argc >= 3. */
    if(strcmp(mode,"serve")==0 && (argc>=3 || flag_datadir)){
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
        if(nwant<0) nwant=0;
        if(nwant>MUX_MAX_OUT) nwant=MUX_MAX_OUT;
        /* # dl_catchup chunk-claiming workers is optional 5th arg (default
         * 16 -- tried both 8 and 16 against the real archive; 16 gave a
         * modest throughput bump once the liveness probe was fixed to
         * actually find enough live peers to support it). dl_catchup itself
         * clamps this down to however many confirmed-live peers it finds
         * (and up to 64 max), so an over-large request here just becomes a
         * ceiling, not a guarantee. */
        /* The DOWNLOAD chunk-worker count is bmc.catchupworkers, NOT -par.
         * Core's -par is the script-verification thread count and now means
         * exactly that here too (tx_verify.c txv_script_threads); it used to
         * be wired to this number instead, so par=8 halved the download and
         * left verification using every core -- the opposite of the ask.
         * dl_catchup clamps this down to however many confirmed-live peers it
         * finds, so it is a ceiling, not a promise. */
        int catchup_workers;
        if(argc>=6) catchup_workers = atoi(argv[5]);
        else        catchup_workers = g_cfg.catchup_workers;   /* bmc.catchupworkers, default 64 since 2026-09-10 (every live peer downloads, up to it) */
        if(catchup_workers<1) catchup_workers=1;
        if(catchup_workers>64) catchup_workers=64;
        dial_gate_configure(g_cfg.dial_rate_limit); dl_gate_configure(g_cfg.download_rate_limit_kbps);
        ul_gate_configure(g_cfg.upload_rate_limit_kbps); if(g_cfg.upload_rate_limit_kbps > 0) g_p2p_write_hook = p2p_upload_pace;   /* inherited by every forked serve child and worker */
        fprintf(stderr,"[boot] config: datadir=%s port=%d (%s) listen=%d nwant=%d catchup_workers=%d (%s) dialratelimit=%d/s%s downloadratelimit=%dKB/s%s uploadratelimit=%dKB/s%s\n",
                dir, port, (argc>=4)?"cli":"bitcoin.conf", g_cfg.listen, nwant,
                catchup_workers, (argc>=6)?"cli":"bmc.catchupworkers", g_cfg.dial_rate_limit, g_cfg.dial_rate_limit ? "" : " (off)",
                g_cfg.download_rate_limit_kbps, g_cfg.download_rate_limit_kbps ? "" : " (off)",
                g_cfg.upload_rate_limit_kbps, g_cfg.upload_rate_limit_kbps ? "" : " (off)");
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
            if(probs > 0){
                fprintf(stderr,"[boot] archive check found %ld problem(s) in %.2fs -- see [check] lines above\n",
                        probs, phase_elapsed(&chk_pt));
                /* STO-11: the check used to stop here. A record pointing at
                 * bytes that never reached disk (the crash window store_append
                 * now closes with fdatasync) was detected on every boot and
                 * repaired on none, so catch-up stalled at that height
                 * forever.
                 *
                 * archive_repair_bad_bodies ZEROES those index records, which
                 * turns each into an ordinary never-fetched hole for the
                 * catch-up path to refill. It does NOT truncate -- see its own
                 * comment, and archive_layout_monotonic's, for why that
                 * distinction is load-bearing here. This is the same mechanism
                 * archive_repair_duplicates already uses, on the same file,
                 * under the same fsync.
                 *
                 * The comment above about archive_check not acting still
                 * holds for the DESTRUCTIVE repair: archive_verify_and_repair
                 * keeps its own narrower trigger and is untouched. */
                if(g_cfg.checklevel >= 3){
                    long healed = archive_repair_bad_bodies(g_cfg.checkblocks, g_cfg.checklevel);
                    if(healed > 0)
                        fprintf(stderr,"[boot] archive self-heal: %ld height(s) marked for re-download\n",
                                healed);
                    else if(healed < 0)
                        fprintf(stderr,"[boot] archive self-heal FAILED -- the bad height(s) remain; "
                                       "catch-up will stall there\n");
                } else {
                    fprintf(stderr,"[boot] checklevel=%d is below 3, so the frame/body check that "
                                   "drives self-heal did not run -- problems are reported only\n",
                            g_cfg.checklevel);
                }
            }
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
                if(store_prune(store_buf, (int)ph) == 1){
                    fprintf(stderr,"[prune] done: block data below height %ld removed\n", ph);
                    /* 2026-09-08: undo follows the block store (Core deletes the rev file with its blk file) */
                    { extern long undo_prune_below(long keep_from); long uf = undo_prune_below(ph);
                      if(uf) fprintf(stderr,"[prune] undo: %ld rev file(s) wholly below height %ld removed\n", uf, ph); }
                }
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
        /* Step 1 of UTXO_INLINE_BUILD_PERF_SCOPE: dl_catchup connects the UTXO
         * set while it downloads -- but only in the download WORKER, the one
         * process that owns the set (utxo_live_init runs there, below). This
         * boot-time call runs in the parent before that engine exists, so its
         * blocks are connected afterwards, by the worker's drain. Say so: an
         * operator who wants the interleaved path on a fresh node sets
         * bmc.bootcatchup=0 and lets the worker's far-behind trigger run it. */
        if(g_cfg.boot_catchup)
            fprintf(stderr,"[boot] boot catch-up runs BEFORE the UTXO engine starts: its blocks are connected by the worker afterwards "
                           "(bmc.bootcatchup=0 leaves the download to the worker, which connects while it downloads)\n");
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
               /* 3.1: seed the connected tip from the persisted applied height
                * so the RPCs and the serve children cap by it from the first
                * request, before the worker has loaded the set and started
                * publishing (utxo_applied_height.dat absent -> -1: nothing
                * connected yet, which is the truth on a fresh datadir). The
                * worker overwrites it with NODE_TIP_UNTRACKED if live
                * tracking fails to come up. */
               { long ph = utxo_live_persisted_height(), stt = *(int*)(store_buf+24);
                 g_node_status->connected_tip = ph;
                 g_node_status->tip_height = ph < stt ? ph : stt; }
               { extern void serve_set_connected_tip_ptr(const volatile long long*);
                 serve_set_connected_tip_ptr(&g_node_status->connected_tip); }
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
        txann_set_status(g_node_status);          /* CC-1: the announce ring lives in the same block */
        /* the coinstats fold ring + watermark (2026-09-06): the worker
         * pushes, its forked fold worker drains, THIS parent's
         * gettxoutsetinfo gates on the watermark. Weak: the dial/sync
         * harnesses that link this file omit daemon/coinstats_index.c. */
        { extern void csi_set_status(void*) __attribute__((weak));
          if (csi_set_status) csi_set_status(g_node_status); }

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
            /* TXOQ-1 (2026-09-05 benchmark): register the between-block
             * service hook before the worker's first utxo_live_catchup, so a
             * long catch-up pass answers gettxout queries at its block
             * boundaries instead of refusing them all until it returns. */
            { extern void utxo_live_set_apply_hook(void (*)(void));
              utxo_live_set_apply_hook(dl_apply_hook); }   /* 3.1: publishes the connected tip, then txoq_service */
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
            { extern void rpc_commands_set_block_mark(long (*)(const unsigned char[32], int, long*, char*, unsigned long)); rpc_commands_set_block_mark(txoq_block_mark); }   /* CC-10 */
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
        if(nwant<1) nwant=1;
        if(nwant>1) nwant=1;   /* one loopback peer */
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
