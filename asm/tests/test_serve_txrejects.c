/* test_serve_txrejects.c -- MPL-1 (audit 2026-10-23), the inbound serve
 * loop's half: bitcoin_serve.asm's .inv_txann consults the shared
 * recent-rejects filter for BOTH announcement dialects.
 *
 * Refusals are filed by WTXID (daemon/tx_accept.c txacc_reject_note, Core's
 * MempoolRejectedTx), so:
 *   1. a MSG_WTX announcement of a refused wtxid is NOT requested -- before
 *      this, a wtxid announcement skipped the filter entirely ("a wtxid
 *      cannot be looked up by txid: just ask");
 *   2. an unknown wtxid still is, with a MSG_WTX getdata;
 *   3. a MSG_TX announcement whose hash is in the filter (a transaction
 *      without a witness, txid == wtxid) is not requested;
 *   4. an unknown txid is requested as MSG_WITNESS_TX -- the type is re-read
 *      after the filter call, which clobbers the register holding it.
 * The filter is a MAP_SHARED region filled before the fork, as the daemon
 * does for its serve children. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>

#include "block_vec.h"
#include "test_tmpdir.h"

extern long node_handshake(int fd);
extern int  node_accept_handshake(int fd);
extern long node_serve_loop(int fd, int lfd, void* st, void* ht_idx, void* out, long cap);
extern int  tcp_connect_ip(unsigned, unsigned short);
extern long store_init(void* st);
extern long store_append(void* st, const unsigned char h[32], const void* blk, long blen);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void idx_init(void* idx, unsigned long slots);
extern int  idx_put(void* idx, const unsigned char hash[32], long height);
extern long p2p_write(int, const char*, unsigned, const void*, unsigned);
extern int  p2p_read(int, char[12], void*, unsigned, unsigned*);
extern unsigned long serve_rejects_size(void);
extern void serve_rejects_attach(void* region);
extern void serve_reject_note(const unsigned char h[32]);
extern int  serve_txdv_preinit(void);

extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const unsigned char txid[32], unsigned index, unsigned long long value,
                         unsigned long long height, unsigned long long is_coinbase, const unsigned char* script, unsigned slen);
extern void utxo_lsm_close(void* lst);
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);

static int failures = 0;
static void ck(const char* l, int ok){ if (ok) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; } }

struct lsm_state {
    long log_fd, idx_fd;
    unsigned long long log_len, ckpt_log_off, ckpt_n;
    unsigned long long op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap;
    unsigned long long next_run_no;
    void* tomb_hash_buf; unsigned long long tomb_hash_mask;
};
/* one confirmed coin, so the serve child's validation snapshot opens and the
 * connection counts as able to validate (tx_dv_ok) -- .inv_txann ignores tx
 * announcements otherwise */
static void seed_one_coin(void){
    unsigned long slots = 1UL << 12;
    void* table = malloc((size_t)utxo_struct_size(slots));
    void* blob = malloc(8UL << 20);
    utxo_init(table, slots, blob, 8UL << 20);
    struct lsm_state lst; memset(&lst, 0, sizeof lst);
    unsigned long long op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    unsigned long long scratch_cap = desc_cap*128 + 4*1024*1024 + 65536;
    lst.op_threshold = op_th; lst.fill_threshold = slots*3/4;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_buf = malloc(scratch_cap); lst.scratch_cap = scratch_cap;
    if (utxo_lsm_init(&lst) != 1){ printf("FAIL utxo_lsm_init\n"); exit(1); }
    unsigned char tid[32]; memset(tid, 0x42, 32);
    utxo_lsm_put(&lst, table, tid, 0, 100000, 1, 0, (const unsigned char*)"\x51", 1);
    utxo_lsm_close(&lst);
}

static unsigned char stbuf[1 << 16];
static void inv1(int fd, unsigned type, const unsigned char h[32]){
    unsigned char inv[37]; inv[0] = 1;
    inv[1] = (unsigned char)type; inv[2] = (unsigned char)(type >> 8); inv[3] = (unsigned char)(type >> 16); inv[4] = (unsigned char)(type >> 24);
    memcpy(inv + 5, h, 32);
    p2p_write(fd, "inv", 3, inv, 37);
}
/* announce, then ping: everything the serve loop sent before the pong is its
 * answer to the announcement. 1 if a getdata for h came back (type in *ty). */
static int asked_for(int fd, unsigned type, const unsigned char h[32], unsigned* ty){
    static unsigned char nonce[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };
    inv1(fd, type, h);
    p2p_write(fd, "ping", 4, nonce, 8);
    int asked = 0;
    for (int k = 0; k < 16; k++){
        char cmd[12]; static unsigned char buf[4096]; unsigned bl = 0;
        if (p2p_read(fd, cmd, buf, sizeof buf, &bl) <= 0) break;
        if (!strncmp(cmd, "pong", 4)) break;
        if (!strncmp(cmd, "getdata", 7) && bl == 37 && !memcmp(buf + 5, h, 32)){
            asked = 1; if (ty) *ty = (unsigned)buf[1] | (unsigned)buf[2] << 8 | (unsigned)buf[3] << 16 | (unsigned)buf[4] << 24;
        }
    }
    return asked;
}

int main(void){
    tt_isolate();
    setbuf(stdout, NULL);
    static unsigned char idx[24 + 64*48];
    unsigned char bh[32];
    store_init(stbuf);
    block_hash(bh, BLOCK_RAW);
    store_append(stbuf, bh, BLOCK_RAW, (long)sizeof BLOCK_RAW);
    idx_init(idx, 64); idx_put(idx, bh, 0);
    seed_one_coin();
    ck("validation path usable (tx_dv_ok)", serve_txdv_preinit() == 1);

    void* rej = mmap(0, serve_rejects_size(), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    ck("reject filter mapped", rej != MAP_FAILED);
    serve_rejects_attach(rej);
    unsigned char W[32], U[32], T[32], V[32];
    memset(W, 0xA1, 32); memset(U, 0xA2, 32); memset(T, 0xA3, 32); memset(V, 0xA4, 32);
    serve_reject_note(W);                  /* a refused segwit transaction's wtxid */
    serve_reject_note(T);                  /* a refused legacy transaction: txid == wtxid */

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(ls, (struct sockaddr*)&a, sizeof a); socklen_t alen = sizeof a; getsockname(ls, (struct sockaddr*)&a, &alen);
    listen(ls, 2);
    pid_t pid = fork();
    if (pid == 0){
        int c = accept(ls, 0, 0);
        if (c < 0) _exit(3);
        if (node_accept_handshake(c) != 1) _exit(4);
        static unsigned char so[1 << 22];
        long served = node_serve_loop(c, -1, stbuf, idx, so, (long)sizeof so);
        _exit(served >= 0 ? 0 : 9);
    }
    int fd = tcp_connect_ip(htonl(INADDR_LOOPBACK), a.sin_port);
    if (fd < 0){ printf("FAIL connect\n"); return 1; }
    struct timeval tv; tv.tv_sec = 8; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ck("handshake", node_handshake(fd) == 1);

    unsigned ty = 0;
    ck("MPL-1 a refused wtxid announced as MSG_WTX is NOT requested", !asked_for(fd, 5, W, 0));
    ty = 0;
    ck("an unknown wtxid announced as MSG_WTX is requested...", asked_for(fd, 5, U, &ty));
    ck("...as MSG_WTX (5)", ty == 5);
    ck("a refused hash announced as MSG_TX is NOT requested", !asked_for(fd, 1, T, 0));
    ty = 0;
    ck("an unknown txid announced as MSG_TX is requested...", asked_for(fd, 1, V, &ty));
    ck("...as MSG_WITNESS_TX (0x40000001), the type re-read after the filter call", ty == 0x40000001u);

    close(fd); waitpid(pid, 0, 0); close(ls);
    printf(failures ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", failures);
    return failures ? 1 : 0;
}
