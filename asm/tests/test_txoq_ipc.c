/* test_txoq_ipc.c -- the gettxout query protocol between the serve parent and
 * the download worker.
 *
 * The property that matters is NOT "it usually returns the right coin" -- it
 * is that it NEVER returns a wrong one. gettxout's null means "that output is
 * spent", so any confusion here turns into a false statement about someone's
 * money. The dangerous case is a query that TIMES OUT: the worker's reply
 * lands in the socket afterwards, and the next query would read a
 * perfectly well-formed response about a DIFFERENT outpoint. Magic alone does
 * not catch that, which is why the response echoes the outpoint it answers.
 *
 * txoq_query is static in daemon/main.c, so this includes that TU directly
 * (main renamed away, the test_dial_budget pattern) and drives it against a
 * fake worker on the other end of the socketpair. */
#include <stdio.h>
#include <stdlib.h>

#define main daemon_main_disabled
#include "../daemon/main.c"
#undef main

static int failures = 0;
static void ck(const char* l, int c){ if(c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); failures++; } }

static void fill(unsigned char t[32], unsigned char b){ for(int i=0;i<32;i++) t[i]=b; }

/* Write one response, optionally for a DIFFERENT outpoint than asked. */
static void fake_reply(int fd, const unsigned char txid[32], unsigned vout,
                       int found, unsigned long long value, const unsigned char* spk, unsigned spklen){
    txoq_resp rp; memset(&rp,0,sizeof rp);
    rp.magic = TXOQ_MAGIC; rp.found = found; rp.value = value;
    rp.height = 500; rp.is_coinbase = 0; rp.spklen = spklen;
    memcpy(rp.txid, txid, 32); rp.vout = vout;
    (void)!write(fd, &rp, sizeof rp);
    if(spklen) (void)!write(fd, spk, spklen);
}

int main(void){
    int sv[2];
    if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0){ perror("socketpair"); return 2; }
    g_txoq_parent = sv[0];
    int worker = sv[1];

    unsigned char want[32], other[32];
    fill(want, 0xAA); fill(other, 0xBB);
    unsigned char spk[22]; spk[0]=0x00; spk[1]=0x14; for(int i=0;i<20;i++) spk[2+i]=(unsigned char)i;

    unsigned long long value; unsigned long height, cb, slen;
    unsigned char got[TXOQ_SPK_CAP];

    printf("---- gettxout worker query ----\n");

    /* 1. a straight hit */
    { txoq_req q; (void)!read(worker, &q, 0);   /* nothing yet */
      pid_t p = fork();
      if(p == 0){ txoq_req r; if(read(worker,&r,sizeof r)==(ssize_t)sizeof r)
                      fake_reply(worker, r.txid, r.vout, 1, 4200000000ULL, spk, 22);
                  _exit(0); }
      long rc = txoq_query(want, 7, &value, &height, &cb, got, sizeof got, &slen);
      int st; waitpid(p,&st,0);
      ck("a matching reply is returned", rc == 1 && value == 4200000000ULL && slen == 22);
      ck("the scriptPubKey survives the round trip", rc==1 && memcmp(got, spk, 22) == 0); }

    /* 2. found=0 is "absent", distinct from a refusal */
    { pid_t p = fork();
      if(p == 0){ txoq_req r; if(read(worker,&r,sizeof r)==(ssize_t)sizeof r)
                      fake_reply(worker, r.txid, r.vout, 0, 0, NULL, 0);
                  _exit(0); }
      long rc = txoq_query(want, 7, &value, &height, &cb, got, sizeof got, &slen);
      int st; waitpid(p,&st,0);
      ck("an absent outpoint reports 0 (not a refusal)", rc == 0); }

    /* 3. THE ONE THAT MATTERS: a stale reply for a different outpoint, left
     *    over from an earlier timed-out query, must be skipped -- never
     *    returned as the answer to this one. */
    { pid_t p = fork();
      if(p == 0){
          txoq_req r;
          if(read(worker,&r,sizeof r)==(ssize_t)sizeof r){
              fake_reply(worker, other, 99, 1, 999999999ULL, spk, 22);   /* stale */
              fake_reply(worker, r.txid, r.vout, 1, 12345ULL, spk, 22);  /* real */
          }
          _exit(0); }
      long rc = txoq_query(want, 7, &value, &height, &cb, got, sizeof got, &slen);
      int st; waitpid(p,&st,0);
      ck("a stale reply for another outpoint is skipped", rc == 1 && value == 12345ULL);
      ck("the stale value is NOT returned", !(rc == 1 && value == 999999999ULL)); }

    /* 4. silence must REFUSE, never fall back to "absent" */
    { long rc = txoq_query(want, 7, &value, &height, &cb, got, sizeof got, &slen);
      ck("a worker that never answers is a refusal (-1), not absent", rc == -1); }

    /* 5. no channel at all is also a refusal */
    { int save = g_txoq_parent; g_txoq_parent = -1;
      long rc = txoq_query(want, 7, &value, &height, &cb, got, sizeof got, &slen);
      g_txoq_parent = save;
      ck("no worker channel is a refusal", rc == -1); }

    /* 6. the WORKER side between legs (2026-09-26): txoq_service_mode(0)
     * answers a gettxout query but leaves a block MARK (invalidateblock /
     * reconsiderblock) in the socket for the full service point -- a mark
     * changes chain state and must not run mid-rotation. */
    { int wv[2]; ck("worker-side pair", socketpair(AF_UNIX, SOCK_STREAM, 0, wv) == 0);
      int save_w = g_txoq_worker; g_txoq_worker = wv[1];
      txoq_req mq; memset(&mq, 0, sizeof mq); mq.magic = TXOQ_MAGIC_MARK; mq.vout = 1; fill(mq.txid, 0x77);
      ck("a MARK request is sent", send(wv[0], &mq, sizeof mq, 0) == (ssize_t)sizeof mq);
      txoq_service_mode(0);
      txoq_req peek; ssize_t pk = recv(wv[1], &peek, sizeof peek, MSG_PEEK | MSG_DONTWAIT);
      ck("between legs the MARK is left in the socket, unconsumed", pk == (ssize_t)sizeof peek && peek.magic == TXOQ_MAGIC_MARK);
      struct pollfd pp = { wv[0], POLLIN, 0 };
      ck("...and nothing was answered for it", poll(&pp, 1, 50) == 0);
      /* take the mark out by hand (the full point would), then a query */
      ck("drain the mark", recv(wv[1], &peek, sizeof peek, 0) == (ssize_t)sizeof peek);
      txoq_req q; memset(&q, 0, sizeof q); q.magic = TXOQ_MAGIC; q.vout = 3; fill(q.txid, 0x5c);
      ck("a gettxout query is sent", send(wv[0], &q, sizeof q, 0) == (ssize_t)sizeof q);
      txoq_service_mode(0);
      txoq_resp rp; memset(&rp, 0, sizeof rp);
      ck("between legs the query IS answered", txoq_read_all(wv[0], &rp, sizeof rp, 500) == 1);
      ck("...echoing its outpoint (absent: no UTXO set in this process)",
         rp.magic == TXOQ_MAGIC && rp.vout == 3 && rp.txid[0] == 0x5c && rp.found == 0);
      g_txoq_worker = save_w; close(wv[0]); close(wv[1]); }

    /* 7. the worker's idle rest (2026-09-26): it rests ON the query channel.
     * A query arriving mid-rest is answered at once and ends the rest; a
     * MARK ends it without being consumed (no spinning on a readable fd);
     * with nothing to do it lasts its full length. */
    { int wv[2]; ck("idle-rest pair", socketpair(AF_UNIX, SOCK_STREAM, 0, wv) == 0);
      int save_w = g_txoq_worker; g_txoq_worker = wv[1];
      struct timespec a, b;
      /* (a) a query 50 ms into a 2 s rest */
      pid_t p = fork();
      if (p == 0){ usleep(50000); txoq_req q; memset(&q, 0, sizeof q); q.magic = TXOQ_MAGIC; q.vout = 9; fill(q.txid, 0x31);
                   (void)!send(wv[0], &q, sizeof q, 0); _exit(0); }
      clock_gettime(CLOCK_MONOTONIC, &a); txoq_idle_rest(2000); clock_gettime(CLOCK_MONOTONIC, &b);
      int st; waitpid(p, &st, 0);
      double ms = (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6;
      txoq_resp rp; memset(&rp, 0, sizeof rp);
      int got = txoq_read_all(wv[0], &rp, sizeof rp, 500);
      char l[160]; snprintf(l, sizeof l, "a query 50 ms into a 2000 ms rest is answered and ends it (%.0f ms)", ms);
      ck(l, got == 1 && rp.vout == 9 && rp.txid[0] == 0x31 && ms < 1000);
      /* (b) a MARK: the rest returns at once, the MARK stays */
      txoq_req mq; memset(&mq, 0, sizeof mq); mq.magic = TXOQ_MAGIC_MARK; fill(mq.txid, 0x42);
      (void)!send(wv[0], &mq, sizeof mq, 0);
      clock_gettime(CLOCK_MONOTONIC, &a); txoq_idle_rest(2000); clock_gettime(CLOCK_MONOTONIC, &b);
      ms = (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6;
      txoq_req pk; ssize_t n = recv(wv[1], &pk, sizeof pk, MSG_PEEK | MSG_DONTWAIT);
      snprintf(l, sizeof l, "a pending MARK ends the rest at once (%.0f ms), left for the full service point", ms);
      ck(l, ms < 100 && n == (ssize_t)sizeof pk && pk.magic == TXOQ_MAGIC_MARK);
      (void)!recv(wv[1], &pk, sizeof pk, 0);
      /* (c) nothing to do: the full rest */
      clock_gettime(CLOCK_MONOTONIC, &a); txoq_idle_rest(150); clock_gettime(CLOCK_MONOTONIC, &b);
      ms = (b.tv_sec - a.tv_sec) * 1e3 + (b.tv_nsec - a.tv_nsec) / 1e6;
      snprintf(l, sizeof l, "an idle channel rests the full 150 ms (%.0f ms)", ms);
      ck(l, ms >= 140 && ms < 600);
      g_txoq_worker = save_w; close(wv[0]); close(wv[1]); }

    close(sv[0]); close(sv[1]);
    if(failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
