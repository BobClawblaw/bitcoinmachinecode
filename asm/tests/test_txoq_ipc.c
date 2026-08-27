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

    close(sv[0]); close(sv[1]);
    if(failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
