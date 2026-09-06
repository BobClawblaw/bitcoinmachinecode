/* tests/test_txann.c -- CC-1: transactions are announced to inbound peers,
 * and inbound-accepted transactions reach the outbound legs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "txann.h"
static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
static unsigned char cap[8192]; static long cap_n; static int cap_writes; static char cap_cmd[16];
static long capw(int fd, const char* cmd, unsigned cl, const void* p, unsigned pl){ (void)fd; memcpy(cap_cmd, cmd, cl); cap_cmd[cl]=0; memcpy(cap, p, pl); cap_n = pl; cap_writes++; return pl; }
static void id(unsigned char* t, int n){ memset(t, 0, 32); t[0]=(unsigned char)n; t[1]=(unsigned char)(n>>8); }
static int inv_count(void){ return cap_n > 0 ? cap[0] : 0; }
static int inv_has(int n){ unsigned char t[32]; id(t,n); for (int i = 0; i < inv_count(); i++) if (cap[1+i*36]==1 && !memcmp(cap+1+i*36+4, t, 32)) return 1; return 0; }
static int drained_ids[64], drained_n; static void wcb(const unsigned char t[32]){ if (drained_n < 64) drained_ids[drained_n++] = t[0] | (t[1]<<8); }
static long long ms(void){ struct timeval t; gettimeofday(&t,0); return t.tv_sec*1000LL + t.tv_usec/1000; }
int main(void){
    node_status_t* st = calloc(1, sizeof *st); if (!st){ puts("calloc"); return 2; }
    txann_set_status(st); txann_set_writer(capw); txann_set_mean_ms(0);
    unsigned char t[32];
    printf("== the finding: an inbound peer receives what we accept ==\n");
    txann_set_my_slot(-1); txann_child_init(5, 1);
    id(t,1); txann_push(t, 1000, 200); id(t,2); txann_push(t, 1000, 200); id(t,3); txann_push(t, 1000, 200);
    cap_n = 0; long n = txann_tick(9, ms()+1, 0);
    ok(n == 3 && !strcmp(cap_cmd,"inv") && inv_count()==3 && inv_has(1) && inv_has(2) && inv_has(3), "three accepts -> one inv of three MSG_TX to the inbound peer");
    printf("== never back to the sender ==\n");
    txann_set_my_slot(5); id(t,4); txann_push(t, 1000, 200);       /* accepted by THIS child's peer */
    txann_set_my_slot(6); id(t,5); txann_push(t, 1000, 200);       /* accepted from another inbound peer */
    cap_n = 0; n = txann_tick(9, ms()+1, 0);
    ok(n == 1 && inv_has(5) && !inv_has(4), "the tx from our own peer (slot 5) is withheld; slot 6's is announced");
    printf("== the peer's feefilter ==\n");
    txann_set_my_slot(-1); id(t,6); txann_push(t, 100, 1000); id(t,7); txann_push(t, 5000, 1000);
    cap_n = 0; n = txann_tick(9, ms()+1, 1000);                    /* peer wants >= 1000 sat/kvB */
    ok(n == 1 && inv_has(7) && !inv_has(6), "100 sat/kvB withheld, 5000 sat/kvB announced");
    id(t,8); txann_push(t, 0, 0); cap_n = 0; n = txann_tick(9, ms()+1, 1000);
    ok(n == 1 && inv_has(8), "unknown fee (0/0) is announced rather than silently dropped");
    printf("== batching and dedup ==\n");
    for (int i = 100; i < 140; i++){ id(t,i); txann_push(t, 1000, 200); }
    cap_n = 0; n = txann_tick(9, ms()+1, 0); ok(n == TXANN_INV_MAX && inv_count()==TXANN_INV_MAX, "40 accepts: first inv carries 35");
    cap_n = 0; n = txann_tick(9, ms()+1, 0); ok(n == 5 && inv_has(139), "...and the second carries the remaining 5");
    id(t,200); txann_push(t, 1000, 200); txann_push(t, 1000, 200);
    cap_n = 0; n = txann_tick(9, ms()+1, 0); ok(n == 1, "the same txid pushed twice is announced once");
    printf("== a lapped consumer resyncs ==\n");
    for (int i = 0; i < RPC_ANN_RING + 50; i++){ id(t, 300 + (i % 1000)); txann_push(t, 1000, 200); }
    cap_n = 0; n = txann_tick(9, ms()+1, 0);
    ok(n == TXANN_INV_MAX && txann_lapped() > 0, "1074 accepts behind: cursor resynced, loss counted, inv still sent");
    printf("== the wait: readable returns at once, idle returns 0 at the bound ==\n");
    int sv[2]; if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)){ perror("sp"); return 2; }
    txann_set_idle_secs(1); txann_child_init(5, 1);
    if (write(sv[1], "x", 1) != 1) return 2;
    long long t0 = ms(); long r = txann_wait(sv[0], 0); long long dt = ms()-t0;
    ok(r == 1 && dt < 200, "data pending: wait returns 1 immediately");
    char b; if (read(sv[0], &b, 1) != 1) return 2;
    txann_child_init(5, 1);
    t0 = ms(); r = txann_wait(sv[0], 0); dt = ms()-t0;
    ok(r == 0 && dt >= 900 && dt <= 2500, "silent peer: wait returns 0 at the 1 s idle bound (was: 20 min in the read)");
    printf("      idle wait took %lld ms\n", dt);
    txann_child_init(5, 1); id(t,400); txann_push(t, 1000, 200); cap_n = 0; cap_writes = 0;
    txann_set_idle_secs(1); r = txann_wait(sv[0], 0);
    ok(cap_writes >= 1 && inv_has(400), "an accept during the wait is announced from inside the wait");
    printf("== worker drain: inbound-origin txs reach the outbound announce queue ==\n");
    txann_set_my_slot(7); id(t,500); txann_push(t, 1000, 200);
    txann_set_my_slot(-1); id(t,501); txann_push(t, 1000, 200);   /* the worker's own: already queued by tx_relay */
    drained_n = 0; txann_worker_drain(wcb);
    ok(drained_n == 1 && drained_ids[0] == 500, "the slot-7 (inbound) tx is handed to the outbound announcer; the worker's own is not duplicated");
    printf("== relay not negotiated ==\n");
    txann_child_init(5, 0); id(t,600); txann_push(t, 1000, 200); cap_n = 0; n = txann_tick(9, ms()+1, 0);
    ok(n == 0 && cap_n == 0, "a peer that sent fRelay=0 gets nothing");
    printf("== negative control: the pre-CC-1 behaviour ==\n");
    txann_set_enabled(0); txann_child_init(5, 1); id(t,700); txann_push(t, 1000, 200);
    cap_n = 0; n = txann_tick(9, ms()+1, 0);
    ok(n == 0 && cap_n == 0, "control: disabled, an accept produces NO inv to the inbound peer (the finding)");
    t0 = ms(); r = txann_wait(sv[0], 0);
    ok(r == 1 && ms()-t0 < 50, "control: disabled, wait falls straight through to the blocking read");
    drained_n = 0; txann_worker_drain(wcb); ok(drained_n == 0, "control: disabled, nothing reaches the outbound legs");
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
