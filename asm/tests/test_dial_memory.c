/* tests/test_dial_memory.c -- the dial memory (daemon/dial_memory.c): an
 * address that refused, timed out or hung up early is not offered again
 * until its backoff passes, doubling per consecutive failure; a leg that
 * lived clears it; lacking NODE_WITNESS is permanent. Production
 * 2026-09-09: 27 refusals an hour from eight flapping addresses, and one
 * anchor dialled every rotation for eight hours. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../daemon/dial_memory.h"
static int fails = 0;
static void ck(const char* l, long g, long e){ if (g == e) printf("  ok  %s (%ld)\n", l, g); else { printf("  FAIL %s (got %ld exp %ld)\n", l, g, e); fails++; } }
int main(void){
    void* mem = malloc(dialmem_bytes(4)); dialmem_init(mem, 4); dm_table_t* t = mem;
    long long now = 1000000;
    ck("an unknown address may be dialled", dialmem_allowed(t, "1.2.3.4:8333", now), 1);
    ck("first failure: 10 min backoff", dialmem_note_failure(t, "1.2.3.4:8333", DM_REFUSED, now), 600);
    ck("... not offered now", dialmem_allowed(t, "1.2.3.4:8333", now), 0);
    ck("... nor under another port (the key is the host)", dialmem_allowed(t, "1.2.3.4:56803", now + 599), 0);
    ck("... offered after 10 min", dialmem_allowed(t, "1.2.3.4:8333", now + 600), 1);
    ck("second failure: 20 min", dialmem_note_failure(t, "1.2.3.4:8333", DM_CONNECT_FAIL, now + 600), 1200);
    ck("third: 40 min", dialmem_note_failure(t, "1.2.3.4:8333", DM_EARLY_DROP, now + 1800), 2400);
    ck("the schedule caps at 6 h", dialmem_backoff_s(20), 21600);
    ck("streak 6 is 5 h 20 m", dialmem_backoff_s(6), 19200);
    dialmem_note_success(t, "1.2.3.4:8333");
    ck("a leg that lived clears it", dialmem_allowed(t, "1.2.3.4:8333", now + 1800), 1);
    ck("... and the next failure starts over at 10 min", dialmem_note_failure(t, "1.2.3.4:8333", DM_REFUSED, now + 1800), 600);
    ck("no witness: permanent", dialmem_note_failure(t, "5.6.7.8:8333", DM_NO_WITNESS, now), -1);
    ck("... never offered", dialmem_allowed(t, "5.6.7.8:8333", now + 10 * 86400), 0);
    dialmem_note_success(t, "5.6.7.8:8333");
    ck("... not even after a 'success'", dialmem_allowed(t, "5.6.7.8:8333", now + 10 * 86400), 0);
    ck("a later connect failure on a permanent entry answers -1, not minutes", dialmem_note_failure(t, "5.6.7.8:8333", DM_CONNECT_FAIL, now), -1);
    ck("an IPv6 literal keeps its colons", (dialmem_note_failure(t, "[2001:db8::1]:8333", DM_REFUSED, now), dialmem_allowed(t, "[2001:db8::1]:8333", now)), 0);
    ck("skips are counted for the heartbeat", (long)t->skips, 5);
    /* the table is full (4): a new failure evicts the entry whose backoff ended longest ago, never the permanent one */
    dialmem_note_failure(t, "9.9.9.9:8333", DM_REFUSED, now);
    ck("four entries", dialmem_count(t), 4);
    dialmem_note_failure(t, "8.8.8.8:8333", DM_REFUSED, now + 100000);
    ck("still four (one evicted)", dialmem_count(t), 4);
    ck("the permanent entry survived", dialmem_allowed(t, "5.6.7.8:8333", now + 100000), 0);
    ck("the newcomer is held", dialmem_allowed(t, "8.8.8.8:8333", now + 100000), 0);
    ck("the evicted one (oldest backoff end) is unknown again", dialmem_allowed(t, "1.2.3.4:8333", now + 100000), 1);
    ck("a NULL table allows everything", dialmem_allowed(0, "1.1.1.1:8333", now), 1);
    printf("%s (%d failure(s))\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
