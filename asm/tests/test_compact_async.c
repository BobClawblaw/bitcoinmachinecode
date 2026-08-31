/* tests/test_compact_async.c -- the LSM-level mechanics behind background
 * compaction (daemon/utxo_live.c, "compaction in the background"):
 *   1. utxo_lsm_set_defer_unlink(1): compaction publishes the new manifest but
 *      leaves its input run files on disk (the adopting parent unlinks them);
 *      negative control: with the flag clear they are unlinked as before.
 *   2. lsm_manifest_read(): a fresh lsm_state rebuilt from the file matches
 *      the compactor's in-memory manifest byte for byte, carries total_live,
 *      and has next_gen/next_run_no advanced past every entry.
 *   3. utxo_lsm_set_flush_hook(): mac_flush calls the hook BEFORE it changes
 *      the manifest -- the hook observes the pre-flush manifest_n. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include "test_tmpdir.h"
#include "lsm_state.h"
#include "lsm_manifest.h"
typedef uint8_t u8; typedef uint32_t u32;
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long long blob_cap);
extern int  utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8 txid[32], u32 index, unsigned long long value,
                         unsigned long long height, unsigned long long is_cb, const u8* script, unsigned long slen);
extern long utxo_lsm_compact(void* lst);
extern void utxo_lsm_close(void* lst);
extern void utxo_lsm_set_defer_unlink(long on);
extern void utxo_lsm_set_flush_hook(void (*fn)(void));
#define BLOOM_MAX_BYTES (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }
static int run_exists(uint64_t run_no){ char n[64]; snprintf(n,sizeof n,"utxo_run_%06u.dat",(unsigned)run_no); return access(n,F_OK)==0; }
static uint64_t entry_run(struct lsm_state* l, uint64_t i){ uint64_t r; memcpy(&r,(char*)l->manifest_buf+i*16+8,8); return r; }
static struct lsm_state* g_hook_lst; static int g_hook_calls; static uint64_t g_hook_saw_n;
static void hook(void){ if (!g_hook_calls) g_hook_saw_n = g_hook_lst->manifest_n; g_hook_calls++; }
static long fill(struct lsm_state* lst, void* table, long from, long n){
    u8 spk[34]; memset(spk,0x51,34); spk[1]=0x20;
    for (long i = from; i < from+n; i++){
        u8 txid[32]; memset(txid,0,32); memcpy(txid,&i,sizeof i); txid[31]=0x44;
        if (utxo_lsm_put(lst, table, txid, (u32)(i&3), 1000+i, 100+(i%50), 0, spk, 34) != 1) return -1;
    }
    return 0;
}
int main(void){
    tt_isolate();
    unsigned long slots = 1UL<<14;
    void* table = malloc((size_t)utxo_struct_size(slots)); void* blob = malloc(64UL<<20);
    utxo_init(table, slots, blob, 64UL<<20);
    struct lsm_state lst; memset(&lst,0,sizeof lst);
    unsigned long long op_th = slots*2, tomb_cap = op_th, desc_cap = slots*3;
    lst.op_threshold = op_th; lst.fill_threshold = slots*3/4;
    lst.tomb_buf = malloc(tomb_cap*36); lst.tomb_cap = tomb_cap;
    lst.manifest_buf = malloc(256*16); lst.manifest_cap = 256;
    lst.scratch_cap = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES; lst.scratch_buf = malloc(lst.scratch_cap);
    if (utxo_lsm_init(&lst) != 1){ fprintf(stderr,"lsm init failed\n"); return 1; }

    printf("== 1. deferred unlink ==\n");
    if (fill(&lst, table, 0, 120000)){ fprintf(stderr,"put failed\n"); return 1; }
    ok(lst.manifest_n >= 4, "flushes produced several runs");
    uint64_t in[64]; int nin = (int)(lst.manifest_n < 64 ? lst.manifest_n : 64);
    for (int i = 0; i < nin; i++) in[i] = entry_run(&lst, (uint64_t)i);
    uint64_t n_before = lst.manifest_n, live_before = lst.total_live;
    uint64_t old_base = lsm_manifest_persisted_live();
    ok(old_base != ~0ULL && old_base <= live_before, "pre-merge manifest carries a runs-only base");
    utxo_lsm_set_defer_unlink(1);
    long cr = utxo_lsm_compact(&lst);
    utxo_lsm_set_defer_unlink(0);
    ok(cr > 0 && lst.manifest_n < n_before, "compaction merged the runs");
    int still = 0; for (int i = 0; i < nin; i++) still += run_exists(in[i]);
    ok(still == nin, "every INPUT run file is still on disk (unlink deferred to the adopter)");
    ok(run_exists(entry_run(&lst, 0)), "the merged output run exists");

    printf("== 2. manifest re-read matches the compactor's memory ==\n");
    struct lsm_state fresh; memset(&fresh,0,sizeof fresh);
    fresh.manifest_buf = malloc(256*16); fresh.manifest_cap = 256;
    uint64_t new_base = ~0ULL;
    ok(lsm_manifest_read(&fresh, &new_base) == 0, "lsm_manifest_read succeeds");
    ok(fresh.manifest_n == lst.manifest_n, "same manifest_n");
    ok(memcmp(fresh.manifest_buf, lst.manifest_buf, (size_t)lst.manifest_n*16) == 0, "entries identical byte for byte");
    printf("      total_live: running before %llu, after %llu; persisted base %llu -> %llu\n",
           (unsigned long long)live_before, (unsigned long long)lst.total_live, (unsigned long long)old_base, (unsigned long long)new_base);
    ok(new_base != ~0ULL && new_base < lst.total_live, "the file's count is RUNS-ONLY (excludes the unflushed memtable tail)");
    ok(fresh.total_live == 0, "lsm_manifest_read leaves the caller's running counter alone");
    ok(live_before + (new_base - old_base) == lst.total_live, "adopter's healing rule (running += new_base - old_base) reproduces the compactor's own counter");
    uint64_t maxr = 0, maxg = 0; for (uint64_t i = 0; i < fresh.manifest_n; i++){ uint64_t g; memcpy(&g,(char*)fresh.manifest_buf+i*16,8); if (g>maxg) maxg=g; if (entry_run(&fresh,i)>maxr) maxr=entry_run(&fresh,i); }
    ok(fresh.next_run_no == maxr+1 && fresh.next_gen == maxg+1, "next_run_no/next_gen advanced past every entry");
    ok(fresh.next_run_no <= lst.next_run_no, "...and never ahead of the compactor's own counters");
    struct lsm_state tiny = fresh; tiny.manifest_cap = 0;
    ok(lsm_manifest_read(&tiny, 0) == -1, "refuses a manifest larger than the caller's buffer");
    /* the adopter's step: unlink inputs the new manifest no longer names */
    int gone = 0; for (int i = 0; i < nin; i++){ int named = 0; for (uint64_t j = 0; j < lst.manifest_n; j++) if (entry_run(&lst,j)==in[i]) named = 1; if (!named){ char n[64]; snprintf(n,sizeof n,"utxo_run_%06u.dat",(unsigned)in[i]); unlink(n); gone++; } }
    ok(gone == nin, "adopter unlinked exactly the inputs");

    printf("== 3. flush hook runs before the manifest changes ==\n");
    g_hook_lst = &lst; g_hook_calls = 0; g_hook_saw_n = 0;
    uint64_t n0 = lst.manifest_n;
    utxo_lsm_set_flush_hook(hook);
    long added = 0; while (lst.manifest_n == n0 && added < 400000){ if (fill(&lst, table, 1000000+added, 5000)) { fprintf(stderr,"put failed\n"); return 1; } added += 5000; }
    utxo_lsm_set_flush_hook(0);
    ok(lst.manifest_n > n0, "a flush happened");
    ok(g_hook_calls >= 1, "the hook was called");
    ok(g_hook_saw_n == n0, "...and saw the PRE-flush manifest (it runs before mac_flush touches anything)");

    printf("== negative control: flag clear -> inputs unlinked as before ==\n");
    nin = (int)(lst.manifest_n < 64 ? lst.manifest_n : 64); for (int i = 0; i < nin; i++) in[i] = entry_run(&lst,(uint64_t)i);
    cr = utxo_lsm_compact(&lst);
    still = 0; for (int i = 0; i < nin; i++) still += run_exists(in[i]);
    ok(cr > 0 && still == 0, "with defer_unlink clear, compaction unlinked its inputs itself");
    utxo_lsm_close(&lst);
    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
