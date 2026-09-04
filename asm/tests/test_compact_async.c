/* tests/test_compact_async.c -- the LSM-level mechanics behind background
 * compaction (daemon/utxo_live.c, "compaction in the background"):
 *   1. utxo_lsm_set_defer_unlink(1): compaction publishes the new manifest but
 *      leaves its input run files on disk (the adopting parent unlinks them);
 *      negative control: with the flag clear they are unlinked as before.
 *   2. lsm_manifest_read(): a fresh lsm_state rebuilt from the file matches
 *      the compactor's in-memory manifest byte for byte, carries total_live,
 *      and has next_gen/next_run_no advanced past every entry.
 *   3. utxo_lsm_set_flush_hook(): mac_flush calls the hook BEFORE it changes
 *      the manifest -- the hook observes the pre-flush manifest_n.
 *   4. utxo_lsm_set_defer_publish(1): the merge leaves utxo_manifest.dat
 *      untouched and writes its result to utxo_manifest.child.
 *   5. lsm_manifest_adopt_child(): with a run FLUSHED between the child's
 *      fork and its adoption, the union manifest names the merged run and the
 *      interim run, the persisted base and running counter follow the rules,
 *      and every key ever inserted -- pre-fork and interim -- still resolves.
 *   6. lsm_manifest_sweep_orphans(): removes unreferenced runs and stale
 *      child/pub files, refuses when memory and file disagree. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
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
extern void utxo_lsm_set_defer_publish(long on);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, unsigned long long* value,
                         unsigned long* height, unsigned long* is_coinbase, const u8** script, unsigned long* slen);
#define BLOOM_MAX_BYTES (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }
static int run_exists(uint64_t run_no){ char n[64]; snprintf(n,sizeof n,"utxo_run_%06u.dat",(unsigned)run_no); return access(n,F_OK)==0; }
static uint64_t entry_run(struct lsm_state* l, uint64_t i){ uint64_t r; memcpy(&r,(char*)l->manifest_buf+i*16+8,8); return r; }
static struct lsm_state* g_hook_lst; static int g_hook_calls; static uint64_t g_hook_saw_n;
static void hook(void){ if (!g_hook_calls) g_hook_saw_n = g_hook_lst->manifest_n; g_hook_calls++; }
static int key_ok(struct lsm_state* lst, void* table, long i){
    u8 txid[32]; memset(txid,0,32); memcpy(txid,&i,sizeof i); txid[31]=0x44;
    unsigned long long v; unsigned long h, cb, sl; const u8* sp;
    if (utxo_lsm_get(lst, table, txid, (u32)(i&3), &v, &h, &cb, &sp, &sl) != 1) return 0;
    return v == (unsigned long long)(1000+i) && sl == 34;
}
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

    printf("== 4. deferred publish ==\n");
    /* play both roles in one process: snapshot the parent's view, run the
     * merge as the child would, then restore the parent's view and continue */
    nin = (int)(lst.manifest_n < 64 ? lst.manifest_n : 64); for (int i = 0; i < nin; i++) in[i] = entry_run(&lst,(uint64_t)i);
    uint64_t pn = lst.manifest_n; unsigned char* pbuf = malloc(pn*16); memcpy(pbuf, lst.manifest_buf, pn*16);
    uint64_t p_live = lst.total_live, p_gen = lst.next_gen, p_run = lst.next_run_no;
    uint64_t fork_base = lsm_manifest_persisted_live();
    int is_full = ((uint64_t)nin == pn);
    FILE* mf = fopen("utxo_manifest.dat","rb"); unsigned char mbefore[4096]; size_t mlen = fread(mbefore,1,sizeof mbefore,mf); fclose(mf);
    utxo_lsm_set_defer_unlink(1); utxo_lsm_set_defer_publish(1);
    cr = utxo_lsm_compact(&lst);
    utxo_lsm_set_defer_unlink(0); utxo_lsm_set_defer_publish(0);
    ok(cr > 0, "merge ran");
    mf = fopen("utxo_manifest.dat","rb"); unsigned char mafter[4096]; size_t mlen2 = fread(mafter,1,sizeof mafter,mf); fclose(mf);
    ok(mlen == mlen2 && memcmp(mbefore, mafter, mlen) == 0, "utxo_manifest.dat is byte-identical (publish deferred)");
    ok(access("utxo_manifest.child", F_OK) == 0, "the result went to utxo_manifest.child");
    still = 0; for (int i = 0; i < nin; i++) still += run_exists(in[i]);
    ok(still == nin, "inputs still on disk");
    uint64_t merged_run = entry_run(&lst, 0);
    struct lsm_state cv; memset(&cv,0,sizeof cv); cv.manifest_buf = malloc(256*16); cv.manifest_cap = 256; uint64_t cbase = ~0ULL;
    ok(lsm_manifest_read_file("utxo_manifest.child", &cv, &cbase) == 0 && cv.manifest_n == lst.manifest_n && memcmp(cv.manifest_buf, lst.manifest_buf, lst.manifest_n*16) == 0, "utxo_manifest.child holds exactly the child's in-memory manifest");

    printf("== 5. adoption with a run flushed meanwhile ==\n");
    /* back to the parent's view; reserve the child's number as the parent does */
    memcpy(lst.manifest_buf, pbuf, pn*16); lst.manifest_n = pn; lst.total_live = p_live; lst.next_gen = p_gen + 1; lst.next_run_no = p_run + 1;
    ok(merged_run == p_run, "child used the run number the parent reserved for it");

    /* ---- UTX-5: a FAILED publish must leave memory untouched ----
     *
     * Before the fix, adopt_child copied the union into lst->manifest_buf and
     * only then published; a publish failure returned -1 with memory already
     * naming the child's merged run and no longer naming the inputs, while
     * the caller (daemon/utxo_live.c compact_adopt) unlinked that very run.
     * Every lookup through it then failed and the next flush published a
     * manifest naming a deleted run.
     *
     * Failure is injected without a hook: utxo_manifest.dat.pub is created as
     * a DIRECTORY, so publish's open(O_WRONLY|O_CREAT) fails with EISDIR.
     * The child manifest is not consumed on failure, so step 5 below can
     * still perform the real adoption afterwards. */
    {
        unsigned char snap[4096]; uint64_t snap_n = lst.manifest_n;
        uint64_t snap_live = lst.total_live;
        memcpy(snap, lst.manifest_buf, (size_t)snap_n * 16);
        ok(mkdir("utxo_manifest.dat.pub", 0755) == 0, "publish target blocked (created as a directory)");
        uint64_t junk = ~0ULL;
        ok(lsm_manifest_adopt_child(&lst, in, nin, is_full, fork_base, &junk) != 0,
           "adopt_child FAILS when the publish cannot be written");
        ok(lst.manifest_n == snap_n && memcmp(lst.manifest_buf, snap, (size_t)snap_n * 16) == 0,
           "UTX-5: in-memory manifest is byte-identical after the failed publish");
        ok(lst.total_live == snap_live, "UTX-5: the live counter did not move either");
        int names_merged = 0, names_all_inputs = 1;
        for (uint64_t j = 0; j < lst.manifest_n; j++) if (entry_run(&lst,j) == merged_run) names_merged = 1;
        for (int i = 0; i < nin; i++){ int f = 0;
            for (uint64_t j = 0; j < lst.manifest_n; j++) if (entry_run(&lst,j) == in[i]) f = 1;
            if (!f) names_all_inputs = 0; }
        ok(!names_merged, "UTX-5: memory does NOT name the merged run the caller is about to unlink");
        ok(names_all_inputs, "UTX-5: memory still names every input run");
        ok(access("utxo_manifest.child", F_OK) == 0, "the child manifest survives a failed adoption");
        ok(rmdir("utxo_manifest.dat.pub") == 0, "publish target unblocked");
    }
    long interim_from = 2000000; long addedi = 0;
    while (lst.manifest_n == pn && addedi < 400000){ if (fill(&lst, table, interim_from+addedi, 5000)){ fprintf(stderr,"put failed\n"); return 1; } addedi += 5000; }
    ok(lst.manifest_n == pn + 1, "an interim flush added a run to the parent's manifest");
    uint64_t interim_run = entry_run(&lst, pn);
    ok(interim_run == p_run + 1, "...numbered past the child's reserved number");
    uint64_t live_pre_adopt = lst.total_live, base_pre_adopt = lsm_manifest_persisted_live();
    uint64_t nbase = ~0ULL;
    ok(lsm_manifest_adopt_child(&lst, in, nin, is_full, fork_base, &nbase) == 0, "adopt_child succeeds");
    ok(lst.manifest_n == cv.manifest_n + 1, "union = child's entries + the interim run");
    ok(entry_run(&lst, 0) == merged_run && entry_run(&lst, lst.manifest_n-1) == interim_run, "merged run first, interim run last");
    ok(access("utxo_manifest.child", F_OK) != 0, "child file consumed");
    struct lsm_state rv; memset(&rv,0,sizeof rv); rv.manifest_buf = malloc(256*16); rv.manifest_cap = 256; uint64_t rbase = ~0ULL;
    ok(lsm_manifest_read(&rv, &rbase) == 0 && rv.manifest_n == lst.manifest_n && memcmp(rv.manifest_buf, lst.manifest_buf, lst.manifest_n*16) == 0, "published manifest == memory");
    printf("      bases: fork %llu, child %llu, pre-adopt %llu -> new %llu; running %llu -> %llu\n", (unsigned long long)fork_base, (unsigned long long)cbase, (unsigned long long)base_pre_adopt, (unsigned long long)nbase, (unsigned long long)live_pre_adopt, (unsigned long long)lst.total_live);
    if (is_full){
        ok(nbase == cbase + (base_pre_adopt - fork_base), "full merge: new base = child's exact count + net flushed since fork");
        ok(lst.total_live == live_pre_adopt + (cbase - fork_base), "running counter healed by the base's movement");
    } else ok(nbase == base_pre_adopt && lst.total_live == live_pre_adopt, "partial merge: count-neutral");
    /* the adopter's unlink step, then: does everything still resolve? */
    for (int i = 0; i < nin; i++){ int named = 0; for (uint64_t j = 0; j < lst.manifest_n; j++) if (entry_run(&lst,j)==in[i]) named = 1; if (!named) { char n[64]; snprintf(n,sizeof n,"utxo_run_%06u.dat",(unsigned)in[i]); unlink(n); } }
    long missing = 0, checked = 0;
    for (long i = 0; i < 120000; i += 97){ checked++; if (!key_ok(&lst, table, i)) missing++; }          /* part 1's keys, merged */
    for (long i = 1000000; i < 1000000+added; i += 89){ checked++; if (!key_ok(&lst, table, i)) missing++; }  /* part 3's keys */
    for (long i = interim_from; i < interim_from+addedi; i += 83){ checked++; if (!key_ok(&lst, table, i)) missing++; } /* interim */
    printf("      %ld keys checked across merged, older and interim runs\n", checked);
    ok(missing == 0, "every key still resolves through the reconciled manifest");

    printf("== 6. orphan sweep ==\n");
    { FILE* f = fopen("utxo_run_999999.dat","wb"); fputs("orphan",f); fclose(f); f = fopen("utxo_manifest.child","wb"); fputs("stale",f); fclose(f); }
    uint64_t saved_n = lst.manifest_n; lst.manifest_n = 0;
    ok(lsm_manifest_sweep_orphans(&lst) == -1 && access("utxo_run_999999.dat", F_OK) == 0, "refuses to sweep when memory and file disagree (nothing deleted)");
    lst.manifest_n = saved_n;
    int swept = lsm_manifest_sweep_orphans(&lst);
    ok(swept == 2 && access("utxo_run_999999.dat", F_OK) != 0 && access("utxo_manifest.child", F_OK) != 0, "sweeps the orphan run and the stale child file");
    int all = 1; for (uint64_t j = 0; j < lst.manifest_n; j++) all &= run_exists(entry_run(&lst,j));
    ok(all, "every referenced run untouched");

    printf("== negative control: flag clear -> inputs unlinked as before ==\n");
    nin = (int)(lst.manifest_n < 64 ? lst.manifest_n : 64); for (int i = 0; i < nin; i++) in[i] = entry_run(&lst,(uint64_t)i);
    cr = utxo_lsm_compact(&lst);
    still = 0; for (int i = 0; i < nin; i++) still += run_exists(in[i]);
    ok(cr > 0 && still == 0, "with defer_unlink clear, compaction unlinked its inputs itself");
    utxo_lsm_close(&lst);
    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
