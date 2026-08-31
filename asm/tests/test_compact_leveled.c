/* tests/test_compact_leveled.c -- leveled compaction at the LSM level.
 *
 * The classic merge always took the OLDEST runs, so every compaction rewrote
 * the base (13 GB on production) to absorb a few MB of fresh runs: write
 * amplification ~base/flush. utxo_lsm_compact_range(lst, lo, k) merges any
 * batch ending at the newest run; lsm_compact_pick chooses it by size ratio.
 * A batch that does not start at the oldest run must KEEP its tombstones --
 * they cancel puts in the runs below -- and get() must still see them
 * (bloom included). That resurrection hazard is the heart of this test:
 *   1. base + tombstoned keys in fresh runs; tail merge keeps the DELs, the
 *      base file is untouched, deleted keys stay dead, live keys resolve;
 *   2. the following full merge drops the DELs (nothing below), same answers;
 *   3. bad ranges (middle, k<2, past the end) are refused without effect;
 *   4. lsm_compact_pick's decisions on shaped size lists;
 *   5. the background protocol with a tail merge: deferred publish, a run
 *      flushed meanwhile, adoption finds the merged run wherever it sits. */
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
extern long utxo_lsm_compact_range(void* lst, unsigned long lo, unsigned long k);
extern long utxo_lsm_del(void* lst, void* u, const u8 txid[32], u32 index);
#include <sys/stat.h>
extern void utxo_lsm_set_defer_publish(long on);
extern long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index, unsigned long long* value,
                         unsigned long* height, unsigned long* is_coinbase, const u8** script, unsigned long* slen);
#define BLOOM_MAX_BYTES (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
static int fails = 0;
static void ok(int c, const char* w){ printf("  %s %s\n", c?"ok ":"FAIL", w); if(!c) fails++; }
static int run_exists(uint64_t run_no){ char n[64]; snprintf(n,sizeof n,"utxo_run_%06u.dat",(unsigned)run_no); return access(n,F_OK)==0; }
static uint64_t entry_run(struct lsm_state* l, uint64_t i){ uint64_t r; memcpy(&r,(char*)l->manifest_buf+i*16+8,8); return r; }
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

static void mk_txid(u8 txid[32], long i){ memset(txid,0,32); memcpy(txid,&i,sizeof i); txid[31]=0x44; }
static int deleted_key(long i){ return i < 120000 && (i % 1000) == 7; }
/* count DEL records in a run file: header 44 (bloom bytes at +20), records
 * from 44+bloom to sparse_off; PUSH = 37+15+slen, DEL = 37. Returns -1 if the
 * records do not tile the region exactly (format assumption broken). */
static long count_dels(uint64_t run_no, long* pushes){
    char n[64]; snprintf(n,sizeof n,"utxo_run_%06u.dat",(unsigned)run_no);
    FILE* f = fopen(n,"rb"); if (!f) return -1;
    unsigned char h[44]; if (fread(h,1,44,f)!=44){ fclose(f); return -1; }
    uint64_t nrec, bloom_bits, soff; memcpy(&nrec,h+12,8); memcpy(&bloom_bits,h+20,8); memcpy(&soff,h+28,8);
    uint64_t bloom = bloom_bits / 8;              /* header stores BITS; the reader shifts to bytes */
    long pos = 44 + (long)bloom, dels = 0, ps = 0; fseek(f, pos, SEEK_SET);
    for (uint64_t r = 0; r < nrec; r++){
        unsigned char kt[37]; if (fread(kt,1,37,f)!=37){ fclose(f); return -1; } pos += 37;
        if (kt[36] == 2){ dels++; continue; }
        if (kt[36] != 1){ fclose(f); return -1; }
        unsigned char v[15]; if (fread(v,1,15,f)!=15){ fclose(f); return -1; } pos += 15;
        uint16_t slen; memcpy(&slen,v+8,2); fseek(f, slen, SEEK_CUR); pos += slen; ps++;
    }
    fclose(f);
    if ((uint64_t)pos != soff) return -1;
    if (pushes) *pushes = ps;
    return dels;
}
static long check_keys(struct lsm_state* lst, void* table, long* missing_live, long* resurrected){
    long checked = 0; *missing_live = 0; *resurrected = 0;
    for (long i = 0; i < 120000; i += 37){ checked++; int ok = key_ok(lst, table, i); if (deleted_key(i)) *resurrected += ok; else *missing_live += !ok; }
    for (long i = 0; i < 120; i++){ long k = i*1000 + 7; checked++; if (key_ok(lst, table, k)) (*resurrected)++; }   /* every deleted key */
    return checked;
}
static uint64_t fsize(uint64_t run_no){ char n[64]; snprintf(n,sizeof n,"utxo_run_%06u.dat",(unsigned)run_no); struct stat sb; return stat(n,&sb)==0 ? (uint64_t)sb.st_size : 0; }
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

    printf("== 1. tail merge keeps tombstones ==\n");
    /* a base large enough that three fresh runs stay under a quarter of it */
    if (fill(&lst, table, 0, 400000)){ fprintf(stderr,"put failed\n"); return 1; }
    while (lst.manifest_n > 1) if (utxo_lsm_compact(&lst) <= 0) break;
    ok(lst.manifest_n == 1, "a single base run");
    uint64_t base = entry_run(&lst, 0), base_size = fsize(base);
    for (long i = 0; i < 120; i++){ u8 t[32]; mk_txid(t, i*1000+7); if (utxo_lsm_del(&lst, table, t, (u32)((i*1000+7)&3)) != 1){ fprintf(stderr,"del failed\n"); return 1; } }
    long added = 0; while (lst.manifest_n < 4 && added < 400000){ if (fill(&lst, table, 1000000+added, 5000)){ fprintf(stderr,"put failed\n"); return 1; } added += 5000; }
    ok(lst.manifest_n >= 4, "tombstones flushed into fresh runs above the base");
    long ml, rs; long checked = check_keys(&lst, table, &ml, &rs);
    ok(ml == 0 && rs == 0, "before: deleted keys dead, live keys resolve");
    uint64_t sizes[64]; long n = (long)lst.manifest_n; for (long i = 0; i < n; i++) sizes[i] = fsize(entry_run(&lst,(uint64_t)i));
    long lo = -1, k = lsm_compact_pick(sizes, n, 3, 64, &lo);
    printf("      sizes: base %.1f MB, %ld fresh runs totalling %.1f MB\n", sizes[0]/1048576.0, n-1, (sizes[1]+sizes[2]+sizes[3])/1048576.0);
    ok(k == n - 1 && lo == 1, "pick: the base dwarfs the fresh runs -> merge everything above it");
    uint64_t in[64]; for (long i = 0; i < k; i++) in[i] = entry_run(&lst,(uint64_t)(lo+i));
    long cr = utxo_lsm_compact_range(&lst, (unsigned long)lo, (unsigned long)k);
    ok(cr > 0 && lst.manifest_n == 2, "tail merge -> [base, merged]");
    ok(entry_run(&lst,0) == base && fsize(base) == base_size, "the base run was not touched");
    uint64_t merged = entry_run(&lst,1); long pushes = 0; long dels = count_dels(merged, &pushes);
    printf("      merged run %lu: %ld PUSH, %ld DEL records\n", (unsigned long)merged, pushes, dels);
    ok(dels == 120, "all 120 tombstones survived into the merged run");
    int gone = 1; for (long i = 0; i < k; i++) gone &= !run_exists(in[i]); ok(gone, "inputs unlinked (inline mode)");
    checked = check_keys(&lst, table, &ml, &rs);
    printf("      %ld keys checked\n", checked);
    ok(rs == 0, "no resurrection: every deleted key is still dead through the merged run (tombstone + bloom)");
    ok(ml == 0, "every live key still resolves");
    uint64_t s2[2] = { fsize(base), fsize(merged) };
    ok(lsm_compact_pick(s2, 2, 2, 64, &lo) == 0, "pick: base > 4x the merged run -> nothing yet (no base rewrite)");

    printf("== 2. the full merge drops them ==\n");
    cr = utxo_lsm_compact(&lst);
    ok(cr > 0 && lst.manifest_n == 1, "full merge -> one run");
    dels = count_dels(entry_run(&lst,0), &pushes);
    ok(dels == 0 && pushes > 0, "no DEL records in a base (nothing below to cancel)");
    checked = check_keys(&lst, table, &ml, &rs);
    ok(ml == 0 && rs == 0, "same answers after the full merge");

    printf("== 3. refused ranges ==\n");
    added = 0; while (lst.manifest_n < 4 && added < 400000){ if (fill(&lst, table, 2000000+added, 5000)){ fprintf(stderr,"put failed\n"); return 1; } added += 5000; }
    n = (long)lst.manifest_n; unsigned char snap[64*16]; memcpy(snap, lst.manifest_buf, (size_t)n*16);
    ok(utxo_lsm_compact_range(&lst, 1, (unsigned long)(n-2)) == 0 && (long)lst.manifest_n == n && memcmp(snap, lst.manifest_buf, (size_t)n*16)==0, "a middle range is refused, manifest untouched");
    ok(utxo_lsm_compact_range(&lst, 0, 1) == 0, "k < 2 refused");
    ok(utxo_lsm_compact_range(&lst, (unsigned long)(n-1), 2) == 0, "past the end refused");
    ok(utxo_lsm_compact_range(&lst, 0, 65) == 0, "k > 64 refused");

    printf("== 4. the policy ==\n");
    { uint64_t a[] = {1000,10,10,10};        ok(lsm_compact_pick(a,4,3,64,&lo)==3 && lo==1, "[1000,10,10,10] -> merge the three smalls"); }
    { uint64_t a[] = {1000,100,10,10,10};    ok(lsm_compact_pick(a,5,3,64,&lo)==4 && lo==1, "[1000,100,10x3] -> the 100 joins (<= 4x30)"); }
    { uint64_t a[] = {1000,600,10,10,10};    ok(lsm_compact_pick(a,5,3,64,&lo)==3 && lo==2, "[1000,600,10x3] -> the 600 dwarfs the smalls, stays"); }
    { uint64_t a[] = {100,100,100};          ok(lsm_compact_pick(a,3,3,64,&lo)==3 && lo==0, "[100,100,100] -> full merge"); }
    { uint64_t a[] = {1000,10,10};           ok(lsm_compact_pick(a,3,4,64,&lo)==0, "below threshold -> nothing"); }
    { uint64_t a[] = {1000,10};              ok(lsm_compact_pick(a,2,2,64,&lo)==0, "a lone small run -> nothing (k would be 1)"); }
    { static uint64_t a[70]; for (int i=0;i<70;i++) a[i]=1; ok(lsm_compact_pick(a,70,3,64,&lo)==64 && lo==6, "capped at 64 runs, still a tail"); }

    printf("== 5. background protocol with a tail merge ==\n");
    n = (long)lst.manifest_n; for (long i = 0; i < n; i++) sizes[i] = fsize(entry_run(&lst,(uint64_t)i));
    k = lsm_compact_pick(sizes, n, 3, 64, &lo); ok(k >= 2 && lo == 1, "pick a tail batch above the base");
    for (long i = 0; i < k; i++) in[i] = entry_run(&lst,(uint64_t)(lo+i));
    uint64_t pn = lst.manifest_n; unsigned char* pbuf = malloc(pn*16); memcpy(pbuf, lst.manifest_buf, pn*16);
    uint64_t p_live = lst.total_live, p_gen = lst.next_gen, p_run = lst.next_run_no, fork_base = lsm_manifest_persisted_live();
    utxo_lsm_set_defer_unlink(1); utxo_lsm_set_defer_publish(1);
    cr = utxo_lsm_compact_range(&lst, (unsigned long)lo, (unsigned long)k);
    utxo_lsm_set_defer_unlink(0); utxo_lsm_set_defer_publish(0);
    ok(cr > 0 && access("utxo_manifest.child", F_OK) == 0, "child-role tail merge wrote utxo_manifest.child");
    uint64_t merged2 = entry_run(&lst, (uint64_t)lo);
    memcpy(lst.manifest_buf, pbuf, pn*16); lst.manifest_n = pn; lst.total_live = p_live; lst.next_gen = p_gen + 1; lst.next_run_no = p_run + 1;
    long addedi = 0; while (lst.manifest_n == pn && addedi < 400000){ if (fill(&lst, table, 3000000+addedi, 5000)){ fprintf(stderr,"put failed\n"); return 1; } addedi += 5000; }
    ok(lst.manifest_n == pn + 1, "a run flushed meanwhile");
    uint64_t interim = entry_run(&lst, pn);
    ok(lsm_manifest_adopt_child(&lst, in, (int)k, 0, fork_base, 0) == 0, "adopt_child finds the merged run at index 1, not 0");
    uint64_t first_before; memcpy(&first_before, pbuf + 8, 8);
    ok(lst.manifest_n == 3 && entry_run(&lst,0) == first_before && entry_run(&lst,1) == merged2 && entry_run(&lst,2) == interim, "manifest = [base, merged, interim]");
    for (long i = 0; i < k; i++){ int named = 0; for (uint64_t j = 0; j < lst.manifest_n; j++) if (entry_run(&lst,j)==in[i]) named = 1; if (!named){ char nm[64]; snprintf(nm,sizeof nm,"utxo_run_%06u.dat",(unsigned)in[i]); unlink(nm); } }
    checked = check_keys(&lst, table, &ml, &rs);
    long mi = 0; for (long i = 3000000; i < 3000000+addedi; i += 83) if (!key_ok(&lst, table, i)) mi++;
    ok(ml == 0 && rs == 0 && mi == 0, "deleted keys dead, live keys and the interim run's keys resolve through the adopted manifest");
    utxo_lsm_close(&lst);
    printf("\n%s (%d failure%s)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
