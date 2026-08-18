/* test_truncate.c -- 100% AI-generated harness for Stage A reorg/fork-choice
 * primitive #4: store_truncate_to (bitcoin_store.asm). Verifies exact
 * on-disk byte sizes after truncation, that idx_build_from_file (the
 * EXISTING bitcoin_idx.asm bulk loader, unmodified) produces a correct
 * hash index containing nothing from the truncated-away blocks, and that
 * the store is genuinely re-appendable afterward (not just truncated and
 * broken). Runs in a throwaway temp dir.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

extern int  store_init(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, unsigned long long len);
extern int  store_get_at(void* st, unsigned long long height, unsigned long long* out_meta);
extern long long store_truncate_to(void* st, long long target_height);

extern void idx_init(void* idx, unsigned long slots_pow2_cap);
extern int  idx_get(void* idx, const unsigned char hash[32], long* height);
extern long idx_count(void* idx);
extern long idx_build_from_file(void* idx, const char* path);

/* state struct layout must mirror bitcoin_store.asm (see tests/test_store.c) */
struct St {
    unsigned long long cur_blk_fd, idx_fd, idx_len;
    int tip_height, cur_file_no, cur_file_pos, magic, pad, pad2, prune_height;
};

static int failures = 0;
static void cki(const char* l, long long g, long long e){ if(g==e)printf("PASS %s (got %lld)\n",l,g); else{printf("FAIL %s got=%lld exp=%lld\n",l,g,e);failures++;} }

static long filesize(const char* path){
    struct stat sb;
    if (stat(path, &sb) != 0) return -1;
    return (long)sb.st_size;
}

/* idx_build_from_file (bitcoin_idx.asm, unmodified) treats index.dat's
 * on-disk hash as big-endian DISPLAY order and idx_puts its byte-reversed
 * (wire/LE) form -- see that file's own header comment. store_append (and
 * this test's synthetic hashes) write/compare hashes in plain, unreversed
 * order, so queries against the loaded index must reverse first to match
 * what idx_build_from_file actually inserted. */
static void reverse32(unsigned char out[32], const unsigned char in[32]){
    for (int i=0;i<32;i++) out[i] = in[31-i];
}

/* IDX layout: +0 n, +8 mask, +16 reserved[8], +24.. slots (48B stride) */
#define IDX_SLOTS 64
static unsigned char g_idx[24 + IDX_SLOTS*48];

int main(void){
    char tmpl[]="/tmp/btctruncXXXXXX";
    char* dir = mkdtemp(tmpl);
    if(!dir){ printf("FAIL mkdtemp\n"); return 1; }
    chdir(dir);

    unsigned char hashes[5][32];
    for (int h=0; h<5; h++) for (int j=0;j<32;j++) hashes[h][j] = (unsigned char)((h+1)*10 + j);
    static unsigned char raws[5][90];
    int sizes[5] = {50,60,70,80,90};
    for (int h=0; h<5; h++) memset(raws[h], (unsigned char)(0x30+h), sizes[h]);

    /* expected data_pos per height, hand-computed: frame = 8+size */
    long expect_pos[5], pos = 0;
    for (int h=0; h<5; h++){ expect_pos[h] = pos; pos += 8 + sizes[h]; }
    long total_file_size = pos; /* after all 5 appended */

    /* ============================================================
     * Part 1: partial truncate (keep 0..2, drop 3,4), verify exact sizes,
     * idx_build_from_file correctness, and re-appendability.
     * ============================================================ */
    {
        struct St st; memset(&st, 0, sizeof st);
        cki("store_init", store_init(&st), 1);
        for (int h=0; h<5; h++){
            long long r = store_append(&st, hashes[h], raws[h], sizes[h]);
            cki("append height", r, h);
        }
        cki("pre-truncate blk00000.dat size", filesize("blk00000.dat"), total_file_size);
        cki("pre-truncate index.dat size", filesize("index.dat"), 5*48);

        cki("truncate_to(2)", store_truncate_to(&st, 2), 1);

        cki("post-truncate index.dat size", filesize("index.dat"), 3*48);
        cki("post-truncate blk00000.dat size", filesize("blk00000.dat"), expect_pos[3]);
        cki("post-truncate st.idx_len", (long long)st.idx_len, 3*48);
        cki("post-truncate st.tip_height", st.tip_height, 2);
        cki("post-truncate st.cur_file_no", st.cur_file_no, 0);
        cki("post-truncate st.cur_file_pos", st.cur_file_pos, expect_pos[3]);

        /* the surviving heights must still read back exactly right */
        unsigned long long meta[3];
        for (int h=0; h<3; h++){
            cki("post-truncate get_at ok", store_get_at(&st, h, meta), 1);
            cki("post-truncate get_at pos", (long long)meta[0], expect_pos[h]);
            cki("post-truncate get_at size", (long long)meta[1], sizes[h]);
        }
        cki("post-truncate get_at(3) now out-of-range", store_get_at(&st, 3, meta), -2);

        /* idx_build_from_file: existing, UNMODIFIED bulk loader must see
         * exactly heights 0,1,2 and nothing of 3,4. */
        idx_init(g_idx, IDX_SLOTS);
        long rc = idx_build_from_file(g_idx, "index.dat");
        cki("idx_build_from_file rc", rc, 0);
        cki("idx_count == 3 after truncate", idx_count(g_idx), 3);
        for (int h=0; h<3; h++){
            long got_h = -999;
            unsigned char rev[32]; reverse32(rev, hashes[h]);
            int found = idx_get(g_idx, rev, &got_h);
            cki("idx_get finds surviving height (found flag)", found, 1);
            cki("idx_get finds surviving height (value)", got_h, h);
        }
        for (int h=3; h<5; h++){
            long got_h = -999;
            unsigned char rev[32]; reverse32(rev, hashes[h]);
            int found = idx_get(g_idx, rev, &got_h);
            cki("idx_get must NOT find truncated-away height", found, 0);
        }

        /* re-append after truncation: store must be genuinely usable, not
         * just truncated-and-broken. New block lands exactly where the
         * truncated data used to begin. */
        unsigned char h3new[32]; memset(h3new, 0x77, 32);
        unsigned char raw3new[33]; memset(raw3new, 0x99, sizeof raw3new);
        long long r = store_append(&st, h3new, raw3new, sizeof raw3new);
        cki("re-append after truncate -> height 3", r, 3);
        unsigned long long meta2[3];
        cki("re-append get_at ok", store_get_at(&st, 3, meta2), 1);
        cki("re-append lands at the old boundary pos", (long long)meta2[0], expect_pos[3]);
        cki("re-append size", (long long)meta2[1], (long long)sizeof raw3new);
        cki("re-append blk file size grows correctly", filesize("blk00000.dat"), expect_pos[3] + 8 + (long)sizeof raw3new);

        unlink("blk00000.dat"); unlink("index.dat");
    }

    /* ============================================================
     * Part 2: no-op truncate (target_height >= tip)
     * ============================================================ */
    {
        struct St st; memset(&st, 0, sizeof st);
        cki("store_init (noop case)", store_init(&st), 1);
        for (int h=0; h<3; h++) store_append(&st, hashes[h], raws[h], sizes[h]);
        unsigned long long idx_len_before = st.idx_len;
        int tip_before = st.tip_height;
        cki("truncate_to(tip) is a no-op success", store_truncate_to(&st, 2), 1);
        cki("no-op: idx_len unchanged", (long long)st.idx_len, (long long)idx_len_before);
        cki("no-op: tip_height unchanged", st.tip_height, tip_before);
        cki("truncate_to(beyond tip) is also a no-op success", store_truncate_to(&st, 99), 1);
        cki("no-op(beyond): tip_height still unchanged", st.tip_height, tip_before);
        unlink("blk00000.dat"); unlink("index.dat");
    }

    /* ============================================================
     * Part 3: full truncate to empty (target_height == -1)
     * ============================================================ */
    {
        struct St st; memset(&st, 0, sizeof st);
        cki("store_init (full-empty case)", store_init(&st), 1);
        for (int h=0; h<3; h++) store_append(&st, hashes[h], raws[h], sizes[h]);

        cki("truncate_to(-1) wipes everything", store_truncate_to(&st, -1), 1);
        cki("full-empty: idx_len==0", (long long)st.idx_len, 0);
        cki("full-empty: tip_height==-1", st.tip_height, -1);
        cki("full-empty: index.dat size 0", filesize("index.dat"), 0);
        cki("full-empty: blk00000.dat gone", filesize("blk00000.dat"), -1);

        /* store must still be usable: appending after a full wipe starts
         * fresh at height 0 again. */
        long long r = store_append(&st, hashes[0], raws[0], sizes[0]);
        cki("append after full wipe -> height 0", r, 0);
        unsigned long long meta[3];
        cki("append after full wipe get_at ok", store_get_at(&st, 0, meta), 1);
        cki("append after full wipe pos 0", (long long)meta[0], 0);

        unlink("blk00000.dat"); unlink("index.dat");
    }

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    rmdir(dir);
    return failures?1:0;
}
