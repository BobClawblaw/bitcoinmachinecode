/* sort_repro3.c -- full-scale flush simulation: 71M descriptors, push gather
 * in REAL base-slot order (utxo_hash), tomb gather last in del order, then
 * utxo_lsm_sort_desc -- print the resulting order of the real tie group. */
#include "../utxo_lsm_twin.c"
#include <stdlib.h>

static u64 rng_state = 0x9e3779b97f4a7c15ull;
static u64 rng(void){ rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17; return rng_state; }

static u64 utxo_hash(const u8 txid[32], u64 index, u64 mask){
    u32 h = 0x811c9dc5u;
    for (int i = 0; i < 8; i++) { h ^= txid[i]; h *= 16777619u; }
    u64 off = (u64)h ^ index;
    off &= mask;
    return off * 48 + 40;
}
static int keycmp36(const u8 *a, const u8 *b){ return memcmp(a, b, 36); }

int main(int argc, char **argv){
    u64 n_total = argc > 1 ? (u64)atoll(argv[1]) : 71000000ull;
    /* the real tie group: txid ae1b..460f, pushes 0..204 minus tombs, tombs in del order */
    u8 txid[32];
    const char *tx = "ae1b2b7b3fceaca5174ee77a47f7a15676abf2681f763331483087e7a304460f";
    for (int i = 0; i < 32; i++){ unsigned v; sscanf(tx + i*2, "%2x", &v); txid[i] = (u8)v; }
    u32 tombs[9] = {11, 22, 33, 181, 123, 81, 64, 16, 42};
    u32 n_tombs = 9;

    u8 *a = malloc(n_total * 64);
    u8 *b = malloc(n_total * 80 + 65536);   /* compact arrays need ~1.25n*64 beyond b, as desc_cap slack does in mac_flush */
    if (!a || !b){ printf("alloc failed\n"); return 2; }

    u64 mask = (1ull << 28) - 1;                       /* dbcache=65536 -> 2^28 slots */
    u64 nd = 0;
    /* push gather: base slots in SLOT ORDER (s = 0..mask) -- for the tie group's
     * coins that means ascending (utxo_hash(txid,vout) & mask); emulate by
     * computing each push's slot and visiting slots ascending = vout order for
     * a txid whose hash low bits are zero; in general XOR-scrambled. We place
     * ALL descriptors by iterating a virtual slot order: background keys get
     * random slots. To keep it tractable we gather: background (random order),
     * then the tie group's pushes in slot order (computed), then tombs in del
     * order -- matching mac_flush's section order (pushes then tombs). */
    u64 n_bg = n_total - 205;   /* 196 pushes + 9 tombs */
    for (u64 i = 0; i < n_bg; i++){
        u8 *d = a + nd * 64;
        u64 r1 = rng(), r2 = rng(), r3 = rng();
        memcpy(d, &r1, 8); memcpy(d + 8, &r2, 8);
        u64 t3 = rng(); memcpy(d + 12, &r3, 8); memcpy(d + 20, &t3, 8);
        u64 t4 = rng(); memcpy(d + 28, &t4, 8);
        u32 idx = (u32)(rng() & 0xFF);
        memcpy(d + 32, &idx, 4);
        d[36] = (rng() & 1) ? 1 : 2;
        nd++;
    }
    /* tie group pushes: order by slot = (fnv8-like hash ^ vout) & mask.
     * compute with the real utxo_hash. */
    u32 push_vouts[205]; u32 np = 0;
    for (u32 v = 0; v <= 204; v++){
        int tomb = 0;
        for (u32 k = 0; k < n_tombs; k++) if (tombs[k] == v) tomb = 1;
        if (!tomb) push_vouts[np++] = v;
    }
    /* slot order: sort push_vouts by utxo_hash(txid, vout, mask) */
    for (u32 i = 0; i < np; i++)
        for (u32 j = i + 1; j < np; j++){
            u64 si = utxo_hash(txid, push_vouts[i], mask);
            u64 sj = utxo_hash(txid, push_vouts[j], mask);
            if (sj < si){ u32 t = push_vouts[i]; push_vouts[i] = push_vouts[j]; push_vouts[j] = t; }
        }
    for (u32 i = 0; i < np; i++){
        u8 *d = a + nd * 64;
        memcpy(d, txid, 32); memcpy(d + 32, &push_vouts[i], 4);
        d[36] = 1; nd++;
    }
    for (u32 i = 0; i < n_tombs; i++){
        u8 *d = a + nd * 64;
        memcpy(d, txid, 32); memcpy(d + 32, &tombs[i], 4);
        d[36] = 2; nd++;
    }
    printf("gathered n=%llu (bg=%llu, group pushes=%u in slot order, tombs last in del order)\n",
           (unsigned long long)nd, (unsigned long long)n_bg, np);

    fprintf(stderr, "gathered; sorting...\n");
    fflush(stderr);
    utxo_lsm_sort_desc(a, b, nd);
    fprintf(stderr, "sorted.\n"); fflush(stderr);

    /* print the tie group's resulting order */
    u64 viol = 0;
    for (u64 i = 1; i < nd; i++)
        if (keycmp36(a + (i-1)*64, a + i*64) > 0) viol++;
    printf("total violations after sort: %llu\n", (unsigned long long)viol);
    u64 shown = 0;
    for (u64 i = 0; i < nd && shown < 230; i++){
        if (memcmp(a + i*64, txid, 32) == 0){
            u32 idx; memcpy(&idx, a + i*64 + 32, 4);
            printf("%s vout=%u%s\n", a[i*64+36] == 2 ? "T" : "P", idx,
                   (idx == 11 || idx == 22 || idx == 33 || idx == 181 || idx == 123 || idx == 81 || idx == 64 || idx == 16 || idx == 42) ? "   <-- tombstoned" : "");
            shown++;
        }
    }
    return 0;
}
