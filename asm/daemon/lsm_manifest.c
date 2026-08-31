/* daemon/lsm_manifest.c -- see lsm_manifest.h.
 * Format (bitcoin_utxo_lsm.asm): UMN2 header = magic(4) manifest_n(8)
 * total_live(8), then manifest_n entries of [gen:8][run_no:8]. The OLD UMAN
 * header lacks total_live (12 bytes). */
#include <stdio.h>
#include <string.h>
#include "lsm_manifest.h"
#define MAGIC_MANIFEST  0x4E414D55u
#define MAGIC_MANIFEST2 0x324E4D55u
int lsm_manifest_read(struct lsm_state* lst, uint64_t* persisted_live){
    FILE* f = fopen("utxo_manifest.dat", "rb");
    if (!f) return -1;
    unsigned char h[20];
    if (fread(h, 1, 12, f) != 12){ fclose(f); return -1; }
    uint32_t magic; memcpy(&magic, h, 4);
    uint64_t n; memcpy(&n, h + 4, 8);
    uint64_t live = 0; int v2 = (magic == MAGIC_MANIFEST2);
    if (magic != MAGIC_MANIFEST && !v2){ fclose(f); return -1; }
    if (v2){ if (fread(h + 12, 1, 8, f) != 8){ fclose(f); return -1; } memcpy(&live, h + 12, 8); }
    if (n > lst->manifest_cap){ fclose(f); return -1; }
    if (n && fread(lst->manifest_buf, 16, (size_t)n, f) != n){ fclose(f); return -1; }
    fclose(f);
    lst->manifest_n = n;
    if (persisted_live) *persisted_live = v2 ? live : ~0ULL;
    const unsigned char* e = (const unsigned char*)lst->manifest_buf;
    for (uint64_t i = 0; i < n; i++){
        uint64_t g, r; memcpy(&g, e + i*16, 8); memcpy(&r, e + i*16 + 8, 8);
        if (g + 1 > lst->next_gen)    lst->next_gen    = g + 1;
        if (r + 1 > lst->next_run_no) lst->next_run_no = r + 1;
    }
    return 0;
}
uint64_t lsm_manifest_persisted_live(void){
    FILE* f = fopen("utxo_manifest.dat", "rb");
    if (!f) return ~0ULL;
    unsigned char h[20]; size_t got = fread(h, 1, 20, f); fclose(f);
    if (got != 20) return ~0ULL;
    uint32_t magic; memcpy(&magic, h, 4);
    if (magic != MAGIC_MANIFEST2) return ~0ULL;
    uint64_t live; memcpy(&live, h + 12, 8); return live;
}
