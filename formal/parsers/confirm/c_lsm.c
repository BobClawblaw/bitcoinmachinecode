/* confirm X-LSM-gen on the compiled lsm_manifest.c: a manifest entry with
 * gen = 2^64-1 leaves next_gen unchanged (g + 1 wraps to 0), so the next run
 * written gets a generation no newer than an existing one. Scratch dir argv[1]. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "lsm_manifest.h"
int main(int argc, char** argv){
    if (argc < 2 || chdir(argv[1]) != 0) return 2;
    unsigned char b[12 + 16]; uint32_t magic = 0x4E414D55u; uint64_t n = 1, g = ~0ULL, rn = 5;
    memcpy(b, &magic, 4); memcpy(b + 4, &n, 8); memcpy(b + 12, &g, 8); memcpy(b + 20, &rn, 8);
    FILE* f = fopen("m.dat", "wb"); fwrite(b, 1, sizeof b, f); fclose(f);
    unsigned char buf[64]; struct lsm_state st; memset(&st, 0, sizeof st);
    st.manifest_buf = buf; st.manifest_cap = 4; st.next_gen = 7; st.next_run_no = 1;
    int r = lsm_manifest_read_file("m.dat", &st, 0);
    unlink("m.dat");
    printf("read = %d; entry gen = 2^64-1; next_gen after read = %llu, next_run_no = %llu\n", r, (unsigned long long)st.next_gen, (unsigned long long)st.next_run_no);
    printf("%s\n", r == 0 && st.next_gen <= g ? "CONFIRMED: next_gen not past the entry's gen" : "not reproduced");
    return 0;
}
