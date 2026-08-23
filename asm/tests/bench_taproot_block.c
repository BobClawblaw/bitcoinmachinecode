/* bench_taproot_block -- wall time and effective parallelism for ONE whole
 * block's script verification, at the block-connection entry point the live
 * daemon actually uses (tx_verify_block_connect_all).
 *
 * This is the measurement PERF_SCOPE.md section 14 was missing. Section 14
 * measured the SYMPTOM -- 32 worker threads asleep, one thread at 67% field
 * arithmetic -- from a live profile, which cannot be re-run cheaply or
 * compared between two trees. This runs the same work offline from a fixture
 * and reports, per block:
 *
 *   wall     ms of real time for one whole-block verification
 *   cpu      ms of process CPU time for the same
 *   par      cpu/wall -- effective cores in use. THIS is the number section 14
 *            said was ~1.0 on a 32-core box because taproot was sequential.
 *
 * It deliberately reports cpu as well as wall: a change that merely moves
 * work between threads leaves cpu alone and cuts wall, while a change that
 * does more total work shows up in cpu. Reporting only wall would hide that.
 *
 * The fixture is the same one tests/test_taproot_block_diff uses:
 *   python3 validation/fetch_taproot_blocks.py 825000
 *   make tests/bench_taproot_block && tests/bench_taproot_block 825000 [runs]
 *
 * Blocks and prevouts come from the scratch Core oracle, never the archive
 * (witness-stripped above height 481,824) and never the production install.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

typedef struct { const u8* ptr; u64 len; u8 txid[32]; u32 pn_in; } block_tx_t;
extern int tx_verify_block_connect_all(const block_tx_t* txs, u64 ntx, long height,
                                       const u8 block_hash32[32], void* lst, void* u, void* bx,
                                       u64* fail_tx_index, const char** reason);
extern void block_hash(u8 out[32], const u8 hdr[80]);

#define MAX_TX   16384
#define MAX_PREV 32768
#define SPK_MAX  10000

typedef struct { u8 key[36]; u64 value; u32 spklen; u8 spk[SPK_MAX]; } prev_t;
static prev_t* g_prev; static long g_nprev;
static int prev_cmp(const void* a, const void* b){ return memcmp(a, b, 36); }

long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
                  u64* value, u64* height, u64* coinbase,
                  const u8** spk, unsigned long* spklen){
    (void)lst; (void)u;
    static u8 scratch[SPK_MAX];
    u8 key[36]; memcpy(key, txid, 32); memcpy(key+32, &index, 4);
    prev_t* e = bsearch(key, g_prev, g_nprev, sizeof(prev_t), prev_cmp);
    if (!e) return 0;
    memcpy(scratch, e->spk, e->spklen);
    *value = e->value; *height = 1; *coinbase = 0;
    *spk = scratch; *spklen = e->spklen;
    return 1;
}
long bidx_get(void* bx, u32 tx_index, const u8 txid[32], u32 index,
              u64* value, u64* height, u64* coinbase,
              const u8** spk, unsigned long* spklen){
    (void)bx;(void)tx_index;(void)txid;(void)index;(void)value;(void)height;(void)coinbase;(void)spk;(void)spklen;
    return -1;
}
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk, unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen; abort();
}

static u64 rd_cs(const u8** p){ u64 v=**p; (*p)++; if(v<0xfd) return v;
    if(v==0xfd){ v=(*p)[0]|((u64)(*p)[1]<<8); *p+=2; return v; }
    if(v==0xfe){ v=(*p)[0]|((u64)(*p)[1]<<8)|((u64)(*p)[2]<<16)|((u64)(*p)[3]<<24); *p+=4; return v; }
    v=0; for(int i=0;i<8;i++) v|=(u64)(*p)[i]<<(8*i); *p+=8; return v; }

static u64 tx_walk(const u8* p, u32* n_in){
    const u8* s = p; p += 4;
    int wit = (p[0]==0x00 && p[1]==0x01); if (wit) p += 2;
    u64 nin = rd_cs(&p); *n_in = (u32)nin;
    for (u64 i=0;i<nin;i++){ p += 36; u64 sl = rd_cs(&p); p += sl + 4; }
    u64 nout = rd_cs(&p);
    for (u64 i=0;i<nout;i++){ p += 8; u64 sl = rd_cs(&p); p += sl; }
    if (wit) for (u64 i=0;i<nin;i++){ u64 ni = rd_cs(&p);
        for (u64 j=0;j<ni;j++){ u64 il = rd_cs(&p); p += il; } }
    p += 4;
    return (u64)(p - s);
}

static int hx(const char* h, u8* out, long cap){ long n=0; for(; h[0]&&h[1]&&n<cap; h+=2,n++){ unsigned v; sscanf(h,"%2x",&v); out[n]=(u8)v; } return (int)n; }
static double now_s(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec + t.tv_nsec*1e-9; }
static double cpu_s(void){ struct timespec t; clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t); return t.tv_sec + t.tv_nsec*1e-9; }

int main(int argc, char** argv){
    if (argc < 2){ printf("usage: %s <height>... [--runs N]\n", argv[0]); return 2; }
    int runs = 5;
    for (int i=1;i<argc-1;i++) if (!strcmp(argv[i],"--runs")) runs = atoi(argv[i+1]);

    g_prev = calloc(MAX_PREV, sizeof(prev_t));
    static u8 blk[8<<20];
    static block_tx_t txs[MAX_TX];
    printf("%-9s %7s %7s %8s %8s %8s %6s %10s\n",
           "height","tx","inputs","tapin","wall_ms","cpu_ms","par","inputs/s");
    double tot_wall=0, tot_cpu=0; u64 tot_in=0; int nblk=0;

    for (int a=1;a<argc;a++){
        if (!strcmp(argv[a],"--runs")) { a++; continue; }
        int H = atoi(argv[a]); if (H <= 0) continue;
        char path[256];
        snprintf(path,sizeof path,"tests/fixtures/blk_%d.bin",H);
        FILE* fb = fopen(path,"rb");
        snprintf(path,sizeof path,"tests/fixtures/blk_%d.prevouts",H);
        FILE* fp = fopen(path,"r");
        if (!fb || !fp){
            if (fb) fclose(fb);
            if (fp) fclose(fp);
            printf("%-9d SKIP (no fixture; validation/fetch_taproot_blocks.py %d)\n", H, H);
            continue;
        }
        long blen = (long)fread(blk,1,sizeof blk,fb); fclose(fb);
        g_nprev = 0;
        {
            static char line[SPK_MAX*2+256];
            while (fgets(line,sizeof line,fp)){
                char txh[80]; static char spkh[SPK_MAX*2+8];
                unsigned idx; unsigned long long val;
                if (sscanf(line,"%79s %u %llu %20007s",txh,&idx,&val,spkh)!=4) continue;
                prev_t* e = &g_prev[g_nprev++];
                u8 disp[32]; hx(txh,disp,32);
                for (int k=0;k<32;k++) e->key[k]=disp[31-k];
                memcpy(e->key+32,&idx,4);
                e->value = val; e->spklen = (u32)hx(spkh,e->spk,sizeof e->spk);
            }
        }
        fclose(fp);
        qsort(g_prev, g_nprev, sizeof(prev_t), prev_cmp);

        u8 bh[32]; block_hash(bh, blk);
        const u8* p = blk + 80; u64 ntx = rd_cs(&p);
        u64 off = (u64)(p - blk), nin_total = 0, ntap = 0;
        for (u64 t=0;t<ntx;t++){
            u32 nin; u64 tl = tx_walk(blk+off,&nin);
            txs[t].ptr = blk+off; txs[t].len = tl; txs[t].pn_in = nin;
            memset(txs[t].txid,0,32);
            if (t) nin_total += nin;
            off += tl;
        }
        (void)blen;
        for (long i=0;i<g_nprev;i++)
            if (g_prev[i].spklen==34 && g_prev[i].spk[0]==0x51 && g_prev[i].spk[1]==0x20) ntap++;

        /* one untimed warm-up: the worker pool starts lazily and the arenas
         * grow on first use, and neither is what this is measuring */
        u64 ft; const char* why;
        if (tx_verify_block_connect_all(txs,ntx,H,bh,NULL,NULL,NULL,&ft,&why) != 1){
            printf("%-9d REJECTED tx=%llu: %s\n", H, (unsigned long long)ft, why);
            continue;
        }
        double w0=now_s(), c0=cpu_s();
        for (int r=0;r<runs;r++)
            if (tx_verify_block_connect_all(txs,ntx,H,bh,NULL,NULL,NULL,&ft,&why) != 1){
                printf("%-9d REJECTED on run %d\n", H, r); break;
            }
        double w=(now_s()-w0)/runs, c=(cpu_s()-c0)/runs;
        printf("%-9d %7llu %7llu %8llu %8.1f %8.1f %6.2f %10.0f\n",
               H,(unsigned long long)(ntx-1),(unsigned long long)nin_total,
               (unsigned long long)ntap, w*1e3, c*1e3, c/w, nin_total/w);
        tot_wall += w; tot_cpu += c; tot_in += nin_total; nblk++;
    }
    if (nblk){
        printf("%-9s %7s %7llu %8s %8.1f %8.1f %6.2f %10.0f\n",
               "TOTAL","",(unsigned long long)tot_in,"",
               tot_wall*1e3, tot_cpu*1e3, tot_cpu/tot_wall, tot_in/tot_wall);
        printf("(%d blocks, %d timed runs each)\n", nblk, runs);
    }
    return 0;
}
