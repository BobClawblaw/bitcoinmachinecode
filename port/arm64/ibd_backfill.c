/* ibd_backfill.c -- re-apply an archived block window to the persisted LSM UTXO.
 *
 * WHY: ibd_lsm's two pre-fix runs appended blocks 965009..965014 to the block
 * archive but added ZERO outputs to the LSM (the legacy-only tx_walk), and the
 * post-fix runs keyed their outputs by WTXID (sha256d over the full
 * serialization) instead of the txid. Both defects leave the persisted UTXO
 * unable to resolve spends of that window. This tool re-applies a window of
 * blocks ALREADY IN THE ARCHIVE -- store_get_at + pread, no network, no
 * store_append (the archive entries stay where they are) -- using the FIXED
 * walker and REAL txids (witness-stripped, BIP141).
 *
 * The wtxid-keyed junk entries from the earlier runs remain in the LSM (they
 * are unspendable garbage; a daemon-side utxo_setinfo reconciliation or an
 * LSM rebuild from an assume-valid point is the full clean-up -- out of
 * scope here).
 *
 * Usage: ibd_backfill <start> <count> [datadir] [slots_log2]
 *   reads datadir's block archive + LSM state IN PLACE (same layout as
 *   ibd_lsm: utxo_lsm_table.map / utxo_lsm_blob.map / manifest / WAL).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>

typedef uint8_t u8;
typedef uint64_t u64;
static int BMC_TRACE_ON(void){ return getenv("BMC_BACKFILL_TRACE")!=0; }

extern int    store_init(void* st);
extern int    store_reload(void* st);
extern int    store_get_at(void* st, long height, void* meta /*{pos,size,file_no}*/);
extern long   store_get_file_fd(void* st, unsigned file_no);
extern unsigned long utxo_struct_size(unsigned long slots);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_lsm_reload(void* lst, void* u);
extern long   utxo_lsm_put(void* lst, void* u, const u8 txid[32], unsigned long index,
                           unsigned long long value, unsigned long height, unsigned long cb,
                           const u8* script, unsigned long slen);
extern long   utxo_lsm_del(void* lst, void* u, const u8 txid[32], unsigned long index);
extern long   utxo_lsm_get(void* lst, void* u, const u8 txid[32], unsigned long index,
                           unsigned long long* value, unsigned long* height, unsigned long* cb,
                           const u8** script, unsigned long* slen);
extern long   utxo_lsm_count(void* lst);
extern long   utxo_lsm_flush(void* lst, void* u);
extern long   utxo_lsm_close(void* lst);
extern void   sha256d(void* out32, const void* in, unsigned long len);

struct lsm_state {
    long log_fd, idx_fd;
    uint64_t log_len, ckpt_log_off, ckpt_n;
    uint64_t op_count, op_threshold, fill_threshold;
    void* tomb_buf; uint64_t tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; uint64_t manifest_cap, manifest_n;
    void* scratch_buf; uint64_t scratch_cap;
    uint64_t next_run_no;
    void* tomb_hash_buf; uint64_t tomb_hash_mask;
};
#define LSM_BARRIER() __asm__ __volatile__("" ::: "memory", "x19","x20","x21","x22","x23","x24","x25","x26","x27","x28")

static void* g_utxo;
static struct lsm_state* g_lst;
static unsigned long G_slots, G_blob_cap, G_fill, G_op, G_tomb_cap, G_scratch_cap, G_manifest_cap;
static long g_flushes=0, g_full_retries=0;

static void* mmap_file(const char* path, uint64_t size){
    int fd = open(path, O_RDWR|O_CREAT, 0644);
    if(fd<0){ perror("open"); return 0; }
    if(ftruncate(fd,(off_t)size)!=0){ perror("ftruncate"); close(fd); return 0; }
    void* p = mmap(0,size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    close(fd);
    if(p == (void*)-1 || !p){ fprintf(stderr,"mmap alloc failed\n"); return 0; }
    return p;
}

static long lsm_put(const u8* txid, unsigned long index, unsigned long long value,
                    unsigned long height, unsigned long cb, const u8* script, unsigned long slen){
    long r = utxo_lsm_put(g_lst, g_utxo, txid, index, value, height, cb, script, slen);
    if (r == 2){
        if (utxo_lsm_flush(g_lst, g_utxo) != 1){
            fprintf(stderr, "FATAL: utxo_lsm_flush after .full failed\n"); return -1;
        }
        g_flushes++; g_full_retries++;
        r = utxo_lsm_put(g_lst, g_utxo, txid, index, value, height, cb, script, slen);
        if (r == 2){ fprintf(stderr, "FATAL: retry still .full\n"); return -1; }
    }
    return r;
}

/* ---- tx helpers (identical to ibd_lsm.c, incl. the wstart/txid fix) ---- */
static int rd_varint(const unsigned char*p, unsigned long n, unsigned long long* out){
    if(n<1) return -1;
    unsigned char b=p[0];
    if(b<0xfd){ *out=b; return 1; }
    else if(b==0xfd){ if(n<3)return -1; *out=p[1]|(p[2]<<8); return 3; }
    else if(b==0xfe){ if(n<5)return -1; *out=p[1]|(p[2]<<8)|(p[3]<<16)|((unsigned long long)p[4]<<24); return 5; }
    else { if(n<9)return -1; *out=p[1]|(p[2]<<8)|(p[3]<<16)|((unsigned long long)p[4]<<24)|((unsigned long long)p[5]<<32)|((unsigned long long)p[6]<<40)|((unsigned long long)p[7]<<48)|((unsigned long long)p[8]<<56); return 9; }
}
static long tx_walk(const unsigned char*tx, unsigned long n, unsigned long* nin, unsigned long* nout,
                    unsigned long* wstart){
    if(n<4+1+1) return -1;
    unsigned long o=4;
    int segwit = 0;
    if(wstart) *wstart = 0;
    if(o+2<=n && tx[o]==0x00 && tx[o+1]==0x01){ segwit=1; o+=2; }
    unsigned long long ni; int v=rd_varint(tx+o,n-o,&ni); if(v<0)return -1; o+=v;
    unsigned long long nin_=ni, i;
    for(i=0;i<nin_;i++){
        if(o+36+4>n) return -1;
        o+=36;
        unsigned long long sl; v=rd_varint(tx+o,n-o,&sl); if(v<0)return -1; o+=v;
        if(o+sl+4>n) return -1;
        o+=sl+4;
    }
    unsigned long long no; v=rd_varint(tx+o,n-o,&no); if(v<0)return -1; o+=v;
    unsigned long long nout_=no, j;
    for(j=0;j<nout_;j++){
        if(o+8>n) return -1; o+=8;
        unsigned long long sl; v=rd_varint(tx+o,n-o,&sl); if(v<0)return -1; o+=v;
        if(o+sl>n) return -1; o+=sl;
    }
    if(segwit){
        if(wstart) *wstart = o;
        for(i=0;i<nin_;i++){
            unsigned long long nitems; v=rd_varint(tx+o,n-o,&nitems); if(v<0)return -1;
            o+=v;
            unsigned long long k;
            for(k=0;k<nitems;k++){
                unsigned long long sl; v=rd_varint(tx+o,n-o,&sl); if(v<0)return -1;
                o+=v; o+=sl;
                if(o>n) return -1;
            }
        }
    }
    if(o+4>n) return -1; o+=4;
    *nin=nin_; *nout=nout_;
    return (long)o;
}
static void txid_of(const unsigned char* tx, unsigned long tl, unsigned long wstart,
                    unsigned char out[32]){
    if (wstart == 0){ sha256d(out, tx, tl); return; }
    static unsigned char core[1<<22];
    unsigned long corelen = 4 + (wstart - 6) + 4;
    memcpy(core, tx, 4);
    memcpy(core+4, tx+6, wstart-6);
    memcpy(core+4+(wstart-6), tx+tl-4, 4);
    sha256d(out, core, corelen);
}
static int tx_in2(const unsigned char*tx, unsigned long n, unsigned long idx,
                  u8* prevhash, unsigned long* previndex){
    unsigned long o=4;
    /* BIP144: skip marker(0x00)+flag(0x01) exactly like tx_walk -- without
     * this the marker reads as ni=0 and every segwit input is skipped. */
    if(o+2<=n && tx[o]==0x00 && tx[o+1]==0x01) o+=2;
    unsigned long long ni; int v=rd_varint(tx+o,n-o,&ni); if(v<0)return -1;
    if(idx>=ni) return -1;
    o+=v;
    for(unsigned long i=0;i<ni;i++){
        if(o+36+4>n) return -1;
        if(i==idx){
            memcpy(prevhash,tx+o,32);
            *previndex=(unsigned long)tx[o+32]|((unsigned long)tx[o+33]<<8)|((unsigned long)tx[o+34]<<16)|((unsigned long)tx[o+35]<<24);
            return 0;
        }
        o+=36;
        unsigned long long sl; v=rd_varint(tx+o,n-o,&sl); if(v<0)return -1; o+=v;
        if(o+sl+4>n) return -1;
        o+=sl+4;
    }
    return -1;
}
static int tx_out(const unsigned char*tx, unsigned long n, unsigned long idx,
                  unsigned long long* value, const u8** script, unsigned long* sl){
    unsigned long o=4;
    /* BIP144: skip marker(0x00)+flag(0x01) exactly like tx_walk -- without
     * this the marker reads as ni=0 and the flag as vout count=1, so "vout 0"
     * becomes 8 bytes of the first prevhash (garbage value/script). */
    if(o+2<=n && tx[o]==0x00 && tx[o+1]==0x01) o+=2;
    unsigned long long ni; int v=rd_varint(tx+o,n-o,&ni); if(v<0)return -1; o+=v;
    unsigned long long no;
    { unsigned long i; for(i=0;i<ni;i++){ if(o+36+4>n)return -1; o+=36; unsigned long long sl_; v=rd_varint(tx+o,n-o,&sl_); if(v<0)return -1; o+=v; if(o+sl_+4>n)return -1; o+=sl_+4; } }
    v=rd_varint(tx+o,n-o,&no); if(v<0)return -1; o+=v;
    unsigned long j;
    for(j=0;j<no;j++){
        if(o+8>n) return -1;
        if(j==idx){
            *value=(unsigned long long)tx[o]|((unsigned long long)tx[o+1]<<8)|((unsigned long long)tx[o+2]<<16)|((unsigned long long)tx[o+3]<<24)|((unsigned long long)tx[o+4]<<32)|((unsigned long long)tx[o+5]<<40)|((unsigned long long)tx[o+6]<<48)|((unsigned long long)tx[o+7]<<56);
            unsigned long long sl_; v=rd_varint(tx+o+8,n-o-8,&sl_); if(v<0)return -1;
            *sl=(unsigned long)sl_;
            *script=tx+o+8+v;
            return 0;
        }
        unsigned long long sl_; v=rd_varint(tx+o+8,n-o-8,&sl_); if(v<0)return -1;
        o+=8+v+(unsigned long)sl_;
    }
    return -1;
}

int main(int argc, char** argv){
    if(argc<3){ fprintf(stderr,"usage: %s <start> <count> [datadir] [slots_log2]\n",argv[0]); return 2; }
    long start = atol(argv[1]);
    long count = atol(argv[2]);
    const char* dd = argc>3?argv[3]:".";
    int G_slots_log2 = argc>4?atoi(argv[4]):20;
    if(count<=0 || start<0){ fprintf(stderr,"bad window\n"); return 2; }
    chdir(dd);

    static unsigned char store_buf[4096];
    if(store_init(store_buf)!=1){ fprintf(stderr,"store_init failed\n"); return 1; }
    store_reload(store_buf);
    long tip = *(int*)(store_buf+24);
    if(start>tip){ fprintf(stderr,"start %ld beyond archive tip %ld\n",start,tip); return 1; }
    if(start+count-1>tip){ count = tip-start+1; fprintf(stderr,"clamped count to %ld (tip %ld)\n",count,tip); }

    G_slots = 1UL<<G_slots_log2;
    G_blob_cap = 1UL<<30;
    long ustruct = utxo_struct_size(G_slots);
    g_utxo = mmap_file("utxo_lsm_table.map", (uint64_t)ustruct);
    void* blob = mmap_file("utxo_lsm_blob.map", G_blob_cap);
    if(!g_utxo || !blob){ fprintf(stderr,"mmap alloc failed\n"); return 1; }
    utxo_init(g_utxo, G_slots, blob, G_blob_cap);
    G_fill = (uint64_t)G_slots*3/4;
    G_op    = (uint64_t)G_slots*2;
    G_tomb_cap = G_op;
    uint64_t desc_cap = (uint64_t)G_slots*3;
    /* EXACTLY ibd_lsm.c's sizing: mac_flush builds run descriptors + per-run
     * blooms + scripts in the scratch -- a smaller buffer makes mac_flush
     * fail, which surfaces as utxo_lsm_put returning -1 mid-backfill. */
    G_scratch_cap = desc_cap*128 + 4*1024*1024 + 65536;
    G_manifest_cap = 8192;
    void* tomb_buf = malloc(G_tomb_cap*36);
    void* manifest_buf = malloc(G_manifest_cap*16);
    void* scratch_buf = malloc(G_scratch_cap);
    if(!tomb_buf||!manifest_buf||!scratch_buf){ fprintf(stderr,"LSM buffer malloc failed\n"); return 1; }
    g_lst = calloc(1,sizeof(struct lsm_state));
    memset(g_lst,0,sizeof *g_lst);
    g_lst->op_threshold=G_op; g_lst->fill_threshold=G_fill;
    g_lst->tomb_buf=tomb_buf; g_lst->tomb_cap=G_tomb_cap;
    g_lst->manifest_buf=manifest_buf; g_lst->manifest_cap=G_manifest_cap;
    g_lst->scratch_buf=scratch_buf; g_lst->scratch_cap=G_scratch_cap;
    long rel = utxo_lsm_reload(g_lst, g_utxo);
    LSM_BARRIER();
    if(rel<0){ fprintf(stderr,"utxo_lsm_reload FAILED (%ld)\n",rel); return 1; }
    long live0 = utxo_lsm_count(g_lst);
    LSM_BARRIER();
    fprintf(stderr,"[backfill] reload live=%ld runs=%lu; window h%ld..%ld\n",
            live0, (unsigned long)g_lst->manifest_n, start, start+count-1);

    long added=0, put_dup=0, spent=0, del_absent=0, missing=0, del_err=0, bad=0;
    for(long h=start; h<start+count; h++){
        long meta[3];
        if(store_get_at(store_buf, h, meta)!=1){ fprintf(stderr,"h%ld store_get_at FAIL\n",h); bad=1; break; }
        long ffd = store_get_file_fd(store_buf, (unsigned)meta[2]);
        if(ffd<0){ fprintf(stderr,"h%ld store_get_file_fd FAIL\n",h); bad=1; break; }
        long pos = meta[0], size = meta[1];
        static unsigned char blk[1<<22];
        if(lseek(ffd, pos+8, SEEK_SET)<0){ perror("lseek"); bad=1; break; }
        long got=0;
        while(got<size){
            long r = read(ffd, blk+got, size-got);
            if(r<=0){ fprintf(stderr,"h%ld short read\n",h); bad=1; break; }
            got+=r;
        }
        if(bad) break;
        /* walk + apply */
        unsigned long long nt; int vv=rd_varint(blk+80,(unsigned long)size-80,&nt);
        if(vv<0){ fprintf(stderr,"h%ld bad txcount\n",h); bad=1; break; }
        unsigned long toff=80+vv;
        for(unsigned long ti=0; ti<nt; ti++){
            unsigned long nin,nout,ws=0;
            long tl=tx_walk(blk+toff,(unsigned long)size-toff,&nin,&nout,&ws);
            if(getenv("BMC_BACKFILL_TRACE"))
                fprintf(stderr,"TRACE h%ld tx%lu toff=%lu tl=%ld nin=%lu nout=%lu ws=%lu\n",
                        h,ti,toff,tl,nin,nout,ws);
            if(tl<0){ fprintf(stderr,"h%ld tx%lu MALFORMED\n",h,ti); bad=1; break; }
            unsigned char* txo=blk+toff;
            unsigned char txid[32]; txid_of(txo,tl,ws,txid);
            if(ti==0){
                for(unsigned long v=0;v<nout;v++){ unsigned long long val; const u8*sp; unsigned long spl;
                    if(tx_out(txo,tl,v,&val,&sp,&spl)==0 && spl>0){
                        long pr=lsm_put(txid,v,val,(uint64_t)h,1,sp,spl);
                        if(pr==1) added++; else if(pr==0) put_dup++; else { fprintf(stderr,"h%ld PUT ERR r=%ld txid=",h,(long)pr); for(int q=0;q<32;q++) fprintf(stderr,"%02x",txid[q]); fprintf(stderr," idx=%lu val=%llu\n",v,val); bad=1; break; }
                    } }
            } else {
                for(unsigned long v=0;v<nin;v++){
                    unsigned char ph[32]; unsigned long pidx;
                    if(tx_in2(txo,tl,v,ph,&pidx)!=0) continue;
                    unsigned long long pval; unsigned long pheight=0,pcb=0; const u8*psp; unsigned long pspl;
                    long gr=utxo_lsm_get(g_lst,g_utxo,ph,pidx,&pval,&pheight,&pcb,&psp,&pspl);
                    if(gr==0){ missing++;
                        if(missing<=3 || BMC_TRACE_ON())
                            fprintf(stderr,"h%ld tx%lu MISSING-PREVOUT idx=%lu ph=",h,ti,pidx);
                        if(missing<=3 || BMC_TRACE_ON())
                            { for(int q=0;q<32;q++) fprintf(stderr,"%02x",ph[q]); fprintf(stderr,"\n"); }
                        continue; }
                    /* 1=tombstoned now, 0=absent (already spent earlier -- the
                     * 1189 dels the post-fix ibd_lsm run DID record), -1=err */
                    long dr=utxo_lsm_del(g_lst,g_utxo,ph,pidx);
                    if(dr==1) spent++;
                    else if(dr==0) del_absent++;
                    else del_err++;
                }
                for(unsigned long v=0;v<nout;v++){ unsigned long long val; const u8*sp; unsigned long spl;
                    if(tx_out(txo,tl,v,&val,&sp,&spl)==0 && spl>0){
                        long pr=lsm_put(txid,v,val,(uint64_t)h,0,sp,spl);
                        if(pr==1) added++; else if(pr==0) put_dup++;
                        else { fprintf(stderr,"h%ld PUT ERR r=%ld txid=",h,(long)pr); for(int q=0;q<32;q++) fprintf(stderr,"%02x",txid[q]); fprintf(stderr," idx=%lu val=%llu\n",v,val); bad=1; break; }
                    } }
            }
            toff += (unsigned long)tl;
        }
        if(bad) break;
        if(utxo_lsm_flush(g_lst,g_utxo)==1) g_flushes++;
        fprintf(stderr,"[backfill] h%ld applied (added=%ld spent=%ld)\n",h,added,spent);
    }
    long liveF = utxo_lsm_count(g_lst);
    utxo_lsm_close(g_lst);
    fprintf(stderr,"[backfill] DONE added=%ld dup=%ld spent=%ld del_absent=%ld missing=%ld del_err=%ld flushes=%ld full_retries=%ld bad=%ld live=%ld\n",
            added,put_dup,spent,del_absent,missing,del_err,g_flushes,g_full_retries,bad,liveF);

    /* persistence check: reload and compare */
    long rel2 = utxo_lsm_reload(g_lst, g_utxo);
    LSM_BARRIER();
    long liveP = rel2<0 ? -1 : utxo_lsm_count(g_lst);
    utxo_lsm_close(g_lst);
    fprintf(stderr,"[PERSISTENCE] reload_after_close live=%ld vs final %ld %s\n",
            liveP, liveF, (liveP==liveF && liveP>=0)? "MATCH":"MISMATCH");
    return (bad==0 && liveP==liveF)? 0 : 1;
}
