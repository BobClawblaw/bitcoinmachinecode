/* ibd_lsm.c -- RESUMABLE, LSM-UTXO-backed full-block downloader (native AArch64).
 *
 * This is the archive/LSM-tip-aware successor to ibd.c. The critical difference:
 * its UTXO is the PERSISTENT LSM store (bitcoin_utxo_lsm.asm), so it can RESUME
 * mid-chain without MISSING-PREVOUT storms. Instead of rebuilding the UTXO from
 * scratch in memory each run (which misses every prevout from already-downloaded
 * earlier blocks), it:
 *
 *   1. utxo_lsm_reload(lst,u)  -- reconstructs the FULL persisted UTXO at the
 *                                 archive tip from WAL+manifest+runs.
 *   2. reads the block-archive tip (bitcoin_store) and RESUMES the download at
 *      tip+1 -- it never re-requests or re-applies already-stored blocks.
 *   3. for each new downloaded + cons_verify'd + store_append'd block, applies
 *      every spend/output to the LSM via utxo_lsm_put / utxo_lsm_del, with an
 *      explicit periodic utxo_lsm_flush (and the caller-side .full flush+retry
 *      contract) so state keeps persisting as run files and stays bounded.
 *
 * A ZERO MISSING-PREVOUT count on the resumed tail is the direct proof that
 * utxo_lsm_reload restored the pre-resume UTXO (the thing the in-memory ibd.c
 * UTXO fundamentally cannot do across runs).
 *
 * Real-time progress is logged in the x86 node_log leveled format to
 * <datadir>/logs/bitcoind.production.log (SERVE/HSHK/BLOCK/CONS/STORE/INFO +
 * ISO timestamp), exactly like ibd.c.
 *
 * Usage: ibd_lsm <peer> <count> [datadir] [slots_log2] [flush_every] [start]
 *   <count>      : number of NEW blocks to download past the archive tip
 *   [datadir]    : default "data"
 *   [slots_log2] : LSM memtable slots log2 (default 20 -> 1<<20 slots)
 *   [flush_every]: force a utxo_lsm_flush every N blocks (default 100)
 *   [start]      : FORCE start height (default = archive tip+1, i.e. true resume)
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* ---- ported asm externs ---- */
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* payload, unsigned plen);
extern int  p2p_read (int fd, char cmd_out[12], void* payload, unsigned cap, unsigned* plen_out);
extern void fd_close(int fd);
extern int  cons_verify(const void* block, unsigned long len, void* txid_scratch, unsigned long cap);
extern void block_hash(void* out, const void* hdr);
extern void sha256d(void* out32, const void* in, unsigned long len);
extern int  store_init(void* st);
extern int  store_reload(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, unsigned long long len);

extern unsigned long utxo_struct_size(unsigned long slots);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_lsm_init(void* lst);
extern long   utxo_lsm_put(void* lst, void* u, const uint8_t txid[32], unsigned long index,
                           unsigned long long value, unsigned long height, unsigned long cb,
                           const uint8_t* script, unsigned long slen);
extern long   utxo_lsm_del(void* lst, void* u, const uint8_t txid[32], unsigned long index);
extern long   utxo_lsm_get(void* lst, void* u, const uint8_t txid[32], unsigned long index,
                           unsigned long long* value, unsigned long* height, unsigned long* cb,
                           const uint8_t** script, unsigned long* slen);
extern long   utxo_lsm_count(void* lst);
extern long   utxo_lsm_flush(void* lst, void* u);
extern long   utxo_lsm_reload(void* lst, void* u);
extern void   utxo_lsm_close(void* lst);

extern int sv_verify_script(const unsigned char* scriptSig, unsigned long ssl,
                            const unsigned char* scriptPubKey, unsigned long spl,
                            uint64_t flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);
#define SV_P2SH        (1ULL<<0)
#define SV_SIGPUSHONLY (1ULL<<5)

extern long node_log_open(const char* path);
extern void node_log_str(long fd, int kind, const char* s, long len);
static long g_log=0;
static void logline(long lfd, int kind, const char* msg, int n){
    if(!lfd) return;
    struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts);
    struct tm tmv; gmtime_r(&ts.tv_sec,&tmv);
    char b[640];
    int p=snprintf(b,sizeof b,"%04d-%02d-%02d %02d:%02d:%02d.%03ld ",
        tmv.tm_year+1900,tmv.tm_mon+1,tmv.tm_mday,tmv.tm_hour,tmv.tm_min,tmv.tm_sec,ts.tv_nsec/1000000);
    if(p<0)p=0; if(p>(int)sizeof b)p=(int)sizeof b;
    int m=n; if(m>(int)sizeof b - p - 1) m=(int)sizeof b - p - 1;
    memcpy(b+p, msg, (size_t)m);
    node_log_str(lfd, kind, b, (long)(p+m));
}
#define LLOG(kind, fmt, ...) do{ \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    if(g_log){ char _b[512]; int _n=snprintf(_b,sizeof _b,fmt, ##__VA_ARGS__); \
               if(_n<0)_n=0; if(_n>(int)sizeof _b)_n=(int)sizeof _b; \
               while(_n>0 && (_b[_n-1]=='\n'||_b[_n-1]=='\r')) _n--; \
               logline(g_log,(kind),_b,_n); } \
}while(0)
#define TLINE(kind,s) do{ logline(g_log,(kind),(s),(int)strlen(s)); }while(0)

/* ---- LSM state (mirror bitcoin_utxo_lsm.asm struct, 168 bytes) + helpers ---- */
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
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
static void* g_utxo=0;
static struct lsm_state* g_lst=0;   /* heap allocated (see main) */
static long g_flushes=0, g_full_retries=0;

/* ---- file-scope scalars: (see comment block in main) ---- */
static long   G_maxblk=0, G_total=0, G_flush_every=100, G_force_start=-1;
static int    G_slots_log2=20;
static unsigned long G_slots;
static uint64_t G_blob_cap, G_fill, G_op, G_tomb_cap, G_scratch_cap, G_manifest_cap;

/* LSM_BARRIER : mac_lsm_reload_impl (the ported bitcoin_utxo_lsm.S reload path,
 * including its recount step) violates AAPCS by leaving the DIRECT caller's
 * callee-saved registers (observed: x19, x27, x28 specifically, restored to
 * leftover scratch values) corrupted on return. This is an unresolved defect in
 * the already-ported asm that we are forbidden to edit. The line below is a
 * compiler barrier that declares EVERY callee-saved register + memory clobbered,
 * so GCC discards whatever it cached in them across the call and re-derives the
 * value (globals base, loop bounds, LSM pointers) fresh from memory immediately
 * AFTER the reload returns. Nothing that must survive reload may live in a
 * callee-saved register, and every read afterwards comes from BSS/stack memory
 * the asm never writes. */
#define LSM_BARRIER() __asm__ __volatile__("" ::: "memory", "x19","x20","x21","x22","x23","x24","x25","x26","x27","x28")

/* utxo_lsm_put is 1=ok, 2=table/blob .full, 0=dup, -1=err. On 2, the caller
 * MUST flush (frees the memtable into a run) then retry, else the record is
 * silently dropped. */
static long lsm_put(const uint8_t* txid, unsigned long index, unsigned long long value,
                    unsigned long height, unsigned long cb, const uint8_t* script, unsigned long slen){
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
static void* mmap_file(const char* path, uint64_t size){
    int fd = open(path, O_RDWR|O_CREAT, 0644);
    if (fd<0){ perror("open"); return 0; }
    if (ftruncate(fd,(off_t)size)!=0){ perror("ftruncate"); close(fd); return 0; }
    void* p = mmap(0,size,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
    close(fd);
    if (p==MAP_FAILED){ perror("mmap"); return 0; }
    return p;
}

/* ---- networking (identical to ibd.c) ---- */
static const char* PEERS[] = {
    "66.181.35.130","203.56.149.66","82.181.245.129","184.174.97.161","87.239.202.205",
    "20.141.185.87","172.232.181.77","138.68.227.57","68.114.136.133","172.234.197.86",
    "90.3.174.204","76.186.126.222","155.4.245.33","209.227.228.193","62.245.76.144",
    "66.176.58.35","139.162.170.49","183.179.14.44","86.85.157.170","36.225.141.113",
    "24.109.211.59","172.104.247.153","2.24.129.243","217.87.210.45","81.32.0.117",
    "139.162.128.22","52.56.64.87","82.75.3.9","79.237.11.102","31.47.167.78",
    "34.91.86.7","75.80.153.97","188.214.129.139","64.121.66.200","206.109.207.21",
    "84.85.102.113","65.33.241.127","89.164.38.221","31.16.100.176","79.239.192.176",
    "191.254.16.77","176.123.4.240","85.230.179.6","172.232.181.65","34.48.121.218",
    "62.210.124.104","87.92.90.235","13.36.183.251",
    0 };
#define NPEERS 48
static int g_npeer=0;
static int connect_peer(const char* host,unsigned char* rbuf){
    int tries=0;
    for(int attempt=0;; attempt++){
        const char* ph = (attempt==0 && host)? host : PEERS[g_npeer % NPEERS];
        unsigned ip=0;
        struct in_addr a; if(inet_pton(AF_INET,ph,&a)) ip=a.s_addr;
        if(!ip){ struct addrinfo h,*res=NULL; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
                 if(getaddrinfo(ph,NULL,&h,&res)==0&&res){ ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr; freeaddrinfo(res);} }
        if(!ip){ g_npeer++; } else {
            int fd=tcp_connect_ip(ip,(unsigned short)htons(8333));
            if(fd>=0){
                unsigned char v[102]; int o=0;
                v[o]=0x7f;o+=1;v[o]=0x11;o+=1;v[o]=0x01;o+=1;v[o]=0x00;o+=1; /* 70016 LE */
                v[o]=1;o+=8;
                unsigned long long nt=(unsigned long long)time(NULL);
                for(int i=0;i<8;i++){v[o+i]=nt&0xff;nt>>=8;} o+=8; o+=8; o+=16; o+=2; o+=8; o+=16; o+=2;
                unsigned long long nn=0x1111111111111111ULL;
                for(int i=0;i<8;i++){v[o+i]=nn&0xff;nn>>=8;} o+=8;
                const char* ua="/Satoshi:0.18.0/"; v[o]=strlen(ua); o++; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
                v[o]=0;o+=4; v[o]=1;o+=1;
                if(p2p_write(fd,"version",7,v,o)<=0){ fd_close(fd); g_npeer++; continue; }
                char cmd[12]; unsigned plen=0; int sv=0,gv=0;
                for(int i=0;i<20&&!(sv&&gv);i++){
                    int r=p2p_read(fd,cmd,rbuf,8*1024*1024,&plen); cmd[11]=0;
                    if(r<=0)break;
                    if(strncmp(cmd,"version",7)==0&&!sv){ p2p_write(fd,"verack",6,rbuf,0); sv=1; }
                    else if(strncmp(cmd,"verack",6)==0) gv=1;
                }
                if(sv&&gv){ fprintf(stderr,"  [peer %s fd=%d]\n",ph,fd); return fd; }
                fd_close(fd);
            }
            g_npeer++;
        }
        if(tries++>NPEERS*3) return -1;
        usleep(100000);
    }
}
static int req_window(int fd, const unsigned char* hdr, long w, long nw){
    unsigned char* gd=malloc(1+(size_t)nw*36);
    gd[0]=(unsigned char)nw;
    for(long k=0;k<nw;k++){ const unsigned char* hash=hdr+(w+k)*112+80;
        gd[1+k*36]=0x02;gd[2+k*36]=0x00;gd[3+k*36]=0x00;gd[4+k*36]=0x40; /* 0x40000002 LE */
        memcpy(gd+5+k*36,hash,32); }
    long wr=p2p_write(fd,"getdata",7,gd,1+(size_t)nw*36);
    free(gd);
    return wr>0 ? 0 : -1;
}

/* ---- tx walking (identical to ibd.c) ---- */
static int rd_varint(const unsigned char*p, unsigned long n, unsigned long long* out){
    if(n<1) return -1;
    unsigned char b=p[0];
    if(b<0xfd){ *out=b; return 1; }
    else if(b==0xfd){ if(n<3)return -1; *out=p[1]|(p[2]<<8); return 3; }
    else if(b==0xfe){ if(n<5)return -1; *out=(unsigned long long)p[1]|((unsigned long long)p[2]<<8)|
        ((unsigned long long)p[3]<<16)|((unsigned long long)p[4]<<24); return 5; }
    else { if(n<9)return -1; unsigned long long v=0; for(int i=7;i>=0;i--) v=(v<<8)|p[1+i]; *out=v; return 9; }
}
static long tx_walk(const unsigned char*tx, unsigned long n, unsigned long* nin, unsigned long* nout){
    if(n<4+1+1) return -1;
    unsigned long o=4;
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
    if(o+4>n) return -1; o+=4;
    *nin=nin_; *nout=nout_;
    return (long)o;
}
static int tx_in(const unsigned char*tx, unsigned long n, unsigned long idx,
                 uint8_t* prevhash, unsigned long* previndex, uint8_t* scriptsig, unsigned long* ssl){
    unsigned long o=4;
    unsigned long long ni; int v=rd_varint(tx+o,n-o,&ni); if(v<0)return -1; o+=v;
    if(idx>=ni) return -1;
    unsigned long i;
    for(i=0;i<ni;i++){
        if(o+36+4>n) return -1;
        if(i==idx){
            memcpy(prevhash,tx+o,32);
            *previndex=tx[o+32]|(tx[o+33]<<8)|(tx[o+34]<<16)|(tx[o+35]<<24);
            o+=36;
            unsigned long long sl; v=rd_varint(tx+o,n-o,&sl); if(v<0)return -1; o+=v;
            if(o+sl+4>n) return -1;
            if(sl>0 && scriptsig) memcpy(scriptsig,tx+o,sl);
            if(ssl)*ssl=(unsigned long)sl;
            return 0;
        }
        o+=36;
        unsigned long long sl; v=rd_varint(tx+o,n-o,&sl); if(v<0)return -1; o+=v;
        if(o+sl+4>n) return -1; o+=sl+4;
    }
    return -1;
}
static int tx_out(const unsigned char*tx, unsigned long n, unsigned long idx,
                  unsigned long long* value, const uint8_t** script, unsigned long* sl){
    unsigned long o=4;
    unsigned long long ni; int v=rd_varint(tx+o,n-o,&ni); if(v<0)return -1; o+=v;
    unsigned long long no;
    { unsigned long i; for(i=0;i<ni;i++){ if(o+36+4>n)return -1; o+=36; unsigned long long sl_; v=rd_varint(tx+o,n-o,&sl_); if(v<0)return -1; o+=v; if(o+sl_+4>n)return -1; o+=sl_+4; } }
    v=rd_varint(tx+o,n-o,&no); if(v<0)return -1; o+=v;
    unsigned long j;
    for(j=0;j<no;j++){
        if(o+8>n) return -1;
        if(j==idx){
            *value=(unsigned long long)tx[o]|((unsigned long long)tx[o+1]<<8)|((unsigned long long)tx[o+2]<<16)|((unsigned long long)tx[o+3]<<24)
                   |((unsigned long long)tx[o+4]<<32)|((unsigned long long)tx[o+5]<<40)|((unsigned long long)tx[o+6]<<48)|((unsigned long long)tx[o+7]<<56);
            o+=8;
            unsigned long long sl_; v=rd_varint(tx+o,n-o,&sl_); if(v<0)return -1; o+=v;
            if(o+sl_>n)return -1;
            *script=tx+o; *sl=(unsigned long)sl_; return 0;
        }
        o+=8;
        unsigned long long sl_; v=rd_varint(tx+o,n-o,&sl_); if(v<0)return -1; o+=v;
        if(o+sl_>n)return -1; o+=sl_;
    }
    return -1;
}

int main(int argc, char** argv){
    if(argc<3){ fprintf(stderr,"usage: %s <peer> <count> [datadir] [slots_log2] [flush_every] [start]\n",argv[0]); return 2; }
    G_maxblk=atol(argv[2]);
    const char* dd= argc>3?argv[3]:"data";
    G_slots_log2 = argc>4?atoi(argv[4]):20;
    G_flush_every = argc>5?atol(argv[5]):100;
    G_force_start = argc>6?atol(argv[6]):-1;
    mkdir(dd,0755); chdir(dd);
    mkdir("logs",0755);
    g_log = node_log_open("logs/bitcoind.production.log");
    TLINE(7, "node start (ibd_lsm resumable LSM download worker)");
    uint64_t flags = SV_SIGPUSHONLY;

    /* ---- verified header chain ---- */
    FILE*hf=fopen("headers.dat","rb");
    if(!hf){ fprintf(stderr,"FAIL open headers.dat\n"); return 1; }
    fseek(hf,0,SEEK_END); long fsz=ftell(hf); fseek(hf,0,SEEK_SET);
    G_total=fsz/112;
    if(G_maxblk<0)G_maxblk=0;
    unsigned char* hdr = malloc((size_t)G_total*112);
    if(fread(hdr,112,(size_t)G_total,hf)!=(size_t)G_total){ fprintf(stderr,"read headers err\n"); return 1; }
    fclose(hf);

    /* ---- block archive: open (tip READ is deferred to after LSM reload,
     * since reload must not see any pre-reload caller locals) ---- */
    static unsigned char store_buf[4096];
    if(store_init(store_buf)!=1){ fprintf(stderr,"store_init failed\n"); return 1; }
    store_reload(store_buf);

    /* ---- LSM: mmap memtable + blob, init, RELOAD persisted UTXO at archive tip ---- */
    G_slots = 1UL<<G_slots_log2;
    G_blob_cap = 1UL<<30;
    long ustruct = utxo_struct_size(G_slots);
    g_utxo = mmap_file("utxo_lsm_table.map", (uint64_t)ustruct);
    void* blob = mmap_file("utxo_lsm_blob.map", G_blob_cap);
    if(!g_utxo || !blob){ fprintf(stderr,"mmap alloc failed\n"); return 1; }
    utxo_init(g_utxo, G_slots, blob, G_blob_cap);

    G_fill = (uint64_t)G_slots*3/4;
    G_op    = (uint64_t)G_slots*2;
    G_tomb_cap         = G_op;
    uint64_t desc_cap         = (uint64_t)G_slots*3;   /* >= fill_threshold+tomb_cap */
    G_scratch_cap       = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    G_manifest_cap       = 8192;
    void* tomb_buf = malloc(G_tomb_cap*36);
    void* manifest_buf = malloc(G_manifest_cap*16);
    void* scratch_buf = malloc(G_scratch_cap);
    if(!tomb_buf||!manifest_buf||!scratch_buf){ fprintf(stderr,"LSM buffer malloc failed\n"); return 1; }
    g_lst = calloc(1, sizeof(struct lsm_state));
    if(!g_lst){ fprintf(stderr,"lst alloc failed\n"); return 1; }
    memset(g_lst,0,sizeof *g_lst);
    g_lst->op_threshold=G_op; g_lst->fill_threshold=G_fill;
    g_lst->tomb_buf=tomb_buf; g_lst->tomb_cap=G_tomb_cap;
    g_lst->manifest_buf=manifest_buf; g_lst->manifest_cap=G_manifest_cap;
    g_lst->scratch_buf=scratch_buf; g_lst->scratch_cap=G_scratch_cap;
    long rel = utxo_lsm_reload(g_lst, g_utxo);
    /* COMPILER BARRIER: stop gcc from hoisting reads of store_buf (static) and
     * the G_* globals ABOVE the reload call (it believes the asm can't alias
     * them). reload genuinely corrupts the caller frame on this port, so every
     * value we touch afterward must come fresh from memory. */
    LSM_BARRIER();
    if(rel<0){ fprintf(stderr,"utxo_lsm_reload FAILED (%ld)\n",rel); return 1; }
    long live0 = utxo_lsm_count(g_lst);
    LSM_BARRIER();

    /* ---- NOW read the archive tip (fresh from the static store, AFTER reload)
     * and derive the resume window. These become the loop bounds. ---- */
    long tip = *(int*)(store_buf+24);
    if(tip < 0){ fprintf(stderr,"empty archive -- can't resume (need build_utxo/ibd to seed first)\n"); return 1; }
    long start = G_force_start>=0 ? G_force_start : tip+1;
    if(start < tip+1){ fprintf(stderr,"WARNING: requested start=%ld below tip+1; resuming from tip+1=%ld\n",start,tip+1); start=tip+1; }
    if(start+G_maxblk>G_total) G_maxblk=G_total-start;
    if(G_maxblk<=0){ fprintf(stderr,"nothing to download (archive tip %ld, headers %ld)\n",tip,G_total); return 0; }
    LLOG(0, "LSM reload: replayed=%ld live_at_archive_tip(h%ld)=%ld memtable=2^%d runs=%lu\n",
            rel, tip, live0, G_slots_log2, (unsigned long)g_lst->manifest_n);
    fprintf(stderr,"[ibd_lsm] archive tip=%ld -> resume h=%ld..%ld count=%ld  LSM live0=%ld (expected 4783)\n",
            tip, start, start+G_maxblk-1, G_maxblk, live0);

    /* ---- connect + handshake ---- */
    unsigned char* rbuf=malloc(8*1024*1024);
    int fd=connect_peer(argv[1], rbuf);
    if(fd<0){ fprintf(stderr,"FAIL connect all peers\n"); return 1; }
    LLOG(1, "PASS connect+handshake; LSM-RESUME h=%ld..%ld  (archive tip %ld) flags=%llx\n",
            start, start+G_maxblk-1, tip, (unsigned long long)flags);

    unsigned char* work = malloc(8u<<20);
    unsigned char* scr = malloc(1<<22);
    long valid=0, bad_gate=0, bad_sig=0, missing=0, spent=0, added=0, ntx=0, nsig=0;
    long put_dup=0, del_err=0;
    const long BATCH=128;
    unsigned char** gblk=malloc((size_t)BATCH*sizeof(void*));
    long* glen=malloc((size_t)BATCH*sizeof(long));
    int* ghave=malloc((size_t)BATCH*sizeof(int));
    char cmd[12]; unsigned plen=0;

    long lastflush=start;
    for(long w=start; w<start+G_maxblk; w+=BATCH){
        long wend=w+BATCH; if(wend>start+G_maxblk) wend=start+G_maxblk;
        long nw=wend-w;
        for(long k=0;k<nw;k++){ ghave[k]=0; gblk[k]=0; glen[k]=0; }
        if(req_window(fd,hdr,w,nw)<0){
            fprintf(stderr,"w%ld req fail; reconnect\n",w);
            fd_close(fd); fd=connect_peer(0,rbuf);
            if(fd<0){ fprintf(stderr,"w%ld NO peer\n",w); goto done; }
            if(req_window(fd,hdr,w,nw)<0){ fprintf(stderr,"w%ld re-req fail\n",w); goto done; }
        }
        while(1){
            int all=1; for(long k=0;k<nw;k++) if(!ghave[k]){all=0;break;}
            if(all) break;
            int r=p2p_read(fd,cmd,rbuf,8*1024*1024,&plen);
            if(r<=0){
                fprintf(stderr,"  w%ld peer EOF r=%d; reconnect+re-request\n",w,r);
                fd_close(fd); fd=connect_peer(0,rbuf);
                if(fd<0){ fprintf(stderr,"w%ld NO peer\n",w); goto done; }
                if(req_window(fd,hdr,w,nw)<0) goto done;
                continue;
            }
            cmd[11]=0;
            if(strncmp(cmd,"block",5)==0){
                unsigned char hh[32]; block_hash(hh,rbuf);
                long k=-1;
                for(long q=0;q<nw;q++) if(!ghave[q] && !memcmp(hh,hdr+(w+q)*112+80,32)){ k=q; break; }
                if(k<0) continue;
                gblk[k]=malloc(plen?plen:1); memcpy(gblk[k],rbuf,plen); glen[k]=plen; ghave[k]=1;
            } else if(strncmp(cmd,"ping",4)==0){
                p2p_write(fd,"pong",4,rbuf,plen);
            }
        }
        for(long k=0;k<nw;k++){
            long h=w+k;
            unsigned char* blk=gblk[k];
            if(!blk){ fprintf(stderr,"h%ld not collected\n",h); goto done; }
            int blklen=(int)glen[k];
            if(cons_verify(blk, blklen, scr, 1<<22)!=1){ fprintf(stderr,"h%ld BAD cons_verify\n",h); bad_gate++; free(blk); continue; }
            { unsigned char bh[32]; block_hash(bh, blk);
              if(store_append(store_buf,bh,blk,(unsigned long long)blklen)<0){ fprintf(stderr,"h%ld STORE_APPEND FAIL\n",h); bad_gate++; free(blk); continue; } }
            unsigned char* txc=blk+80;
            unsigned long long nt; int vv=rd_varint(txc,(unsigned long)(blklen-80),&nt);
            if(vv<0){ fprintf(stderr,"h%ld bad txcount\n",h); bad_gate++; free(blk); continue; }
            unsigned long toff=80+vv;
            int bad=0;
            for(unsigned long ti=0; ti<nt; ti++){
                unsigned long nin,nout;
                long tl=tx_walk(blk+toff,(unsigned long)blklen-toff,&nin,&nout);
                if(tl<0){ fprintf(stderr,"h%ld tx%lu MALFORMED\n",h,ti); bad=1; break; }
                unsigned char* txo=blk+toff;
                ntx++;
                unsigned long v;
                if(ti==0){
                    for(v=0;v<nout;v++){ unsigned long long val; const uint8_t*sp; unsigned long spl;
                        if(tx_out(txo,tl,v,&val,&sp,&spl)==0 && spl>0){
                            uint8_t txid[32]; sha256d(txid,txo,tl);
                            long pr=lsm_put(txid,v,val,(uint64_t)h,1,sp,spl);
                            if(pr==1) added++; else if(pr==0) put_dup++; else { fprintf(stderr,"h%ld PUT ERR\n",h); bad=1; break; }
                        } }
                } else {
                    uint8_t ph[32]; unsigned long pidx; unsigned char sigb[520]; unsigned long ssl;
                    for(v=0;v<nin;v++){
                        if(tx_in(txo,tl,v,ph,&pidx,sigb,&ssl)!=0) continue;
                        unsigned long long pval; unsigned long pheight=0,pcb=0; const uint8_t*psp; unsigned long pspl;
                        long gr=utxo_lsm_get(g_lst,g_utxo,ph,pidx,&pval,&pheight,&pcb,&psp,&pspl);
                        if(gr==0){
                            LLOG(6, "h%ld tx%lu in%lu MISSING-PREVOUT idx=%lu\n",h,ti,v,pidx);
                            missing++; bad_sig++; continue;
                        }
                        if(gr<0){ fprintf(stderr,"h%ld tx%lu LSM GET ERR\n",h,ti); bad=1; break; }
                        int rr=sv_verify_script(sigb,ssl,psp,pspl,flags,v,txo,tl,work,8u<<20);
                        if(rr!=0){ LLOG(6, "h%ld tx%lu in%lu SIGFAIL err=%d\n",h,ti,v,rr); bad_sig++; }
                        else { nsig++; }
                        long dr=utxo_lsm_del(g_lst,g_utxo,ph,pidx);
                        if(dr<0){ del_err++; LLOG(6,"h%ld tx%lu del err\n",h,ti); }
                        else spent++;
                    }
                    for(v=0;v<nout;v++){ unsigned long long val; const uint8_t*sp; unsigned long spl;
                        if(tx_out(txo,tl,v,&val,&sp,&spl)==0 && spl>0){
                            uint8_t txid[32]; sha256d(txid,txo,tl);
                            long pr=lsm_put(txid,v,val,(uint64_t)h,0,sp,spl);
                            if(pr==1) added++; else if(pr==0) put_dup++; else { fprintf(stderr,"h%ld PUT ERR\n",h); bad=1; break; }
                        } }
                }
                toff += tl;
            }
            if(bad){ bad_gate++; free(blk); continue; }
            if((h-start+1)%G_flush_every==0 || h==start+G_maxblk-1){
                long fr=utxo_lsm_flush(g_lst,g_utxo);
                if(fr<0){ LLOG(6,"h%ld FLUSH ERR\n",h); }
                else { g_flushes++; }
                LLOG(5, "h%ld FLUSH ok runs=%lu live=%ld\n", h,
                        (unsigned long)g_lst->manifest_n, (long)utxo_lsm_count(g_lst));
            }
            valid++;
            if(((h-start)%50)==0)
                LLOG(3, "h%ld txs=%llu utxo=%ld spent=%ld sigs=%ld runs=%lu\n",
                        h, (unsigned long long)nt, (long)utxo_lsm_count(g_lst), spent, nsig,
                        (unsigned long)g_lst->manifest_n);
            free(blk); gblk[k]=0;
        }
        (void)lastflush;
    }
done:
    { long fr=utxo_lsm_flush(g_lst,g_utxo); if(fr==1) g_flushes++; }
    long liveF = utxo_lsm_count(g_lst);
    LLOG(5, "DONE: valid=%ld bad_gate=%ld MISSING_PREVOUT=%ld bad_sig=%ld\n", valid, bad_gate, missing, bad_sig);
    LLOG(5, "      txs=%ld spent=%ld sigs=%ld added=%ld put_dup=%ld del_err=%ld\n",
        ntx, spent, nsig, added, put_dup, del_err);
    LLOG(5, "      LSM final live=%ld runs=%lu flushes=%ld full_retries=%ld\n",
        liveF, (unsigned long)g_lst->manifest_n, g_flushes, g_full_retries);
    fprintf(stderr,"\n[RESUME] archive tip=%ld -> downloaded h=%ld..%ld  MISSING_PREVOUT=%ld\n",
            tip, start, start+G_maxblk-1, missing);

    /* in-process persistence check: close, reload_ro, confirm live count survives */
    utxo_lsm_close(g_lst);
    /* re-open a FRESH zeroed lst + fresh memtable to prove the persisted state
     * (WAL+runs+manifest) reconstructs to the same live set. */
    void* u2 = malloc(utxo_struct_size(G_slots));
    void* blob2 = malloc(G_blob_cap);
    utxo_init(u2, G_slots, blob2, G_blob_cap);
    struct lsm_state* l2 = calloc(1,sizeof(struct lsm_state));
    l2->op_threshold=G_op; l2->fill_threshold=G_fill;
    l2->tomb_buf=calloc(1,G_tomb_cap*36); l2->tomb_cap=G_tomb_cap;
    l2->manifest_buf=calloc(1,G_manifest_cap*16); l2->manifest_cap=G_manifest_cap;
    l2->scratch_buf=malloc(G_scratch_cap); l2->scratch_cap=G_scratch_cap;
    long rel2 = utxo_lsm_reload(l2, u2);
    LSM_BARRIER();
    long liveP = rel2<0 ? -1 : utxo_lsm_count(l2);
    utxo_lsm_close(l2);
    LLOG(5, "PERSISTENCE CHECK: reload_after_close live=%ld (final live was %ld) %s\n",
        liveP, liveF, (liveP==liveF && liveP>=0)? "MATCH" : "MISMATCH");
    fprintf(stderr,"[PERSISTENCE] reload_after_close live=%ld vs downloader final %ld\n", liveP, liveF);

    fd_close(fd);
    TLINE(0, (missing==0 && bad_gate==0 && bad_sig==0)
        ? "LSM-RESUME SIGNED OFF NATIVELY (miss=0 gate=0 sig=0)"
        : "LSM-RESUME INCOMPLETE (see failures above)");
    return (missing==0 && bad_gate==0 && bad_sig==0 && valid==G_maxblk)? 0 : 1;
}
