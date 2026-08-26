/* ibd.c -- Integrated Blockchain Download + trusted verification (native AArch64).
 *
 * Walks the VERIFIED mainnet header chain from data/headers.dat (963,935 headers,
 * 112 B each = 80 B header + 32 B hash), downloading a contiguous
 * [start,start+count) window in BATCHES of blocks per getdata (MSG_WITNESS_BLOCK)
 * from a live peer, then for each block in height order:
 *   1. block gate: cons_verify (PoW + merkle root + coinbase structure)
 *   2. per-transaction script verification: for each non-coinbase input, look up
 *      the prevout in the in-memory UTXO set and run sv_verify_script (the C
 *      VerifyScript wrapper over the ported script_eval VM + ECDSA checksig)
 *   3. UTXO apply: spend spent inputs (del), add outputs (put)
 *   4. periodic checkpoint via the persistent bitcoin_utxo_store (WAL + ckpt);
 *      P2SH (BIP16) enforcement auto-activates at height 173805.
 *
 * BASE-legacy era (pre-481824 segwit) is fully verifiable now; the same loop
 * carries witness-era blocks (requested with MSG_WITNESS_BLOCK) and segwit/taproot
 * verification is handled by sv_verify_script when the segwit path is wired.
 *
 * Usage: ibd <peer> <start_height> <count> [datadir] [p2sh]
 *
 * Links the complete verified AArch64 stack.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

/* ---- ported asm externs ---- */
extern int  tcp_connect_ip(unsigned ip_le, unsigned short port_be);
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* payload, unsigned plen);
extern int  p2p_read (int fd, char cmd_out[12], void* payload, unsigned cap, unsigned* plen_out);
extern void fd_close(int fd);
extern int  tx_parse(unsigned long long info[8], const void* tx, unsigned long txlen);
extern int  cons_verify(const void* block, unsigned long len, void* txid_scratch, unsigned long cap);
extern void block_hash(void* out, const void* hdr);
extern void sha256d(void* out32, const void* in, unsigned long len);

extern unsigned long utxo_struct_size(unsigned long slots);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_get(void* u, const uint8_t* txid, unsigned long index, unsigned long long* value,
                       unsigned long* height, unsigned long* cb, const uint8_t** script, unsigned long* slen);
extern long   utxo_put(void* u, const uint8_t* txid, unsigned long index, unsigned long long value,
                       unsigned long height, unsigned long cb, const uint8_t* script, unsigned long slen);
extern long   utxo_del(void* u, const uint8_t* txid, unsigned long index);
extern long   utxo_count(void* u);
extern long   utxo_store_init(void* st);
extern long   utxo_store_sync(void* st, void* u);

/* C VerifyScript over the ported VM+checksig (asm/bitcoin_scriptverify.c) */
extern int sv_verify_script(const unsigned char* scriptSig, unsigned long ssl,
                            const unsigned char* scriptPubKey, unsigned long spl,
                            uint64_t flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);
#define SV_P2SH        (1ULL<<0)
#define SV_SIGPUSHONLY (1ULL<<5)

/* all-asm leveled logger (node_log.S); kinds: 0 INFO 1 HSHK 2 HDRS 3 BLOCK
 * 4 CONS 5 STORE 6 ERROR 7 SERVE. Official log = <datadir>/logs/bitcoind.production.log */
extern long node_log_open(const char* path);
extern void node_log_event(long fd, int kind, unsigned a, unsigned b, unsigned c);
extern void node_log_str(long fd, int kind, const char* s, long len);
#define NL(fd,kind,s) do{ const char*_s=(s); node_log_str((fd),(kind),_s,(long)strlen(_s)); }while(0)
static long g_log=0;
#define LLOG(kind, fmt, ...) do{ \
    fprintf(stderr, fmt, ##__VA_ARGS__); \
    if(g_log){ char _b[512]; int _n=snprintf(_b,sizeof _b,fmt, ##__VA_ARGS__); \
               if(_n<0)_n=0; if(_n>(int)sizeof _b)_n=(int)sizeof _b; \
               while(_n>0 && (_b[_n-1]=='\n'||_b[_n-1]=='\r')) _n--; \
               node_log_str(g_log,(kind),_b,_n); } \
}while(0)

/* ---- helpers ---- */
static void p16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}
static void p32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void p64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static unsigned long long rd64le(const unsigned char*p){unsigned long long v=0;for(int i=7;i>=0;i--){v=(v<<8)|p[i];}return v;}

static int rd_varint(const unsigned char*p, unsigned long n, unsigned long long* out){
    if(n<1) return -1;
    unsigned char b=p[0];
    if(b<0xfd){ *out=b; return 1; }
    else if(b==0xfd){ if(n<3)return -1; *out=p[1]|(p[2]<<8); return 3; }
    else if(b==0xfe){ if(n<5)return -1; *out=(unsigned long long)p[1]|((unsigned long long)p[2]<<8)|
        ((unsigned long long)p[3]<<16)|((unsigned long long)p[4]<<24); return 5; }
    else { if(n<9)return -1; *out=rd64le(p+1); return 9; }
}

static unsigned fnv8(const uint8_t*p){ unsigned h=0x811c9dc5; for(int i=0;i<8;i++){h^=p[i]; h*=0x01000193;} return h; }
/* dump every probed slot + the blob record for key (txid,index) in U, mirroring utxo_get */
static void utxo_dump(const void* U, const uint8_t* txid, unsigned long index){
    unsigned long mask = *(const unsigned long*)((const uint8_t*)U+8);
    unsigned long slots = mask+1;
    const uint8_t* blob = *(const uint8_t* const*)((const uint8_t*)U+16);
    unsigned long home = (((unsigned long)fnv8(txid) ^ (unsigned long)index) & mask)*48 + 40;
    unsigned long end = 40 + slots*48;
    unsigned long off = home;
    int step=0;
    for(;;){
        const uint8_t* s = (const uint8_t*)U + off;
        unsigned st_idx; memcpy(&st_idx, s+40, 4);
        unsigned long long blob_off; memcpy(&blob_off, s, 8);
        int txid_m = memcmp(s+8, txid, 32)==0;
        if(st_idx==0xFFFFFFFFUL){ printf("  slot[%d] EMPTY at off=%lu (home=%lu)\n", step, off, home); break; }
        printf("  slot[%d] off=%lu stored_idx=%u txid_match=%d blob_off=%llu\n", step, off, st_idx, txid_m, blob_off);
        if(txid_m && st_idx==(unsigned)index){
            const uint8_t* rec = blob + blob_off;
            unsigned long long val, slen; memcpy(&val,rec,8); memcpy(&slen,rec+16,8);
            printf("  -> MATCH record: value=%llu slen=%llu script=", val, slen);
            unsigned long cap = slen>64?64:(unsigned long)slen; unsigned k; for(k=0;k<cap;k++) printf("%02x", rec[24+k]);
            if(slen>64) printf("...");
            printf("\n");
            break;
        }
        off += 48; if(off>=end) off=40;
        if(off==home){ printf("  slot: wrap-to-home, MISS\n"); break; }
        if(++step>100000){ printf("  slot: probe runaway\n"); break; }
    }
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
            *value=rd64le(tx+o); o+=8;
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

/* peer rotation + reconnect (refreshed via DNS seeds 2026-08-25) */
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
        /* attempt 0: use the caller-supplied host; afterwards rotate through PEERS */
        const char* ph = (attempt==0 && host)? host : PEERS[g_npeer % NPEERS];
        unsigned ip=0;
        struct in_addr a; if(inet_pton(AF_INET,ph,&a)) ip=a.s_addr;
        if(!ip){ struct addrinfo h,*res=NULL; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
                 if(getaddrinfo(ph,NULL,&h,&res)==0&&res){ ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr; freeaddrinfo(res);} }
        if(!ip){ g_npeer++; } else {
            int fd=tcp_connect_ip(ip,(unsigned short)htons(8333));
            if(fd>=0){
                unsigned char v[102]; int o=0;
                p32le(v+o,70016); o+=4; p64le(v+o,1); o+=8; p64le(v+o,(unsigned long long)time(NULL)); o+=8;
                p64le(v+o,1); o+=8; o+=16; p16be(v+o,8333); o+=2; p64le(v+o,1); o+=8; o+=16; p16be(v+o,0); o+=2;
                p64le(v+o,0x1111111111111111ULL); o+=8;
                const char* ua="/Satoshi:0.18.0/"; v[o]=strlen(ua); o++; memcpy(v+o,ua,strlen(ua)); o+=strlen(ua);
                p32le(v+o,0); o+=4; v[o]=1; o+=1;
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
/* request a window of block hashes in ONE getdata; returns 0 on send-ok */
static int req_window(int fd, const unsigned char* hdr, long w, long nw){
    unsigned char* gd=malloc(1+(size_t)nw*36);
    gd[0]=(unsigned char)nw;
    for(long k=0;k<nw;k++){ const unsigned char* hash=hdr+(w+k)*112+80;
        p32le(gd+1+k*36,0x40000002); memcpy(gd+5+k*36,hash,32); }
    long wr=p2p_write(fd,"getdata",7,gd,1+(size_t)nw*36);
    free(gd);
    return wr>0 ? 0 : -1;
}

int main(int argc, char** argv){
    if(argc<4){ fprintf(stderr,"usage: %s <peer> <start_height> <count> [datadir] [p2sh]\n", argv[0]); return 2; }
    long start=atol(argv[2]); long maxblk=atol(argv[3]);
    const char* dd= argc>4?argv[4]:"data"; mkdir(dd,0755); chdir(dd);
    /* official log: <datadir>/logs/bitcoind.production.log (all-asm leveled logger) */
    mkdir("logs",0755);
    g_log = node_log_open("logs/bitcoind.production.log");
    NL(g_log, 7, "node start (ibd download worker)");
    uint64_t flags = SV_SIGPUSHONLY | ((argc>5&&atoi(argv[5]))?SV_P2SH:0);

    /* ---- load verified header chain ---- */
    FILE*hf=fopen("headers.dat","rb");
    if(!hf){ fprintf(stderr,"FAIL open headers.dat (run from repo data dir or pass it)\n"); return 1; }
    fseek(hf,0,SEEK_END); long fsz=ftell(hf); fseek(hf,0,SEEK_SET);
    long total=fsz/112;
    if(start<0)start=0; if(start+maxblk>total)maxblk=total-start;
    unsigned char* hdr = malloc((size_t)total*112);
    if(fread(hdr,112,(size_t)total,hf)!=(size_t)total){ fprintf(stderr,"read headers err\n"); return 1; }
    fclose(hf);

    /* ---- UTXO + persistent store ---- */
    unsigned long slots=1<<20; void* U=malloc(utxo_struct_size(slots));
    uint8_t* bob=malloc(1u<<27);
    utxo_init(U,slots,bob,1u<<27);
    void* ST=calloc(1,64); utxo_store_init(ST);

    /* ---- connect + handshake ---- */
    unsigned char* rbuf=malloc(8*1024*1024);
    int fd=connect_peer(argv[1], rbuf);
    if(fd<0){ fprintf(stderr,"FAIL connect all peers\n"); return 1; }
    LLOG(1, "PASS connect+handshake; IBD h=%ld..%ld flags=%llx\n",
            start, start+maxblk-1, (unsigned long long)flags);

    /* ---- download+verify+apply loop (batched) ---- */
    /* work buffer doubles as the legacy_sighash preimage scratch. legacy_sighash
     * materializes the full raw-input/output serialization in it (for
     * hashPrevouts/hashOutputs), so it must be >= the largest tx's raw serialized
     * size + overlay. 64KB silently overflowed on big txs (e.g. the 68KB
     * 2000-output spam tx at h134329) -> legacy_sighash rc=0 -> spurious
     * EVAL_FALSE on every large tx. 8MB covers the whole chain incl. 1MB legacy
     * / 4MB witness-era txs. */
    unsigned char* work = malloc(8u<<20); if(!work){ fprintf(stderr,"FAIL work alloc\n"); return 1; }
    unsigned char* scr = malloc(1<<22);
    long valid=0, bad_gate=0, bad_sig=0, spent=0, added=0, ntx=0, nsig=0;
    unsigned long long total_val_out=0, total_val_in=0;
    const long BATCH=128;
    unsigned char** gblk=malloc((size_t)BATCH*sizeof(void*));
    long* glen=malloc((size_t)BATCH*sizeof(long));
    int* ghave=malloc((size_t)BATCH*sizeof(int));
    char cmd[12]; unsigned plen=0;

    for(long w=start; w<start+maxblk; w+=BATCH){
        long wend=w+BATCH; if(wend>start+maxblk) wend=start+maxblk;
        long nw=wend-w;
        for(long k=0;k<nw;k++){ ghave[k]=0; gblk[k]=0; glen[k]=0; }
        /* request the whole window; retry across peers on send failure */
        if(req_window(fd,hdr,w,nw)<0){
            fprintf(stderr,"w%ld req fail; reconnect\n",w);
            fd_close(fd); fd=connect_peer(0,rbuf);
            if(fd<0){ fprintf(stderr,"w%ld NO peer\n",w); goto done; }
            if(req_window(fd,hdr,w,nw)<0){ fprintf(stderr,"w%ld re-req fail\n",w); goto done; }
        }
        /* collect every block in the window */
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
            } /* ignore others */
        }
        /* process the window in height order */
        for(long k=0;k<nw;k++){
            long h=w+k;
            if(h==173805){ flags |= SV_P2SH; LLOG(4, "P2SH ACTIVATED at h%ld flags=%llx\n",h,(unsigned long long)flags); }      /* BIP16 */
            unsigned char* blk=gblk[k];
            if(!blk){ fprintf(stderr,"h%ld not collected\n",h); goto done; }
            int blklen=(int)glen[k];
            /* block gate */
            if(cons_verify(blk, blklen, scr, 1<<22)!=1){ fprintf(stderr,"h%ld BAD cons_verify\n",h); bad_gate++; free(blk); continue; }
            /* walk txs */
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
                            utxo_put(U,txid,v,val,h,1,sp,spl); added++; total_val_out+=val;
                        } }
                } else {
                    uint8_t ph[32]; unsigned long pidx; unsigned char sigb[520]; unsigned long ssl;
                    for(v=0;v<nin;v++){
                        if(tx_in(txo,tl,v,ph,&pidx,sigb,&ssl)!=0) continue;
                        unsigned long long pval; unsigned long pheight=0,pcb=0; const uint8_t*psp; unsigned long pspl;
                        /* utxo_get returns 1=present, 0=absent */
                        if(utxo_get(U,ph,pidx,&pval,&pheight,&pcb,&psp,&pspl)==0){
                            LLOG(6, "h%ld tx%lu in%lu MISSING-PREVOUT idx=%lu txid=",h,ti,v,pidx);
                            for(int _k=0;_k<32;_k++){ fprintf(stderr,"%02x",ph[_k]); if(g_log){ char _hb[3]; snprintf(_hb,3,"%02x",ph[_k]); node_log_str(g_log,6,_hb,2);} }
                            fprintf(stderr,"\n"); if(g_log) node_log_str(g_log,6,"\n",1);
                            bad_sig++; continue;
                        }
                        int rr=sv_verify_script(sigb,ssl,psp,pspl,flags,v,txo,tl,work,8u<<20);
                        if(rr!=0){ LLOG(6, "h%ld tx%lu in%lu SIGFAIL err=%d\n",h,ti,v,rr); bad_sig++;
                            static int dumped=0;
                            if(!dumped){ dumped=1;
                                fprintf(stderr,"--- UTXO slot dump for failing prevout ---\n");
                                utxo_dump(U, ph, pidx);
                                FILE*fz=fopen("/tmp/fail_ctx.txt","w");
                                fprintf(fz,"txlen=%lu nIn=%lu flags=%llx\n",tl,v,(unsigned long long)flags);
                                fprintf(fz,"scriptSig(%lu)=",ssl); for(unsigned z=0;z<ssl;z++)fprintf(fz,"%02x",sigb[z]); fprintf(fz,"\n");
                                fprintf(fz,"scriptPubKey(%lu)=",pspl); for(unsigned z=0;z<pspl;z++)fprintf(fz,"%02x",psp[z]); fprintf(fz,"\n");
                                fprintf(fz,"tx="); for(unsigned z=0;z<tl;z++)fprintf(fz,"%02x",txo[z]); fprintf(fz,"\n");
                                fclose(fz);
                            }
                        }
                        else { nsig++; total_val_in+=pval; }
                        utxo_del(U,ph,pidx); spent++;
                    }
                    for(v=0;v<nout;v++){ unsigned long long val; const uint8_t*sp; unsigned long spl;
                        if(tx_out(txo,tl,v,&val,&sp,&spl)==0 && spl>0){
                            uint8_t txid[32]; sha256d(txid,txo,tl);
                            utxo_put(U,txid,v,val,h,0,sp,spl); added++; total_val_out+=val;
                        } }
                }
                toff += tl;
            }
            if(bad){ bad_gate++; free(blk); continue; }
            if((h%16)==0 || h==start+maxblk-1){ utxo_store_sync(ST,U); }
            valid++;
            if(((h-start)%50)==0)
                LLOG(3, "h%ld txs=%llu utxo=%ld spent=%ld sigs=%ld\n",
                        h, (unsigned long long)nt, (long)utxo_count(U), spent, nsig);
            free(blk); gblk[k]=0;
        }
    }
done:
    LLOG(5, "DONE: blocks_valid=%ld bad_gate=%ld bad_sig=%ld\n", valid, bad_gate, bad_sig);
    LLOG(5, "      txs=%ld inputs_spent=%ld sigs_verified=%ld outputs_added=%ld utxo_count=%ld\n",
        ntx, spent, nsig, added, (long)utxo_count(U));
    LLOG(5, "      value_in=%llu value_out=%llu\n", (unsigned long long)total_val_in, (unsigned long long)total_val_out);
    utxo_store_sync(ST,U);
    fd_close(fd);
    fprintf(stderr,"\n%s\n",
        (valid==maxblk && bad_sig==0)? "IBD VERIFY SIGNED OFF NATIVELY (all blocks, all sigs)"
        : (bad_sig==0? "IBD GATE OK (sigs clean)" : "IBD INCOMPLETE (see failures above)"));
    if(g_log) node_log_str(g_log, 0,
        (valid==maxblk && bad_sig==0)? "IBD VERIFY SIGNED OFF NATIVELY (all blocks, all sigs)"
        : (bad_sig==0? "IBD GATE OK (sigs clean)" : "IBD INCOMPLETE (see failures above)"),
        (long)strlen((valid==maxblk && bad_sig==0)? "IBD VERIFY SIGNED OFF NATIVELY (all blocks, all sigs)"
        : (bad_sig==0? "IBD GATE OK (sigs clean)" : "IBD INCOMPLETE (see failures above)")));
    return (bad_sig==0 && valid==maxblk)? 0 : 1;
}
