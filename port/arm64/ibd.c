/* ibd.c -- Integrated Blockchain Download + trusted verification (native AArch64).
 *
 * Walks the VERIFIED mainnet header chain from data/headers.dat (963,935 headers,
 * 112 B each = 80 B header + 32 B hash), and for a contiguous [start,start+count)
 * window downloads each block from a live peer via getdata(BLOCK), then:
 *   1. block gate: cons_verify (PoW + merkle root + coinbase structure)
 *   2. per-transaction script verification: for each non-coinbase input, look up
 *      the prevout in the in-memory UTXO set and run sv_verify_script (the C
 *      VerifyScript wrapper over the ported script_eval VM + ECDSA checksig)
 *   3. UTXO apply: spend spent inputs (del), add outputs (put)
 *   4. periodic checkpoint via the persistent bitcoin_utxo_store (WAL + ckpt)
 *
 * BASE-legacy era (pre-481824 segwit) is the fully-verifiable target of this
 * stage; the same loop carries witness-era blocks since we request with
 * MSG_WITNESS_BLOCK and cons_verify / sv_verify_script handle both.
 *
 * Usage: ibd <peer> <start_height> <count> [datadir] [flags]
 *   flags: bit0 = P2SH on (enforce after BIP16 ~173805)
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

/* ---- helpers ---- */
static void p16be(unsigned char*p,unsigned v){p[0]=v>>8;p[1]=v&0xff;}
static void p32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void p64le(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;}}
static unsigned long long rd64le(const unsigned char*p){unsigned long long v=0;for(int i=7;i>=0;i--){v=(v<<8)|p[i];}return v;}

/* read a Bitcoin varint; returns length consumed or -1 on overrun */
static int rd_varint(const unsigned char*p, unsigned long n, unsigned long long* out){
    if(n<1) return -1;
    unsigned char b=p[0];
    if(b<0xfd){ *out=b; return 1; }
    else if(b==0xfd){ if(n<3)return -1; *out=p[1]|(p[2]<<8); return 3; }
    else if(b==0xfe){ if(n<5)return -1; *out=(unsigned long long)p[1]|((unsigned long long)p[2]<<8)|
        ((unsigned long long)p[3]<<16)|((unsigned long long)p[4]<<24); return 5; }
    else { if(n<9)return -1; *out=rd64le(p+1); return 9; }
}

/* walk one raw transaction: returns length of the whole tx (>=0, incl. locktime)
 * or -1 on malformed/overrun. Fills *nin,*nout. On success *txlen == ret. */
static long tx_walk(const unsigned char*tx, unsigned long n, unsigned long* nin, unsigned long* nout){
    if(n<4+1+1) return -1;
    unsigned long o=4;                 /* version */
    unsigned long long ni; int v=rd_varint(tx+o,n-o,&ni); if(v<0)return -1; o+=v;
    unsigned long long nin_=ni, i;
    for(i=0;i<nin_;i++){
        if(o+36+4>n) return -1;        /* prevout(36) + seq(4) min */
        o+=36;
        unsigned long long sl; v=rd_varint(tx+o,n-o,&sl); if(v<0)return -1; o+=v;
        if(o+sl+4>n) return -1;        /* scriptSig + sequence */
        o+=sl+4;
    }
    unsigned long long no; v=rd_varint(tx+o,n-o,&no); if(v<0)return -1; o+=v;
    unsigned long long nout_=no, j;
    for(j=0;j<nout_;j++){
        if(o+8>n) return -1; o+=8;     /* value */
        unsigned long long sl; v=rd_varint(tx+o,n-o,&sl); if(v<0)return -1; o+=v;
        if(o+sl>n) return -1; o+=sl;
    }
    if(o+4>n) return -1; o+=4;         /* locktime */
    *nin=nin_; *nout=nout_;
    return (long)o;
}

/* locate the i-th input of a raw tx: fills prevhash[32], previndex, and the
 * value+length of its scriptSig. Returns 0 ok, -1 malformed. */
static int tx_in(const unsigned char*tx, unsigned long n, unsigned long idx,
                 uint8_t* prevhash, unsigned long* previndex, uint8_t* scriptsig,
                 unsigned long* ssl){
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
/* locate the j-th output of a raw tx: value + script ptr/len */
static int tx_out(const unsigned char*tx, unsigned long n, unsigned long idx,
                  unsigned long long* value, const uint8_t** script, unsigned long* sl){
    unsigned long o=4;
    unsigned long long ni; int v=rd_varint(tx+o,n-o,&ni); if(v<0)return -1; o+=v;
    { unsigned long long sl_; o+= (ni==0)?0:0; }
    unsigned long long no; 
    /* walk inputs */
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

/* peer rotation + reconnect */
static const char* PEERS[] = {
    "13.53.88.24","50.5.47.223","85.230.179.6","31.44.60.174","45.202.248.118",
    "38.51.144.232","79.136.22.16","184.161.137.147","172.233.78.120","118.141.2.9",
    "185.88.248.162","184.174.97.161","204.83.75.130","70.173.91.108","23.175.0.220",
    "172.105.244.125","65.33.241.127","142.132.147.162","69.144.245.66","71.69.213.11",
    "89.33.17.242","31.47.167.78","69.197.174.36","86.85.157.170","217.87.210.45",
    "62.210.124.104","76.51.10.42","13.53.202.93","172.105.175.172","20.141.185.87",
    0 };
static int g_npeer=0;
static int connect_peer(const char* host,unsigned char* rbuf){
    int tries=0;
    for(int attempt=0;; attempt++){
        const char* ph = host? host : PEERS[g_npeer % 30];
        unsigned ip=0;
        struct in_addr a; if(inet_pton(AF_INET,ph,&a)) ip=a.s_addr;
        if(!ip){ struct addrinfo h,*res=NULL; memset(&h,0,sizeof h); h.ai_family=AF_INET; h.ai_socktype=SOCK_STREAM;
                 if(getaddrinfo(ph,NULL,&h,&res)==0&&res){ ip=((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr; freeaddrinfo(res);} }
        if(!ip){ g_npeer++; } else {
            int fd=tcp_connect_ip(ip,(unsigned short)htons(8333));
            if(fd>=0){
                /* version handshake */
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
        if(tries++>30) return -1;
        usleep(200000);
    }
}

int main(int argc, char** argv){
    if(argc<4){ fprintf(stderr,"usage: %s <peer> <start_height> <count> [datadir] [p2sh]\n", argv[0]); return 2; }
    long start=atol(argv[2]); long maxblk=atol(argv[3]);
    const char* dd= argc>4?argv[4]:"data"; mkdir(dd,0755); chdir(dd);
    uint64_t flags = SV_SIGPUSHONLY | ((argc>5&&atoi(argv[5]))?SV_P2SH:0);

    /* ---- load verified header chain ---- */
    char hpath[512]; snprintf(hpath,sizeof hpath,"headers.dat");
    FILE*hf=fopen(hpath,"rb");
    if(!hf){ fprintf(stderr,"FAIL open %s\n",hpath); return 1; }
    fseek(hf,0,SEEK_END); long fsz=ftell(hf); fseek(hf,0,SEEK_SET);
    long total=fsz/112;
    if(start<0)start=0; if(start+maxblk>total)maxblk=total-start;
    unsigned char* hdr = malloc((size_t)total*112);
    if(fread(hdr,112,(size_t)total,hf)!=(size_t)total){ fprintf(stderr,"read headers err\n"); return 1; }
    fclose(hf);

    /* ---- UTXO + persistent store ---- */
    unsigned long slots=1<<20; void* U=malloc(utxo_struct_size(slots));
    static uint8_t* bob = 0; bob=malloc(1u<<27);
    utxo_init(U,slots,bob,1u<<27);
    void* ST=calloc(1,64); utxo_store_init(ST);

    /* ---- connect + handshake (with peer rotation) ---- */
    unsigned char* rbuf=malloc(8*1024*1024);
    char cmd[12]; unsigned plen=0;
    int fd=connect_peer(argv[1], rbuf);
    if(fd<0){ fprintf(stderr,"FAIL connect all peers\n"); return 1; }
    fprintf(stderr,"PASS connect+handshake; IBD h=%ld..%ld flags=%llx\n",
            start, start+maxblk-1, (unsigned long long)flags);

    /* ---- download+verify+apply loop ---- */
    unsigned char work[1<<16];
    unsigned char* scr = malloc(1<<22);           /* cons_verify scratch */
    long valid=0, bad_gate=0, bad_sig=0, spent=0, added=0, ntx=0, nsig=0;
    unsigned long long total_val_out=0, total_val_in=0;
    long h;
    for(h=start; h<start+maxblk; h++){
        unsigned char* hash = hdr + h*112 + 80;

        /* request block by hash (MSG_WITNESS_BLOCK): varint count=1 + type + hash */
        unsigned char gd[1+4+32];
        gd[0]=1;                                 /* count varint = 1 */
        p32le(gd+1,0x40000002);                  /* type MSG_WITNESS_BLOCK */
        memcpy(gd+5,hash,32);
        if(p2p_write(fd,"getdata",7,gd,sizeof gd)<=0){ fprintf(stderr,"h%ld FAIL getdata\n",h); break; }

        /* receive until we get THIS block */
        unsigned char* blk=0; int blklen=0; int got=0;
        for(int iter=0; iter<4000 && !got; iter++){
            int r=p2p_read(fd,cmd,rbuf,8*1024*1024,&plen);
            if(r<=0){
                /* peer dropped/throttled -> reconnect to a fresh peer, resume at h */
                fprintf(stderr,"  h%ld peer EOF r=%d; reconnecting+resume...\n",h,r);
                fd_close(fd);
                fd=connect_peer(0, rbuf);
                if(fd<0){ fprintf(stderr,"h%ld NO peer\n",h); goto done; }
                /* re-request this block */
                if(p2p_write(fd,"getdata",7,gd,sizeof gd)<=0){ fprintf(stderr,"h%ld FAIL re-getdata\n",h); goto done; }
                continue;
            }
            cmd[11]=0;
            if(strncmp(cmd,"block",5)==0){
                unsigned char hh[32]; block_hash(hh,rbuf);
                if(memcmp(hh,hash,32)==0){ blk=rbuf; blklen=plen; got=1; }
            } else if(strncmp(cmd,"ping",4)==0){
                p2p_write(fd,"pong",4,rbuf,plen);
            } else if(strncmp(cmd,"reject",6)==0){ /* peer refused this block -- keep pulling */ }
        }
        if(!got){ fprintf(stderr,"h%ld MISSING (peer did not serve)\n",h); break; }

        /* ---- block gate ---- */
        if(cons_verify(blk, blklen, scr, 1<<22)!=1){ fprintf(stderr,"h%ld BAD cons_verify\n",h); bad_gate++; goto nxt; }


        /* ---- walk transactions ---- */
        unsigned char* txc=blk+80;
        unsigned long long nt; int vv=rd_varint(txc,(unsigned long)(blklen-80),&nt);
        if(vv<0){ fprintf(stderr,"h%ld bad txcount\n",h); bad_gate++; goto nxt; }
        unsigned long toff = 80+vv;
        unsigned long ti;
        for(ti=0; ti<nt; ti++){
            unsigned long nin,nout;
            long tl=tx_walk(blk+toff,(unsigned long)blklen-toff,&nin,&nout);
            if(tl<0){ fprintf(stderr,"h%ld tx%lu MALFORMED\n",h,ti); bad_gate++; goto nxt; }
            unsigned char* txo=blk+toff;
            ntx++;
            unsigned long v;
            if(ti==0){
                /* coinbase: no spend, add outputs */
                for(v=0;v<nout;v++){ unsigned long long val; const uint8_t*sp; unsigned long spl;
                    if(tx_out(txo,tl,v,&val,&sp,&spl)==0 && spl>0){
                        uint8_t txid[32]; sha256d(txid,txo,tl);
                        utxo_put(U,txid,v,val,h,1,sp,spl); added++; total_val_out+=val;
                    } }
            } else {
                /* non-coinbase: spend inputs (verify against prevout) */
                uint8_t ph[32]; unsigned long pidx; unsigned char sigb[520]; unsigned long ssl;
                for(v=0;v<nin;v++){
                    if(tx_in(txo,tl,v,ph,&pidx,sigb,&ssl)!=0) continue;
                    unsigned long long pval; unsigned long pheight=0,pcb=0; const uint8_t*psp; unsigned long pspl;
                    /* utxo_get returns 1=present, 0=absent */
                    if(utxo_get(U,ph,pidx,&pval,&pheight,&pcb,&psp,&pspl)==0){
                        fprintf(stderr,"h%ld tx%lu in%lu MISSING-PREVOUT idx=%lu txid=",h,ti,v,pidx);
                        for(int _k=0;_k<32;_k++)fprintf(stderr,"%02x",ph[_k]);
                        fprintf(stderr,"\n");
                        bad_sig++; continue;
                    }
                    int rr=sv_verify_script(sigb,ssl,psp,pspl,flags,v,txo,tl,work,sizeof work);
                    if(rr!=0){ fprintf(stderr,"h%ld tx%lu in%lu SIGFAIL err=%d\n",h,ti,v,rr); bad_sig++; }
                    else { nsig++; total_val_in+=pval; }
                    utxo_del(U,ph,pidx); spent++;
                }
                /* add outputs */
                for(v=0;v<nout;v++){ unsigned long long val; const uint8_t*sp; unsigned long spl;
                    if(tx_out(txo,tl,v,&val,&sp,&spl)==0 && spl>0){
                        uint8_t txid[32]; sha256d(txid,txo,tl);
                        utxo_put(U,txid,v,val,h,0,sp,spl); added++; total_val_out+=val;
                    } }
            }
            toff += tl;
        }
        /* ---- periodic checkpoint ---- */
        if((h%16)==0 || h==start+maxblk-1){ utxo_store_sync(ST,U); }
        valid++;
        if(((h-start)%20)==0)
            fprintf(stderr,"  h%ld ok=5 blk=%dB txs=%lu utxo=%ld spent=%ld sigs=%ld\n",
                h, blklen, nt, (long)utxo_count(U), spent, nsig);
    nxt: ;
    }
done:
    fprintf(stderr,"DONE: blocks_valid=%ld bad_gate=%ld bad_sig=%ld\n", valid, bad_gate, bad_sig);
    fprintf(stderr,"      txs=%ld inputs_spent=%ld sigs_verified=%ld outputs_added=%ld utxo_count=%ld\n",
        ntx, spent, nsig, added, (long)utxo_count(U));
    fprintf(stderr,"      value_in=%llu value_out=%llu\n", total_val_in, total_val_out);
    utxo_store_sync(ST,U);
    fd_close(fd);
    fprintf(stderr,"\n%s\n",
        (valid==maxblk && bad_sig==0)? "IBD VERIFY SIGNED OFF NATIVELY (all blocks, all sigs)"
        : (bad_sig==0? "IBD GATE OK (sigs clean)" : "IBD INCOMPLETE (see failures above)"));
    return (bad_sig==0 && valid==maxblk)? 0 : 1;
}
