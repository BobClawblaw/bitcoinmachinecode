/* test_cli.c -- S6 CLI harness: exercises cli_main (all-asm bitcoin_cli.asm)
 * against a store freshly built with the same block-builder oracle as
 * test_bitcoind_sync. Every command's output is checked against expected
 * values computed here via the PROVEN asm block_hash/sha256d + a C hex fmt.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

static int failures = 0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void cks(const char*l,const char*g,const char*e){ if(strcmp(g,e)==0)printf("PASS %s\n",l); else{printf("FAIL %s\n  got : %s\n  exp : %s\n",l,g,e);failures++;} }

/* asm exports */
extern long store_init(void* st);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern void sha256d(unsigned char o[32], const void* m, long l);
extern long store_append(void* st, const unsigned char h[32], const void* blk, long blen);
extern long cli_main(void* st, long argc, void** argv, unsigned char* out, long cap);

static void put_u32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static void put_u64(unsigned char*p,unsigned long long v){for(int i=0;i<8;i++)p[i]=v>>(8*i);}

#define NB 8
static unsigned char blk[NB][600];
static long blen[NB];
static unsigned char bhash[NB][32];
static unsigned char cbtx[NB][300];   /* each block's coinbase tx bytes */
static long cbtxlen[NB];
static unsigned char cbtxid[NB][32];  /* raw txid of the coinbase */

static void hexfmt(char* out, const unsigned char* p, int n){ for(int i=0;i<n;i++) sprintf(out+i*2,"%02x",p[i]); out[n*2]=0; }
static void rev32(unsigned char* o, const unsigned char* s){ for(int i=0;i<32;i++) o[i]=s[31-i]; }

/* Build the same single-coinbase chain as test_bitcoind_sync. */
static void build_chain(void){
    unsigned char prev[32]; memset(prev,0,32);
    for(int i=0;i<NB;i++){
        unsigned char* b=blk[i]; unsigned char* o=b; unsigned char* t=cbtx[i]; unsigned char* q=t;
        put_u32(q,1);q+=4;                    /* tx version */
        q[0]=1;q+=1;                           /* n_in=1 */
        memset(q,0,32);q+=32;                  /* prevout hash */
        put_u32(q,0xffffffff);q+=4;            /* prevout index */
        q[0]=3; q[1]=(unsigned char)i; q[2]=0; q[3]=0; q+=4;  /* scriptSig len+data */
        put_u32(q,0xffffffff);q+=4;            /* sequence */
        q[0]=1;q+=1;                           /* n_out=1 */
        put_u64(q, (unsigned long long)8*1000000);q+=8;       /* value 8 BTC */
        q[0]=1;q[1]=0x51;q+=2;                 /* scriptPubKey OP_TRUE */
        put_u32(q,0);q+=4;                     /* locktime */
        cbtxlen[i]=q-t;
        /* txid = sha256d(tx) */
        sha256d(cbtxid[i], t, cbtxlen[i]);
        /* header */
        put_u32(o,1);o+=4; memcpy(o,prev,32);o+=32; memcpy(o,cbtxid[i],32);o+=32;
        put_u32(o,1300000000u);o+=4; put_u32(o,0x207fffff);o+=4; put_u32(o,0);o+=4;
        /* tx-count varint (1) then coinbase tx */
        o[0]=1; o+=1; memcpy(o,t,cbtxlen[i]); o+=cbtxlen[i];
        blen[i]=o-b;
        block_hash(bhash[i], blk[i]); memcpy(prev,bhash[i],32);
    }
}

int main(void){
    build_chain();
    /* build store in CWD (empty dir); use a scratch subdir */
    /* fixed /tmp/clitest was shared by every concurrent run */
    tt_isolate();
    unlink("blk00000.dat"); unlink("index.dat"); unlink("prune.dat");
    static unsigned char st[4096];
    cki("store_init", store_init(st), 1);
    for(int i=0;i<NB;i++) cki("append", store_append(st,bhash[i],blk[i],blen[i]), i);

    static unsigned char out[65536];
    static void* av0[8]; char* cmd0="getblockcount"; av0[0]=cmd0;
    long n = cli_main(st,1,av0,out,sizeof out);
    out[n]=0; cks("getblockcount", (char*)out, "8\n");

    /* best block hash: reversed bhash[7] */
    char* cmd1="getbestblockhash"; void* av1[8]; av1[0]=cmd1;
    n=cli_main(st,1,av1,out,sizeof out); out[n]=0;
    { unsigned char rev[32]; rev32(rev,bhash[7]); char e[67]; hexfmt(e,rev,32); strcat(e,"\n"); cks("getbestblockhash",(char*)out,e); }

    /* getblockhash 3 */
    char* cmd2="getblockhash"; char* h3="3"; void* av2[8]; av2[0]=cmd2; av2[1]=h3;
    n=cli_main(st,2,av2,out,sizeof out); out[n]=0;
    { unsigned char rev[32]; rev32(rev,bhash[3]); char e[67]; hexfmt(e,rev,32); strcat(e,"\n"); cks("getblockhash 3",(char*)out,e); }

    /* getblock 2 -> hex of raw block2 */
    char* cmd3="getblock"; char* h2="2"; void* av3[8]; av3[0]=cmd3; av3[1]=h2;
    n=cli_main(st,2,av3,out,sizeof out); out[n]=0;
    { char e[1600]; hexfmt(e,blk[2],(int)blen[2]); strcat(e,"\n"); cks("getblock 2",(char*)out,e); }

    /* getblock <hash of 2> (display order) -> same hex */
    unsigned char rev[32]; rev32(rev,bhash[2]); char hx[65]; hexfmt(hx,rev,32);
    void* av4[8]; av4[0]=cmd3; av4[1]=hx;
    n=cli_main(st,2,av4,out,sizeof out); out[n]=0;
    { char e[1600]; hexfmt(e,blk[2],(int)blen[2]); strcat(e,"\n"); cks("getblock by-hash",(char*)out,e); }

    /* gettx <txid of coinbase in block0, display order>
     * expected: "found in block 0\n<hex tx>\n" */
    unsigned char trev[32]; rev32(trev,cbtxid[0]); char thx[65]; hexfmt(thx,trev,32);
    char* cmd4="gettx"; void* av5[8]; av5[0]=cmd4; av5[1]=thx;
    n=cli_main(st,2,av5,out,sizeof out); out[n]=0;
    { char e[800]; sprintf(e,"found in block 0\n");
      char th[600]; hexfmt(th,cbtx[0],(int)cbtxlen[0]); strcat(e,th); strcat(e,"\n");
      cks("gettx coinbase@0",(char*)out,e); }
    /* a nonexistent txid -> error */
    void* av6[8]; av6[0]=cmd4; av6[1]="000000000000000000000000000000000000000000000000000000000000dead";
    n=cli_main(st,2,av6,out,sizeof out); out[n]=0;
    if(strncmp((char*)out,"error:",6)==0) printf("PASS gettx unknown -> error\n");
    else { printf("FAIL gettx unknown (got %s)\n",out); failures++; }

    /* getbalance -> 8 blocks * 8 BTC = 64,000,000 */
    char* cmd5="getbalance"; void* av7[8]; av7[0]=cmd5;
    n=cli_main(st,1,av7,out,sizeof out); out[n]=0;
    { char e[32]; strcpy(e,"64000000\n"); cks("getbalance",(char*)out,e); }

    /* unknown command */
    char* cmd6="bogus"; void* av8[8]; av8[0]=cmd6;
    n=cli_main(st,1,av8,out,sizeof out); out[n]=0;
    if(strncmp((char*)out,"error:",6)==0) printf("PASS unknown->error\n");
    else { printf("FAIL unknown (got %s)\n",out); failures++; }

    /* help */
    char* cmd7="help"; void* av9[8]; av9[0]=cmd7;
    n=cli_main(st,1,av9,out,sizeof out); out[n]=0;
    if(strstr((char*)out,"getblockcount") && strstr((char*)out,"gettx")) printf("PASS help lists commands\n");
    else { printf("FAIL help\n"); failures++; }

    /* stop -> block count (now with trailing newline like the other commands) */
    char* cmd8="stop"; void* ava[8]; ava[0]=cmd8;
    n=cli_main(st,1,ava,out,sizeof out); out[n]=0; cks("stop",(char*)out,"8\n");

    /* ---- prune (Core-style -prune): delete blk data below a height ----
     * NB blocks have blen: b[0] has a compact tx. Retain only blocks >= 4. */
    char* cmd9="prune"; char* p4="4"; void* avb[8]; avb[0]=cmd9; avb[1]=p4;
    n=cli_main(st,2,avb,out,sizeof out); out[n]=0;
    if(strncmp((char*)out,"pruned to height ",17)==0) printf("PASS prune cmd (got %.20s)\n",(char*)out);
    else { printf("FAIL prune cmd got=%.30s\n",(char*)out); failures++; }
    /* block count still reports the full stored chain (index retained) */
    n=cli_main(st,1,ava,out,sizeof out); out[n]=0; cks("count after prune",(char*)out,"8\n");
    /* pruned height (<4) -> unavailable (error output) */
    char* h1="1"; void* avc[8]; avc[0]=cmd3; avc[1]=h1;   /* getblock 1 */
    n=cli_main(st,2,avc,out,sizeof out); out[n]=0;
    if(strncmp((char*)out,"error:",6)==0) printf("PASS getblock pruned->error\n");
    else { printf("FAIL getblock pruned got=%.20s\n",(char*)out); failures++; }
    /* retained height (>=4) still served byte-exact */
    char* h7="7"; void* avd[8]; avd[0]=cmd3; avd[1]=h7;
    n=cli_main(st,2,avd,out,sizeof out); out[n]=0;
    { char e[1600]; hexfmt(e,blk[7],(int)blen[7]); strcat(e,"\n"); cks("getblock 7 after prune",(char*)out,e); }
    /* prune-all: prune to a height > tip deletes every blk file (UTXO-only) */
    char* p99="99"; void* ave[8]; ave[0]=cmd9; ave[1]=p99;   /* prune > tip */
    n=cli_main(st,2,ave,out,sizeof out); out[n]=0;
    if(strncmp((char*)out,"pruned to height ",17)==0) printf("PASS prune-all ok\n");
    else { printf("FAIL prune-all got=%.30s\n",(char*)out); failures++; }
    n=cli_main(st,2,avd,out,sizeof out); out[n]=0;   /* getblock 7 now pruned too */
    if(strncmp((char*)out,"error:",6)==0) printf("PASS getblock pruned-all->error\n");
    else { printf("FAIL getblock pruned-all got=%.20s\n",(char*)out); failures++; }

    printf(failures?"FAILURES %d\n":"ALL TESTS PASSED (0 failures)\n",failures);
    return failures?1:0;
}
