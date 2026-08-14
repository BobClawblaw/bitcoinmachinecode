/* smoke_interp.c -- minimal link/run smoke test for the asm interpreter. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define ELEM_SIZE 528
#define ELEM_DATA_OFF 4
#define MAX_STACK 1000
struct script_state {
    uint8_t* main_elems; size_t main_sp;
    uint8_t* alt_elems;  size_t alt_sp;
    uint8_t* script;     size_t script_len;
    int      sigversion; uint64_t flags;
    uint8_t* work;       size_t work_cap;
    uint64_t* error_out;
    void*    checksig_ctx;
    uint64_t (*checksig_fn)(void*,const uint8_t*,size_t,const uint8_t*,size_t,const void*);
};
extern int script_eval(struct script_state* st);
static uint8_t main_elems[MAX_STACK*ELEM_SIZE];
static uint8_t alt_elems[MAX_STACK*ELEM_SIZE];
static uint64_t g_err;
static int hex2b(const char*h,uint8_t*o){int n=0;for(const char*p=h;p[0]&&p[1];){if(*p==' '||*p=='\t'){p++;continue;}unsigned v;sscanf(p,"%2x",&v);o[n++]=(uint8_t)v;p+=2;}return n;}
static int run(const char* sh, int sigv, uint64_t flags){
    static uint8_t scr[10000];
    size_t sl=hex2b(sh,scr);
    struct script_state st;
    memset(main_elems,0,sizeof(main_elems));
    memset(alt_elems,0,sizeof(alt_elems));
    st.main_elems=main_elems; st.main_sp=0;
    st.alt_elems=alt_elems; st.alt_sp=0;
    st.script=scr; st.script_len=sl; st.sigversion=sigv; st.flags=flags;
    st.work=NULL; st.work_cap=0; st.error_out=&g_err;
    st.checksig_ctx=NULL; st.checksig_fn=NULL;
    g_err=999;
    int r=script_eval(&st);
    printf("script=%-28s sigv=%d -> r=%d err=%llu depth=%zu\n", sh, sigv, r,
           (unsigned long long)g_err, st.main_sp);
    return r;
}
int main(void){
    int f=0;
    f|= run("51",0,0)!=1;          /* OP_1 */
    f|= run("515187",0,0)!=1;      /* 1 1 EQUAL */
    f|= run("525187",0,0)!=1;      /* 1 2 EQUAL -> valid exec (false top) */
    f|= run("6a",0,0)!=0;          /* OP_RETURN -> fail */
    f|= run("517e",0,0)!=0;        /* CAT disabled */
    f|= run("505151",0,0)!=0;      /* OP_RESERVED bad */
    f|= run("515193",0,0)!=1;      /* 1 1 ADD */
    f|= run("5163 51 68",0,0)!=1;  /* IF 1 ENDIF */
    f|= run("00 63 51 68",0,0)!=1; /* IF(false) 1 ENDIF */
    f|= run("51 63 51 67 52 68",0,0)!=1; /* IF 1 ELSE 2 ENDIF */
    f|= run("00 a8",0,0)!=1;       /* OP_0 SHA256 */
    f|= run("51 a9",0,0)!=1;       /* 1 HASH160 */
    f|= run("51 aa",0,0)!=1;       /* 1 HASH256 */
    f|= run("51 a6",0,0)!=1;       /* 1 RIPEMD160 */
    f|= run("51 69",0,0)!=1;       /* 1 VERIFY */
    f|= run("00 69",0,0)!=0;       /* 0 VERIFY fail */
    f|= run("51 52 7c",0,0)!=1;    /* 1 2 SWAP */
    f|= run("51 52 53 7b",0,0)!=1; /* 1 2 3 ROT */
    f|= run("51 52 6e",0,0)!=1;    /* 1 2 2DUP */
    f|= run("51 82",0,0)!=1;       /* 1 SIZE */
    f|= run("51 52 9c",0,0)!=1;    /* 1 2 NUMEQUAL */
    f|= run("01 02 51 9c",0,0)!=1;  /* 2 1 NUMEQUAL -> exec ok */
    f|= run("51 52 6d",0,0)!=1;    /* 1 2 2DROP -> eval accepted (empty final) */
    printf("\n%s\n", f?"SMOKE FAILED":"SMOKE PASSED");
    return f?1:0;
}
