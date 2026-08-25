/* t_eval.c -- drives the AArch64 script_eval against a Python EvalScript oracle.
 * One case per line:
 *   run <sigversion> <flags> <locktime> <seq> <ver> <rstub> <stk(hex,comma)> <scripthex>
 * Prints:  rc=<err> d=<depth> then each element: L<hx>:<datahex>
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ELEM 528
#define NSTK 1000
static uint8_t stk[NSTK*ELEM];
static uint8_t alt[NSTK*ELEM];
static uint8_t sbuf[10001];
typedef struct {
    uint8_t* stk_elems; uint64_t stk_sp;
    uint8_t* alt_elems; uint64_t alt_sp;
    const uint8_t* script; uint64_t script_len;
    uint32_t sigversion; uint32_t pad1;
    uint64_t flags;      // 56
    uint64_t pad2;       // 64
    uint64_t pad3;       // 72
    uint64_t* err_out;   // 80
    uint64_t ctx;        // 88
    long (*checksig)(uint64_t,const uint8_t*,uint64_t,const uint8_t*,uint64_t,uint64_t*); // 96
    uint32_t tx_locktime; // 104
    uint32_t in_sequence; // 108
    uint32_t tx_version;  // 112
} SState;
extern long script_eval(void* state);

static long stub_checksig(uint64_t ctx,const uint8_t* sig,uint64_t sl,
                          const uint8_t* pub,uint64_t pl,uint64_t* slice){
    (void)pub;(void)pl;(void)slice;
    return (sl>0 && ctx==1) ? 1 : 0;
}
static int hv(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return 0;}
static size_t h2b(const char*h,uint8_t*o,size_t m){size_t n=strlen(h);if(m<n/2)n=m*2;for(size_t i=0;i<n/2;i++)o[i]=(uint8_t)((hv(h[2*i])<<4)|hv(h[2*i+1]));return n/2;}
static void b2h(const uint8_t*d,size_t n,char*o){static const char*X="0123456789abcdef";for(size_t i=0;i<n;i++){o[2*i]=X[d[i]>>4];o[2*i+1]=X[d[i]&15];}o[2*n]=0;}

int main(){
    char line[140000];
    while(fgets(line,sizeof line,stdin)){
        unsigned sv,fl,lt,seq,ver; char rstub;
        char stkstr[70000], scr[140000];
        if(sscanf(line,"run %u %u %u %u %u %c %69999s %139999s",&sv,&fl,&lt,&seq,&ver,&rstub,stkstr,scr)!=8)continue;
        /* parse '<'separator'?' ... I'll keep format: run ... <stk> <script> */
        SState st; memset(&st,0,sizeof st);
        st.stk_elems=stk; st.alt_elems=alt;
        st.sigversion=sv; st.flags=fl;
        st.tx_locktime=lt; st.in_sequence=seq; st.tx_version=ver;
        st.checksig=stub_checksig; st.ctx=(uint64_t)(rstub-'0');
        unsigned err=12345; st.err_out=&err;
        st.stk_sp=0; char* save; char* tok=strtok_r(stkstr,",",&save);
        while(tok){
            if(st.stk_sp>=NSTK)break;
            if(!strcmp(tok,"--")){tok=strtok_r(NULL,",",&save);continue;}
            uint8_t* r=stk+st.stk_sp*ELEM;
            if(tok[0]=='-'){*(uint32_t*)r=0; st.stk_sp++; tok=strtok_r(NULL,",",&save); continue;}
            size_t n=h2b(tok,r+4,520); *(uint32_t*)r=(uint32_t)n; st.stk_sp++; tok=strtok_r(NULL,",",&save);
        }
        st.script=sbuf; st.script_len=h2b(scr,sbuf,sizeof sbuf);
        err=9999;
        long rc=script_eval(&st);
        unsigned depth=(unsigned)st.stk_sp;
        printf("rc=%d eo=%u d=%u",(int)(rc?1:0), (unsigned)err, depth);
        for(unsigned i=0;i<depth && i<40;i++){
            uint8_t* r=stk+i*ELEM; unsigned n=*(uint32_t*)r;
            char out[1100]; if(n>520)n=520; b2h(r+4,n,out);
            printf(" L%u:%s",i,out);
        }
        /* note: depth printed is the sp AFTER eval (script_eval mutated st.stk_sp) */
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
