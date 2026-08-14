/* interp_shim.c -- C bridge so a Python driver can drive the asm interpreter
 * (bitcoin_interp.asm) for the script_tests.json harness. */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

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

/* Eval one script with an initial stack of byte-strings.
 *   script, script_len     : the script bytes
 *   init_items             : array of len+ptr for initial stack (bottom -> top)
 *   ninit                  : number of initial items
 *   sigversion, flags      : passed through
 *   out_err                : receives the error code
 * returns 1 (accepted) / 0 (rejected). */
int eval_script_bytes(const uint8_t* script, size_t script_len,
                      const uint8_t* const* init_data, const size_t* init_len, size_t ninit,
                      int sigversion, uint64_t flags, uint64_t* out_err)
{
    static uint8_t main_elems[MAX_STACK*ELEM_SIZE];
    static uint8_t alt_elems[MAX_STACK*ELEM_SIZE];
    static uint8_t scr[20000];
    if (script_len > sizeof(scr)) return -1;
    memcpy(scr, script, script_len);
    memset(main_elems,0,sizeof(main_elems));
    for(size_t i=0;i<ninit;i++){
        uint8_t* rec = main_elems + i*ELEM_SIZE;
        ((uint32_t*)rec)[0] = (uint32_t)init_len[i];
        memcpy(rec+ELEM_DATA_OFF, init_data[i], init_len[i]);
    }
    struct script_state st;
    st.main_elems=main_elems; st.main_sp=ninit;
    st.alt_elems=alt_elems; st.alt_sp=0;
    st.script=scr; st.script_len=script_len;
    st.sigversion=sigversion; st.flags=flags;
    st.work=NULL; st.work_cap=0; st.error_out=out_err;
    st.checksig_ctx=NULL; st.checksig_fn=NULL;
    if(out_err) *out_err=0;
    return script_eval(&st);
}

/* Parse the leading push operations of `script` into a stack of byte-strings
 * (the scriptSig "initial stack"). Supports OP_0, direct pushes, PUSHDATA1/2/4,
 * OP_1..OP_16, OP_1NEGATE. Returns number of items, fills *items (pointers into
 * caller buffer 'out' area). */
int parse_pushes(const uint8_t* script, size_t len,
                 const uint8_t* out_data[520], size_t out_len[520])
{
    size_t i=0; int n=0;
    while(i<len){
        uint8_t op=script[i];
        if(op <= 0x4e){
            size_t sz; size_t off;
            if(op < 0x4c){ sz=op; off=i+1; }
            else if(op==0x4c){ if(i+2>len) return n; sz=script[i+1]; off=i+2; }
            else if(op==0x4d){ if(i+3>len) return n; sz=script[i+1]|(script[i+2]<<8); off=i+3; }
            else { if(i+5>len) return n; sz=(size_t)script[i+1]|(script[i+2]<<8)|(script[i+3]<<16)|((size_t)script[i+4]<<24); off=i+5; }
            if(off+sz>len) return n;
            out_data[n]=script+off; out_len[n]=sz; n++;
            i=off+sz;
        } else if(op==0x4f){ /* OP_1NEGATE -> -1 */
            static uint8_t m1[1]={0x81}; out_data[n]=m1; out_len[n]=1; n++; i++;
        } else if(op>=0x51 && op<=0x60){ /* OP_1..OP_16 */
            static uint8_t sbuf[16]; 
            uint8_t val=(uint8_t)(op-0x50);
            sbuf[n&15]=val; out_data[n]=&sbuf[n&15]; out_len[n]=(val?1:0); n++; i++;
        } else {
            break; /* not a push */
        }
    }
    return n;
}
