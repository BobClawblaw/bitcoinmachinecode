/* t_stack.c -- driver for the element-stack engine + get_op + vfexec.
 * Reads scripted lines from argv[1]; appends a per-op transcript to stdout.
 *
 * Stack ops (operate on a shared sp + elems[1024] of ELEM_SIZE=528):
 *   P <hex>          push a new element
 *   PC <idx>         push_copy of record at idx   (reserved)
 *   I <idx> <hex>    insert new element at idx
 *   D <idx>          dup index (push copy of elem at idx)
 *   E <idx>          erase index
 *   X                swap top two
 *   r                pop
 *   d                print depth
 *   T  -> emit top   / 2 -> emit second  / 3 -> emit third
 *   p <idx>          emit elem at idx
 *   R                reset sp to 0
 *
 * get_op line "go <hex>": step the reader over the script, print each
 *   "op=<opcode+1> pushlen=<n>" then "end".
 * vfexec line "vf <seq>": chars '1'=push1 '0'=push0 'p'=pop 'T'=toggle
 *   'd'=print depth 'a'=print all_true 'R'=reset.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ELEM_SIZE 528
#define MAX_STACK 1000
static struct __attribute__((packed)) { uint32_t len; uint8_t data[520]; } elems[1024];
static uint64_t sp = 0;

extern long stack_push(uint64_t*,uint8_t*,const uint8_t*,uint64_t);
extern long stack_push_copy(uint64_t*,uint8_t*,const uint8_t*);
extern long stack_dup_index(uint64_t*,uint8_t*,uint64_t);
extern void stack_erase_index(uint64_t*,uint8_t*,uint64_t);
extern long stack_insert_index(uint64_t*,uint8_t*,uint64_t,const uint8_t*,uint64_t);
extern void stack_swap_two(uint64_t*,uint8_t*);
extern void stack_pop(uint64_t*);
extern long stack_depth(uint64_t*);
extern uint8_t* stack_top_ptr(uint64_t*,uint8_t*);
extern uint8_t* stack_second_ptr(uint64_t*,uint8_t*);
extern uint8_t* stack_third_ptr(uint64_t*,uint8_t*);
extern uint8_t* stack_elem_ptr(uint64_t*,uint8_t*,uint64_t);
extern long get_op(uint64_t*,uint64_t);
extern void vfexec_sp_reset(void);
extern void vfexec_push(uint32_t);
extern void vfexec_pop(void);
extern long vfexec_depth(void);
extern void vfexec_toggle_top(void);
extern long vfexec_all_true(void);

static int hv(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return 0;}
static size_t h2b(const char*h,uint8_t*o,size_t m){size_t n=strlen(h);if(m< n/2) n=m*2;for(size_t i=0;i<n/2;i++)o[i]=(uint8_t)((hv(h[2*i])<<4)|hv(h[2*i+1]));return n/2;}
static void b2h(const uint8_t*d,size_t n,char*o){static const char*X="0123456789abcdef";for(size_t i=0;i<n;i++){o[2*i]=X[d[i]>>4];o[2*i+1]=X[d[i]&15];}o[2*n]=0;}

static void emit(int idx){ /* print e<idx>:<hex> */
    if(idx==(int)sp){ printf("e%d:-\n",idx); return; }
    char out[1100]; b2h(elems[idx].data, elems[idx].len, out);
    printf("e%d:%s\n",idx,out);
}

int main(int ac,char**av){
    if(ac<2)return 2;
    FILE*f=fopen(av[1],"r"); if(!f){perror("open");return 2;}
    char line[16384]; uint8_t tmp[800]; char hexbuf[1100];
    while(fgets(line,sizeof line,f)){
        int done=0;
        char* tok=strtok(line," \t\r\n");
        while(tok && !done){
            if(!strcmp(tok,"go")){
                char*hex=strtok(NULL," \t\r\n"); if(!hex)break;
                size_t n=h2b((hex[0]=='-')?"":hex, tmp,sizeof tmp);
                uint8_t* pc=tmp; uint8_t* pend=tmp+n;
                for(;;){ long rr=get_op((uint64_t*)&pc,(uint64_t)pend); if(!rr){printf("end\n");break;}
                    printf("op=%ld pc=%ld\n", rr, (long)(pc-tmp)); }
                done=1;
            }
            else if(!strcmp(tok,"vf")){
                vfexec_sp_reset();   /* each case starts a fresh eval (as script_eval does) */
                char*s=strtok(NULL," \t\r\n");
                while(s&&*s){switch(*s){
                    case '1': vfexec_push(1);break;
                    case '0': vfexec_push(0);break;
                    case 'p': vfexec_pop();break;
                    case 'T': vfexec_toggle_top();break;
                    case 'd': printf("vdep=%ld\n",vfexec_depth());break;
                    case 'a': printf("vall=%ld\n",vfexec_all_true());break;
                    case 'R': vfexec_sp_reset();break;
                }s++;}
                done=1;
            }
            else if(!strcmp(tok,"R")){ sp=0; }
            else if(!strcmp(tok,"P")){ char*hex=strtok(NULL," \t\r\n"); size_t n=h2b(hex, tmp,sizeof tmp); stack_push(&sp,(uint8_t*)elems,tmp,n); }
            else if(!strcmp(tok,"PC")){ long idx=strtol(strtok(NULL," \t\r\n"),0,10); stack_push_copy(&sp,(uint8_t*)elems,(uint8_t*)&elems[idx]); }
            else if(!strcmp(tok,"D")){ long idx=strtol(strtok(NULL," \t\r\n"),0,10); stack_dup_index(&sp,(uint8_t*)elems,idx); }
            else if(!strcmp(tok,"E")){ long idx=strtol(strtok(NULL," \t\r\n"),0,10); stack_erase_index(&sp,(uint8_t*)elems,idx); }
            else if(!strcmp(tok,"I")){ long idx=strtol(strtok(NULL," \t\r\n"),0,10); char*hex=strtok(NULL," \t\r\n"); size_t n=h2b(hex,tmp,sizeof tmp); stack_insert_index(&sp,(uint8_t*)elems,idx,tmp,n); }
            else if(!strcmp(tok,"X")){ stack_swap_two(&sp,(uint8_t*)elems); }
            else if(!strcmp(tok,"r")){ stack_pop(&sp); }
            else if(!strcmp(tok,"d")){ printf("d=%ld\n",(long)sp); }
            else if(!strcmp(tok,"T")){ uint8_t*p=stack_top_ptr(&sp,(uint8_t*)elems); uint32_t l=*(uint32_t*)p; b2h(p+4,l,hexbuf); printf("t:%s\n",hexbuf); }
            else if(!strcmp(tok,"2")){ uint8_t*p=stack_second_ptr(&sp,(uint8_t*)elems); uint32_t l=*(uint32_t*)p; b2h(p+4,l,hexbuf); printf("s2:%s\n",hexbuf); }
            else if(!strcmp(tok,"3")){ uint8_t*p=stack_third_ptr(&sp,(uint8_t*)elems); uint32_t l=*(uint32_t*)p; b2h(p+4,l,hexbuf); printf("s3:%s\n",hexbuf); }
            else if(!strcmp(tok,"p")){ long idx=strtol(strtok(NULL," \t\r\n"),0,10); uint8_t*p=stack_elem_ptr(&sp,(uint8_t*)elems,idx); uint32_t l=*(uint32_t*)p; b2h(p+4,l,hexbuf); printf("pe%d:%s\n",idx,hexbuf); }
            tok=strtok(NULL," \t\r\n");
        }
    }
    fclose(f); return 0;
}
