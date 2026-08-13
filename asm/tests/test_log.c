/* test_log.c -- verify node_log.asm produces the expected structured lines. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern int  node_log_open(const char* path);
extern void node_log_event(int fd, int kind, unsigned a, unsigned b, unsigned c);
extern void node_log_str(int fd, int kind, const char* s, long len);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e) printf("PASS %s (got %ld)\n",l,g); else { printf("FAIL %s got=%ld exp=%ld\n",l,g,e); failures++; } }

int main(void){
    const char* path="/tmp/test_log.txt";
    remove(path);
    int fd = node_log_open(path);
    cki("log open fd>=0", fd>0, 1);
    node_log_event(fd, 1, 70016, 1, 0);          /* HSHK protocol services */
    node_log_event(fd, 2, 2000, 162003, 750001); /* HDRS count bytes from */
    node_log_event(fd, 3, 5, 209, 1);            /* BLOCK idx len ok */
    node_log_event(fd, 4, 1, 1, 0);              /* CONS ok */
    node_log_event(fd, 5, 1, 0, 0);              /* STORE */
    node_log_str(fd, 6, "getdata no-match for block", 26);
    FILE* f=fopen(path,"r");
    char line[256];
    int n=0;
    if(f){ while(fgets(line,sizeof line,f)){ line[strcspn(line,"\n")]=0; printf("  |%s|\n", line); n++; } fclose(f); }
    cki("6 lines logged", n, 6);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    remove(path);
    return failures?1:0;
}
