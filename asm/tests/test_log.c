/* test_log.c -- verify node_log.asm produces the expected structured lines. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "test_tmpdir.h"

extern int  node_log_open(const char* path);
extern void node_log_event(int fd, int kind, unsigned a, unsigned b, unsigned c);
extern void node_log_str(int fd, int kind, const char* s, long len);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e) printf("PASS %s (got %ld)\n",l,g); else { printf("FAIL %s got=%ld exp=%ld\n",l,g,e); failures++; } }

int main(void){
    tt_isolate();   /* fixed /tmp/test_log.txt was shared by every concurrent run */
    const char* path="test_log.txt";
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

    /* A failed open must not hand back fd 0: the writers would then send
     * every line to whatever fd 0 is (stdin, or a socket that reused it).
     * fd 0 is a pipe here; nothing may arrive on it. */
    int pp[2];
    if (pipe(pp) == 0 && dup2(pp[1], 0) == 0){
        close(pp[1]);
        int bad = node_log_open("no-such-dir/test_log.txt");
        cki("failed open returns a negative fd", bad < 0, 1);
        node_log_str(bad, 6, "must not reach fd 0", 19);
        node_log_event(bad, 1, 1, 2, 3);
        close(0);
        fcntl(pp[0], F_SETFL, O_NONBLOCK);
        char b[64]; long got = read(pp[0], b, sizeof b);
        cki("nothing written to fd 0", got > 0 ? got : 0, 0);
        close(pp[0]);
    } else { printf("FAIL pipe/dup2 setup\n"); failures++; }
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    remove(path);
    return failures?1:0;
}
