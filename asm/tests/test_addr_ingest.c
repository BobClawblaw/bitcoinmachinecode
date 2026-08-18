/* Live test: does getaddr actually bring back peers from a REAL node?
 * Deliberately hits the network -- a synthetic pass would prove nothing about
 * wire-format handling against real implementations. */
#include <stdio.h>
#include <string.h>
extern int  amr_init(void* ab);
extern long amr_count(void* ab);
extern long addr_gather_from(void* ab, const char* ip_str, int wait_s);

static unsigned char ab[1<<22];

int main(int argc, char** argv){
    if(argc<2){ fprintf(stderr,"usage: %s <peer-ip> [more...]\n",argv[0]); return 2; }
    amr_init(ab);
    printf("book starts at %ld\n", amr_count(ab));
    int wins=0;
    for(int i=1;i<argc;i++){
        long before=amr_count(ab);
        long got=addr_gather_from(ab, argv[i], 25);
        long after=amr_count(ab);
        printf("  %-16s -> +%ld  (book %ld -> %ld)\n", argv[i], got, before, after);
        if(got>0) wins++;
    }
    long total=amr_count(ab);
    printf("\nfinal book: %ld entries from %d peer(s) asked, %d responded\n", total, argc-1, wins);
    if(total>0 && wins>0){ printf("PASS: getaddr returned real peers\n"); return 0; }
    printf("FAIL: no peers harvested\n");
    return 1;
}
