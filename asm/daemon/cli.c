/* daemon/cli.c -- thin C driver over the all-asm S6 CLI (bitcoin_cli.asm).
 *
 *   cli <dir> <command> [args...]
 *
 * Opens the persistent store in <dir> (blk00000.dat + index.dat), reloads the
 * block index, then hands the remaining argv to the assembly cli_main, which
 * parses the command and renders the answer entirely in machine code. This
 * file is only process glue (chdir + store reload + write stdout); the whole
 * command engine lives in bitcoin_cli.asm.
 *
 *   cli /chain getblockcount
 *   cli /chain getbestblockhash
 *   cli /chain getblockhash 3
 *   cli /chain getblock 2
 *   cli /chain gettx <txid64>
 *   cli /chain getbalance
 *   cli /chain help
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

extern long store_init(void* st);
extern long store_reload(void* st);
extern long cli_main(void* st, long argc, void** argv, unsigned char* out, long cap);

static unsigned char store_buf[4096];
static unsigned char out[16<<20];   /* up to 16 MB of CLI output (4MB block -> 8MB hex, plus headroom) */

int main(int argc, char** argv){
    if(argc < 3){ fprintf(stderr, "usage: cli <dir> <command> [args...]\n"); return 2; }
    if(chdir(argv[1])!=0){ perror("chdir"); return 1; }
    if(store_init(store_buf)!=1){ fprintf(stderr,"store_init failed\n"); return 1; }
    if(store_reload(store_buf)!=1){ fprintf(stderr,"store_reload failed\n"); return 1; }
    /* argv[2..] = command + its args; argv[0] (program name) is dropped. */
    long n = cli_main(store_buf, argc-2, (void**)(argv+2), out, (long)sizeof out);
    if(n < 0){ fprintf(stderr, "CLI error\n"); return 1; }
    fwrite(out, 1, (size_t)n, stdout);
    return 0;
}
