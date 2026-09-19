/* tests/zmq_pub_drill.c -- drives daemon/zmq_pub.c against a REAL libzmq
 * subscriber (tests/zmq_interop.py, pyzmq).
 *
 * This is the test that justifies not linking libzmq. Everything else about
 * the ZMTP implementation could be self-consistent and still wrong: only a
 * subscriber built from the other implementation of the spec can show that
 * the greeting, the READY exchange, the frame flags, the LONG size encoding
 * and the multipart structure are all right. A second reading of the RFC by
 * the same author proves nothing.
 *
 * Publishes a fixed, predictable pattern the Python side asserts against,
 * including a body well over the 255-byte boundary where ZMTP switches from
 * a 1-byte to an 8-byte big-endian length -- the case that matters for real
 * blocks and the easiest one to get wrong.
 *
 *   zmq_pub_drill <addr> <seconds>
 *   zmq_pub_drill <addr> <seconds> queue
 *
 * The `queue` mode is the production shape for tests/zmq_queue_interop.py
 * (MEM-22): the servicing thread runs, and every 250 ms it publishes a
 * hashblock, a 2 MB rawblock and a burst of 200 rawtx -- so a subscriber that
 * stops reading overruns the 1000-message high-water mark within seconds.
 * rawblock body: byte j = (j*7 + 3) & 0xff, then bytes 0-3 overwritten with
 * the block's index (u32 LE).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern int  zmqpub_add(const char* topic, const char* addr);
extern void zmqpub_poll(void);
extern void zmqpub_notify(const char* topic, const void* body, unsigned long blen);
extern int  zmqpub_active(void);

/* The drill's own payloads, mirrored in zmq_interop.py. */
#define BIG_LEN 5000

int main(int argc, char** argv){
    if (argc < 3){ fprintf(stderr, "usage: %s <addr> <seconds>\n", argv[0]); return 2; }
    const char* addr = argv[1];
    double secs = atof(argv[2]);

    /* queue mode configures the high-water marks exactly as the daemon does
     * (node_config's default 1000 per topic, set before the first
     * subscriber), so the drill reproduces production rather than a
     * publisher nobody runs */
    if (argc > 3 && !strcmp(argv[3], "queue")){
        extern void zmq_pub_set_hwm(const int*);
        static const int hwm[5] = { 1000, 1000, 1000, 1000, 1000 };
        zmq_pub_set_hwm(hwm);
    }
    if (!zmqpub_add("hashblock", addr) || !zmqpub_add("hashtx", addr) ||
        !zmqpub_add("rawblock", addr)  || !zmqpub_add("rawtx", addr)){
        fprintf(stderr, "drill: bind failed\n"); return 1;
    }
    if (!zmqpub_active()){ fprintf(stderr, "drill: publisher inactive\n"); return 1; }

    if (argc > 3 && !strcmp(argv[3], "queue")){
        extern int zmqpub_start(void);
        if (!zmqpub_start()){ fprintf(stderr, "drill: no servicing thread\n"); return 1; }
        static unsigned char blk[2 * 1024 * 1024];
        for (int j = 0; j < (int)sizeof blk; j++) blk[j] = (unsigned char)(j * 7 + 3);
        unsigned char tx[300];
        struct timespec q0; clock_gettime(CLOCK_MONOTONIC, &q0);
        struct timespec gs = {1, 0}; nanosleep(&gs, NULL);   /* subscribers attach */
        double worst = 0;
        for (unsigned idx = 0;; idx++){
            struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
            if ((double)(now.tv_sec - q0.tv_sec) > secs) break;
            for (int i = 0; i < 4; i++) blk[i] = (unsigned char)(idx >> (8 * i));
            unsigned char h[32]; memset(h, (int)idx, 32);
            struct timespec a, b; clock_gettime(CLOCK_MONOTONIC, &a);
            zmqpub_notify("hashblock", h, 32);
            zmqpub_notify("rawblock", blk, sizeof blk);
            clock_gettime(CLOCK_MONOTONIC, &b);
            double ms = (double)(b.tv_sec - a.tv_sec) * 1e3 + (double)(b.tv_nsec - a.tv_nsec) / 1e6;
            if (ms > worst) worst = ms;
            for (int k = 0; k < 200; k++){
                memset(tx, k, sizeof tx); tx[0] = (unsigned char)idx;
                zmqpub_notify("rawtx", tx, sizeof tx);
            }
            struct timespec sl = {0, 250*1000*1000};
            nanosleep(&sl, NULL);
        }
        fprintf(stderr, "drill: worst hashblock+2MB rawblock publish %.3f ms\n", worst);
        return 0;
    }

    unsigned char hash[32];
    for (int i = 0; i < 32; i++) hash[i] = (unsigned char)i;

    /* > 255 bytes: forces the 8-byte big-endian length path */
    static unsigned char big[BIG_LEN];
    for (int i = 0; i < BIG_LEN; i++) big[i] = (unsigned char)(i * 7 + 3);

    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;){
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        double el = (double)(now.tv_sec - t0.tv_sec) + (double)(now.tv_nsec - t0.tv_nsec)/1e9;
        if (el > secs) break;

        zmqpub_poll();                 /* accept + handshake subscribers */

        /* Give a connecting subscriber time to finish its handshake before
         * the burst: a PUB socket has no queue for a peer that is not there
         * yet, in this implementation or in libzmq. */
        if (el > 0.5){
            zmqpub_notify("hashblock", hash, 32);
            zmqpub_notify("hashtx",    hash, 32);
            zmqpub_notify("rawblock",  big, BIG_LEN);
            zmqpub_notify("rawtx",     big, BIG_LEN);
        }
        struct timespec sl = {0, 50*1000*1000};
        nanosleep(&sl, NULL);
    }
    return 0;
}
