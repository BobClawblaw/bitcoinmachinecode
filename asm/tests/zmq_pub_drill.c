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

    if (!zmqpub_add("hashblock", addr) || !zmqpub_add("hashtx", addr) ||
        !zmqpub_add("rawblock", addr)  || !zmqpub_add("rawtx", addr)){
        fprintf(stderr, "drill: bind failed\n"); return 1;
    }
    if (!zmqpub_active()){ fprintf(stderr, "drill: publisher inactive\n"); return 1; }

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
