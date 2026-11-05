/* tests/loopback_alias.h -- for tests whose fake peers need DISTINCT loopback
 * addresses (the downloader's pool and the dial gate tell peers apart by IP,
 * so 127.0.0.1 with several ports is not the same test).
 *
 * Linux routes all of 127.0.0.0/8 to lo. macOS answers only 127.0.0.1 unless
 * the extra addresses are aliased onto lo0 (root, lost at reboot):
 *     sudo ifconfig lo0 alias 127.0.0.2 up   (and .3, .4 as needed)
 * Without them a dial to 127.0.0.2 never completes and such a test hangs
 * until its own timeouts -- 15 minutes for test_dlc_interleave. This check
 * turns that into an immediate, explained SKIP. */
#ifndef BMC_LOOPBACK_ALIAS_H
#define BMC_LOOPBACK_ALIAS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* exits 0 with a SKIP line when 127.0.0.2..127.0.0.<last> cannot be bound */
static inline void require_loopback_aliases(int last){
#ifdef __APPLE__
    for (int h = 2; h <= last; h++){
        int s = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = 0; a.sin_addr.s_addr = htonl(0x7f000000u | (unsigned)h);
        int ok = s >= 0 && bind(s, (struct sockaddr*)&a, sizeof a) == 0;
        if (s >= 0) close(s);
        if (!ok){
            printf("SKIP: 127.0.0.%d is not configured on lo0 (macOS answers only 127.0.0.1 by default).\n"
                   "      This test needs 127.0.0.2..127.0.0.%d. To run it:\n", h, last);
            for (int k = 2; k <= last; k++) printf("        sudo ifconfig lo0 alias 127.0.0.%d up\n", k);
            printf("\nALL TESTS PASSED (0 failures)  [skipped: no loopback aliases]\n");
            exit(0);
        }
    }
#else
    (void)last;                      /* Linux: all of 127.0.0.0/8 is lo */
#endif
}
#endif
