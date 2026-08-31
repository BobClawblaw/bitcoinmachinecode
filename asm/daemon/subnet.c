/* daemon/subnet.c -- see subnet.h. */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "subnet.h"

/* Zero every bit past `bits`, so a sloppy 10.0.0.1/8 means what it says. */
static void mask_addr(unsigned char* a, int len, int bits){
    for (int i = 0; i < len; i++){
        int keep = bits - i * 8;
        if (keep >= 8) continue;
        a[i] = (unsigned char)(keep <= 0 ? 0 : (a[i] & (0xff << (8 - keep))));
    }
}

/* "[::1]" and "::1" are the same address; both forms are printed here. */
static void strip_brackets(char* s){
    size_t n = strlen(s);
    if (n >= 2 && s[0] == '[' && s[n-1] == ']'){ memmove(s, s+1, n-2); s[n-2] = 0; }
}

int subnet_parse(const char* spec, subnet_t* out){
    if (!spec || !*spec || !out) return 0;
    char buf[128];
    if (strlen(spec) >= sizeof buf) return 0;
    snprintf(buf, sizeof buf, "%s", spec);

    int bits = -1;
    char* slash = strchr(buf, '/');
    if (slash){
        *slash = 0;
        char* end = 0;
        long v = strtol(slash + 1, &end, 10);
        if (!end || *end || v < 0 || v > 128) return 0;
        bits = (int)v;
    }
    strip_brackets(buf);

    memset(out, 0, sizeof *out);
    if (inet_pton(AF_INET, buf, out->addr) == 1){
        out->family = AF_INET;
        if (bits < 0) bits = 32;
        if (bits > 32) return 0;
        mask_addr(out->addr, 4, bits);
    } else if (inet_pton(AF_INET6, buf, out->addr) == 1){
        out->family = AF_INET6;
        if (bits < 0) bits = 128;
        mask_addr(out->addr, 16, bits);
    } else return 0;
    out->bits = bits;
    return 1;
}

int subnet_covers(const subnet_t* net, const char* ip){
    if (!net || !ip || !*ip) return 0;
    char buf[128];
    if (strlen(ip) >= sizeof buf) return 0;
    snprintf(buf, sizeof buf, "%s", ip);
    strip_brackets(buf);
    /* an IPv4 peer string may carry ":port"; a bare IPv6 literal cannot, so
     * only trim when there is exactly one colon. */
    char* colon = strchr(buf, ':');
    if (colon && !strchr(colon + 1, ':')) *colon = 0;

    unsigned char a[16];
    int fam;
    if (inet_pton(AF_INET, buf, a) == 1) fam = AF_INET;
    else if (inet_pton(AF_INET6, buf, a) == 1) fam = AF_INET6;
    else return 0;
    if (fam != net->family) return 0;

    int len = (fam == AF_INET) ? 4 : 16;
    mask_addr(a, len, net->bits);
    return memcmp(a, net->addr, (size_t)len) == 0;
}

int subnet_covers_str(const char* spec, const char* ip){
    subnet_t n;
    if (!subnet_parse(spec, &n)) return 0;
    return subnet_covers(&n, ip);
}
