/* netdb.c -- getaddrinfo/freeaddrinfo over the Windows resolver (bmc_win).
 * Replaces musl's (which reads /etc/resolv.conf and /etc/hosts). */
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

typedef struct {
	int family, socktype, protocol, addrlen;
	unsigned char addr[28];
} ws_ai;

__attribute__((ms_abi)) int __bmc_win_getaddrinfo(const char *, const char *, int, int, int, int, ws_ai *, int);

struct node {
	struct addrinfo ai;
	struct sockaddr_storage sa;
};

int getaddrinfo(const char *restrict host, const char *restrict serv, const struct addrinfo *restrict hint,
		struct addrinfo **restrict res)
{
	if (!host && !serv)
		return EAI_NONAME;
	int fam = hint ? hint->ai_family : 0, st = hint ? hint->ai_socktype : 0;
	int pr = hint ? hint->ai_protocol : 0, fl = hint ? hint->ai_flags : 0;
	ws_ai buf[256];
	int n = __bmc_win_getaddrinfo(host, serv, fam, st, pr, fl, buf, 256);
	if (n < 0)
		return n;
	struct node *nodes = calloc((size_t)n, sizeof *nodes);
	if (!nodes)
		return EAI_MEMORY;
	for (int i = 0; i < n; i++) {
		nodes[i].ai.ai_family = buf[i].family;
		nodes[i].ai.ai_socktype = buf[i].socktype;
		nodes[i].ai.ai_protocol = buf[i].protocol;
		nodes[i].ai.ai_addrlen = (socklen_t)buf[i].addrlen;
		memcpy(&nodes[i].sa, buf[i].addr, (size_t)buf[i].addrlen);
		nodes[i].ai.ai_addr = (struct sockaddr *)&nodes[i].sa;
		nodes[i].ai.ai_next = i + 1 < n ? &nodes[i + 1].ai : NULL;
	}
	*res = &nodes[0].ai;
	return 0;
}

/* the whole list is one calloc block headed by its first node */
void freeaddrinfo(struct addrinfo *p)
{
	free(p);
}
