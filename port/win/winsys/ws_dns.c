/* ws_dns.c -- getaddrinfo through the Windows resolver (bmc_win).
 * musl's resolver speaks DNS itself from /etc/resolv.conf, which Windows does
 * not have; rt/netdb.c calls this instead. Results come back as flat records
 * in Linux numbering (AF_INET6 = 10). */
#include "winsys.h"

typedef struct {
	int family, socktype, protocol, addrlen;
	unsigned char addr[28];
} ws_ai;

static int wflags(int f)
{
	return (f & 1 ? AI_PASSIVE : 0) | (f & 2 ? AI_CANONNAME : 0) | (f & 4 ? AI_NUMERICHOST : 0) |
	       (f & 0x400 ? AI_NUMERICSERV : 0) | (f & 0x10 ? AI_ALL : 0) | (f & 0x20 ? AI_ADDRCONFIG : 0) |
	       (f & 8 ? AI_V4MAPPED : 0);
}

static int eai(int e)
{
	switch (e) {
	case WSAHOST_NOT_FOUND: case WSANO_DATA: return -2;      /* EAI_NONAME */
	case WSATRY_AGAIN: return -3;                            /* EAI_AGAIN */
	case WSANO_RECOVERY: return -4;                          /* EAI_FAIL */
	case WSAEAFNOSUPPORT: return -6;                         /* EAI_FAMILY */
	case WSAESOCKTNOSUPPORT: return -7;                      /* EAI_SOCKTYPE */
	case WSATYPE_NOT_FOUND: return -8;                       /* EAI_SERVICE */
	case WSA_NOT_ENOUGH_MEMORY: return -10;                  /* EAI_MEMORY */
	case WSAEINVAL: return -1;                               /* EAI_BADFLAGS */
	default: return -4;
	}
}

WSAPI int __bmc_win_getaddrinfo(const char *node, const char *service, int family, int socktype, int protocol,
				int flags, ws_ai *out, int cap)
{
	ADDRINFOA hints, *res = NULL;
	__ws_memset(&hints, 0, sizeof hints);
	hints.ai_family = family == 10 ? AF_INET6 : family;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;
	hints.ai_flags = wflags(flags);
	int r = getaddrinfo(node, service, &hints, &res);
	if (r)
		return eai(r);
	int n = 0;
	for (ADDRINFOA *p = res; p && n < cap; p = p->ai_next) {
		if ((p->ai_family != AF_INET && p->ai_family != AF_INET6) || p->ai_addrlen > sizeof out[n].addr)
			continue;
		out[n].family = p->ai_family == AF_INET6 ? 10 : p->ai_family;
		out[n].socktype = p->ai_socktype;
		out[n].protocol = p->ai_protocol;
		out[n].addrlen = (int)p->ai_addrlen;
		__ws_memcpy(out[n].addr, p->ai_addr, p->ai_addrlen);
		*(unsigned short *)out[n].addr = (unsigned short)out[n].family;
		n++;
	}
	freeaddrinfo(res);
	return n ? n : -2;
}
