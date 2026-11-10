/* ws_net.c -- sockets (bmc_win). Filled in by the network phase. */
#include "winsys.h"

void ws_net_init(void)
{
	WSADATA w;
	WSAStartup(MAKEWORD(2, 2), &w);
}

i64 ws_sock_read(ws_desc *d, void *buf, size_t n)
{
	int r = recv(d->s, buf, n > 0x7fffffff ? 0x7fffffff : (int)n, 0);
	return r == SOCKET_ERROR ? ws_wsaerr(WSAGetLastError()) : r;
}

i64 ws_sock_write(ws_desc *d, const void *buf, size_t n)
{
	int r = send(d->s, buf, n > 0x7fffffff ? 0x7fffffff : (int)n, 0);
	return r == SOCKET_ERROR ? ws_wsaerr(WSAGetLastError()) : r;
}

i64 ws_sys_net(i64 n, i64 a1, i64 a2, i64 a3, i64 a4, i64 a5, i64 a6, int *handled)
{
	(void)n; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
	*handled = 0;
	return 0;
}
