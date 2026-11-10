/* ws_ws2.h -- Winsock reached through a GetProcAddress table (bmc_win).
 *
 * ws2_32 exports POSIX names (accept, connect, recv, freeaddrinfo, ...) that
 * the SysV side defines too (musl, bmc test mocks). Linking ws2_32.lib would
 * put both in one symbol space, so winsys never imports them by name: each
 * call below goes through ws2, filled by ws_ws2_init(). Include after
 * <winsock2.h>/<ws2tcpip.h>. */
#ifndef BMC_WS_WS2_H
#define BMC_WS_WS2_H

#define WS2_FUNCS(X) \
	X(int, WSAStartup, (WORD, LPWSADATA)) \
	X(SOCKET, WSASocketW, (int, int, int, LPWSAPROTOCOL_INFOW, GROUP, DWORD)) \
	X(SOCKET, socket, (int, int, int)) \
	X(int, connect, (SOCKET, const struct sockaddr *, int)) \
	X(int, bind, (SOCKET, const struct sockaddr *, int)) \
	X(int, listen, (SOCKET, int)) \
	X(SOCKET, accept, (SOCKET, struct sockaddr *, int *)) \
	X(int, getpeername, (SOCKET, struct sockaddr *, int *)) \
	X(int, getsockname, (SOCKET, struct sockaddr *, int *)) \
	X(int, send, (SOCKET, const char *, int, int)) \
	X(int, recv, (SOCKET, char *, int, int)) \
	X(int, sendto, (SOCKET, const char *, int, int, const struct sockaddr *, int)) \
	X(int, recvfrom, (SOCKET, char *, int, int, struct sockaddr *, int *)) \
	X(int, WSASendTo, (SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr *, int, \
			   LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE)) \
	X(int, WSARecvFrom, (SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr *, LPINT, \
			     LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE)) \
	X(int, shutdown, (SOCKET, int)) \
	X(int, setsockopt, (SOCKET, int, int, const char *, int)) \
	X(int, getsockopt, (SOCKET, int, int, char *, int *)) \
	X(int, ioctlsocket, (SOCKET, long, u_long *)) \
	X(int, closesocket, (SOCKET)) \
	X(int, WSAPoll, (LPWSAPOLLFD, ULONG, INT)) \
	X(int, WSAGetLastError, (void)) \
	X(u_long, htonl, (u_long)) \
	X(INT, getaddrinfo, (PCSTR, PCSTR, const ADDRINFOA *, PADDRINFOA *)) \
	X(VOID, freeaddrinfo, (PADDRINFOA))

#define WS2_PTR(ret, name, args) ret (WSAAPI *name) args;
struct ws2_table { WS2_FUNCS(WS2_PTR) };
#undef WS2_PTR
extern struct ws2_table ws2;
void ws_ws2_init(void);

#ifndef BMC_WS2_IMPL
#define WSAStartup ws2.WSAStartup
#define WSASocketW ws2.WSASocketW
#define socket ws2.socket
#define connect ws2.connect
#define bind ws2.bind
#define listen ws2.listen
#define accept ws2.accept
#define getpeername ws2.getpeername
#define getsockname ws2.getsockname
#define send ws2.send
#define recv ws2.recv
#define sendto ws2.sendto
#define recvfrom ws2.recvfrom
#define WSASendTo ws2.WSASendTo
#define WSARecvFrom ws2.WSARecvFrom
#define shutdown ws2.shutdown
#define setsockopt ws2.setsockopt
#define getsockopt ws2.getsockopt
#define ioctlsocket ws2.ioctlsocket
#define closesocket ws2.closesocket
#define WSAPoll ws2.WSAPoll
#define WSAGetLastError ws2.WSAGetLastError
#undef htonl
#define htonl ws2.htonl
#define getaddrinfo ws2.getaddrinfo
#define freeaddrinfo ws2.freeaddrinfo
#endif

#endif
