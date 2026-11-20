/* ws_ws2.c -- fills the Winsock table (see ws_ws2.h). */
#define BMC_WS2_IMPL
#include "winsys.h"

struct ws2_table ws2;

void ws_ws2_init(void)
{
	HMODULE m = LoadLibraryW(L"ws2_32.dll");
	if (!m)
		ws_fatal("cannot load ws2_32.dll");
#define WS2_LOAD(ret, name, args) \
	if (!(ws2.name = (ret (WSAAPI *) args)(void *)GetProcAddress(m, #name))) \
		ws_fatal("ws2_32.dll lacks " #name);
	WS2_FUNCS(WS2_LOAD)
#undef WS2_LOAD
}
