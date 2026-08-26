/* rpc_signer.h -- the external signer interface (Core's -signer / HWI);
 * see rpc_signer.c for the protocol and the quoting note. */
#ifndef RPC_SIGNER_H
#define RPC_SIGNER_H
#include "rpc_json.h"

/* The operator's signer command (bitcoin.conf signer=). Empty/NULL detaches;
 * with none configured the methods answer Core's exact
 * "Error: restart bitcoind with -signer=<cmd>". */
void rpc_signer_set_cmd(const char* cmd);
int  rpc_signer_configured(void);

int rpc_signer_enumerate(rj_val** res, long* ec, const char** em);
int rpc_signer_display(const char* fingerprint, const char* desc,
                       rj_val** res, long* ec, const char** em);
#endif
