/* psbt_update.h -- the PSBT Updater role from descriptors (see psbt_update.c) */
#ifndef BMC_PSBT_UPDATE_H
#define BMC_PSBT_UPDATE_H
#include "descriptor.h"
typedef struct { descr_t* d; long lo, hi; } pu_desc_t;   /* same layout as rpc_commands.c's dpp_desc_t */
/* Adds Core's Updater fields for every input/output a descriptor expansion covers.
 * Returns a malloc'd base64 PSBT, or NULL when nothing was added (or on a parse error). */
char* psbt_update_from_descs(const char* b64, pu_desc_t* dv, int nd);
/* the same on v0-shaped PSBT bytes: returns the new length written to outbuf, 0 when nothing was added, -1 on error */
long psbt_update_bytes_from_descs(const unsigned char* in, long inlen, pu_desc_t* dv, int nd, unsigned char* outbuf, long outcap);
#endif
