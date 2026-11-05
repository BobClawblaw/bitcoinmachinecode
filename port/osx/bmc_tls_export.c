/* bmc_tls_export.c -- bmc_tls_alloc (asm/bmc_thread.h) for the port's
 * assembly, which cannot call a static inline.
 *
 * secp256k1_taproot.S keeps a per-thread 4 MiB tap_preimg buffer behind a
 * TLV pointer and malloc'd it on a thread's first use, never freeing it --
 * the same leak BMC_TLS_BUF had (2026-10-08): every short-lived verification
 * thread (txv_verify_all spawns them per 8+-input transaction) that checked a
 * taproot input left 4 MiB behind. Allocating through bmc_tls_alloc puts the
 * buffer on the thread's list, freed by the key destructor at thread exit;
 * the TLV pointer dies with the thread. */
#include <stddef.h>
#include "bmc_thread.h"
void* bmc_tls_alloc_export(size_t size){ return bmc_tls_alloc(size); }
