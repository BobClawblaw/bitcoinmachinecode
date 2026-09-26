/* port/osx/test_support/bitcoin_utxo_lsm_badsparse_twin.c -- the Mac stand-in
 * for tests/bitcoin_utxo_lsm_badsparse.o: the LSM with the 2026-09-01
 * lost-tombstones bug (b3d47a9: a flushed run's sparse-index offsets short by
 * the bytes still in the write buffer) compiled back IN, for the negative
 * controls test_lsm_lost_tombstones_bad and test_utxo_lost_tombstones_bad,
 * which are built -DEXPECT_INCIDENT and must reproduce the incident.
 * x86 assembles bitcoin_utxo_lsm.asm with -DLSM_REPRO_BAD_SPARSE; this is the
 * same switch on the Mac twin. Test-only: never part of a daemon. */
#define LSM_REPRO_BAD_SPARSE 1
#include "../utxo_lsm_twin.c"
