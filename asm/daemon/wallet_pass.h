/* daemon/wallet_pass.h -- where the daemon gets the wallet passphrase.
 *
 * Deliberately NOT <store>.pass any more: see wallet_pass.c. */
#ifndef BMC_WALLET_PASS_H
#define BMC_WALLET_PASS_H

/* Load the passphrase into out[cap]. Returns 1 if one was found, 0 if not.
 * *why (optional) is set to a short explanation on refusal, for logging --
 * a passphrase file that is silently ignored is worse than none at all,
 * because the operator believes the wallet will unlock. */
int wallet_pass_load(char* out, int cap, const char** why);

/* Warn once if a legacy <store>.pass sits in the datadir. The daemon no
 * longer reads it, and leaving it there pairs the ciphertext with its key in
 * one directory -- and in any backup of that directory. */
void wallet_pass_warn_legacy(const char* store_path);
#endif
