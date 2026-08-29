/* daemon/asmap.h -- Core's -asmap. Maps an IP to its AS number so the address
 * book can bucket by AS instead of /16. See asmap.c for the bytecode format. */
#ifndef BMC_ASMAP_H
#define BMC_ASMAP_H
/* Load Core's asmap file. 1 on success; failure is never fatal -- the caller
 * falls back to /16 bucketing. */
int  asmap_load(const char* path);
void asmap_unload(void);
int  asmap_active(void);
unsigned long asmap_size(void);
/* ASN for an address, or 0 when there is no map or no answer (0 is not a
 * valid ASN, which is how Core signals "unknown" too).
 * nbytes: 4 for IPv4, 16 for IPv6. */
unsigned asmap_lookup(const unsigned char* ip, int nbytes);
/* What Core actually looks up: an IPv4 is mapped into ::ffff: form first,
 * because the trie is built over 128-bit space. Returns 0 for onion/i2p. */
unsigned asmap_lookup_net(int net, const unsigned char* addr, int len);
/* the interpreter against an explicit buffer -- for tests */
unsigned asmap_lookup_raw(const unsigned char* code, unsigned long codelen,
                          const unsigned char* ip, int nbytes);
#endif
