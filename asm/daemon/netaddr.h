/* daemon/netaddr.h -- one address type for every network a Bitcoin peer can
 * live on (BIP155): IPv4, IPv6, Tor v3, I2P, CJDNS. Core's CNetAddr in
 * miniature: the raw address bytes plus the network id, with Core's string
 * forms (dotted quad, bracketed IPv6, <56 base32>.onion, <52 base32>.b32.i2p,
 * CJDNS as its fc00::/8 IPv6) and the BIP155 / legacy wire records.
 *
 * Until 2026-08-28 this node's whole address model was `unsigned ip` -- one
 * IPv4 in a u32 -- so a Tor/I2P/CJDNS address arriving on the wire had
 * nowhere to go. This is the type everything else (book, codecs, dialer,
 * RPC) is being moved onto. */
#ifndef BMC_NETADDR_H
#define BMC_NETADDR_H

enum { BMC_NET_UNKNOWN = 0, BMC_NET_IPV4 = 1, BMC_NET_IPV6 = 2, BMC_NET_TORV3 = 4,
       BMC_NET_I2P = 5, BMC_NET_CJDNS = 6 };          /* BIP155 network ids */

typedef struct {
    unsigned char  net;        /* BMC_NET_* */
    unsigned char  len;        /* 4 / 16 / 32 / 32 / 16 */
    unsigned char  addr[32];   /* raw bytes, network order; onion = pubkey, i2p = sha256(dest) */
    unsigned short port;       /* HOST order */
} bmc_addr_t;

/* BIP155 length for a network id, or 0 if unknown */
int  bmc_net_addrlen(int net);
const char* bmc_net_name(int net);                  /* "ipv4" "ipv6" "onion" "i2p" "cjdns" */
int  bmc_net_from_name(const char* s);              /* -1 unknown */

/* string forms (Core's): out needs >= 80 bytes. ipv4 "a.b.c.d"; ipv6
 * "2001:db8::1"; onion "<56>.onion"; i2p "<52>.b32.i2p"; cjdns "fc00:..". */
long bmc_addr_to_string(char* out, long cap, const bmc_addr_t* a);
/* "host:port" -- IPv6/CJDNS bracketed as "[..]:port" */
long bmc_addr_to_string_port(char* out, long cap, const bmc_addr_t* a);
/* parse any of the string forms (no port). Validates the onion v3 checksum
 * and version byte exactly as Core's SetTor does. 1 ok / 0 not an address */
int  bmc_addr_from_string(bmc_addr_t* a, const char* s);
/* "host:port" or "[v6]:port" or bare host (port = def) */
int  bmc_addr_from_string_port(bmc_addr_t* a, const char* s, unsigned short def_port);

/* classification */
int  bmc_addr_is_v1_compatible(const bmc_addr_t* a);   /* fits a legacy addr record */
int  bmc_addr_is_routable(const bmc_addr_t* a);        /* public, usable as a peer */
/* group key for per-source quotas: ipv4 /16, ipv6 /32, cjdns /32, onion and
 * i2p each address on its own (Core groups them per address too) */
unsigned long long bmc_addr_group(const bmc_addr_t* a);
int  bmc_addr_equal(const bmc_addr_t* a, const bmc_addr_t* b);  /* addr + port */

/* wire records. BIP155 addrv2 entry:
 *   time u32 LE | services CompactSize | net u8 | addr len CompactSize | addr | port u16 BE
 * legacy addr entry (30 bytes):
 *   time u32 LE | services u64 LE | ip16 (v4 mapped ::ffff:) | port u16 BE
 * Encoders return bytes written (0 if the address does not fit that format);
 * decoders return bytes consumed, or -1 on malformed input / unknown network
 * (Core skips an unknown network id after consuming its declared bytes: a
 * decode returning -2 means "skipped, `consumed` set"). */
long bmc_addr_encode_v2(unsigned char* out, long cap, const bmc_addr_t* a, unsigned long long services, unsigned time);
long bmc_addr_decode_v2(bmc_addr_t* a, unsigned long long* services, unsigned* time,
                        const unsigned char* p, long len, long* consumed);
long bmc_addr_encode_v1(unsigned char* out, long cap, const bmc_addr_t* a, unsigned long long services, unsigned time);
long bmc_addr_decode_v1(bmc_addr_t* a, unsigned long long* services, unsigned* time,
                        const unsigned char* p, long len);
#endif
