/* tests/psbt_tapscript_vec.h -- GENERATED, do not edit.
 *
 * A taproot SCRIPT-PATH spend, created and signed by Bitcoin Core v31.99
 * on regtest (2026-09-06) and finalized by Core itself. The descriptor is
 *   tr(NUMS, {pk(leafA), pk(leafB)})
 * with the BIP341 unspendable NUMS point as the internal key, so the ONLY
 * way to spend it is the script path -- which is what forces Core to emit
 * PSBT_IN_TAP_SCRIPT_SIG (0x14) rather than a key-path signature.
 *
 * PSBT_SIGNED_B64 is Core's signed but NOT finalized PSBT
 * (walletprocesspsbt finalize=false). FINAL_TX_HEX is what Core's own
 * finalizepsbt produced from it; testmempoolaccept says allowed=true.
 * Our finalizer has to turn the first into the second, byte for byte. */
#ifndef PSBT_TAPSCRIPT_VEC_H
#define PSBT_TAPSCRIPT_VEC_H
static const char PSBT_SIGNED_B64[] =
    "cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQECAfsEAgAAAAABASsA4fUFAAAAACJRIIYmbt1flx0a"
    "rCn6mcFg7CHFB0w7jV7vFiy/FzZvS3D8QRQI9uJwzwVMOrT559wss0OyA3JldbVc7WhoIwUgKgW7"
    "1nVWh/LWtaNP7+mDXP8bzLxKPUhHNmGjlgrLMaqVsDVaQOcfdHioXGCreUyWkc/7yvjtM4aU5N3X"
    "mUFsXyins1MC6jX4ykaglcxH9kBwY0zBgKHKMnac3NWHdzazBRzaB0ZBFHYg9ayhnzCEy941o2Nb"
    "dUKoxuUCMR5QhRxUVEenM9e1/nBX3NAFXrUXBTfFAl4nrBVQWmXhMJ+nr4hk2Uq37C5AkJHyr5Af"
    "SNVQqZbeEzvwzMCHujum+o2NnYstODQuI3FtVblFwWgTLEyRPDWdMNm0Yd+1JwwvojheLb9WGpNf"
    "BEIVwVCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrA/nBX3NAFXrUXBTfFAl4nrBVQWmXh"
    "MJ+nr4hk2Uq37C4jIAj24nDPBUw6tPnn3CyzQ7IDcmV1tVztaGgjBSAqBbvWrMBCFcFQkpt0waBJ"
    "VLeLS2A16XpeB4paDyjsltVHv+6azoA6wHVWh/LWtaNP7+mDXP8bzLxKPUhHNmGjlgrLMaqVsDVa"
    "IyB2IPWsoZ8whMveNaNjW3VCqMblAjEeUIUcVFRHpzPXtazAIRYI9uJwzwVMOrT559wss0OyA3Jl"
    "dbVc7WhoIwUgKgW71jkBdVaH8ta1o0/v6YNc/xvMvEo9SEc2YaOWCssxqpWwNVpYvXjwVgAAgAEA"
    "AIAAAACAAgAAAAkAAAAhFlCSm3TBoElUt4tLYDXpel4HiloPKOyW1Ue/7prOgDrABQB8Rh5dIRZ2"
    "IPWsoZ8whMveNaNjW3VCqMblAjEeUIUcVFRHpzPXtTkB/nBX3NAFXrUXBTfFAl4nrBVQWmXhMJ+n"
    "r4hk2Uq37C5YvXjwVgAAgAEAAIAAAACAAQAAAAkAAAABFyBQkpt0waBJVLeLS2A16XpeB4paDyjs"
    "ltVHv+6azoA6wAEYIFBivpxPsvUJ13+3sJOFXT9wJN1+PR5kSeqcDjFP0TyRAQ4gXhB9YsoGj0j8"
    "otB0KShm3m8CHHewJXz5EE8Fx5rn6vYBDwQBAAAAARAE/f///wABAwhgWvQFAAAAAAEEIlEgg3Mb"
    "0csW11rCYZhJc3LWS7jPSTp/bQlnG4dQKOQ8qOwAAQMIaoUBAAAAAAABBCJRII1khmPNJ039g5hf"
    "tmEsR65RDnWHeUzBPnFlytmz/k69AA=="
;
static const char FINAL_TX_HEX[] =
    "020000000001015e107d62ca068f48fca2d074292866de6f021c77b0257cf9104f05c79ae7ea"
    "f60100000000fdffffff02605af4050000000022512083731bd1cb16d75ac26198497372d64b"
    "b8cf493a7f6d09671b875028e43ca8ec6a850100000000002251208d648663cd274dfd83985f"
    "b6612c47ae510e7587794cc13e7165cad9b3fe4ebd0340e71f7478a85c60ab794c9691cffbca"
    "f8ed338694e4ddd799416c5f28a7b35302ea35f8ca46a095cc47f64070634cc180a1ca32769c"
    "dcd5877736b3051cda0746222008f6e270cf054c3ab4f9e7dc2cb343b203726575b55ced6868"
    "2305202a05bbd6ac41c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9a"
    "ce803ac0fe7057dcd0055eb5170537c5025e27ac15505a65e1309fa7af8864d94ab7ec2e0000"
    "0000"
;
#endif
