# one line per finding: driver name, the product sources it links
one c_locator "$D/serve_invbounds.c"
one c_irs     "$D/index_runs.c"
one c_mpj     "$D/mempool_journal.c"
one c_mpd     "$D/mempool_persist.c"
one c_lsm     "$D/lsm_manifest.c"
one c_addr    "$D/addr_ingest.c $D/netaddr.c $A/base32.c $A/bitcoin_addrmgr.o"
one c_v2      "$A/crypto_bip324_transport.c $A/crypto_bip324.c $A/crypto_bip324_fs.c $A/crypto_chacha20.c $A/crypto_poly1305.c $A/crypto_hkdf.c $A/crypto_ellswift_ecdh.c $A/crypto_ellswift.c $A/crypto_ellswift_enc.c $A/crypto_fe_sqrt.c $A/secp256k1_fe.o $A/secp256k1_point_ct.o $A/sha256.o $A/secp256k1_point.o $A/secp256k1_glv_c.o $A/secp256k1_scalar.o $A/chacha20_avx2.o"
