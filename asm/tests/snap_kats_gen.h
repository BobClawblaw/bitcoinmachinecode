/* GENERATED from a real oracle snapshot (dumptxoutset @964065, 2026-08-25).
 * Each row: a coin decoded from Core's own bytes, and those bytes verbatim.
 * The encoder must reproduce raw_span EXACTLY. Kinds 4/5 (uncompressed
 * P2PK) carry only the x-coordinate in the snapshot, so the full 65-byte
 * key cannot be reconstructed here; those rows pin the DECODED fields and
 * the amount/varint prefix instead (prefix_len bytes of raw_span). */
typedef struct { unsigned int vout; unsigned long height; int coinbase;
    unsigned long long amount; int nsize; const char* spk_hex;
    const char* raw_hex; } snap_kat_t;
static const snap_kat_t SNAP_KATS[] = {
    { 2, 684110, 0, 330ULL, 40, "0020160d0000000000f0558db21dc3e8d765044120f3b6d18c22f5957ad83382521f",
      "02d2c01c8124280020160d0000000000f0558db21dc3e8d765044120f3b6d18c22f5957ad83382521f" },
    { 12, 679159, 0, 8577ULL, 28, "001442307a744d3c7b1ccd2b8c3c78bafa5d695c1e9d",
      "0cd1f26e83da071c001442307a744d3c7b1ccd2b8c3c78bafa5d695c1e9d" },
    { 1, 920268, 0, 251085ULL, 28, "001409e4581b5a796feffc1c4f0669206e801cb7a9eb",
      "01efaa188088f5311c001409e4581b5a796feffc1c4f0669206e801cb7a9eb" },
    { 0, 890664, 0, 93160ULL, 0, "76a914f0f95be137ece93262b4e24ee1313748300226dd88ac",
      "00ebdb50848e0200f0f95be137ece93262b4e24ee1313748300226dd" },
    { 1, 572832, 0, 546ULL, 0, "76a914673dd9d36a11514101656088aac4aef30c21ca3888ac",
      "01c4f540a52f00673dd9d36a11514101656088aac4aef30c21ca38" },
    { 0, 665538, 0, 90000000ULL, 1, "a914642b9094a01a8728f6940f5958c665f1a2118e9587",
      "00d09e045801642b9094a01a8728f6940f5958c665f1a2118e95" },
    { 13, 908377, 0, 24878ULL, 1, "a9146a4f2a955c033b483af9005615ecd68ab154f3bc87",
      "0dedf0328cd41d016a4f2a955c033b483af9005615ecd68ab154f3bc" },
    { 0, 940511, 0, 800ULL, 5, NULL,
      "00f1e63e4905678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6" },
    { 0, 938246, 1, 546ULL, 1, "a91442402a28dd61f2718a4b27ae72a4791d5bbdade787",
      "00f1c30da52f0142402a28dd61f2718a4b27ae72a4791d5bbdade7" },
    { 0, 873964, 1, 546ULL, 1, "a91442402a28dd61f2718a4b27ae72a4791d5bbdade787",
      "00e9d659a52f0142402a28dd61f2718a4b27ae72a4791d5bbdade7" },
    { 0, 84990, 1, 5000000000ULL, 4, NULL,
      "0089ae7d32047a488354d9d5414de09b7121b80b973c991b76998ad68756d8cf4560c0ddcbe2" },
    { 1, 919428, 0, 546ULL, 31, "5c170281e0a6f3c799e206e4c608efff02e807c0a2332a0000",
      "01ef9d08a52f1f5c170281e0a6f3c799e206e4c608efff02e807c0a2332a0000" },
    { 0, 251871, 0, 24320ULL, 2, "2102b6a9c29a27c0b4255c1a12b0fef67c9c467d6306c782daaa8cf65509585e7f3dac",
      "009dde3e80a97a02b6a9c29a27c0b4255c1a12b0fef67c9c467d6306c782daaa8cf65509585e7f3d" },
    { 0, 251832, 0, 999990000ULL, 3, "210305162a589aba9c6c1b99c2877aa6cab84257e5a68b0b39feda94f7835989f9bbac",
      "009ddd70b5f61b0305162a589aba9c6c1b99c2877aa6cab84257e5a68b0b39feda94f7835989f9bb" },
};
