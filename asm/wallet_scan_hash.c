/* link shim: wscan_sha256d over the project's proven sha256d */
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
void wscan_sha256d(unsigned char out[32], const void* data, unsigned long len){
    sha256d(out, data, len);
}
