#include "certificates.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Host-only exercise of the exact installer preparation code; no system writes. */
int main(int argc, char **argv) {
    TlsFixerCertificateBundle bundle;
    if (argc != 5 && argc != 6) return 2;
    const char *url = strcmp(argv[3], "offline") == 0 ? NULL : argv[3];
    long timeout = argc == 6 ? strtol(argv[5], NULL, 10) : 30;
    if (tls_fixer_prepare_certificates(argv[1], argv[2], url, timeout, &bundle) != 0) return 1;
    FILE *file = fopen(argv[4], "wb");
    if (file == NULL) { tls_fixer_free_certificates(&bundle); return 1; }
    int result = fwrite(bundle.data, 1, bundle.size, file) == bundle.size ? 0 : 1;
    if (fclose(file) != 0) result = 1;
    printf("downloaded=%d error=%d http=%ld sony=%zu mozilla=%zu combined=%zu bytes=%zu\n",
        bundle.downloaded, bundle.download_error, bundle.http_status, bundle.sony_count,
        bundle.mozilla_count, bundle.combined_count, bundle.size);
    tls_fixer_free_certificates(&bundle);
    return result;
}
