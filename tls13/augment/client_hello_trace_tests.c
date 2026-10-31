#include "client_hello_trace.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    unsigned char tls[64] = {22,3,1,0,59,1,0,0,55,3,3};
    unsigned char ssl2[46] = {0x80,44,1,3,3,0,3,0,0,0,32};
    TlsFixerHelloView view = {0};
    assert(tls_fixer_hello_view(tls, sizeof(tls), &view) && view.format == 3 && view.version == 0x303 && view.bytes == 64);
    for (size_t n = 0; n < sizeof(tls); ++n) assert(!tls_fixer_hello_view(tls,n,&view));
    assert(tls_fixer_hello_view(ssl2, sizeof(ssl2), &view) && view.format == 2 && view.bytes == 46);
    for (size_t n = 0; n < sizeof(ssl2); ++n) assert(!tls_fixer_hello_view(ssl2,n,&view));
    tls[0] = 23; assert(!tls_fixer_hello_view(tls,sizeof(tls),&view)); tls[0] = 22;
    tls[5] = 2; assert(!tls_fixer_hello_view(tls,sizeof(tls),&view)); tls[5] = 1;
    tls[6] = 255; assert(!tls_fixer_hello_view(tls,sizeof(tls),&view)); tls[6] = 0;
    ssl2[6] = 4; assert(!tls_fixer_hello_view(ssl2,sizeof(ssl2),&view));
    assert(!tls_fixer_hello_view(NULL,64,&view) && !tls_fixer_hello_view(tls,64,NULL));
    unsigned char oversized[4097] = {0}; memcpy(oversized,tls,sizeof(tls));
    assert(!tls_fixer_hello_view(oversized,sizeof(oversized),&view));
    puts("ClientHello capture validates framing, truncation, type and limits");
    return 0;
}
