#define main unused_native_api_suite
#include "test_native_module_api.c"
#undef main
int main(void) {
    identity_nid=0x726c6635;family=0;fail_index=-1;
    assert(tls_fixer_native_module_api_init()==0);
    consumer_query=1;consumer_sharing=1;consumer_private=0;
    consumer_name="SceCommonDialog";import_header[0]=0x34;
    uint32_t library=0x3d643ce8;memcpy(import_header+16,&library,4);
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_private=1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==0);
    puts("Already-loaded shared indirect GUI consumer blocks private HTTP: PASS");
    return 0;
}
