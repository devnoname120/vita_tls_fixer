#define main unused_native_api_suite
#include "test_native_module_api.c"
#undef main
int main(void) {
    identity_nid=0x726c6635; family=0; fail_index=-1;
    assert(tls_fixer_native_module_api_init()==0);
    consumer_query=1; import_header[0]=0x34;
    uint32_t library=0xe8f15cde; memcpy(import_header+16,&library,4);
    consumer_private=1; consumer_sharing=1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==0);
    consumer_private=0; consumer_sharing=0;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_private=1; consumer_sharing=-19;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==0);
    consumer_bad_span=1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_bad_span=0; consumer_bad_type=1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_bad_type=0;
    /* Every populated segment must be private, not just the executable start. */
    consumer_data_shared = 1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_data_shared = 0; consumer_no_text = 1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_no_text = 0; consumer_extra_segment = 1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_extra_segment = 0; consumer_text_perms = 7;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_text_perms = 5; consumer_missing_block = 1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_missing_block = 0; consumer_block_error = -19;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_block_error = 0; consumer_type_error = -20;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_type_error = 1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_type_error = 0; consumer_text_start = 0x7ffff000;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_text_start = 0xe0000000;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_text_start = 0xdffff000; consumer_text_size = 0x1001;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_text_size = 0x1000;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==0);
    consumer_text_start = 0x81000000; consumer_text_size = 0xffffffff;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    consumer_text_size = 0x2000;
    library=0x3d643ce8; memcpy(import_header+16,&library,4);
    consumer_private=0;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    assert(consumer_shared_queries == 0);
    consumer_private=1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==0);
    library=0xdeadbeef; memcpy(import_header+16,&library,4);
    consumer_private=0;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==0);
    consumer_name="ScePspemu"; consumer_private=1;
    assert(tls_fixer_native_http_requires_sony(21,NULL)==1);
    puts("GUI/HTTP consumers: allocation ownership overrides misleading native flag in both directions PASS");
    return 0;
}
