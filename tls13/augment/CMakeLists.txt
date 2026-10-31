cmake_minimum_required(VERSION 3.16)
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "Vita toolchain")
endif()
project(tls_fixer_http_augment_probe C)
include("$ENV{VITASDK}/share/vita.cmake" REQUIRED)

option(TLS_FIXER_BUILD_EMBEDDED_HTTP "Build the experimental embedded TLS payload" OFF)
option(TLS_FIXER_BUILD_AUGMENTED_MODULE "Construct the quiet experimental Sony HTTP module" OFF)
option(TLS_FIXER_EMBEDDED_MBEDTLS36 "Use the isolated Mbed TLS 3.6 comparison backend" OFF)
option(TLS_FIXER_EMBEDDED_TRACE "Record embedded HTTP diagnostics in a separate experimental build" OFF)
option(TLS_FIXER_EMBEDDED_COMPARE_HTTP "Compare accepted PSN auth request bytes without recording their contents" OFF)
option(TLS_FIXER_EMBEDDED_NATIVE_CONTROL "Diagnostic comparison using Sony transport inside the augmented image" OFF)
option(TLS_FIXER_EMBEDDED_LOWERCASE_SNI_CONTROL "Diagnostic comparison using lowercase DNS names in Mbed TLS" OFF)
option(TLS_FIXER_EMBEDDED_NO_SNI_CONTROL "Diagnostic comparison omitting SNI while retaining hostname verification" OFF)
option(TLS_FIXER_EMBEDDED_AUTH_TLS12_CONTROL "Diagnostic comparison restricting Shell auth to TLS 1.2" OFF)
option(TLS_FIXER_EMBEDDED_AUTH_RSA_CONTROL "Diagnostic comparison using the native auth cipher with Mbed TLS" OFF)
option(TLS_FIXER_NATIVE_HELLO_EXPERIMENT "Diagnostic comparison with the complete native auth offer" OFF)
option(TLS_FIXER_NATIVE_HELLO_PROFILE "Select the native handshake through explicit private HTTPS options" OFF)
set(TLS_FIXER_EMBEDDED_TRACE_HOST "" CACHE STRING "Explicit private LAN receiver address")
set(TLS_FIXER_EMBEDDED_TRACE_NONCE "" CACHE STRING "128-bit hexadecimal capture nonce")
set(TLS_FIXER_EMBEDDED_TRACE_PORT 19013 CACHE STRING "Diagnostic UDP receiver port")
if(TLS_FIXER_BUILD_AUGMENTED_MODULE AND
   (NOT TLS_FIXER_BUILD_EMBEDDED_HTTP OR NOT TLS_FIXER_RESTORE_RSA_CLIENT OR
    NOT TLS_FIXER_NATIVE_HELLO_PROFILE OR TLS_FIXER_EMBEDDED_MBEDTLS36 OR
    TLS_FIXER_EMBEDDED_TRACE OR TLS_FIXER_EMBEDDED_COMPARE_HTTP OR
    TLS_FIXER_EMBEDDED_NATIVE_CONTROL OR TLS_FIXER_NATIVE_HELLO_EXPERIMENT OR
    TLS_FIXER_EMBEDDED_AUTH_TLS12_CONTROL OR TLS_FIXER_EMBEDDED_AUTH_RSA_CONTROL OR
    TLS_FIXER_EMBEDDED_NO_SNI_CONTROL OR TLS_FIXER_EMBEDDED_LOWERCASE_SNI_CONTROL))
    message(FATAL_ERROR "Augmented module requires the quiet Mbed TLS 4.2 private-option profile")
endif()
if(TLS_FIXER_BUILD_EMBEDDED_HTTP)
    if(TLS_FIXER_NATIVE_HELLO_PROFILE AND
       (NOT TLS_FIXER_RESTORE_RSA_CLIENT OR TLS_FIXER_EMBEDDED_MBEDTLS36 OR TLS_FIXER_NATIVE_HELLO_EXPERIMENT))
        message(FATAL_ERROR "Private API handshake profile requires the restored 4.2 backend without the host selector")
    endif()
    if(TLS_FIXER_NATIVE_HELLO_EXPERIMENT AND
       (NOT TLS_FIXER_EMBEDDED_TRACE OR
        (NOT TLS_FIXER_EMBEDDED_MBEDTLS36 AND NOT TLS_FIXER_RESTORE_RSA_CLIENT) OR
        TLS_FIXER_EMBEDDED_NATIVE_CONTROL OR TLS_FIXER_EMBEDDED_AUTH_TLS12_CONTROL OR
        TLS_FIXER_EMBEDDED_AUTH_RSA_CONTROL OR TLS_FIXER_EMBEDDED_NO_SNI_CONTROL OR
        TLS_FIXER_EMBEDDED_LOWERCASE_SNI_CONTROL))
        message(FATAL_ERROR "Native hello experiment requires traced RSA-capable transport without other controls")
    endif()
    if(TLS_FIXER_EMBEDDED_COMPARE_HTTP AND NOT TLS_FIXER_EMBEDDED_TRACE)
        message(FATAL_ERROR "HTTP transport comparison requires diagnostic tracing")
    endif()
    if(TLS_FIXER_EMBEDDED_COMPARE_HTTP)
        execute_process(COMMAND "$ENV{VITASDK}/bin/vita-libs-gen" -c
            "${CMAKE_CURRENT_SOURCE_DIR}/native_tls_trace.yml" "${CMAKE_CURRENT_BINARY_DIR}/native-tls-stubs"
            RESULT_VARIABLE native_trace_stub_result)
        if(NOT native_trace_stub_result EQUAL 0)
            message(FATAL_ERROR "Cannot generate native TLS comparison stubs")
        endif()
        add_subdirectory("${CMAKE_CURRENT_BINARY_DIR}/native-tls-stubs"
            "${CMAKE_CURRENT_BINARY_DIR}/native-tls-stubs-build")
    endif()
    if(TLS_FIXER_EMBEDDED_NATIVE_CONTROL AND NOT TLS_FIXER_EMBEDDED_TRACE)
        message(FATAL_ERROR "Native transport control is diagnostic-only")
    endif()
    if(TLS_FIXER_EMBEDDED_AUTH_TLS12_CONTROL AND
       (NOT TLS_FIXER_EMBEDDED_TRACE OR TLS_FIXER_EMBEDDED_NATIVE_CONTROL OR
        TLS_FIXER_EMBEDDED_NO_SNI_CONTROL OR TLS_FIXER_EMBEDDED_LOWERCASE_SNI_CONTROL))
        message(FATAL_ERROR "Auth TLS1.2 control requires traced Mbed transport without other controls")
    endif()
    if(TLS_FIXER_EMBEDDED_AUTH_RSA_CONTROL AND
       (NOT TLS_FIXER_EMBEDDED_MBEDTLS36 OR NOT TLS_FIXER_EMBEDDED_AUTH_TLS12_CONTROL))
        message(FATAL_ERROR "Auth RSA control requires the isolated 3.6 backend and TLS1.2 auth control")
    endif()
    if(TLS_FIXER_EMBEDDED_LOWERCASE_SNI_CONTROL AND
       (NOT TLS_FIXER_EMBEDDED_TRACE OR TLS_FIXER_EMBEDDED_NATIVE_CONTROL))
        message(FATAL_ERROR "Lowercase SNI control requires traced Mbed transport")
    endif()
    if(TLS_FIXER_EMBEDDED_NO_SNI_CONTROL AND
       (NOT TLS_FIXER_EMBEDDED_TRACE OR TLS_FIXER_EMBEDDED_NATIVE_CONTROL OR TLS_FIXER_EMBEDDED_LOWERCASE_SNI_CONTROL))
        message(FATAL_ERROR "No-SNI control requires traced Mbed transport without another control")
    endif()
    if(TLS_FIXER_EMBEDDED_MBEDTLS36)
        add_subdirectory(mbed36/crypto crypto)
    else()
        # HTTP writes are capped at 1500 bytes. A 16 KiB outgoing record buffer
        # per connection exhausts the 128 KiB TLS heap during concurrent Store
        # handshakes. Keep the standard 16 KiB incoming limit; only trim the
        # unused outgoing capacity in this backend (the Browser is separate).
        add_compile_definitions(MBEDTLS_SSL_OUT_CONTENT_LEN=2048)
        set(TLS_FIXER_SMALL_RX_BUFFER ON CACHE BOOL "Small receive allocations" FORCE)
        add_subdirectory(../crypto crypto)
        set(TLS_FIXER_CRYPTO_PLATFORM_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/../provider/platform_shims.c")
        if(TLS_FIXER_BUILD_AUGMENTED_MODULE)
            FetchContent_GetProperties(tls_fixer_mbedtls SOURCE_DIR embedded_crypto_source)
            foreach(target mbedtls mbedx509 tfpsacrypto)
                target_compile_options(${target} PRIVATE
                    "-ffile-prefix-map=${embedded_crypto_source}=mbedtls")
            endforeach()
        endif()
    endif()
    if(TLS_FIXER_EMBEDDED_NO_SNI_CONTROL)
        foreach(target mbedtls mbedx509 tfpsacrypto)
            target_compile_definitions(${target} PUBLIC TLS_FIXER_DIAGNOSTIC_NO_SNI=1)
        endforeach()
    endif()
    add_library(tls_fixer_embedded_core STATIC
        ../src/cert_registry.c ../src/cert_policy.c ../src/error_map.c ../src/module_gate.c
        ../src/host_map.c ../src/redirect_list.c ../src/path.c
        ../src/registry.c ../src/x509_names.c)
    target_include_directories(tls_fixer_embedded_core PUBLIC ../include)
    target_compile_definitions(tls_fixer_embedded_core PUBLIC TLS_FIXER_DYNAMIC_REGISTRY=1)
    target_compile_options(tls_fixer_embedded_core PRIVATE -O2 -ffunction-sections -fdata-sections)
    add_executable(tls_fixer_http_embedded
        embedded.c embedded_cert.c embedded_redirect.c embedded_profile.c hello_policy.c native_cert.c cert_facade.c
        ../provider/ca_index.c ../provider/ca_file.c ../provider/game_ca.c
        ${TLS_FIXER_CRYPTO_PLATFORM_SOURCE} ../provider/transport.c ../provider/trust_store.c
        ../provider/user_runtime.c ../provider/vita_net.c)
    if(NOT TLS_FIXER_EMBEDDED_MBEDTLS36)
        target_sources(tls_fixer_http_embedded PRIVATE ../provider/user_runtime_growth.c)
        target_compile_definitions(tls_fixer_http_embedded PRIVATE TLS_FIXER_RUNTIME_GROWTH=1)
        set_source_files_properties(../provider/user_runtime_growth.c PROPERTIES COMPILE_OPTIONS "-fno-builtin")
    endif()
    target_include_directories(tls_fixer_http_embedded PRIVATE . ../provider ../include)
    target_compile_options(tls_fixer_http_embedded PRIVATE -std=gnu11 -O2
        -Wall -Wextra -Werror -ffunction-sections -fdata-sections)
    set_source_files_properties(../provider/user_runtime.c PROPERTIES COMPILE_OPTIONS "-fno-builtin")
    target_compile_definitions(tls_fixer_http_embedded PRIVATE
        TLS_FIXER_ENABLE_DEBUG_LOG=$<BOOL:${TLS_FIXER_EMBEDDED_TRACE}> TLS_FIXER_EMBEDDED_HTTP=1
        TLS_FIXER_EMBEDDED_COMPARE_HTTP=$<BOOL:${TLS_FIXER_EMBEDDED_COMPARE_HTTP}>
        TLS_FIXER_EMBEDDED_NATIVE_CONTROL=$<BOOL:${TLS_FIXER_EMBEDDED_NATIVE_CONTROL}>
        TLS_FIXER_NATIVE_HELLO_EXPERIMENT=$<BOOL:${TLS_FIXER_NATIVE_HELLO_EXPERIMENT}>
        TLS_FIXER_NATIVE_HELLO_PROFILE=$<BOOL:${TLS_FIXER_NATIVE_HELLO_PROFILE}>
        TLS_FIXER_DEFAULT_CA_PATH="vs0:/data/external/cert/CA_LIST.cer")
    if(TLS_FIXER_EMBEDDED_LOWERCASE_SNI_CONTROL)
        target_compile_definitions(tls_fixer_http_embedded PRIVATE TLS_FIXER_DIAGNOSTIC_LOWERCASE_SNI=1)
    endif()
    if(TLS_FIXER_EMBEDDED_AUTH_TLS12_CONTROL)
        target_compile_definitions(tls_fixer_http_embedded PRIVATE TLS_FIXER_DIAGNOSTIC_AUTH_TLS12=1)
    endif()
    if(TLS_FIXER_EMBEDDED_AUTH_RSA_CONTROL)
        target_compile_definitions(tls_fixer_http_embedded PRIVATE TLS_FIXER_DIAGNOSTIC_AUTH_RSA=1)
    endif()
    set(embedded_config "${CMAKE_CURRENT_SOURCE_DIR}/embedded.yml")
    if(TLS_FIXER_EMBEDDED_TRACE)
        string(LENGTH "${TLS_FIXER_EMBEDDED_TRACE_NONCE}" nonce_length)
        if(NOT TLS_FIXER_EMBEDDED_TRACE_HOST MATCHES "^192\\.168\\.[0-9]+\\.[0-9]+$" OR
           NOT nonce_length EQUAL 32 OR NOT TLS_FIXER_EMBEDDED_TRACE_NONCE MATCHES "^[0-9a-fA-F]+$" OR
           TLS_FIXER_EMBEDDED_TRACE_PORT LESS 1024 OR TLS_FIXER_EMBEDDED_TRACE_PORT GREATER 65535)
            message(FATAL_ERROR "Experimental tracing needs a private LAN receiver and fresh 128-bit nonce")
        endif()
        target_sources(tls_fixer_http_embedded PRIVATE embedded_trace.c)
        target_compile_definitions(tls_fixer_http_embedded PRIVATE TLS_FIXER_FILE_LOG=1
            TLS_FIXER_TRACE_COMPONENT="embedded" TLS_FIXER_TRACE_RECORD_LIMIT=4096
            TLS_FIXER_EMBEDDED_TRACE_HOST="${TLS_FIXER_EMBEDDED_TRACE_HOST}"
            TLS_FIXER_EMBEDDED_TRACE_NONCE="${TLS_FIXER_EMBEDDED_TRACE_NONCE}"
            TLS_FIXER_EMBEDDED_TRACE_PORT=${TLS_FIXER_EMBEDDED_TRACE_PORT})
        target_link_options(tls_fixer_http_embedded PRIVATE -Wl,--undefined=tls_fixer_embedded_parse_header
            -Wl,--undefined=tls_fixer_embedded_set_stack_observer)
        file(READ "${embedded_config}" embedded_yaml)
        string(REPLACE "      variables:" "        - tls_fixer_embedded_parse_header: 0x03A6C89E\n        - tls_fixer_embedded_set_stack_observer: 0x7F10B005\n      variables:"
            embedded_yaml "${embedded_yaml}")
        set(embedded_config "${CMAKE_CURRENT_BINARY_DIR}/embedded-trace.yml")
        file(WRITE "${embedded_config}" "${embedded_yaml}")
    endif()
    target_link_options(tls_fixer_http_embedded PRIVATE -nostdlib -Wl,--gc-sections
        -Wl,-e,module_start -Wl,--defsym=__sce_headroom=8192
        -Wl,--undefined=module_start -Wl,--undefined=module_stop
        -Wl,--undefined=g_tls_fixer_embedded_bindings -Wl,--undefined=tls_fixer_embedded_stats
        -Wl,--undefined=tls_fixer_embedded_active
        -Wl,-Map=${CMAKE_CURRENT_BINARY_DIR}/embedded.map)
    set(embedded_exports http_init http_term load_cert unload_cert create_connection create_connection_url
        create_request_url enable_private disable_private copy_settings destroy_settings
        free_failed_connection free_failed_request
        create connect map_io read write shutdown)
    foreach(function ${embedded_exports})
        target_link_options(tls_fixer_http_embedded PRIVATE "-Wl,--undefined=tls_fixer_embedded_${function}")
    endforeach()
    foreach(function malloc calloc realloc free memchr memcmp memcpy memmove memset
                     strchr strcmp strlen strstr printf puts snprintf vsnprintf)
        target_link_options(tls_fixer_http_embedded PRIVATE "-Wl,--wrap=${function}")
    endforeach()
    set(TLS_FIXER_EMBEDDED_KERNEL_STUB ""
        CACHE FILEPATH "Optional redirect reader syscall weak stub")
    if(TLS_FIXER_EMBEDDED_KERNEL_STUB STREQUAL "")
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/redirects_imports.yml")
        execute_process(COMMAND "$ENV{VITASDK}/bin/vita-libs-gen" -c
            "${CMAKE_CURRENT_SOURCE_DIR}/redirects_imports.yml"
            "${CMAKE_CURRENT_BINARY_DIR}/redirect-stubs"
            RESULT_VARIABLE redirects_stub_result)
        if(NOT redirects_stub_result EQUAL 0)
            message(FATAL_ERROR "Cannot generate the optional redirect reader import")
        endif()
        add_subdirectory("${CMAKE_CURRENT_BINARY_DIR}/redirect-stubs"
            "${CMAKE_CURRENT_BINARY_DIR}/redirect-stubs-build")
        set(embedded_redirect_stub tls_fixer_kernel_stub_weak)
    else()
        if(NOT TLS_FIXER_EMBEDDED_KERNEL_STUB MATCHES "_stub_weak\\.a$")
            message(FATAL_ERROR "Embedded HTTP needs the weak redirect reader stub to load without a coordinator")
        endif()
        set(embedded_redirect_stub "${TLS_FIXER_EMBEDDED_KERNEL_STUB}")
    endif()
    target_link_libraries(tls_fixer_http_embedded PRIVATE tls_fixer_embedded_core mbedtls mbedx509 tfpsacrypto
        ${embedded_redirect_stub} gcc SceAppMgr_stub SceSysmem_stub SceNet_stub
        SceIofilemgr_stub SceRtc_stub SceLibKernel_stub SceKernelThreadMgr_stub)
    if(TLS_FIXER_EMBEDDED_COMPARE_HTTP)
        target_link_libraries(tls_fixer_http_embedded PRIVATE SceLibSsl_374_stub_weak)
    endif()
    set(VITA_ELF_CREATE_FLAGS "")
    vita_create_self(tls_fixer_http_embedded.suprx tls_fixer_http_embedded
        CONFIG ${embedded_config} UNSAFE)
    if(TLS_FIXER_BUILD_AUGMENTED_MODULE)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        set(TLS_FIXER_AUGMENTED_NATIVE_HTTP "${CMAKE_CURRENT_SOURCE_DIR}/../../misc/lhttp.suprx"
            CACHE FILEPATH "Original Sony HTTP input validated by the offline merger")
        get_filename_component(augmented_native "${TLS_FIXER_AUGMENTED_NATIVE_HTTP}" ABSOLUTE)
        set(augmented_dir "${CMAKE_CURRENT_BINARY_DIR}/augmented")
        set(augment_tools "${CMAKE_CURRENT_SOURCE_DIR}/../../tools")
        add_custom_command(
            OUTPUT "${augmented_dir}/libhttp.suprx" "${augmented_dir}/libhttp.elf"
                "${augmented_dir}/libhttp.json"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${augmented_dir}"
            COMMAND ${CMAKE_COMMAND} -E remove -f "${augmented_dir}/libhttp.next.elf"
                "${augmented_dir}/libhttp.next.json" "${augmented_dir}/libhttp.next.suprx"
            COMMAND ${Python3_EXECUTABLE} "${augment_tools}/augment_libhttp.py"
                --native "${augmented_native}"
                --payload "${CMAKE_CURRENT_BINARY_DIR}/tls_fixer_http_embedded.velf"
                --output "${augmented_dir}/libhttp.next.elf"
                --report "${augmented_dir}/libhttp.next.json" --mode tls
            COMMAND "$ENV{VITASDK}/bin/vita-make-fself" -c -a 0x2f00000000000001
                "${augmented_dir}/libhttp.next.elf" "${augmented_dir}/libhttp.next.suprx"
            COMMAND ${Python3_EXECUTABLE} "${augment_tools}/check_http_runtime.py"
                "${augmented_dir}/libhttp.next.suprx" --native-http "${augmented_native}"
            # Stage the merged ELF and SELF before publishing the module.
            COMMAND ${CMAKE_COMMAND} -E rename "${augmented_dir}/libhttp.next.elf"
                "${augmented_dir}/libhttp.elf"
            COMMAND ${CMAKE_COMMAND} -E rename "${augmented_dir}/libhttp.next.json"
                "${augmented_dir}/libhttp.json"
            COMMAND ${CMAKE_COMMAND} -E rename "${augmented_dir}/libhttp.next.suprx"
                "${augmented_dir}/libhttp.suprx"
            DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/tls_fixer_http_embedded.velf" "${augmented_native}"
                "${augment_tools}/augment_libhttp.py" "${augment_tools}/firmware_matrix.py"
                "${augment_tools}/check_http_runtime.py"
            VERBATIM)
        add_custom_target(tls_fixer_augmented_http
            DEPENDS "${augmented_dir}/libhttp.suprx" "${augmented_dir}/libhttp.elf"
                "${augmented_dir}/libhttp.json")
        add_dependencies(tls_fixer_augmented_http tls_fixer_http_embedded-velf)
    endif()
endif()
# Separate offline target. Nothing from this directory enters the installer.
add_executable(tls_fixer_http_augment_probe lifecycle_probe.c)
target_compile_options(tls_fixer_http_augment_probe PRIVATE -std=c11 -Wall -Wextra -Werror
    -O2 -ffreestanding -fno-builtin -ffunction-sections -fdata-sections)
target_link_options(tls_fixer_http_augment_probe PRIVATE -nostdlib -Wl,--gc-sections -Wl,-e,module_start
    -Wl,--undefined=module_start -Wl,--undefined=module_stop
    -Wl,--undefined=tls_fixer_augment_probe_snapshot -Wl,--undefined=g_tls_fixer_augment_probe)
set(VITA_ELF_CREATE_FLAGS "-n") # The lifecycle-only payload intentionally has no imports.
vita_create_self(tls_fixer_http_augment_probe.suprx tls_fixer_http_augment_probe
    CONFIG ${CMAKE_CURRENT_SOURCE_DIR}/lifecycle_probe.yml UNSAFE)

option(TLS_FIXER_BUILD_AUGMENT_APP "Build the separate private-loader test application" OFF)
option(TLS_FIXER_AUGMENT_SHARED_CHECK "Use the native shared open/close APIs in the test app" OFF)
option(TLS_FIXER_AUGMENT_CERT_CHECK "Check conversion to native certificate objects" OFF)
option(TLS_FIXER_AUGMENT_CERT_FACADE_CHECK "Use the metadata facade with native inspection APIs" OFF)
option(TLS_FIXER_AUGMENT_TLS_CHECK "Run HTTPS through the embedded module" OFF)
option(TLS_FIXER_AUGMENT_CUSTOM_CA_CHECK "Exercise per-app CA load/unload against a controlled test server" OFF)
option(TLS_FIXER_AUGMENT_SMALL_STACK_CHECK "Measure initialization with small system-app caller stacks" OFF)
option(TLS_FIXER_AUGMENT_PRIVATE_PROFILE_CHECK "Exercise native private/public option inheritance on controlled endpoints" OFF)
option(TLS_FIXER_AUGMENT_DEPENDENCY_ONLY "Inspect native dependencies and exit without loading augmented HTTP" OFF)
set(TLS_FIXER_AUGMENT_MODULE_PATH "ux0:/data/tls_fixer-augment/http-embedded.suprx"
    CACHE STRING "Separately staged module for the diagnostic app")
if(TLS_FIXER_BUILD_AUGMENT_APP)
    if(TLS_FIXER_AUGMENT_PRIVATE_PROFILE_CHECK AND NOT TLS_FIXER_AUGMENT_CUSTOM_CA_CHECK)
        message(FATAL_ERROR "Private profile checks require the controlled CA fixtures")
    endif()
    if((TLS_FIXER_AUGMENT_CUSTOM_CA_CHECK OR TLS_FIXER_AUGMENT_SMALL_STACK_CHECK) AND NOT TLS_FIXER_AUGMENT_TLS_CHECK)
        message(FATAL_ERROR "The custom CA test requires the embedded TLS lifecycle test")
    endif()
    add_executable(tls_fixer_augment_check check_vita.c)
    target_compile_options(tls_fixer_augment_check PRIVATE -std=gnu11 -Wall -Wextra -Werror -O2)
    # Link-time address spacing for the SCE tables appended by vita-elf-create.
    # This does not reserve additional runtime heap or load-segment memory.
    target_link_options(tls_fixer_augment_check PRIVATE -Wl,--defsym=__sce_headroom=4096)
    target_compile_definitions(tls_fixer_augment_check PRIVATE
        TLS_FIXER_AUGMENT_MODULE_PATH="${TLS_FIXER_AUGMENT_MODULE_PATH}"
        TLS_FIXER_AUGMENT_SHARED_CHECK=$<BOOL:${TLS_FIXER_AUGMENT_SHARED_CHECK}>
        TLS_FIXER_AUGMENT_CERT_CHECK=$<BOOL:${TLS_FIXER_AUGMENT_CERT_CHECK}>
        TLS_FIXER_AUGMENT_CERT_FACADE_CHECK=$<BOOL:${TLS_FIXER_AUGMENT_CERT_FACADE_CHECK}>
        TLS_FIXER_AUGMENT_CUSTOM_CA_CHECK=$<BOOL:${TLS_FIXER_AUGMENT_CUSTOM_CA_CHECK}>
        TLS_FIXER_AUGMENT_SMALL_STACK_CHECK=$<BOOL:${TLS_FIXER_AUGMENT_SMALL_STACK_CHECK}>
        TLS_FIXER_AUGMENT_PRIVATE_PROFILE_CHECK=$<BOOL:${TLS_FIXER_AUGMENT_PRIVATE_PROFILE_CHECK}>
        TLS_FIXER_AUGMENT_DEPENDENCY_ONLY=$<BOOL:${TLS_FIXER_AUGMENT_DEPENDENCY_ONLY}>
        TLS_FIXER_AUGMENT_TLS_CHECK=$<BOOL:${TLS_FIXER_AUGMENT_TLS_CHECK}>)
    if(TLS_FIXER_AUGMENT_CERT_CHECK)
        target_sources(tls_fixer_augment_check PRIVATE native_cert.c cert_facade.c check_cert_vita.c)
    endif()
    if(TLS_FIXER_AUGMENT_TLS_CHECK)
        target_sources(tls_fixer_augment_check PRIVATE check_tls_vita.c)
    endif()
    if(TLS_FIXER_AUGMENT_CUSTOM_CA_CHECK)
        target_sources(tls_fixer_augment_check PRIVATE check_ca_vita.c)
    endif()
    if(TLS_FIXER_AUGMENT_SMALL_STACK_CHECK)
        target_sources(tls_fixer_augment_check PRIVATE check_stack_vita.c)
    endif()
    target_link_libraries(tls_fixer_augment_check PRIVATE taihen_stub SceSysmodule_stub
        SceKernelModulemgr_stub SceLibKernel_stub SceNet_stub SceNetCtl_stub
        SceIofilemgr_stub SceSysmem_stub)
    set(VITA_ELF_CREATE_FLAGS "")
    vita_create_self(tls_fixer_augment_check.self tls_fixer_augment_check UNSAFE)
    vita_create_vpk(tls_fixer_augment_check.vpk TLSAUG001 tls_fixer_augment_check.self
        VERSION "00.01" NAME "tls_fixer Module Check")
endif()
