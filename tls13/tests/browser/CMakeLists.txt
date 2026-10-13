add_executable(tls_fixer_browser_config_tests test_config.c ../../browser/config.c)
target_link_libraries(tls_fixer_browser_config_tests PRIVATE tls_fixer_core)
target_compile_options(tls_fixer_browser_config_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_browser_config COMMAND tls_fixer_browser_config_tests)

add_executable(tls_fixer_browser_config_runtime_tests test_config.c ../../browser/config.c)
target_link_libraries(tls_fixer_browser_config_runtime_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_browser_config_runtime_tests PRIVATE
    TLS_FIXER_ENABLE_RUNTIME_UDP=1 TLS_FIXER_TEST_CONFIG_RUNTIME=1)
target_compile_options(tls_fixer_browser_config_runtime_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_browser_config_runtime COMMAND tls_fixer_browser_config_runtime_tests)

add_executable(tls_fixer_browser_config_diagnostics_tests test_config.c ../../browser/config.c)
target_link_libraries(tls_fixer_browser_config_diagnostics_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_browser_config_diagnostics_tests PRIVATE
    TLS_FIXER_ENABLE_RUNTIME_UDP=1 TLS_FIXER_TEST_CONFIG_RUNTIME=1
    TLS_FIXER_ENABLE_DEBUG_LOG=1 TLS_FIXER_BROWSER_FILE_LOG=1 TLS_FIXER_TEST_CONFIG_DIAGNOSTICS=1)
target_compile_options(tls_fixer_browser_config_diagnostics_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_browser_config_diagnostics COMMAND tls_fixer_browser_config_diagnostics_tests)

add_executable(tls_fixer_browser_backend_tests test_backend.c ../../browser/backend.c
    ../../browser/config.c ../../provider/ca_file.c ../../provider/platform_shims.c)
target_include_directories(tls_fixer_browser_backend_tests PRIVATE ../../browser ../../provider)
target_link_libraries(tls_fixer_browser_backend_tests PRIVATE tls_fixer_core mbedtls tls_fixer_vita_mock)
target_compile_definitions(tls_fixer_browser_backend_tests PRIVATE TLS_FIXER_ENABLE_DEBUG_LOG=0)
target_compile_options(tls_fixer_browser_backend_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(tls_fixer_browser_backend_tests PRIVATE -no-pie)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME tls_fixer_browser_loopback COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_browser_loopback.py" $<TARGET_FILE:tls_fixer_browser_backend_tests>)
set_tests_properties(tls_fixer_browser_loopback PROPERTIES TIMEOUT 120)

add_executable(tls_fixer_browser_memory_tests test_backend.c memory_tracker.c ../../browser/backend.c
    ../../browser/config.c ../../provider/ca_file.c ../../provider/platform_shims.c)
target_include_directories(tls_fixer_browser_memory_tests PRIVATE ../../browser ../../provider)
target_link_libraries(tls_fixer_browser_memory_tests PRIVATE tls_fixer_core mbedtls tls_fixer_vita_mock)
target_compile_definitions(tls_fixer_browser_memory_tests PRIVATE TLS_FIXER_ENABLE_DEBUG_LOG=0
    TLS_FIXER_BROWSER_MEMORY_TEST=1)
target_compile_options(tls_fixer_browser_memory_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(tls_fixer_browser_memory_tests PRIVATE -no-pie -Wl,--wrap=malloc -Wl,--wrap=calloc
    -Wl,--wrap=realloc -Wl,--wrap=free)
add_test(NAME tls_fixer_browser_memory COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_browser_loopback.py" $<TARGET_FILE:tls_fixer_browser_memory_tests>
    --scenario memory-full-ca)
set_tests_properties(tls_fixer_browser_memory PROPERTIES TIMEOUT 120)

add_executable(tls_fixer_browser_lazy_ca_tests test_lazy_ca.c ../../browser/backend.c
    ../../browser/config.c ../../provider/platform_shims.c)
target_include_directories(tls_fixer_browser_lazy_ca_tests PRIVATE ../../browser ../../provider)
target_link_libraries(tls_fixer_browser_lazy_ca_tests PRIVATE tls_fixer_core mbedtls tls_fixer_vita_mock)
target_compile_definitions(tls_fixer_browser_lazy_ca_tests PRIVATE TLS_FIXER_ENABLE_DEBUG_LOG=0)
target_compile_options(tls_fixer_browser_lazy_ca_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(tls_fixer_browser_lazy_ca_tests PRIVATE -no-pie -Wl,--wrap=tls_fixer_load_ca_file)
foreach(scenario IN ITEMS init legacy failure)
    add_test(NAME tls_fixer_browser_lazy_ca_${scenario} COMMAND tls_fixer_browser_lazy_ca_tests ${scenario})
endforeach()

add_executable(tls_fixer_browser_module_tests test_module.c ../../browser/module.c
    ../../browser/webkit_callback.c)
target_include_directories(tls_fixer_browser_module_tests PRIVATE ../../browser ../../provider ../transport/include)
target_link_libraries(tls_fixer_browser_module_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_browser_module_tests PRIVATE TLS_FIXER_HOST_MODULE_TEST=1 TLS_FIXER_ENABLE_DEBUG_LOG=0)
target_compile_options(tls_fixer_browser_module_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid bad-args bad-id bad-name bad-size bad-path bad-site-0 bad-site-1 bad-site-2 bad-site-3 bad-site-4 bad-site-5 hook-0 hook-1 hook-2 hook-3
    bad-buffer bad-arg-size bad-version bad-reserved bad-negative-id bad-address bad-text-memsz bad-data-filesz bad-data-memsz init-fail)
    add_test(NAME tls_fixer_browser_module_${scenario} COMMAND tls_fixer_browser_module_tests ${scenario})
endforeach()

add_executable(tls_fixer_startdiag_tests test_module.c ../../browser/module.c
    ../../browser/webkit_callback.c)
target_include_directories(tls_fixer_startdiag_tests PRIVATE ../../browser ../../provider ../transport/include)
target_link_libraries(tls_fixer_startdiag_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_startdiag_tests PRIVATE TLS_FIXER_HOST_MODULE_TEST=1
    TLS_FIXER_ENABLE_DEBUG_LOG=0 TLS_FIXER_BROWSER_START_DIAGNOSTICS=1)
target_compile_options(tls_fixer_startdiag_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid bad-args bad-id bad-name bad-size bad-path bad-site-0 bad-site-1 bad-site-2
    bad-site-3 bad-site-4 bad-site-5 hook-0 hook-1 hook-2 hook-3 bad-buffer bad-arg-size
    bad-version bad-reserved bad-negative-id bad-address bad-text-memsz bad-data-filesz bad-data-memsz init-fail)
    add_test(NAME tls_fixer_startdiag_${scenario} COMMAND tls_fixer_startdiag_tests ${scenario})
endforeach()

add_executable(tls_fixer_webkit_callback_diagnostics_tests test_module.c ../../browser/module.c
    ../../browser/webkit_callback.c)
target_include_directories(tls_fixer_webkit_callback_diagnostics_tests PRIVATE
    ../../browser ../../provider ../transport/include)
target_link_libraries(tls_fixer_webkit_callback_diagnostics_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_webkit_callback_diagnostics_tests PRIVATE TLS_FIXER_HOST_MODULE_TEST=1
    TLS_FIXER_ENABLE_DEBUG_LOG=1 TLS_FIXER_BROWSER_FILE_LOG=1 TLS_FIXER_TEST_WEBKIT_DIAGNOSTICS=1
    TLS_FIXER_ENABLE_RUNTIME_UDP=1)
target_compile_options(tls_fixer_webkit_callback_diagnostics_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_webkit_callback_diagnostics COMMAND tls_fixer_webkit_callback_diagnostics_tests valid)

add_library(tls_fixer_startdiag_paths OBJECT ../../src/path.c)
target_include_directories(tls_fixer_startdiag_paths PRIVATE ../../include)
target_compile_definitions(tls_fixer_startdiag_paths PRIVATE TLS_FIXER_BROWSER_START_DIAGNOSTICS=1)
target_compile_options(tls_fixer_startdiag_paths PRIVATE -Wall -Wextra -Werror)
add_executable(tls_fixer_startdiag_path_tests ../test_browser_startdiag_paths.c $<TARGET_OBJECTS:tls_fixer_startdiag_paths>)
target_include_directories(tls_fixer_startdiag_path_tests PRIVATE ../../include)
target_compile_definitions(tls_fixer_startdiag_path_tests PRIVATE TLS_FIXER_BROWSER_START_DIAGNOSTICS=1)
target_compile_options(tls_fixer_startdiag_path_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_startdiag_paths COMMAND tls_fixer_startdiag_path_tests)

add_executable(tls_fixer_startdiag_backend_tests test_startdiag_backend.c ../../browser/backend.c
    ../../browser/config.c ../../provider/ca_file.c ../../provider/platform_shims.c)
target_include_directories(tls_fixer_startdiag_backend_tests PRIVATE ../../browser ../../provider)
target_link_libraries(tls_fixer_startdiag_backend_tests PRIVATE tls_fixer_core mbedtls tls_fixer_vita_mock)
target_compile_definitions(tls_fixer_startdiag_backend_tests PRIVATE TLS_FIXER_ENABLE_DEBUG_LOG=0
    TLS_FIXER_BROWSER_START_DIAGNOSTICS=1)
target_compile_options(tls_fixer_startdiag_backend_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(symbol tls_fixer_crypto_platform_init psa_crypto_init tls_fixer_load_ca_file
    sceKernelCreateMutex sceKernelDeleteMutex tls_fixer_registry_init)
    target_link_options(tls_fixer_startdiag_backend_tests PRIVATE "-Wl,--wrap=${symbol}")
endforeach()
foreach(scenario valid argument platform psa ca registry-mutex attach-mutex registry)
    add_test(NAME tls_fixer_startdiag_backend_${scenario} COMMAND tls_fixer_startdiag_backend_tests ${scenario})
endforeach()

foreach(kind route loader)
    set(sources ../kernel/test_browser_activation_${kind}.c)
    if(kind STREQUAL "loader")
        list(APPEND sources ../../../kernel/tls13_loader.c)
    endif()
    add_executable(tls_fixer_startdiag_kernel_${kind}_tests ${sources} $<TARGET_OBJECTS:tls_fixer_startdiag_paths>)
    target_include_directories(tls_fixer_startdiag_kernel_${kind}_tests PRIVATE
        ../kernel/include ../transport/include ../../../kernel)
    target_link_libraries(tls_fixer_startdiag_kernel_${kind}_tests PRIVATE tls_fixer_core)
    target_compile_definitions(tls_fixer_startdiag_kernel_${kind}_tests PRIVATE TLS_FIXER_ENABLE_BOOT_TRACE=1
        TLS_FIXER_TRACE_MODULE_PATHS=1 TLS_FIXER_BROWSER_ACTIVATION=1 TLS_FIXER_PREPARE_NAME_QUERY=1
        TLS_FIXER_PREPARE_EXTENDED_STACK=1 TLS_FIXER_BROWSER_START_DIAGNOSTICS=1)
    target_compile_options(tls_fixer_startdiag_kernel_${kind}_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME tls_fixer_startdiag_kernel_${kind} COMMAND tls_fixer_startdiag_kernel_${kind}_tests)
endforeach()

add_executable(tls_fixer_trace_tests test_trace.c ../../provider/trace.c)
target_include_directories(tls_fixer_trace_tests PRIVATE ../../provider)
target_link_libraries(tls_fixer_trace_tests PRIVATE tls_fixer_vita_mock)
target_compile_options(tls_fixer_trace_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario primary fallback unavailable short-write write-error)
    add_test(NAME tls_fixer_browser_trace_${scenario} COMMAND tls_fixer_trace_tests ${scenario})
endforeach()

add_executable(tls_fixer_http_trace_tests test_trace.c ../../provider/trace.c)
target_include_directories(tls_fixer_http_trace_tests PRIVATE ../../provider)
target_link_libraries(tls_fixer_http_trace_tests PRIVATE tls_fixer_vita_mock)
target_compile_definitions(tls_fixer_http_trace_tests PRIVATE
    TLS_FIXER_TRACE_COMPONENT="http" TLS_FIXER_TRACE_RECORD_LIMIT=4096)
target_compile_options(tls_fixer_http_trace_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario primary fallback unavailable short-write write-error)
    add_test(NAME tls_fixer_http_trace_${scenario} COMMAND tls_fixer_http_trace_tests ${scenario})
endforeach()

add_executable(tls_fixer_browser_passthrough_tests test_module.c ../../browser/module.c
    ../../browser/webkit_callback.c)
target_include_directories(tls_fixer_browser_passthrough_tests PRIVATE ../../browser ../../provider ../transport/include)
target_link_libraries(tls_fixer_browser_passthrough_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_browser_passthrough_tests PRIVATE TLS_FIXER_HOST_MODULE_TEST=1
    TLS_FIXER_ENABLE_DEBUG_LOG=0 TLS_FIXER_BROWSER_START_DIAGNOSTICS=1 TLS_FIXER_BROWSER_PASSTHROUGH_ONLY=1)
target_compile_options(tls_fixer_browser_passthrough_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid bad-args bad-id bad-name bad-size bad-path bad-site-0 init-fail hook-0 hook-1 hook-2 hook-3)
    add_test(NAME tls_fixer_browser_passthrough_${scenario} COMMAND tls_fixer_browser_passthrough_tests ${scenario})
endforeach()

add_executable(tls_fixer_passthrough_integration_tests test_passthrough_integration.c
    ../../browser/module.c ../../browser/webkit_callback.c ../../browser/backend.c ../../browser/config.c
    ../../provider/ca_file.c ../../provider/platform_shims.c)
target_include_directories(tls_fixer_passthrough_integration_tests PRIVATE ../../browser ../../provider)
target_link_libraries(tls_fixer_passthrough_integration_tests PRIVATE tls_fixer_core mbedtls tls_fixer_vita_mock)
target_compile_definitions(tls_fixer_passthrough_integration_tests PRIVATE TLS_FIXER_HOST_MODULE_TEST=1
    TLS_FIXER_ENABLE_DEBUG_LOG=0 TLS_FIXER_BROWSER_START_DIAGNOSTICS=1 TLS_FIXER_BROWSER_PASSTHROUGH_ONLY=1)
target_compile_options(tls_fixer_passthrough_integration_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_options(tls_fixer_passthrough_integration_tests PRIVATE -Wl,--wrap=sceNetSend -Wl,--wrap=sceNetRecv)
foreach(scenario terminal chain concurrent hook-0 hook-1 hook-2 hook-3)
    add_test(NAME tls_fixer_passthrough_integration_${scenario} COMMAND tls_fixer_passthrough_integration_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/../../../misc/certs.cer" ${scenario})
    set_tests_properties(tls_fixer_passthrough_integration_${scenario} PROPERTIES TIMEOUT 30)
endforeach()

add_executable(tls_fixer_browser_initialize_only_tests test_module.c ../../browser/module.c
    ../../browser/webkit_callback.c)
target_include_directories(tls_fixer_browser_initialize_only_tests PRIVATE ../../browser ../../provider ../transport/include)
target_link_libraries(tls_fixer_browser_initialize_only_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_browser_initialize_only_tests PRIVATE TLS_FIXER_HOST_MODULE_TEST=1
    TLS_FIXER_ENABLE_DEBUG_LOG=0 TLS_FIXER_BROWSER_START_DIAGNOSTICS=1 TLS_FIXER_BROWSER_PASSTHROUGH_ONLY=1
    TLS_FIXER_BROWSER_INITIALIZE_ONLY=1)
target_compile_options(tls_fixer_browser_initialize_only_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid bad-args bad-id bad-name bad-size bad-path bad-site-0 bad-site-1 bad-site-2
    bad-site-3 bad-site-4 bad-site-5 hook-0 hook-1 hook-2 hook-3 bad-buffer bad-arg-size
    bad-version bad-reserved bad-negative-id bad-address bad-text-memsz bad-data-filesz bad-data-memsz init-fail)
    add_test(NAME tls_fixer_browser_initialize_only_${scenario} COMMAND tls_fixer_browser_initialize_only_tests ${scenario})
endforeach()

foreach(mask 0 1 2 3 4 8 12 15)
    set(target tls_fixer_browser_hook_selection_${mask}_tests)
    add_executable(${target} test_hook_selection.c ../../browser/module.c
        ../../browser/webkit_callback.c)
    target_include_directories(${target} PRIVATE ../../browser ../../provider ../transport/include)
    target_link_libraries(${target} PRIVATE tls_fixer_core)
    target_compile_definitions(${target} PRIVATE TLS_FIXER_HOST_MODULE_TEST=1 TLS_FIXER_ENABLE_DEBUG_LOG=0
        TLS_FIXER_BROWSER_START_DIAGNOSTICS=1 TLS_FIXER_BROWSER_PASSTHROUGH_ONLY=1 TLS_FIXER_BROWSER_HOOK_MASK=${mask})
    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    foreach(failure -1 0 1 2 3)
        add_test(NAME tls_fixer_browser_hook_selection_${mask}_${failure} COMMAND ${target} ${failure})
    endforeach()
endforeach()

find_package(Threads REQUIRED)
add_executable(tls_fixer_runtime_udp_tests test_runtime_udp.c ../../browser/runtime_udp.c)
target_include_directories(tls_fixer_runtime_udp_tests PRIVATE ../../browser ../transport/include)
target_link_libraries(tls_fixer_runtime_udp_tests PRIVATE Threads::Threads)
target_compile_definitions(tls_fixer_runtime_udp_tests PRIVATE TLS_FIXER_ENABLE_RUNTIME_UDP=1
    TLS_FIXER_RUNTIME_HOST="192.168.1.249" TLS_FIXER_RUNTIME_PORT=52154
    TLS_FIXER_RUNTIME_NONCE_HEX="000102030405060708090a0b0c0d0e0f")
target_compile_options(tls_fixer_runtime_udp_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid invalid-stage no-errno socket-fail address-fail send-fail reentry limit concurrent)
    add_test(NAME tls_fixer_runtime_udp_${scenario} COMMAND tls_fixer_runtime_udp_tests ${scenario})
endforeach()

add_executable(tls_fixer_runtime_native_errno_tests test_runtime_udp.c ../../browser/runtime_udp.c)
target_include_directories(tls_fixer_runtime_native_errno_tests PRIVATE ../../browser ../transport/include)
target_link_libraries(tls_fixer_runtime_native_errno_tests PRIVATE Threads::Threads)
target_compile_definitions(tls_fixer_runtime_native_errno_tests PRIVATE TLS_FIXER_ENABLE_RUNTIME_UDP=1
    TLS_FIXER_RUNTIME_USE_SCE_LIBC=1 TLS_FIXER_RUNTIME_HOST="192.168.1.249" TLS_FIXER_RUNTIME_PORT=52154
    TLS_FIXER_RUNTIME_NONCE_HEX="000102030405060708090a0b0c0d0e0f")
target_compile_options(tls_fixer_runtime_native_errno_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid invalid-stage no-errno no-libc-errno socket-fail address-fail send-fail reentry limit concurrent)
    add_test(NAME tls_fixer_runtime_native_errno_${scenario} COMMAND tls_fixer_runtime_native_errno_tests ${scenario})
endforeach()

add_executable(tls_fixer_runtime_hook_tests test_runtime_hooks.c ../../browser/module.c
    ../../browser/webkit_callback.c)
target_include_directories(tls_fixer_runtime_hook_tests PRIVATE ../../browser ../../provider ../transport/include)
target_link_libraries(tls_fixer_runtime_hook_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_runtime_hook_tests PRIVATE TLS_FIXER_HOST_MODULE_TEST=1
    TLS_FIXER_ENABLE_DEBUG_LOG=0 TLS_FIXER_ENABLE_RUNTIME_UDP=1)
target_compile_options(tls_fixer_runtime_hook_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_runtime_hook_passthrough COMMAND tls_fixer_runtime_hook_tests valid)

add_executable(tls_fixer_runtime_backend_tests test_runtime_backend.c ../../browser/backend.c
    ../../browser/config.c ../../provider/ca_file.c ../../provider/platform_shims.c)
target_include_directories(tls_fixer_runtime_backend_tests PRIVATE ../../browser ../../provider)
target_link_libraries(tls_fixer_runtime_backend_tests PRIVATE tls_fixer_core mbedtls tls_fixer_vita_mock)
target_compile_definitions(tls_fixer_runtime_backend_tests PRIVATE TLS_FIXER_ENABLE_DEBUG_LOG=0 TLS_FIXER_ENABLE_RUNTIME_UDP=1)
target_compile_options(tls_fixer_runtime_backend_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(tls_fixer_runtime_backend_tests PRIVATE -no-pie)
add_test(NAME tls_fixer_runtime_browser_loopback COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_browser_loopback.py" $<TARGET_FILE:tls_fixer_runtime_backend_tests>)
set_tests_properties(tls_fixer_runtime_browser_loopback PROPERTIES TIMEOUT 120)
