find_package(Threads REQUIRED)
add_library(tls_fixer_vita_mock STATIC vita_mock.c)
target_include_directories(tls_fixer_vita_mock PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(tls_fixer_vita_mock PUBLIC Threads::Threads)
add_executable(tls_fixer_crypto_platform_tests test_crypto_platform.c ../../provider/platform_shims.c)
target_include_directories(tls_fixer_crypto_platform_tests PRIVATE ../../provider)
target_link_libraries(tls_fixer_crypto_platform_tests PRIVATE mbedtls tls_fixer_vita_mock)
target_compile_options(tls_fixer_crypto_platform_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_crypto_platform COMMAND tls_fixer_crypto_platform_tests)
set_tests_properties(tls_fixer_crypto_platform PROPERTIES TIMEOUT 20)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_executable(tls_fixer_transport_tests
    ../../provider/ca_file.c
    test_transport.c
    taihen_mock.c
    ../../provider/cert_hooks.c
    ../../provider/platform_shims.c
    ../../provider/private_mapping.c
    ../../provider/transport.c
    ../../provider/trust_store.c
    ../../provider/vita_net.c
)
target_include_directories(tls_fixer_transport_tests PRIVATE ../../provider)
target_compile_definitions(tls_fixer_transport_tests PRIVATE TLS_FIXER_ENABLE_DEBUG_LOG=0)
target_compile_options(tls_fixer_transport_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(tls_fixer_transport_tests PRIVATE -no-pie)
target_link_libraries(tls_fixer_transport_tests PRIVATE tls_fixer_core mbedtls tls_fixer_vita_mock)
add_test(NAME tls_fixer_transport_loopback
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_loopback.py"
            $<TARGET_FILE:tls_fixer_transport_tests>)
set_tests_properties(tls_fixer_transport_loopback PROPERTIES TIMEOUT 120)

add_executable(tls_fixer_trust_store_tests
    ../../provider/ca_file.c
    test_trust_store.c ../../provider/platform_shims.c ../../provider/trust_store.c)
target_include_directories(tls_fixer_trust_store_tests PRIVATE ../../provider ../../include)
target_link_libraries(tls_fixer_trust_store_tests PRIVATE mbedtls tls_fixer_vita_mock)
target_compile_options(tls_fixer_trust_store_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_trust_store COMMAND tls_fixer_trust_store_tests
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../misc/certs.cer")
set_tests_properties(tls_fixer_trust_store PROPERTIES TIMEOUT 30)
