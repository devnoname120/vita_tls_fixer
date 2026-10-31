find_package(Threads REQUIRED)
if(NOT DEFINED TLS_FIXER_CRYPTO_PLATFORM_SOURCE)
    set(TLS_FIXER_CRYPTO_PLATFORM_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/../../provider/platform_shims.c")
endif()
if(NOT DEFINED TLS_FIXER_CRYPTO_PLATFORM_TEST_SOURCE)
    set(TLS_FIXER_CRYPTO_PLATFORM_TEST_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/test_crypto_platform.c")
endif()
add_library(tls_fixer_vita_mock STATIC vita_mock.c)
target_include_directories(tls_fixer_vita_mock PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(tls_fixer_vita_mock PUBLIC Threads::Threads)
add_executable(tls_fixer_crypto_platform_tests ${TLS_FIXER_CRYPTO_PLATFORM_TEST_SOURCE} ${TLS_FIXER_CRYPTO_PLATFORM_SOURCE})
target_include_directories(tls_fixer_crypto_platform_tests PRIVATE ../../provider)
target_link_libraries(tls_fixer_crypto_platform_tests PRIVATE mbedtls tls_fixer_vita_mock)
target_compile_options(tls_fixer_crypto_platform_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_crypto_platform COMMAND tls_fixer_crypto_platform_tests)
set_tests_properties(tls_fixer_crypto_platform PROPERTIES TIMEOUT 20)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_executable(tls_fixer_hello_policy_tests ../../augment/hello_policy.c ../../augment/hello_policy_tests.c)
target_compile_options(tls_fixer_hello_policy_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_hello_policy COMMAND tls_fixer_hello_policy_tests)
if(TLS_FIXER_RESTORE_RSA_CLIENT AND TLS_FIXER_NATIVE_HELLO_EXPERIMENT)
    add_executable(native_clienthello_test ../../augment/mbed36/native_clienthello_test.c
        ${TLS_FIXER_CRYPTO_PLATFORM_SOURCE})
    target_include_directories(native_clienthello_test PRIVATE ../../provider)
    target_link_libraries(native_clienthello_test PRIVATE mbedtls tls_fixer_vita_mock)
    target_compile_options(native_clienthello_test PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME native_clienthello COMMAND native_clienthello_test)
endif()
add_executable(tls_fixer_transport_tests
    ../../provider/ca_index.c ../../provider/ca_file.c
    test_transport.c
    taihen_mock.c
    ../../provider/game_ca.c
    ../../provider/cert_hooks.c
    ${TLS_FIXER_CRYPTO_PLATFORM_SOURCE}
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
            $<TARGET_FILE:tls_fixer_transport_tests> ${TLS_FIXER_TRANSPORT_TEST_ARGUMENTS})
set_tests_properties(tls_fixer_transport_loopback PROPERTIES TIMEOUT 120)

add_executable(tls_fixer_trust_store_tests
    ../../provider/ca_index.c ../../provider/ca_file.c
    test_trust_store.c ${TLS_FIXER_CRYPTO_PLATFORM_SOURCE} ../../provider/trust_store.c)
target_include_directories(tls_fixer_trust_store_tests PRIVATE ../../provider ../../include)
target_link_libraries(tls_fixer_trust_store_tests PRIVATE mbedtls tls_fixer_vita_mock)
target_compile_options(tls_fixer_trust_store_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_trust_store COMMAND tls_fixer_trust_store_tests
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../misc/certs.cer")
set_tests_properties(tls_fixer_trust_store PROPERTIES TIMEOUT 30)

add_executable(tls_fixer_exact_trust_tests test_exact_trust.c ../../provider/ca_index.c ${TLS_FIXER_CRYPTO_PLATFORM_SOURCE})
target_include_directories(tls_fixer_exact_trust_tests PRIVATE ../../provider ../../include)
target_link_libraries(tls_fixer_exact_trust_tests PRIVATE mbedtls tls_fixer_vita_mock)
target_compile_options(tls_fixer_exact_trust_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_exact_trust COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_exact_trust.py" $<TARGET_FILE:tls_fixer_exact_trust_tests>)
set_tests_properties(tls_fixer_exact_trust PROPERTIES TIMEOUT 120)

add_executable(tls_fixer_game_ca_tests test_game_ca.c taihen_mock.c
    ../../provider/game_ca.c ../../provider/cert_hooks.c ../../provider/private_mapping.c
    ../../provider/ca_file.c ../../provider/ca_index.c ${TLS_FIXER_CRYPTO_PLATFORM_SOURCE})
target_include_directories(tls_fixer_game_ca_tests PRIVATE ../../provider)
target_link_libraries(tls_fixer_game_ca_tests PRIVATE tls_fixer_core mbedtls tls_fixer_vita_mock)
target_compile_options(tls_fixer_game_ca_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_game_ca COMMAND tls_fixer_game_ca_tests "${CMAKE_CURRENT_SOURCE_DIR}/../../../misc/certs.cer")

get_target_property(transport_sources tls_fixer_transport_tests SOURCES)
add_executable(tls_fixer_http_memory_tests ${transport_sources} ../browser/memory_tracker.c)
target_include_directories(tls_fixer_http_memory_tests PRIVATE ../../provider ../browser)
target_compile_definitions(tls_fixer_http_memory_tests PRIVATE TLS_FIXER_ENABLE_DEBUG_LOG=0 TLS_FIXER_HTTP_MEMORY_TEST=1)
target_compile_options(tls_fixer_http_memory_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG -fno-pie)
target_link_options(tls_fixer_http_memory_tests PRIVATE -no-pie -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=realloc -Wl,--wrap=free)
target_link_libraries(tls_fixer_http_memory_tests PRIVATE tls_fixer_core mbedtls tls_fixer_vita_mock)
add_test(NAME tls_fixer_http_memory COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_loopback.py"
    $<TARGET_FILE:tls_fixer_http_memory_tests> ${TLS_FIXER_TRANSPORT_TEST_ARGUMENTS})
set_tests_properties(tls_fixer_http_memory PROPERTIES TIMEOUT 120)

add_executable(tls_fixer_ca_index_tests test_ca_index.c ../../provider/ca_index.c
    ../../provider/ca_file.c ${TLS_FIXER_CRYPTO_PLATFORM_SOURCE})
target_include_directories(tls_fixer_ca_index_tests PRIVATE ../../provider ../../include)
target_link_libraries(tls_fixer_ca_index_tests PRIVATE mbedtls tls_fixer_vita_mock)
target_compile_options(tls_fixer_ca_index_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(symbol malloc calloc sceIoOpen sceIoRead sceIoLseek sceIoClose)
    target_link_options(tls_fixer_ca_index_tests PRIVATE "-Wl,--wrap=${symbol}")
endforeach()
add_test(NAME tls_fixer_ca_index COMMAND tls_fixer_ca_index_tests "${CMAKE_CURRENT_SOURCE_DIR}/../../../misc/certs.cer")
set_tests_properties(tls_fixer_ca_index PROPERTIES TIMEOUT 30)
