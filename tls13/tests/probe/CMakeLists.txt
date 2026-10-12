add_executable(tls_fixer_probe_protocol_tests test_protocol.c ../../probe/protocol.c)
target_include_directories(tls_fixer_probe_protocol_tests PRIVATE ../../probe)
target_compile_options(tls_fixer_probe_protocol_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_probe_protocol COMMAND tls_fixer_probe_protocol_tests)

add_executable(tls_fixer_probe_client_tests test_client.c ../../probe/core.c ../../probe/protocol.c
    ../../provider/platform_shims.c)
target_include_directories(tls_fixer_probe_client_tests PRIVATE ../../probe ../../provider)
target_compile_options(tls_fixer_probe_client_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_probe_client_tests PRIVATE mbedtls mbedx509 tfpsacrypto tls_fixer_vita_mock)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME tls_fixer_probe_loopback COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_loopback.py" $<TARGET_FILE:tls_fixer_probe_client_tests>)
set_tests_properties(tls_fixer_probe_loopback PROPERTIES TIMEOUT 120)

add_executable(tls_fixer_probe_platform_tests test_platform.c)
target_include_directories(tls_fixer_probe_platform_tests PRIVATE . ../../probe)
target_link_libraries(tls_fixer_probe_platform_tests PRIVATE mbedtls)
target_compile_options(tls_fixer_probe_platform_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_probe_platform COMMAND tls_fixer_probe_platform_tests)

add_executable(tls_fixer_probe_screen_tests test_screen.c ../../probe/screen.c)
target_include_directories(tls_fixer_probe_screen_tests PRIVATE ../../probe)
target_compile_options(tls_fixer_probe_screen_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_probe_screen COMMAND tls_fixer_probe_screen_tests)

add_executable(tls_fixer_probe_screen_native_tests test_screen_native.c ../../probe/screen.c ../../probe/screen_vita.c)
target_include_directories(tls_fixer_probe_screen_native_tests PRIVATE . ../../probe)
target_compile_definitions(tls_fixer_probe_screen_native_tests PRIVATE TLS_FIXER_PROBE_SCREEN_NATIVE_TEST=1)
target_compile_options(tls_fixer_probe_screen_native_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_probe_screen_native COMMAND tls_fixer_probe_screen_native_tests)

add_executable(tls_fixer_probe_nonce_tests test_nonce.c ../../probe/nonce.c)
target_include_directories(tls_fixer_probe_nonce_tests PRIVATE ../../probe)
target_compile_options(tls_fixer_probe_nonce_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_probe_nonce COMMAND tls_fixer_probe_nonce_tests)

add_executable(tls_fixer_probe_nonce_native_tests test_nonce.c ../../probe/nonce.c ../../probe/nonce_vita.c)
target_include_directories(tls_fixer_probe_nonce_native_tests PRIVATE ../../probe)
target_compile_definitions(tls_fixer_probe_nonce_native_tests PRIVATE TLS_FIXER_PROBE_NONCE_NATIVE_TEST=1)
target_compile_options(tls_fixer_probe_nonce_native_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_probe_nonce_native COMMAND tls_fixer_probe_nonce_native_tests)

add_executable(tls_fixer_probe_report_tests test_report.c ../../probe/report.c ../../probe/protocol.c)
target_include_directories(tls_fixer_probe_report_tests PRIVATE ../../probe)
target_link_libraries(tls_fixer_probe_report_tests PRIVATE mbedx509)
target_compile_options(tls_fixer_probe_report_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_probe_report COMMAND tls_fixer_probe_report_tests)

add_executable(tls_fixer_probe_application_tests test_application.c ../../probe/application.c
    ../../probe/report.c ../../probe/protocol.c)
target_include_directories(tls_fixer_probe_application_tests PRIVATE ../../probe)
target_link_libraries(tls_fixer_probe_application_tests PRIVATE mbedx509)
target_compile_options(tls_fixer_probe_application_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid entropy display-first display-second display-last prepare first-failed
    connection-cleanup false-success cleanup report-open report-result report-close)
    add_test(NAME tls_fixer_probe_application_${scenario} COMMAND tls_fixer_probe_application_tests ${scenario})
endforeach()

add_executable(tls_fixer_probe_report_native_tests test_report_native.c ../../probe/report_vita.c)
target_include_directories(tls_fixer_probe_report_native_tests PRIVATE . ../../probe)
target_compile_definitions(tls_fixer_probe_report_native_tests PRIVATE TLS_FIXER_PROBE_REPORT_NATIVE_TEST=1)
target_link_libraries(tls_fixer_probe_report_native_tests PRIVATE mbedx509)
target_compile_options(tls_fixer_probe_report_native_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_probe_report_native COMMAND tls_fixer_probe_report_native_tests)

add_executable(tls_fixer_probe_trust_tests test_trust.c ../../probe/trust.c ../../provider/platform_shims.c)
target_include_directories(tls_fixer_probe_trust_tests PRIVATE ../../probe ../../provider)
target_compile_options(tls_fixer_probe_trust_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_probe_trust_tests PRIVATE mbedtls mbedx509 tfpsacrypto tls_fixer_vita_mock)
add_test(NAME tls_fixer_probe_trust COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run_trust.py" $<TARGET_FILE:tls_fixer_probe_trust_tests>)
set_tests_properties(tls_fixer_probe_trust PROPERTIES TIMEOUT 120)
