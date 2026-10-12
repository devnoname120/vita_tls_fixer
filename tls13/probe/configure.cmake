set(TLS_FIXER_PROBE_ADDRESS "" CACHE STRING "Explicit private-LAN IPv4 server address")
set(TLS_FIXER_PROBE_DNS_NAME "" CACHE STRING "Certificate/SNI DNS identity of the probe server")
set(TLS_FIXER_PROBE_TLS13_PORT "" CACHE STRING "Strict TLS 1.3 TCP port")
set(TLS_FIXER_PROBE_TLS12_PORT "" CACHE STRING "Strict TLS 1.2 TCP port")
set(TLS_FIXER_PROBE_CA "" CACHE FILEPATH "Single public PEM certificate for the app-local trust store")
set(TLS_FIXER_MBEDTLS_ARCHIVE "${CMAKE_CURRENT_LIST_DIR}/../../build/deps/mbedtls-4.2.0.tar.bz2"
    CACHE FILEPATH "Checksum-pinned official Mbed TLS release archive")
foreach(input ADDRESS DNS_NAME TLS13_PORT TLS12_PORT CA)
    if("${TLS_FIXER_PROBE_${input}}" STREQUAL "")
        message(FATAL_ERROR "Explicit TLS_FIXER_PROBE_${input} is required")
    endif()
endforeach()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(TLS_FIXER_PROBE_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/probe-generated")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_LIST_DIR}/../../tools/probe_config.py"
    --address "${TLS_FIXER_PROBE_ADDRESS}" --name "${TLS_FIXER_PROBE_DNS_NAME}"
    --tls13-port "${TLS_FIXER_PROBE_TLS13_PORT}" --tls12-port "${TLS_FIXER_PROBE_TLS12_PORT}"
    --ca "${TLS_FIXER_PROBE_CA}" --archive "${TLS_FIXER_MBEDTLS_ARCHIVE}" --compiler "${CMAKE_C_COMPILER}"
    --build-type "${CMAKE_BUILD_TYPE}" "--compile-flags=${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_RELEASE}"
    --toolchain "${CMAKE_TOOLCHAIN_FILE}"
    --output "${TLS_FIXER_PROBE_GENERATED}"
    RESULT_VARIABLE probe_config_result OUTPUT_VARIABLE probe_config_output ERROR_VARIABLE probe_config_error)
if(NOT probe_config_result EQUAL 0)
    message(FATAL_ERROR "Probe configuration rejected: ${probe_config_error}")
endif()
message(STATUS "${probe_config_output}")
file(GLOB probe_source_inputs CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/*")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${probe_source_inputs}
    "${TLS_FIXER_PROBE_CA}" "${CMAKE_CURRENT_LIST_DIR}/../../tools/probe_config.py"
    "${CMAKE_CURRENT_LIST_DIR}/../provider/platform_shims.c"
    "${CMAKE_CURRENT_LIST_DIR}/../crypto/mbedtls_user_config.h"
    "${CMAKE_CURRENT_LIST_DIR}/../crypto/psa_user_config.h"
    "${CMAKE_CURRENT_LIST_DIR}/../crypto/threading_alt.h"
    "${CMAKE_CURRENT_LIST_DIR}/../../font.c")
