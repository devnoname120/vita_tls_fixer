cmake_minimum_required(VERSION 3.16)

project(tls_fixer C)

option(TLS_FIXER_BUILD_HOST_TESTS "Build host unit tests" OFF)
option(TLS_FIXER_BUILD_VITA_PROVIDER "Build the Vita user provider" OFF)
option(TLS_FIXER_BUILD_VITA_PROBE "Build only the ordinary standalone Vita TLS probe" OFF)
option(TLS_FIXER_BUILD_TRANSPORT_TESTS "Build host tests with the real TLS engine" OFF)
option(TLS_FIXER_ENABLE_SANITIZERS "Enable host sanitizers" OFF)
option(TLS_FIXER_ENABLE_DEBUG_LOG "Enable bounded Vita provider diagnostics" ON)
option(TLS_FIXER_BROWSER_START_DIAGNOSTICS "Report passive browser-start failures through native entry status" OFF)
option(TLS_FIXER_BROWSER_PASSTHROUGH_ONLY "Install the browser hooks but leave TLS transport on the original backend" OFF)
option(TLS_FIXER_BROWSER_INITIALIZE_ONLY "Initialize the disabled browser provider without publishing any hooks" OFF)
set(TLS_FIXER_BROWSER_HOOK_MASK "" CACHE STRING "Optional passthrough-only hook selection; bits close/pending/check/connect")
option(TLS_FIXER_ENABLE_RUNTIME_UDP "Send bounded scalar browser diagnostics to the explicitly selected LAN receiver" OFF)
set(TLS_FIXER_RUNTIME_HOST "" CACHE STRING "IPv4 address of the diagnostic receiver")
set(TLS_FIXER_RUNTIME_PORT "" CACHE STRING "UDP port of the diagnostic receiver")
set(TLS_FIXER_RUNTIME_NONCE_HEX "" CACHE STRING "128-bit hexadecimal diagnostic-session nonce")

if(NOT TLS_FIXER_BROWSER_HOOK_MASK STREQUAL "")
    if(NOT TLS_FIXER_BROWSER_HOOK_MASK MATCHES "^([0-9]|1[0-5])$")
        message(FATAL_ERROR "Hook mask must be a decimal integer from 0 to 15")
    endif()
    if(NOT TLS_FIXER_BUILD_VITA_PROVIDER OR NOT TLS_FIXER_BROWSER_START_DIAGNOSTICS
       OR NOT TLS_FIXER_BROWSER_PASSTHROUGH_ONLY OR TLS_FIXER_BROWSER_INITIALIZE_ONLY
       OR TLS_FIXER_ENABLE_RUNTIME_UDP OR TLS_FIXER_BUILD_VITA_PROBE)
        message(FATAL_ERROR "Selective hooks require the Vita passthrough diagnostic without initialization-only, UDP or probe")
    endif()
endif()

if(TLS_FIXER_BUILD_VITA_PROBE)
    if(TLS_FIXER_BUILD_VITA_PROVIDER OR TLS_FIXER_BUILD_HOST_TESTS OR TLS_FIXER_BUILD_TRANSPORT_TESTS
       OR TLS_FIXER_ENABLE_SANITIZERS OR TLS_FIXER_BROWSER_START_DIAGNOSTICS
       OR TLS_FIXER_BROWSER_PASSTHROUGH_ONLY OR TLS_FIXER_BROWSER_INITIALIZE_ONLY OR TLS_FIXER_ENABLE_RUNTIME_UDP)
        message(FATAL_ERROR "Probe must be built separately from providers, hooks and host tests")
    endif()
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Generic" OR NOT CMAKE_C_COMPILER MATCHES "arm-vita-eabi-gcc$")
        message(FATAL_ERROR "Probe requires the VitaSDK toolchain")
    endif()
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
        message(FATAL_ERROR "Probe requires an explicit Release build")
    endif()
    include(probe/configure.cmake)
endif()

if(TLS_FIXER_BROWSER_INITIALIZE_ONLY AND NOT TLS_FIXER_BROWSER_PASSTHROUGH_ONLY)
    message(FATAL_ERROR "Initialization-only control requires the disabled-transport diagnostic")
endif()

if(TLS_FIXER_BROWSER_PASSTHROUGH_ONLY AND
   (NOT TLS_FIXER_BUILD_VITA_PROVIDER OR NOT TLS_FIXER_BROWSER_START_DIAGNOSTICS OR TLS_FIXER_ENABLE_RUNTIME_UDP))
    message(FATAL_ERROR "Passthrough control requires the Vita startup diagnostic without runtime UDP")
endif()

if(TLS_FIXER_ENABLE_RUNTIME_UDP)
    if(NOT TLS_FIXER_BUILD_VITA_PROVIDER OR NOT TLS_FIXER_BROWSER_START_DIAGNOSTICS)
        message(FATAL_ERROR "Runtime UDP requires the explicitly selected Vita browser diagnostic")
    endif()
    if(NOT TLS_FIXER_RUNTIME_HOST MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")
        message(FATAL_ERROR "An explicit IPv4 receiver address is required")
    endif()
    string(REPLACE "." ";" runtime_octets "${TLS_FIXER_RUNTIME_HOST}")
    foreach(octet IN LISTS runtime_octets)
        string(LENGTH "${octet}" octet_length)
        if(octet_length GREATER 3 OR octet GREATER 255 OR (octet_length GREATER 1 AND octet MATCHES "^0"))
            message(FATAL_ERROR "Invalid runtime receiver address")
        endif()
    endforeach()
    list(GET runtime_octets 0 first_octet)
    list(GET runtime_octets 1 second_octet)
    if(NOT (first_octet EQUAL 10 OR (first_octet EQUAL 192 AND second_octet EQUAL 168)
            OR (first_octet EQUAL 172 AND second_octet GREATER_EQUAL 16 AND second_octet LESS_EQUAL 31)))
        message(FATAL_ERROR "Runtime diagnostics are restricted to a private LAN receiver")
    endif()
    string(LENGTH "${TLS_FIXER_RUNTIME_PORT}" port_length)
    if(NOT TLS_FIXER_RUNTIME_PORT MATCHES "^[1-9][0-9]*$" OR port_length GREATER 5
            OR TLS_FIXER_RUNTIME_PORT LESS 1024 OR TLS_FIXER_RUNTIME_PORT GREATER 65535)
        message(FATAL_ERROR "An explicit unprivileged UDP receiver port is required")
    endif()
    string(LENGTH "${TLS_FIXER_RUNTIME_NONCE_HEX}" nonce_length)
    if(NOT nonce_length EQUAL 32 OR NOT TLS_FIXER_RUNTIME_NONCE_HEX MATCHES "^[0-9a-fA-F]+$")
        message(FATAL_ERROR "A 128-bit hexadecimal diagnostic-session nonce is required")
    endif()
endif()

if(TLS_FIXER_ENABLE_SANITIZERS)
    if(TLS_FIXER_BUILD_VITA_PROVIDER OR NOT CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        message(FATAL_ERROR "Sanitizers require a supported native host compiler")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

add_library(tls_fixer_core STATIC
    src/cert_registry.c
    src/cert_policy.c
    src/error_map.c
    src/module_gate.c
    src/path.c
    src/registry.c
    src/x509_names.c
)

target_include_directories(tls_fixer_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(tls_fixer_core PUBLIC c_std_11)

target_compile_options(tls_fixer_core PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wconversion
    -Wsign-conversion
    -Wshadow
    -Wstrict-prototypes
)

if(TLS_FIXER_BUILD_HOST_TESTS)
    enable_testing()

    add_executable(tls_fixer_tests
        tests/test_main.c
    )

    target_link_libraries(tls_fixer_tests PRIVATE tls_fixer_core)
    target_compile_features(tls_fixer_tests PRIVATE c_std_11)
    target_compile_options(tls_fixer_tests PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wstrict-prototypes
    )

    add_test(NAME tls_fixer_core COMMAND tls_fixer_tests)
    add_executable(tls_fixer_x509_name_tests tests/test_x509_names.c)
    target_link_libraries(tls_fixer_x509_name_tests PRIVATE tls_fixer_core)
    target_compile_options(tls_fixer_x509_name_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME tls_fixer_x509_names COMMAND tls_fixer_x509_name_tests)
    add_executable(tls_fixer_registry_lifetime_tests tests/test_registry_lifetime.c)
    target_link_libraries(tls_fixer_registry_lifetime_tests PRIVATE tls_fixer_core)
    target_compile_options(tls_fixer_registry_lifetime_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME tls_fixer_registry_lifetime COMMAND tls_fixer_registry_lifetime_tests)
    add_executable(tls_fixer_cert_policy_tests tests/test_cert_policy.c)
    target_link_libraries(tls_fixer_cert_policy_tests PRIVATE tls_fixer_core)
    target_compile_options(tls_fixer_cert_policy_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME tls_fixer_cert_policy COMMAND tls_fixer_cert_policy_tests)
    add_executable(tls_fixer_browser_path_tests tests/test_browser_paths.c)
    target_link_libraries(tls_fixer_browser_path_tests PRIVATE tls_fixer_core)
    target_compile_options(tls_fixer_browser_path_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME tls_fixer_browser_paths COMMAND tls_fixer_browser_path_tests)
    add_subdirectory(tests/kernel)
endif()

if(TLS_FIXER_BUILD_VITA_PROVIDER OR TLS_FIXER_BUILD_TRANSPORT_TESTS OR TLS_FIXER_BUILD_VITA_PROBE)
    add_subdirectory(crypto)
endif()

if(TLS_FIXER_BUILD_VITA_PROBE)
    add_subdirectory(probe)
endif()

if(TLS_FIXER_BUILD_TRANSPORT_TESTS)
    enable_testing()
    add_subdirectory(tests/transport)
    add_subdirectory(tests/browser)
    add_subdirectory(tests/probe)
endif()

if(TLS_FIXER_BUILD_VITA_PROVIDER)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Generic")
        message(FATAL_ERROR "TLS_FIXER_BUILD_VITA_PROVIDER requires the VitaSDK toolchain")
    endif()
    add_subdirectory(provider)
    add_subdirectory(browser)
endif()
