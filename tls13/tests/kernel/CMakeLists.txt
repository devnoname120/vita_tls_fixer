add_executable(tls_fixer_kernel_loader_tests test_loader.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_kernel_loader_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_kernel_loader_tests PRIVATE tls_fixer_core)
target_compile_options(tls_fixer_kernel_loader_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_kernel_loaders COMMAND tls_fixer_kernel_loader_tests)
add_executable(tls_fixer_browser_inventory_tests test_browser_inventory.c ../../../kernel/browser_inventory.c)
target_include_directories(tls_fixer_browser_inventory_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_browser_inventory_tests PRIVATE TLS_FIXER_BROWSER_INVENTORY=1)
target_compile_options(tls_fixer_browser_inventory_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_browser_inventory COMMAND tls_fixer_browser_inventory_tests)
add_executable(tls_fixer_kernel_route_tests test_route.c)
target_include_directories(tls_fixer_kernel_route_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_kernel_route_tests PRIVATE tls_fixer_core)
target_compile_options(tls_fixer_kernel_route_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_kernel_route COMMAND tls_fixer_kernel_route_tests)

add_executable(tls_fixer_module_status_tests test_module_status.c)
target_include_directories(tls_fixer_module_status_tests PRIVATE ../transport/include)
target_compile_options(tls_fixer_module_status_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_module_status COMMAND tls_fixer_module_status_tests)

add_executable(tls_fixer_hook_guard_tests test_hook_guard.c ../../../kernel/hook_guard.c)
target_include_directories(tls_fixer_hook_guard_tests PRIVATE include ../transport/include ../../../kernel)
target_include_directories(tls_fixer_hook_guard_tests PRIVATE ../../include)
target_compile_options(tls_fixer_hook_guard_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_hook_guard COMMAND tls_fixer_hook_guard_tests)

add_executable(tls_fixer_native_module_api_tests test_native_module_api.c ../../../kernel/native_module_api.c)
target_include_directories(tls_fixer_native_module_api_tests PRIVATE include ../transport/include ../../../kernel ../../include)
target_compile_options(tls_fixer_native_module_api_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_native_module_api COMMAND tls_fixer_native_module_api_tests)

add_executable(tls_fixer_kernel_disarm_probe_tests test_route.c)
target_include_directories(tls_fixer_kernel_disarm_probe_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_kernel_disarm_probe_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_kernel_disarm_probe_tests PRIVATE TLS_FIXER_SELF_DISARM_ONLY=1)
target_compile_options(tls_fixer_kernel_disarm_probe_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_kernel_disarm_probe COMMAND tls_fixer_kernel_disarm_probe_tests)

add_executable(tls_fixer_kernel_init_probe_tests test_route.c)
target_include_directories(tls_fixer_kernel_init_probe_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_kernel_init_probe_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_kernel_init_probe_tests PRIVATE TLS_FIXER_INITIALIZE_ONLY=1)
target_compile_options(tls_fixer_kernel_init_probe_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_kernel_init_probe COMMAND tls_fixer_kernel_init_probe_tests)

add_executable(tls_fixer_kernel_redirection_probe_tests test_route.c)
target_include_directories(tls_fixer_kernel_redirection_probe_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_kernel_redirection_probe_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_kernel_redirection_probe_tests PRIVATE TLS_FIXER_REDIRECTION_ONLY=1)
target_compile_options(tls_fixer_kernel_redirection_probe_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_kernel_redirection_probe COMMAND tls_fixer_kernel_redirection_probe_tests)

add_executable(tls_fixer_kernel_path_observer_tests test_route.c)
target_include_directories(tls_fixer_kernel_path_observer_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_kernel_path_observer_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_kernel_path_observer_tests PRIVATE TLS_FIXER_REDIRECTION_ONLY=1
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_STACK_HEADROOM=1 TLS_FIXER_TRACE_MODULE_PATHS=1)
target_compile_options(tls_fixer_kernel_path_observer_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_kernel_path_observer COMMAND tls_fixer_kernel_path_observer_tests)

add_executable(tls_fixer_kernel_prepare_probe_tests test_loader.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_kernel_prepare_probe_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_kernel_prepare_probe_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_kernel_prepare_probe_tests PRIVATE TLS_FIXER_PREPARE_ONLY=1)
target_compile_options(tls_fixer_kernel_prepare_probe_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_kernel_prepare_probe COMMAND tls_fixer_kernel_prepare_probe_tests)

add_executable(tls_fixer_kernel_prepare_route_tests test_route.c)
target_include_directories(tls_fixer_kernel_prepare_route_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_kernel_prepare_route_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_kernel_prepare_route_tests PRIVATE TLS_FIXER_PREPARE_ONLY=1)
target_compile_options(tls_fixer_kernel_prepare_route_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_kernel_prepare_route COMMAND tls_fixer_kernel_prepare_route_tests)

add_executable(tls_fixer_self_disarm_tests test_self_disarm.c ../../../kernel/self_disarm.c)
target_include_directories(tls_fixer_self_disarm_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_options(tls_fixer_self_disarm_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_self_disarm COMMAND tls_fixer_self_disarm_tests)

add_executable(tls_fixer_module_path_trace_tests test_boot_trace.c ../../../kernel/boot_trace.c)
target_include_directories(tls_fixer_module_path_trace_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_module_path_trace_tests PRIVATE TLS_FIXER_ENABLE_BOOT_TRACE=1
    TLS_FIXER_TRACE_MODULE_PATHS=1 TLS_FIXER_STACK_HEADROOM=1)
target_compile_options(tls_fixer_module_path_trace_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario path-valid path-encoded path-null path-empty path-long path-unbounded path-partial path-reentry path-sync-fail limit
    status-valid status-write-fail status-sync-fail status-thread-fail status-reentry
    async-valid async-full async-partial async-reentry async-write-fail async-sync-fail async-concurrent)
    add_test(NAME tls_fixer_module_path_trace_${scenario} COMMAND tls_fixer_module_path_trace_tests ${scenario})
endforeach()

add_executable(tls_fixer_boot_trace_tests test_boot_trace.c ../../../kernel/boot_trace.c)
add_executable(tls_fixer_activation_trace_tests test_boot_trace.c ../../../kernel/boot_trace.c)
target_include_directories(tls_fixer_activation_trace_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_activation_trace_tests PRIVATE TLS_FIXER_ENABLE_BOOT_TRACE=1
    TLS_FIXER_TRACE_MODULE_PATHS=1 TLS_FIXER_TRACE_ACTIVATION_ONLY=1)
target_compile_options(tls_fixer_activation_trace_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_activation_trace COMMAND tls_fixer_activation_trace_tests activation-filter)
add_executable(tls_fixer_memory_probe_tests test_memory_probe.c ../../../kernel/memory_probe.c)
target_include_directories(tls_fixer_memory_probe_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_memory_probe_tests PRIVATE TLS_FIXER_ENABLE_BOOT_TRACE=1
    TLS_FIXER_TRACE_MODULE_PATHS=1 TLS_FIXER_TRACE_ACTIVATION_ONLY=1 TLS_FIXER_MEMORY_PROBE=1)
target_compile_options(tls_fixer_memory_probe_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_memory_probe COMMAND tls_fixer_memory_probe_tests)
target_include_directories(tls_fixer_boot_trace_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_boot_trace_tests PRIVATE TLS_FIXER_ENABLE_BOOT_TRACE=1)
target_compile_options(tls_fixer_boot_trace_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid open-fail initial-sync-fail zero-write sync-fail partial reentry limit close-fail
    before-open bad-stage thread-fail short-write-fail oversized-write)
    add_test(NAME tls_fixer_boot_trace_${scenario} COMMAND tls_fixer_boot_trace_tests ${scenario})
endforeach()

add_executable(tls_fixer_traced_prepare_tests test_loader.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_traced_prepare_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_traced_prepare_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_traced_prepare_tests PRIVATE TLS_FIXER_PREPARE_ONLY=1 TLS_FIXER_ENABLE_BOOT_TRACE=1)
target_compile_options(tls_fixer_traced_prepare_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_traced_prepare COMMAND tls_fixer_traced_prepare_tests)

add_executable(tls_fixer_extended_stack_prepare_tests test_loader.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_extended_stack_prepare_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_extended_stack_prepare_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_extended_stack_prepare_tests PRIVATE
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_PREPARE_ONLY=1 TLS_FIXER_PREPARE_EXTENDED_STACK=1)
target_compile_options(tls_fixer_extended_stack_prepare_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_extended_stack_prepare COMMAND tls_fixer_extended_stack_prepare_tests)

add_executable(tls_fixer_no_module_query_tests test_loader.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_no_module_query_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_no_module_query_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_no_module_query_tests PRIVATE
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_PREPARE_ONLY=1 TLS_FIXER_PREPARE_EXTENDED_STACK=1
    TLS_FIXER_PREPARE_NO_MODULE_QUERIES=1)
target_compile_options(tls_fixer_no_module_query_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_no_module_queries COMMAND tls_fixer_no_module_query_tests)

add_executable(tls_fixer_target_query_only_tests test_loader.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_target_query_only_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_target_query_only_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_target_query_only_tests PRIVATE
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_PREPARE_ONLY=1 TLS_FIXER_PREPARE_EXTENDED_STACK=1
    TLS_FIXER_PREPARE_TARGET_QUERY_ONLY=1)
target_compile_options(tls_fixer_target_query_only_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_target_query_only COMMAND tls_fixer_target_query_only_tests)

add_executable(tls_fixer_list_target_query_tests test_list_target.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_list_target_query_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_list_target_query_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_list_target_query_tests PRIVATE
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_PREPARE_ONLY=1 TLS_FIXER_PREPARE_EXTENDED_STACK=1
    TLS_FIXER_PREPARE_LIST_TARGET_ONLY=1)
target_compile_options(tls_fixer_list_target_query_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_list_target_query COMMAND tls_fixer_list_target_query_tests)

add_executable(tls_fixer_name_query_tests test_name_query.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_name_query_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_name_query_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_name_query_tests PRIVATE
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_PREPARE_ONLY=1 TLS_FIXER_PREPARE_EXTENDED_STACK=1
    TLS_FIXER_PREPARE_NAME_QUERY=1)
target_compile_options(tls_fixer_name_query_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_name_query COMMAND tls_fixer_name_query_tests)

add_executable(tls_fixer_browser_activation_route_tests test_browser_activation_route.c)
target_include_directories(tls_fixer_browser_activation_route_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_browser_activation_route_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_browser_activation_route_tests PRIVATE TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_BROWSER_ACTIVATION=1)
target_compile_options(tls_fixer_browser_activation_route_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_browser_activation_route COMMAND tls_fixer_browser_activation_route_tests)

add_executable(tls_fixer_queued_browser_activation_route_tests test_browser_activation_route.c)
target_include_directories(tls_fixer_queued_browser_activation_route_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_queued_browser_activation_route_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_queued_browser_activation_route_tests PRIVATE TLS_FIXER_ENABLE_BOOT_TRACE=1
    TLS_FIXER_BROWSER_ACTIVATION=1 TLS_FIXER_TRACE_MODULE_PATHS=1 TLS_FIXER_STACK_HEADROOM=1
    TLS_FIXER_PREPARE_NAME_QUERY=1 TLS_FIXER_PREPARE_EXTENDED_STACK=1)
target_compile_options(tls_fixer_queued_browser_activation_route_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_queued_browser_activation_route COMMAND tls_fixer_queued_browser_activation_route_tests)

add_executable(tls_fixer_browser_activation_loader_tests test_browser_activation_loader.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_browser_activation_loader_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_browser_activation_loader_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_browser_activation_loader_tests PRIVATE
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_PREPARE_ONLY=0 TLS_FIXER_PREPARE_EXTENDED_STACK=1
    TLS_FIXER_PREPARE_NAME_QUERY=1 TLS_FIXER_BROWSER_ACTIVATION=1)
target_compile_options(tls_fixer_browser_activation_loader_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_browser_activation_loader COMMAND tls_fixer_browser_activation_loader_tests)

add_executable(tls_fixer_connect_patch_loader_tests test_browser_activation_loader.c ../../../kernel/tls13_loader.c
    ../../src/path.c)
target_include_directories(tls_fixer_connect_patch_loader_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_connect_patch_loader_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_connect_patch_loader_tests PRIVATE TLS_FIXER_INSPECT_CONNECT_PATCH=1
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_PREPARE_EXTENDED_STACK=1 TLS_FIXER_PREPARE_NAME_QUERY=1
    TLS_FIXER_BROWSER_ACTIVATION=1 TLS_FIXER_BROWSER_START_DIAGNOSTICS=1 TLS_FIXER_TRACE_MODULE_PATHS=1)
target_compile_options(tls_fixer_connect_patch_loader_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_connect_patch_loader COMMAND tls_fixer_connect_patch_loader_tests)

add_executable(tls_fixer_traced_route_tests test_route.c)
target_include_directories(tls_fixer_traced_route_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_traced_route_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_traced_route_tests PRIVATE TLS_FIXER_PREPARE_ONLY=1 TLS_FIXER_ENABLE_BOOT_TRACE=1)
target_compile_options(tls_fixer_traced_route_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_traced_route COMMAND tls_fixer_traced_route_tests)

add_executable(tls_fixer_traced_redirection_tests test_route.c)
target_include_directories(tls_fixer_traced_redirection_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_traced_redirection_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_traced_redirection_tests PRIVATE TLS_FIXER_REDIRECTION_ONLY=1 TLS_FIXER_ENABLE_BOOT_TRACE=1)
target_compile_options(tls_fixer_traced_redirection_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_traced_redirection COMMAND tls_fixer_traced_redirection_tests)

add_executable(tls_fixer_stack_probe_tests test_stack_probe.c)
target_include_directories(tls_fixer_stack_probe_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_options(tls_fixer_stack_probe_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_stack_probe COMMAND tls_fixer_stack_probe_tests)

add_executable(tls_fixer_headroom_trace_tests test_boot_trace.c ../../../kernel/boot_trace.c)
target_include_directories(tls_fixer_headroom_trace_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_headroom_trace_tests PRIVATE TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_STACK_HEADROOM=1)
target_compile_options(tls_fixer_headroom_trace_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid bad-stage limit reentry open-fail initial-sync-fail stack-probe-fail no-headroom
    unknown-headroom before-open partial zero-write oversized-write short-write-fail thread-fail sync-fail close-fail)
    add_test(NAME tls_fixer_headroom_trace_${scenario} COMMAND tls_fixer_headroom_trace_tests ${scenario})
endforeach()

add_executable(tls_fixer_disarm_result_tests test_disarm_result.c ../../../kernel/disarm_result.c)
target_include_directories(tls_fixer_disarm_result_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_options(tls_fixer_disarm_result_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid invalid open-fail wrong-size zero-write partial sync-fail close-fail
    seek-fail oversized-write negative-write trace-setup)
    add_test(NAME tls_fixer_disarm_result_${scenario} COMMAND tls_fixer_disarm_result_tests ${scenario})
endforeach()

add_executable(tls_fixer_disarm_result_route_tests test_route.c)
target_include_directories(tls_fixer_disarm_result_route_tests PRIVATE include ../transport/include ../../../kernel)
target_link_libraries(tls_fixer_disarm_result_route_tests PRIVATE tls_fixer_core)
target_compile_definitions(tls_fixer_disarm_result_route_tests PRIVATE TLS_FIXER_DISARM_RESULT_ONLY=1)
target_compile_options(tls_fixer_disarm_result_route_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_disarm_result_route COMMAND tls_fixer_disarm_result_route_tests)

add_executable(tls_fixer_trace_status_report_tests test_trace_status_report.c ../../../kernel/disarm_result.c)
target_include_directories(tls_fixer_trace_status_report_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_trace_status_report_tests PRIVATE TLS_FIXER_TRACE_MODULE_PATHS=1)
target_compile_options(tls_fixer_trace_status_report_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
foreach(scenario valid partial limit invalid open-fail write-fail sync-fail close-fail bad-size)
    add_test(NAME tls_fixer_trace_status_report_${scenario} COMMAND tls_fixer_trace_status_report_tests ${scenario})
endforeach()

find_package(Threads REQUIRED)
add_executable(tls_fixer_post_start_guard_tests test_hook_guard.c ../../../kernel/hook_guard.c)
target_include_directories(tls_fixer_post_start_guard_tests PRIVATE ../../include)
target_include_directories(tls_fixer_post_start_guard_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_post_start_guard_tests PRIVATE TLS_FIXER_BROWSER_POST_START=1)
target_compile_options(tls_fixer_post_start_guard_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_post_start_guard COMMAND tls_fixer_post_start_guard_tests)

add_executable(tls_fixer_post_start_tests test_post_start.c ../../../kernel/post_start.c)
target_include_directories(tls_fixer_post_start_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_post_start_tests PRIVATE TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_ENABLE_PSN_REDIRECT=1)
target_compile_options(tls_fixer_post_start_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_post_start COMMAND tls_fixer_post_start_tests)

add_executable(tls_fixer_post_start_route_tests test_post_start_route.c ../../../kernel/post_start.c)
target_include_directories(tls_fixer_post_start_route_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_post_start_route_tests PRIVATE TLS_FIXER_BROWSER_POST_START=1
    TLS_FIXER_BROWSER_ACTIVATION=1 TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_TRACE_MODULE_PATHS=1)
target_compile_options(tls_fixer_post_start_route_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_post_start_route_tests PRIVATE tls_fixer_core)
foreach(scenario valid disarm-fail guard-fail init-fail start-install-fail load-install-fail after-start-publication)
    add_test(NAME tls_fixer_post_start_route_${scenario} COMMAND tls_fixer_post_start_route_tests ${scenario})
endforeach()

add_executable(tls_fixer_post_start_production_tests test_post_start_production.c ../../../kernel/post_start.c)
target_include_directories(tls_fixer_post_start_production_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_post_start_production_tests PRIVATE TLS_FIXER_BROWSER_POST_START=1)
target_compile_options(tls_fixer_post_start_production_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_post_start_production_tests PRIVATE tls_fixer_core)
add_test(NAME tls_fixer_post_start_production COMMAND tls_fixer_post_start_production_tests)

add_executable(tls_fixer_persistent_activation_tests test_post_start_production.c ../../../kernel/post_start.c)
target_include_directories(tls_fixer_persistent_activation_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_persistent_activation_tests PRIVATE TLS_FIXER_BROWSER_POST_START=1
    TLS_FIXER_ENABLE_SELF_DISARM=0)
target_compile_options(tls_fixer_persistent_activation_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_persistent_activation_tests PRIVATE tls_fixer_core)
add_test(NAME tls_fixer_persistent_activation COMMAND tls_fixer_persistent_activation_tests)

add_executable(tls_fixer_untraced_browser_control_tests test_post_start_production.c ../../../kernel/post_start.c)
target_include_directories(tls_fixer_untraced_browser_control_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_untraced_browser_control_tests PRIVATE TLS_FIXER_BROWSER_POST_START=1
    TLS_FIXER_SKIP_HTTP_START=1 TLS_FIXER_SKIP_DNS_START=1)
target_compile_options(tls_fixer_untraced_browser_control_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_untraced_browser_control_tests PRIVATE tls_fixer_core)
add_test(NAME tls_fixer_untraced_browser_control COMMAND tls_fixer_untraced_browser_control_tests)

add_executable(tls_fixer_production_context_tests test_production_context.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_production_context_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_production_context_tests PRIVATE TLS_FIXER_PREPARE_EXTENDED_STACK=1
    TLS_FIXER_PREPARE_NAME_QUERY=1)
target_compile_options(tls_fixer_production_context_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_production_context_tests PRIVATE tls_fixer_core)
add_test(NAME tls_fixer_production_context COMMAND tls_fixer_production_context_tests)

add_executable(tls_fixer_runtime_scope_tests test_runtime_scope.c ../../../kernel/tls13_loader.c)
target_include_directories(tls_fixer_runtime_scope_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_runtime_scope_tests PRIVATE TLS_FIXER_PREPARE_EXTENDED_STACK=1
    TLS_FIXER_PREPARE_NAME_QUERY=1 TLS_FIXER_HTTP_TEST_TITLE_ID="TLSCK0001")
target_compile_options(tls_fixer_runtime_scope_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_runtime_scope_tests PRIVATE tls_fixer_core)
add_test(NAME tls_fixer_runtime_scope COMMAND tls_fixer_runtime_scope_tests)

add_executable(tls_fixer_dns_isolation_tests test_dns_isolation.c)
target_include_directories(tls_fixer_dns_isolation_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_dns_isolation_tests PRIVATE TLS_FIXER_SKIP_DNS_START=1)
target_compile_options(tls_fixer_dns_isolation_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_dns_isolation_tests PRIVATE tls_fixer_core)
add_test(NAME tls_fixer_dns_isolation COMMAND tls_fixer_dns_isolation_tests)

add_executable(tls_fixer_allocation_probe_tests test_allocation_probe.c)
target_include_directories(tls_fixer_allocation_probe_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_allocation_probe_tests PRIVATE TLS_FIXER_ALLOCATION_PROBE=1
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_TRACE_MODULE_PATHS=1 TLS_FIXER_TRACE_ACTIVATION_ONLY=1)
target_compile_options(tls_fixer_allocation_probe_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_allocation_probe COMMAND tls_fixer_allocation_probe_tests)

add_executable(tls_fixer_allocation_lifecycle_tests test_allocation_lifecycle.c)
target_include_directories(tls_fixer_allocation_lifecycle_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_allocation_lifecycle_tests PRIVATE TLS_FIXER_ALLOCATION_PROBE=1
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_TRACE_MODULE_PATHS=1 TLS_FIXER_REDIRECTION_ONLY=1)
target_compile_options(tls_fixer_allocation_lifecycle_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_allocation_lifecycle_tests PRIVATE tls_fixer_core)
foreach(scenario prepare-fail install-fail after-publication valid)
    add_test(NAME tls_fixer_allocation_lifecycle_${scenario} COMMAND tls_fixer_allocation_lifecycle_tests ${scenario})
endforeach()

add_executable(tls_fixer_code_snapshot_tests test_code_snapshot.c ../../../kernel/code_snapshot.c)
target_include_directories(tls_fixer_code_snapshot_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_code_snapshot_tests PRIVATE TLS_FIXER_ENABLE_BOOT_TRACE=1)
target_compile_options(tls_fixer_code_snapshot_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
add_test(NAME tls_fixer_code_snapshot COMMAND tls_fixer_code_snapshot_tests)

target_link_libraries(tls_fixer_module_path_trace_tests PRIVATE Threads::Threads)
set_tests_properties(tls_fixer_module_path_trace_async-concurrent PROPERTIES TIMEOUT 10)
add_executable(tls_fixer_trace_status_worker_tests test_trace_status_worker.c ../../../kernel/trace_status.c)
target_include_directories(tls_fixer_trace_status_worker_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_trace_status_worker_tests PRIVATE TLS_FIXER_TRACE_MODULE_PATHS=1 TLS_FIXER_ENABLE_BOOT_TRACE=1)
target_compile_options(tls_fixer_trace_status_worker_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_trace_status_worker_tests PRIVATE Threads::Threads)
add_executable(tls_fixer_inventory_worker_tests test_trace_status_worker.c ../../../kernel/trace_status.c)
target_include_directories(tls_fixer_inventory_worker_tests PRIVATE include ../transport/include ../../../kernel)
target_compile_definitions(tls_fixer_inventory_worker_tests PRIVATE TLS_FIXER_TRACE_MODULE_PATHS=1
    TLS_FIXER_ENABLE_BOOT_TRACE=1 TLS_FIXER_BROWSER_INVENTORY=1)
target_compile_options(tls_fixer_inventory_worker_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(tls_fixer_inventory_worker_tests PRIVATE Threads::Threads)
add_test(NAME tls_fixer_inventory_worker_lifetime COMMAND tls_fixer_inventory_worker_tests limit)
set_tests_properties(tls_fixer_inventory_worker_lifetime PROPERTIES TIMEOUT 10)
foreach(scenario valid create-fail start-fail enable-fail report-fail delay-fail limit wait-fail delete-fail)
    add_test(NAME tls_fixer_trace_status_worker_${scenario} COMMAND tls_fixer_trace_status_worker_tests ${scenario})
    set_tests_properties(tls_fixer_trace_status_worker_${scenario} PROPERTIES TIMEOUT 10)
endforeach()

foreach(kind psn_redirect redirects)
    add_executable(tls_fixer_kernel_${kind}_tests test_${kind}.c ../../../kernel/${kind}.c)
    target_include_directories(tls_fixer_kernel_${kind}_tests PRIVATE include ../transport/include ../../../kernel ../../include)
    target_compile_definitions(tls_fixer_kernel_${kind}_tests PRIVATE TLS_FIXER_ENABLE_PSN_REDIRECT=1)
    target_compile_options(tls_fixer_kernel_${kind}_tests PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    add_test(NAME tls_fixer_kernel_${kind} COMMAND tls_fixer_kernel_${kind}_tests)
endforeach()
