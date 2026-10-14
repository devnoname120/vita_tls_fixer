cmake_minimum_required(VERSION 3.16)

set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_C_COMPILER "arm-vita-eabi-gcc")
set(CMAKE_CXX_COMPILER "arm-vita-eabi-g++")

project(HENkaku)
set(TLS_FIXER_HTTP_PROVIDER_PATH "vs0:/data/external/tls_fixer/native/tls_fixer_http.suprx"
    CACHE STRING "HTTP provider path; diagnostics stage their provider separately")
set(TLS_FIXER_HTTP_TEST_TITLE_ID "" CACHE STRING "Optional single-title diagnostic HTTP activation")
option(TLS_FIXER_HTTP_GLOBAL_DIAGNOSTIC "Explicit broad activation of a separately staged provider" OFF)
if(NOT TLS_FIXER_HTTP_PROVIDER_PATH MATCHES "^(vs0|ux0|ur0):/[A-Za-z0-9_./-]+$")
    message(FATAL_ERROR "HTTP provider requires an absolute vs0, ux0 or ur0 path")
endif()
if(TLS_FIXER_HTTP_GLOBAL_DIAGNOSTIC AND (NOT TLS_FIXER_HTTP_TEST_TITLE_ID STREQUAL "" OR
   NOT TLS_FIXER_HTTP_PROVIDER_PATH MATCHES "^(ux0|ur0):/data/tls_fixer-runtime[-/A-Za-z0-9_.]*"))
    message(FATAL_ERROR "Global diagnostic requires a separately staged runtime path and no title restriction")
endif()
if(NOT TLS_FIXER_HTTP_TEST_TITLE_ID STREQUAL "")
    string(LENGTH "${TLS_FIXER_HTTP_TEST_TITLE_ID}" tls_fixer_test_title_length)
    if(NOT tls_fixer_test_title_length EQUAL 9 OR NOT TLS_FIXER_HTTP_TEST_TITLE_ID MATCHES "^[A-Z0-9]+$")
        message(FATAL_ERROR "HTTP diagnostic title must be a nine-character title ID")
    endif()
elseif(TLS_FIXER_HTTP_PROVIDER_PATH MATCHES "^(ux0|ur0):" AND NOT TLS_FIXER_HTTP_GLOBAL_DIAGNOSTIC)
    message(FATAL_ERROR "A separately staged HTTP provider requires an explicit diagnostic title")
endif()

option(TLS_FIXER_ENABLE_SELF_DISARM "Disable this plugin's boot entries before activation" ON)
option(TLS_FIXER_SELF_DISARM_ONLY "Build a diagnostic with no module redirection or TLS injection" OFF)
option(TLS_FIXER_INITIALIZE_ONLY "Stop the diagnostic after loader initialization, before installing hooks" OFF)
option(TLS_FIXER_REDIRECTION_ONLY "Install module path redirection but do not start TLS or DNS providers" OFF)
option(TLS_FIXER_PREPARE_ONLY "Validate provider prerequisites without calling module load/start" OFF)
option(TLS_FIXER_ENABLE_BOOT_TRACE "Persist bounded synchronized preparation-stage records" OFF)
option(TLS_FIXER_TRACE_MODULE_PATHS "Queue process-namespace diagnostics for observation or browser-only activation" OFF)
option(TLS_FIXER_BROWSER_INVENTORY "Read-only mapped Browser inventory using the diagnostic worker" OFF)
if(TLS_FIXER_BROWSER_INVENTORY AND NOT TLS_FIXER_TRACE_MODULE_PATHS)
    message(FATAL_ERROR "Browser inventory requires the queued diagnostic worker")
endif()
option(TLS_FIXER_TRACE_ACTIVATION_ONLY "Limit queued diagnostics to provider activation boundaries" OFF)
option(TLS_FIXER_MEMORY_PROBE "Record primary physical-partition bytes on audited retail 3.60" OFF)
option(TLS_FIXER_MAPPING_PROBE "Read-only checker mapping type diagnostics" OFF)
if(TLS_FIXER_MAPPING_PROBE AND (NOT TLS_FIXER_ENABLE_BOOT_TRACE OR TLS_FIXER_HTTP_TEST_TITLE_ID STREQUAL ""))
    message(FATAL_ERROR "Mapping inspection requires tracing and an explicit diagnostic title")
endif()
option(TLS_FIXER_ALLOCATION_PROBE "Capture first physical-page allocation failure on audited retail 3.60" OFF)
option(TLS_FIXER_STACK_HEADROOM "Measure native current kernel-stack headroom in trace records" OFF)
option(TLS_FIXER_PREPARE_EXTENDED_STACK "Run preparation diagnostics on a 16 KiB native-managed stack" OFF)
option(TLS_FIXER_PREPARE_NO_MODULE_QUERIES "Omit module queries only in the native-stack preparation diagnostic" OFF)
option(TLS_FIXER_PREPARE_TARGET_QUERY_ONLY "Query only the loaded target, without enumeration, in preparation diagnostics" OFF)
option(TLS_FIXER_PREPARE_LIST_TARGET_ONLY "Enumerate IDs and query the target, without inspecting other modules" OFF)
option(TLS_FIXER_PREPARE_NAME_QUERY "Use taiHEN name queries for diagnostic provider-presence checking" OFF)
option(TLS_FIXER_BROWSER_ACTIVATION "Activate only browser TLS with traced name checks and no application/DNS startup" OFF)
option(TLS_FIXER_BROWSER_START_DIAGNOSTICS "Select the separate startup-status diagnostic provider" OFF)
option(TLS_FIXER_INSPECT_CONNECT_PATCH "Read the connect entry around diagnostic provider startup" OFF)
option(TLS_FIXER_BROWSER_POST_START "Defer browser injection until native module start returns" ON)
option(TLS_FIXER_SKIP_DNS_START "Exclude legacy DNS helper startup for controlled isolation" OFF)
option(TLS_FIXER_SKIP_HTTP_START "Exclude HTTP-provider startup for controlled isolation" OFF)
option(TLS_FIXER_DISARM_RESULT_ONLY "Report the self-disarm result without later initialization" OFF)
if(NOT TLS_FIXER_ENABLE_SELF_DISARM AND (TLS_FIXER_SELF_DISARM_ONLY OR TLS_FIXER_DISARM_RESULT_ONLY))
    message(FATAL_ERROR "Self-disarm diagnostics require TLS_FIXER_ENABLE_SELF_DISARM")
endif()
set(TLS_FIXER_NORMAL_ACTIVATION OFF)
if(NOT (TLS_FIXER_SELF_DISARM_ONLY OR TLS_FIXER_DISARM_RESULT_ONLY OR TLS_FIXER_INITIALIZE_ONLY
   OR TLS_FIXER_REDIRECTION_ONLY OR TLS_FIXER_PREPARE_ONLY OR TLS_FIXER_BROWSER_ACTIVATION))
	set(TLS_FIXER_NORMAL_ACTIVATION ON)
	# Carry the hardware-qualified loader context into the combined-provider build.
	set(TLS_FIXER_PREPARE_EXTENDED_STACK ON)
	set(TLS_FIXER_PREPARE_NAME_QUERY ON)
endif()
if(TLS_FIXER_DISARM_RESULT_ONLY AND (TLS_FIXER_SELF_DISARM_ONLY OR TLS_FIXER_INITIALIZE_ONLY
   OR TLS_FIXER_REDIRECTION_ONLY OR TLS_FIXER_PREPARE_ONLY OR TLS_FIXER_ENABLE_BOOT_TRACE))
	message(FATAL_ERROR "The disarm-result diagnostic must be selected alone")
endif()
# The same stage recorder can diagnose the normal, combined-provider route.
if(TLS_FIXER_STACK_HEADROOM AND NOT TLS_FIXER_ENABLE_BOOT_TRACE)
	message(FATAL_ERROR "Stack-headroom measurements require the diagnostic boot trace")
endif()
if(TLS_FIXER_TRACE_ACTIVATION_ONLY AND NOT (TLS_FIXER_ENABLE_BOOT_TRACE AND TLS_FIXER_TRACE_MODULE_PATHS))
	message(FATAL_ERROR "Activation tracing requires the asynchronous diagnostic recorder")
endif()
if(TLS_FIXER_MEMORY_PROBE AND NOT TLS_FIXER_TRACE_ACTIVATION_ONLY)
	message(FATAL_ERROR "Memory snapshots require sparse asynchronous tracing")
endif()
if(TLS_FIXER_ALLOCATION_PROBE AND (NOT TLS_FIXER_TRACE_ACTIVATION_ONLY OR TLS_FIXER_MEMORY_PROBE))
	message(FATAL_ERROR "Allocation capture requires sparse tracing without the startup memory probe")
endif()
if(TLS_FIXER_TRACE_MODULE_PATHS AND NOT
   ((TLS_FIXER_REDIRECTION_ONLY OR TLS_FIXER_BROWSER_ACTIVATION OR TLS_FIXER_NORMAL_ACTIVATION) AND TLS_FIXER_ENABLE_BOOT_TRACE AND TLS_FIXER_STACK_HEADROOM))
	message(FATAL_ERROR "Queued path diagnostics require redirection-only or browser-only activation, boot trace and headroom reporting")
endif()
if(TLS_FIXER_PREPARE_EXTENDED_STACK AND NOT TLS_FIXER_NORMAL_ACTIVATION AND NOT
   ((TLS_FIXER_PREPARE_ONLY OR TLS_FIXER_BROWSER_ACTIVATION) AND TLS_FIXER_ENABLE_BOOT_TRACE AND TLS_FIXER_STACK_HEADROOM))
	message(FATAL_ERROR "Extended-stack diagnostics require preparation-only, boot trace and headroom reporting")
endif()
if(TLS_FIXER_PREPARE_NO_MODULE_QUERIES AND NOT
   (TLS_FIXER_PREPARE_ONLY AND TLS_FIXER_PREPARE_EXTENDED_STACK AND TLS_FIXER_ENABLE_BOOT_TRACE AND TLS_FIXER_STACK_HEADROOM))
	message(FATAL_ERROR "Omitting module queries requires the traced native-stack preparation diagnostic")
endif()
if(TLS_FIXER_PREPARE_TARGET_QUERY_ONLY AND (TLS_FIXER_PREPARE_NO_MODULE_QUERIES OR NOT
   (TLS_FIXER_PREPARE_ONLY AND TLS_FIXER_PREPARE_EXTENDED_STACK AND TLS_FIXER_ENABLE_BOOT_TRACE AND TLS_FIXER_STACK_HEADROOM)))
	message(FATAL_ERROR "Target-only queries require an exclusive traced native-stack preparation diagnostic")
endif()
if(TLS_FIXER_PREPARE_LIST_TARGET_ONLY AND (TLS_FIXER_PREPARE_NO_MODULE_QUERIES OR TLS_FIXER_PREPARE_TARGET_QUERY_ONLY OR NOT
   (TLS_FIXER_PREPARE_ONLY AND TLS_FIXER_PREPARE_EXTENDED_STACK AND TLS_FIXER_ENABLE_BOOT_TRACE AND TLS_FIXER_STACK_HEADROOM)))
	message(FATAL_ERROR "List-and-target queries require an exclusive traced native-stack preparation diagnostic")
endif()
if(TLS_FIXER_PREPARE_NAME_QUERY AND (TLS_FIXER_PREPARE_NO_MODULE_QUERIES OR TLS_FIXER_PREPARE_TARGET_QUERY_ONLY OR TLS_FIXER_PREPARE_LIST_TARGET_ONLY OR
   NOT TLS_FIXER_PREPARE_EXTENDED_STACK OR (NOT TLS_FIXER_NORMAL_ACTIVATION AND NOT
   ((TLS_FIXER_PREPARE_ONLY OR TLS_FIXER_BROWSER_ACTIVATION) AND TLS_FIXER_ENABLE_BOOT_TRACE AND TLS_FIXER_STACK_HEADROOM))))
	message(FATAL_ERROR "Name queries require an exclusive traced native-stack preparation diagnostic")
endif()
if(TLS_FIXER_BROWSER_ACTIVATION AND (TLS_FIXER_PREPARE_ONLY OR TLS_FIXER_SELF_DISARM_ONLY OR TLS_FIXER_DISARM_RESULT_ONLY
   OR TLS_FIXER_INITIALIZE_ONLY OR TLS_FIXER_REDIRECTION_ONLY OR NOT
   (TLS_FIXER_PREPARE_NAME_QUERY AND TLS_FIXER_PREPARE_EXTENDED_STACK AND TLS_FIXER_ENABLE_BOOT_TRACE AND TLS_FIXER_STACK_HEADROOM)))
	message(FATAL_ERROR "Browser activation requires exclusive traced native-stack name lookup with preparation-only disabled")
endif()
if((TLS_FIXER_SELF_DISARM_ONLY AND TLS_FIXER_INITIALIZE_ONLY)
   OR (TLS_FIXER_SELF_DISARM_ONLY AND TLS_FIXER_REDIRECTION_ONLY)
   OR (TLS_FIXER_INITIALIZE_ONLY AND TLS_FIXER_REDIRECTION_ONLY)
   OR (TLS_FIXER_PREPARE_ONLY AND (TLS_FIXER_SELF_DISARM_ONLY OR TLS_FIXER_INITIALIZE_ONLY OR TLS_FIXER_REDIRECTION_ONLY)))
	message(FATAL_ERROR "Select only one startup isolation profile")
endif()

if(TLS_FIXER_BROWSER_START_DIAGNOSTICS AND NOT (TLS_FIXER_BROWSER_ACTIVATION AND TLS_FIXER_TRACE_MODULE_PATHS))
	message(FATAL_ERROR "Startup-status provider selection requires queued browser-only activation")
endif()
if(TLS_FIXER_INSPECT_CONNECT_PATCH AND NOT
   (TLS_FIXER_BROWSER_START_DIAGNOSTICS AND TLS_FIXER_BROWSER_ACTIVATION AND TLS_FIXER_TRACE_MODULE_PATHS))
	message(FATAL_ERROR "Connect snapshots require the queued browser startup diagnostic")
endif()
if(TLS_FIXER_SELF_DISARM_ONLY OR TLS_FIXER_DISARM_RESULT_ONLY OR TLS_FIXER_INITIALIZE_ONLY
   OR TLS_FIXER_REDIRECTION_ONLY OR TLS_FIXER_PREPARE_ONLY)
	# These isolation profiles never install browser transport hooks.
	set(TLS_FIXER_BROWSER_POST_START OFF)
elseif(NOT TLS_FIXER_BROWSER_POST_START)
	message(FATAL_ERROR "Browser injection must run after native module start; early hook installation is unsafe")
endif()

set(CMAKE_C_FLAGS "-Wl,-q -Wall -Wextra -Werror -O3 -std=gnu11 -mgeneral-regs-only")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -fno-rtti -fno-exceptions")

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/../tls13/include
)

link_directories(
	${CMAKE_CURRENT_BINARY_DIR}
)

add_executable(tls_fixer.elf
	main.c
	native_contract.c
)
if(TLS_FIXER_ENABLE_SELF_DISARM)
    target_sources(tls_fixer.elf PRIVATE self_disarm.c)
endif()

target_compile_definitions(tls_fixer.elf PRIVATE
    TLS_FIXER_HTTP_PROVIDER_PATH="${TLS_FIXER_HTTP_PROVIDER_PATH}"
    TLS_FIXER_HTTP_TEST_TITLE_ID="${TLS_FIXER_HTTP_TEST_TITLE_ID}"
	TLS_FIXER_ENABLE_SELF_DISARM=$<BOOL:${TLS_FIXER_ENABLE_SELF_DISARM}>
	TLS_FIXER_SELF_DISARM_ONLY=$<BOOL:${TLS_FIXER_SELF_DISARM_ONLY}>
	TLS_FIXER_INITIALIZE_ONLY=$<BOOL:${TLS_FIXER_INITIALIZE_ONLY}>
	TLS_FIXER_REDIRECTION_ONLY=$<BOOL:${TLS_FIXER_REDIRECTION_ONLY}>
	TLS_FIXER_PREPARE_ONLY=$<BOOL:${TLS_FIXER_PREPARE_ONLY}>
		TLS_FIXER_ENABLE_BOOT_TRACE=$<BOOL:${TLS_FIXER_ENABLE_BOOT_TRACE}>
		TLS_FIXER_TRACE_MODULE_PATHS=$<BOOL:${TLS_FIXER_TRACE_MODULE_PATHS}>
	TLS_FIXER_BROWSER_INVENTORY=$<BOOL:${TLS_FIXER_BROWSER_INVENTORY}>
	TLS_FIXER_TRACE_ACTIVATION_ONLY=$<BOOL:${TLS_FIXER_TRACE_ACTIVATION_ONLY}>
	TLS_FIXER_MEMORY_PROBE=$<BOOL:${TLS_FIXER_MEMORY_PROBE}>
	TLS_FIXER_MAPPING_PROBE=$<BOOL:${TLS_FIXER_MAPPING_PROBE}>
	TLS_FIXER_ALLOCATION_PROBE=$<BOOL:${TLS_FIXER_ALLOCATION_PROBE}>
	TLS_FIXER_STACK_HEADROOM=$<BOOL:${TLS_FIXER_STACK_HEADROOM}>
	TLS_FIXER_PREPARE_EXTENDED_STACK=$<BOOL:${TLS_FIXER_PREPARE_EXTENDED_STACK}>
	TLS_FIXER_PREPARE_NO_MODULE_QUERIES=$<BOOL:${TLS_FIXER_PREPARE_NO_MODULE_QUERIES}>
	TLS_FIXER_PREPARE_TARGET_QUERY_ONLY=$<BOOL:${TLS_FIXER_PREPARE_TARGET_QUERY_ONLY}>
	TLS_FIXER_PREPARE_LIST_TARGET_ONLY=$<BOOL:${TLS_FIXER_PREPARE_LIST_TARGET_ONLY}>
	TLS_FIXER_PREPARE_NAME_QUERY=$<BOOL:${TLS_FIXER_PREPARE_NAME_QUERY}>
	TLS_FIXER_BROWSER_ACTIVATION=$<BOOL:${TLS_FIXER_BROWSER_ACTIVATION}>
	TLS_FIXER_BROWSER_START_DIAGNOSTICS=$<BOOL:${TLS_FIXER_BROWSER_START_DIAGNOSTICS}>
		TLS_FIXER_INSPECT_CONNECT_PATCH=$<BOOL:${TLS_FIXER_INSPECT_CONNECT_PATCH}>
		TLS_FIXER_BROWSER_POST_START=$<BOOL:${TLS_FIXER_BROWSER_POST_START}>
	TLS_FIXER_SKIP_DNS_START=$<BOOL:${TLS_FIXER_SKIP_DNS_START}>
	TLS_FIXER_SKIP_HTTP_START=$<BOOL:${TLS_FIXER_SKIP_HTTP_START}>
	TLS_FIXER_DISARM_RESULT_ONLY=$<BOOL:${TLS_FIXER_DISARM_RESULT_ONLY}>
)

if(TLS_FIXER_DISARM_RESULT_ONLY OR TLS_FIXER_ENABLE_BOOT_TRACE)
	target_sources(tls_fixer.elf PRIVATE disarm_result.c)
endif()

if(TLS_FIXER_ENABLE_BOOT_TRACE)
	target_sources(tls_fixer.elf PRIVATE boot_trace.c)
endif()
if(TLS_FIXER_STACK_HEADROOM)
	target_sources(tls_fixer.elf PRIVATE stack_probe.c)
endif()
if(TLS_FIXER_MEMORY_PROBE)
	target_sources(tls_fixer.elf PRIVATE memory_probe.c)
endif()
if(TLS_FIXER_MAPPING_PROBE)
    target_sources(tls_fixer.elf PRIVATE mapping_probe.c)
    target_link_libraries(tls_fixer.elf SceSysmemForKernel_stub)
endif()
if(TLS_FIXER_ALLOCATION_PROBE)
	target_sources(tls_fixer.elf PRIVATE allocation_probe.c)
endif()
if(TLS_FIXER_TRACE_MODULE_PATHS)
	target_sources(tls_fixer.elf PRIVATE trace_status.c)
endif()
if(TLS_FIXER_BROWSER_INVENTORY)
    target_sources(tls_fixer.elf PRIVATE browser_inventory.c)
endif()
if(TLS_FIXER_INSPECT_CONNECT_PATCH)
	target_sources(tls_fixer.elf PRIVATE code_snapshot.c)
endif()
if(TLS_FIXER_BROWSER_POST_START)
	target_sources(tls_fixer.elf PRIVATE post_start.c)
endif()

target_link_libraries(tls_fixer.elf
	SceSysclibForDriver_stub
	SceSysmemForDriver_stub
	SceIofilemgrForDriver_stub
)

if(NOT TLS_FIXER_SELF_DISARM_ONLY AND NOT TLS_FIXER_DISARM_RESULT_ONLY)
	target_sources(tls_fixer.elf PRIVATE native_module_api.c)
	target_sources(tls_fixer.elf PRIVATE tls13_loader.c ../tls13/src/path.c)
	if(NOT TLS_FIXER_INITIALIZE_ONLY)
		target_sources(tls_fixer.elf PRIVATE hook_guard.c)
	endif()
	target_link_libraries(tls_fixer.elf
		SceThreadmgrForDriver_stub
		SceCpuForDriver_stub
		taihenModuleUtils_stub
		taihenForKernel_stub
		SceDebugForDriver_stub
		SceModulemgrForDriver_stub
		SceModulemgrForKernel_stub
		SceSysrootForDriver_stub
		SceSysrootForKernel_stub
		SceKernelUtilsForDriver_stub
	)
endif()

set_target_properties(tls_fixer.elf
	PROPERTIES LINK_FLAGS "-nostdlib"
	COMPILE_FLAGS "-D__VITA_KERNEL__"
)

add_custom_target(tls_fixer.skprx ALL
	COMMAND vita-elf-create -e ${CMAKE_SOURCE_DIR}/tls_fixer.yml tls_fixer.elf tls_fixer.velf
	COMMAND vita-make-fself -c tls_fixer.velf tls_fixer.skprx
)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_custom_target(tls_fixer_kernel_register_check
	COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/../tools/verify_kernel_registers.py
		$<TARGET_FILE:tls_fixer.elf>
	DEPENDS tls_fixer.elf
	VERBATIM
)
add_dependencies(tls_fixer.skprx tls_fixer_kernel_register_check)
