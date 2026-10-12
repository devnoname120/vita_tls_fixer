cmake_minimum_required(VERSION 3.16)

set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_C_COMPILER "arm-vita-eabi-gcc")
set(CMAKE_CXX_COMPILER "arm-vita-eabi-g++")

project(HENkaku)

option(TLS_FIXER_SELF_DISARM_ONLY "Build a diagnostic with no module redirection or TLS injection" OFF)
option(TLS_FIXER_INITIALIZE_ONLY "Stop the diagnostic after loader initialization, before installing hooks" OFF)
option(TLS_FIXER_REDIRECTION_ONLY "Install module path redirection but do not start TLS or DNS providers" OFF)
option(TLS_FIXER_PREPARE_ONLY "Validate provider prerequisites without calling module load/start" OFF)
option(TLS_FIXER_ENABLE_BOOT_TRACE "Persist bounded synchronized preparation-stage records" OFF)
option(TLS_FIXER_TRACE_MODULE_PATHS "Queue process-namespace diagnostics for observation or browser-only activation" OFF)
option(TLS_FIXER_STACK_HEADROOM "Measure native current kernel-stack headroom in trace records" OFF)
option(TLS_FIXER_PREPARE_EXTENDED_STACK "Run preparation diagnostics on a 16 KiB native-managed stack" OFF)
option(TLS_FIXER_PREPARE_NO_MODULE_QUERIES "Omit module queries only in the native-stack preparation diagnostic" OFF)
option(TLS_FIXER_PREPARE_TARGET_QUERY_ONLY "Query only the loaded target, without enumeration, in preparation diagnostics" OFF)
option(TLS_FIXER_PREPARE_LIST_TARGET_ONLY "Enumerate IDs and query the target, without inspecting other modules" OFF)
option(TLS_FIXER_PREPARE_NAME_QUERY "Use taiHEN name queries for diagnostic provider-presence checking" OFF)
option(TLS_FIXER_BROWSER_ACTIVATION "Activate only browser TLS with traced name checks and no application/DNS startup" OFF)
option(TLS_FIXER_BROWSER_START_DIAGNOSTICS "Select the separate startup-status diagnostic provider" OFF)
option(TLS_FIXER_INSPECT_CONNECT_PATCH "Read the connect entry around diagnostic provider startup" OFF)
option(TLS_FIXER_BROWSER_POST_START "Defer browser injection until native module start returns" OFF)
option(TLS_FIXER_DISARM_RESULT_ONLY "Report the self-disarm result without later initialization" OFF)
if(TLS_FIXER_DISARM_RESULT_ONLY AND (TLS_FIXER_SELF_DISARM_ONLY OR TLS_FIXER_INITIALIZE_ONLY
   OR TLS_FIXER_REDIRECTION_ONLY OR TLS_FIXER_PREPARE_ONLY OR TLS_FIXER_ENABLE_BOOT_TRACE))
	message(FATAL_ERROR "The disarm-result diagnostic must be selected alone")
endif()
if(TLS_FIXER_ENABLE_BOOT_TRACE AND NOT (TLS_FIXER_PREPARE_ONLY OR TLS_FIXER_REDIRECTION_ONLY OR TLS_FIXER_BROWSER_ACTIVATION))
	message(FATAL_ERROR "The boot trace requires the preparation-only or redirection-only diagnostic")
endif()
if(TLS_FIXER_STACK_HEADROOM AND NOT TLS_FIXER_ENABLE_BOOT_TRACE)
	message(FATAL_ERROR "Stack-headroom measurements require the diagnostic boot trace")
endif()
if(TLS_FIXER_TRACE_MODULE_PATHS AND NOT
   ((TLS_FIXER_REDIRECTION_ONLY OR TLS_FIXER_BROWSER_ACTIVATION) AND TLS_FIXER_ENABLE_BOOT_TRACE AND TLS_FIXER_STACK_HEADROOM))
	message(FATAL_ERROR "Queued path diagnostics require redirection-only or browser-only activation, boot trace and headroom reporting")
endif()
if(TLS_FIXER_PREPARE_EXTENDED_STACK AND NOT
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
if(TLS_FIXER_PREPARE_NAME_QUERY AND (TLS_FIXER_PREPARE_NO_MODULE_QUERIES OR TLS_FIXER_PREPARE_TARGET_QUERY_ONLY OR TLS_FIXER_PREPARE_LIST_TARGET_ONLY OR NOT
   ((TLS_FIXER_PREPARE_ONLY OR TLS_FIXER_BROWSER_ACTIVATION) AND TLS_FIXER_PREPARE_EXTENDED_STACK AND TLS_FIXER_ENABLE_BOOT_TRACE AND TLS_FIXER_STACK_HEADROOM)))
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
if(TLS_FIXER_BROWSER_POST_START AND NOT (TLS_FIXER_BROWSER_ACTIVATION AND TLS_FIXER_TRACE_MODULE_PATHS))
	message(FATAL_ERROR "Post-start injection requires queued browser-only activation")
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
	self_disarm.c
	native_contract.c
)

target_compile_definitions(tls_fixer.elf PRIVATE
	TLS_FIXER_SELF_DISARM_ONLY=$<BOOL:${TLS_FIXER_SELF_DISARM_ONLY}>
	TLS_FIXER_INITIALIZE_ONLY=$<BOOL:${TLS_FIXER_INITIALIZE_ONLY}>
	TLS_FIXER_REDIRECTION_ONLY=$<BOOL:${TLS_FIXER_REDIRECTION_ONLY}>
	TLS_FIXER_PREPARE_ONLY=$<BOOL:${TLS_FIXER_PREPARE_ONLY}>
		TLS_FIXER_ENABLE_BOOT_TRACE=$<BOOL:${TLS_FIXER_ENABLE_BOOT_TRACE}>
		TLS_FIXER_TRACE_MODULE_PATHS=$<BOOL:${TLS_FIXER_TRACE_MODULE_PATHS}>
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
if(TLS_FIXER_TRACE_MODULE_PATHS)
	target_sources(tls_fixer.elf PRIVATE trace_status.c)
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
