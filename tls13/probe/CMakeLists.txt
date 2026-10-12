include("${VITASDK}/share/vita.cmake" REQUIRED)

add_executable(tls_fixer_probe
    main_vita.c application.c core.c protocol.c report.c report_vita.c trust.c
    platform_vita.c screen.c screen_vita.c nonce.c nonce_vita.c
    ../provider/platform_shims.c ../../font.c)
target_include_directories(tls_fixer_probe PRIVATE . ../provider "${TLS_FIXER_PROBE_GENERATED}")
target_compile_features(tls_fixer_probe PRIVATE c_std_11)
target_compile_options(tls_fixer_probe PRIVATE -std=gnu11 -Wall -Wextra -Werror
    -ffunction-sections -fdata-sections -O2)
target_link_options(tls_fixer_probe PRIVATE -Wl,--gc-sections)
target_link_libraries(tls_fixer_probe PRIVATE mbedtls mbedx509 tfpsacrypto
    SceNet_stub SceNetCtl_stub SceSysmodule_stub SceRtc_stub SceDisplay_stub
    SceCtrl_stub SceLibKernel_stub SceKernelThreadMgr_stub SceIofilemgr_stub)

vita_create_self(tls_fixer_probe.self tls_fixer_probe)
vita_create_vpk(tls_fixer_probe.vpk TLSF00002 tls_fixer_probe.self
    VERSION "00.10" NAME "tls_fixer Standalone Probe"
    FILE "${TLS_FIXER_PROBE_GENERATED}/probe-ca.pem" probe-ca.pem
         "${TLS_FIXER_PROBE_GENERATED}/probe-build.json" probe-build.json)
