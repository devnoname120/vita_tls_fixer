#ifndef TLS_FIXER_INSTALLER_OPTIONS_H
#define TLS_FIXER_INSTALLER_OPTIONS_H
#define TLS_FIXER_VERSION "0.1.0"
enum TlsFixerOption {
    TLS_FIXER_OPTION_FULL,
    TLS_FIXER_OPTION_BROWSER,
    TLS_FIXER_OPTION_SYSTEM,
    TLS_FIXER_OPTION_CERTIFICATES,
    TLS_FIXER_OPTION_DOWNLOAD_CERTIFICATES,
    TLS_FIXER_OPTION_EXIT,
    TLS_FIXER_OPTION_COUNT
};
enum TlsFixerComponent {
    TLS_FIXER_COMPONENT_COORDINATOR = 1u,
    TLS_FIXER_COMPONENT_BROWSER = 2u,
    TLS_FIXER_COMPONENT_SYSTEM = 4u,
    TLS_FIXER_COMPONENT_CERTIFICATES = 8u
};
typedef struct { unsigned components; int removing; } TlsFixerInstallPlan;
int tls_fixer_plan_option(enum TlsFixerOption option, int removing,
    int browser_present, int system_present, TlsFixerInstallPlan *plan);
typedef int (*TlsFixerInstallAction)(void *context, unsigned component, int removing);
int tls_fixer_execute_plan(const TlsFixerInstallPlan *plan, TlsFixerInstallAction action, void *context);
#endif
