#include "tls_fixer/error_map.h"

uint32_t tls_fixer_map_certificate_detail(uint32_t provider_flags) {
    uint32_t detail = 0;

    if ((provider_flags & TLS_FIXER_CERT_INTERNAL) != 0) {
        detail |= TLS_FIXER_SCE_HTTPS_DETAIL_INTERNAL;
    }
    if ((provider_flags & TLS_FIXER_CERT_INVALID) != 0) {
        detail |= TLS_FIXER_SCE_HTTPS_DETAIL_INVALID_CERT;
    }
    if ((provider_flags & TLS_FIXER_CERT_HOSTNAME) != 0) {
        detail |= TLS_FIXER_SCE_HTTPS_DETAIL_CN_CHECK;
    }
    if ((provider_flags & TLS_FIXER_CERT_EXPIRED) != 0) {
        detail |= TLS_FIXER_SCE_HTTPS_DETAIL_NOT_AFTER;
    }
    if ((provider_flags & TLS_FIXER_CERT_FUTURE) != 0) {
        detail |= TLS_FIXER_SCE_HTTPS_DETAIL_NOT_BEFORE;
    }
    if ((provider_flags & TLS_FIXER_CERT_UNKNOWN_CA) != 0) {
        detail |= TLS_FIXER_SCE_HTTPS_DETAIL_UNKNOWN_CA;
    }

    return detail;
}

uint32_t tls_fixer_filter_certificate_flags(uint32_t provider_flags, uint32_t https_options) {
    uint32_t filtered;

    if ((https_options & TLS_FIXER_SCE_HTTPS_OPTION_SERVER_VERIFY) == 0) {
        return 0;
    }

    filtered = provider_flags & (TLS_FIXER_CERT_INVALID | TLS_FIXER_CERT_INTERNAL);
    if ((https_options & TLS_FIXER_SCE_HTTPS_OPTION_CN_CHECK) != 0) {
        filtered |= provider_flags & TLS_FIXER_CERT_HOSTNAME;
    }
    if ((https_options & TLS_FIXER_SCE_HTTPS_OPTION_NOT_AFTER) != 0) {
        filtered |= provider_flags & TLS_FIXER_CERT_EXPIRED;
    }
    if ((https_options & TLS_FIXER_SCE_HTTPS_OPTION_NOT_BEFORE) != 0) {
        filtered |= provider_flags & TLS_FIXER_CERT_FUTURE;
    }
    if ((https_options & TLS_FIXER_SCE_HTTPS_OPTION_KNOWN_CA) != 0) {
        filtered |= provider_flags & TLS_FIXER_CERT_UNKNOWN_CA;
    }
    return filtered;
}

TlsFixerMappedError tls_fixer_map_outcome(TlsFixerOutcome outcome, uint32_t detail) {
    TlsFixerMappedError mapped = {
        .hook_result = 0,
        .ssl_error = 0,
        .detail = detail,
        .fatal = 0,
    };

    switch (outcome) {
        case TLS_FIXER_OUTCOME_OK:
        case TLS_FIXER_OUTCOME_CLOSE_NOTIFY:
            break;
        case TLS_FIXER_OUTCOME_WANT_READ:
        case TLS_FIXER_OUTCOME_WANT_WRITE:
            mapped.hook_result = TLS_FIXER_SCE_HTTP_ERROR_EAGAIN;
            break;
        case TLS_FIXER_OUTCOME_TIMEOUT:
            mapped.hook_result = TLS_FIXER_SCE_HTTP_ERROR_TIMEOUT;
            break;
        case TLS_FIXER_OUTCOME_CERTIFICATE:
            mapped.hook_result = TLS_FIXER_SCE_HTTP_ERROR_SSL;
            mapped.ssl_error = TLS_FIXER_SCE_HTTPS_ERROR_CERT;
            mapped.detail = tls_fixer_map_certificate_detail(detail);
            mapped.fatal = 1;
            break;
        case TLS_FIXER_OUTCOME_HANDSHAKE:
            mapped.hook_result = TLS_FIXER_SCE_HTTP_ERROR_SSL;
            mapped.ssl_error = TLS_FIXER_SCE_HTTPS_ERROR_HANDSHAKE;
            mapped.fatal = 1;
            break;
        case TLS_FIXER_OUTCOME_IO:
        case TLS_FIXER_OUTCOME_EOF:
            mapped.hook_result = TLS_FIXER_SCE_HTTP_ERROR_SSL;
            mapped.ssl_error = TLS_FIXER_SCE_HTTPS_ERROR_IO;
            mapped.fatal = 1;
            break;
        case TLS_FIXER_OUTCOME_NO_MEMORY:
            mapped.hook_result = TLS_FIXER_SCE_HTTP_ERROR_OUT_OF_MEMORY;
            mapped.ssl_error = TLS_FIXER_SCE_HTTPS_ERROR_INTERNAL;
            mapped.fatal = 1;
            break;
        case TLS_FIXER_OUTCOME_INTERNAL:
        default:
            mapped.hook_result = TLS_FIXER_SCE_HTTP_ERROR_SSL;
            mapped.ssl_error = TLS_FIXER_SCE_HTTPS_ERROR_INTERNAL;
            mapped.fatal = 1;
            break;
    }

    return mapped;
}
