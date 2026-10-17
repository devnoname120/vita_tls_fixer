#include "probe.h"
#include <string.h>

void check_run_protocol(unsigned test, CheckFetch fetch, void *context, char *body,
                        size_t *length, CheckResult *result) {
    if (test >= 4) {
        memset(result, 0, sizeof(*result));
        result->state = CHECK_FAIL;
        result->error = -1;
        return;
    }
    fetch(context, test, 1, body, length, result);
    check_protocol_response(test, body, *length, result);
    if (check_should_retry_unverified(test, result)) {
        CheckResult retry = {0};
        fetch(context, test, 0, body, length, &retry);
        check_protocol_response(test, body, *length, &retry);
        check_record_retry(result, &retry);
    }
}
