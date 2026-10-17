"""Run the actual Vita fetch function against a deterministic host API fixture.

The production function is extracted verbatim; only the Sony API boundary and
clock/UI logging calls are substituted. No network or Vita access occurs.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

sample = Path(__file__).resolve().parents[1]
source = (sample / "main.c").read_text()
fetch = source[source.index("static int fetch("):source.index("static int detect_tls_fixer(")]
prefix = r'''
#include "model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define SCE_HTTP_VERSION_1_1 1
#define SCE_HTTP_DISABLE 0
#define SCE_HTTP_METHOD_GET 0
#define SCE_HTTP_HEADER_OVERWRITE 0
#define NOOP2(a,b) ((void)(a), (void)(b), 0)
#define sceHttpCreateTemplate(a,b,c) ((void)(a),(void)(b),(void)(c),fake_template())
#define sceHttpSetResolveTimeOut(a,b) NOOP2(a,b)
#define sceHttpSetResolveRetry(a,b) NOOP2(a,b)
#define sceHttpSetConnectTimeOut(a,b) NOOP2(a,b)
#define sceHttpSetSendTimeOut(a,b) NOOP2(a,b)
#define sceHttpSetRecvTimeOut(a,b) NOOP2(a,b)
#define sceHttpSetAutoRedirect(a,b) NOOP2(a,b)
#define sceHttpSetCookieEnabled(a,b) NOOP2(a,b)
#define sceHttpSetResponseHeaderMaxSize(a,b) NOOP2(a,b)
#define sceHttpCreateConnectionWithURL(a,b,c) ((void)(a),(void)(b),(void)(c),2)
#define sceHttpCreateRequestWithURL(a,b,c,d) ((void)(a),(void)(b),(void)(c),(void)(d),3)
#define sceHttpAddRequestHeader(a,b,c,d) ((void)(a),(void)(b),(void)(c),(void)(d),0)
static int active_request = -1, cancelled, abort_sent, run_identity;
static CheckService service;
static unsigned next_request_identity, request_identity;
static uint64_t request_begin, ticks;
static int fake_http, fake_error, reads, deletes;
static uint64_t now_ms(void) { return ++ticks; }
static uint64_t sceKernelGetSystemTimeWide(void) { return ++ticks * 1000; }
static uint64_t check_diag_time(void) { return ++ticks; }
static void lock(void) {}
static void unlock(void) {}
static int stopped(void) { return cancelled; }
static void check_diag(const char *format, ...) { (void)format; }
static void check_diag_sync(void) {}
static int sceHttpSendRequest(int request, const void *data, unsigned size) {
    assert(request == 3 && !data && !size);
    return fake_error;
}
static int sceHttpGetStatusCode(int request, int *code) {
    assert(request == 3);
    *code = fake_http;
    return 0;
}
static int sceHttpReadData(int request, void *body, unsigned size) {
    assert(request == 3 && body && size);
    ++reads;
    return 0;
}
static int sceHttpsGetSslError(int request, int *error, unsigned *detail) {
    assert(request == 3);
    if (fake_error == (int)0x80431075) {
        *error = (int)0x80435060;
        *detail = 2;
    }
    return 0;
}
static int sceHttpDeleteRequest(int request) { assert(request == 3); ++deletes; return 0; }
static int sceHttpDeleteConnection(int connection) { assert(connection == 2); ++deletes; return 0; }
static int sceHttpDeleteTemplate(int tmpl) { assert(tmpl == 1); ++deletes; return 0; }

#define VERIFY_FLAGS 0x3d
static int policy_on, enables, disables, fail_enable, fail_disable, fail_template, templates;
static int sceHttpsEnableOption(unsigned flags) {
    assert(flags==VERIFY_FLAGS);
    if (++enables==fail_enable) return -99;
    policy_on=1; return 0;
}
static int sceHttpsDisableOption(unsigned flags) {
    assert(flags==VERIFY_FLAGS); ++disables;
    /* Treat a failing policy call as possibly having partially changed state. */
    policy_on=0; return fail_disable ? -98 : 0;
}
static int fake_template(void) { ++templates; return fail_template ? -97 : 1; }
'''
suffix = r'''
static void exercise(unsigned test, int http, int failure, int expected_pass, int expected_reads) {
    char body[CHECK_BODY_MAX + 1];
    CheckResult result;
    size_t length = 123;
    fake_http = http;
    fake_error = failure;
    reads = deletes = cancelled = 0;
    int rc = fetch(NULL, test, 1, body, &length, &result);
    assert((rc == 0) == expected_pass);
    assert(result.state == (expected_pass ? CHECK_PASS : CHECK_FAIL));
    assert(result.http_code == (failure ? 0 : http));
    assert(reads == expected_reads && deletes == 3 && active_request == -1);
    if (failure) assert(result.error == failure);
    if (failure == (int)0x80431075)
        assert(result.ssl_error == (int)0x80435060 && result.ssl_detail == 2);
    if (expected_pass && test == CHECK_PLAYSTATION) {
        char expected[128];
        snprintf(expected, sizeof(expected), "Connected (HTTP %d)", http);
        assert(!strcmp(result.message, expected) && length == 0);
    }
    printf("PASS: actual fetch test=%u HTTP=%d error=0x%08X pass=%d reads=%d; cleanup complete\n",
           test, http, (unsigned)failure, expected_pass, reads);
}
static void existing_cases(void) {
    const int statuses[] = {200, 204, 302, 403, 404, 503, 599};
    for (unsigned i = 0; i < sizeof(statuses)/sizeof(statuses[0]); ++i)
        exercise(CHECK_PLAYSTATION, statuses[i], 0, 1, 0);
    exercise(CHECK_PLAYSTATION, 0, 0, 0, 0);
    exercise(CHECK_PLAYSTATION, 100, 0, 0, 0);
    exercise(CHECK_PLAYSTATION, 600, 0, 0, 0);
    exercise(CHECK_PLAYSTATION, 0, (int)0x80431075, 0, 0);
    exercise(CHECK_PLAYSTATION, 0, (int)0x80431068, 0, 0);
    exercise(CHECK_PLAYSTATION, 0, (int)0x80436007, 0, 0);
    exercise(3, 200, 0, 1, 1);
    exercise(3, 403, 0, 0, 1);
    exercise(CHECK_REPORT, 503, 0, 0, 1);
    return;
}

static void reset(void) {
    fake_http=200; fake_error=reads=deletes=cancelled=0;
    policy_on=enables=disables=fail_enable=fail_disable=fail_template=templates=0;
}
static void policy_case(int failure, int begin_fail, int disable_fail, int restore_fail,
                        int template_fail, int cancel, unsigned test) {
    reset();fake_error=failure;fail_enable=restore_fail?2:begin_fail;
    fail_disable=disable_fail;fail_template=template_fail;cancelled=cancel;
    char body[CHECK_BODY_MAX+1];size_t length=0;CheckResult r;
    int rc=fetch(NULL,test,0,body,&length,&r);
    if (restore_fail) {
        assert(rc==-99 && r.restore_error==-99 && r.state==CHECK_FAIL && !policy_on);
    } else {
        assert(policy_on && !r.restore_error);
        if (failure || begin_fail || disable_fail || template_fail || cancel || test>=4)
            assert(rc<0 && r.state==CHECK_FAIL);
        else assert(rc==0 && r.state==CHECK_PASS);
    }
    assert(r.verification_disabled==(!cancel && test<4 && !begin_fail && !disable_fail));
    assert(active_request==-1);
    if(cancel || test>=4) assert(disables==0 && templates==0 && enables==1);
    else if(begin_fail) assert(disables==0 && templates==0 && enables==2);
    else if(disable_fail) assert(disables==1 && templates==0 && enables==2);
    else assert(disables==1 && templates==1 && enables==2);
    /* Next verified request must reset policy even after restoration failed. */
    fail_enable=fail_disable=fail_template=cancelled=fake_error=0;
    assert(fetch(NULL,CHECK_PLAYSTATION,1,body,&length,&r)==0);
    assert(policy_on && r.state==CHECK_PASS && !r.retry.attempted && !r.verification_disabled);
}
int main(void) {
    existing_cases();
    policy_case(0,0,0,0,0,0,0);
    policy_case((int)0x80431075,0,0,0,0,0,0);
    policy_case((int)0x80431068,0,0,0,0,0,0);
    policy_case(0,1,0,0,0,0,0);
    policy_case(0,0,1,0,0,0,0);
    policy_case(0,0,0,1,0,0,0);
    policy_case(0,0,0,0,1,0,0);
    policy_case(0,0,0,0,0,1,0);
    policy_case(0,0,0,0,0,0,CHECK_PLAYSTATION);
    policy_case(0,0,0,0,0,0,CHECK_REPORT);
    puts("Actual native request adapter: verified-first, scoped override, failure cleanup and policy restoration PASS");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="tls-check-fetch-") as directory:
    out = Path(directory)
    harness = out / "fetch_test.c"
    harness.write_text(prefix + fetch + suffix)
    subprocess.run([sys.argv[1] if len(sys.argv)>1 else "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-g",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-I", str(sample),
                    str(harness), str(sample / "model.c"), "-o", str(out / "fetch_test")], check=True)
    subprocess.run([str(out / "fetch_test")], check=True)
