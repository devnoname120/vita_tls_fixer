#include "probe.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    CheckResult attempts[2];
    const char *body[2];
    unsigned calls;
    int verification[2];
} Fixture;
static int fake_fetch(void *context, unsigned test, int verify, char *body,
                       size_t *length, CheckResult *result) {
    Fixture *f=context;
    assert(test<4 && f->calls<2);
    unsigned i=f->calls++;
    f->verification[i]=verify;
    *result=f->attempts[i];
    result->verification_disabled = !verify && result->error != (int)0x8043506b;
    *length=f->body[i]?strlen(f->body[i]):0;
    if (*length) memcpy(body,f->body[i],*length);
    return result->error;
}
static CheckResult run(Fixture *f, unsigned version) {
    char body[64];
    size_t length=0;
    CheckResult r={0};
    check_run_protocol(version,fake_fetch,f,body,&length,&r);
    if(f->calls) assert(f->verification[0]==1);
    if(f->calls==2) assert(f->verification[1]==0);
    return r;
}
int main(void) {
    CheckResult cert={.state=CHECK_FAIL,.error=(int)0x80431075,
        .ssl_error=(int)0x80435060,.ssl_detail=0x20,.elapsed_ms=100};
    CheckResult tls={.state=CHECK_FAIL,.error=(int)0x80431075,
        .ssl_error=(int)0x80435061,.elapsed_ms=100};
    CheckResult ok={.state=CHECK_PASS,.http_code=200,.elapsed_ms=200};
    for(unsigned version=0;version<4;++version) {
        char reply[16];snprintf(reply,sizeof(reply),"TLS 1.%u",version);
        Fixture f={.attempts={ok},.body={reply}};
        CheckResult r=run(&f,version);
        assert(f.calls==1 && r.protocol_confirmed && !r.retry.attempted);

        f=(Fixture){.attempts={tls,tls}};
        f.attempts[0].tls_fixer_active=1;
        f.attempts[0].ssl_detail=0xffff8880u;
        r=run(&f,version);
        assert(f.calls==(version<2?1u:2u));
        assert(r.retry.attempted==(version>=2));
        assert(check_expected_legacy_block(version,&r)==(version<2));

        f=(Fixture){.attempts={cert,ok},.body={NULL,reply}};
        f.attempts[0].tls_fixer_active=1;
        r=run(&f,version);
        assert(f.calls==2 && r.state==CHECK_WARNING && r.retry.protocol_confirmed);
        assert(r.error==cert.error && r.ssl_error==cert.ssl_error && r.ssl_detail==0x20);
        assert(r.http_code==0 && r.retry.http_code==200 && r.elapsed_ms==100);
        CheckProtocolDisplay d=check_protocol_display(version,&r);
        assert(!strcmp(d.label,"Cert error") && d.style==CHECK_WARNING && !d.qualifier);
        assert(!check_should_retry_unverified(version,&r));

        f=(Fixture){.attempts={tls,ok},.body={NULL,reply}};
        r=run(&f,version);d=check_protocol_display(version,&r);
        assert(!strcmp(d.label,"Unverified") && d.style==CHECK_WARNING && !d.qualifier);

        f=(Fixture){.attempts={tls,tls}};
        r=run(&f,version);d=check_protocol_display(version,&r);
        assert(f.calls==2 && !r.retry.protocol_confirmed && !strcmp(d.label,"TLS error"));
        assert(d.style!=CHECK_PASS && !d.qualifier);

        f=(Fixture){.attempts={tls,{.state=CHECK_FAIL,.error=(int)0x8043506b}}};
        r=run(&f,version);
        char detail[128];check_protocol_detail(version,&r,detail,sizeof(detail));
        assert(r.retry.attempted && !r.retry.verification_disabled && !r.retry.protocol_confirmed);
        assert(strstr(detail,"retry unavailable") && !strcmp(check_protocol_display(version,&r).label,"TLS error"));

        f=(Fixture){.attempts={cert,ok},.body={NULL,"<html>redirect</html>"}};
        r=run(&f,version);
        assert(!r.retry.protocol_confirmed && r.retry.error==-1 && r.state==CHECK_FAIL);
        assert(!strcmp(check_protocol_display(version,&r).label,"Cert error"));

        f=(Fixture){.attempts={cert,ok},.body={NULL,reply}};
        f.attempts[1].state=CHECK_FAIL;f.attempts[1].restore_error=-9;
        r=run(&f,version);
        assert(r.restore_error==-9 && !r.retry.protocol_confirmed);
        assert(!strcmp(check_protocol_display(version,&r).label,"Check error"));
    }
    CheckResult no_retry[]={
        {.state=CHECK_FAIL,.error=(int)0x80431068}, /* timeout */
        {.state=CHECK_FAIL,.error=(int)0x80436007}, /* DNS */
        {.state=CHECK_FAIL,.error=(int)0x80431080}, /* cancelled */
        {.state=CHECK_FAIL,.error=(int)0x80431075,.http_code=200}, /* body read */
        {.state=CHECK_FAIL,.error=-1,.http_code=403},
        {.state=CHECK_FAIL,.error=(int)0x80431075,.restore_error=-1},
    };
    for(unsigned i=0;i<sizeof(no_retry)/sizeof(no_retry[0]);++i) {
        Fixture f={.attempts={no_retry[i]}};(void)run(&f,0);assert(f.calls==1);
    }
    for(unsigned test=CHECK_REPORT;test<=CHECK_TEST_COUNT;++test) {
        Fixture f={0};assert(!check_should_retry_unverified(test,&cert));
        (void)run(&f,test);assert(f.calls==0);
    }
    puts("Verified-first protocol probes, one isolated retry, preserved errors and honest states: PASS");
    return 0;
}
