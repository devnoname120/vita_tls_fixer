/* SPDX-License-Identifier: 0BSD */
#include "http.h"
#include <string.h>
static int equal(const char *s,size_t n,const char *lower) {
    if(strlen(lower)!=n)return 0;
    for(size_t i=0;i<n;++i){unsigned c=(unsigned char)s[i];if(c>='A'&&c<='Z')c+='a'-'A';if(c!=(unsigned char)lower[i])return 0;}
    return 1;
}
void store_http_init(StoreHttpHeaders *s){memset(s,0,sizeof(*s));s->first=1;}
static int line_done(StoreHttpHeaders *s) {
    size_t n=s->line_length;
    if(s->first) {
        if(n<13||(memcmp(s->line,"HTTP/1.0 ",9)&&memcmp(s->line,"HTTP/1.1 ",9))||s->line[12]!=' ')return -1;
        for(size_t i=9;i<12;++i){if(s->line[i]<'0'||s->line[i]>'9')return -1;s->code=s->code*10+(unsigned)(s->line[i]-'0');}
        if(s->code<200||s->code>599)return -1;
        s->first=0;return 0;
    }
    if(!n&&!s->overflow){s->ready=1;return 0;}
    if(s->line[0]==' '||s->line[0]=='\t')return -1;
    size_t colon=0;while(colon<n&&s->line[colon]!=':')++colon;
    if(!colon)return -1;
    if(colon==n)return s->overflow?0:-1; /* An overlong unknown field name. */
    size_t first=colon+1,last=n;
    while(first<last&&(s->line[first]==' '||s->line[first]=='\t'))++first;
    while(last>first&&(s->line[last-1]==' '||s->line[last-1]=='\t'))--last;
    if(equal(s->line,colon,"transfer-encoding"))return -1; /* Not requested with HTTP/1.0. */
    if(equal(s->line,colon,"content-encoding")&&(s->overflow||!equal(s->line+first,last-first,"identity")))return -1;
    if(equal(s->line,colon,"content-length")) {
        if(s->have_length||s->overflow||first==last)return -1;
        s->have_length=1;
        for(size_t i=first;i<last;++i){unsigned c=(unsigned char)s->line[i];if(c<'0'||c>'9'||s->content_length>(UINT64_MAX-(c-'0'))/10)return -1;s->content_length=s->content_length*10+(c-'0');}
    }
    return 0;
}
int store_http_feed(StoreHttpHeaders *s,const char *data,size_t size,size_t *consumed) {
    if(!s||!consumed)return -1;
    *consumed=0;
    if(s->error||(!data&&size))return -1;
    while(*consumed<size&&!s->ready) {
        unsigned c=(unsigned char)data[(*consumed)++];
        if(++s->bytes>STORE_COVER_HEADER_LIMIT)goto bad;
        if(s->cr) {
            if(c!='\n')goto bad;
            s->cr=0;
            if(line_done(s)<0)goto bad;
            s->line_length=s->overflow=0;continue;
        }
        if(c=='\r'){s->cr=1;continue;}
        if(c=='\n'||(c!='\t'&&(c<32||c>126)))goto bad;
        if(s->line_length<sizeof(s->line)-1)s->line[s->line_length++]=(char)c;
        else s->overflow=1;
    }
    if(!s->ready&&s->bytes==STORE_COVER_HEADER_LIMIT)goto bad;
    return s->ready?1:0;
bad:s->error=1;return -1;
}

int store_response_init(StoreCoverResponse *s, const char *id) {
    if (!s) return -1;
    memset(s, 0, sizeof(*s));
    store_http_init(&s->headers);
    if (store_json_init(&s->json, id) < 0) { s->error = 1; return -1; }
    return 0;
}
int store_response_feed(StoreCoverResponse *s, const char *data, size_t size) {
    if (!s || s->error || (!data && size)) return -1;
    size_t used = 0;
    if (!s->headers.ready && store_http_feed(&s->headers, data, size, &used) < 0) goto bad;
    if (!s->headers.ready) return 0;
    if (s->headers.code != 200) return 1;
    size_t bytes = size - used;
    if (s->received > UINT64_MAX - bytes || (s->headers.have_length &&
        (s->received > s->headers.content_length || bytes > s->headers.content_length - s->received))) goto bad;
    s->received += bytes;
    if (bytes && store_json_feed(&s->json, data + used, bytes) < 0) goto bad;
    return s->headers.have_length && s->received == s->headers.content_length ? 1 : 0;
bad:
    s->error = 1;
    return -1;
}
int store_response_finish(StoreCoverResponse *s, char out[STORE_COVER_URL_SIZE]) {
    if (!out) return -1;
    out[0] = 0;
    if (!s || s->error || !s->headers.ready) return -1;
    if (s->headers.code != 200) return s->headers.code == 404 || s->headers.code == 410 ? 1 : -1;
    if (s->headers.have_length && s->received != s->headers.content_length) return -1;
    if (s->json.error || !s->json.done) return -1;
    return store_json_finish(&s->json, out) == 0 ? 0 : 1;
}
