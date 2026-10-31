/* SPDX-License-Identifier: 0BSD */
#include "json_stream.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ID "EP0001-CUSA00001_00-ABCDEFGHIJKLMNOP"
#define URL "https://vulcan.dl.playstation.net/img/cfn/cover.png"
#define GOOD "{\"id\":\"" ID "\",\"images\":[{\"type\":10,\"url\":\"" URL "\"}]}"
static int run(const char *data,size_t n,size_t chunk,char *out) {
    StoreJsonStream s;assert(store_json_init(&s,ID)==0);
    for(size_t at=0;at<n;){size_t step=n-at<chunk?n-at:chunk;if(store_json_feed(&s,data+at,step)<0)return -1;at+=step;}
    return store_json_finish(&s,out);
}
int main(int argc,char **argv) {
    char out[STORE_COVER_URL_SIZE];
    assert(sizeof(StoreJsonStream)<2048);
    for(size_t chunk=1;chunk<=strlen(GOOD);++chunk){assert(run(GOOD,strlen(GOOD),chunk,out)==0);assert(!strcmp(out,URL));}
    for(size_t n=0;n<strlen(GOOD);++n)assert(run(GOOD,n,1,out)<0);
    const char reverse[]="{\"links\":[" GOOD "],\"images\":[{\"url\":\"https:\\/\\/vulcan.dl.playstation.net\\/img\\/cfn\\/cover.png\",\"unused\":{\"type\":11,\"array\":[null,true,false,-0.12e+20]},\"t\\u0079pe\":10}],\"\\u0069d\":\"" ID "\"}";
    for(size_t n=1;n<100;++n)assert(run(reverse,strlen(reverse),n,out)==0&&!strcmp(out,URL));
    const char *bad[]={"[]","{}","null",GOOD "x","{\"id\":\"" ID "\",\"id\":\"" ID "\",\"images\":[]}",
        "{\"links\":[" GOOD "]}","{\"id\":\"" ID "\",\"images\":[{\"type\":10,\"type\":10,\"url\":\"" URL "\"}]}",
        "{\"id\":\"" ID "\",\"images\":[{\"type\":1e1,\"url\":\"" URL "\"}]}",
        "{\"id\":false}","{\"images\":[null]}","{\"a\":01}","{\"a\":1.}","{\"a\":-}","{\"a\":1e+}","{\"a\":tru}","{\"a\":\"\\u12G3\"}","{\"a\":\"\\q\"}","{\"a\":[1,]}","{\"a\":1,}","{\"a\":{]}","{\"id\":\"UP0001-CUSA00001_00-ABCDEFGHIJKLMNOP\",\"images\":[{\"type\":10,\"url\":\"" URL "\"}]}"};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i)for(size_t chunk=1;chunk<=7;++chunk)assert(run(bad[i],strlen(bad[i]),chunk,out)<0);
    /* A multi-megabyte ignored string is processed with fixed parser memory. */
    StoreJsonStream s;assert(store_json_init(&s,ID)==0);const char *prefix="{\"unused\":\"";assert(store_json_feed(&s,prefix,strlen(prefix))==0);
    char block[4096];memset(block,'x',sizeof(block));for(unsigned i=0;i<1024;++i)assert(store_json_feed(&s,block,sizeof(block))==0);
    const char *tail="\",\"id\":\"" ID "\",\"images\":[{\"url\":\"" URL "\",\"type\":10}]}";
    assert(store_json_feed(&s,tail,strlen(tail))==0&&store_json_finish(&s,out)==0&&!strcmp(out,URL));
    char nested[100];memset(nested,'[',sizeof(nested));assert(store_json_init(&s,ID)==0);assert(store_json_feed(&s,"{\"x\":",5)==0);assert(store_json_feed(&s,nested,sizeof(nested))<0);
    /* Chunk boundaries must not change malformed-token acceptance. */
    char changed[sizeof(GOOD)];char old[STORE_COVER_URL_SIZE];
    for(size_t i=0;i<strlen(GOOD);++i)for(unsigned c=0;c<256;++c){memcpy(changed,GOOD,sizeof(GOOD));changed[i]=(char)c;int a=store_cover_parse(changed,strlen(GOOD),ID,old);int b=run(changed,strlen(GOOD),1,out);assert((a==0)==(b==0));if(!a)assert(!strcmp(old,out));}
    if(argc==3){FILE *f=fopen(argv[1],"rb");assert(f);assert(store_json_init(&s,argv[2])==0);size_t n;while((n=fread(block,1,sizeof(block),f)))assert(store_json_feed(&s,block,n)==0);assert(!ferror(f));fclose(f);assert(store_json_finish(&s,out)==0);puts(out);}
    printf("Streaming JSON contracts passed; parser bytes=%zu\n",sizeof(StoreJsonStream));return 0;
}
