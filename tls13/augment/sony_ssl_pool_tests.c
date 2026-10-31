#define _GNU_SOURCE
#include "sony_ssl_pool.h"
#include <psp2/kernel/modulemgr.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static unsigned char *text,*data;
static int info_error,wrong_name;
SceUID sceKernelGetModuleIdByAddr(void *p){return p==text+0x48140?42:-31;}
int sceKernelGetModuleInfo(SceUID id,SceKernelModuleInfo *info) {
    assert(id==42);if(info_error)return -32;
    strcpy(info->module_name,wrong_name?"OtherModule":"SceLibSsl");
    info->segments[0].vaddr=text;info->segments[0].memsz=421540;
    info->segments[1].vaddr=data;info->segments[1].memsz=20392;return 0;
}
static void mov(unsigned char *p,unsigned reg,unsigned value,int top) {
    uint16_t a=(uint16_t)((top?0xf2c0u:0xf240u)|((value>>12)&15u)|((value>>1)&0x400u));
    uint16_t b=(uint16_t)((reg<<8)|((value<<4)&0x7000u)|(value&255u));
    p[0]=(unsigned char)a;p[1]=(unsigned char)(a>>8);p[2]=(unsigned char)b;p[3]=(unsigned char)(b>>8);
}
static void pair(size_t w,size_t t,unsigned reg,uintptr_t address){mov(text+w,reg,(unsigned)address&65535u,0);mov(text+t,reg,(unsigned)(address>>16),1);}
int main(int argc,char **argv) {
    assert(argc==2);
    text=mmap((void *)(uintptr_t)0x91000000,0x68000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    data=mmap((void *)(uintptr_t)0xe1000000,0x6000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    assert(text!=MAP_FAILED&&data!=MAP_FAILED);
    FILE *f=fopen(argv[1],"rb");assert(f&&fread(text,1,421540,f)==421540);fclose(f);
    pair(0x48140,0x48144,3,(uintptr_t)data+0x4f78);
    pair(0x4814c,0x48152,3,(uintptr_t)data+0x4fa0);
    pair(0x47e2a,0x47e2e,3,(uintptr_t)data+0x4f7c);
    pair(0x47f7c,0x47f90,7,(uintptr_t)data+0x4114);
    uintptr_t target=(uintptr_t)text+0x48141;
    uint32_t stub[3]={0xe300c000u|((target&0xf000u)<<4)|(target&0xfffu),
        0xe340c000u|(((target>>16)&0xf000u)<<4)|((target>>16)&0xfffu),0xe12fff1c};
    assert(!tls_fixer_sony_ssl_pool_prepare(stub));
    TlsFixerSslPoolView view;
    assert(tls_fixer_sony_ssl_pool_read(NULL,&view)<0);
    *(uint32_t *)(data+0x4f78)=1;*(uint32_t *)(data+0x4f7c)=0x92800000;*(int32_t *)(data+0x4114)=77;
    assert(!tls_fixer_sony_ssl_pool_read(NULL,&view)&&view.heap==(void *)(uintptr_t)0x92800000&&view.block==77);
    text[0x47e28]^=1;assert(tls_fixer_sony_ssl_pool_prepare(stub)<0);text[0x47e28]^=1;
    pair(0x47e2a,0x47e2e,3,(uintptr_t)data+0x4f80);assert(tls_fixer_sony_ssl_pool_prepare(stub)<0);
    pair(0x47e2a,0x47e2e,3,(uintptr_t)data+0x4f7c);
    info_error=1;assert(tls_fixer_sony_ssl_pool_prepare(stub)==-32);info_error=0;
    wrong_name=1;assert(tls_fixer_sony_ssl_pool_prepare(stub)<0);wrong_name=0;
    stub[2]=0xe12fff1e;assert(tls_fixer_sony_ssl_pool_prepare(stub)<0);
    assert(!munmap(text,0x68000)&&!munmap(data,0x6000));
    puts("Sony SSL pool binding: real code, separate relocated RW, malformed imports/profile and before-init PASS");
}
