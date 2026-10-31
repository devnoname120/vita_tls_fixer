"""Exercise the production badge detector with absent, legacy and embedded providers."""
from pathlib import Path
import subprocess
import sys
import tempfile

source = (Path(__file__).resolve().parents[1] / 'main.c').read_text()
function = source[source.index('static int detect_tls_fixer('):source.index('static void save_report(')]
prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef int SceUID;
typedef unsigned int SceSize;
typedef struct {unsigned size; char module_name[28]; unsigned state;} SceKernelModuleInfo;
typedef struct {unsigned size;unsigned short version,attributes;unsigned libnid;} SceKernelModuleLibraryInfo;
typedef SceKernelModuleLibraryInfo SceKernelLibraryInfo;
static int scenario, calls, query_calls;
static void check_diag(const char *format, ...) {(void)format;}
static int sceKernelGetModuleList(int type,SceUID *ids,SceSize *count) {
    assert(type==0xff);ids[0]=1;ids[1]=2;*count=2;return 0;
}
static int sceKernelGetModuleInfo(int id,SceKernelModuleInfo *info) {
    strcpy(info->module_name,id==1 ? "SceLibHttp" : scenario==1 ? "tls_fixer_http" : "other");
    info->state=scenario==5 ? 5 : 6;return 0;
}
static int sceKernelGetLibraryInfoByNID(int id,unsigned nid,SceKernelLibraryInfo *info) {
    assert(id==1&&nid==0x7f10b001);++query_calls;
    if(scenario<2||scenario==5)return -1;
    info->libnid=nid;return 0;
}
int tls_fixer_embedded_active(void) {++calls;return scenario==2 ? 1 : scenario==3 ? 0 : -1;}
static int check_provider_module_active(const char *name,unsigned state) {
    return strcmp(name,"tls_fixer_http")==0&&state==6;
}
'''
suffix = r'''
int main(void) {
    for(scenario=0;scenario<6;++scenario) {
        calls=query_calls=0;
        assert(detect_tls_fixer()==(scenario==1||scenario==2));
        assert(calls==(scenario>=2&&scenario<=4));
        assert(query_calls==(scenario!=5));
    }
    return 0;
}
'''
with tempfile.TemporaryDirectory() as directory:
    src = Path(directory) / 'detect.c'
    exe = Path(directory) / 'detect'
    src.write_text(prefix + function + suffix)
    subprocess.run([sys.argv[1], '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
