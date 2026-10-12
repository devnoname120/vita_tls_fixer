#include <psp2common/kernel/modulemgr.h>
#include <assert.h>

int main(void) {
    assert(SCE_KERNEL_START_SUCCESS == 0);
    assert(SCE_KERNEL_START_NO_RESIDENT == 1);
    assert(SCE_KERNEL_START_FAILED == 2);
    assert(SCE_KERNEL_STOP_SUCCESS == 0);
    assert(SCE_KERNEL_STOP_FAIL == 1);
    return 0;
}
