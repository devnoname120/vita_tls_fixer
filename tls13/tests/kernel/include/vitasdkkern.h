#include <kernel_mock.h>
extern int syscall_depth;
#define ENTER_SYSCALL(state) do { (state) = syscall_depth++; } while (0)
#define EXIT_SYSCALL(state) do { syscall_depth = (state); } while (0)
int ksceIoPread(SceUID, void *, SceSize, SceOff);
int ksceKernelCopyToUser(void *, const void *, SceSize);
