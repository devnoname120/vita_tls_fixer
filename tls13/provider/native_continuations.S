.syntax unified
.thumb
.text
.align 2

/* Keep the original stack/register setup and BLX into the ARM import stub.
 * Sony's unchanged function tail restores these registers and returns. */
.global tls_fixer_native_map_io
.type tls_fixer_native_map_io, %function
.thumb_func
tls_fixer_native_map_io:
    push {r4-r6, lr}
    movs r4, r0
    ldr r0, [r4, #0x40]
    movs r5, r1
    movw r12, #:lower16:g_tls_fixer_native_continuations
    movt r12, #:upper16:g_tls_fixer_native_continuations
    ldr r12, [r12]
    blx r12
    movw r12, #:lower16:g_tls_fixer_native_continuations
    movt r12, #:upper16:g_tls_fixer_native_continuations
    ldr r12, [r12, #4]
    bx r12
.size tls_fixer_native_map_io, .-tls_fixer_native_map_io

.align 2
.global tls_fixer_native_shutdown
.type tls_fixer_native_shutdown, %function
.thumb_func
tls_fixer_native_shutdown:
    push {r4, lr}
    movs r4, r0
    movw r12, #:lower16:g_tls_fixer_native_continuations
    movt r12, #:upper16:g_tls_fixer_native_continuations
    ldr r12, [r12, #8]
    blx r12
    movw r12, #:lower16:g_tls_fixer_native_continuations
    movt r12, #:upper16:g_tls_fixer_native_continuations
    ldr r12, [r12, #12]
    bx r12
.size tls_fixer_native_shutdown, .-tls_fixer_native_shutdown

.section .note.GNU-stack,"",%progbits
