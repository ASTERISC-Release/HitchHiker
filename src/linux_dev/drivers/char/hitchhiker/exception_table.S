/* https://stackoverflow.com/questions/29393677/armv8-exception-vector-significance-of-el0-sp */
/* https://developer.arm.com/documentation/100933/0100/AArch64-exception-vector-table */
.text
.global hhkrd_exception_vector_table
.globl hhkrd_exception_vector_table_end
.balign 2048    /* 2kb total */

/* each entry has 0x80 bytes (can put 32 * 0x4 instrs) */
hhkrd_exception_vector_table:

/* Group 1 */
/* CurrentEL with SP_EL0 (useless) */
    b .
.balign 0x80
    b . 
.balign 0x80
    b .
.balign 0x80
    b .

/* Group 2 */
/* CurrentEL with SP_ELx */
.balign 0x80
    b .
.balign 0x80
    b . 
.balign 0x80
    b .
.balign 0x80
    b .

/* Group 3 (only entries) <important> */
/* Lower EL using AArch64 */
.balign 0x80
    b tl_exit_sync
.balign 0x80
    b tl_exit_irq
.balign 0x80
    b tl_exit_fiq
.balign 0x80
    b tl_exit_error

/* Group 3 (useless) */
/* Lower EL using AArch32 */
.balign 0x80
    b .
.balign 0x80
    b .
.balign 0x80
    b .
.balign 0x80
    b .

.align 6    /* 2^6 = 64 bytes */

/*
 * General Procedure for hhkrd process's exception handler:
 * Copy the current group (group 3)'s each table entry offset to `x14`, 
 * and then invoke smc (x0=0x80000F00 HHKRD_EXCEPTION) to request EL3
 * monitor.
 * 
 * The EL3 monitor handler (hhkrd_os_exception_request) will preprocess
 * the exception first:
 *  e.g., for syscall svc exception, monitor will copy hhkrd's syscall
 * buffers to the shared region for normal OS to access.
 *  e.g., for data abort, monitor will set some flag. When OS complete 
 * the page fault, the monitor will know to set hhkrd's page accordingly.
 * Then EL3 monitor will forward to OS's default exception handler.
 * 
), 
 */
tl_exit_sync:  /* svc here */
    mov x14, xzr /* offset 0 */
    mov x13, x0  /* save x0 to x13 */
    mov x0, #0x80000000
    add x0, x0, #0xF00
    smc #0

tl_exit_irq: 
    mov x14, 0x80  /* offset 0x80 */
    mov x13, x0
    mov x0, #0x80000000
    add x0, x0, #0xF00
    smc #0

tl_exit_fiq:
    mov x14, 0x100 /* offset 0x100 */
    mov x13, x0
    mov x0, #0x80000000
    add x0, x0, #0xF00
    smc #0

tl_exit_error:
    mov		x14, 0x180  /* offset 0x180 */
	mov		x13, x0
	mov     x0, #0x80000000                      
    add     x0, x0,#0xF00
    smc     #0

hhkrd_exception_vector_table_end: