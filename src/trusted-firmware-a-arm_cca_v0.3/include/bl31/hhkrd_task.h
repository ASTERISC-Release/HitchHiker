#ifndef HHKRD_TASK_H
#define HHKRD_TASK_H

#include <stdint.h>
#include <arch.h>
#include <arch_helpers.h>
#include <lib/spinlock.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <bl31/hhkrd_comm_lib.h>

#define VECTOR_EL0_OFFSET 0x400
#define SHARE_BUF_OFFSET 0x1000	/* 4KB */
#define FUTEX_PAGE 0x1000

/* GPRs */
typedef struct {
	uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, \
             x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, \
             x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30;
} general_regs;

/* hhkrd task struct */
typedef struct {
	uint64_t td_id;        /* id for gpt */
	uint64_t td_sp;        /* task stack */
	uint64_t task_elr_el1; // used by control flow integrity
	uint64_t ret_pc_from_signal; 
	uint64_t os_TTBR0_EL1;   /* normalOS page table */
	uint64_t sapp_TTBR0_EL1; /* hhkrd task page table */
	uint64_t task_struct_addr;
	uint64_t tid; //CTX_CONTEXTIDR_EL1, require kernel config enable to save pid in contextidr_el1
	bool inited;
	uint64_t task_sp_el1;
	
	//exception manage
	uint32_t wait_syscallno;
	bool is_wait_syscall_ret;
	uint64_t syscall_hhkrd_user_addr;
	uint64_t second_syscall_hhkrd_user_addr;
	uint64_t third_syscall_hhkrd_user_addr;
	uint32_t iotcl_cmd;
	uint64_t wait_data_abort_exception;
	bool is_wait_data_abort_ret;
	uint64_t far_addr;
	
	/* shared memory buffer for syscall support 
	 * mapped by hhkrd_assign_share()
	 */
	uint64_t task_shared_virt;
	uint64_t task_shared_phys; 
	uint32_t task_shared_length;
	uint32_t user_buf_size;
	uint32_t second_user_buf_size;
	bool is_use_task_shared_virt;

	//futex
	uint64_t task_futex_virt;
	uint64_t task_futex_phys;
	bool is_use_task_futex_virt; 
	
	/* 
     * Signal frame stack used by setup_frame to set up a separate user mode
	 * stack specifically for signal handling. The registed handler addr is
	 * recorded during syscall handle such as rt_sigaction. When handling a
	 * signal, we first verify that the address has been registered and that the
	 * pretcode on the signal stack is correct. Then we make the memory
	 * inaccessible to the OS, and maintain the signal context and normal
	 * context. 
     */
	uint64_t task_signal_stack_virt;
	uint64_t task_signal_stack_phys;
	uint32_t task_signal_stack_length; 
	bool is_use_task_signal_stack_virt;
	uint64_t signal_context;
	int to_be_registered_signal_no;
	uint64_t to_be_registered_signal_handler_addr;
	uint64_t registered_signal_handler_addrs[SIGNAL_MAX]; 
} hhkrd_task_t;

extern spinlock_t task_lock;

/* APIs */
hhkrd_task_t *hhkrd_task_search(void* task_struct_addr, uint64_t tid);
hhkrd_task_t *hhkrd_empty_task_search(void);
/*
 * Create hhkrd task
 * @param x1: hhkrd physical memory address
 * @param x2: hhkrd el0 stack sp
 * @param x3: hhkrd el0 entry
 * @param x4: cmafd
 * @param x5: hhkrd el1 vector virtual address
 * @param x6: hhkrd prog mem size
 * @param x7: normal OS task_struct address
 */
int hhkrd_prog_create(u_register_t x1, u_register_t x2, u_register_t x3, 
                       u_register_t x4, u_register_t x5, u_register_t x6, 
                       u_register_t x7);

void register_signal_handles(hhkrd_task_t *td_task);
uint64_t search_registered_signal_handle(hhkrd_task_t *td_task, u_register_t pc);
uint64_t hhkrd_os_exception_request(void);

u_register_t hhkrd_sched_in(void);
u_register_t hhkrd_exit_thread(u_register_t x1, u_register_t x2);
int hhkrd_clone(u_register_t x1, u_register_t x2, u_register_t x3, u_register_t x4);
int hhkrd_destruct(u_register_t x1, u_register_t x2);
#endif