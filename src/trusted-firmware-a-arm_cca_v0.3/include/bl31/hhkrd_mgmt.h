#ifndef HHKRD_MGMT_H
#define HHKRD_MGMT_H

#include <lib/libc/stdint.h>
#include <arch.h>
#include <errno.h>
#include <lib/spinlock.h>
#include <arch_helpers.h>
#include <bl31/hhkrd_pgtable.h>
#include <bl31/hhkrd_task.h>
#include <plat/arm/common/arm_def.h>

/* hhkrd memory management */
typedef struct {
	/* hhkrd memory for .text, .data, stack, init variable */
    uint64_t td_phys_pa1;	
	uint64_t td_phys_size1;
	/* hhkrd vector memory - 4KB */
    uint64_t td_phys_pa2; 
	uint64_t td_phys_size2;
    /* hhkrd memory pool for object allocation and shared buffer, etc. */
	uint64_t td_phys_pa3; 
	uint64_t td_phys_size3;
    /* standby for expanding hhkrd memory pool */
	uint64_t td_phys_pa4; 
	uint64_t td_phys_size4;
	bool alive;
	int cmafd;
	uint64_t hhkrd_vector_virt_addr;
	uint64_t os_vector_virt_addr;
	hhkrd_pg td_pg;
} hhkrd_mem_t;

extern hhkrd_mem_t hhkrd_mem[HHKRD_MAX];

/* management */
#define         HHKRD_TASK_SHARED_LENGTH           0x10000    // 64KB
#define         HHKRD_TASK_SIGNAL_STACK_LENGTH     0x4000     // 16KB
#define         EXCEPTION_VECTOR_LENGTH            0x1000     // 4KB
#define         HHKRD_VECTOR_PAGE_TABLE_SPACE      0x1000000  // 16MB
#define         HHKRD_EXTEND_MEM_DEFAULT_LENGTH    0x4000000  // 64MB

#define         __os_pgd(x)                         (pgd_t *)(x & 0xFFFFFFFFFFFF)

/* APIs */
size_t search_avlbl_td_id(bool occupy);
void occupy_td_id(size_t td_id);
void free_td_id(size_t td_id);

int copy_pte_range(pmd_t *dst_pmd, pmd_t *src_pmd, hhkrd_pg *td_pg, \
                   unsigned long addr, unsigned long addr_end);
int copy_pmd_range(pgd_t *dst_pud, pgd_t *src_pud, hhkrd_pg *td_pg, \
		           unsigned long addr, unsigned long addr_end);
                   
int hhkrd_set_page(u_register_t x1, u_register_t x2, u_register_t x3);
uint64_t allocate_hhkrd_pagetable(uint64_t td_id, uint64_t src_ttbr0);

int hhkrd_memexpand(u_register_t x1, u_register_t x2);
int hhkrd_assign_share_mem(u_register_t x1, u_register_t x2, u_register_t x3);
/* syscall handle */
void hhkrd_syscall_params_handle(hhkrd_task_t *td_task, uint32_t syscallno);
void hhkrd_syscall_return_handle(hhkrd_task_t *td_task, cpu_context_t *src_ctx);


/* compare omni log */
int hhkr_init_omni_buffers(u_register_t k, u_register_t d);
int hhkr_write_omni_buf(u_register_t phys_addr, u_register_t size);
#endif