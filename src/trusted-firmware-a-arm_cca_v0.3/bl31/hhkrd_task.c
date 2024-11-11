#include <bl31/hhkrd_task.h>
#include <bl31/hhkrd_mgmt.h>
#include <bl31/hhkrd_comm_lib.h>

#include <lib/gpt/gpt.h>

#if !ENABLE_HHKRD
#error "ENABLE_HHKRD must be enabled to use the hhkrd task library."
#endif

#define TD_TASK_MAX     32   /* thread pool, we support maximum 32 task threads */
hhkrd_task_t hhkrd_task[TD_TASK_MAX];

spinlock_t task_lock;

// from gpt_core.c
/* Helper function that cleans the data cache only if it is enabled. */
static inline
	void gpt_clean_dcache_range(uintptr_t addr, size_t size)
{
#if !(HW_ASSISTED_COHERENCY || WARMBOOT_ENABLE_DCACHE_EARLY)
	if ((read_sctlr_el3() & SCTLR_C_BIT) != 0U) {
		clean_dcache_range(addr, size);
	}
#endif
}


/*
 * Search the hhkrd_task thread pool to search for the given OS task
 * 
 * @param task_struct_addr (optional): The Normal OS task addr
 * @param tid: The Normal OS tid
 */
hhkrd_task_t *hhkrd_task_search(void* task_struct_addr, uint64_t tid) {
    hhkrd_task_t *td_task = NULL;

    for (int i = 0; i < TD_TASK_MAX; i++) {
        td_task = &hhkrd_task[i];

        if (!td_task->inited)
            continue;

        if (td_task->tid == tid) {
            if (!task_struct_addr)
                return td_task;
            
            else if (task_struct_addr == (void *)td_task->task_struct_addr)
                return td_task;
        }
    }
    return NULL;
}

/*
 * Search an uninitialized empty hhkrd task from the hhkrd_task[] pool
 */
hhkrd_task_t *hhkrd_empty_task_search(void) {
    for (int i = 0; i < TD_TASK_MAX; i++) {
        if (!hhkrd_task[i].inited)
            return &hhkrd_task[i];
    }
    return NULL;
}


/** ===================================================================================
 * Lifetime Management
 * ====================================================================================
 */

/*
 * Create hhkrd prog
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
                       u_register_t x7) 
{
    spin_lock(&task_lock);
    NOTICE("<hhkrd_prog_create> start create hhkrd task...\n");
    /* Save the non-secure context before entering the Monitor */
	cm_el1_sysregs_context_save(NON_SECURE);
    cpu_context_t *src_ctx = cm_get_context(NON_SECURE);
    /* get hhkrd el1 vector phys addr */
    uint64_t vector_pa = hhkrd_virt_to_phys(x5);
    // TODO() overlap check?
    // TODO() sign verify?

    /* assign hhkrd_id and build gpt */
    size_t td_id = hhkrd_assign_id_gpt();
    NOTICE("<hhkrd_prog_create> assigned id: %lu and created GPT.\n", td_id);
    /* configure hhkrd_mem for management */
    /* memory for .text, .data, stack, init variable */
    hhkrd_mem_t *td_mem = &hhkrd_mem[td_id];
    td_mem->td_phys_pa1 = x1; 
    td_mem->td_phys_size1 = x6;
    /* fd for cma allocator */
    td_mem->cmafd = x4;
    /* memory for vector table */
    td_mem->hhkrd_vector_virt_addr = x5;
    /* memory for vector table and page table (fixed 16MB) */
    td_mem->td_phys_pa2 = vector_pa;
    td_mem->td_phys_size2 = HHKRD_VECTOR_PAGE_TABLE_SPACE;
    /* memory address for normal OS system vector */
    td_mem->os_vector_virt_addr = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_VBAR_EL1);

    /* search and initalize an empty hhkrd task */
    hhkrd_task_t *td_task = hhkrd_empty_task_search();
    if (!td_task) {
        ERROR("<hhkrd_prog_create> task_id search error.\n");
    }
    td_task->td_id = td_id;
    td_task->td_sp = x2;
    td_task->task_elr_el1 = x3;
    /* 
     * CnP set to 0: do not share td_task's TLB
     * https://developer.arm.com/documentation/ddi0595/2021-06/AArch64-Registers/TTBR0-EL1--Translation-Table-Base-Register-0--EL1- 
     */
    td_task->os_TTBR0_EL1 = ttbr_val_disable_CnP(read_ttbr0_el1());
    td_task->task_struct_addr = x7;
    td_task->tid = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_CONTEXTIDR_EL1);
    /* activate hhkrd task (td_task), and hhkrd memory management (td_mem) */
    td_task->inited = true;
    td_mem->alive = true;
    /* protect hhkrd memory */
    hhkrd_gpt_memory_protection(td_id, td_mem->td_phys_pa1, td_mem->td_phys_size1);
    hhkrd_gpt_memory_protection(td_id, td_mem->td_phys_pa2, td_mem->td_phys_size2);    
    /* copy normal OS's page table to hhkrd's private memory */
    td_task->sapp_TTBR0_EL1 = allocate_hhkrd_pagetable(td_id, td_task->os_TTBR0_EL1);
    /* 
     * normal OS context restore:
     * 1. enable the normal world's GPT for memory isolation
     * 2. restore normal world's cpu context, system regs
     */
    gpt_enable_td(0);
    cm_el1_sysregs_context_restore(NON_SECURE);
    NOTICE("<hhkrd_create prog> done for tid: %llu. td_id: %llu.\n", td_task->tid, td_task->td_id);
    spin_unlock(&task_lock);
    return td_id;
}

/*
 * enter and execute the hhkrd program
 * (invoked by kernel_exit)
 * 1) normal world starts a hhkrd: NS EL0 - kernel sched in (prepare task) - kernel_exit - SMC() here - hhkrd EL0
 */
u_register_t hhkrd_sched_in(void) {
    spin_lock(&task_lock);
    /* Save the non-secure context before entering the Monitor */
    cm_el1_sysregs_context_save(NON_SECURE);
    cpu_context_t *src_ctx = cm_get_context(NON_SECURE);

    /* 
     * Get the trust_struct and tid to sched_in. In entry.S (kernel_exit el0), we 
     * have put x14 <- tsk. So that x14 is the current thread id.
     */

    u_register_t task_struct = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X14);
    uint64_t tid = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_CONTEXTIDR_EL1);
    
    /* search hhkrd task via the OS task and tid */
    hhkrd_task_t *td_task = hhkrd_task_search((void *)task_struct, tid);
    if (!td_task) {
        NOTICE("<hhkrd_sched_in> Failed to find td_task. (os task: 0x%lx, os tid: %llu)\n", task_struct, tid);
        panic();
    }

    size_t td_id = td_task->td_id;
    /* enable hhkrd's GPT for protection */
    gpt_enable_td(td_id);

    /* save the OS's ttbr0_el1 for new process */
    u_register_t ttbr0_el1 = read_ttbr0_el1();
    if (!td_task->os_TTBR0_EL1) {
        td_task->os_TTBR0_EL1 = ttbr0_el1 & (~0x1);
        NOTICE("<hhkrd_sched_in> tid: %llux. hhkrd task's ttbr0 is 0x%llx.\n", \
                td_task->tid, td_task->os_TTBR0_EL1);
    } else if ((ttbr0_el1 & (~0x1)) != td_task->os_TTBR0_EL1) {
        NOTICE("<hhkrd_sched_in> tid: %llux. hhkrd task's ttbr0 is changed to 0x%lx.\n", \
                td_task->tid, ttbr0_el1);
        td_task->os_TTBR0_EL1 = ttbr0_el1;
    }

    /*
     * Restore the original x0 register. We save the x0 to x13 in entry.S kernel_exit el0.
     */
    u_register_t x0 = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X13);
    write_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0, x0);

    /* 
     * Check the exception handle status. Is this sched_in caused by finishing an exception?
     * If true, update the OS's exception handle results accordingly.
     */ 
    
    /*
     * Check if the hhkrd task is waiting for the return from a syscall handler.
     * If true, we check the syscall return value to defense the Iago attack,
     * and we copy the syscall values from the shared content to the hhkrd's userspace.
     */
    if (td_task->is_wait_syscall_ret) {
        hhkrd_syscall_return_handle(td_task, src_ctx);
        td_task->is_wait_syscall_ret = false;
        td_task->wait_syscallno = 0;
    } 
    /* 
     * Data abort. Since the OS has handled the page fault, we just set the fault page to OS's 
     * page table.
     */
    else if (td_task->is_wait_data_abort_ret) {
        if(td_task->wait_data_abort_exception == 0x9200004f) {
            hhkrd_set_page(tid, td_task->far_addr, S_PAGE_SIZE);
            gpt_enable_td(td_id);
        }
        td_task->is_wait_data_abort_ret = false;
        td_task->wait_data_abort_exception = 0;
    }

    u_register_t pc = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_ELR_EL1);
    if (pc != td_task->task_elr_el1 && td_task->task_elr_el1 != 0) {
        NOTICE("tid: %llu, The hhkrd's return address is inconsistent. pc = 0x%lx, task_elr_el1=0x%llx\n", \
               td_task->tid, pc, td_task->task_elr_el1);
        if (pc == (td_task->task_elr_el1 + 0x4)) {
            td_task->task_elr_el1 = pc;
            goto out;
        }
        /* verify that the address has been registered to ensure that
         * the task will be correctly returning to a registered handler 
         */
        if (!search_registered_signal_handle(td_task, pc)) {
            NOTICE("tid:%llu, hhkrd's return address is not a registered signal handler address.\n", td_task->tid);
        }
        /* 
         * make the signal stack memory inaccessable to the normal OS before the signal handler is executed.
         * Only hhkrd itself could access and execute the task signal stack.
         */
        gpt_transition_pas_td_contiguous(td_task->task_signal_stack_phys, td_task->task_signal_stack_length, GPI_ROOT, 0);
        
        /* reserve the signal return pc */
        td_task->ret_pc_from_signal = td_task->task_elr_el1;
        /* setup the signal pc */
        td_task->task_elr_el1 = pc;
    }

out:;
    /* use hhkrd's own page table and diable cnp bit to defense gpt tlb attack */
    write_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_TTBR0_EL1, td_task->sapp_TTBR0_EL1 & (~0x1));
    /* save the normal OS's stack pointer */
    td_task->task_sp_el1 = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_SP_EL1);
    /* 
     * Change the VBAR_EL1 register to set up the hhkrd process's exception vector table. 
     * This vector table is created in a cma `exception_table_region` by the EL1 hhkrd_driver,
     * and recorded by the td_mem at hhkrd_sched_in().
     */
    write_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_VBAR_EL1, hhkrd_mem[td_id].hhkrd_vector_virt_addr);
    /* ret val */
    x0 = read_ctx_reg(get_gpregs_ctx(src_ctx), CTX_GPREG_X0);

    /* set exception return address (pc) and pstate (spsr) for eret */
    u_register_t spsr_el3 = SPSR_64(MODE_EL0, MODE_SP_EL0, 0);
    cm_set_elr_spsr_el3(NON_SECURE, pc, spsr_el3);
    
    cm_el1_sysregs_context_restore(NON_SECURE);
    cm_set_next_eret_context(NON_SECURE);

    spin_unlock(&task_lock);
    return x0;
}

/*
 * exit a hhkrd thread
 * (by OS do_exit)
 * @param x1: OS task_struct address
 * @param x2: OS tid
 */
u_register_t hhkrd_exit_thread(u_register_t x1, u_register_t x2) {
    spin_lock(&task_lock);
    u_register_t task_struct = x1;
    uint64_t tid = x2;

    hhkrd_task_t *td_task = hhkrd_task_search((void *)task_struct, tid);
    if (!td_task) {
        NOTICE("<hhkrd_exit_thread> Failed to find OS tid: %llu to sched out.\n", tid);
		panic();
    }

    NOTICE("<hhkrd_exit_thread> Exit hhkrd td_id: %llu, OS tid: %llu.\n", td_task->td_id, td_task->tid);
    if (td_task->inited) {
        memset((void *)td_task, 0, sizeof(hhkrd_task_t));
    }
    spin_unlock(&task_lock);
    return 0;
}

/*
 * destruct the hhkrd program (all threads are exited)
 * (by OS do_exit_group)
 * @param x1: OS task_struct address
 * @param x2: OS tid
 */
int hhkrd_destruct(u_register_t x1, u_register_t x2) {
    spin_lock(&task_lock);
    u_register_t task_struct = x1;
    uint64_t tid = x2;

    hhkrd_task_t *td_task = hhkrd_task_search((void *)task_struct, tid);
    if (!td_task) {
        NOTICE("<hhkrd_destruct> Failed to find OS tid: %llu to desctruct.\n", tid);
		panic();
    }
    NOTICE("<hhkrd_destruct> Destruct hhkrd td_id: %llu, OS tid: %llu.\n", td_task->td_id, td_task->tid);
    size_t td_id = td_task->td_id;
    hhkrd_mem_t *td_mem = &hhkrd_mem[td_id];
    
    /* return from the unalive task */
    if (!td_mem->alive)
        goto out;

    /* clean and destruct an alive hhkrd task */
    gpt_enable_td(td_id);
    /*  
     * Clean hhkrd memory regions:
     * 1) clear memory via memset(,.., 0)
     * 2) clean memory cache
     * 3) enable NS access todo(): all access
     */
    if (td_mem->td_phys_pa1 != 0) {
        memset((void *)td_mem->td_phys_pa1, td_mem->td_phys_size1, 0);
        gpt_clean_dcache_range(td_mem->td_phys_pa1, td_mem->td_phys_size1);
        gpt_transition_pas_td_contiguous(td_mem->td_phys_pa1, td_mem->td_phys_size1, GPI_NS, 0);
    }
    if (td_mem->td_phys_pa2 != 0) {
        memset((void *)td_mem->td_phys_pa2, td_mem->td_phys_size2, 0);
        gpt_clean_dcache_range(td_mem->td_phys_pa2, td_mem->td_phys_size2);
        gpt_transition_pas_td_contiguous(td_mem->td_phys_pa2, td_mem->td_phys_size2, GPI_NS, 0);
    }
    if (td_mem->td_phys_pa3 != 0) {
        memset((void *)td_mem->td_phys_pa3, td_mem->td_phys_size3, 0);
        gpt_clean_dcache_range(td_mem->td_phys_pa3, td_mem->td_phys_size3);
        gpt_transition_pas_td_contiguous(td_mem->td_phys_pa3, td_mem->td_phys_size3, GPI_NS, 0);
    }
    if (td_mem->td_phys_pa4 != 0) {
        memset((void *)td_mem->td_phys_pa4, td_mem->td_phys_size4, 0);
        gpt_clean_dcache_range(td_mem->td_phys_pa4, td_mem->td_phys_size4);
        gpt_transition_pas_td_contiguous(td_mem->td_phys_pa4, td_mem->td_phys_size4, GPI_NS, 0);
    }
    memset((void *)td_mem, 0, sizeof(hhkrd_mem_t));

    /* free this td_id */
    free_td_id(td_id);
    gpt_enable_td(0);
out:;
    spin_unlock(&task_lock);
    return 0;
}

/*
 * hhkrd clone
 * @param x1: OS task_struct
 * @param x2: parent's OS tid
 * @param x3: child's OS tid
 * @param x4: is_fork?
 */
int hhkrd_clone(u_register_t x1, u_register_t x2, u_register_t x3, u_register_t x4) {
	u_register_t task_struct = x1;
	uint64_t parent_tid = x2;
	uint64_t child_tid = x3;
	int is_fork_flag = x4;
	NOTICE("<hhkrd_clone> -- task_struct_addr:0x%lx, ppid:%llu, tid:%llu\n", task_struct, parent_tid, child_tid);

	if(parent_tid == child_tid) {
		NOTICE("The calling task has invalid tid\n");
		panic();
	}

    hhkrd_task_t *parent_td_task = hhkrd_task_search(NULL, parent_tid);
	if (!parent_td_task) {	
		NOTICE("Fail to find task_struct in shelter_tasks, the calling task is fault\n");
		panic();
	}

    hhkrd_task_t *child_td_task = hhkrd_empty_task_search();
    child_td_task->task_struct_addr = task_struct;
	child_td_task->tid = child_tid;
	child_td_task->inited = true;

	/* sync the thread's shared task vals */
	if(!is_fork_flag) {
        /*
         * For creating a new thread, the parent and the child thread share:
         *  td_id: belong to the same hhkrd program (so that the hhkrd_mem[] memories are the same);
         *  os_ttbr0_el1: the same OS page table
         *  sapp_ttbr0_el1: the same hhkrd page table
         */
        child_td_task->td_id = parent_td_task->td_id;
		child_td_task->os_TTBR0_EL1 = parent_td_task->os_TTBR0_EL1;
		child_td_task->sapp_TTBR0_EL1 = parent_td_task->sapp_TTBR0_EL1;
	} else {
        NOTICE("FIXME: Implementation error.\n");
        panic();
    }
	return 0;
}

/** ===================================================================================
 * OS Service (exception) Forward Check & Request
 * ====================================================================================
 */
uint64_t search_registered_signal_handle(hhkrd_task_t *td_task, u_register_t pc) {
    for (int i = 0; i < SIGNAL_MAX; i++) {
        if (td_task->registered_signal_handler_addrs[i] == pc)
            return pc;
    }
    return 0;
}

void register_signal_handles(hhkrd_task_t *td_task) {
    /* just record the handler in td_task's array */
    u_register_t task_struct = td_task->task_struct_addr;
    uint64_t tid = td_task->tid;
    uint64_t sig_handler_addr = td_task->to_be_registered_signal_handler_addr;
    // int signo = td_task->to_be_registered_signal_no;

    hhkrd_task_t *td_tar_task = hhkrd_task_search((void *)task_struct, tid);
    assert(td_task == td_tar_task);

    for (int i = 0; i < SIGNAL_MAX; i++) {
        if(td_task->registered_signal_handler_addrs[i])
            continue;
        td_task->registered_signal_handler_addrs[i] = sig_handler_addr;
        break;
    }
}

/*
 * Invoked from the hhkrd's `execption_table.S`.
 * Pre-process the hhkrd's exception before forwarding the service to the normal OS.
 * For svc() syscall request, we call the `hhkrd_syscall_params_handle` to deal with
 * the syscall parameters, and then forward the service back to the normal OS.
 * 
 * 
 */
uint64_t hhkrd_os_exception_request(void)
{
    spin_lock(&task_lock);
    /* Save the non-secure context before entering the Monitor */
    cm_el1_sysregs_context_save(NON_SECURE);
    cpu_context_t *src_ctx = cm_get_context(NON_SECURE);
    /* Fetch td_task */
    uint64_t tid = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_CONTEXTIDR_EL1);
    hhkrd_task_t *td_task = hhkrd_task_search(NULL, tid);
    if (!td_task) {
        NOTICE("<hhkrd_os_exception_request> failed to find td_task for tid: %llu.\n", tid);
        panic();
    }

    size_t td_id = td_task->td_id;
    /* get the exception info */
    u_register_t esr_el1 = read_el1_sysreg(src_ctx, CTX_ESR_EL1);
    /* 
     * the current group (group3)'s table entry offset has been passed to x14 in the hhkrd's
     * exception vector table. Also, original x0 is saved in x13. 
     * (see hhkrd_driver's exception_table.S)
     */
    u_register_t vec_handler_offset = read_gpreg(src_ctx, CTX_GPREG_X14);
    u_register_t x0 = read_gpreg(src_ctx, CTX_GPREG_X13);
    /* restore x0 */
    write_gpreg(src_ctx, CTX_GPREG_X0, x0);
    
    /* svc: syscall exception; use syscall param handle */
    if (esr_el1 == 0x56000000 && vec_handler_offset == 0) {
        uint32_t syscallno = read_gpreg(src_ctx, CTX_GPREG_X8);
        td_task->wait_syscallno = syscallno;
        td_task->is_wait_syscall_ret = true;
        NOTICE("<hhkrd_os_exception_request> td_id: %llu, tid:%llu, syscallno: 0x%x\n", td_task->td_id, td_task->tid, syscallno);
        /* handle syscall params */
        hhkrd_syscall_params_handle(td_task, syscallno);
    }
    /* other exceptions */
    else {
        u_register_t far_el1 = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_FAR_EL1);
        u_register_t elr_el1 = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_ELR_EL1);
        NOTICE("[debug exception request] tid:%llu, vec_offset: 0x%lx, esr_el1 0x%lx, far_el1: 0x%lx, elr_el1: 0x%lx\n",
               td_task->tid, vec_handler_offset, esr_el1, far_el1, elr_el1);
        
        if (vec_handler_offset == 0) {
            /* data abort (mmu fault) */
            if (esr_el1 & 0x92000000) {
                // u_register_t far_el1 = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_FAR_EL1);
                // u_register_t elr_el1 = read_ctx_reg(get_el1_sysregs_ctx(src_ctx), CTX_ELR_EL1);
                /* setup td_task exception status */
                // NOTICE("<hhkrd_os_exception_request> tid:%llu, esr_el1 0x%lx, far_el1: 0x%lx, elr_el1: 0x%lx\n", td_task->tid, esr_el1, far_el1, elr_el1);
                td_task->wait_data_abort_exception = esr_el1;
                td_task->is_wait_data_abort_ret = true;
                td_task->far_addr = far_el1;
            }
        }
        /* switch to normal OS's gpt to handle exception */ 
        gpt_enable_td(0);
    }

    /* set the eret to be the normal OS's linux vector entry and let OS chane the os_ttbr0_el1 user page table */
    write_el1_sysreg(src_ctx, CTX_TTBR0_EL1, ttbr_val_disable_CnP(td_task->os_TTBR0_EL1));
    /* restore the OS's default exception vector table */
    write_el1_sysreg(src_ctx, CTX_VBAR_EL1, hhkrd_mem[td_id].os_vector_virt_addr);
    /* restore the normal OS's stack pointer */
    write_el1_sysreg(src_ctx, CTX_SP_EL1, td_task->task_sp_el1);
    x0 = read_gpreg(src_ctx, CTX_GPREG_X0);
    
    /* 
     * save hhkrd's exception return address in CTX_ELR_EL1. This will be checked in the later 
     * sched_in(), after OS finishing the exception handling.
     */
    td_task->task_elr_el1 = read_el1_sysreg(src_ctx, CTX_ELR_EL1);

    /* set the pc to be normal OS's default exception vector table entry point */
    u_register_t pc = hhkrd_mem[td_id].os_vector_virt_addr + VECTOR_EL0_OFFSET + vec_handler_offset;
    u_register_t spsr_el3 = SPSR_64(MODE_EL1, MODE_SP_ELX, DISABLE_INTERRUPTS);
    
    /* set exception return address (pc) and pstate (spsr) for eret */
    cm_set_elr_spsr_el3(NON_SECURE, pc, spsr_el3);
    cm_el1_sysregs_context_restore(NON_SECURE);
    cm_set_next_eret_context(NON_SECURE);

    spin_unlock(&task_lock);
    return x0;
}