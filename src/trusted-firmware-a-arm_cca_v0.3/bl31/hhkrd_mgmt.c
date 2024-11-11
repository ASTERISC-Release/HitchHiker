#include <bl31/hhkrd_mgmt.h>
#include <bl31/hhkrd_comm_lib.h>
#include <bl31/hhkrd_handlers.h>

#include <lib/spinlock.h>
#include <lib/gpt/gpt.h>
#include <assert.h>

#if !ENABLE_HHKRD
#error "ENABLE_HHKRD must be enabled to use the hhkrd memory management library."
#endif

/* Keep track of the available hhkrd id td_id */
unsigned int td_avlbl_map[HHKRD_MAX] = {0};

/* from gpt_core */
extern unsigned int l1_gpt_mem_avlbl_index[HHKRD_MAX];

/* memory management array (indexed by hhkrd id td_id) */
hhkrd_mem_t hhkrd_mem[HHKRD_MAX];

spinlock_t pte_lock;

/** =================================================
 * hhkrd_id management
 * ==================================================
 */
void occupy_td_id(size_t td_id) {
    assert(td_id <= HHKRD_MAX);
    td_avlbl_map[td_id - 1] = 1;
}

void free_td_id(size_t td_id) {
    assert(td_id <= HHKRD_MAX);
    /* free td_avlbl_map */
    td_avlbl_map[td_id - 1] = 0;
    /* refresh l1_gpt_mem_avlbl_index */
    l1_gpt_mem_avlbl_index[td_id] = 0;
}

size_t search_avlbl_td_id(bool occupy) {
    for (int i = 0; i < HHKRD_MAX; i++) {
        if (!td_avlbl_map[i]) {
            if (occupy)
                occupy_td_id(i + 1);
            return (i + 1);
        }
    }
    return 0;
}

/** ================================================
 * Memory Management 
 * =================================================
 */
bool allocate_memory_check(uint64_t pa, uint64_t size, uint64_t td_id) {
	uint64_t high_bound = pa + size;
	/* allocate inside hhkr's memory buf pool starting from 0x84400000 with size 256MB */
    if (pa >= 0x84400000 && pa <= 0x84400000 + 0x10000000) {
        return true;
    }
    /* allocate inside the shared buf range */
    if(hhkrd_mem[td_id].td_phys_pa3) {
		if(pa >= hhkrd_mem[td_id].td_phys_pa3 && high_bound <= hhkrd_mem[td_id].td_phys_pa3 + hhkrd_mem[td_id].td_phys_size3)
			return true;
	}
    /* allocate inside the expend mem range */
	if(hhkrd_mem[td_id].td_phys_pa4) {
		if(pa >= hhkrd_mem[td_id].td_phys_pa4 && high_bound <= hhkrd_mem[td_id].td_phys_pa4 + hhkrd_mem[td_id].td_phys_size4)
            return true;
	}
    return false;
}

unsigned long copy_one_pte(pte_t *dst_pte, pte_t *src_pte, hhkrd_pg * td_pg, unsigned long addr) {
	pte_t pte = *src_pte;
	uint64_t pa = pte.pte & 0xFFFFFFFFF000;
	if(td_pg->use_mem_pool && !allocate_memory_check(pa, S_PAGE_SIZE, td_pg->td_id)) {
		NOTICE("the pa 0x%llx is not from memory pool.\n", pa);
	}
	*dst_pte = __pte(pte.pte);
	return 0;
}

int copy_pte_range(pmd_t *dst_pmd, pmd_t *src_pmd, hhkrd_pg *td_pg,
		   unsigned long addr, unsigned long addr_end) {
	pte_t *src_pte, *dst_pte;
    /* allocate and populate the dest pte */
	dst_pte = pte_alloc(td_pg, dst_pmd, addr);
	if (!dst_pte)
		return -ENOMEM;
	src_pte = pte_offset(src_pmd, addr);

	do {
		if (pte_none(*src_pte)) {
			if(td_pg->use_mem_pool)
				*dst_pte = __pte(0);
			continue;
		}
		copy_one_pte(dst_pte, src_pte, td_pg, addr);
		// NOTICE("dst_pte: 0x%llx, pte_entry: 0x%lx, src_pte: 0x%lx, addr: 0x%lx, end: 0x%lx\n",
		// 	(uint64_t)dst_pte, pte_val(*dst_pte), pte_val(*src_pte), addr, addr_end);
	} while (dst_pte++, src_pte++, addr += S_PAGE_SIZE, addr != addr_end);

	return 0;
}

int copy_pmd_range(pgd_t *dst_pud, pgd_t *src_pud, hhkrd_pg *td_pg,
		unsigned long addr, unsigned long addr_end) {
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;
    /* allocate and populate the dest pmd */
	dst_pmd = pmd_alloc(td_pg, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;
	src_pmd = pmd_offset(src_pud, addr);

    // NOTICE("[debug copy_pmd_range] addr: 0x%lx, end: 0x%lx, dst_pmd_addr: 0x%lx, src_pmd_addr: 0x%lx, src_pmd_val: 0x%lx.\n",
    //         addr, addr_end, (unsigned long)dst_pmd, (unsigned long)src_pmd, pmd_val(*src_pmd));

	do {
		next = pmd_addr_end(addr, addr_end);
		if (pmd_none_or_clear_bad(src_pmd))
			continue;
		if (copy_pte_range(dst_pmd, src_pmd,
						td_pg, addr, next))
			return -ENOMEM;
		NOTICE("dst_pmd: 0x%lx, src_pmd: 0x%lx, addr: 0x%lx, next: 0x%lx\n",
			 pmd_val(*dst_pmd), pmd_val(*src_pmd), addr, next);
	} while (dst_pmd++, src_pmd++, addr = next, addr != addr_end);
	return 0;
}

int copy_page_range(unsigned long addr, unsigned long addr_end, hhkrd_pg *td_pg, pgd_t *os_pgd) {
	unsigned long next;
	int ret;
	pgd_t *src_pgd, *dst_pgd;

	ret = 0;
	src_pgd = pgd_offset_raw(os_pgd, addr);
    // NOTICE("os_pgd addr: 0x%lx; addr: 0x%lx, get src_pgd: 0x%lx.\n",
    //         (unsigned long)os_pgd, addr, (unsigned long)src_pgd);
	
    dst_pgd = pgd_offset_raw((pgd_t *) td_pg->td_pgd_phys_addr, addr);
    // NOTICE("td_pgd_phys_addr: 0x%lx; addr: 0x%lx, get dst_pgd: 0x%lx.\n",
    //         (unsigned long)td_pg->td_pgd_phys_addr, addr, (unsigned long)dst_pgd);

    NOTICE("[debug copy_page_range] addr: 0x%lx, end: 0x%lx, td_pgd_phys_addr: 0x%llx, dst_pgd_addr: 0x%lx, src_pgd_addr: 0x%lx, src_pgd_val: 0x%lx.\n",
            addr, addr_end, td_pg->td_pgd_phys_addr, (unsigned long)dst_pgd, (unsigned long)src_pgd, pgd_val(*src_pgd));
	do {
		next = pgd_addr_end(addr, addr_end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if ((copy_pmd_range(dst_pgd, src_pgd,
						td_pg, addr, next))) {
			ret = -ENOMEM;
			break;
		}
		NOTICE("dst_pgd: 0x%lx, src_pgd: 0x%lx, addr: 0x%lx, next: 0x%lx\n",
			 pgd_val(*dst_pgd), pgd_val(*src_pgd), addr, next);
	} while (dst_pgd++, src_pgd++, addr = next, addr != addr_end);

	return ret;
}


/*
 * =================================================================================
 * Base Addr               | Size             |       Content       | Comment
 * =================================================================================
 * td_phys_pa2             |       4KB        | exception vector    | set by OS driver
 * ---------------------------------------------------------------------------------
 * td_phys_pa2 + 4KB       |       4KB        | td_pgd table        |
 * ---------------------------------------------------------------------------------
 * td_phys_pa2 + 8KB       |       2MB        | td_pmd tables       |
 * ---------------------------------------------------------------------------------
 * td_phys_pa2 + 2MB + 8KB | 16MB - 2MB - 8KB | td_pte tables       |
 * =================================================================================
 */

uint64_t allocate_hhkrd_pagetable(uint64_t td_id, uint64_t src_ttbr0) {
    /* initialize the td_pg */
    hhkrd_pg * td_pg = &hhkrd_mem[td_id].td_pg;
    td_pg->td_id = td_id;
    
    td_pg->td_pgd_phys_addr = hhkrd_mem[td_id].td_phys_pa2 + EXCEPTION_VECTOR_LENGTH;
    td_pg->td_pmd_phys_addr = td_pg->td_pgd_phys_addr + S_PAGE_SIZE;
    td_pg->td_pte_phys_addr = td_pg->td_pmd_phys_addr + 512 * S_PAGE_SIZE; 
    /* 16MB - 4KB */
    td_pg->pg_length = HHKRD_VECTOR_PAGE_TABLE_SPACE - EXCEPTION_VECTOR_LENGTH;
    /* pmd pages */
    td_pg->td_pmd_pages_number = 512;
    /* pte pages (512 + 1) means 512 pmd pages + 1 pgd page */
    td_pg->td_pte_pages_number = (td_pg->pg_length - ((512 + 1) * S_PAGE_SIZE)) / S_PAGE_SIZE; 
    td_pg->pmd_pages_index = 0;
    td_pg->pte_pages_index = 0;
    // try to read an EL1 addr
    // NOTICE("[try to read el1] read phys: 0x%llx.\n", hhkrd_mem[td_id].td_phys_pa2);
    // NOTICE("[try to read el1] read val: 0x%llx.\n", *(uint64_t *)hhkrd_mem[td_id].td_phys_pa2);
    pgd_t *os_pgd = (pgd_t*) (src_ttbr0 & 0xFFFFFFFFF000);
    /* TODO() gpt enable */
    gpt_enable_td(td_id);
    NOTICE("[allocate_hhkrd_pagetable] td_pgd_phys_addr: 0x%llx, td_pmd_phys_addr: 0x%llx, td_pte_phys_addr: 0x%llx.\n",
            td_pg->td_pgd_phys_addr, td_pg->td_pmd_phys_addr, td_pg->td_pte_phys_addr);
    NOTICE("CUR gptbr: 0x%lx, gpccr: 0x%lx.\n", read_gptbr_el3(), read_gpccr_el3());
	NOTICE("cur spsrel3: 0x%lx, scr_el3: 0x%lx.\n", read_spsr_el3(), read_scr_el3());
    NOTICE("[debug os pgd val]: 0x%lx.\n", pgd_val(*os_pgd));
    /* copy os page table to the private page table */
    int ret = copy_page_range(0, VA_END, td_pg, os_pgd);
    if (ret == 0) {
        return td_pg->td_pgd_phys_addr;
    } else {
        return 0;
    }
}

/**
 * Setup hhkrd task's page table from OS's page table
 * @param x1: tid
 * @param x2: address
 * @param x3: size
 */
int hhkrd_set_page(u_register_t x1, u_register_t x2, u_register_t x3) {
    spin_lock(&pte_lock);
    uint64_t tid = x1;
    uint64_t addr = x2;
    uint64_t size = x3;
    uint64_t end = addr + size;
    NOTICE("<hhkrd_set_page> tid: %llu, addr: 0x%llx, size: 0x%llx, end: 0x%llx.\n", tid, addr, size, end);
    /* fetch the relevant td_task */
    hhkrd_task_t *td_task = hhkrd_task_search(NULL, tid);
    if (!td_task) {
        NOTICE("<hhkrd_set_page> Failed to find OS tid: %llu in hhkrd_tasks.\n", tid);
        panic();
    }
    /* TODO() enable gpt protection */
    gpt_enable_td(td_task->td_id);
    /* fetch the td_task's pagetable td_pg */
    hhkrd_pg *td_pg = &hhkrd_mem[td_task->td_id].td_pg;
    /* fetch OS's page table PGD (ttbr0_el1) */
    pgd_t *os_pgd = __os_pgd(td_task->os_TTBR0_EL1);
    /* copy OS's page table to the private td_task's pagetable td_pg */
    int ret = copy_page_range(addr, end, td_pg, os_pgd);
    if (ret) 
        goto error;
    
    gpt_enable_td(0);
    spin_unlock(&pte_lock);
    NOTICE("<set_page> done.\n");
    return 0;
    
error:
    NOTICE("<hhkrd_set_page> copy_page_range [0x%llx, 0x%llx] error.\n", addr, end);
    gpt_enable_td(0);	
    spin_unlock(&pte_lock);
    return -ENOMEM;
}

/*
 * Assign a shared buffer (from CMA allocator) for hhkrd
 * @param x1: OS tid
 * @param x2 (optional): virtual address for shared buffer
 * @param x3 (optional): virtual address for signal stack
 */
int hhkrd_assign_share_mem(u_register_t x1, u_register_t x2, u_register_t x3) {
    spin_lock(&task_lock);

    uint64_t tid = x1;
    hhkrd_task_t *td_task = hhkrd_task_search(NULL, tid);
    if (!td_task) {
        NOTICE("<hhkrd_assign_share_buffer> Failed to find td task for tid: %llu.\n", tid);
		panic();
    }

    NOTICE("<hhkrd_assign_share_buffer> tid:%llu\n", tid);    

    uint64_t pa;
    if (x2) {
        pa = hhkrd_virt_to_phys(x2);
        if (!pa || !allocate_memory_check(pa, HHKRD_TASK_SHARED_LENGTH, td_task->td_id)) {
            NOTICE("<hhkrd_assign_share_buffer> allocate error.\n");    
            panic();
        }
        td_task->task_shared_virt = x2;
        td_task->task_shared_length = HHKRD_TASK_SHARED_LENGTH;
        td_task->task_shared_phys = pa;
    }
    if (x3) {
        pa = hhkrd_virt_to_phys(x3);
        if (!pa || !allocate_memory_check(pa, HHKRD_TASK_SIGNAL_STACK_LENGTH, td_task->td_id)) {
            NOTICE("<hhkrd_assign_share_buffer> allocate error.\n");    
            panic();
        }
        td_task->task_signal_stack_virt = x3;
        td_task->task_signal_stack_length = HHKRD_TASK_SIGNAL_STACK_LENGTH;
        td_task->task_signal_stack_phys = pa;
        /* make the signal frame stack accessible for OS to remedy for later setup_frame */
        gpt_transition_pas_td_contiguous(pa, HHKRD_TASK_SIGNAL_STACK_LENGTH, GPI_NS, 0);
    }

    spin_unlock(&task_lock);
    return 0;
}

/*
 * expand memory for hhkrd
 * @param x1: physical memory address
 * @param x2: memory size
 */
int hhkrd_memexpand(u_register_t x1, u_register_t x2) {	
	spin_lock(&task_lock);
    cm_el1_sysregs_context_save(NON_SECURE);
	cpu_context_t *src_ctx  = cm_get_context(NON_SECURE);

    uint64_t tid = read_el1_sysreg(src_ctx, CTX_CONTEXTIDR_EL1);
    hhkrd_task_t *td_task = hhkrd_task_search(NULL, tid);
	if (!td_task) {	
		NOTICE("<hhkrd_memexpand> Fail to find task_struct in hhkrd_tasks\n");
		panic();
	}
    /* todo() memory overlap check */
	// if(!hhkrd_gpt_memory_overlap_check(x1, x2))
	// {
	// 	NOTICE("hhkrd_gpt_memory_overlap!\n");
	// 	return -1;
	// }

	size_t td_id = td_task->td_id;
	hhkrd_mem_t *td_mem = &hhkrd_mem[td_id];

	if(!td_mem->td_phys_pa3) {
        td_mem->td_phys_pa3 = x1;
		td_mem->td_phys_size3 = x2;
        // todo(): inaccessable to all other hhkrds
        gpt_transition_pas_td_contiguous(x1, x2, GPI_ROOT, 0);
        gpt_transition_pas_td_contiguous(x1, x2, GPI_NS, td_id);
	}
	else if(!td_mem->td_phys_pa4) {
		td_mem->td_phys_pa4 = x1;
		td_mem->td_phys_size4 = x2;
		// todo(): inaccessable to all other hhkrds
        gpt_transition_pas_td_contiguous(x1, x2, GPI_ROOT, 0);
        gpt_transition_pas_td_contiguous(x1, x2, GPI_NS, td_id);
	}
	else {
		NOTICE("Fail to expand memory, the standby hhkrd_phys_pa is full.\n");
		spin_unlock(&task_lock);
		return -1;
	}
    td_mem->td_pg.use_mem_pool = true;
    NOTICE("<hhkrd_memexpand> expand phys_addr: 0x%lx, size: 0x%lx. success.\n",
            x1, x2);
	spin_unlock(&task_lock);
	return 0;
}

/** ================================================
 * OS Service Management (handler)
 * =================================================
 */
/*
 * Handle the hhkrd's system call parameters before forwarding the service to the normal OS. 
 *
 * Since the hhkrd userspace is protected by the GPT, the normal OS cannot directly handle 
 * those system call parameters. So we need to: 
 * 
 * 1) For buffer-operation syscall (e.g., read, write), copy the buffer parameters into the 
 *    hhkrd shared memory region task_shared_virt, and change the buffer pointer to this region .
 * 
 *   i) for output syscalls (e.g., write) that OS read from hhkrd userspace buffer, we memcpy
 *      the origin buffer content to the shared region.
 *   ii) for input syscalls (e.g., read) that OS write the hhkrd userspace buffer, we just 
 *       replace the buffer to the shared region, and copy the writted content back to the 
 *       userspace buffer at the syscall_return_handle (after the normal OS proceeding the syscall).
 * 
 * 2) [todo] copy the signal stack parameter into the hhkrd shared region task_signal_task_virt, 
 *    and change the signal stack pointer to this region.
 */
void hhkrd_syscall_params_handle(hhkrd_task_t *td_task, uint32_t syscallno) {
    cpu_context_t *src_ctx = cm_get_context(NON_SECURE);
    int ret = 0;
    /* handle syscall parameter case-by-case */
    switch (syscallno) {
        case SYS_ioctl:
            ret = syscall_params_handler(ioctl, src_ctx, td_task);
            break;
        case SYS_uname:
        case SYS_pipe2:
        case SYS_sysinfo:
        case SYS_nanosleep:
            ret = syscall_params_handler(uname_pipe2_sysinfo_nanosleep, src_ctx, td_task);
            break;
        case SYS_clock_nanosleep:
            ret = syscall_params_handler(clock_nanosleep, src_ctx, td_task);
            break;
        case SYS_fstat:
        case SYS_clock_gettime:
        case SYS_getrlimit:
        case SYS_setgroups:
            ret = syscall_params_handler(fstat_clockgettime_getrlimit_setgroups, src_ctx, td_task);
            break;
        case SYS_readlinkat:
            ret = syscall_params_handler(readlinkat, src_ctx, td_task);
            break;
        case SYS_read:
        case SYS_pread64:
            ret = syscall_params_handler(read_pread64, src_ctx, td_task);
            break;
        case SYS_write:
        case SYS_pwrite64:
            ret = syscall_params_handler(write_pwrite64, src_ctx, td_task);
            break;
        case SYS_readv:
            ret = syscall_params_handler(readv, src_ctx, td_task);
            break;
        case SYS_writev:
            ret = syscall_params_handler(writev, src_ctx, td_task);
            break;
        case SYS_openat:
        case SYS_unlinkat: 
        case SYS_fchmodat:
        case SYS_mkdirat:
            ret = syscall_params_handler(openat_unlinkat_fchmodat_mkdirat, 
                                        src_ctx, td_task);
            break;
        case SYS_renameat:
        case SYS_renameat2:
            ret = syscall_params_handler(renameat_renameat2, src_ctx, td_task);
            break;
        case SYS_prlimit64:
            ret = syscall_params_handler(prlimit64, src_ctx, td_task);
            break;
        /* clone */
        case SYS_clone:
            ret = syscall_params_handler(clone, src_ctx, td_task);
            break;
        /* futex */
        case SYS_futex:
            ret = syscall_params_handler(futex, src_ctx, td_task);
            break;
        /* signals */
        case SYS_RT_SIGACTION:
            ret = syscall_params_handler(rt_sigaction, src_ctx, td_task);
            break;
        case SYS_RT_SIGRETURN:
            ret = syscall_params_handler(rt_sigreturn, src_ctx, td_task);
            break;
        case SYS_RT_SIGPROCMASK:
            ret = syscall_params_handler(rt_sigprocmask, src_ctx, td_task);
            break;
        default:
            NOTICE("<sys_param_handle> just unhandled sysno: 0x%x.\n", syscallno);
            ret = 1;
            break;
    }

    if (ret != 0)
        goto out;
    /* 
     * Finish cases. For the param handler region, give access permission to OS's handler
     */
    if (td_task->is_use_task_shared_virt) {
        gpt_transition_pas_td_contiguous(td_task->task_shared_phys, td_task->task_shared_length, GPI_NS, 0);
    } else if (td_task->is_use_task_signal_stack_virt) {
        gpt_transition_pas_td_contiguous(td_task->task_signal_stack_phys, td_task->task_signal_stack_length, GPI_NS, 0);
    } else if (td_task->is_use_task_futex_virt) {
        /* we just give futex' page access permission to normal OS */
        gpt_transition_pas_td_contiguous(td_task->task_futex_phys, FUTEX_PAGE, GPI_NS, 0);
    }

out:;
    /* switch to normal world's GPT to run normal OS service */
    gpt_enable_td(0);
    NOTICE("<hhkrd_syscall_params_handle> sysno: %d done.\n", syscallno);
}



/*
 *
 */
void hhkrd_syscall_return_handle(hhkrd_task_t *td_task, cpu_context_t *src_ctx) {
    uint32_t syscallno = td_task->wait_syscallno;
    /* buffer based system calls */
    if (td_task->is_use_task_shared_virt) {
        /* cancal the permission of normal OS after the service */
        gpt_transition_pas_td_contiguous(td_task->task_shared_phys, 
                                         td_task->task_shared_length,
                                         GPI_ROOT, 0);
        switch (syscallno) {
        case SYS_ioctl:
            syscall_return_handler(ioctl, src_ctx, td_task);
            break;
        case SYS_fstat:
        case SYS_newfstatat:
        case SYS_sysinfo:
        case SYS_uname:
        case SYS_prlimit64:
        case SYS_getrlimit:
        case SYS_pipe2:
        case SYS_clock_gettime:
            syscall_return_handler(fstat_newfstatat_sysinfo_uname_prlimit64_getrlimit_pipe2_clockgettime, 
                                    src_ctx, td_task);
            break;
        case SYS_clock_nanosleep:
            syscall_return_handler(clock_nanosleep, src_ctx, td_task);
            break;
        case SYS_read:
        case SYS_pread64:
        case SYS_readlinkat:
            syscall_return_handler(read_pread64_readlinkat, src_ctx, td_task);
            break;
        case SYS_RT_SIGACTION:
            syscall_return_handler(rt_sigaction, src_ctx, td_task);
            break;
        case SYS_RT_SIGPROCMASK:
            syscall_return_handler(rt_sigprocmask, src_ctx, td_task);
            break;
        default:
            break;
        }
        /* clean up */
        memset((void *)td_task->task_shared_phys, 0, td_task->task_shared_length);
        td_task->is_use_task_shared_virt = false;
    }

    /* signal stack based system calls */
    else if (td_task->is_use_task_signal_stack_virt) {
        switch (syscallno) {
        case SYS_RT_SIGRETURN:
            syscall_return_handler(rt_sigreturn, src_ctx, td_task);
            break;
        default:
            break;
        }
    }
    /* futex */
    else if (td_task->is_use_task_futex_virt) {
        switch (syscallno) {
        case SYS_futex:
            td_task->is_use_task_futex_virt = false;
            break;
        default:
            break;
        }
    }

    NOTICE("<hhkrd_syscall_return_handle> sysno: %d done.\n", syscallno);
}

/** =================================================
 * omnilog buf compare
 * ==================================================
 */

void * omni_buf_k;    // physical address for omni_buf_k
void * omni_buf_d;    // physical address for omni_buf_d

int omni_buf_d_pos = 0;      // pos for omni_buf_d
int *omni_buf_d_s;           // physical address for wait signal

spinlock_t omni_lock;

int hhkr_init_omni_buffers(u_register_t k, u_register_t d) {
    omni_buf_k = (void *)k;
    omni_buf_d = (void *)d;
    omni_buf_d_s = (int *)(omni_buf_d + (1 << 20));    // omni_buf + 1MB

    /* init as a random value */
    *omni_buf_d_s = 100;
    NOTICE("[omni_buf] init done buf_k: 0x%lx, buf_d: 0x%lx, buf_d_s: %d.\n",
            (unsigned long)omni_buf_k, (unsigned long)omni_buf_d, *omni_buf_d_s);
    return 0;
}

int hhkr_write_omni_buf(u_register_t phys_addr, u_register_t size) {
    spin_lock(&omni_lock);
    cm_el1_sysregs_context_save(NON_SECURE);
    unsigned long k_addr = (unsigned long)phys_addr;
    
    if (omni_buf_d_pos + size > (1 << 20)) {
        *omni_buf_d_s = 1;
        /* reset pos */
        omni_buf_d_pos = 0;
    }
    // /* waiting for the daemon to process logs, pass. */
    // while (*omni_buf_d_s == 1) {
    //     /* busy waiting */
    //     WARN("[omni_buf_d_s] waiting...\n");
    // }
    /* copy the log to the omni_buf_d */
    memcpy(omni_buf_d + omni_buf_d_pos, (void *)k_addr, size);
    NOTICE("[write_omni_buf] buf_d_phys: 0x%lx, pos: 0x%x, size: 0x%x.\n",
            (unsigned long)omni_buf_d, omni_buf_d_pos, (int)size);
    omni_buf_d_pos += size;
    
    dsbsy();
    cm_el1_sysregs_context_restore(NON_SECURE);
    spin_unlock(&omni_lock);
    return 0;
}