#include <linux/mm.h>
#include <linux/cma.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/sizes.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/dma-contiguous.h>
#include <linux/arm-smccc.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/timer.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>

#include <linux/hitchhiker.h>
#include "hhkr_mempool.h"
#include "hhkrd_mgmt.h"

#define DEV_NAME    "hitchhiker-ctl"

// record for device instrumentation
#define DEBUG_RECORD_SATA

#ifdef DEBUG_RECORD_SATA
#include <linux/syscalls.h>
extern bool fetch_debug_record_sata(void);
extern void set_debug_record_sata(bool);
#endif

#define pr_fmt(fmt) "hitchhiker-ctl: " fmt
#define log_info(fmt, arg...) \
    printk(KERN_INFO "[%s][%d] "pr_fmt(fmt)"", __func__, __LINE__, ##arg)
#define log_err(fmt, arg...) \
    printk(KERN_ERR "[%s][%d] "pr_fmt(fmt)"", __func__, __LINE__, ##arg)

struct miscdevice *misc;

static size_t hhkrd_mem_wait_release_queue[HHKRD_MAX];

/** =========================================================================================================
 *  Hitchhiker receiver (hhkrd) exception vector table (see exception_table.S under this dir)
 *  ========================================================================================================= */
/* exception vector table for hhkrd */
extern void __attribute__ ((visibility ("hidden"))) hhkrd_exception_vector_table(void);
extern void __attribute__ ((visibility ("hidden"))) hhkrd_exception_vector_table_end(void);

/** =========================================================================================================
 *  Hitchhiker builtin secure policy
 *  ========================================================================================================= */
/* timer for interval_based policy */
static struct hrtimer hhkr_timer;

/* default time interval (1ms) */
static ktime_t _hhkr_interval = 0;

static ktime_t hhkr_default_interval(int interval_us) {
    if (unlikely(_hhkr_interval == 0)) {
        if (interval_us)
            _hhkr_interval = ktime_set(0, interval_us * NSEC_PER_USEC);
        else  /* set default 1ms (1000us) */
            _hhkr_interval = ktime_set(0, MESSAGE_INTERVAL_MS * NSEC_PER_MSEC);
    }
    return _hhkr_interval;
}


static void hhkr_activate_interval_secure_policy(unsigned int time_interval_us) {
    if (time_interval_us)
        log_info("activate secure policy with time interval: %dus.\n", time_interval_us);
    else
        log_info("activate secure policy with time (default) interval: 1ms.\n");
    hrtimer_start(&hhkr_timer, hhkr_default_interval(time_interval_us), HRTIMER_MODE_REL);
}

static void hhkr_deactivate_interval_secure_policy(void) {
    log_info("deactivate secure policy.\n");
    _hhkr_interval = 0;
    hrtimer_cancel(&hhkr_timer);
}

static int use_memcpy = 0;    /* evaluation flag: use gpt / el3_memcpy to secure a buffer */
/* Hitchhiker builtin secure policy implementation (1ms interval default) */
static enum hrtimer_restart hhkr_do_secure_policy(struct hrtimer *timer) {
    /* secure the current buf */
    hhkr_secure_current_buf(0, use_memcpy);
    /* 
     * update the timer. at this time, the _hhkr_interval is already set,
     * so that we just fill 0 as the parameter.
     */
    hrtimer_forward_now(timer, hhkr_default_interval(0));
    return HRTIMER_RESTART;
}

/** =========================================================================================================
 *  Hitchhiker ioctl() interface
 *  ========================================================================================================= */
static long hhkr_ctl_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    // /* hhkr variables */
    // hhkr_buf_t *buf, temp_buf;
    /* hhkrd variables */
    hhkrd_mem_region_t *exception_table_region;
    hhkrd_mem_info_t mem_info;
    hhkrd_mem_region_t *temp_hhkrd_region;
    int gpt_id, rvl, i, obs_type, ret;
    uint64_t x0, x1, x2, x3, x4, x5, x6, x7;
    // uint64_t start, end, start2, end2;
    unsigned long ttbr0_el1, queue_mmap_addr, freeback_wl_mmap_addr, sg_pg_addr, buf_addr;
    unsigned long addr;
    struct page *page;
    hhkr_scatterlist_pgs_t *hhkr_sg_pg;
    struct pt_regs *task_regs;

#if DEBUGLABEL
    log_info("cmd: 0x%x, arg: 0x%lx.\n", cmd, arg);
#endif

    switch (cmd) {
#ifdef DEBUG_RECORD_SATA
    case 0:  // set debug_record_sata
        if (arg) {
            set_debug_record_sata(true);
        } else {
            set_debug_record_sata(false);
        }
        log_info("update debug_record_sata to %d.\n", fetch_debug_record_sata());
        return 0;
#endif

/** =========================================================================================
 * Interface for HITCHHIKER (hhkr) memory pool management
 * ========================================================================================== */

    case HHKR_MMAP_BUF:
        __hhkr_mmap_buf_all((enum hhkr_obs_type)arg);
        return 0;
    
    case HHKR_MMAP_MSG_QUEUE:
        queue_mmap_addr = __hhkr_mmap_msg_queue();
        /* return its page off */
        return (long)(queue_mmap_addr >> PAGE_SHIFT);
    
    case HHKR_MMAP_BUF_META_MSG:
        addr = __hhkr_mmap_buf_meta_msg();
        return (long)(addr >> PAGE_SHIFT);
        
    case HHKR_MMAP_FREEBACK_WL:
        freeback_wl_mmap_addr = __hhkrd_mmap_free_wl();
        /* return its page off */
        return (long)(freeback_wl_mmap_addr >> PAGE_SHIFT);
    
    /* evaluation compare */
    case HHKR_MMAP_OMNI_BUF_D:
        buf_addr = __hhkr_mmap_omni_buffer_d();
        return (long)(buf_addr >> PAGE_SHIFT);
/** =========================================================================================
 * Interface for HITCHHIKER (hhkr) secure policy management
 * ========================================================================================== */

    case HHKR_ACT_INTERVAL_POLICY:
        hhkr_activate_interval_secure_policy((int)arg);
        return 0;

    case HHKR_CLR_INTERVAL_POLICY:
        hhkr_deactivate_interval_secure_policy();
        return 0;

    case HHKR_POLICY_CDF_MODE:
        policy_cdf_mode = 1;
        return 0;

    case HHKR_MEMCPY_MODE:
        use_memcpy = (int)arg;
        log_info("update use_el3_memcpy mode: %d.\n", use_memcpy);
        return 0;
    // case HHKR_MMAP_POLICY_ACT_FLAG:
    //     return (long)(__hhkr_activate_flag_mmap() >> PAGE_SHIFT);
/** =========================================================================================
 * Interface for HITCHHIKER (hhkr) secure I/O management
 * ========================================================================================== */
    case HHKRD_INIT_SECIO:
        __hhkr_secure_IO_init(arg);
        return 0;

    case HHKRD_MMAP_PENDING_STAT:
        buf_addr = __hhkrd_mmap_secIO_pending_job();
        return (long)(buf_addr >> PAGE_SHIFT); 

    case HHKRD_MMAP_SCATTER:
        obs_type = arg;
        sg_pg_addr = __hhkr_sg_pg_mmap(obs_type);
        return (long)(sg_pg_addr >> PAGE_SHIFT);
    
    case HHKRD_ASSIGN_SECIO: /* TODO: debug test now */
        hhkr_sg_pg = (hhkr_scatterlist_pgs_t *)arg;
        hhkrd_secIO_assignjob(arg, hhkr_sg_pg->blk_start, hhkr_sg_pg->write_size);
        return 0;
/** =========================================================================================
 * Interface for HITCHHIKER DAEMON (hhkrd) management
 * ========================================================================================== */
    /*
     * Allocate a memory segment (default 64 MB) for `hhkrd`'s initialization 
     * (its stack, .text, .data, and init variable segments)
     */
    case HHKRD_AL_ALLOCATE:
        mutex_lock(&hhkrd_mngr->lock);
        /* get info from userland */
        if (copy_from_user(&mem_info, (void __user *)arg, sizeof(hhkrd_mem_info_t))) {
            log_err("copy_from_user error.\n");
            rvl = -EFAULT;
            goto err_user;
        }
        /* setup new region */
        temp_hhkrd_region = (hhkrd_mem_region_t *)kzalloc(sizeof(temp_hhkrd_region), GFP_KERNEL);
        if (!temp_hhkrd_region) {
            log_err("kzalloc error.\n");
            rvl = -EFAULT;
            goto err_alloc;
        }
        /* allocate memory and fill the region's info */
        page = hhkrd_allocate_memory(mem_info.length, temp_hhkrd_region, hhkrd_mngr, -1);
        if (!page) {
            log_err("hhkrd_allocate_memory error.\n");
            rvl = -ENOMEM;
            goto err_dma;
        }
        hhkrd_region = temp_hhkrd_region;
        if (copy_to_user((void __user *)arg, &mem_info, sizeof(hhkrd_mem_info_t))) {
            log_err("copy_to_user error.\n");
            rvl = -EINVAL;
            goto err_to;
        }
        mutex_unlock(&hhkrd_mngr->lock);
        return 0;
    /*
     * Create a `hhkrd` process (user space daemon). This is invoked by the syscall handler
     * of syscall(__NR_hhkrd_exec)
     */
    case HHKRD_CREATE:
        mutex_lock(&hhkrd_mngr->lock);
        log_info("<hhkrd_create> Start to create hhkrd.\n");
        if (!hhkrd_region) {
            log_err("<hhkrd_create> hhkrd_region is NULL.\n");
            rvl = -EINVAL;
            goto err_user;
        }
        exception_table_region = (hhkrd_mem_region_t *)kzalloc(sizeof(exception_table_region), GFP_KERNEL);
        if (!exception_table_region) {
            log_err("<kzalloc> Failed to allocate memory.\n");
            rvl = -ENOMEM;
            goto err_alloc;
        }
        /* assign vector table */
        page = hhkrd_allocate_memory(HHKRD_VECTOR_PAGE_TABLE_SPACE, exception_table_region,
                                      hhkrd_mngr, -1);
        /* mark kernel executable */
        if (!hhkrd_mark_region_exec(exception_table_region->hhkrd_mem_info.virt_addr, 
                                     HHKRD_VECTOR_PAGE_TABLE_SPACE, 1)) {
            rvl = -EINVAL;
            goto err_user;   
        }
        /* copy the exception vector table */
        memcpy((void *)exception_table_region->hhkrd_mem_info.virt_addr, &hhkrd_exception_vector_table,
               (&hhkrd_exception_vector_table_end - &hhkrd_exception_vector_table));

        task_regs = task_pt_regs(get_current());
        hhkrd_region->hhkrd_mem_info.__entry = task_regs->pc;
        hhkrd_region->hhkrd_mem_info.__sp_top = task_regs->sp;

        x0 = HHKRD_CREATE;
        x1 = hhkrd_region->hhkrd_mem_info.phys_addr;
        x2 = hhkrd_region->hhkrd_mem_info.__sp_top;
        x3 = hhkrd_region->hhkrd_mem_info.__entry;
        x4 = get_current()->hhkr_ctl_fd;
        x5 = exception_table_region->hhkrd_mem_info.virt_addr;
        x6 = hhkrd_region->hhkrd_mem_info.length;
        x7 = (unsigned long)get_current();
        mutex_unlock(&hhkrd_mngr->lock);
#if DEBUGLABEL
		asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0_el1));
		printk(KERN_INFO "[debug] ttbr0_el1: 0x%lx\n", ttbr0_el1);
#endif
        /* create and record hhkrd program td_task in the EL3 monitor */
        log_info("<hhkrd_create> Create hhkrd for OS tid: %d, task addr: 0x%llx.\n", get_current()->pid, x7);
        /* SMC */
        gpt_id = hitchhiker_smc(x0, x1, x2, x3, x4, x5, x6, x7);
        asm volatile("isb");
        if (gpt_id) {
            /* setup hhkrd_region's gpt id */
            hhkrd_region->hhkrd_mem_info.gpt_id = gpt_id;
            exception_table_region->hhkrd_mem_info.gpt_id = gpt_id;
            /*
             * create a new hhkrd_region used for this hhkrd's shared memory alloc
             * i.e., task_shard_mem and task_signal_stack_mem
             */
            ret = hhkrd_memexpand(gpt_id);
            if (ret != 0) {
                log_err("<hhkrd_memexpand> failed.\n");
                return -1;
            }
        }
        return gpt_id;

    // case HHKR_SECURE_BUF:
    //     buf_addr = hhkr_secure_current_buf(0);
    //     return (long)(buf_addr >> PAGE_SHIFT);
        
    case HHKRD_FREEBACK_BUFS:
        // mutex_lock(&hhkrd_mngr->lock);
        ret = __hhkr_free_back_bufs();
        // mutex_unlock(&hhkrd_mngr->lock);
        return ret;
    /* invoked by do_group_exit() in exit.c */
    case HHKRD_DESTROY:
        mutex_lock(&hhkrd_mngr->lock);
        /* Get information from userland */
		if (copy_from_user(&mem_info, (void __user *)arg,
					sizeof(hhkrd_mem_info_t))) {
			log_err("<hhkrd_destory>: copy_from_user error\n");
			rvl = -EFAULT;
			goto err_user;
		}
		// x0 = HHKRD_DESTROY;
		// x1 = info.virt; //enclave memory phsy address
		// arm_smccc_smc(x0, x1, 0, 0, 0, 0, 0, 0, &smccc_res);
		// asm volatile("isb");
        mutex_unlock(&hhkrd_mngr->lock);
        return 0;

    case HHKRD_AL_MARK_RELEASE:
        gpt_id = get_current()->gpt_id;
        for (i = 0; i < HHKRD_MAX; i++) {
            /* already in the queue? then return; */
            if (hhkrd_mem_wait_release_queue[i] == gpt_id) {
                return 0;
            }
        }
        /* find an empty elem and insert */
        for (i = 0; i < HHKRD_MAX; i++) {
            if (!hhkrd_mem_wait_release_queue[i]) {
                hhkrd_mem_wait_release_queue[i] = gpt_id;
                break;
            }
        }
        return 0;

    /* release all the memories in the queue */
    case HHKRD_AL_RELEASE:
        mutex_lock(&hhkrd_mngr->lock);
        for (i = 0; i < HHKRD_MAX; i++) {
            if (!hhkrd_mem_wait_release_queue[i])
                continue;
            gpt_id = hhkrd_mem_wait_release_queue[i];
            /* iterate all regions for release */
            list_for_each_entry(temp_hhkrd_region, &hhkrd_mngr->region_head, list) {
                /* free */
                if(temp_hhkrd_region->hhkrd_mem_info.gpt_id == gpt_id) {
                    page = phys_to_page(temp_hhkrd_region->hhkrd_mem_info.phys_addr);
                    hhkrd_release_memory(page, temp_hhkrd_region->hhkrd_mem_info.length, temp_hhkrd_region);
                    // todo?  manipulate linked-list ?
                }
            }
            hhkrd_mem_wait_release_queue[i] = 0;
        }
        mutex_unlock(&hhkrd_mngr->lock);
        return 0;

    default:
        return 0;
    }
err_to:;
    if (temp_hhkrd_region)
        list_del(&temp_hhkrd_region->list);
    if (page)
        hhkrd_release_memory(page, mem_info.length, NULL);
err_dma:;
    kfree(temp_hhkrd_region);
err_alloc:;
err_user:;
    mutex_unlock(&hhkrd_mngr->lock);
    return rvl;
}

/** =========================================================================================================
 *  Hitchhiker memory mmap() interface
 *  ========================================================================================================= */
/** Interface for hitchhiker's mmap.
 * 
 * This hhkr_ctl_mmap() is only used for memory map management for both hhkrd's internal & shared memory.
 * 
 * userspace: mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
 * or kern: ksys_mmap_pgoff(unsigned long addr, unsigned long len,
 *                          unsigned long prot, unsigned long flags,
 *                          unsigned long fd, unsigned long pgoff);
 * 
 * The @param offset / pgoff is used to control the behavior of this mmap.
 * When vma->vm_pgoff = 0: Allocate a new memory from the hhkrd_region for hhkrd (do allocation + mmap)
 * else vma->vm_pgoff > 0: Map a physical page starting from pg_off for hhkrd (only do anonymous mapping)
 */
static int hhkr_ctl_mmap(struct file *file, struct vm_area_struct *vma) {
    unsigned long start = vma->vm_start;
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long pg_off = vma->vm_pgoff; // the offset of the physical memory

    bool do_allocate;
    unsigned long base_phys_offset;
    unsigned long phys_page;

    int ret; 

    do_allocate = (pg_off) ? false : true;
    /* allocate a new memory region */
    if (do_allocate) { /* allocate and map a new memory from the td_region */
        /* the remaining memory in this region is enough */
        if (hhkrd_region->hhkrd_mem_info.offset + size <= hhkrd_region->hhkrd_mem_info.length) {
            base_phys_offset = hhkrd_region->hhkrd_mem_info.phys_addr + hhkrd_region->hhkrd_mem_info.offset;
            hhkrd_region->hhkrd_mem_info.offset += size;
        } 
        /* remaining memory not enough: try to allocate */
        else
            goto add_new_hhkrd_mem;
    }
    /* just map to the current offset page */
    goto do_remap;

add_new_hhkrd_mem:;
    /* allocate a new memory region `hhkrd_region` */
    ret = hhkrd_memexpand(get_current()->gpt_id);
    if (ret) {
        log_err("hhkrd_allocate_memory failed.\n");
        return -ENOMEM;
    }
    if (hhkrd_region->hhkrd_mem_info.offset + size <= hhkrd_region->hhkrd_mem_info.length) {
        base_phys_offset = hhkrd_region->hhkrd_mem_info.phys_addr + hhkrd_region->hhkrd_mem_info.offset;
        hhkrd_region->hhkrd_mem_info.offset += size;
    } else {
        log_err("hhkrd_allocate_memory failed.\n");
        return -ENOMEM;
    }
    
do_remap:;
    if (do_allocate) {
        /* convert mem's base offset to page_no */
        phys_page = base_phys_offset >> PAGE_SHIFT;
        /* revise the pgoff of this vma to correctly map to hhkrd_region offset */
        vma->vm_pgoff = pg_off = phys_page;
    } else { /* in this case, just map a physical memory region into vma */ }
    
    // vma->vm_flags &= ~VM_IO;
    vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP | VM_READ | VM_WRITE | VM_SHARED);

#if DEBUGLABEL
    // log_info("vma: vm_start = 0x%lx, vm_end = 0x%lx, vm_pgoff = 0x%lx, vm_flags = 0x%lx, vm_page_prot = 0x%llx.\n", 
    //          vma->vm_start, vma->vm_end, vma->vm_pgoff, vma->vm_flags, vma->vm_page_prot.pgprot);
#endif

    if (remap_pfn_range(vma, start, pg_off, size, vma->vm_page_prot)) {
        log_err("remap_pfn_range failed.\n");
        return -EAGAIN;
    }
    /* finally, sync the VM page table by invoking the monitor */
    if (current->is_hhkrd && current->is_created) {
#if DEBUGLABEL
        // log_info("hhkrd_mmap setpage: current->gpt_id = %d, start = 0x%lx, size = 0x%lx, pg_off = 0x%lx\n", 
        //          current->gpt_id, start, size, pg_off);
#endif
        hitchhiker_smc(HHKRD_SETPAGE, current->pid, start, size, 0, 0, 0, 0);
    }
    return 0;
}


static struct file_operations hhkr_ctl_ops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = hhkr_ctl_ioctl,
    .mmap = hhkr_ctl_mmap,
};


/** =========================================================================================================
 *  Hitchhiker device controller module init
 *  ========================================================================================================= */
static int __init hhkr_ctl_init(void) {
    int rvl;
    /* initialize bufferqueue entry cache */
    bufqueue_entry_cache = kmem_cache_create("bufqueue_entry_cache", sizeof(hhkr_buf_queue_t),
                                              0, SLAB_HWCACHE_ALIGN, NULL);
    /* register hitchhiker system observability */
    /* we unify collection all logs to the same buffer, so 1 - 3 are deprecated */
    hhkr_register_observability(0, HHKR_BUF_LENGTH_DEFAULT / 16, HHKR_BUFPOOL_NUM_DEFAULT * 4);
    hhkr_register_observability(1, HHKR_BUF_LENGTH_DEFAULT, HHKR_BUFPOOL_NUM_DEFAULT);
    hhkr_register_observability(2, HHKR_BUF_LENGTH_DEFAULT, HHKR_BUFPOOL_NUM_DEFAULT);
    hhkr_register_observability(3, HHKR_BUF_LENGTH_DEFAULT, HHKR_BUFPOOL_NUM_DEFAULT);
    /* register device information */
    misc = kzalloc(sizeof(struct miscdevice), GFP_KERNEL);
    misc->name = DEV_NAME;
    misc->minor = MISC_DYNAMIC_MINOR;
    misc->fops = &hhkr_ctl_ops;
    
    rvl = misc_register(misc);
    if (rvl) {
        log_err("misc_register failed.\n");
        return rvl;
    }
    /* initialize hitchhiker daemon manager hhkrd_mngr */
    hhkrd_mngr = kzalloc(sizeof(hhkrd_mngr), GFP_KERNEL);
    if (!hhkrd_mngr) {
        log_err("hhkrd_mngr kzalloc failed.\n");
        return -ENOMEM;
    }
    mutex_init(&hhkrd_mngr->lock);
    INIT_LIST_HEAD(&hhkrd_mngr->region_head);

    /* initialize message queue */
    __hhkr_msg_queue_init();

    /* initialize buffer metadata message */
    __hhkr_buf_meta_msg_init();

    /* initialize freeback waitlist */
    __hhkrd_free_wl_init();

    /* initialize timer (time policy) */
    hrtimer_init(&hhkr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    hhkr_timer.function = hhkr_do_secure_policy;
    log_info("log buffer protection hrtimer init done.\n");

    /* initialize the policy activate flag */
    // __hhkr_activate_flag_init();

    /* initialize memory structures for secure I/O */
    __hhkr_IO_mem_init();

    /* initialize omni_buffers */
    __hhkr_init_omni_buffers((SZ_1M + SZ_4K));
    
    /* print the log buf hashtable */
    debug_print_hashtable();
    log_info("Init success.\n");
    return 0;
}

static void __exit hhkr_ctl_exit(void) {
    hhkrd_mem_region_t *temp_region;

    misc_deregister(misc);
    kfree(misc);
    /* stop the default timer */
    hrtimer_cancel(&hhkr_timer);

    /* Deregister system observabilities */
    __hhkr_deregister_observability(0);
    __hhkr_deregister_observability(1);
    __hhkr_deregister_observability(2);
    __hhkr_deregister_observability(3);

    /* destroy hitchhiker daemon manager */
    mutex_lock(&hhkrd_mngr->lock);
    list_for_each_entry(temp_region, &hhkrd_mngr->region_head, list) {
        list_del(&temp_region->list);
        kfree(temp_region);
    }
    mutex_unlock(&hhkrd_mngr->lock);
    kfree(hhkrd_mngr);

    /* destroy message queue */
    if (hhkr_msg_queue)
        kfree(hhkr_msg_queue);

    log_info("Exit success.\n");
}


module_init(hhkr_ctl_init);
module_exit(hhkr_ctl_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hitchhiker kernel module.");