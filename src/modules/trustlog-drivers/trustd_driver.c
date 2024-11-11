#include <linux/mm.h>
#include <linux/cma.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
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

#include <arch_def.h>
#include <cma/cmalib.h>
#include <memlib.h>

#define DEV_NAME    "trustd"

static size_t trustd_mem_wait_release_queue[TRUSTD_MAX];
static int td_this_page_mapped = 0; /* a padding flag */
static struct arm_smccc_res smccc_res;

extern void __attribute__ ((visibility ("hidden"))) trustd_exception_vector_table(void);
extern void __attribute__ ((visibility ("hidden"))) trustd_exception_vector_table_end(void);

static int trustd_memexpand(int gpt_id) {
    struct page *page;
    /* update the td_region */
    td_region = kzalloc(sizeof(td_region), GFP_KERNEL);
    if (!td_region) {
        printk(KERN_ERR "<kzalloc> no free memory.\n");
        return -ENOMEM;
    }
    /* fetch a 64MB region from the allocator */
    page = trustd_allocate_memory(TRUSTD_EXTEND_MEM_DEFAULT_LENGTH, td_region, td_mngr, gpt_id); 
    if (!page) {
        printk(KERN_ERR "<Allocator> DMA error.\n");
        return -ENOMEM;
    }
    
    /* sync monitor */
    arm_smccc_smc(TRUSTD_MEMEXPAND, td_region->td_mem_info.phys_addr, td_region->td_mem_info.length,
                  0, 0, 0, 0, 0, &smccc_res);
    printk(KERN_INFO "<el1 trustd_memexpend> return: %lu.\n", smccc_res.a0);
    return smccc_res.a0;
}

static long trustd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    td_mem_region_t *exception_table_region;
    td_mem_info_t mem_info;
    td_mem_region_t *temp_td_region;
    int gpt_id, rvl, i;
    uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8;
    // uint64_t start, end, start2, end2;
    unsigned long ttbr0_el1;
    struct page *page;
    int found = 0;
    
    switch (cmd) {
    case TRUSTD_AL_ALLOCATE:
        mutex_lock(&td_mngr->lock);
        /* get info from userland */
        if (copy_from_user(&mem_info, (void __user *)arg, sizeof(td_mem_info_t))) {
            printk(KERN_ERR "<TRUSTD_AL_ALLOCATE> copy_from_user error.\n");
            rvl = -EFAULT;
            goto err_user;
        }
        /* setup new region */
        temp_td_region = (td_mem_region_t *)kzalloc(sizeof(temp_td_region), GFP_KERNEL);
        printk("<trustd_al_allocate> allocate td_region successfully.\n");
        if (!temp_td_region) {
            printk(KERN_ERR "<kzalloc> No free memory.\n");
            rvl = -EFAULT;
            goto err_alloc;
        }
        page = trustd_allocate_memory(mem_info.length, temp_td_region, td_mngr, -1);
        if (!page) {
            printk(KERN_ERR "<trustd_allocate_memory> cma error.\n");
            rvl = -ENOMEM;
            goto err_dma;
        }

        td_region = temp_td_region;
        if (copy_to_user((void __user *)arg, &mem_info, sizeof(td_mem_info_t))) {
            printk(KERN_ERR "<TRUSTD_AL_ALLOCATE> copy_to_user error.\n");
            rvl = -EINVAL;
            goto err_to;
        }
        mutex_unlock(&td_mngr->lock);
        return 0;
    /* put the caller trustd's id in the release queue */
    case TRUSTD_AL_MARK_RELEASE:
        gpt_id = get_current()->gpt_id;
        for (i = 0; i < TRUSTD_MAX; i++) {
            /* already in the queue? then return; */
            if (trustd_mem_wait_release_queue[i] == gpt_id) {
                return 0;
            }
        }
        /* find an empty elem and insert */
        for (i = 0; i < TRUSTD_MAX; i++) {
            if (!trustd_mem_wait_release_queue[i]) {
                trustd_mem_wait_release_queue[i] = gpt_id;
                break;
            }
        }
        return 0;
    /* release all the memories in the queue */
    case TRUSTD_AL_RELEASE:
        mutex_lock(&td_mngr->lock);
        for (i = 0; i < TRUSTD_MAX; i++) {
            if (!trustd_mem_wait_release_queue[i])
                continue;
            gpt_id = trustd_mem_wait_release_queue[i];
            /* iterate all regions for release */
            list_for_each_entry(temp_td_region, &td_mngr->region_head, list) {
                /* free */
                if(temp_td_region->td_mem_info.gpt_id == gpt_id) {
                    page = phys_to_page(temp_td_region->td_mem_info.phys_addr);
                    trustd_release_memory(page, temp_td_region->td_mem_info.length, temp_td_region);
                    // todo?  manipulate linked-list ?
                }
            }
            trustd_mem_wait_release_queue[i] = 0;
        }
        mutex_unlock(&td_mngr->lock);
        return 0;
    
    case TRUSTD_CREATE:
        mutex_lock(&td_mngr->lock);
        printk(KERN_INFO "<trustd_create> start.\n");
        if (!td_region) {
            printk(KERN_ERR "<trustd_create> cannot find available td_region.\n");
            rvl = -EINVAL;
            goto err_user;
        }

        exception_table_region = (td_mem_region_t *)kzalloc(sizeof(exception_table_region), GFP_KERNEL);
        if (!exception_table_region) {
            printk(KERN_ERR "<kzalloc> Failed to allocate memory.\n");
            rvl = -ENOMEM;
            goto err_alloc;
        }
        /* assign vector table */
        page = trustd_allocate_memory(TRUSTD_VECTOR_PAGE_TABLE_SPACE, exception_table_region,
                                      td_mngr, -1);
        /* mark kernel executable */
        if (!trustd_mark_region_exec(exception_table_region->td_mem_info.virt_addr, 
                                     TRUSTD_VECTOR_PAGE_TABLE_SPACE, 1)) {
            rvl = -EINVAL;
            goto err_user;   
        }
        /* copy the exception vector table */
        memcpy((void *)exception_table_region->td_mem_info.virt_addr, &trustd_exception_vector_table,
               (&trustd_exception_vector_table_end - &trustd_exception_vector_table));

        struct pt_regs *task_regs = task_pt_regs(get_current());
        td_region->td_mem_info.__entry = task_regs->pc;
        td_region->td_mem_info.__sp_top = task_regs->sp;

        x0 = TRUSTD_CREATE;
        x1 = td_region->td_mem_info.phys_addr;
        x2 = td_region->td_mem_info.__sp_top;
        x3 = td_region->td_mem_info.__entry;
        x4 = get_current()->cmafd;
        x5 = exception_table_region->td_mem_info.virt_addr;
        x6 = td_region->td_mem_info.length;
        x7 = (unsigned long)get_current();
        mutex_unlock(&td_mngr->lock);
        
		asm volatile("mrs %0, ttbr0_el1" : "=r"(ttbr0_el1));
		printk(KERN_INFO "[debug] ttbr0_el1: 0x%lx\n", ttbr0_el1);
        /* create and record trustd program td_task in the EL3 monitor */
        printk(KERN_INFO "<trustd_create> Create trustd for OS tid: %d, task addr: 0x%lx.\n", get_current()->pid, x7);
        arm_smccc_smc(x0, x1, x2, x3, x4, x5, x6, x7, &smccc_res);
        asm volatile("isb");
        gpt_id = smccc_res.a0;
        if (gpt_id) {
            td_region->td_mem_info.gpt_id = gpt_id;
            exception_table_region->td_mem_info.gpt_id = gpt_id;
            int ret;
            /*
             * create a new td_region and used for this trustd's shared memory alloc
             * i.e., task_shard_mem and task_signal_stack_mem
             */
            ret = trustd_memexpand(gpt_id);
            if (ret != 0) {
                printk(KERN_ERR "<trustd_memexpand> failed.\n");
                return -1;
            }
        }
        return gpt_id;
    
    case TRUSTD_DESTROY:
        mutex_lock(&td_mngr->lock);
        /* Get information from userland */
		if (copy_from_user(&mem_info, (void __user *)arg,
					sizeof(td_mem_info_t))) {
			printk(KERN_ERR "<trustd_destory>: copy_from_user error\n");
			rvl = -EFAULT;
			goto err_user;
		}

		// x0 = TRUSTD_DESTROY;
		// x1 = info.virt; //enclave memory phsy address
		// arm_smccc_smc(x0, x1, 0, 0, 0, 0, 0, 0, &smccc_res);
		// asm volatile("isb");
		mutex_unlock(&td_mngr->lock);
		return 0;

    default:
        break;
    }
err_to:
    list_del(&temp_td_region->list);
    trustd_release_memory(page, mem_info.length, NULL);
err_dma:
    kfree(temp_td_region);
err_alloc:
err_user:
    mutex_unlock(&td_mngr->lock);
    return rvl;
}

/*
 * userspace: mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
 * or kern: ksys_mmap_pgoff(unsigned long addr, unsigned long len,
 *                          unsigned long prot, unsigned long flags,
 *                          unsigned long fd, unsigned long pgoff);
 * This trustd_mmap() is only used for allocate new memory in the td_region; or map the current page 
 * in the td_region->offset.
 * 
 * The @param offset / pgoff is used to control the behavior of this mmap.
 * When vma->vm_pgoff = 0: Allocate a new memory from the td_region (do allocation for malloc)
 * When vma->vm_pgoff = 1: Map the current offset page in td_region (do anonymous mapping)
 */
static int trustd_mmap(struct file *filp, struct vm_area_struct *vma) {
    unsigned long start = vma->vm_start;
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long pg_off = vma->vm_pgoff;

    bool do_allocate;
    unsigned long phys_page;
    unsigned long base_phys_offset;

    struct page *page;
    int ret; 

    do_allocate = (pg_off == 1) ? false : true;
    /* allocate a new memory region */
    if (do_allocate) { /* allocate and map a new memory from the td_region */
        /* the current offset has been mapped before, then skip this page */
        if (td_this_page_mapped) {
            td_this_page_mapped = 0;
            td_region->td_mem_info.offset += PAGE_SIZE;
        }
        /* the remaining memory in this region is enough */
        if (td_region->td_mem_info.offset + size <= td_region->td_mem_info.length) {
            base_phys_offset = td_region->td_mem_info.phys_addr + td_region->td_mem_info.offset;
            td_region->td_mem_info.offset += size;
        } 
        /* remaining memory not enough: try to allocate */
        else
            goto add_new_td_mem;
    }
    /* just map to the current offset page TODO: support map more pages */
    else {
        if (size != PAGE_SIZE)
            goto invalid_map_size;
        /* mark the current offset page in td_region is mapped */
        td_this_page_mapped = 1;
        /* no enough memory to map */
        if (td_region->td_mem_info.offset + size > td_region->td_mem_info.length) 
            goto add_new_td_mem;
        base_phys_offset = td_region->td_mem_info.phys_addr + td_region->td_mem_info.offset;
    }

    goto do_remap;
    
invalid_map_size:
    printk(KERN_ERR "Tried to anonymous map a larger than 4KB memory.\n");
	return -EINVAL;

add_new_td_mem:
    ret = trustd_memexpand(get_current()->gpt_id);
    if (ret == 0) {
        /* can do map or allocate now */
        if (td_region->td_mem_info.offset + size <= td_region->td_mem_info.length) {
            base_phys_offset = td_region->td_mem_info.phys_addr + td_region->td_mem_info.offset;
            if (do_allocate)
                td_region->td_mem_info.offset += size;
        } else {
            printk(KERN_ERR "<td_allocator> no enough memory.\n");
            return -ENOMEM;
        }
    } else {
        printk(KERN_ERR "<trustd_memexpend> smc handle failed.");
        return -ENOMEM;
    }

do_remap:
    /* convert to page no */
    phys_page = base_phys_offset >> PAGE_SHIFT;
    /* revise the pgoff of this vma to correctly map to td_region offset */
    vma->vm_pgoff = phys_page; 
    vma->vm_flags &= ~VM_IO;
    vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP | VM_READ | VM_WRITE | VM_SHARED);

    if (remap_pfn_range(vma, start, phys_page, size, vma->vm_page_prot)) {
        printk(KERN_ERR "REMAP: failed.\n");
        return -EAGAIN;
    }
    /* sync the page table by invoking the monitor */
    if (current->is_trustd && current->is_created) {
        printk(KERN_INFO "Trustd memory allocation. tid: %d, addr: 0x%lx, size: 0x%lx.\n",
                current->pid, start, size);
        arm_smccc_smc(TRUSTD_SETPAGE, current->pid, start, size, 0, 0, 0, 0, &smccc_res);
    }
    
    return 0;
}


static struct file_operations td_ops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = trustd_ioctl,
    .mmap = trustd_mmap,
};

static int __init td_driver_init(void) {
    int rvl;

    td_mngr = kzalloc(sizeof(td_mngr), GFP_KERNEL);
    if (!td_mngr) {
        printk(KERN_ERR "allocate td_mngr failed.\n");
        rvl = -ENOMEM;
        goto err_alloc;
    }
    mutex_init(&td_mngr->lock);

    td_mngr->misc.name = DEV_NAME;
    td_mngr->misc.minor = MISC_DYNAMIC_MINOR;
    td_mngr->misc.fops = &td_ops;

    INIT_LIST_HEAD(&td_mngr->region_head);
    misc_register(&td_mngr->misc);
    printk(KERN_INFO "trustd driver loaded successfully.\n");

    return 0;
err_alloc:
    return rvl;
}

static void __exit td_driver_exit(void)
{
    td_mem_region_t *temp_region;
    mutex_lock(&td_mngr->lock);

    list_for_each_entry(temp_region, &td_mngr->region_head, list)
        kfree(temp_region);
    
    mutex_unlock(&td_mngr->lock);
    
    misc_deregister(&td_mngr->misc);
    kfree(td_mngr);
    td_mngr = NULL;
    printk(KERN_ALERT "bye: exiting trustd-driver...\n");
}

module_init(td_driver_init);
module_exit(td_driver_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("driver module.");