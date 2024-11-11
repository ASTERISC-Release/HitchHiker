/**
 * @file cma_driver.c
 * @author chuqi zhang
 * @brief 
 * ref blog doc: https://biscuitos.github.io/blog/CMA/
 * ref (kernel): https://github.com/BiscuitOS/HardStack/tree/BiscuitOS/Device-Driver/CMA/Base/kernel
 * ref (user): https://github.com/BiscuitOS/HardStack/tree/BiscuitOS/Device-Driver/CMA/Base/userland
 * @version 0.1
 * @date 2022-12-29
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// #define __KERNEL__
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/pgtable.h>
#include <linux/cma.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/dma-contiguous.h>

#include <linux/arm-smccc.h>
#include <test_defs.h>


// ***** CPU Cycle

static inline uint64_t getCycle(void) {
    uint64_t tsc;
    asm volatile("mrs %0, pmccntr_el0" : "=r"(tsc));
    return tsc;
}

static uint64_t cpu_start, cpu_end;
// ***** smc functions //
static uint64_t cpu_start_smc, cpu_end_smc_arg_prep, cpu_end_smc;
/* smc */
static inline uint64_t smc_asm_3args(unsigned int fid, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    uint64_t _fid = fid;
    uint64_t _arg1 = arg1;
    uint64_t _arg2 = arg2;
    uint64_t _arg3 = arg3;
    uint64_t ret0;
    printk(KERN_INFO "[debug smc] fid: 0x%llx, arg1: 0x%llx, arg2: 0x%llx, arg3: 0x%llx.\n",
           _fid, _arg1, _arg2, _arg3);
    cpu_start_smc = getCycle();
    /* prepare smc args & make smc */
    __asm__ volatile("mov x0, %[fid]\n"
                     "mov x1, %[arg1]\n"
                     "mov x2, %[arg2]\n"
                     "mov x3, %[arg3]\n"
                     "mov x4, #0\n"
                     "mov x5, #0\n"
                     "smc #0"
                     :: [fid]"r"(_fid), [arg1]"r"(_arg1), [arg2]"r"(_arg2), [arg3]"r"(_arg3)
                     : "x0", "x1", "x2", "x3", "cc", "memory");
    /* return value: x0 */
    asm volatile("mov %0, x0" : "=r"(ret0)); 
    cpu_end_smc = getCycle();
    return ret0;
}

// static inline void simu_smc_arg_prep(unsigned int fid, uint64_t _arg1, uint64_t _arg2, uint64_t _arg3) {
//     uint64_t _fid = fid;
//     cpu_start_smc = getCycle();
//     /* prepare smc args */
//     __asm __volatile("mov x0, %[fid]\n\t"
//                      "mov x1, %[arg1]\n\t"
//                      "mov x2, %[arg2]\n\t"
//                      "mov x3, %[arg3]\n\t"
//                      "mov x4, #0\n\t"
//                      "mov x5, #0" ::[fid] "r"(_fid),
//                      [arg1] "r"(_arg1), [arg2] "r"(_arg2), [arg3] "r"(_arg3));
//     cpu_end_smc_arg_prep = getCycle();
//     return;
// }

// *******************

static inline void fast_memcpy(void *dst, void *src, size_t size) {
    long long remain;
    for (remain = size; remain - 32 >= 0; dst += 32, src += 32, remain -= 32) {
        ((unsigned long *)dst)[0] = ((unsigned long *)src)[0];
        ((unsigned long *)dst)[1] = ((unsigned long *)src)[1];
        ((unsigned long *)dst)[2] = ((unsigned long *)src)[2];
        ((unsigned long *)dst)[3] = ((unsigned long *)src)[3];
    }
}

#define DEV_NAME            "cma_demo"
#define CMA_REGION_NUM      64

#define GETLOCK             (struct mutex *)&manager->lock

/* tzsac controller in bl31 */
static int tzasc_enabled = 0;

/* CMA region information */
struct CMA_demo_info {
	unsigned long virt;
	unsigned long phys;
	unsigned long offset;
	unsigned long length;
};

/* CMA Memory Region */
struct CMA_demo_region {
	struct CMA_demo_info info;
	struct list_head list;
};

/* CMA manager information */
struct CMA_demo_manager {
	struct miscdevice misc;
	struct mutex lock;
	struct list_head head;
};

/* CMA memory device */
static struct CMA_demo_manager *manager;
static int cma_init_allocate = 1;

struct arm_smccc_res smccc_res;

static long cma_driver_ioctl(struct file * filp, unsigned int cmd, unsigned long arg) {
    struct CMA_demo_region * region;
    struct CMA_demo_info info;
    unsigned int pool_size_order;
    unsigned long nr_pages;
    
    struct page *page, *page1, *page2;
    dma_addr_t page_phys, page1_phys, page2_phys;

    char *_va, *_temp_buf;
    int found = 0;
    unsigned long arg0;
    int rvl, ret;

    switch(cmd) {
        case CMA_MEM_ALLOCATE: /* allocate contiguous memory */
            /* lock */
            mutex_lock(GETLOCK);
            /* get information from userland */
            if (copy_from_user(&info, (void __user *)arg, sizeof(struct CMA_demo_info))) {
                printk(KERN_ERR "Allocate: copy_from_user error.\n");
                rvl = -EFAULT;
                goto err_user;
            }
            /* allocate new region */
            region = kzalloc(sizeof(*region), GFP_KERNEL);
            if (!region) {
                printk(KERN_ERR "Allocate: no free memory for a new region.\n");
                rvl = -ENOMEM;
                goto err_alloc;
            }

            nr_pages = info.length >> PAGE_SHIFT;
            pool_size_order = get_order(info.length);
            /* Allocate memory from CMA */
            page = dma_alloc_from_contiguous(NULL, nr_pages, pool_size_order, GFP_KERNEL);
            if (!page) {
                printk(KERN_ERR "Allocate: DMA allocate error.\n");
                rvl = -ENOMEM;
                goto err_dma;
            }
            /* insert region to the manager */
            info.virt = (dma_addr_t)page_to_virt(page);
            info.phys = (dma_addr_t)page_to_phys(page);
            region->info.virt = info.virt;
            region->info.phys = info.phys;
            region->info.length = info.length;
            /* init memory cell content */
            memset((void *)info.virt, 'A', info.length);
            /* debug */
            printk(KERN_INFO "cma_driver: allocate size: 0x%lx (%luMB) virt: 0x%lx <==> phys: 0x%lx\n", 
                                info.length, info.length / (MEM_SZ_1MB), info.virt, info.phys);
            
            list_add(&region->list, &manager->head);
            
            /* TEST: gpt_transition_test smc */
            
            /* determine whether it's the first allocate (need to build gpt) */
            if (cma_init_allocate == 1) {
                arg0 = 1;
                cma_init_allocate = 0;
            } else {
                arg0 = 0;
            }
            // get start cycle
            cpu_start = getCycle();
            // arm_smccc_smc(GPT_TRANS_TEST, arg0, info.phys, info.length, 0, 0, 0, 0, &smccc_res);
            ret = smc_asm_3args(GPT_TRANS_TEST, arg0, info.phys, info.length);
            // get end cycle
            cpu_end = getCycle();
            printk(KERN_INFO "[CMA_MEM_ALLOCATE][gpt_trans_test EL1] Invoking SMC at cycle: %llu\n", cpu_start);
            printk(KERN_INFO "[CMA_MEM_ALLOCATE][gpt_trans_test EL1] End-up SMC at cycle: %llu\n", cpu_end);
            // log smc cycles
            printk(KERN_INFO "<smc> whole smc cycle (return to el1): %llu (%llu - %llu).\n",
                   cpu_end_smc - cpu_start_smc, cpu_end_smc, cpu_start_smc);
            // ret = smccc_res.a0;
            printk(KERN_INFO "[CMA_MEM_ALLOCATE] gpt transition test ret:%d\n", ret);

            /* export to userland */
            if (copy_to_user((void __user *)arg, &info, sizeof(info))) {
                printk(KERN_ERR "Allocate: copy_to_user error.\n");
                rvl = -EINVAL;
                goto err_to;
            }
            /* unlock */
            mutex_unlock(GETLOCK);
            return 0;

        case CMA_MEM_RELEASE:
            mutex_lock(GETLOCK);
            if (copy_from_user(&info, (void __user *)arg, sizeof(struct CMA_demo_info))) {
                printk(KERN_ERR "Release: copy_from_user error.\n");
                rvl = -EFAULT;
                goto err_user;
            }
            /* search region */
            list_for_each_entry(region, &manager->head, list) {
                if (region->info.phys == info.phys && 
                    region->info.length == info.length) {
                        found = 1;
                        break;
                    }
            }
            if (!found) {
                printk(KERN_ERR "Release: Can't find special region\n");
			    rvl = -EINVAL;
			    goto err_user;
            }
            /* Free contiguous memory */
            page = phys_to_page(info.phys);
            nr_pages = info.length >> PAGE_SHIFT;
            dma_release_from_contiguous(NULL, page, nr_pages);
            list_del(&region->list);
            kfree(region);
            mutex_unlock(&manager->lock);
            
            return 0;

        case CMA_FAST_MEMCPY_TEST:
            mutex_lock(GETLOCK);
            char _src[64];
            memset(_src, 'A', 64);
            _temp_buf = kzalloc(sizeof(char) * 65, GFP_KERNEL);
            
            cpu_start = getCycle();
            fast_memcpy(_temp_buf, _src, 64);
            cpu_end = getCycle();

            printk(KERN_INFO "[FAST_MEMCPY_TEST][EL1] Start Memcpy 64B at cycle: %llu\n", cpu_start);
            printk(KERN_INFO "[FAST_MEMCPY_TEST][EL1] End Memcpy 64B at cycle: %llu\n", cpu_end);
            printk(KERN_INFO "<memcpy> whole memcpy cycle: %llu.\n", cpu_end - cpu_start);
            printk(KERN_INFO "content: %s.\n", _temp_buf);
            _temp_buf[64] = 0;
            kfree(_temp_buf);
            mutex_unlock(GETLOCK);
            return 0;

        case CMA_EL3_MEMCPY_TEST:
            mutex_lock(GETLOCK);
            if (copy_from_user(&info, (void __user *)arg, sizeof(struct CMA_demo_info))) {
                printk(KERN_ERR "Release: copy_from_user error.\n");
                rvl = -EFAULT;
                goto err_user;
            }
            /* assign two memory and use memcpy in el3 */
            nr_pages = info.length >> PAGE_SHIFT;
            pool_size_order = get_order(info.length);
            page1 = dma_alloc_from_contiguous(NULL, nr_pages, pool_size_order, GFP_KERNEL);
            if (!page1) {
                printk(KERN_ERR "[CMA_EL3_MEMCPY_TEST] Allocate: DMA allocate error.\n");
                rvl = -ENOMEM;
                goto err_dma;
            }
            page2 = dma_alloc_from_contiguous(NULL, nr_pages, pool_size_order, GFP_KERNEL);
            if (!page2)
            {
                printk(KERN_ERR "[CMA_EL3_MEMCPY_TEST] Allocate: DMA allocate error.\n");
                rvl = -ENOMEM;
                goto err_dma;
            }
            
            page1_phys = (dma_addr_t)page_to_phys(page1);
            memset((char *)page_to_virt(page1), 'A', info.length);
            page2_phys = (dma_addr_t)page_to_phys(page2);
            memset((char *)page_to_virt(page2), 0, info.length);
            printk(KERN_INFO "[CMA_EL3_MEMCPY_TEST][el3_memcpy_test EL1] assigned two buffers, size: 0x%lx (%luKB / %luMB), addrs: 0x%llx, 0x%llx\n",
                   info.length, info.length / (1 << 10), info.length / (MEM_SZ_1MB), page1_phys, page2_phys);
            
            /* EL1 memcpy first */
            void *page1_virt = (void *)page_to_virt(page1);
            void *page2_virt = (void *)page_to_virt(page2);
            cpu_start = getCycle();
            memcpy(page2_virt, page1_virt, info.length);
            cpu_end = getCycle();
            printk(KERN_INFO "[MEMCPY_TEST][el1_memcpy_test EL1] Memcpy %luKB / %luMB. cycle: %llu\n", info.length / (1 << 10), info.length / (1 << 20), cpu_end - cpu_start);
            memset((char*)page2_virt, 0, info.length);

            /* EL1 fast memcpy then */
            cpu_start = getCycle();
            fast_memcpy(page2_virt, page1_virt, info.length);
            cpu_end = getCycle();
            printk(KERN_INFO "[MEMCPY_TEST][el1_memcpy_test EL1] Fast Memcpy %luKB / %luMB. cycle: %llu\n", info.length / (1 << 10), info.length / (1 << 20), cpu_end - cpu_start);
            memset((char *)page2_virt, 0, info.length);

            cpu_start = getCycle();
            // arm_smccc_smc(EL3_MEMCPY_TEST, page1_phys, page2_phys, info.length, 0, 0, 0, 0, &smccc_res);
            ret = smc_asm_3args(EL3_MEMCPY_TEST, page1_phys, page2_phys, info.length);
            cpu_end = getCycle();
            printk(KERN_INFO "[MEMCPY_TEST][el3_memcpy_test EL1] Invoking SMC at cycle: %llu\n", cpu_start);
            printk(KERN_INFO "[MEMCPY_TEST][el3_memcpy_test EL1] End-up SMC at cycle: %llu\n", cpu_end);
            // log smc cycles
            printk(KERN_INFO "<smc> whole smc cycle (return to el1): %llu (%llu - %llu).\n",
                   cpu_end_smc - cpu_start_smc, cpu_end_smc, cpu_start_smc);

            // release memories
            dma_release_from_contiguous(NULL, page1, nr_pages);
            dma_release_from_contiguous(NULL, page2, nr_pages);
            // // debug check memcontent
            // char buf[50];
            // memcpy(buf, (void *) page_to_virt(page2) + 0x10005, 49);
            // buf[49] = '\0';
            // printk("[DEBUG] page2_phys_cont: %s\n", buf);
            mutex_unlock(GETLOCK);
            return 0;

        case CMA_SMC_EMPTY_TEST:
            mutex_lock(GETLOCK);
            printk(KERN_INFO "[CMA_SMC_EMPTY_TEST][smc EL1] Invoking SMC at cycle: %llu\n", getCycle());
            smc_asm_3args(SMC_EMPTY_TEST, 0, 0, 0);
            printk(KERN_INFO "[CMA_SMC_EMPTY_TEST][smc EL1] End-up SMC at cycle: %llu\n", getCycle());
            printk(KERN_INFO "<smc> whole smc cycle (return to el1): %llu (%llu - %llu).\n", 
                    cpu_end_smc - cpu_start_smc, cpu_end_smc, cpu_start_smc);
            // printk(KERN_INFO "[CMA_SMC_ARG_PREP][smc EL1] Start Preparing SMC at cycle: %llu\n", getCycle());
            // simu_smc_arg_prep(SMC_EMPTY_TEST, 0x100, 0x1000, 0x10000);
            // printk(KERN_INFO "[CMA_SMC_ARG_PREP][smc EL1] End Preparing SMC at cycle: %llu\n", getCycle());
            // printk(KERN_INFO "<smc> args prepare cycle: %llu (%llu - %llu).\n",
            //        cpu_end_smc_arg_prep - cpu_start_smc, cpu_end_smc_arg_prep, cpu_start_smc);
            mutex_unlock(GETLOCK);
            return 0;

        case CMA_TZASC_SETUP:
            mutex_lock(GETLOCK);
            if (!tzasc_enabled) {
                printk(KERN_INFO "[CMA_TZASC_SETUP] Setting TZASC controller in bl31.\n");
                /* initialize tzasc controller */
                smc_asm_3args(SMC_TZASC_SETUP, 0, 0, 0);
                tzasc_enabled = 1;
            }
            printk(KERN_INFO "[CMA_TZASC_SETUP] TZASC controller setup done.\n");
            mutex_unlock(GETLOCK);
            return 0;

        case CMA_TZASC_TEST:
            mutex_lock(GETLOCK);
            /* allocate memory */
            if (copy_from_user(&info, (void __user *)arg, sizeof(struct CMA_demo_info))) {
                printk(KERN_ERR "Release: copy_from_user error.\n");
                rvl = -EFAULT;
                goto err_user;
            }
            /* assign a memory region for tzasc region permission change */
            nr_pages = info.length >> PAGE_SHIFT;
            pool_size_order = get_order(info.length);
            page = dma_alloc_from_contiguous(NULL, nr_pages, pool_size_order, GFP_KERNEL);
            if (!page) {
                printk(KERN_ERR "[CMA_TZASC_TEST] Allocate: DMA allocate error.\n");
                rvl = -ENOMEM;
                goto err_dma;
            }
            page_phys = (dma_addr_t)page_to_phys(page);
            memset((char *)page_to_virt(page), 'A', info.length);
            printk(KERN_INFO "[CMA_TZASC_TEST][tzasc_test EL1] assigned buffer, size: 0x%lx (%luMB), addr: 0x%llx\n",
                   info.length, info.length / (MEM_SZ_1MB), page_phys);
            // get start cycle
            cpu_start = getCycle();
            ret = smc_asm_3args(SMC_TZASC_TEST, page_phys, info.length, 1);
            // get end cycle
            cpu_end = getCycle();

            printk(KERN_INFO "[CMA_TZASC_TEST][smc EL1] Invoking SMC at cycle: %llu\n", cpu_start);
            printk(KERN_INFO "[CMA_TZASC_TEST][smc EL1] End-up SMC at cycle: %llu\n", cpu_end);
            // log smc cycles
            printk(KERN_INFO "<smc> whole smc cycle (return to el1): %llu (%llu - %llu).\n",
                   cpu_end_smc - cpu_start_smc, cpu_end_smc, cpu_start_smc);
            
            // FIXME debug: try to access memory from NS world
            // _va = (char *)page_to_virt(page);
            // printk(KERN_INFO "[debug] read va content after tzasc first change: %c\n", *_va);

            /* after evaluation: tzasc region back */
            ret = smc_asm_3args(SMC_TZASC_TEST, page_phys, info.length, 0);
            // FIXME debug: try to access memory from NS world
            // _va = (char *) page_to_virt(page);
            // printk(KERN_INFO "[debug] read va content after tzasc change back NS: %c\n", *_va);
            /* release memory */
            
            dma_release_from_contiguous(NULL, page, nr_pages);
            
            mutex_unlock(GETLOCK);
            return 0;

        default:
            printk(KERN_INFO "CMA not support command.\n");
		    return -EFAULT;
    }
err_to:
	list_del(&region->list);
	dma_release_from_contiguous(NULL, page, nr_pages);
err_dma:
	kfree(region);
err_alloc:
err_user:
    mutex_unlock(GETLOCK);
    return rvl;
}

static int cma_driver_mmap(struct file *filp, struct vm_area_struct *vma) {
    unsigned long start = vma->vm_start;
    unsigned long size = vma->vm_end - vma->vm_start;
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    unsigned long page;

    /* offset is physical address */
	page = offset >> PAGE_SHIFT;

    /* Remap */
	if (remap_pfn_range(vma, start, page, size, PAGE_SHARED)) {
		printk("REMAP: failed\n");
		return -EAGAIN;
	}

    /* set flags */
    vma->vm_flags &= ~VM_IO;
    vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);

    return 0;
}

/* file operations */
static struct file_operations CMA_demo_fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = cma_driver_ioctl,
    .mmap           = cma_driver_mmap,
};

// init 
static int __init cma_driver_init(void) {
    int rvl; 
    /* CMA: initialize device manager */
    manager = kzalloc(sizeof(struct CMA_demo_manager), GFP_KERNEL);
    if (!manager) {
        printk(KERN_ERR "Allocate cma_manager failed.\n");
        rvl = -ENOMEM;
        goto err_alloc;
    }
    
    /* Lock: initialize */
    mutex_init(&manager->lock);
    /* Misc: initialize */
    manager->misc.name = DEV_NAME;
    manager->misc.minor = MISC_DYNAMIC_MINOR;
    manager->misc.fops = &CMA_demo_fops;

    /* list: initialize */
    INIT_LIST_HEAD(&manager->head);

    /* Register Misc device */
    misc_register(&manager->misc);
    return 0;

err_alloc:
    return rvl;
}

static void __exit cma_driver_exit(void) {
    struct CMA_demo_region *reg;

    printk(KERN_INFO "Exiting cma_driver module.\n");

    /* free all regions */
    mutex_lock(GETLOCK);
    list_for_each_entry(reg, &manager->head, list)
        kfree(reg);
    mutex_unlock(GETLOCK);

    /* un-register misc device */
    misc_deregister(&manager->misc);
    /* free memory */
    kfree(manager);
    manager = NULL;
}

module_init(cma_driver_init);
module_exit(cma_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chuqi zhang");
MODULE_DESCRIPTION("Contiguous Memory Allocate (CMA) Device Driver");