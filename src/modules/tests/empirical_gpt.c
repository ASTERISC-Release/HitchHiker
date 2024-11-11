#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/pgtable.h>
#include <linux/cma.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/dma-contiguous.h>

#include <linux/arm-smccc.h>
#include <linux/cma.h>
#include <linux/hitchhiker.h>
#include <test_defs.h>

struct cma
{
    unsigned long base_pfn;
    unsigned long count;
    unsigned long *bitmap;
    unsigned int order_per_bit; /* Order of pages represented by one bit */
    struct mutex lock;
#ifdef CONFIG_CMA_DEBUGFS
    struct hlist_head mem_head;
    spinlock_t mem_head_lock;
#endif
    const char *name;
};

/* export from linux kernel */
extern struct cma cma_areas[MAX_CMA_AREAS];
extern unsigned int cma_area_count;

static inline unsigned long cma_bitmap_maxno(struct cma *cma)
{
    return cma->count >> cma->order_per_bit;
}

static inline struct cma *cma_allocator_search(char *name) {
    int i;
    printk(KERN_INFO "total cma count: %u, %d.\n", cma_area_count, MAX_CMA_AREAS);
    for (i = 0; i < cma_area_count; i++) {
        printk(KERN_INFO "targ_name: %s, searched_name: %s.\n", name, cma_areas[i].name);
        if (strcmp(name, cma_areas[i].name) == 0)
            return &cma_areas[i];
    }
    return NULL;
}


/* logger buffer pool allocator */
#define CMA_HKKR_BUF_POOL       "bufpool@84400000"
/* helpers */
struct cma *cma_logger_pool;

#define AL_logger   ({  \
    if (!cma_logger_pool) \
        cma_logger_pool = cma_allocator_search(CMA_HKKR_BUF_POOL); \
    (struct cma*)cma_logger_pool;   \
})


static inline unsigned long cma_allocate_mem(unsigned long size) {
    struct page *page;
    unsigned int pg_align;
    /* assign size mems */
    pg_align = get_order(size);

    page = cma_alloc(AL_logger, (size >> PAGE_SHIFT), pg_align, GFP_KERNEL);
    if (!page) {
        log_err("Failed to allocate memory for the secure I/O.\n");
        return -1;
    }
    return (unsigned long)page_to_virt(page);
}


static inline uint64_t getCycle(void) {
    uint64_t tsc;
    asm volatile("mrs %0, pmccntr_el0" : "=r"(tsc));
    return tsc;
}

static uint64_t cpu_start, cpu_end;

struct empirical_test {
	uint64_t gpt_walk_c;
	uint64_t tlb_inv_c;
	uint64_t cache_clean_c;
	uint64_t context_save_c;
	uint64_t context_restore_c;
};

#define num_elements   16


static int __init test_init(void) {
    
    int i, j;
    unsigned long x, empirical_res_phys;
    /* mem sizes */
    unsigned long mem_sizes[] = {SZ_4K, SZ_4K, SZ_8K, SZ_16K, SZ_32K, SZ_64K, SZ_128K, SZ_256K, SZ_512K, SZ_1M, SZ_4M, SZ_8M, SZ_16M, SZ_32M, SZ_64M, SZ_64M};
    
    struct empirical_test *emp_result = (struct empirical_test *)cma_allocate_mem(SZ_4K);
    
    empirical_res_phys = virt_to_phys(emp_result);


    uint64_t avg_gpt_walk_c[num_elements] = {0};
    uint64_t avg_tlb_inv_c[num_elements] = {0};
    uint64_t avg_cache_clean_c[num_elements] = {0};
    uint64_t avg_context_save_restore_c[num_elements] = {0};
    uint64_t avg_context_switch_c[num_elements] = {0};

    // /* prepare GPT */
    // hitchhiker_smc(GPT_TRANS_PRE, 0, 0, 0, 0, 0, 0, 0);

    // /* calc 5 times to count avg */
    int iter_time = 100;
    // for (i = 0; i < iter_time; i++) {
    //     printk(KERN_INFO "GPT Empirical Test Iter: %d.\n", i);
    //     for (j = 0; j < num_elements; j++) {
    //         // assign memory
    //         unsigned long virt_addr = cma_allocate_mem(mem_sizes[j]);
    //         unsigned long phys_addr = virt_to_phys((void *)virt_addr);

    //         // smc to trigger gpt transition
    //         cpu_start = getCycle();
    //         hitchhiker_smc(GPT_TRANS_TEST, empirical_res_phys, phys_addr, mem_sizes[j], 0, 0, 0, 0);
    //         cpu_end = getCycle();

    //         cma_release(AL_logger, phys_to_page(phys_addr), mem_sizes[j] >> PAGE_SHIFT);

    //         avg_gpt_walk_c[j] += emp_result->gpt_walk_c;
    //         avg_tlb_inv_c[j] += emp_result->tlb_inv_c;
    //         avg_cache_clean_c[j] += emp_result->cache_clean_c;
    //         avg_context_save_restore_c[j] += emp_result->context_save_c + emp_result->context_restore_c;
            
    //         x = (cpu_end - cpu_start) - (emp_result->gpt_walk_c + emp_result->tlb_inv_c + emp_result->cache_clean_c + emp_result->context_save_c + emp_result->context_restore_c);
    //         avg_context_switch_c[j] += x;

    //         // printk("GPT Trans memory size: %luKB / %luMB, gpt_walk_c: %lld, tlb_inv_c: %lld, cache_clean_c: %lld, context_save_c: %lld, context_switch_c: %ld\n", 
    //         //         mem_sizes[j] / (1 << 10), mem_sizes[j] / (1 << 20), emp_result->gpt_walk_c, emp_result->tlb_inv_c, emp_result->cache_clean_c,
    //         //         (emp_result->context_save_c + emp_result->context_restore_c), x);
    //     }   
    // }

    // for (j = 0; j < num_elements; j++) {
    //     printk(KERN_INFO "GPT Trans Memory AVG Statistics. Size: %luKB / %luMB.\n", mem_sizes[j] / (1 << 10), mem_sizes[j] / (1 << 20));
    //     printk(KERN_INFO "gpt_walk_c: %lld, tlb_inv_c: %lld, cache_clean_c: %lld, context_save_c: %lld, context_switch_c: %lld.\n",
    //                       avg_gpt_walk_c[j] / iter_time, avg_tlb_inv_c[j] / iter_time, avg_cache_clean_c[j] / iter_time, avg_context_save_restore_c[j] / iter_time, avg_context_switch_c[j] / iter_time);
    
    //     // clear
    //     avg_gpt_walk_c[j] = 0;
    //     avg_tlb_inv_c[j] = 0;
    //     avg_cache_clean_c[j] = 0;
    //     avg_context_save_restore_c[j] = 0;
    //     avg_context_switch_c[j] = 0;
    // }

    // /* MEMCPY */

    // /* calc 5 times to count avg */
    // for (i = 0; i < 5; i++) {
    //     printk(KERN_INFO "MEMCPY Empirical Test Iter: %d.\n", i);
    //     for (j = 0; j < num_elements; j++) {
    //         // assign memory
    //         unsigned long virt_addr1 = cma_allocate_mem(mem_sizes[j]);
    //         unsigned long virt_addr2 = cma_allocate_mem(mem_sizes[j]);

    //         unsigned long phys_addr1 = virt_to_phys((void *)virt_addr1);
    //         unsigned long phys_addr2 = virt_to_phys((void *)virt_addr2);

    //         // smc to trigger gpt transition
    //         cpu_start = getCycle();
    //         hitchhiker_smc(EL3_MEMCPY_TEST, phys_addr1, phys_addr2, mem_sizes[j], empirical_res_phys, 0, 0, 0);
    //         cpu_end = getCycle();

    //         cma_release(AL_logger, phys_to_page(phys_addr1), mem_sizes[j] >> PAGE_SHIFT);
    //         cma_release(AL_logger, phys_to_page(phys_addr2), mem_sizes[j] >> PAGE_SHIFT);

    //         avg_gpt_walk_c[j] += emp_result->gpt_walk_c;
    //         // avg_tlb_inv_c[j] += emp_result->tlb_inv_c;
    //         // avg_cache_clean_c[j] += emp_result->cache_clean_c;
    //         avg_context_save_restore_c[j] += emp_result->context_save_c + emp_result->context_restore_c;
            
    //         x = (cpu_end - cpu_start) - (emp_result->gpt_walk_c +  emp_result->context_save_c + emp_result->context_restore_c);
    //         avg_context_switch_c[j] += x;
    //     }   
    // }

    // for (j = 0; j < num_elements; j++) {
    //     printk(KERN_INFO "EL3 MEMCPY AVG Statistics. Size: %luKB / %luMB.\n", mem_sizes[j] / (1 << 10), mem_sizes[j] / (1 << 20));
    //     printk(KERN_INFO "mem_cpy_c: %lld,  context_save_c: %lld, context_switch_c: %lld.\n",
    //                       avg_gpt_walk_c[j] / 5, avg_context_save_restore_c[j] / 5, avg_context_switch_c[j] / 5);
    //     // clear
    //     avg_gpt_walk_c[j] = 0;
    //     avg_tlb_inv_c[j] = 0;
    //     avg_cache_clean_c[j] = 0;
    //     avg_context_save_restore_c[j] = 0;
    //     avg_context_switch_c[j] = 0;
    // }
    

    // tzc setup?
    hitchhiker_smc(SMC_TZASC_SETUP, 0, 0, 0, 0, 0, 0, 0);
    printk(KERN_INFO "TZC DONE.\n");
    // test region?
    // unsigned long virt_addr = cma_allocate_mem(SZ_64K);
    // unsigned long phys_addr = virt_to_phys((void *)virt_addr);
    // hitchhiker_smc(SMC_TZASC_TEST, phys_addr, SZ_64K, 1, empirical_res_phys, 0, 0, 0);
    // hitchhiker_smc(SMC_TZASC_TEST, phys_addr, SZ_64K, 0, empirical_res_phys, 0, 0, 0);

    // printk(KERN_INFO "tzc_c: %lld, \n", emp_result->gpt_walk_c);

    iter_time = 5;
    unsigned long mem_sizes1[] = {SZ_32K, SZ_32K, SZ_64K, SZ_128K, SZ_256K, SZ_512K, SZ_1M, SZ_4M, SZ_8M, SZ_16M, SZ_32M, SZ_64M, SZ_64M};
    for (i = 0; i < iter_time; i++) {
        printk(KERN_INFO "TZC Empirical Test Iter: %d.\n", i);
        for (j = 0; j < 13; j++) {
            // assign memory
            unsigned long virt_addr = cma_allocate_mem(mem_sizes1[j]);
            unsigned long phys_addr = virt_to_phys((void *)virt_addr);

            // smc to trigger gpt transition
            cpu_start = getCycle();
            hitchhiker_smc(SMC_TZASC_TEST, phys_addr, mem_sizes1[j], 1, empirical_res_phys, 0, 0, 0);
            cpu_end = getCycle();

            hitchhiker_smc(SMC_TZASC_TEST, phys_addr, mem_sizes1[j], 0, empirical_res_phys, 0, 0, 0);
            cma_release(AL_logger, phys_to_page(phys_addr), mem_sizes1[j] >> PAGE_SHIFT);

            avg_gpt_walk_c[j] += emp_result->gpt_walk_c;
            avg_context_save_restore_c[j] += emp_result->context_save_c + emp_result->context_restore_c;
            x = (cpu_end - cpu_start) - (emp_result->gpt_walk_c + emp_result->context_save_c + emp_result->context_restore_c);
            avg_context_switch_c[j] += x;
        
            printk("TZC memory size: %luKB / %luMB, tzc_c: %lld,context_save_c: %lld, context_switch_c: %ld\n", 
                    mem_sizes1[j] / (1 << 10), mem_sizes1[j] / (1 << 20), emp_result->gpt_walk_c, 
                    (emp_result->context_save_c + emp_result->context_restore_c), x);
        }   
    }
    
    for (j = 0; j < 13; j++) {
        printk(KERN_INFO "TZC AVG Statistics. Size: %luKB / %luMB.\n", mem_sizes1[j] / (1 << 10), mem_sizes[j] / (1 << 20));
        printk(KERN_INFO "tzc_c: %lld,  context_save_c: %lld, context_switch_c: %lld.\n",
                          avg_gpt_walk_c[j] / iter_time, avg_context_save_restore_c[j] / iter_time, avg_context_switch_c[j] / iter_time);
        // clear
        avg_gpt_walk_c[j] = 0;
        avg_tlb_inv_c[j] = 0;
        avg_cache_clean_c[j] = 0;
        avg_context_save_restore_c[j] = 0;
        avg_context_switch_c[j] = 0;
    }
    return 0;
}

static void __exit test_exit(void) {
}



module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chuqi zhang");
MODULE_DESCRIPTION("Empirical GPT test.");