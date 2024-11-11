#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <asm/io.h>
#include <linux/uaccess.h>

#include <asm/memory.h>
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/cma.h>

#include <test_defs.h>
#include <test_cma.h>

#define DEVICE_NAME "s2pt_demo"

MODULE_AUTHOR("chuqi zhang");
MODULE_DESCRIPTION("s2pt_demo");
MODULE_VERSION("v1.0");
MODULE_LICENSE("GPL");


#define get_bit_range_value(number, start, end) (((number) >> (end)) & ((1L << ((start) - (end) + 1)) - 1))

static inline uint64_t getCycle(void) {
    uint64_t tsc;
    asm volatile("mrs %0, pmccntr_el0"
                 : "=r"(tsc));
    return tsc;
}

struct empirical_test {
	uint64_t gpt_walk_c;
	uint64_t tlb_inv_c;
	uint64_t cache_clean_c;
	uint64_t context_save_c;
	uint64_t context_restore_c;
};


static uint64_t cpu_start, cpu_end;
// ***** smc functions //
static uint64_t cpu_start_smc, cpu_end_smc_arg_prep, cpu_end_smc;

#define num_elements   16


int secure_pid;

static inline uint64_t smc_asm_5args(unsigned int fid, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5)
{
    uint64_t _fid = fid;
    uint64_t _arg1 = arg1;
    uint64_t _arg2 = arg2;
    uint64_t _arg3 = arg3;
    uint64_t ret0;
    // printk(KERN_INFO "[debug smc] fid: 0x%llx, arg1: 0x%llx, arg2: 0x%llx, arg3: 0x%llx.\n",
    //        _fid, _arg1, _arg2, _arg3);
    // cpu_start_smc = getCycle();
    /* prepare smc args & make smc */
    __asm__ volatile("mov x0, %[fid]\n"
                     "mov x1, %[arg1]\n"
                     "mov x2, %[arg2]\n"
                     "mov x3, %[arg3]\n"
                     "mov x4, %[arg4]\n"
                     "mov x5, %[arg5]\n"
                     "smc #0" ::[fid] "r"(_fid),
                     [arg1] "r"(_arg1), [arg2] "r"(_arg2), [arg3] "r"(_arg3), [arg4] "r"(arg4), [arg5] "r"(arg5)
                     : "x0", "x1", "x2", "x3", "x4", "x5", "cc", "memory");
    /* return value: x0 */
    asm volatile("mov %0, x0"
                 : "=r"(ret0));
    // cpu_end_smc = getCycle();
    return ret0;
}



static inline unsigned long cma_allocate_mem(unsigned long size) {
    struct page *page;
    unsigned int pg_align;
    /* assign size mems */
    pg_align = get_order(size);

    struct cma *cma1 = &cma_areas[1];
    page = cma_alloc(cma1, (size >> PAGE_SHIFT), pg_align, GFP_KERNEL);
    if (!page) {
        printk(KERN_INFO "Failed to allocate memory for S2PT Test.\n");
        return -1;
    }
    return (unsigned long)page_to_virt(page);
}


static int __init s2pt_driver_module_init(void)
{
    int i, j, pg_count;
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
    int iter_time = 10;
    for (i = 0; i < iter_time; i++) {
        printk(KERN_INFO "S2PT Empirical Test Iter: %d.\n", i);
        for (j = 0; j < num_elements; j++) {
            // assign memory
            unsigned long virt_addr = cma_allocate_mem(mem_sizes[j]);
            unsigned long phys_addr = virt_to_phys((void *)virt_addr);
            pg_count = mem_sizes[j] >> PAGE_SHIFT;
            // smc to trigger gpt transition
            cpu_start = getCycle();
            smc_asm_5args(0xc7000001, 11, phys_addr, pg_count, 0x0, (unsigned long)emp_result);
            cpu_end = getCycle();

            // back
            smc_asm_5args(0xc7000001, 11, phys_addr, pg_count, 0x3, (unsigned long)emp_result);
            cma_release(&cma_areas[1], phys_to_page(phys_addr), mem_sizes[j] >> PAGE_SHIFT);
            // cma_release(cma1, page, pg_count);

            avg_gpt_walk_c[j] += emp_result->gpt_walk_c;
            avg_tlb_inv_c[j] += emp_result->tlb_inv_c;
            avg_cache_clean_c[j] += emp_result->cache_clean_c;
            avg_context_save_restore_c[j] += emp_result->context_save_c + emp_result->context_restore_c;
            
            x = (cpu_end - cpu_start) - (emp_result->gpt_walk_c + emp_result->tlb_inv_c + emp_result->cache_clean_c + emp_result->context_save_c + emp_result->context_restore_c);
            avg_context_switch_c[j] += x;

            printk("S2PT Trans memory size: %luKB / %luMB, gpt_walk_c: %lld, tlb_inv_c: %lld, cache_clean_c: %lld, context_save_c: %lld, context_switch_c: %ld\n", 
                    mem_sizes[j] / (1 << 10), mem_sizes[j] / (1 << 20), emp_result->gpt_walk_c, emp_result->tlb_inv_c, emp_result->cache_clean_c,
                    (emp_result->context_save_c + emp_result->context_restore_c), x);
        }   
    }

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


    return 0;
}

static void __exit s2pt_driver_module_exit(void)
{
    printk("exit module.\n");
}

module_init(s2pt_driver_module_init);
module_exit(s2pt_driver_module_exit);

MODULE_LICENSE("GPL");
