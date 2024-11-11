#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/io.h>  // page_to_phys
#include <linux/arm-smccc.h>
// #include <linux/memory.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <asm/memory.h>

#include <cma/cmalib.h>


static int __init cma_test_init(void) {
    struct cma *cma_area = NULL;
    cma_area = cma_allocator_search("bufpool@84400000");
    if (cma_area) {
        printk(KERN_INFO "base_pfn: 0x%lx, count: %lu\n", cma_area->base_pfn, cma_area->count);
    }
    return 0;
}

static void __exit cma_test_exit(void)
{
    printk(KERN_ALERT "bye: exiting cma_test...\n");
}

module_init(cma_test_init);
module_exit(cma_test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("cma test module.");