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

#include <test_defs.h>

#define ENC_ENTER_TEST  U(0x80000FFE)
#define ENC_EXIT_TEST   U(0x80000FFF)
#define ENC_STATUS      U(0x80001000)

void __attribute__ ((visibility ("hidden"))) test_enclave(void);
void __attribute__ ((visibility ("hidden"))) test_enclave_end(void);
// a code segment
__asm (
    ".text                                      \n"
    "test_enclave:                              \n"
    "   mov     x0, #0x11                       \n"
    "   mov     x1, #0x11                       \n"
    "   mov     x2, #0x11                       \n"
    "   mov     x3, #0x11                       \n"
    "   mov     x4, #0x11                       \n"
    "   mov     x5, #0x11                       \n"
    "   mov     x6, #0x11                       \n"
    "   mov     x7, #0x11                       \n"
    "   mov     x8, #0x11                       \n"
    "   mov     x9, #0x11                       \n"
    "   mov     x0, #0x80000000                       \n"
    "   add     x0, x0,#0xFFF                       \n"
    "   mov     x1, #0x1234                       \n"
    "   smc     #0                        \n"
    "   mrs     x10, scr_el3                        \n"
    "test_enclave_end:                          \n"
);

static int __init enc_test_module_init(void) {
    uint64_t addr;
    uint64_t fid, pa, ret0, ret1, ret2;
    struct arm_smccc_res smccc_res; 

    struct page * shared_page;
    uint64_t shared_phys;
    void * shared_virt;
    
    // allocate a kernel page (4KB)
    shared_page = alloc_page(GFP_KERNEL);
    BUG_ON(shared_page == NULL);

    shared_phys = page_to_phys(shared_page);
    shared_virt = kmap(shared_page);
    memcpy(shared_virt, &test_enclave, &test_enclave_end - &test_enclave);

    // ENC_ENTER
    uint64_t x0 = ENC_ENTER_TEST;
    uint64_t x1 = (uint64_t)virt_to_phys(&test_enclave);
    uint64_t x2 = (uint64_t)(&test_enclave_end - &test_enclave);
    uint64_t x3 = (uint64_t)(&test_enclave);
    printk(KERN_INFO "smc fid %llx\n", x0);
    printk(KERN_INFO "smc x1 %llx\n", x1);
    arm_smccc_smc(x0, x1, x2, x3, 0, 0, 0, 0, &smccc_res);
    
    // ENC_STATUS
    x0 = ENC_STATUS;
    printk(KERN_INFO "smc fid %llx\n", x0);
    arm_smccc_smc(x0, 0, 0, 0, 0, 0, 0, 0, &smccc_res);

    // current info
    uint64_t current_el;
    __asm__ __volatile__("mrs %[output], CurrentEL\n\t" : [output] "=r" (current_el) :  : "memory");
    printk(KERN_INFO "current_el: %llx\n", current_el);

    return 0;
}

static void __exit enc_test_module_exit(void)
{
    printk(KERN_ALERT "bye: exiting...\n");
}

module_init(enc_test_module_init);
module_exit(enc_test_module_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("enc test module.");