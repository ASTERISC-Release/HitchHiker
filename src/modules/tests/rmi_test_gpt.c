#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/init.h>

#include <test_defs.h>


static int __init rmi_test_gpt_module_init(void) {
    uint64_t func_id;   // function id for SMC (w0)
    uint64_t ret0, ret1, ret2, ret3; // return values (x1 - x3)
    /* allocate a PA memory */
    uintptr_t *_va;
    _va = kmalloc(sizeof(uintptr_t), GFP_KERNEL);
    *_va = 1024;
    phys_addr_t _pa;
    _pa = virt_to_phys(_va);
    pr_info("1. Assigned NS memory region: va: %llx <==> pa: %lx\n", _va, _pa);
    /* access the memory */
    int64_t cont = *_va; 
    pr_info("2. Access NS memory region: [va: %llx, value: %lld]\n", _va, cont);
    /* smc[rmi]: NS -> REALM */
    // func_id = GEN_RMI_FUNCID(SMC_64, RMI_FNUM_GRAN_NS_REALM);
    // test another func_id
    func_id = GTSI_FID(SMC_64, GRAN_TRANS_TO_REALM_FNUM);
    pr_info("3. SMC[rmi] (fid: %llx) to change GPT permission (NS -> Realm).\n", func_id);
    __asm __volatile("mov x0, %[fid]" :: [fid] "r" (func_id));  // fid
    __asm __volatile("mov x1, %[arg1]" :: [arg1] "r" (_pa));    // args
    __asm __volatile("mov x2, #0");
    __asm __volatile("mov x3, #0");
    __asm __volatile("mov x4, #0");
    __asm __volatile("mov x5, #0");
    __asm __volatile("smc #0"); // smc
    /* return value: x0 (error code) */
    __asm __volatile("mov %[ret0], x0" : [ret0] "=r" (ret0)); // return values
    __asm __volatile("mov %[ret1], x1" : [ret1] "=r" (ret1));
    __asm __volatile("mov %[ret2], x2" : [ret2] "=r" (ret2));
    __asm __volatile("mov %[ret3], x3" : [ret3] "=r" (ret3));
    pr_info("SMC[rmi] return values: 0x%llx, 0x%llx, 0x%llx, 0x%llx\n", ret0, ret1, ret2, ret3);
    // pr_info("4. Access the memory [va: %lx] from NS world again (will crash).\n", _va);
    // cont = *_va;
    // // free 
    /* smc[rmi]: REALM -> NS */
    // func_id = GEN_RMI_FUNCID(SMC_64, RMI_FNUM_GRAN_REALM_NS);
    // test another func_id
    func_id = GTSI_FID(SMC_64, GRAN_TRANS_TO_NS_FNUM);
    pr_info("4. SMC[rmi] (fid: %llx) to change GPT permission (Realm -> NS).\n", func_id);
    __asm __volatile("mov x0, %[fid]" :: [fid] "r" (func_id));  // fid
    __asm __volatile("mov x1, %[arg1]" :: [arg1] "r" (_pa));    // args
    __asm __volatile("mov x2, #0");
    __asm __volatile("mov x3, #0");
    __asm __volatile("mov x4, #0");
    __asm __volatile("mov x5, #0");
    __asm __volatile("smc #0"); // smc
    pr_info("5. free the memory.\n");
    kfree(_va);
    return 0;
}

static void __exit rmi_test_gpt_module_exit(void) {
    pr_info("exiting rmi_test_gpt...\n");
}

module_init(rmi_test_gpt_module_init);
module_exit(rmi_test_gpt_module_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("rmi test gpt permission change.");
MODULE_AUTHOR("chuqiz");