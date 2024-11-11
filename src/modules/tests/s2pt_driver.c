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

static int s2pt_driver_major;
static struct class *s2pt_driver_class = NULL;
static struct device *s2pt_driver_device = NULL;

#define get_bit_range_value(number, start, end) (((number) >> (end)) & ((1L << ((start) - (end) + 1)) - 1))

static inline uint64_t getCycle(void) {
    uint64_t tsc;
    asm volatile("mrs %0, pmccntr_el0"
                 : "=r"(tsc));
    return tsc;
}
static uint64_t cpu_start, cpu_end;
// ***** smc functions //
static uint64_t cpu_start_smc, cpu_end_smc_arg_prep, cpu_end_smc;

static int s2pt_open(struct inode *inode, struct file *filp) {
    return 0;
}

static int s2pt_release(struct inode *inode, struct file *filp) {
    return 0;
}

ssize_t s2pt_read(struct file *file, char __user *buf, size_t size, loff_t *ppos) {
    return 0;
}

int secure_pid;

static inline uint64_t smc_asm_4args(unsigned int fid, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)
{
    uint64_t _fid = fid;
    uint64_t _arg1 = arg1;
    uint64_t _arg2 = arg2;
    uint64_t _arg3 = arg3;
    uint64_t ret0;
    printk(KERN_INFO "[debug smc] fid: 0x%llx, arg1: 0x%llx, arg2: 0x%llx, arg3: 0x%llx.\n",
           _fid, _arg1, _arg2, _arg3);
    // cpu_start_smc = getCycle();
    /* prepare smc args & make smc */
    __asm__ volatile("mov x0, %[fid]\n"
                     "mov x1, %[arg1]\n"
                     "mov x2, %[arg2]\n"
                     "mov x3, %[arg3]\n"
                     "mov x4, %[arg4]\n"
                     "mov x5, #0\n"
                     "smc #0" ::[fid] "r"(_fid),
                     [arg1] "r"(_arg1), [arg2] "r"(_arg2), [arg3] "r"(_arg3), [arg4] "r"(arg4)
                     : "x0", "x1", "x2", "x3", "x4", "cc", "memory");
    /* return value: x0 */
    asm volatile("mov %0, x0"
                 : "=r"(ret0));
    // cpu_end_smc = getCycle();
    return ret0;
}


ssize_t s2pt_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    unsigned long virt_addr, phys_addr;
	uint64_t ttbr0_base, ttbr1_base;
	// uint64_t ttbr0_entry0, ttbr1_entry0;
	uint64_t _OA;
	struct cma *cma0, *cma1;
	struct page *page;
    unsigned long pg_count = arg;

    cmd = _IOC_NR(cmd);
    switch (cmd)
    {
    case 0:
        break;
    case 1:
        // asm volatile(
        //     "mov x1, #1\n"
        //     "ldr w0, =0xc7000001\n"
        //     "smc #0\n" ::
        //         : "x1", "w0");
        break;
    case 2: // mark secure ?
        // secure_pid = current->pid;
        break;
    case 4: // De-protect page table and setup TZASC after running GPU kernel.
        // asm volatile(
            // "mov x1, #4\n"
            // "ldr w0, =0xc7000001\n"
            // "smc #0\n" ::
            //     : "x1", "w0");
        break;
    case 10:
        // test cma memory allocate
        // cma0 = &cma_areas[0];
        // cma1 = &cma_areas[1];
        // // debug cma name
        // printk(KERN_INFO "cma_allocator0_name: %s\n", cma0->name);
        // printk(KERN_INFO "cma_allocator1_name: %s\n", cma1->name);
        // // debug: allocate 1 page content
        // page = cma_alloc(cma1, 1, 1 << PAGE_SHIFT, GFP_KERNEL);
        // // debug: check page physical address
        // if (!page)
        // {
        //     printk(KERN_ERR "cma_alloc failed.\n");
        //     return -1;
        // }
        // virt_addr = (uint64_t)page_to_virt(page);
        // phys_addr = (uint64_t)page_to_phys(page);
        // *(uint64_t *)virt_addr = 1000;
        // printk(KERN_INFO "debug cma memory: virt: 0x%lx -- phys: 0x%lx, content: 0x%llx\n", virt_addr, phys_addr, *(uint64_t *)virt_addr);
        // // debug: page table address
        // ttbr0_base = (uint64_t)phys_to_virt(ttbr0_base_address());
        // ttbr1_base = (uint64_t)phys_to_virt(ttbr1_base_address());
        // printk(KERN_INFO "TTBR0_el1 virt addr: 0x%llx\n", ttbr0_base);
        // printk(KERN_INFO "TTBR1_el1 virt addr: 0x%llx\n", ttbr1_base);
        
        // // debug: smc to vttbr
        // smc_asm_4args(0xc7000001, 10, phys_addr, 0, 0);
        
        // // debug: mmu translate
        // // _OA = read_ttbr_core(0xb0002000);
        // // printk(KERN_INFO "MMU translated IA: %lx -- OA: %llx\n", virt_addr, _OA);
        // // debug: page table entry content
        // // ttbr0_entry0 = *(uintptr_t *)ttbr0_base;
        // // ttbr1_entry0 = *(uintptr_t *)ttbr1_base;
        // // printk(KERN_INFO "TTBR0 entry0 content: 0x%llx\n", ttbr0_entry0);
        // // printk(KERN_INFO "TTBR1 entry0 content: 0x%llx\n", ttbr1_entry0);
        
        // /* release memory */
        // cma_release(cma1, page, 1);
        break;
    case 11:
        cma0 = &cma_areas[0];
        cma1 = &cma_areas[1];
        /* allocate  */
        page = cma_alloc(cma1, pg_count, 1 << PAGE_SHIFT, GFP_KERNEL);
        if (!page) {
            printk(KERN_ERR "cma_alloc failed.\n");
            return -1;
        }
        virt_addr = (uint64_t)page_to_virt(page);
        phys_addr = (uint64_t)page_to_phys(page);
        *(uint64_t *)virt_addr = 1000;
        printk(KERN_INFO "[S2PT_TEST][EL1] assigned buffer, size: 0x%lx (%luMB), addr: 0x%llx\n",
               pg_count * (1 << 12), pg_count * (1 << 12) / (MEM_SZ_1MB), phys_addr);
        /* smc to protect */
        cpu_start = getCycle();
        smc_asm_4args(0xc7000001, 11, phys_addr, pg_count, 0x0);
        cpu_end = getCycle();
        printk(KERN_INFO "[S2PT_TEST][EL1] Invoking SMC at cycle: %llu\n", cpu_start);
        printk(KERN_INFO "[S2PT_TEST][EL1] End-up SMC at cycle: %llu\n", cpu_end);
        // log smc cycles
        printk(KERN_INFO "<smc> whole smc cycle (return to el1): %llu (%llu - %llu).\n",
               cpu_end_smc - cpu_start_smc, cpu_end_smc, cpu_start_smc);
        /* FIXME debug: try to access again */
        // printk(KERN_INFO "prepare to access again.\n");
        // printk(KERN_INFO "access again: 0x%llx.\n", *(uint64_t *)virt_addr);
        
        /* smc back */
        smc_asm_4args(0xc7000001, 11, phys_addr, pg_count, 0x3);
        /* release memory */
        cma_release(cma1, page, pg_count);
        break;
    case 12:
        break;
    default:
        break;
    }
    return 0;
}

static struct file_operations s2pt_driver_fops = {
    .owner = THIS_MODULE,
    .open = s2pt_open,
    .release = s2pt_release,
    .read = s2pt_read,
    .unlocked_ioctl = s2pt_ioctl,
};

static int __init s2pt_driver_module_init(void)
{
    s2pt_driver_major = register_chrdev(0, DEVICE_NAME, &s2pt_driver_fops);
    if (s2pt_driver_major < 0)
    {
        printk("failed to register device.\n");
        return -1;
    }

    s2pt_driver_class = class_create(THIS_MODULE, "s2pt_driver");
    if (IS_ERR(s2pt_driver_class))
    {
        printk("failed to create s2pt moudle class.\n");
        unregister_chrdev(s2pt_driver_major, DEVICE_NAME);
        return -1;
    }

    s2pt_driver_device = device_create(s2pt_driver_class, NULL,
                                       MKDEV(s2pt_driver_major, 0), NULL, "s2pt_device");
    if (IS_ERR(s2pt_driver_device))
    {
        printk("failed to create device.\n");
        unregister_chrdev(s2pt_driver_major, DEVICE_NAME);
        return -1;
    }

    printk("s2pt driver initial successfully!\n");

    return 0;
}

static void __exit s2pt_driver_module_exit(void)
{
    printk("exit module.\n");
    device_destroy(s2pt_driver_class, MKDEV(s2pt_driver_major, 0));
    class_unregister(s2pt_driver_class);
    class_destroy(s2pt_driver_class);
    unregister_chrdev(s2pt_driver_major, DEVICE_NAME);
    printk("s2pt demo module exit.\n");
}

module_init(s2pt_driver_module_init);
module_exit(s2pt_driver_module_exit);

MODULE_LICENSE("GPL");
