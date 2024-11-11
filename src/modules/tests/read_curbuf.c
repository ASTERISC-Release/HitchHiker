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

// basic content
typedef struct {
    /* The (kernel space) base virtual address */
    unsigned long virt_addr;
    /* The base physical address */
    unsigned long phys_addr;
    /* Current data position */
    unsigned long cur_pos;
    /* total size */
    unsigned long length;
} log_buf_t;

extern log_buf_t *get_current_log_buf(void);

static int __init test_init(void) {
    log_buf_t *buf = get_current_log_buf();
    char temp[50] ={0};
    memcpy(temp, (void *)buf->virt_addr, 49);
    printk(KERN_INFO "cur_buf_content: %s\n", temp);
    return 0;
}


static void __exit test_exit(void) {
}

module_init(test_init);
module_exit(test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chuqi zhang");
MODULE_DESCRIPTION("print curbuf");