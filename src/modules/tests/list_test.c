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


// basic content

struct cell {
    int cell_id;
};

// list for list_cell
struct cell_pool {
    struct cell *cell;
    struct list_head list;
};

// manager for cell pool
struct cell_pool_manager {
    struct list_head head;
    struct mutex lock;
};

// manager instance
static struct cell_pool_manager *manager;

static void queue_creat(struct list_head *list) {
    INIT_LIST_HEAD(list);
}

static void queue_in(struct list_head *list, struct cell *cell) {
    struct cell_pool *pool = kzalloc(sizeof(struct cell_pool), GFP_KERNEL);
    if (!pool) {
        printk(KERN_ERR "Allocate pool failed.\n");
        return;
    }
    pool->cell = cell;
    list_add_tail(&pool->list, list);
}

static struct cell *queue_out(struct list_head *list) {
    struct cell_pool *pool;
    struct cell *cell;
    if (list_empty(list)) {
        printk(KERN_ERR "List is empty.\n");
        return NULL;
    }
    pool = list_first_entry(list, struct cell_pool, list);
    cell = pool->cell;
    list_del(&pool->list);
    kfree(pool);
    return cell;
}

static int queue_size(struct list_head *list) {
    struct cell_pool *pool;
    int size = 0;
    list_for_each_entry(pool, list, list) {
        size++;
    }
    return size;
}

static int __init list_test_init(void) {
    // init the manager
    manager = kzalloc(sizeof(struct cell_pool_manager), GFP_KERNEL);
    if (!manager) {
        printk(KERN_ERR "Allocate manager failed.\n");
        return -1;
    }
    
    /* Lock: initialize */
    mutex_init(&manager->lock);

    // init queue from manager head
    queue_creat(&manager->head);
    // add a cell to the queue
    struct cell *cell1 = kzalloc(sizeof(struct cell), GFP_KERNEL);
    struct cell *cell2 = kzalloc(sizeof(struct cell), GFP_KERNEL);
    if (!cell1) {
        printk(KERN_ERR "Allocate cell failed.\n");
        return -1;
    }
    cell1->cell_id = 1;
    cell2->cell_id = 2;
    queue_in(&manager->head, cell1);
    queue_in(&manager->head, cell2);

    // print queue length of manager head
    printk(KERN_INFO "Queue length: %d\n", queue_size(&manager->head));
    
    // pop the first elem
    struct cell *cell = queue_out(&manager->head);
    printk(KERN_INFO "Pop cell: %d\n", cell->cell_id);
    // pop
    cell = queue_out(&manager->head);
    printk(KERN_INFO "Pop cell: %d\n", cell->cell_id);
    // check length again
    printk(KERN_INFO "Queue length: %d\n", queue_size(&manager->head));
    // pop
    cell = queue_out(&manager->head);
    if (cell) {
        printk(KERN_INFO "Pop cell: %d\n", cell->cell_id);
    } else {
        printk(KERN_INFO "Pop cell: NULL\n");
    }
    
    return 0;
}


static void __exit list_test_exit(void) {
    printk(KERN_INFO "Exiting list_test module.\n");

    /* free all content */
    while (!list_empty(&manager->head)) {
        struct cell *cell = queue_out(&manager->head);
        kfree(cell);
    }
    /* free memory */
    kfree(manager);
    manager = NULL;
}

module_init(list_test_init);
module_exit(list_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chuqi zhang");
MODULE_DESCRIPTION("queue test");