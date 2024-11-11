/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TD_CMALIB_H__
#define __TD_CMALIB_H__

#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/cma.h>
#include <linux/string.h>

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
    // printk(KERN_INFO "total cma count: %u, %d.\n", cma_area_count, MAX_CMA_AREAS);
    for (i = 0; i < cma_area_count; i++) {
        // printk(KERN_INFO "targ_name: %s, searched_name: %s.\n", name, cma_areas[i].name);
        if (strcmp(name, cma_areas[i].name) == 0)
            return &cma_areas[i];
    }
    return NULL;
}

/* logger buffer pool allocator */
#define CMA_HKKR_BUF_POOL       "bufpool@84400000"
#define CMA_HKKR_RECVD_POOL     "mempool@b0000000"


/* helpers */
extern struct cma *cma_logger_pool;
extern struct cma *cma_hhkrd_pool;
#define AL_logger   ({  \
    if (!cma_logger_pool) \
        cma_logger_pool = cma_allocator_search(CMA_HKKR_BUF_POOL); \
    (struct cma*)cma_logger_pool;   \
})

/* hhkrd memory pool allocator */
#define AL_hhkrd   ({  \
    if (!cma_hhkrd_pool)   \
        cma_hhkrd_pool = cma_allocator_search(CMA_HKKR_RECVD_POOL); \
    (struct cma*)cma_hhkrd_pool;   \
})

#endif
