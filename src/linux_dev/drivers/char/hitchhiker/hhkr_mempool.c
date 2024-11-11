#include <linux/syscalls.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/hitchhiker.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <uapi/linux/types.h>

#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/arm-smccc.h>

#include "cmalib.h"
#include "commonlib.h"
#include "hhkr_mempool.h"
#include "ahci_include.h"


#define pr_fmt(fmt) "hhkr_mempool: " fmt


/** ==========================================================================================================
 *  Variables for evaluation
 *  ========================================================================================================== */
int policy_cdf_mode = 0;
int omnilog_mode = 0;

/** ==========================================================================================================
 *  Hashtable interface to index the log buffers
 *  ========================================================================================================== */
struct hlist_head hhkr_bufs_table[];
DEFINE_HASHTABLE(hhkr_bufs_table, 8);

typedef struct hhkr_hash_entry {
    unsigned long phys_addr;  // use it's physical address as the key
    hhkr_buf_t *buf;
    struct hlist_node hlist;
} hhkr_hash_entry_t;

static hhkr_buf_t *__hhkr_search_buf(unsigned long phys_addr) {
    hhkr_hash_entry_t *entry;
    hash_for_each_possible(hhkr_bufs_table, entry, hlist, phys_addr) {
        if (entry->phys_addr == phys_addr) {
            return entry->buf;
        }
    }
    return NULL;
}

void debug_print_hashtable(void) {
    hhkr_hash_entry_t *entry;
    int bkt = 0;
    hash_for_each(hhkr_bufs_table, bkt, entry, hlist) {
        log_info("hashtable content. buf phys_addr (key): 0x%lx, buf metadata pointer: 0x%lx, type: %d, length: 0x%lx.\n",
                 entry->phys_addr, (unsigned long)entry->buf, entry->buf->obs_type, entry->buf->length);
    }
}

/** ==========================================================================================================
 * APIs for buffer pool management 
 *  ========================================================================================================== */

/* APIs to support a logger_mem buffer pool (queue) */
struct cma *cma_logger_pool = NULL;
EXPORT_SYMBOL(cma_logger_pool);

static hhkr_queue_mngr_t *hhkr_queue_mngr[__HHKR_OBS_MAX_ID];
static hhkr_buf_t *hhkr_current_buf[__HHKR_OBS_MAX_ID];

struct kmem_cache *bufqueue_entry_cache = NULL;
/*
 * `hhkr_buf_lock` is used to protect the read/write to the buffer pool (queue) from concurrent.
 *  Unlike the `lock` in `hhkr_queue_mngr`, which is used to protect the dequeue/enqueue to the buffer pool.
 */ 
static spinlock_t *hhkr_buf_lock[__HHKR_OBS_MAX_ID];


static inline hhkr_buf_t *__hhkr_buf_alloc(unsigned long length) {
    hhkr_buf_t *buf = NULL;
    struct page *page;
    unsigned int pg_align;
    hhkr_hash_entry_t *entry;
    pg_align = get_order(length);

    page = cma_alloc(AL_logger, (length >> PAGE_SHIFT), pg_align, GFP_KERNEL);
    if (page) {
        buf = kzalloc(sizeof(hhkr_buf_t), GFP_KERNEL);
        if (buf) {
            buf->phys_addr = (dma_addr_t)page_to_phys(page);
            buf->virt_addr = (dma_addr_t)page_to_virt(page);
            buf->length = length;
            buf->cur_pos = 0;
            memset((void *)buf->virt_addr, 0, buf->length);
            /* insert into the hash table */
            entry = kzalloc(sizeof(hhkr_hash_entry_t), GFP_KERNEL);
            if (entry) {
                entry->phys_addr = buf->phys_addr;
                entry->buf = buf;
                hash_add(hhkr_bufs_table, &entry->hlist, entry->phys_addr);
            }
        }
    }
    return buf;
}


/** @brief Register an observability type
 *  @param type: the type of the observability
 *  @param length: the length of the buffer
 *  @param num: the number of buffers in its buffer pool
 */
int hhkr_register_observability(enum hhkr_obs_type type, unsigned long length, unsigned long num) {
    int ret = 0;
    unsigned long buf_length = length;
    unsigned long buf_num = num;
#if DEBUGLABEL
    int buf_alloced = 0;
#endif
    /* initialize buf pool (queue) manager */
    hhkr_queue_mngr[type] = kzalloc(sizeof(hhkr_queue_mngr_t), GFP_KERNEL);
    if (!hhkr_queue_mngr[type]) {
        log_err("Failed to allocate memory for hhkr_queue_mngr[%d].\n", type);
        ret = -ENOMEM;
        goto out;
    }
    spin_lock_init(&hhkr_queue_mngr[type]->lock);

    /* initialize buf pool (queue)*/
    INIT_LIST_HEAD(&hhkr_queue_mngr[type]->pool_head);

    /* initialize buf lock */
    hhkr_buf_lock[type] = (spinlock_t *)kzalloc(sizeof(spinlock_t), GFP_KERNEL);
    if (!hhkr_buf_lock[type]) {
        log_err("Failed to allocate memory for hhkr_buf_lock[%d].\n", type);
        ret = -ENOMEM;
        goto out;
    }
    spin_lock_init(hhkr_buf_lock[type]);

    /* initialize buffers */
    while (buf_num--) {
        hhkr_buf_t *buf = __hhkr_buf_alloc(buf_length);
        if (buf) {
            buf->obs_type = type;
            __hhkr_enqueue_bufpool(type, buf);
#if DEBUGLABEL
            buf_alloced++;
#endif
        }
    }
#if DEBUGLABEL
    log_info("Registered: type=%d, buf_length=0x%lx, buf_num=%lu, successful buf_alloced=%d.\n", type, length, num, buf_alloced);
#endif
out:
    return ret;
}


/** @brief Given an observability type (e.g., HHKR_OBS_app_log),
 *         return it's current buffer for writing.
 * 
 * This function is useful for hardware-tracing to configure the 
 * physical address of the buffer.
 */
hhkr_buf_t *hhkr_get_current_buf(enum hhkr_obs_type type) {
    /* 
     * The pool of buffers can be consumed by the hhkrd receiver thread.
     * In this case, we should wait until a free buffer.
     */
    while (!hhkr_current_buf[type]) {
        hhkr_current_buf[type] = __hhkr_dequeue_bufpool(type);
        if (!hhkr_current_buf[type]) {
#if DEBUGLABEL
            /* debug: just return NULL */
            log_info("hhkr_current_buf[%d] is NULL... Just wait...\n", type);
            // return NULL;
#else
            /* 
             * Just busy waiting inside the current atomic and 
             * non-preemptible observability generation environment.
             *
             * We should not allow to yield the scheduler in the 
             * current context.
             */
            // log_info("hhkr_current_buf[%d] is NULL... Just wait another round...\n", type);
#endif
            // if (current->is_hhkrd && hhkrd_free_wl->num) {
            //     /* interrupt triggered inside the hhkrd receiver context,
            //      * in this case, we must freeback buffers. elsewise, hhkrd
            //      * won't be able to return from the kernel.                
            //      */
            //     __hhkr_free_back_bufs();
            // }
        }
    }
    return hhkr_current_buf[type];
}
EXPORT_SYMBOL(hhkr_get_current_buf);


/** @brief write data to the current buf of the given observability type.
 */
unsigned long hhkr_write_current_buf(enum hhkr_obs_type type, const char *data, unsigned long len) {
    hhkr_buf_t *buf;
    unsigned long ret = 0;
    spin_lock_irq(hhkr_buf_lock[type]);
    buf = hhkr_get_current_buf(type);
    
    // if (unlikely(!hhkr_policy_has_activated && (*activate_flag > 0))) {
    //     /* activate secure policy here! */
    //     hhkr_activate_interval_secure_policy();
    // }

    if (buf) {
        /* multiple log sources can write to the current buf. 
         * we need to protect the current position.
         */
        if (buf->cur_pos + len > buf->length) {
            /* 
             * The current buf is full. We should not allow this happens
             * to avoid extra synchronous overhead. 
             */
            panic("Hitchhiker buffer is too small (buf: 0x%lx, cur: 0x%lx + len: 0x%lx > length: 0x%lx)...\n",
                   buf->phys_addr, buf->cur_pos, len, buf->length);
        } else {
            memcpy((void *)(buf->virt_addr + buf->cur_pos), data, len);
            buf->cur_pos += len;
#if DEBUGLABEL
            log_info("After write buf: 0x%lx. type=%d, buf->cur_pos=0x%lx, len=0x%lx.\n", 
                      buf->phys_addr, type, buf->cur_pos, len);
#endif
            ret = len;
        }
    }
    spin_unlock_irq(hhkr_buf_lock[type]);
    return ret;
}
EXPORT_SYMBOL(hhkr_write_current_buf);


/** @brief secure the current buf of the given observability type.
 */

unsigned long hhkr_secure_current_buf(enum hhkr_obs_type type, int use_memcpy) {
    hhkr_buf_t *buf;
    unsigned long ret = 0;
    spin_lock_irq(hhkr_buf_lock[type]);
    buf = hhkr_get_current_buf(type);
    /* only do secure_buf when the buf certains payloads */
    if (buf && buf->cur_pos) {
        /* --- start code here --- */
        /* secure the buffer */
        if (use_memcpy == 1)
            hitchhiker_smc(HHKR_SECURE_BUF, buf->phys_addr, max((unsigned long)(SZ_16K + SZ_8K), (unsigned long)buf->cur_pos),
                        1, 0, 0, 0, 0);
        else if (use_memcpy == 2)
            hitchhiker_smc(HHKR_SECURE_BUF, buf->phys_addr, max((unsigned long)SZ_16K, (unsigned long)buf->cur_pos),
                        1, 0, 0, 0, 0);
        else
            hitchhiker_smc(HHKR_SECURE_BUF, buf->phys_addr, buf->length,
                        0, 0, 0, 0, 0);
        /* update the secure time to count CDF */
        if (policy_cdf_mode)
            buf->ts_secure = ktime_get_mono_fast_ns();

        /* notify the hhkrd by sending message */
        hhkr_send_message(buf);
        /* --- end code here   --- */
#if DEBUGLABEL
        log_info("secured type: %d, buf (phys) 0x%lx, buf pos: 0x%lx.\n", type, buf->phys_addr, buf->cur_pos);
#endif
        /* reset current buf as the next? */
        // buf->cur_pos = 0;
        hhkr_current_buf[type] = NULL;

        ret =  buf->user_addr;
    }
#if DEBUGLABEL
        log_info("secured type: %d, buf (phys) 0x%lx, buf pos: 0x%lx. (didn't secure...)\n", type, buf->phys_addr, buf->cur_pos);
#endif
    spin_unlock_irq(hhkr_buf_lock[type]);
    return ret;
}

void __hhkr_enqueue_bufpool(enum hhkr_obs_type type, hhkr_buf_t *buf) {
    hhkr_buf_queue_t *entry;
    if (buf) {
        spin_lock_irq(&hhkr_queue_mngr[type]->lock);
        /* don't use kzalloc inside non-preemptible context */
        // entry = kzalloc(sizeof(hhkr_buf_queue_t), GFP_KERNEL);
        entry = kmem_cache_alloc(bufqueue_entry_cache, GFP_ATOMIC);
        if (entry) {
            buf->cur_pos = 0;     /* reset buf */
            entry->buf = buf;
            list_add_tail(&entry->list, &hhkr_queue_mngr[type]->pool_head);
        }
        spin_unlock_irq(&hhkr_queue_mngr[type]->lock);
    }
}

hhkr_buf_t *__hhkr_dequeue_bufpool(enum hhkr_obs_type type) {
    hhkr_buf_t *buf = NULL;
    hhkr_buf_queue_t *entry;
    spin_lock_irq(&hhkr_queue_mngr[type]->lock);
    if (!list_empty(&hhkr_queue_mngr[type]->pool_head)) {
        entry = list_first_entry(&hhkr_queue_mngr[type]->pool_head, hhkr_buf_queue_t, list);
        if (entry) {
            buf = entry->buf;
            list_del(&entry->list);
            /* don't use kfree inside non-preemptible context */
            // kfree(entry);
            kmem_cache_free(bufqueue_entry_cache, entry);
        }
    }
    spin_unlock_irq(&hhkr_queue_mngr[type]->lock);
    return buf;
}

hhkr_buf_t *__hhkr_get_unmmapped_buf(enum hhkr_obs_type type) {
    hhkr_buf_t *buf = NULL;
    hhkr_buf_queue_t *entry = NULL;
    spin_lock(&hhkr_queue_mngr[type]->lock);
    /* iterate the buf pool */
    if (!list_empty(&hhkr_queue_mngr[type]->pool_head)) {
        list_for_each_entry(entry, &hhkr_queue_mngr[type]->pool_head, list) {
            /* find a hhkrd user-unmapped buffer */
            if (!entry->buf->user_addr) {
                buf = entry->buf;
                break;
            }
        }
    }
    spin_unlock(&hhkr_queue_mngr[type]->lock);
    return buf;
}

void __hhkr_mmap_buf_all(enum hhkr_obs_type type) {
    hhkr_buf_t *buf;
    int fd = current->hhkr_ctl_fd;
    if (!current->is_hhkrd) {
        // chuqi: only for debugging
        // log_err("Only hhkrd can mmap the buffers.\n");
        // return;
        fd = 3;
    }
    while ((buf = __hhkr_get_unmmapped_buf(type)) != NULL) {
        /* do_mmap */ 
        buf->user_addr = ksys_mmap_pgoff(0, buf->length, PROT_READ | PROT_WRITE, MAP_SHARED, 
                                         fd, (buf->phys_addr) >> PAGE_SHIFT);
#if DEBUGLABEL
        log_info("Observability type: %d, mmap buf phys: 0x%lx <-> user: 0x%lx.\n", 
                 type, (unsigned long)buf->phys_addr, (unsigned long)buf->user_addr);
#endif
    }
}

void __hhkr_deregister_observability(enum hhkr_obs_type type) {
    hhkr_buf_t *buf;
    if (hhkr_queue_mngr[type]) {
        spin_lock(&hhkr_queue_mngr[type]->lock);
        while ((buf = __hhkr_dequeue_bufpool(type)) != NULL) {
            cma_release(AL_logger, phys_to_page(buf->phys_addr), buf->length >> PAGE_SHIFT);
            kfree(buf);
        }
        spin_unlock(&hhkr_queue_mngr[type]->lock);
        kfree(hhkr_queue_mngr[type]);
        hhkr_queue_mngr[type] = NULL;
    }
}

/** ==========================================================================================================
 * APIs for kernel-user space daemon (hhkrd) communication (a lock-free queue, and an extra shared memory) 
 * ========================================================================================================== */

// @deprecated: this buf_meta_msg is deprecated.
// chuqi: not used anymore. use the lock-free queue below.
hhkr_buf_t *buf_meta_msg;

void __hhkr_buf_meta_msg_init(void) {
    struct page *page;
    unsigned int pg_align;
    /* assign 1 * 4K pages */
    int length = PAGE_SIZE;
    pg_align = get_order(length);

    page = cma_alloc(AL_logger, (length >> PAGE_SHIFT), pg_align, GFP_KERNEL);
    if (!page) {
        log_err("Failed to allocate memory for the buf metadata message.\n");
        return;
    }
    buf_meta_msg = (hhkr_buf_t *)page_to_virt(page);
#if DEBUGLABEL
    log_info("Buffer metadata message init at phys: 0x%llx, virt: 0x%lx, size: 0x%lx.\n", 
             virt_to_phys((void*)buf_meta_msg), (unsigned long)buf_meta_msg, sizeof(hhkr_buf_t));
#endif
    return;
}

unsigned long __hhkr_mmap_buf_meta_msg(void) {
    unsigned long ret;
    int fd = current->hhkr_ctl_fd;
    if (!current->is_hhkrd) {
        // log_err("Only hhkrd can mmap the buf metadata message.\n");
        // return 0;
        fd = 3;
    }

    ret = ksys_mmap_pgoff(0, sizeof(hhkr_buf_t), PROT_READ | PROT_WRITE, MAP_SHARED, 
                          fd, virt_to_phys((void*)buf_meta_msg) >> PAGE_SHIFT);
#if DEBUGLABEL
    log_info("mmap: buf_meta_msg size: %ld, phys: 0x%llx, virt: 0x%lx <-> user 0x%lx.\n", sizeof(hhkr_buf_t), 
             virt_to_phys((void*)buf_meta_msg), (unsigned long)buf_meta_msg, ret);
#endif
    return ret;
}

// Chuqi: use this lock-free queue instead of the metadata msg.
hhkr_msg_queue_t *hhkr_msg_queue = NULL;

void hhkr_send_message(hhkr_buf_t *msg) {
    int tail = atomic_read(&hhkr_msg_queue->tail);
    int next_tail = (tail + 1) % HHKR_MSG_QUEUE_SIZE;

    if (next_tail != atomic_read(&hhkr_msg_queue->head)) {
        /* setup message */
        hhkr_msg_queue->messages[tail].obs_type = msg->obs_type;
        hhkr_msg_queue->messages[tail].phys_addr = msg->phys_addr;
        hhkr_msg_queue->messages[tail].virt_addr = msg->virt_addr;
        hhkr_msg_queue->messages[tail].user_addr = msg->user_addr;
        hhkr_msg_queue->messages[tail].cur_pos = msg->cur_pos;
        hhkr_msg_queue->messages[tail].length = msg->length;
        hhkr_msg_queue->messages[tail].ts_secure = msg->ts_secure;
        /* update tail */
        atomic_set(&hhkr_msg_queue->tail, next_tail);
    }
}

int __hhkr_msg_queue_init(void) {
    struct page *page;
    unsigned int pg_align;
    /* assign 32 * 4K pages */
    int length = 0x1000 * 32;
    pg_align = get_order(length);

    page = cma_alloc(AL_logger, (length >> PAGE_SHIFT), pg_align, GFP_KERNEL);
    if (!page) {
        log_err("Failed to allocate memory for the message queue.\n");
        return -1;
    }
    hhkr_msg_queue = (hhkr_msg_queue_t*)page_to_virt(page);
    atomic_set(&hhkr_msg_queue->head, 0);
    atomic_set(&hhkr_msg_queue->tail, 0);
#if DEBUGLABEL
    log_info("Message queue init at phys: 0x%llx, virt: 0x%lx, size: 0x%lx.\n", 
             virt_to_phys((void*)hhkr_msg_queue), (unsigned long)hhkr_msg_queue, sizeof(hhkr_msg_queue_t));
#endif
    return 0;
}

unsigned long __hhkr_mmap_msg_queue(void) {
    int fd = current->hhkr_ctl_fd;
    if (!current->is_hhkrd) {
        log_err("Only hhkrd can mmap the message queue.\n");
        return 0;
    }
    
    log_info("mmap: size: %ld, phys: 0x%llx, virt: 0x%lx.\n", sizeof(hhkr_msg_queue_t), 
             virt_to_phys((void*)hhkr_msg_queue), (unsigned long)hhkr_msg_queue);
    return ksys_mmap_pgoff(0, sizeof(hhkr_msg_queue_t), PROT_READ | PROT_WRITE, MAP_SHARED, 
                           fd, virt_to_phys((void*)hhkr_msg_queue) >> PAGE_SHIFT);
}

/** ==========================================================================================================
 * APIs for the hitchhiker daemon (hhkrd)'s freeback buffer waitlist 
 * ========================================================================================================== */

hhkrd_free_wl_t *hhkrd_free_wl = NULL;
unsigned long hhkrd_free_wl_phys = 0;

int __hhkrd_free_wl_init(void) {
    /* Allocate 1 * 4K */
    struct page *page;
    unsigned int pg_align;
    /* assign 1 * 4K page is enough */
    int length = PAGE_SIZE;
    pg_align = get_order(length);

    page = cma_alloc(AL_logger, (length >> PAGE_SHIFT), pg_align, GFP_KERNEL);
    if (!page) {
        log_err("Failed to allocate memory for the freeback buffer waitlist.\n");
        return -1;
    }
    hhkrd_free_wl = (hhkrd_free_wl_t*)page_to_virt(page);
    memset(hhkrd_free_wl, 0, sizeof(hhkrd_free_wl_t));
    hhkrd_free_wl_phys = virt_to_phys((void*)hhkrd_free_wl);
#if DEBUGLABEL
    log_info("Freeback buffer waitlist init at phys: 0x%llx, virt: 0x%lx, size: 0x%lx.\n", 
             virt_to_phys((void*)hhkrd_free_wl), (unsigned long)hhkrd_free_wl, sizeof(hhkrd_free_wl_t));
#endif
    return 0;
}

unsigned long __hhkrd_mmap_free_wl(void) {
    int fd = current->hhkr_ctl_fd;
    if (!current->is_hhkrd) {
        log_err("Only hhkrd can mmap the freeback buffer waitlist.\n");
        return 0;
    }
    return ksys_mmap_pgoff(0, sizeof(hhkrd_free_wl_t), PROT_READ | PROT_WRITE, MAP_SHARED, 
                           fd, hhkrd_free_wl_phys >> PAGE_SHIFT);
}

int __hhkr_free_back_bufs(void) {
    int i, ret;
    if (!hhkrd_free_wl) {
        log_err("Freeback buffer waitlist is not initialized.\n");
        return -1;
    }
#if DEBUGLABEL
    log_info("Num of bufs in freelist %u, current pid: %d.\n", hhkrd_free_wl->num, current->pid);
#endif
    /* smc */
    ret = hitchhiker_smc(HHKRD_FREEBACK_BUFS, hhkrd_free_wl_phys, 0, 0, 0, 0, 0, 0);
    /* add back to the bufpool */
    for (i = 0; i < hhkrd_free_wl->num; i++) {
        /* search buf from hashtable */
        hhkr_buf_t *buf = __hhkr_search_buf(hhkrd_free_wl->buf_addrs[i]);
        if (buf) {
            __hhkr_enqueue_bufpool(buf->obs_type, buf);
        } else {
            log_err("Failed to find buf: 0x%lx in hashtable.\n", hhkrd_free_wl->buf_addrs[i]);
        }
    }
    /* reset freeback wl */
    hhkrd_free_wl->num = 0;
    return ret;
}

/** ==========================================================================================================
 * APIs for the secure I/O's scatterlist and buffer allocate
 * ========================================================================================================== */

/* format: 
 * int: ()
 * u64: sil24 [paddr] (DMA) address
 * u64: sil24 [activate] (MMIO) mmaped userspace address
 * u64: sil24 [activate] (MMIO) kernel physical address
 */
int *hhkr_secIO_pending_job = NULL;
EXPORT_SYMBOL(hhkr_secIO_pending_job);

static int hhkr_secIO_pending_job_init(void) {
    struct page *page;
    unsigned int pg_align;
    /* assign 1 * 4K page is enough */
    int length = PAGE_SIZE;
    pg_align = get_order(length);

    page = cma_alloc(AL_logger, (length >> PAGE_SHIFT), pg_align, GFP_KERNEL);
    if (!page) {
        log_err("Failed to allocate memory for the hhkr_secIO_pending_job.\n");
        return -1;
    }
    hhkr_secIO_pending_job = (int *)page_to_virt(page);
    memset(hhkr_secIO_pending_job, 0, length);
#if DEBUGLABEL
    log_info("hhkr_secIO_pending_job init at phys: 0x%llx, virt: 0x%lx, size: 0x%lx.\n", 
             virt_to_phys((void*)hhkr_secIO_pending_job), (unsigned long)hhkr_secIO_pending_job, length);
#endif
    return 0;
}

/* should be done after secIO_init */
unsigned long __hhkrd_mmap_secIO_pending_job(void) {
    unsigned long activate_phys, activate_user, _off, *activate_virt, *activate_phys_loc;
    int fd = current->hhkr_ctl_fd;
    if (!current->is_hhkrd) {
        log_err("Only hhkrd can mmap the secIO pending job.\n");
        return 0;
    }
    /* first of all, check the activate is set correctly */
    if (!hhkr_secIO_pending_job) {
        log_err("hhkr_secIO_pending_job is not initialized.\n");
        return 0;
    }
    activate_virt = (unsigned long*)((void *)hhkr_secIO_pending_job + sizeof(int) + sizeof(unsigned long));
    if (!*activate_virt) {
        log_err("hhkr_secIO_pending_job activate MMIO is not set correctly.\n");
        return 0;
    }
    /* mmap this whole page */
    activate_phys = (unsigned long)virt_to_phys((void*)*activate_virt);
    _off = activate_phys & (0x0fff);
    activate_user = ksys_mmap_pgoff(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, 
                                                  fd, activate_phys >> PAGE_SHIFT);
    log_info("activate MMIO (kern: 0x%lx -- phys: 0x%lx -- user: 0x%lx.)\n", 
                *activate_virt, activate_phys, activate_user);
    /* reset */
    *activate_virt = activate_user + _off;
    /* setup phys addr */
    activate_phys_loc = activate_virt + 1;
    *activate_phys_loc = activate_phys;
    return ksys_mmap_pgoff(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, 
                           fd, virt_to_phys(hhkr_secIO_pending_job) >> PAGE_SHIFT);
}

/**
 * Hitchhiker Secure I/O record-and-replay status support (mainly for tracing and recording)
*/
// debug record MMIO messages
static bool debug_record_sata = 0;
EXPORT_SYMBOL(debug_record_sata);

// debug replay
static bool debug_replay_sata = 0;
EXPORT_SYMBOL(debug_replay_sata);

bool fetch_debug_record_sata(void) {
    return debug_record_sata;
}
EXPORT_SYMBOL(fetch_debug_record_sata);

void set_debug_record_sata(bool val) {
    debug_record_sata = val;
}
EXPORT_SYMBOL(set_debug_record_sata);

bool fetch_debug_replay_sata(void) {
    return debug_replay_sata;
}
EXPORT_SYMBOL(fetch_debug_replay_sata);

void set_debug_replay_sata(bool val) {
    debug_replay_sata = val;
}
EXPORT_SYMBOL(set_debug_replay_sata);

/* for each system observability type, maintains two scatterlist_pgs */
static hhkr_scatterlist_pgs_t *hhkr_obs_sg_pgs[__HHKR_OBS_MAX_ID][2];
EXPORT_SYMBOL(hhkr_obs_sg_pgs);

static int __hhkr_sg_pgs_alloc(struct device *dev, int obs_type, unsigned int buf_size) {
    struct page *page;
    unsigned int pg_align;
    hhkr_scatterlist_pgs_t *sg_pgs;
    void *buf_start;
    /* assign 4KB + buf_size */
    int length = buf_size + PAGE_SIZE, i;
    pg_align = get_order(length);

    for (i = 0; i < 2; i++) {
        page = cma_alloc(AL_logger, (length >> PAGE_SHIFT), pg_align, GFP_KERNEL);
        if (!page) {
            log_err("Failed to allocate memory for the secure I/O's scatterlist pgs.\n");
            return -1;
        }
        sg_pgs = (hhkr_scatterlist_pgs_t*)page_to_virt(page);
        sg_pgs->pgs_kern_addr = (unsigned long)sg_pgs;
        sg_pgs->pgs_phys_addr = (unsigned long)virt_to_phys((void*)sg_pgs);
        sg_pgs->pgs_user_addr = 0;     // unmapped yet.
        sg_pgs->cur_pos = 0;
        sg_pgs->buf_size = buf_size;

        /* configure it's scatterlist */
        buf_start = (void *)sg_pgs + PAGE_SIZE;
        sg_pgs->sg.page_link = (unsigned long)virt_to_page(buf_start) | SG_END;
        sg_pgs->sg.offset = 0;
        sg_pgs->sg.length = buf_size;
        /* map to dma TODO() juno */
// #ifndef ENV_JUNO
        log_info("dma-mapping sg for obs_type: %d, idx: %d.\n", obs_type, i);
        dma_map_sg(dev, &sg_pgs->sg, 1, DMA_TO_DEVICE);
// #endif
        hhkr_obs_sg_pgs[obs_type][i] = sg_pgs;
#if DEBUGLABEL
        log_info("Secure I/O scatterlist pgs hhkr_obs_sg_pgs[%d][%d] init at phys: 0x%llx, virt: 0x%lx (scatterlist pagelink: 0x%lx, length: 0x%x), size: 0x%x.\n", 
                 obs_type, i, virt_to_phys((void*)sg_pgs), (unsigned long)sg_pgs, sg_pgs->sg.page_link, sg_pgs->sg.length, length);
#endif
    }
    return 0;
}
EXPORT_SYMBOL(__hhkr_sg_pgs_alloc);   // export for debug now

unsigned long __hhkr_sg_pg_mmap(int obs_type) {
    unsigned long user_addr, mmap_len;
    hhkr_scatterlist_pgs_t *hhkr_sg_pg;
    int fd = current->hhkr_ctl_fd;
    if (!current->is_hhkrd) {
        log_err("Only hhkrd can mmap the message queue.\n");
        return 0;
    }
    if (obs_type >= __HHKR_OBS_MAX_ID) {
        log_err("Invalid obs_type: %d.\n", obs_type);
        return 0;
    }
    if (!hhkr_obs_sg_pgs[obs_type][0] || !hhkr_obs_sg_pgs[obs_type][1]) {
        log_err("Secure I/O scatterlist pgs for obs_type %d not allocated yet.\n", obs_type);
        return 0;
    }

    hhkr_sg_pg = hhkr_obs_sg_pgs[obs_type][0];
    /* first sg_pg already mmaped */
    if (hhkr_sg_pg->pgs_user_addr) {
        hhkr_sg_pg = hhkr_obs_sg_pgs[obs_type][1];
    }
    /* second sg_pg already mmaped */
    if (hhkr_sg_pg->pgs_user_addr) {
        log_info("Both secure I/O scatterlist pgs for obs_type %d already mmaped.\n", obs_type);
        return 0;
    }
    mmap_len = PAGE_SIZE + hhkr_sg_pg->buf_size;
    user_addr = ksys_mmap_pgoff(0, mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED, 
                            fd, virt_to_phys((void*)hhkr_sg_pg) >> PAGE_SHIFT);
    hhkr_sg_pg->pgs_user_addr = user_addr;
    
    return user_addr;
}

/** @brief Init secure I/O structures for hitchhiker
 * 
 */
static unsigned int hhkr_secIO_init = 0;

int __hhkr_secure_IO_init(unsigned long obs_bpf_iosz) {
    struct file *filp;
    struct block_device *bdev;
    struct gendisk *disk;
    struct device *dev;
    struct Scsi_Host *shost;
    struct ata_port *ap;
    struct ata_device *adev;
    struct ahci_port_priv *pp;
    unsigned long _obs_bpf_iosz = obs_bpf_iosz;
    unsigned long pp_cmd_tbl, pp_cmd_tbl_dma, pp_cmd_slot;
    unsigned long ahci_port_mmio_virt, ahci_port_mmio_phys;
    int pmp;

    if (hhkr_secIO_init) {
        log_info("Already inited.\n");
        return 0;
    }
    /* init pending job status */
    if (!hhkr_secIO_pending_job) {
        if (hhkr_secIO_pending_job_init() == -1) {
            log_err("Failed to init pending job status.\n");
            return -1;
        }
    } else {
        log_info("Already inited.\n");
        return 0;
    }
    filp = filp_open(SATA_DEV_NAME, O_RDWR | O_DIRECT | O_SYNC, 0);
    bdev = I_BDEV(filp->f_mapping->host);
    disk = bdev->bd_disk;
    if (!disk) {
        log_err("Failed bdev->bd_disk.\n");
        return -1;
    }
    if (disk->disk_name) {
        log_info("diskname: %s\n", disk->disk_name);
    }

    dev = disk_to_dev(disk);
    if (!dev) {
        log_err("Failed.\n");
        return -1;
    }
    log_info("dev name: %s\n", dev_name(dev));

    shost = dev_to_shost(dev);
    if (!shost) {
        log_err("Failed shost.\n");
        return -1;
    } else {
        log_info("shost name: %s\n", shost->hostt->name);
    }
    
    ap = ata_shost_to_port(shost);
    // assume dev_no is always 0!
    // a simple impl of ata_find_dev() from ata_scsi_find_dev() in libata-scsi.c
    adev = &ap->link.device[0];
    if (!adev) {
        log_err("Failed adev.\n");
        return -1;
    }
    // strictly follow the procedure in ata_sg_setup()
    ap = adev->link->ap;    // from ata_qc_new() -> ata_qc_new_init()
    dev = ap->dev;          // from ata_sg_setup() -> dma_map_sg()
    pp = ap->private_data;  // ahci_qc_prep() on FVP && sil24_qc_prep() on JUNO

#ifndef ENV_JUNO
    log_info("Init for FVP board...\n");
    /* smc to init in el3 */
    pp_cmd_tbl = virt_to_phys((void *)pp->cmd_tbl);
    pp_cmd_tbl_dma = pp->cmd_tbl_dma;
    pp_cmd_slot = virt_to_phys((void *)pp->cmd_slot);
    ahci_port_mmio_virt = (unsigned long)__ahci_port_base(ap->host, ap->port_no);
    ahci_port_mmio_phys = virt_to_phys((void *)ahci_port_mmio_virt);
    pmp = adev->link->pmp;
    
    log_info("pending physaddr: 0x%lx.\n", (unsigned long)virt_to_phys(hhkr_secIO_pending_job));
    /* el3 driver */
    hitchhiker_smc(HHKRD_INIT_SECIO, pp_cmd_tbl, pp_cmd_tbl_dma, pp_cmd_slot, 
                   ahci_port_mmio_phys, pmp, virt_to_phys(hhkr_secIO_pending_job), 0);
    /* el1 driver */
    hhkrd_secIO_init((unsigned long)pp->cmd_tbl, pp_cmd_tbl_dma, (unsigned long)pp->cmd_slot, 
                     ahci_port_mmio_virt, pmp, (unsigned long)hhkr_secIO_pending_job);
#else
    log_info("Init for JUNO board...\n");
    int SIL24_PORT_BAR = 2;
    int PORT_REGS_SIZE = 0x2000;
    /* sil24 port MMIO: 0x8118dc00 */
    unsigned long sil24_port_mmio_virt = (unsigned long)ap->host->iomap[SIL24_PORT_BAR] + 
                                          ap->port_no * PORT_REGS_SIZE;
    log_info("tf->ctl: %d.\n", adev->link->ap->ctl);
    hhkrd_secIO_init_juno((void *)ap->private_data, sil24_port_mmio_virt, adev->link->pmp, 
                           adev->link->ap->ctl, (unsigned long)hhkr_secIO_pending_job);
#endif
    /* init scatterlist_pgs */
    if (!_obs_bpf_iosz)
        _obs_bpf_iosz = SZ_8M;
    __hhkr_sg_pgs_alloc(dev, 0, _obs_bpf_iosz);  // 8MB for ebpfs
    __hhkr_sg_pgs_alloc(dev, 1, SZ_1M);  // 1MB for omnilog
    __hhkr_sg_pgs_alloc(dev, 2, SZ_1M);  // 1MB for padding
    __hhkr_sg_pgs_alloc(dev, 3, SZ_4M);  // 4MB for padding
    
    hhkr_secIO_init = 1;
    return 0;
}
EXPORT_SYMBOL(__hhkr_secure_IO_init);   // for test and debug now

/* just for test now... */
unsigned long hhkr_IO_mem;
EXPORT_SYMBOL(hhkr_IO_mem);
int __hhkr_IO_mem_init(void) {
    struct page *page;
    unsigned int pg_align;
    /* assign 16 MB pages */
    int length = (1 << 20) * 16;
    pg_align = get_order(length);

    page = cma_alloc(AL_logger, (length >> PAGE_SHIFT), pg_align, GFP_KERNEL);
    if (!page) {
        log_err("Failed to allocate memory for the secure I/O.\n");
        return -1;
    }
    hhkr_IO_mem = (unsigned long)page_to_virt(page);
#if DEBUGLABEL
    log_info("Secure I/O init at phys: 0x%llx, virt: 0x%lx, size: 0x%x.\n", 
             virt_to_phys((void*)hhkr_IO_mem), (unsigned long)hhkr_IO_mem, length);
#endif
    return 0;
}

/** ==========================================================================================================
 * Evaluation 
 * ========================================================================================================== */
hhkr_buf_t *omni_buffer_k;
hhkr_buf_t *omni_buffer_d;
int __hhkr_init_omni_buffers(unsigned long size) {
    if (!omni_buffer_k) {
        omni_buffer_k = __hhkr_buf_alloc(size);
        omni_buffer_k->obs_type = 1;
#if DEBUGLABEL
    log_info("omni_buffer_k inited at phys: 0x%lx, virt: 0x%lx, size: 0x%lx.\n", 
             omni_buffer_k->phys_addr, omni_buffer_k->virt_addr, size);
#endif
    }
    if (!omni_buffer_d) {
        omni_buffer_d = __hhkr_buf_alloc(size);
        omni_buffer_d->obs_type = 1;
#if DEBUGLABEL
    log_info("omni_buffer_d inited at phys: 0x%lx, virt: 0x%lx, size: 0x%lx.\n", 
             omni_buffer_d->phys_addr, omni_buffer_d->virt_addr, size);
#endif
    }

    /* notify monitor */
    hitchhiker_smc(HHKR_INIT_OMNI_BUF, omni_buffer_k->phys_addr, omni_buffer_d->phys_addr,
                   0, 0, 0, 0, 0);
    return 0;
}

unsigned long __hhkr_mmap_omni_buffer_d(void) {
    int fd = current->hhkr_ctl_fd;
    if (!current->is_hhkrd) {
        // log_err("Only hhkrd can mmap the buf metadata message.\n");
        // return 0;
        fd = 3;
    }
    if (!omni_buffer_d) {
        panic("Omni buffer not allocated.\n");
    }
    omni_buffer_d->user_addr = ksys_mmap_pgoff(0, omni_buffer_d->length, PROT_READ | PROT_WRITE, MAP_SHARED, 
                                         fd, (omni_buffer_d->phys_addr) >> PAGE_SHIFT);
    return omni_buffer_d->user_addr;
}

/** @brief write data to the omni buffer kernel to synchronously protect data
 */
unsigned long hhkr_write_omni_buf_k(const char *data, unsigned long len) {
    struct arm_smccc_res smccc_res;
    hhkr_buf_t *buf = omni_buffer_k;
    spin_lock_irq(hhkr_buf_lock[buf->obs_type]);
    
    if (!buf) {
        panic("Omni_buffer_k not allocated.\n");
    }

    buf->cur_pos = 0;
     
    memcpy((void *)(buf->virt_addr + buf->cur_pos), data, len);
    buf->cur_pos += len;

#if DEBUGLABEL
    log_info("After write buf: 0x%lx. type=%d, buf->cur_pos=0x%lx, len=0x%lx.\n", 
                buf->phys_addr, buf->obs_type, buf->cur_pos, len);
#endif
    /* synchronously protect the buffer data */
    arm_smccc_smc(HHKR_WRITE_OMNI_BUF, buf->phys_addr, buf->cur_pos, 0, 0, 0, 0, 0, &smccc_res);
#if DEBUGLABEL
    log_info("omni_buf el3_memcpy done.\n");
#endif
    /* done.  */
    buf->cur_pos = 0;

    spin_unlock_irq(hhkr_buf_lock[buf->obs_type]);
    return len;
}
EXPORT_SYMBOL(hhkr_write_omni_buf_k);