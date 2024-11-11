#ifndef LINUX_HITCHHIKER_H
#define LINUX_HITCHHIKER_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/kconfig.h>

#define DEBUGLABEL           (0)

// build for FVP 
#ifdef ENV_JUNO
#undef ENV_JUNO
#endif

#define log_info(fmt, arg...) \
    printk(KERN_INFO "[%s][%d] "pr_fmt(fmt)"", __func__, __LINE__, ##arg)
#define log_err(fmt, arg...) \
    printk(KERN_ERR "[%s][%d] "pr_fmt(fmt)"", __func__, __LINE__, ##arg)


#define HHKR_BUF_LENGTH_DEFAULT    (0x100000)  /* 1 MB */
#define HHKR_BUFPOOL_NUM_DEFAULT   (0x8)       /* 8 bufs */

// TODO(): the types of system observability should be configurable via a 
//         user configuration file
#define __HHKR_OBS_TYPE_WRAPPER(OBS_PREFIX)	\
	OBS_PREFIX(obs_bpfs),        \
    OBS_PREFIX(obs_omni),		 \
    OBS_PREFIX(obs_tbd),         \
	OBS_PREFIX(obs_tbd2)

#define __HHKR_OBS_TYPE(x) HHKR_OBS_ ## x

enum hhkr_obs_type {
	__HHKR_OBS_TYPE_WRAPPER(__HHKR_OBS_TYPE),
	__HHKR_OBS_MAX_ID,
};
#undef __HHKR_OBS_TYPE

/* a single memory buf */
typedef struct hitchhiker_buf {
    /* Type of system observability e.g., HKKR_OBS_audit_log */
    int obs_type;
    /* The (kernel space) base virtual address */
    unsigned long virt_addr;
    /* The (hhkrd user space) base virtual address */
    unsigned long user_addr;
    /* The base physical address */
    unsigned long phys_addr;
    /* Current data position */
    unsigned long cur_pos;
    /* total size */
    unsigned long length;
    /* secured timestamp (used to calc CDF) */
    unsigned long ts_secure;
} hhkr_buf_t;

/* a queue entry for buf element */
typedef struct hitchhiker_buf_queue {
    hhkr_buf_t *buf;
    struct list_head list;
} hhkr_buf_queue_t;

/* a manager that maintains the buf pool */
typedef struct hitchhiker_queue_manager {
    spinlock_t lock;
    struct list_head pool_head;
} hhkr_queue_mngr_t;


#define MESSAGE_INTERVAL_MS 1

/* User interfaces */
/**
 * Register a type of system observability, and allocate its buffer pool
 * @param length: the length of each buffer
 * @param num: the number of buffers
 */
extern int hhkr_register_observability(enum hhkr_obs_type type, unsigned long length, unsigned long num);

/**
 * Get the current writing buffer 
 */
extern hhkr_buf_t *hhkr_get_current_buf(enum hhkr_obs_type type);

/**
 * Write data to the current writing buffer
 */
extern unsigned long hhkr_write_current_buf(enum hhkr_obs_type type, const char *data, unsigned long len);

/**
 * Protect the current buffer, and switch to the next writing buffer
 * @param use_memcpy is an evaluation flag, to test the performance by using el3_memcpy
 *                   to secure the current buffer via copying content rather than GPT permission
 *                   change.
 */
extern unsigned long hhkr_secure_current_buf(enum hhkr_obs_type type, int use_memcpy);

/**
 * Write data to the omni buffer kernel and synchronously protect the buffer by immediately
 * copy the data to a protected buffer in EL3 via SMC
 */
extern unsigned long hhkr_write_omni_buf_k(const char *data, unsigned long len);


static inline unsigned int hitchhiker_smc(unsigned int fid, uint64_t arg1, uint64_t arg2, uint64_t arg3, 
                                          uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7) 
{
    unsigned int ret0;
    asm volatile("mov x0, %[fid]\n"
                 "mov x1, %[a1]\n"
                 "mov x2, %[a2]\n"
                 "mov x3, %[a3]\n"
                 "mov x4, %[a4]\n"
                 "mov x5, %[a5]\n"
                 "mov x6, %[a6]\n"
                 "mov x7, %[a7]\n"
                 "smc #0"
                 :: [fid]"r"(fid), [a1]"r"(arg1), [a2]"r"(arg2), [a3]"r"(arg3), 
                    [a4]"r"(arg4), [a5]"r"(arg5), [a6]"r"(arg6), [a7]"r"(arg7)
                 : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "cc", "memory");
    asm volatile("mov %0, x0" : "=r"(ret0));
    return ret0;
}

#define U_(_x) (_x##U)
#define U(_x) U_(_x)
// #define UL(_x) (_x##UL)
// #define ULL(_x) (_x##ULL)
#define L(_x) (_x##L)
#define LL(_x) (_x##LL)

/* hhkr ioctl */
#define         HHKR_GET_UNMMAPPED_BUF  _IOW('m', 2, unsigned int)
#define         HHKR_MMAP_BUF           _IOW('m', 4, unsigned int)
#define         HHKR_MMAP_MSG_QUEUE     _IOW('m', 5, unsigned int)
#define         HHKR_MMAP_BUF_META_MSG  _IOW('m', 9, unsigned int)
#define         HHKR_MMAP_FREEBACK_WL   _IOW('m', 7, unsigned int)
#define         HHKR_POLICY_CDF_MODE    _IOW('m', 10, unsigned int)

#define         HHKR_MMAP_OMNI_BUF_D    _IOW('m', 11, unsigned int)
#define         HHKR_MEMCPY_MODE        _IOW('m', 13, unsigned int)

/* hhkr secure policy */
#define         HHKR_ACT_INTERVAL_POLICY   _IOW('m', 6, unsigned int)
#define         HHKR_CLR_INTERVAL_POLICY   _IOW('m', 8, unsigned int)

#define         HHKR_SECURE_BUF        U(0x80000FF2)
#define         HHKRD_FREEBACK_BUFS    U(0x80000FF3)

/* hhkrd smc & ioctl */
#define         HHKRD_CREATE           U(0x80000FFE)
#define         HHKRD_EXIT_TEST        U(0x80000FFF)
#define         HHKRD_STATUS           U(0x80001000)
#define         HHKRD_EXCEPTION        U(0x80000F00)
#define         HHKRD_SETPAGE          U(0x80000F01)
#define         HHKRD_MEMEXPAND        U(0x80000F02)
#define         HHKRD_CLONE            U(0x80000F03)

#define         HHKRD_ASSIGN_SHARE     U(0x80000FFD)
#define         HHKRD_DESTROY          U(0x80000FF0)
#define         HHKRD_ENTER            U(0x80000FF1)

#define         HHKR_INIT_OMNI_BUF     U(0x80000F10)
#define         HHKR_WRITE_OMNI_BUF    U(0x80000F11)

/* hhkrd secure IO */
#define         HHKRD_INIT_SECIO       U(0x80000FF4)
#define         HHKRD_DO_SECIO         U(0x80000FF5)
#define         HHKRD_MMAP_SCATTER     U(0x80000FF6)
#define         HHKRD_ASSIGN_SECIO     U(0x80000FF7)
#define         HHKRD_INIT_SECIO_JUNO  U(0x80000FF8)
#define         HHKRD_ASSIGN_SECIO_JUNO U(0x80000FF9)
#define         HHKRD_MMAP_PENDING_STAT _IOW('m', 12, unsigned int)

/* management */
#define         HHKRD_MAX                          0x2
#define         HHKRD_TASK_SHARED_LENGTH           0x10000    // 64KB
#define         HHKRD_TASK_SIGNAL_STACK_LENGTH     0x4000     // 16KB
#define         EXCEPTION_VECTOR_LENGTH            0x1000     // 4KB
#define         HHKRD_VECTOR_PAGE_TABLE_SPACE      0x1000000  // 16MB
#define         HHKRD_EXTEND_MEM_DEFAULT_LENGTH    0x4000000  // 64MB

/* HHKRD driver */
#define HHKRD_AL_ALLOCATE	        _IOW('m', 1, unsigned int)
#define HHKRD_AL_RELEASE		    _IOW('m', 3, unsigned int)
#define HHKRD_AL_MARK_RELEASE		U(0x80000F04)

#endif