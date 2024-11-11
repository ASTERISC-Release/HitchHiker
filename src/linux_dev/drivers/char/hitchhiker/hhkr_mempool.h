#include <linux/module.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/scatterlist.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/mm_types.h>
#include <linux/hitchhiker.h>

#define HHKR_MSG_QUEUE_SIZE 1024
typedef struct hitchhiker_message_queue {
    hhkr_buf_t messages[HHKR_MSG_QUEUE_SIZE];
    atomic_t head;
    atomic_t tail;
} hhkr_msg_queue_t;


typedef struct hitchhiker_daemon_freeback_waitinglist {
	unsigned int num;   // number of buffers in the waiting list
	unsigned long buf_addrs[64];  // buffers physcal addresses
	unsigned long buf_sizes[64];
} hhkrd_free_wl_t;

extern hhkr_msg_queue_t *hhkr_msg_queue;
extern hhkrd_free_wl_t *hhkrd_free_wl;

void debug_print_hashtable(void);

extern struct kmem_cache *bufqueue_entry_cache;
void __hhkr_enqueue_bufpool(enum hhkr_obs_type type, hhkr_buf_t *buf);
hhkr_buf_t *__hhkr_dequeue_bufpool(enum hhkr_obs_type type);

void __hhkr_mmap_buf_all(enum hhkr_obs_type type);
void __hhkr_mmap_buf(enum hhkr_obs_type type, unsigned long buf_phys_addr, unsigned long mapped_addr);
hhkr_buf_t *__hhkr_get_unmmapped_buf(enum hhkr_obs_type type);

void __hhkr_deregister_observability(enum hhkr_obs_type type);

/** ============================================================================================
 *  Message Queue between kkhr kernel logger module and the hhkrd receiver thread
 *  ============================================================================================ */
int __hhkr_msg_queue_init(void);
void hhkr_send_message(hhkr_buf_t *msg);
unsigned long __hhkr_mmap_msg_queue(void);

extern hhkr_buf_t *buf_meta_msg;

void __hhkr_buf_meta_msg_init(void);
unsigned long __hhkr_mmap_buf_meta_msg(void);

/** ==========================================================================================================
 * APIs for the hitchhiker daemon (hhkrd)'s freeback buffer waitlist 
 * ========================================================================================================== */
int __hhkrd_free_wl_init(void);
unsigned long __hhkrd_mmap_free_wl(void);
int __hhkr_free_back_bufs(void);

/** ==========================================================================================================
 * APIs for the secure I/O's scatterlist and buffer allocate
 * ========================================================================================================== */
#define SATA_DEV_NAME  "/dev/sda"

typedef struct hitchhiker_el1_scatterlist_pgs {
    /* 1. scatterlist */
    struct scatterlist sg;
    /* 2. metadata */
    unsigned long pgs_phys_addr;
    unsigned long pgs_kern_addr;
    unsigned long pgs_user_addr;
	unsigned int cur_pos;
	unsigned int buf_size;

    unsigned long blk_start;  // write block start
	unsigned long write_size; // write block size
    /* 3. buffer */
} hhkr_scatterlist_pgs_t;

unsigned long __hhkrd_mmap_secIO_pending_job(void);

#ifndef ENV_JUNO
extern int hhkrd_secIO_init(unsigned long pp_cmd_tbl, unsigned long pp_cmd_tbl_dma, unsigned long pp_cmd_slot, 
                     unsigned long ahci_port_mmio, unsigned long pmp, unsigned long io_job_pending_addr);
// extern int hhkrd_secIO_init_plat(void *pp);
#else
extern int hhkrd_secIO_init_juno(void *pp, unsigned long port_base_mmio_virt, int pmp, 
                                 int tf_ctl, unsigned long io_job_pending_addr);
#endif
extern int hhkrd_secIO_assignjob(unsigned long scatterlist_pgs, unsigned long blk_start, unsigned long write_size);

int __hhkr_secure_IO_init(unsigned long obs_bpf_iosz);
int __hhkr_IO_mem_init(void);    // just for test now
unsigned long __hhkr_sg_pg_mmap(int obs_type);

/** ==========================================================================================================
 * Evaluation variables
 * ========================================================================================================== */
extern int policy_cdf_mode;
extern int omnilog_mode;

extern hhkr_buf_t *omni_buffer_k;
extern hhkr_buf_t *omni_buffer_d;
extern int __hhkr_init_omni_buffers(unsigned long size);
extern unsigned long __hhkr_mmap_omni_buffer_d(void);

unsigned long hhkr_write_omni_buf_k(const char *data, unsigned long len);