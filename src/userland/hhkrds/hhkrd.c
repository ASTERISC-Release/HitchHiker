#define _GNU_SOURCE
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <linux/types.h>
#include <stdatomic.h>
#include <arch_def.h>

#define DEV_PATH		"/dev/hitchhiker-ctl"

#define EVAL_MODE

#define QUIET
#define SHOW_POLICY_TIME
// #undef QUIET


#define TEST

/** ============================================================================================================================================
 *  hhkrd data structures and APIs
 * ============================================================================================================================================= */

/* defs */
#define __HHKR_OBS_MAX_ID       4        // todo: import from kernel header

// log data structs -----------------------------------------------------
typedef struct hitchhiker_event_context {
    unsigned long ts;
    int pid;
    int tid;
    int uid;
	int obs_type;
    char comm[16];
	struct task_struct *task;
} hhkr_event_ctx_t;


// SYSCALL DATA STRUCTS --------------------------------------------------

typedef struct args {
    unsigned long args[6];
}args_t;

typedef struct hitchhiker_syscall_data {
    unsigned int syscall_id;
    args_t args;
    unsigned long ts;
    unsigned long ret;
} hhkr_syscall_data_t;

typedef struct hitchhiker_net_traffic_data {
	unsigned int saddr;
	unsigned int daddr;
	unsigned int lport;
	unsigned int dport;
	unsigned int size;
	char net_packet_data[128];
} hhkr_net_data_t;

// OBSERVABILITY DATA STRUCTS ------------------------------------------------

typedef struct hitchhiker_audit_log {
    hhkr_event_ctx_t ctx;
    hhkr_syscall_data_t syscall_data;
} hhkr_audit_log_t;

typedef struct hitchhiker_app_log {
	hhkr_event_ctx_t ctx;
	char app_log_data[128];
} hhkr_app_log_t;

typedef struct hitchhiker_net_log {
	hhkr_event_ctx_t ctx;
	hhkr_net_data_t net_traffic;
} hhkr_net_log_t;

/* defines from hitchhiker.h */
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


typedef struct hitchhiker_daemon_freeback_waitinglist {
	unsigned int num;   // number of buffers in the waiting list
	unsigned long buf_addrs[64];  // buffers physcal addresses
	unsigned long buf_sizes[64];
} hhkrd_free_wl_t;


hhkrd_free_wl_t *free_wl = NULL;

static int fd = 0;

/* ----------------------------------------- sec IO start ----------------------------------------------------- */
struct hhkr_scatterlist {
    unsigned long page_link;
    unsigned int  offset;
    unsigned int  length;
    unsigned long dma_address;
    unsigned int  dma_length;
};

typedef struct hitchhiker_el1_scatterlist_pgs {
    /* 1. scatterlist */
    struct hhkr_scatterlist sg;
    /* 2. metadata */
    unsigned long pgs_phys_addr;
    unsigned long pgs_kern_addr;
    unsigned long pgs_user_addr;
	unsigned int cur_pos;
	unsigned int buf_size;

    unsigned long blk_start;  // write block start
	unsigned long write_size; // write block size
    /* --------- 4K page boundary -------- */
    /* 3. buffer (in the next page) */
} hhkr_scatterlist_pgs_t;

static unsigned long obs_blk_starts[4] = {0, 2097152, 4194304, 6291456};

hhkr_scatterlist_pgs_t *hhkr_obs_sg_pgs[__HHKR_OBS_MAX_ID][2];

static int hhkr_current_sg_pg_ids[__HHKR_OBS_MAX_ID];
static int hhkr_tostore_sg_pg_ids[__HHKR_OBS_MAX_ID];

static void init_current_sg_pg_ids(void) {
    for (int i = 0; i < __HHKR_OBS_MAX_ID; i++) {
        hhkr_current_sg_pg_ids[i] = 0;
    }
}

static void init_tostore_sg_pg_ids(void) {
    for (int i = 0; i < __HHKR_OBS_MAX_ID; i++) {
        hhkr_tostore_sg_pg_ids[i] = -1;
    }
}

static void mmap_sg_pgs(int hhkr_ctl_fd) {
    unsigned long user_addr;
    for (int i = 0; i < __HHKR_OBS_MAX_ID; i++) {
        for (int j = 0; j < 2; j++) {
            user_addr = ioctl(hhkr_ctl_fd, HHKRD_MMAP_SCATTER, i);
            if (user_addr) {
                hhkr_obs_sg_pgs[i][j] = (hhkr_scatterlist_pgs_t *)(user_addr << 12);
                printf("[hhkrd] mmap scatterlist pages for obs[%d][%d], user_addr: 0x%lx, kern_addr: 0x%lx.\n",
                        i, j, (user_addr << 12), hhkr_obs_sg_pgs[i][j]->pgs_kern_addr);
            } else {
                printf("[hhkrd] mmap scatterlist pages for obs[%d][%d] failed.\n", i, j);
            }
        }
    }
}

static unsigned int hhkr_write_to_sg_pg(int obs_type, void *data, unsigned int size) {
    hhkr_scatterlist_pgs_t *cur_sg_pg = hhkr_obs_sg_pgs[obs_type][hhkr_current_sg_pg_ids[obs_type]];
    
    /* enough space */
    if (cur_sg_pg->buf_size - cur_sg_pg->cur_pos >= size) {
        void *buf_addr = (void *)cur_sg_pg + 0x1000;
        memcpy((void *)(buf_addr + cur_sg_pg->cur_pos), data, size);
        // cur_sg_pg->cur_pos += size;
        return size;
    }

    /* mark as to_store for the store thread */
    hhkr_tostore_sg_pg_ids[obs_type] = hhkr_current_sg_pg_ids[obs_type];
    /* switch current sg_pg */
    hhkr_current_sg_pg_ids[obs_type] = (hhkr_current_sg_pg_ids[obs_type] + 1) % 2;
    /* write again */
    return hhkr_write_to_sg_pg(obs_type, data, size);
}
/* ----------------------------------------- sec IO end ------------------------------------------------------- */

/* ----------------------------------------- msg queue start -------------------------------------------------- */
#define HHKR_MSG_QUEUE_SIZE 1024
typedef struct hitchhiker_message_queue {
    hhkr_buf_t messages[HHKR_MSG_QUEUE_SIZE];
    atomic_int head;
    atomic_int tail;
} hhkr_msg_queue_t;


hhkr_msg_queue_t *queue = NULL;

// /* kernel-user share memory for passing the just-secured data buffer */
// hhkr_buf_t *buf = NULL;


static void hhkr_receive_message(hhkr_buf_t *to_msg) {
    int head = atomic_load(&queue->head);
    /* wait until queue is not empty */
    while (head == atomic_load(&queue->tail)) {
        // busy waiting?
        // usleep(1);
        /* sleep? */
    }
    // get message from head
    *to_msg = queue->messages[head];
    // update head
    atomic_store(&queue->head, (head + 1) % HHKR_MSG_QUEUE_SIZE);
}
/* ----------------------------------------- msg queue end ---------------------------------------------------- */

/** ============================================================================================================================================
 * hhkrd code section
 * ============================================================================================================================================= */

// receiver thread ----------------------------------------------------
static void __debug_print_syscall_log(hhkr_audit_log_t *audit_data) {
    printf("[Syscall Log] <comm: %s, pid: %u, tid: %u> sys_id: %u, args: 0x%lx, 0x%lx, 0x%lx, ..., ret: 0x%lx.\n",
            audit_data->ctx.comm, audit_data->ctx.pid, audit_data->ctx.tid, 
            audit_data->syscall_data.syscall_id, audit_data->syscall_data.args.args[0], audit_data->syscall_data.args.args[1],
            audit_data->syscall_data.args.args[2], audit_data->syscall_data.ret);
}

static void __debug_print_app_log(hhkr_app_log_t *app_log_data) {
    printf("[App Log] <comm: %s, pid: %u, tid: %u> raw: %s.\n",
            app_log_data->ctx.comm, app_log_data->ctx.pid, app_log_data->ctx.tid, 
            app_log_data->app_log_data);
}

static void __debug_print_net_log(hhkr_net_log_t *net_log_data) {
    printf("[Net Log] <comm: %s, pid: %u, tid: %u> 0x%x:%d -- 0x%x:%d.\n",
            net_log_data->ctx.comm, net_log_data->ctx.pid, net_log_data->ctx.tid, 
            net_log_data->net_traffic.saddr, net_log_data->net_traffic.lport,
            net_log_data->net_traffic.daddr, net_log_data->net_traffic.dport);
}

static void __debug_print_buffer(hhkr_buf_t *mbuf) {
    unsigned long user_addr = mbuf->user_addr;
    
    for (int i =0; i < mbuf->cur_pos; ) {
        hhkr_event_ctx_t *ctx = (hhkr_event_ctx_t *)(user_addr + i);
        /* syscall log */
        if (ctx->obs_type == 0) { 
            __debug_print_syscall_log((hhkr_audit_log_t *)(user_addr + i));
            i += sizeof(hhkr_audit_log_t);
        } 
        /* application log */
        else if(ctx->obs_type == 1) { 
            __debug_print_app_log((hhkr_app_log_t *)(user_addr + i));
            i += sizeof(hhkr_app_log_t);
        }
        else if (ctx->obs_type == 2) {
            __debug_print_net_log((hhkr_net_log_t *)(user_addr + i));
            i += sizeof(hhkr_net_log_t);
        }
        else {

        }
    }
}

static void __debug_print_policy_time_statistics(hhkr_buf_t *mbuf, FILE *file) {
    unsigned long t_min, t_avg, t_max, t;
    // t_min = t_avg = t_max = 0;
    for (int i = 0; i < mbuf->cur_pos; i += sizeof(hhkr_audit_log_t)) {
        hhkr_audit_log_t *audit_data = (hhkr_audit_log_t *)(mbuf->user_addr + i);

        t = mbuf->ts_secure - audit_data->ctx.ts;
        
        // if (t_min == 0 || t < t_min) {
        //     t_min = t;
        // }
        // if (t > t_max) {
        //     t_max = t;
        // }
        
        // t_avg += t;
        // we should print every single protection time!
        fprintf(file, "%.3fus\n", t / 1e3);
    }
    // t_avg /= (mbuf->cur_pos / sizeof(hhkr_audit_log_t));

    // double t_min_ms, t_max_ms, t_avg_ms;
    // t_min_ms = t_min / 1e6;
    // t_max_ms = t_max / 1e6;
    // t_avg_ms = t_avg / 1e6;
    // printf("===> buf: 0x%lx (%ld logs), policy time statistics: min: %.3fms, avg: %.3fms, max: %.3fms.\n",
    //         mbuf->phys_addr, mbuf->cur_pos / sizeof(hhkr_audit_log_t), t_min_ms, t_avg_ms, t_max_ms);
}

struct timespec prev_time = {};
struct timespec cur_time = {}; // count time
double time_diff = 0;


int main(int argc, char *argv[]) {
    unsigned long ret;
    printf("[hhkrd] hello from now-hhkrd...\n");
#ifdef EVAL_MODE
    printf("[hhkrd] Evaluation mode: On.\n");
#elif defined(QUIET)
    printf("[hhkrd] Quiet mode: On.\n");
#else
    printf("[hhkrd] Verbose mode: On.\n");
#endif
    
    if ((fd = open(DEV_PATH, O_RDWR, 0)) <= 0) {
        perror("Error.\n");
        return 1;
    }
    /* mmap bufs */
    ioctl(fd, HHKR_MMAP_BUF, 0);   // map audit log bufs

    /* mmap message queue */
    ret = (unsigned long)ioctl(fd, HHKR_MMAP_MSG_QUEUE, 0);
    if (ret) {
        queue = (hhkr_msg_queue_t *)(ret << 12);
        printf("<mmap msg_queue> address: 0x%lx.\n", (unsigned long)queue);
    }

    /* mmap freeback waitlist */
    ret = (unsigned long)ioctl(fd, HHKR_MMAP_FREEBACK_WL, 0);
    if (ret) {
        free_wl = (hhkrd_free_wl_t *)(ret << 12);
        printf("<mmap free_wl> address: 0x%lx.\n", (unsigned long)free_wl);
    }

    /* ------------------------- Secure I/O Configuration Start ---------------------- */
    /* initialize secure I/O */
    ioctl(fd, HHKRD_INIT_SECIO, 0);
    /* mmap scatterlist pages */
    mmap_sg_pgs(fd);

    /* TODO: start debug test: fill buffer and assign I/O job */
    void *abuf = ((void *)hhkr_obs_sg_pgs[0][0]) + 0x1000;
    memset(abuf, 'A', hhkr_obs_sg_pgs[0][0]->buf_size);
    hhkr_obs_sg_pgs[0][0]->blk_start = 0;
    hhkr_obs_sg_pgs[0][0]->write_size = hhkr_obs_sg_pgs[0][0]->buf_size;
    ioctl(fd, HHKRD_ASSIGN_SECIO, hhkr_obs_sg_pgs[0][0]->pgs_kern_addr);

    // issue again
    sleep(1);
    abuf = ((void *)hhkr_obs_sg_pgs[0][1]) + 0x1000;
    memset(abuf, 'B', hhkr_obs_sg_pgs[0][1]->buf_size);
    hhkr_obs_sg_pgs[0][1]->blk_start = 0x4000;
    hhkr_obs_sg_pgs[0][1]->write_size = hhkr_obs_sg_pgs[0][1]->buf_size;
    ioctl(fd, HHKRD_ASSIGN_SECIO, hhkr_obs_sg_pgs[0][1]->pgs_kern_addr);

    init_current_sg_pg_ids();
    init_tostore_sg_pg_ids();
    /* ------------------------- Secure I/O Configuration End ------------------------ */

    hhkr_buf_t buf;
    unsigned int w_size;


#ifdef SHOW_POLICY_TIME
    ioctl(fd, HHKR_POLICY_CDF_MODE, 0);

    FILE* file = fopen("/data/policy_cdf.tmp", "a");
    if (file == NULL) {
        perror("Failed to open /data/policy_cdf.tmp.\n");
        return 0;
    }
#endif
    /* ============================= event handling start ============================ */
    while (1) {
        /* receive message from queue */
        hhkr_receive_message(&buf);
        
        /* process message */

#ifdef SHOW_POLICY_TIME
        __debug_print_policy_time_statistics(&buf, file);
#elif defined(EVAL_MODE)

#elif defined(QUIET)
        /* consume the buffer into the store (sg_pg) buffer */
        w_size = hhkr_write_to_sg_pg(buf.obs_type, (void *)(buf.user_addr), buf.cur_pos);
#else
        /* debug buffer content */
        printf("buf.phys_addr: 0x%lx, buf.user_addr: 0x%lx, buf.pos: 0x%lx, log_size: 0x%lx, consumed_bytes: 0x%x.\n", 
                buf.phys_addr, buf.user_addr, buf.cur_pos, sizeof(hhkr_audit_log_t), w_size);
        __debug_print_buffer(&buf);
#endif

        /* freeback message */
        if (free_wl) {
            free_wl->buf_addrs[free_wl->num] = buf.phys_addr;
            free_wl->buf_sizes[free_wl->num] = buf.length;
            free_wl->num++;

            ioctl(fd, HHKRD_FREEBACK_BUFS, 0);
            free_wl->num = 0;
        }
    }

    close(fd);
    return 0;
}
