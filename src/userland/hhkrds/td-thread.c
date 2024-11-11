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
#include <linux/types.h>
#include <arch_def.h>

#define DEV_PATH		"/dev/hitchhiker-ctl"


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
    char comm[16];
    unsigned long long task;
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

// AUDIT LOG DATA STRUCTS ------------------------------------------------

typedef struct hitchhiker_audit_log {
    hhkr_event_ctx_t ctx;
    hhkr_syscall_data_t syscall_data;
} hhkr_audit_log_t;

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
} hhkr_buf_t;

#define HHKR_MSG_QUEUE_SIZE 1024
typedef struct hitchhiker_message_queue {
    hhkr_buf_t messages[HHKR_MSG_QUEUE_SIZE];
    int head;
    int tail;
} hhkr_msg_queue_t;

typedef struct hitchhiker_daemon_freeback_waitinglist {
	unsigned int num;   // number of buffers in the waiting list
	unsigned long buf_addrs[64];  // buffers physcal addresses
	unsigned long buf_sizes[64];
} hhkrd_free_wl_t;

hhkr_msg_queue_t *queue = NULL;
hhkrd_free_wl_t *free_wl = NULL;
hhkr_buf_t *buf = NULL;

static int fd = 0;

/* ------------------------------------ message queue begin --------------------------------------------------- */
static int is_queue_empty(hhkr_msg_queue_t *queue) {
    return (queue == NULL)? 1 : (queue->head == queue->tail);
}

static hhkr_buf_t *read_queue(hhkr_msg_queue_t *queue) {
    buf = NULL;
    printf("start to read queue.\n");
    if (is_queue_empty(queue)) {
        printf("queue is empty.\n");
        return buf;
    }
    buf = &queue->messages[queue->head];
    queue->head = (queue->head + 1) % HHKR_MSG_QUEUE_SIZE;
    return buf;
}
/* ------------------------------------ message queue end ----------------------------------------------------- */

/* secure policy flag */
unsigned long *hhkr_activate_flag = NULL;

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
                printf("mmap scatterlist pages for obs[%d][%d], user_addr: 0x%lx, kern_addr: 0x%lx.\n",
                        i, j, (user_addr << 12), hhkr_obs_sg_pgs[i][j]->pgs_kern_addr);
            } else {
                printf("mmap scatterlist pages for obs[%d][%d] failed.\n", i, j);
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
        cur_sg_pg->cur_pos += size;
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

/** ============================================================================================================================================
 * hhkrd code section
 * ============================================================================================================================================= */

// receiver thread ----------------------------------------------------
static void __debug_print_auditlog(hhkr_audit_log_t *audit_data) {
    printf("ts: %lu, pid: %u, tid: %u, uid: %u, comm: %s, syscall_id: %u, args: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, ret: 0x%lx.\n",
            audit_data->ctx.ts, audit_data->ctx.pid, audit_data->ctx.tid, audit_data->ctx.uid, audit_data->ctx.comm,
            audit_data->syscall_data.syscall_id, audit_data->syscall_data.args.args[0], audit_data->syscall_data.args.args[1],
            audit_data->syscall_data.args.args[2], audit_data->syscall_data.args.args[3], audit_data->syscall_data.args.args[4],
            audit_data->syscall_data.args.args[5], audit_data->syscall_data.ret);
}

void *timer_thread(void *arg) {
    printf("timer thread enabled.\n");
    ioctl(fd, HHKR_ACT_INTERVAL_POLICY, 0);
    return NULL;    
}

void *receiver_thread(void *arg) {
    /* activate time interval based secure policy */
    // *hhkr_activate_flag = 1;
    while(1) {
        buf = read_queue(queue);
        /* lets just print out the buffer */
        if (buf) {
            printf("buf.phys_addr: 0x%lx, buf.user_addr: 0x%lx, buf.pos: 0x%lx, log_size: 0x%lx.\n", 
                    buf->phys_addr, buf->user_addr, buf->cur_pos, sizeof(hhkr_audit_log_t));
            
            /* debug print */
            // if (buf->obs_type == 0 && buf->cur_pos > sizeof(hhkr_audit_log_t)) {
            //     for (int i = 0; i <= buf->cur_pos; i+=sizeof(hhkr_audit_log_t)) {
            //         __debug_print_auditlog((hhkr_audit_log_t *)(buf->user_addr + i));
            //     }
            // }
            /* consume the buffer into the store (sg_pg) buffer */
            unsigned int size = hhkr_write_to_sg_pg(buf->obs_type, (void *)(buf->user_addr), buf->cur_pos);

            /* add to the freeback list */
            if (free_wl) {
                free_wl->buf_addrs[free_wl->num] = buf->phys_addr;
                free_wl->buf_sizes[free_wl->num] = buf->length;
                free_wl->num++;
                // todo: now just test
                if (free_wl->num >= 8) {
                    ioctl(fd, HHKRD_FREEBACK_BUFS, 0);
                    // printf("freeback bufs done.\n");
                }
            }
        }
        printf("recv_thread.\n");
    }
    return NULL;
}

void *store_thread(void *arg) {
    while(1) {
        /* check if there is sg_pg to store */
        for (int i = 0; i < __HHKR_OBS_MAX_ID; i++) {
            if (hhkr_tostore_sg_pg_ids[i] != -1) {
                /* store the sg_pg */
                hhkr_scatterlist_pgs_t *sg_pg = hhkr_obs_sg_pgs[i][hhkr_tostore_sg_pg_ids[i]];
                unsigned long blk_start = obs_blk_starts[i];

                sg_pg->blk_start = blk_start;
                /* TODO: determine size */
                sg_pg->write_size = sg_pg->sg.length;
                printf("store sg_pg for obs[%d][%d], sg_pg->cur_pos: 0x%x.\n", i, hhkr_tostore_sg_pg_ids[i], sg_pg->cur_pos);
                ioctl(fd, HHKRD_ASSIGN_SECIO, sg_pg->pgs_kern_addr);
                /* reset the sg_pg */
                sg_pg->cur_pos = 0;
                sg_pg->blk_start = 0;
                sg_pg->write_size = 0;
                /* update blk_start */
                obs_blk_starts[i] += sg_pg->buf_size;
                /* reset the tostore sg_pg id */
                hhkr_tostore_sg_pg_ids[i] = -1;
            }
        }
        /* sleep */
        /* do not use usleep now... clock_nanosleep syscall unhandled yet */
        sleep(1);
        printf("store_thread.\n");
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    unsigned long ret;
    printf("hello from td-thread...\n");
    
    if ((fd = open(DEV_PATH, O_RDWR, 0)) <= 0) {
        perror("Error.\n");
        return 1;
    }
    
    /* mmap bufs */
    ioctl(fd, HHKR_MMAP_BUF, 0);

    /* mmap message queue */
    ret = (unsigned long)ioctl(fd, HHKR_MMAP_MSG_QUEUE, 0);
    if (ret) {
        queue = (hhkr_msg_queue_t *)(ret << 12);
        printf("ret: 0x%lx, queue addr: 0x%lx.\n", ret, (unsigned long)queue);
    }
    /* mmap freeback waitlist */
    ret = (unsigned long)ioctl(fd, HHKR_MMAP_FREEBACK_WL, 0);
    if (ret) {
        free_wl = (hhkrd_free_wl_t *)(ret << 12);
        printf("ret: 0x%lx, free_wl addr: 0x%lx.\n", ret, (unsigned long)free_wl);
    }

    /* mmap policy activate flag */
    ret = (unsigned long)ioctl(fd, HHKR_MMAP_POLICY_ACT_FLAG, 0);
    if (ret) {
        hhkr_activate_flag = (unsigned long *)(ret << 12);
        printf("ret: 0x%lx, policy_activate_flag addr: 0x%lx.\n", ret, (unsigned long)hhkr_activate_flag);
    }

    /* ------------------------- Secure I/O Configuration Start ---------------------- */
    /* initialize secure I/O */
    ioctl(fd, HHKRD_INIT_SECIO, 0);
    /* mmap scatterlist pages */
    mmap_sg_pgs(fd);

    /* TODO: start debug test: fill buffer and assign I/O job */
    void *buf = ((void *)hhkr_obs_sg_pgs[0][0]) + 0x1000;
    memset(buf, 'A', hhkr_obs_sg_pgs[0][0]->buf_size);
    hhkr_obs_sg_pgs[0][0]->blk_start = 0;
    hhkr_obs_sg_pgs[0][0]->write_size = hhkr_obs_sg_pgs[0][0]->buf_size;
    ioctl(fd, HHKRD_ASSIGN_SECIO, hhkr_obs_sg_pgs[0][0]->pgs_kern_addr);

    init_current_sg_pg_ids();
    init_tostore_sg_pg_ids();
    /* ------------------------- Secure I/O Configuration End ------------------------ */

    /* create sub-thread */
    pthread_t timer_t, receiver_t, store_t;
    
    if (pthread_create(&timer_t, NULL, timer_thread, NULL) != 0) {
        perror("Error.\n");
        munmap(queue, sizeof(hhkr_msg_queue_t));
        return 1;
    }
    if (pthread_create(&receiver_t, NULL, receiver_thread, NULL) != 0) {
        perror("Error.\n");
        munmap(queue, sizeof(hhkr_msg_queue_t));
        return 1;
    }
    if (pthread_create(&store_t, NULL, store_thread, NULL) != 0) {
        perror("Error.\n");
        munmap(queue, sizeof(hhkr_msg_queue_t));
        return 1;
    }
    pthread_join(receiver_t, NULL);
    pthread_join(store_t, NULL);
    pthread_join(timer_t, NULL);
    munmap(queue, sizeof(hhkr_msg_queue_t));
    close(fd);
    return 0;
}