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

#define QUIET
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

typedef struct hitchhiker_scatterlist_pgs {
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

#define Q_SIZE  1024
typedef struct {
    hhkr_buf_t buffers[Q_SIZE];
    atomic_int head;
    atomic_int tail;
} thread_queue;


/* kernel-user share memory for passing the just-secured data buffer */
hhkr_buf_t *buf = NULL;

/* receive queue and free queue */
thread_queue queue, free_queue;

// cond variables for queue
pthread_cond_t cond_nonempty = PTHREAD_COND_INITIALIZER;
pthread_cond_t cond_nonfull = PTHREAD_COND_INITIALIZER;

// cond variables for free_queue
pthread_cond_t cond_free_queue_nonempty = PTHREAD_COND_INITIALIZER;
pthread_cond_t cond_free_queue_nonfull = PTHREAD_COND_INITIALIZER;

pthread_mutex_t mutex_queue = PTHREAD_MUTEX_INITIALIZER;


/** ============================================================================================================================================
 * hhkrd code section
 * ============================================================================================================================================= */

// sem_t sem_receive, sem_free, sem_kernel;
pthread_mutex_t mutex_control = PTHREAD_MUTEX_INITIALIZER;

// receiver thread ----------------------------------------------------
static void __debug_print_auditlog(hhkr_audit_log_t *audit_data) {
    printf("ts: %lu, pid: %u, tid: %u, uid: %u, comm: %s, syscall_id: %u, args: 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, ret: 0x%lx.\n",
            audit_data->ctx.ts, audit_data->ctx.pid, audit_data->ctx.tid, audit_data->ctx.uid, audit_data->ctx.comm,
            audit_data->syscall_data.syscall_id, audit_data->syscall_data.args.args[0], audit_data->syscall_data.args.args[1],
            audit_data->syscall_data.args.args[2], audit_data->syscall_data.args.args[3], audit_data->syscall_data.args.args[4],
            audit_data->syscall_data.args.args[5], audit_data->syscall_data.ret);
}

struct timespec prev_time = {};
struct timespec cur_time = {}; // count time
double time_diff = 0;

#define HHKRD_SECURE_POLICY_MS      15


//  SHOULDNT USE THIS SHIT TIMER THREAD ANYMORE...

void *timer_thread(void *arg) {
    struct timespec sleep_time, rem_time;
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = HHKRD_SECURE_POLICY_MS * 1000000;
    int exe_time = 0;
    while (1) {
        // exe_time += 1;
        /* 15ms time interval */
        // clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep_time, &rem_time);
        /*
         * secure current buffer,
         * after that, the variable *buf should be set by the kernel
         */
        unsigned long buffer_addr = 0;
        
// #ifndef TEST
        buffer_addr = ((unsigned long)ioctl(fd, HHKR_SECURE_BUF, 0) << 12);         
// #endif
        if (buffer_addr) {
#ifdef TEST
            printf("SHOULD NOT REACH in TEST! secured buffer: 0x%lx (buf: 0x%lx).\n", buffer_addr, buf->user_addr);
#endif
            /* a buffer is secured, we send to the receive queue */
            while (1) {
                int old_tail = atomic_load(&queue.tail);
                int next_tail = (old_tail + 1) % Q_SIZE;
                /* queue is full, wait */
                if (next_tail == atomic_load(&queue.head)) {
                    pthread_mutex_lock(&mutex_queue);
                    pthread_cond_wait(&cond_nonfull, &mutex_queue);
                    pthread_mutex_unlock(&mutex_queue);
                    continue;
                }
                /* update queue tail */
                if (atomic_compare_exchange_weak(&queue.tail, &old_tail, next_tail)) {
                    hhkr_buf_t *queue_buf = &queue.buffers[old_tail];
                    queue_buf->phys_addr = buf->phys_addr;
                    queue_buf->user_addr = buf->user_addr;
                    queue_buf->cur_pos = buf->cur_pos;
                    queue_buf->obs_type = buf->obs_type;
                    queue_buf->length = buf->length;

                    /* notify the receiver that the message queue is not empty */
                    pthread_cond_signal(&cond_nonempty);
                    break;
                }
            }
        }
        // // count time
        // clock_gettime(CLOCK_MONOTONIC, &cur_time);
        // if (prev_time.tv_nsec)
        //     time_diff = (cur_time.tv_sec - prev_time.tv_sec) * 1e3 + 
        //                 (cur_time.tv_nsec - prev_time.tv_nsec) / 1e6;
        // prev_time = cur_time;
    } 
    return NULL;    
}

void *receiver_thread(void *arg) {
    int num; 
    while(1) {
        hhkr_buf_t msg_buf = {};

        while (1) {
            int old_head = atomic_load(&queue.head);
            /* queue is empty, wait until there is a buf needs to be consumed */
            if (old_head == atomic_load(&queue.tail)) {
                pthread_mutex_lock(&mutex_queue);
                pthread_cond_wait(&cond_nonempty, &mutex_queue);
                pthread_mutex_unlock(&mutex_queue);
                continue;
            }
            /* get buffer from queue and update queue head */
            if (atomic_compare_exchange_weak(&queue.head, &old_head, (old_head + 1) % Q_SIZE)) {
                msg_buf = queue.buffers[old_head];
                pthread_cond_signal(&cond_nonfull);
                break;
            }
        }
        /* lets just print out the buffer */
#ifndef QUIET
        printf("Interval: %.3f ms, buf: 0x%lx, buf.phys_addr: 0x%lx, buf.user_addr: 0x%lx, buf.pos: 0x%lx, log_size: 0x%lx.\n", 
                time_diff, (unsigned long)buf, buf->phys_addr, buf->user_addr, buf->cur_pos, sizeof(hhkr_audit_log_t));
#endif
        msg_buf.obs_type = 0;
        /* debug print */
        // if (buf->obs_type == 0 && buf->cur_pos > sizeof(hhkr_audit_log_t)) {
        //     for (int i = 0; i <= buf->cur_pos; i+=sizeof(hhkr_audit_log_t)) {
        //         __debug_print_auditlog((hhkr_audit_log_t *)(buf->user_addr + i));
        //     }
        // }

        /* consume the buffer into the store (sg_pg) buffer */
        unsigned int size = hhkr_write_to_sg_pg(msg_buf.obs_type, (void *)(msg_buf.user_addr), msg_buf.cur_pos);

        /* notify the control thread to free back buffers */
        while (1) {
            int old_tail = atomic_load(&free_queue.tail);
            /* free queue is full, wait */
            if ((old_tail + 1) % Q_SIZE == atomic_load(&free_queue.head)) {
                pthread_mutex_lock(&mutex_queue);
                pthread_cond_wait(&cond_free_queue_nonfull, &mutex_queue);
                pthread_mutex_unlock(&mutex_queue);
                continue;
            }
            /* put buf into the free_queue */
            if (atomic_compare_exchange_weak(&free_queue.tail, &old_tail, (old_tail + 1) % Q_SIZE)) {
                free_queue.buffers[old_tail] = msg_buf;         // copy buf into free_queue
                pthread_cond_signal(&cond_free_queue_nonempty); // notify control_thread the free_queue is not empty
                break;
            }
        }
    }
    return NULL;
}

// void *store_thread(void *arg) {
//     while(1) {
//         /* check if there is sg_pg to store */
//         for (int i = 0; i < __HHKR_OBS_MAX_ID; i++) {
//             if (hhkr_tostore_sg_pg_ids[i] != -1) {
//                 /* store the sg_pg */
//                 hhkr_scatterlist_pgs_t *sg_pg = hhkr_obs_sg_pgs[i][hhkr_tostore_sg_pg_ids[i]];
//                 unsigned long blk_start = obs_blk_starts[i];

//                 sg_pg->blk_start = blk_start;
//                 /* TODO: determine size */
//                 sg_pg->write_size = sg_pg->sg.length;
//                 printf("store sg_pg for obs[%d][%d], sg_pg->cur_pos: 0x%x.\n", i, hhkr_tostore_sg_pg_ids[i], sg_pg->cur_pos);
//                 ioctl(fd, HHKRD_ASSIGN_SECIO, sg_pg->pgs_kern_addr);
//                 /* reset the sg_pg */
//                 sg_pg->cur_pos = 0;
//                 sg_pg->blk_start = 0;
//                 sg_pg->write_size = 0;
//                 /* update blk_start */
//                 obs_blk_starts[i] += sg_pg->buf_size;
//                 /* reset the tostore sg_pg id */
//                 hhkr_tostore_sg_pg_ids[i] = -1;
//             }
//         }
//         /* sleep */
//         /* do not use usleep now... clock_nanosleep syscall unhandled yet */
//         sleep(1);
//     }
//     return NULL;
// }

void *control_thread(void *arg) {
    hhkr_buf_t *msg_buf;
    while (1) {
        while (1) {
            int old_head = atomic_load(&free_queue.head);
            /* free queue is empty, wait */
            if (old_head == atomic_load(&free_queue.tail)) {
                pthread_mutex_lock(&mutex_queue);
                pthread_cond_wait(&cond_free_queue_nonempty, &mutex_queue);
                pthread_mutex_unlock(&mutex_queue);
                continue;
            }
            /* get buffer from free_queue and update free_queue head */
            if (atomic_compare_exchange_weak(&free_queue.head, &old_head, (old_head + 1) % Q_SIZE)) {
                msg_buf = &free_queue.buffers[old_head];
                msg_buf->cur_pos = 0;
                /* add to freelist */
                if (free_wl) {
                    free_wl->buf_addrs[free_wl->num] = msg_buf->phys_addr;
                    free_wl->buf_sizes[free_wl->num] = msg_buf->length;
                    free_wl->num++;
                }
                pthread_cond_signal(&cond_free_queue_nonfull);
                break;
            }
        }
        /* free-back buf */
        if (free_wl && free_wl->num) {
#ifndef QUIET
            printf("freeback, buffer num: %d. buffer[0] phys_addr: 0x%lx\n", free_wl->num, free_wl->buf_addrs[0]);
#endif
            ioctl(fd, HHKRD_FREEBACK_BUFS, 0);
            free_wl->num = 0;
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    unsigned long ret;
    printf("hello from hhkrd...\n");
    
    if ((fd = open(DEV_PATH, O_RDWR, 0)) <= 0) {
        perror("Error.\n");
        return 1;
    }
#ifdef TEST
    // int ffff = ioctl(fd, 0x80000999, fd);
    printf("hhkr_ctl_fd: %d.\n", fd);
#endif
    /* mmap bufs */
    ioctl(fd, HHKR_MMAP_BUF, 0);   // map audit log bufs

    /* mmap buf message */
    ret = ioctl(fd, HHKR_MMAP_BUF_META_MSG, 0);
    if (ret) {
        buf = (hhkr_buf_t *)(ret << 12);
        printf("ret: 0x%lx, buf_msg addr: 0x%lx.\n", ret, (unsigned long)buf);
    }

    /* mmap freeback waitlist */
    ret = (unsigned long)ioctl(fd, HHKR_MMAP_FREEBACK_WL, 0);
    if (ret) {
        free_wl = (hhkrd_free_wl_t *)(ret << 12);
        printf("ret: 0x%lx, free_wl addr: 0x%lx.\n", ret, (unsigned long)free_wl);
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

    init_current_sg_pg_ids();
    init_tostore_sg_pg_ids();
    /* ------------------------- Secure I/O Configuration End ------------------------ */

    /* create sub-thread */
    // sem_init(&sem_receive, 0, 0);
    // sem_init(&sem_free, 0, 0);
    // sem_init(&sem_kernel, 0, 1);
    atomic_init(&queue.head, 0);
    atomic_init(&queue.tail, 0);
    atomic_init(&free_queue.head, 0);
    atomic_init(&free_queue.tail, 0);

    // TEST HERE ----------------------------------------------------------------------------------------
    while (1) {
        // exe_time += 1;
        /* 15ms time interval */
        // clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep_time, &rem_time);
        /*
         * secure current buffer,
         * after that, the variable *buf should be set by the kernel
         */
        unsigned long buffer_addr = 0;
        
#ifndef TEST
        buffer_addr = ((unsigned long)ioctl(fd, HHKR_SECURE_BUF, 0) << 12);         
#endif
        if (buffer_addr) {
#ifdef TEST
            printf("SHOULD NOT REACH in TEST! secured buffer: 0x%lx (buf: 0x%lx).\n", buffer_addr, buf->user_addr);
#endif
            /* a buffer is secured, we send to the receive queue */
            while (1) {
                int old_tail = atomic_load(&queue.tail);
                int next_tail = (old_tail + 1) % Q_SIZE;
                /* queue is full, wait */
                if (next_tail == atomic_load(&queue.head)) {
                    pthread_mutex_lock(&mutex_queue);
                    pthread_cond_wait(&cond_nonfull, &mutex_queue);
                    pthread_mutex_unlock(&mutex_queue);
                    continue;
                }
                /* update queue tail */
                if (atomic_compare_exchange_weak(&queue.tail, &old_tail, next_tail)) {
                    hhkr_buf_t *queue_buf = &queue.buffers[old_tail];
                    queue_buf->phys_addr = buf->phys_addr;
                    queue_buf->user_addr = buf->user_addr;
                    queue_buf->cur_pos = buf->cur_pos;
                    queue_buf->obs_type = buf->obs_type;
                    queue_buf->length = buf->length;

                    /* notify the receiver that the message queue is not empty */
                    pthread_cond_signal(&cond_nonempty);
                    break;
                }
            }
        }
        // // count time
        // clock_gettime(CLOCK_MONOTONIC, &cur_time);
        // if (prev_time.tv_nsec)
        //     time_diff = (cur_time.tv_sec - prev_time.tv_sec) * 1e3 + 
        //                 (cur_time.tv_nsec - prev_time.tv_nsec) / 1e6;
        // prev_time = cur_time;
    } 
    //----------------------------------------------------------------------------------------------------------------------------


    // pthread_t timer_t, receiver_t, store_t, ctrl_t;
    
    // if (pthread_create(&timer_t, NULL, timer_thread, NULL) != 0) {
    //     perror("Error.\n");
    //     return 1;
    // }

    // if (pthread_create(&receiver_t, NULL, receiver_thread, NULL) != 0) {
    //     perror("Error.\n");
    //     return 1;
    // }
    // // if (pthread_create(&store_t, NULL, store_thread, NULL) != 0) {
    // //     perror("Error.\n");
    // //     return 1;
    // // }
    // if (pthread_create(&ctrl_t, NULL, control_thread, NULL) != 0) {
    //     perror("Error.\n");
    //     return 1;
    // }


    // pthread_join(timer_t, NULL);

#ifndef TEST
    pthread_join(receiver_t, NULL);
    // pthread_join(store_t, NULL);
    pthread_join(ctrl_t, NULL);
#endif
    // sem_destroy(&sem_receive);
    // sem_destroy(&sem_free);
    // sem_destroy(&sem_kernel);
    pthread_cond_destroy(&cond_nonempty);
    pthread_cond_destroy(&cond_nonfull);
    pthread_cond_destroy(&cond_free_queue_nonempty);
    pthread_cond_destroy(&cond_free_queue_nonfull);

    close(fd);
    return 0;
}
