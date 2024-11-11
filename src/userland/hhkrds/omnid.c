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

// #define EVAL_MODE

#define QUIET
// #define SHOW_POLICY_TIME
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

static int fd = 0;


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


static int iloc = 0;
static void __debug_print_buffer(void *mbuf) {
    unsigned long user_addr = (unsigned long)mbuf;
    
    for (iloc; ; ) {
        hhkr_event_ctx_t *ctx = (hhkr_event_ctx_t *)(user_addr + iloc);
        /* no log */
        if (!ctx->ts) {
            // printf("nodata. buf_addr: 0x%lx, iloc: %d pid?: %d comm?:%s.\n", 
            //        user_addr, iloc, ctx->pid, ctx->comm);
            break;
        }
        /* syscall log */
        if (ctx->obs_type == 0) { 
            __debug_print_syscall_log((hhkr_audit_log_t *)(user_addr + iloc));
            iloc += sizeof(hhkr_audit_log_t);
        } 
        /* application log */
        else if(ctx->obs_type == 1) { 
            __debug_print_app_log((hhkr_app_log_t *)(user_addr + iloc));
            iloc += sizeof(hhkr_app_log_t);
        }
        else if (ctx->obs_type == 2) {
            __debug_print_net_log((hhkr_net_log_t *)(user_addr + iloc));
            iloc += sizeof(hhkr_net_log_t);
        }
        else {
            break;
        }
    }
}

struct timespec prev_time = {};
struct timespec cur_time = {}; // count time
double time_diff = 0;

void * omni_buf_d = 0;
int *omni_buf_d_s = NULL;


int main(int argc, char *argv[]) {
    unsigned long ret;
    printf("[hhkrd] hello from now-omnid...\n");
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
    ioctl(fd, HHKR_MMAP_BUF, 0);   // map log bufs

    /* mmap omni_buf_d */
    ret = (unsigned long)ioctl(fd, HHKR_MMAP_OMNI_BUF_D, 0);
    if (ret) {
        omni_buf_d = (void *)(ret << 12);
        omni_buf_d_s = (int *)(omni_buf_d + (1 << 20));  // 1MB start
        printf("<mmap omni_buf_d> address: 0x%lx, omni_buf_d_s (addr: 0x%lx): %d\n", 
               (unsigned long)omni_buf_d, (unsigned long)omni_buf_d_s, *omni_buf_d_s);
    }

    unsigned int w_size;

    /* ============================= event handling start ============================ */
    while (1) {
        /* check status */
        if (*omni_buf_d_s == 1) {
            /* omni_buf_d full, no need to flash... */
            *omni_buf_d_s = 0;
            iloc = 0;
        }
        /* process message */
#if !defined(QUIET)
        /* debug buffer content */
        __debug_print_buffer(omni_buf_d);
#endif
    }

    close(fd);
    return 0;
}
