// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <asm/unistd.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <time.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "bpf.h"
#include "libbpf.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

#define GRN     "\033[1;32m"
#define RESET   "\033[0;0m"
#define LOG_INFO(fmt, ...) \
            printf(GRN fmt RESET, ##__VA_ARGS__);\
            printf("\n");

#define HHKR_DEV_PATH             "/dev/hitchhiker-ctl"
#define HHKR_ACT_INTERVAL_POLICY  _IOW('m', 6, unsigned int)
#define HHKR_CLR_INTERVAL_POLICY  _IOW('m', 8, unsigned int)
#define HHKR_MEMCPY_MODE        _IOW('m', 13, unsigned int)

typedef struct {
    char str[16];
} string_filter_t;

static int exe_time = 0;

static void read_trace_pipe(void) {
	int trace_fd;
    struct timespec start;
    if (exe_time) { /* set time-interval */
        if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
            perror("clock_gettime failed");
            return;
        }
    }

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
        if (exe_time) {
            struct timespec current;
            if (clock_gettime(CLOCK_MONOTONIC, &current) != 0) {
                perror("clock_gettime failed");
                return;
            }
            if (current.tv_sec >= start.tv_sec + exe_time) {
                break;
            }
        }

		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

static void print_help(char* progname) {
    printf(
        "Usage: %s [OPTIONS]\n"
        "\n"
        "OPTIONS:\n"
        "  --time,      -t [SECONDS]        Run the hitchhiker observability logger program for [SECONDS] seconds.\n"
        "  --interval,  -i [MICROSECONDS]   Set the hitchhiker secure policy interval to [MICROSECONDs] us (useless in test).\n"
        "  --only-comm, -c [STRING]         Only trace the program named [STRING].\n"
        "  --only-pid,  -p [PID]            Only trace the process with pid [PID].\n"
        "  --eval,      -e                  Run in evaluation mode.\n"
        "  --hhkrd,     -d                  Enable Hitchhiker daemon (useless in this test mode).\n"
        "  --omnilog,   -m                  Enable OmniLog mode (useless in this test mode).\n"
        "  --memcpy,    -x                  Enable el3-memcpy mode for buffer protection (useless in this test mode).\n"
        "  --audit-log, -s                  Enable syscall log.\n"
        "  --app-log,   -a                  Enable app log.\n"
        "  --net-log,   -n                  Enable net log.\n"
        "  --help,      -h                  Show this help message and exit.\n",
        progname
    );
}

static int open_map_to_fd(struct bpf_object *obj, char *mapname) {
    int fd = bpf_object__find_map_fd_by_name(obj, mapname);
    if (fd < 0) {
        printf("Failed to find map `%s`.\n", mapname);
        bpf_object__close(obj);
        exit(-1);
    }
    return fd;
}

static struct bpf_program *get_bpf_program(struct bpf_object *obj, char *title) {
    struct bpf_program *prog;
    prog = bpf_object__find_program_by_title(obj, title);
    if (!prog) {
        printf("Failed to find program `%s`.\n", title);
        bpf_object__close(obj);
        exit(-1);
    }
    return prog;
}

struct bpf_object *obj = NULL;
int eval_flag = 0;
int data_count_mapfd = -1;

int hhkr_fd;
/* default 1ms secure interval */
int default_sec_interval = 1000;

/* by default use GPT */
int el3_memcpy_mode = 0;

static void sig_handler(int sig_num) {
    signal(SIGINT, sig_handler);  
    /* print out statistics */
    if (eval_flag) {
        /* get statistics */
        int audit_count, app_count, net_count;
        int key = 0;
        bpf_map_lookup_elem(data_count_mapfd, &key, &audit_count);
        key = 1;
        bpf_map_lookup_elem(data_count_mapfd, &key, &app_count);
        key = 2;
        bpf_map_lookup_elem(data_count_mapfd, &key, &net_count);
        printf("=== Evaluation Statistics: time: %ds, audit_entries: %d, app_entries: %d, net_entries: %d.===\n",
                exe_time, audit_count, app_count, net_count);
    } else {
        printf("ctrl + c triggered.\n");
    }
    ioctl(hhkr_fd, HHKR_CLR_INTERVAL_POLICY, default_sec_interval);
    if (el3_memcpy_mode) /* reset */
            ioctl(hhkr_fd, HHKR_MEMCPY_MODE, 0);
    if (obj)
        bpf_object__close(obj);
    exit(1);
}

#define HHKRD_MASK  (1 << 0)
#define AUDIT_MASK  (1 << 1)
#define APP_MASK    (1 << 2)
#define NET_MASK    (1 << 3)
#define OMNI_MASK   (1 << 4)

int main(int argc, char *argv[]) {
    /* command line parameters */
    int only_trace_pid = 0;
    char *only_trace_prog = NULL;
    
    // char *only_trace_prog = NULL;
    int obs_option_mask = 0;

    int key = 0, pid, val = 1;
    pid = (int)getpid();

    /* Set the SIGINT (Ctrl+C) signal handler to our signalHandler function */
    signal(SIGINT, sig_handler);

    struct option long_options[] = {
        {"time", optional_argument, NULL, 't'},
        {"interval", optional_argument, NULL, 'i'},
        {"only-comm", optional_argument, NULL, 'c'},
        {"only-pid", optional_argument, NULL, 'p'},
        {"eval", no_argument, NULL, 'e'},
        {"hhkrd", no_argument, NULL, 'd'},
        {"omnilog", no_argument, NULL, 'm'},
        {"memcpy", no_argument, NULL, 'x'},
        {"audit-log", no_argument, NULL, 's'},
        {"app-log", no_argument, NULL, 'a'},
        {"net-log", no_argument, NULL, 'n'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    int c;

    while ((c = getopt_long(argc, argv, "i::t::c::p::adehmns", long_options, &option_index)) != -1) {
        switch (c) {
            case 't':
                if(optarg) {
                    exe_time = atoi(optarg);
                    LOG_INFO("Set exe time: %ds.", exe_time);
                }
                else
                    exe_time = 0; 
                break;
            case 'i':
                if (optarg)
                    default_sec_interval = atoi(optarg);
                break;
            case 'c':
                only_trace_prog = optarg ? optarg : NULL;
                LOG_INFO("Set only_trace_prog: %s.", only_trace_prog);
                break;
            case 'd':
                LOG_INFO("Hitchhiker daemon: on.");
                obs_option_mask |= HHKRD_MASK;
                break;
            case 'm':
                LOG_INFO("OmniLog mode: on.");
                obs_option_mask |= OMNI_MASK;
                break;
            case 'x':
                LOG_INFO("EL3-memcpy mode: on.");
                el3_memcpy_mode = 1;
                break;
            case 's':
                obs_option_mask |= AUDIT_MASK;
                LOG_INFO("Syscall log: on.");
                break;
            case 'a':
                obs_option_mask |= APP_MASK;
                LOG_INFO("App log: on.");
                break;
            case 'n':
                obs_option_mask |= NET_MASK;
                LOG_INFO("Net log: on.");
                break;
            case 'p':
                if (optarg) {
                    only_trace_pid = atoi(optarg);
                    LOG_INFO("Set only_trace_pid: %d.", only_trace_pid);
                }
                break;
            case 'e':
                eval_flag = 1;
                LOG_INFO("Evaluation mode: on.");
                break;
            case '?':
                if (optopt == 0) { // log option fault
                    printf("Invalid long option: %s\n", argv[optind-1]);
                } else { // short option fault
                    printf("Invalid option: -%c\n", optopt);
                }
            case 'h':
            default:
                print_help(argv[0]);
                return 1;
        }
    }

    if ((hhkr_fd = open(HHKR_DEV_PATH, O_RDWR, 0)) <= 0) {
        perror("Error.\n");
        return 1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &r);
    
    int err, prog_fd;

    const char *file = "./hitchhiker_test_kern.o";
    // load programs and maps
    err = bpf_prog_load(file, BPF_PROG_TYPE_UNSPEC, &obj, &prog_fd);
    if (err) {
        char bf[128];
		libbpf_strerror(err, bf, sizeof(bf));
		printf("bpf: load objects failed: err=%d: (%s)\n", err, bf);
        bpf_object__close(obj);
        return 1;
    }
    // get programs 
    struct bpf_program *prog1 = get_bpf_program(obj, "raw_tracepoint/sys_enter");
    struct bpf_program *prog2 = get_bpf_program(obj, "raw_tracepoint/sys_exit");
    // struct bpf_program *prog3 = get_bpf_program(obj, "kprobe/tcp_sendmsg");
    // struct bpf_program *prog4 = get_bpf_program(obj, "kprobe/tcp_recvmsg");

    // get config_map (setup auditor pid)
    int config_map_fd = open_map_to_fd(obj, "config_map");
    bpf_map_update_elem(config_map_fd, &key, &pid, BPF_ANY);
    
    // get comm_filter_map
    int comm_filter_mapfd = open_map_to_fd(obj, "comm_filter_map");

    // set comm_filter_map: td-thread (hhkrd receiver)
    bpf_map_update_elem(comm_filter_mapfd, "hhkrd", &val, BPF_ANY);

    /* update app_log_map */
    int app_log_mapfd = open_map_to_fd(obj, "app_log_map");
    string_filter_t nginx_key = {.str = "nginx"};
    bpf_map_update_elem(app_log_mapfd, &nginx_key, "/data/androdeb/debian/var/log/nginx/", BPF_ANY);
    string_filter_t apache_key = {.str = "apache2"};
    bpf_map_update_elem(app_log_mapfd, &apache_key, "/data/androdeb/debian/var/log/apache2/", BPF_ANY);
    string_filter_t redis_key = {.str = "redis-server"};
    bpf_map_update_elem(app_log_mapfd, &redis_key, "/data/androdeb/debian/var/log/redis/redis-server.log", BPF_ANY);
    string_filter_t memcached_key = {.str = "memcached"};
    bpf_map_update_elem(app_log_mapfd, &memcached_key, "/data/androdeb/debian/var/log/memcached.log", BPF_ANY);
    /* sqlite no log */
    /* mysql */
    string_filter_t mysql_key = {.str = "mysqld"};
    bpf_map_update_elem(app_log_mapfd, &mysql_key, "/data/androdeb/debian/var/log/mysql/", BPF_ANY);
    string_filter_t firefox_key = {.str = "firefox-esr"};
    bpf_map_update_elem(app_log_mapfd, &firefox_key, "/data/androdeb/debian/var/log/firefox/", BPF_ANY);
    /* get pid_only_map if set onlytrace pid */
    int filter_options = 0;
    if (only_trace_pid) {
        filter_options |= 0x1;

        int only_trace_pid_mapfd = open_map_to_fd(obj, "pid_only_map");
        key = 0, val = 1;
        bpf_map_update_elem(only_trace_pid_mapfd, &only_trace_pid, &val, BPF_ANY);
    }
    /* onlytrace comm */
    if (only_trace_prog != NULL) {
        filter_options |= 0x2;

        int only_trace_comm_mapfd = open_map_to_fd(obj, "comm_only_map");
        val = 1;
        string_filter_t comm_key = {.str = 0};
        strcpy(comm_key.str, only_trace_prog);
        bpf_map_update_elem(only_trace_comm_mapfd, &comm_key, &val, BPF_ANY);
    }

    /* set FILTER_OPTIONS in config_map */
    key = 1;
    bpf_map_update_elem(config_map_fd, &key, &filter_options, BPF_ANY);
    
    /* set LOGGER_OPTIONS in config_map */
    key = 2;
    val = obs_option_mask;
    bpf_map_update_elem(config_map_fd, &key, &val, BPF_ANY);

    /* update log data count */
    data_count_mapfd = open_map_to_fd(obj, "log_count_map");
    val = 0;
    for (key = 0; key < 3; key++)
        bpf_map_update_elem(data_count_mapfd, &key, &val, BPF_ANY);


    /* activate secure policy from the logger side! */
    if (obs_option_mask & HHKRD_MASK) {
        printf("Hitchhiker policy interval: %dus.\n", default_sec_interval);
        ioctl(hhkr_fd, HHKR_ACT_INTERVAL_POLICY, default_sec_interval);
        if (el3_memcpy_mode)
            ioctl(hhkr_fd, HHKR_MEMCPY_MODE, 1);
    }

    // attach programs
    bpf_program__attach_raw_tracepoint(prog1, "sys_enter");
    bpf_program__attach_raw_tracepoint(prog2, "sys_exit");

    /* don't use kprobe. also use static tracepoint */
    // if (obs_option_mask & NET_MASK) {
    //     bpf_program__attach_kprobe(prog3, 0, "tcp_sendmsg");
    //     bpf_program__attach_kprobe(prog4, 0, "tcp_recvmsg");
    // }

	// read trace_pipe
    read_trace_pipe();
    /* time to stop! */
    /* time to stop! */
    if (obs_option_mask & HHKRD_MASK) {
        ioctl(hhkr_fd, HHKR_CLR_INTERVAL_POLICY, default_sec_interval);
        if (el3_memcpy_mode) /* reset */
            ioctl(hhkr_fd, HHKR_MEMCPY_MODE, 0);
    }
    if (eval_flag) {
        /* get statistics */
        int audit_count, app_count, net_count;
        key = 0;
        bpf_map_lookup_elem(data_count_mapfd, &key, &audit_count);
        key = 1;
        bpf_map_lookup_elem(data_count_mapfd, &key, &app_count);
        key = 2;
        bpf_map_lookup_elem(data_count_mapfd, &key, &net_count);
        printf("=== Evaluation Statistics: time: %ds, audit_entries: %d, app_entries: %d, net_entries: %d.===\n",
                exe_time, audit_count, app_count, net_count);
    }

    bpf_object__close(obj);  
	return 0;
}
