#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "hitchhiker_bpf.h"

#define ENABLE_AUDIT_LOG
#define ENABLE_APP_LOG
// EBPF MAPS ----------------------------------------------

/* (logger_pid, FILTER_OPTIONS, NULL) 
 * FILTER_OPTIONS:  bit[0]: activate only trace pid?
 *                  bit[1]: activate only trace comm?
 * 
 * LOGGER_OPTIONS:  bit[0]: enable hhkrd?
 *                  bit[1]: enable AUDIT_LOG?
 *                  bit[2]: enable APP_LOG?
 *                  bit[3]: enable NET_LOG?
 *                  bit[4]: enable omnilog?
 */
BPF_MAP_ARRAY(config_map, u32, 3);                      // currently [CONFIG_AUDITER_PID, FILTER_OPTIONS, LOGGER_OPTIONS]
/* comm filter map to filter out programs by pid for tracing */
BPF_MAP_HASH(pid_filter_map, u32, u32);                 // pid filter map [pid: filter_out?]
/* comm filter map to filter out programs by name for tracing */
BPF_MAP_HASH(comm_filter_map, string_filter_t, u32);    // comm filter map [comm: filter_out?]

/* only trace program by it's pid */
BPF_MAP_HASH(pid_only_map, u32, u32);             // pid only map [pid: only?] 
/* only trace porgram by it's comm name */          
BPF_MAP_HASH(comm_only_map, string_filter_t, u32); // comm only map [comm: only?]

BPF_MAP_HASH(app_log_map, string_filter_t, string_path_t);  // application log path map [comm: app_log_path]

BPF_MAP_HASH(hhkr_audit_log_map, u32, hhkr_audit_log_t);   // persist syscall data (tid -> syscall_data)

/* buf map used for string matching */
#define PATH_BUF_IDX     0
BPF_MAP_PERCPU_ARRAY(bufs_off, u32, MAX_BUFFERS);           // offsets to percpu global bufs
BPF_MAP_PERCPU_ARRAY(bufs, buf_t, MAX_BUFFERS);             // percpu global bufs

/* map to count the number of log entries (audit_count, app_count, net_count) */
BPF_MAP_ARRAY(log_count_map, u32, 3);


static __always_inline void update_log_count(u32 key) {
    u32 mpkey = key;
    u32 *count = bpf_map_lookup_elem(&log_count_map, &mpkey);
    if (count) {
        (*count)++;
    }
    return;
}

/* =========================== Program State ==================================== */
#define HHKRD_MASK  (1 << 0)
#define AUDIT_MASK  (1 << 1)
#define APP_MASK    (1 << 2)
#define NET_MASK    (1 << 3)
#define OMNI_MASK   (1 << 4)

static int __enable_hhkrd = -1;
static int __enable_omnilog = -1;
static int __enable_audit = -1;
static int __enable_app = -1;
static int __enable_net = -1;

static __always_inline int enable_hhkrd(void) {
    if (__enable_hhkrd != -1)
        return __enable_hhkrd;

    u32 key = 2, *val;
    val = bpf_map_lookup_elem(&config_map, &key);
    if (val) {
        __enable_hhkrd = (*val) & HHKRD_MASK;
    } else {
        __enable_hhkrd = 0;
    }
    return __enable_hhkrd;
}

static __always_inline int enable_omnilog(void) {
    if (__enable_omnilog != -1)
        return __enable_omnilog;

    u32 key = 2, *val;
    val = bpf_map_lookup_elem(&config_map, &key);
    if (val) {
        __enable_omnilog = (*val) & OMNI_MASK;
    } else {
        __enable_omnilog = 0;
    }
    return __enable_omnilog;
}

static __always_inline int enable_audit_log(void) {
    if (__enable_audit != -1)
        return __enable_audit;

    u32 key = 2, *val;
    val = bpf_map_lookup_elem(&config_map, &key);
    if (val) {
        __enable_audit = (*val) & AUDIT_MASK;
    } else {
        __enable_audit = 0;
    }
    return __enable_audit;
}

static __always_inline int enable_app_log(void) {
    if (__enable_app != -1)
        return __enable_app;

    u32 key = 2, *val;
    val = bpf_map_lookup_elem(&config_map, &key);
    if (val) {
        __enable_app = (*val) & APP_MASK;
    } else {
        __enable_app = 0;
    }
    return __enable_app;
}

static __always_inline int enable_net_log(void) {
    if (__enable_net != -1)
        return __enable_net;

    u32 key = 2, *val;
    val = bpf_map_lookup_elem(&config_map, &key);
    if (val) {
        __enable_net = (*val) & NET_MASK;
    } else {
        __enable_net = 0;
    }
    return __enable_net;
}
/* =========================== Program State END ==================================== */

static __always_inline int hhkr_strncmp(const char *cs, const char *ct, int size)
{
    int len = 0;
    unsigned char c1, c2;
    for (len = 0; len < size; len++) {
        c1 = *cs++;
        c2 = *ct++;
        if (c1 != c2) return c1 < c2 ? -1 : 1;
        if (!c1 || !c2) break;
     }
     return 0;
}

static __always_inline void debug_print(hhkr_audit_log_t *audit_data) {
    bpf_printk("[Syscall Log] prog: %s, tid: %u, ts: %llu.\n", 
                audit_data->ctx.comm, audit_data->ctx.tid, audit_data->ctx.ts);
    // bpf_printk("      |======> uid: %u, ts: %llu.\n", audit_data->ctx.uid, audit_data->ctx.ts);
    // bpf_printk("      |====> sysid: %u, arg0: 0x%lx, arg1: 0x%lx.\n", 
    //            audit_data->syscall_data.syscall_id, audit_data->syscall_data.args.args[0], audit_data->syscall_data.args.args[1]);
    // bpf_printk("   >arg2: 0x%lx, arg3: 0x%lx, arg4: 0x%lx.\n", 
    //             audit_data->syscall_data.args.args[2], audit_data->syscall_data.args.args[3], audit_data->syscall_data.args.args[4]);
    // bpf_printk("      |===> return: 0x%lx. datasz: 0x%lx\n", audit_data->syscall_data.ret, sizeof(*audit_data));
}

static __always_inline u32 get_config_map(u32 k) {
    u32 key = k, *config_val = NULL;
    config_val = bpf_map_lookup_elem(&config_map, &key);
    if (config_val == NULL) {
        return 0;
    }
    return *config_val;
}

static __always_inline u32 hhkr_logger_get_pid(void) {
    return (u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline u32 hhkr_logger_get_tid(void) {
    u64 id = bpf_get_current_pid_tgid();
    return (u32)id;
}

static __always_inline buf_t *get_buf(int idx) {
    return bpf_map_lookup_elem(&bufs, &idx);
}

static __always_inline void set_buf_off(int buf_idx, u32 new_off)
{
    bpf_map_update_elem(&bufs_off, &buf_idx, &new_off, BPF_ANY);
}

static __always_inline struct dentry *get_mnt_root_ptr_from_vfsmnt(struct vfsmount *vfsmnt) {
    return READ_KERN(vfsmnt->mnt_root);
}

static __always_inline struct dentry *get_d_parent_ptr_from_dentry(struct dentry *dentry) {
    return READ_KERN(dentry->d_parent);
}

static __always_inline struct qstr get_d_name_from_dentry(struct dentry *dentry)
{
    return READ_KERN(dentry->d_name);
}

static __always_inline int check_fd_type(struct file *file, u16 type) {
    umode_t i_mode;
    struct inode *inode = READ_KERN(file->f_inode);
    i_mode = READ_KERN(inode->i_mode);

    if ((i_mode & S_IFMT) == type)
        return 1;
    return 0;
}

static __always_inline struct file *fd_to_file(struct task_struct *task, int fd_num) {
    struct file **fdd = NULL;
    struct file *f = NULL;
    // struct path file_path;
    struct files_struct *files = READ_KERN(task->files);
    struct fdtable *fdt = READ_KERN(files->fdt);
    fdd = READ_KERN(fdt->fd);

    f = READ_KERN(fdd[fd_num]);
    return f;
}

static __always_inline bool is_fd_sock(struct file *file) {
    /* Determine whether a fd is socket
     * See: https://lists.kernelnewbies.org/pipermail/kernelnewbies/2011-November/003830.html
     */
    // umode_t file->f_inode->i_mode
    umode_t i_mode;
    struct inode *inode = READ_KERN(file->f_inode);
    i_mode = READ_KERN(inode->i_mode);
    // READ_KERN_BUNCH(&i_mode, file, f_inode, i_mode);
    return S_ISSOCK(i_mode);
}

static inline struct mount *real_mount(struct vfsmount *mnt)
{
    return container_of(mnt, struct mount, mnt);
}

static __always_inline void *get_path_str(struct path *path) {
    struct path f_path;
    bpf_probe_read(&f_path, sizeof(struct path), path);
    char slash = '/';
    int zero = 0;
    struct dentry *dentry = f_path.dentry;
    struct vfsmount *vfsmnt = f_path.mnt;
    struct mount *mnt_parent_p;

    struct mount *mnt_p = real_mount(vfsmnt);
    bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);

    u32 buf_off = (MAX_PERCPU_BUFSIZE >> 1);
    struct dentry *mnt_root;
    struct dentry *d_parent;
    struct qstr d_name;
    unsigned int len;
    unsigned int off;
    int sz;

    // Get per-cpu string buffer
    buf_t *string_p = get_buf(PATH_BUF_IDX);
    // buf_t strbuf = {};
    // buf_t *string_p = &strbuf;
    if (string_p == NULL) {
        bpf_printk("get_buf failed\n");
        return NULL;
    }

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        mnt_root = get_mnt_root_ptr_from_vfsmnt(vfsmnt);
        d_parent = get_d_parent_ptr_from_dentry(dentry);
        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt_parent_p) {
                // We reached root, but not global root - continue with mount point path
                bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
                bpf_probe_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
                vfsmnt = &mnt_p->mnt;
                continue;
            }
            // Global root - path fully parsed
            break;
        }
        // Add this dentry name to path
        d_name = get_d_name_from_dentry(dentry);
        len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);
        off = buf_off - len;

        // Is string buffer big enough for dentry name?
        sz = 0;
        if (off <= buf_off) { // verify no wrap occurred
            len = len & ((MAX_PERCPU_BUFSIZE >> 1) - 1);
            sz = bpf_probe_read_str(
                &(string_p->buf[off & ((MAX_PERCPU_BUFSIZE >> 1) - 1)]), len, (void *) d_name.name);
        } else
            break;
        if (sz > 1) {
            buf_off -= 1; // remove null byte termination with slash sign
            bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
            buf_off -= sz - 1;
        } else {
            // If sz is 0 or 1 we have an error (path can't be null nor an empty string)
            break;
        }
        dentry = d_parent;
    }

    if (buf_off == (MAX_PERCPU_BUFSIZE >> 1)) {
        // memfd files have no path in the filesystem -> extract their name
        buf_off = 0;
        d_name = get_d_name_from_dentry(dentry);
        bpf_probe_read_str(&(string_p->buf[0]), MAX_STRING_SIZE, (void *) d_name.name);
    } else {
        // Add leading slash
        buf_off -= 1;
        bpf_probe_read(&(string_p->buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)]), 1, &slash);
        // Null terminate the path string
        bpf_probe_read(&(string_p->buf[(MAX_PERCPU_BUFSIZE >> 1) - 1]), 1, &zero);
    }

    set_buf_off(PATH_BUF_IDX, buf_off);
    return &string_p->buf[buf_off];
}

static __always_inline int debug_print_fd(u64 fd_num, struct task_struct *task) {
    // struct path file_path = task->files->fdt->fd[fd_num]->f_path;
    struct file **fdd = NULL;
    // struct path file_path;
    struct files_struct *files = READ_KERN(task->files);
    struct fdtable *fdt = READ_KERN(files->fdt);
    fdd = READ_KERN(fdt->fd);

    // READ_KERN_BUNCH(&fdd, task, files, fdt, fd);
    struct file *f = READ_KERN(fdd[fd_num]);
    // socket
    if (is_fd_sock(f)) {
        // struct socket *f_socket = READ_KERN(f->private_data);
        // socket_state s_stat = READ_KERN(f_socket->state);
        // struct sock *f_sock = get_socket_sock(f_socket);
        // u16 sock_sk_family = get_sock_family(f_sock);
        // if (sock_sk_family == AF_INET) {
        //     net_conn_v4_t conn_detail = {};
        //     get_connection_from_sockv4(&conn_detail, f_sock);
        //     union {
        //         u32 ip;
        //         u_char byte[4];
        //     }itoch;
        //     itoch.ip = conn_detail.remote_address;
            
        //     char *sock_str = convert_to_ip_string(itoch.byte[0], itoch.byte[1], itoch.byte[2], itoch.byte[3]);
        //     bpf_printk("Operate on socket: <%s:%d>", sock_str, conn_detail.remote_port);
        // }
    }
    // normal file
    else {
        struct path file_path = READ_KERN(f->f_path);
        char * pname = get_path_str(&file_path);
        bpf_printk("Operate on file: %s", pname);
    }
    return 0;
}

static __always_inline char *fd_to_path(int fd_num, struct task_struct *task) {
    struct file **fdd = NULL;
    struct files_struct *files = READ_KERN(task->files);
    struct fdtable *fdt = READ_KERN(files->fdt);
    fdd = READ_KERN(fdt->fd);

    struct file *f = READ_KERN(fdd[fd_num]);
    if (is_fd_sock(f))
        return NULL;
    
    struct path file_path = READ_KERN(f->f_path);
    return (char *)get_path_str(&file_path);
}

/* ********************************* NETWORK TRAFFIC ************************************************** */

// static __always_inline char *convert_to_ip_string(u8 part1, u8 part2, u8 part3, u8 part4) {
//     int key = 0;
//     buf_t *buf_p = bpf_map_lookup_elem(&sock_dbg_buf, &key);
//     if (buf_p == NULL)
//         return 0;
//     bpf_snprintf(buf_p->buf, 20, "%u.%u.%u.%u", part1, part2, part3, part4);
//     return buf_p->buf;
// }

static __always_inline struct sock *get_socket_sock(struct socket *socket) {
    return READ_KERN(socket->sk);
}

static __always_inline u16 get_sock_family(struct sock *sk) {
    return READ_KERN(sk->sk_family);
}

static __always_inline struct inet_sock *__inet_sk(const struct sock *sk) {
    return (struct inet_sock *)sk;
}

static __always_inline u32 get_inet_sock_rcv_saddr(struct inet_sock *inet_sk) {
    return READ_KERN(inet_sk->inet_rcv_saddr);
}

static __always_inline u32 get_inet_sock_saddr(struct inet_sock *inet_sk) {
    return READ_KERN(inet_sk->inet_saddr);
}

static __always_inline u16 get_inet_sock_sport(struct inet_sock *inet_sk) {
    return READ_KERN(inet_sk->inet_sport);
}

static __always_inline u32 get_inet_sock_daddr(struct inet_sock *inet_sk) {
    return READ_KERN(inet_sk->inet_daddr);
}

static __always_inline u16 get_inet_sock_dport(struct inet_sock *inet_sk) {
    return READ_KERN(inet_sk->inet_dport);
}

static __always_inline u32 get_inet_sock_inet_num(struct inet_sock *inet_sk) {
    return READ_KERN(inet_sk->inet_num);
}

static __always_inline int get_connection_from_sockv4(hhkr_net_log_t *net_log, struct sock *sk) {
    struct inet_sock *inet = __inet_sk(sk);

    net_log->net_traffic.saddr = get_inet_sock_rcv_saddr(inet);
    net_log->net_traffic.lport = bpf_ntohs(get_inet_sock_inet_num(inet));
    
    net_log->net_traffic.daddr = get_inet_sock_daddr(inet);
    net_log->net_traffic.dport = get_inet_sock_dport(inet);

    return 0;
}


static __always_inline int hhkr_should_log(hhkr_event_ctx_t *ctx) {
    /* do not log the logger itself */
    if (ctx->pid == get_config_map(0)) {
        return 0;
    }
    /* do not log the receiver hhkrd */
    u32 *filter;
    filter = bpf_map_lookup_elem(&comm_filter_map, &ctx->comm);
    if (filter && *filter)
        return 0;
    
    /* get filter_options */
    u32 filter_options = get_config_map(1);
    /* if only_pid_map is set, we only log the corresponding pid */
    if (filter_options & 0x1){
        filter = bpf_map_lookup_elem(&pid_only_map, &ctx->pid);
        if (!(filter && *filter))
            return 0;
    }

    /* if only_comm_map is set, we only log the correspoinding command */
    if (filter_options & (0x2)) {
        filter = bpf_map_lookup_elem(&comm_only_map, &ctx->comm);
        if (!(filter && *filter))
            return 0;
    }
    
    return 1;
}

static __always_inline int hhkr_should_app_log(hhkr_audit_log_t *audit_data) {
    hhkr_event_ctx_t *ctx = &audit_data->ctx;
    hhkr_syscall_data_t *syscall_data = &audit_data->syscall_data;
    string_path_t *app_log_path = NULL;
    app_log_path = bpf_map_lookup_elem(&app_log_map, &ctx->comm);
    if (!app_log_path) {
        // bpf_printk("[debug] comm: %s no app_log_path.\n", ctx->comm);
        return 0;
    }
    // bpf_printk("[debug] comm applog path: %s.\n", app_log_path);
    uint sysid = syscall_data->syscall_id;
    if (sysid == SYS_WRITE) {
        int fd = syscall_data->args.args[0];
        char *path = fd_to_path(fd, ctx->task);
        // bpf_printk("path: %s.\n", path);
        char _s1[64];
        char _s2[64];
        bpf_probe_read_str(_s1, sizeof(_s1), path);
        bpf_probe_read_str(_s2, sizeof(_s2), app_log_path->str);

        int val = hhkr_strncmp(_s1, _s2, 64);
    
        if (val >= 0) 
            return 1;
    }
    return 0;
}

static __always_inline int hhkr_config_net_log(hhkr_audit_log_t *audit_data, hhkr_net_log_t *net_log) {
    hhkr_event_ctx_t *ctx = &audit_data->ctx;
    hhkr_syscall_data_t *syscall_data = &audit_data->syscall_data;
    int ret = 0;
    uint sysid = syscall_data->syscall_id;
    uint param1 = syscall_data->args.args[0];
    unsigned long param2 = syscall_data->args.args[1];
    struct file *f = NULL;

    if (sysid == SYS_READ || sysid == SYS_WRITE || sysid == SYS_READV || 
        sysid == SYS_WRITEV || sysid == SYS_PREADV || sysid == SYS_PWRITEV || 
        sysid == SYS_PREAD64 || sysid == SYS_PWRITE64) {
        f = fd_to_file(ctx->task, param1);
        if (is_fd_sock(f)) {
            ret = 1;
        }
    }

    if (sysid == SYS_sendto || sysid == SYS_recvfrom || sysid == SYS_sendmsg ||
        sysid == SYS_recvmsg || sysid == SYS_sendmmsg || sysid == SYS_recvmmsg) {
        f = fd_to_file(ctx->task, param1);
        if (!is_fd_sock(f)) {
            bpf_printk("Error! sysid: %d not socket!.\n", sysid);
        }
        ret = 1;
    }

    if (ret) {
        struct socket *f_socket = READ_KERN(f->private_data);
        struct sock *f_sock = get_socket_sock(f_socket);
        u16 sock_sk_family = get_sock_family(f_sock);
        if (sock_sk_family == AF_INET) {
            net_log->net_traffic.size = syscall_data->ret;
            /* set up connection information */
            get_connection_from_sockv4(net_log, f_sock);
            /* set up header information */
            if (sysid == SYS_READ || sysid == SYS_WRITE || sysid == SYS_sendto ||
                sysid == SYS_recvfrom) {
                // read from user buffer
                bpf_probe_read_user(&net_log->net_traffic.net_packet_data, 
                                    sizeof(net_log->net_traffic.net_packet_data), 
                                    (void *)param2);
            }
            else if (sysid == SYS_READV || sysid == SYS_WRITEV) {
                // read from user iovec
                void *base = READ_USER(((struct iovec *)param2)->iov_base);
                bpf_probe_read_user(&net_log->net_traffic.net_packet_data, 
                                    sizeof(net_log->net_traffic.net_packet_data), 
                                    (void *)base);
            }
        } else {
            ret = 0;
        }
    }   
    return ret;
}


static __always_inline int init_hhkr_event_ctx(hhkr_event_ctx_t *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    ctx->ts = bpf_ktime_get_ns();
    ctx->pid = id >> 32;     // kernel level tgid = user level pid
    ctx->tid = id;           // kernel level pid = user level tid
    ctx->uid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&ctx->comm, sizeof(ctx->comm));
    ctx->task = (struct task_struct *)bpf_get_current_task();
    return 0;
}


SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    u32 config_val;

    hhkr_audit_log_t hhkr_audit_data = {};
    init_hhkr_event_ctx(&hhkr_audit_data.ctx);
    if (!hhkr_should_log(&hhkr_audit_data.ctx)) {
        return 0;
    }

    uint sysid;
    hhkr_audit_data.syscall_data.syscall_id = sysid = ctx->args[1];

    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    hhkr_audit_data.syscall_data.args.args[0] = (unsigned long)READ_KERN(PT_REGS_PARM1(regs));
    hhkr_audit_data.syscall_data.args.args[1] = (unsigned long)READ_KERN(PT_REGS_PARM2(regs));
    hhkr_audit_data.syscall_data.args.args[2] = (unsigned long)READ_KERN(PT_REGS_PARM3(regs));
    hhkr_audit_data.syscall_data.args.args[3] = (unsigned long)READ_KERN(PT_REGS_PARM4(regs));
    hhkr_audit_data.syscall_data.args.args[4] = (unsigned long)READ_KERN(PT_REGS_PARM5(regs));

    /* save data to the map */
    if (sysid != SYS_EXIT && sysid != SYS_EXIT_GROUP && sysid != SYS_RT_SIGRETURN) { // no ret syscalls
        bpf_map_update_elem(&hhkr_audit_log_map, &hhkr_audit_data.ctx.tid, &hhkr_audit_data, BPF_ANY);
    }

    if (enable_audit_log()) {
        hhkr_audit_data.ctx.obs_type = 0;
        /* no-ret syscalls, just handle them. otherwise, we handle data in the 
         * sys_exit tracepoint
         */
        if (sysid == SYS_EXIT || sysid == SYS_EXIT_GROUP || sysid == SYS_RT_SIGRETURN) { // no ret syscalls
            // send value
            debug_print(&hhkr_audit_data);
            update_log_count(0);
        }
    }
    
    if (enable_app_log()) {
        if (hhkr_should_app_log(&hhkr_audit_data)) {
            hhkr_app_log_t app_log = {};
            app_log.ctx = hhkr_audit_data.ctx;
            app_log.ctx.obs_type = 1;
            bpf_probe_read_user(&app_log.app_log_data, sizeof(app_log.app_log_data), 
                                (void *)hhkr_audit_data.syscall_data.args.args[1]);
            if (!enable_hhkrd())
                bpf_printk("[App Log] RAW: %s.\n", &app_log.app_log_data);
                update_log_count(1);
        }
    }
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int tracepoint__raw_syscalls__sys_exit(struct bpf_raw_tracepoint_args * ctx) {
    hhkr_event_ctx_t event_ctx = {};
    init_hhkr_event_ctx(&event_ctx);
    if (!hhkr_should_log(&event_ctx)) {
        return 0;
    }

    /* fetch data from map */
    u32 tid = hhkr_logger_get_tid();
    hhkr_audit_log_t *hhkr_audit_data = bpf_map_lookup_elem(&hhkr_audit_log_map, &tid);
    if (!hhkr_audit_data) {
        // bpf_printk("Error: cannot find hhkr_audit_log_t data for tid %u.\n", tid);
        return 0;
    }
    /* syscall return val */
    uint retval = ctx->args[1];
    /* complete data */
    hhkr_audit_data->syscall_data.ret = retval;

    if (enable_audit_log()) {
        struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
        unsigned int sysid = READ_KERN(regs->syscallno);
        
        /* sanity check */
        if (sysid != hhkr_audit_data->syscall_data.syscall_id) {
            bpf_printk("Error: syscall id mismatch, %u != %u.\n", sysid, hhkr_audit_data->syscall_data.syscall_id);
            return 0;
        }
        
        debug_print(hhkr_audit_data);
        update_log_count(0);
    }   

    if (enable_net_log()) {
        hhkr_net_log_t hhkr_net_log = {};
        hhkr_net_log.ctx = hhkr_audit_data->ctx;
        hhkr_net_log.ctx.obs_type = 2;
        /* net log successfully traced */
        if (hhkr_config_net_log(hhkr_audit_data, &hhkr_net_log)) {
            /* net log successfully traced */
            bpf_printk("[NET LOG] testing now...\n");
            bpf_printk("[Net LOG] src_addr: 0x%x, dst_addr: 0x%x.\n", 
                hhkr_net_log.net_traffic.saddr, hhkr_net_log.net_traffic.daddr);
            bpf_printk("   |====> lport: %d, dport: %d, size: %u.\n", 
                hhkr_net_log.net_traffic.lport, hhkr_net_log.net_traffic.dport, hhkr_net_log.net_traffic.size);
            bpf_printk("   |====> header: %s\n", &hhkr_net_log.net_traffic.net_packet_data);
            update_log_count(2);
        }   
    }
    return 0;
}



SEC("kprobe/tcp_sendmsg")
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    
    hhkr_net_log_t hhkr_net_log = {};

    init_hhkr_event_ctx(&hhkr_net_log.ctx);
    if (!hhkr_should_log(&hhkr_net_log.ctx)) {
        return 0;
    }
    hhkr_net_log.ctx.obs_type = 2;

    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (void *)PT_REGS_PARM2(ctx);
    size_t size = READ_KERN(PT_REGS_PARM3(ctx));

    if (get_sock_family(sk) == AF_INET) {
        hhkr_net_log.net_traffic.size = size;
        get_connection_from_sockv4(&hhkr_net_log, sk);

        const struct iovec *iov = READ_KERN(msg->msg_iter.iov);
        void *base = READ_KERN(iov->iov_base);

        bpf_probe_read(&hhkr_net_log.net_traffic.net_packet_data, 
                        sizeof(hhkr_net_log.net_traffic.net_packet_data), base);
    }

    bpf_printk("[Net log] src_addr: 0x%x, dst_addr: 0x%x, size: %u.\n", 
                hhkr_net_log.net_traffic.saddr, hhkr_net_log.net_traffic.daddr, size);
    bpf_printk("   |====> lport: %d, dport: %d.\n", hhkr_net_log.net_traffic.lport, hhkr_net_log.net_traffic.dport);
    bpf_printk("   |====> header: %s\n", &hhkr_net_log.net_traffic.net_packet_data);
    update_log_count(2);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe__tcp_recvmsg(struct pt_regs *ctx) {
    
    hhkr_net_log_t hhkr_net_log = {};

    init_hhkr_event_ctx(&hhkr_net_log.ctx);
    if (!hhkr_should_log(&hhkr_net_log.ctx)) {
        return 0;
    }
    hhkr_net_log.ctx.obs_type = 2;
    
    struct sock *sk = (void *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (void *)PT_REGS_PARM2(ctx);
    size_t size = READ_KERN(PT_REGS_PARM3(ctx));

    if (get_sock_family(sk) == AF_INET) {
        hhkr_net_log.net_traffic.size = size;
        get_connection_from_sockv4(&hhkr_net_log, sk);

        const struct iovec *iov = READ_KERN(msg->msg_iter.iov);
        void *base = READ_KERN(iov->iov_base);

        bpf_probe_read(&hhkr_net_log.net_traffic.net_packet_data, 
                        sizeof(hhkr_net_log.net_traffic.net_packet_data), base);
    }

    bpf_printk("[Net log] src_addr: 0x%x, dst_addr: 0x%x, size: %u.\n", 
                hhkr_net_log.net_traffic.saddr, hhkr_net_log.net_traffic.daddr, size);
    bpf_printk("   |====> lport: %d, dport: %d.\n", hhkr_net_log.net_traffic.lport, hhkr_net_log.net_traffic.dport);
    bpf_printk("   |====> header: %s\n", &hhkr_net_log.net_traffic.net_packet_data);
    update_log_count(2);
    return 0;
}

char _license[] SEC("license") = "GPL";
// __u32 _version SEC("version") = 1; /* ignored by tracepoints, required by libbpf.a */