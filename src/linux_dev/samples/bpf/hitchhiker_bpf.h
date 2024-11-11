#include "bpf_helpers.h"
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/mount.h>

#include <linux/dcache.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/stat.h>
#include <uapi/linux/socket.h>
#include "bpf_endian.h"
#include <linux/ptrace.h>

// BPF MAP MACROS --------------------------------------------------------
#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct bpf_map_def SEC("maps") _name={                          \
        .type = _type,                                              \
        .key_size = sizeof(_key_type),                              \
        .value_size = sizeof(_value_type),                          \
        .max_entries = _max_entries,                                \
    };                                                              \

#define BPF_MAP_HASH(_name, _key_type, _value_type)                 \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240)

#define BPF_MAP_LRU_HASH(_name, _key_type, _value_type)             \
    BPF_MAP(_name, BPF_MAP_TYPE_LRU_HASH, _key_type, _value_type, 10240)

#define BPF_MAP_PERCPU_ARRAY(_name, _value_type, _max_entries)      \
    BPF_MAP(_name, BPF_MAP_TYPE_PERCPU_ARRAY, u32, _value_type, _max_entries)

#define BPF_MAP_ARRAY(_name, _value_type, _max_entries)             \
    BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries)

#define BPF_MAP_PROG_ARRAY(_name, _max_entries)                     \
    BPF_MAP(_name, BPF_MAP_TYPE_PROG_ARRAY, u32, u32, _max_entries)

#define READ_KERN(ptr)                                              \
    ({                                                              \
        typeof(ptr) _p;                                             \
        __builtin_memset((void *)&_p, 0, sizeof(_p));               \
        bpf_probe_read((void *)&_p, sizeof(_p), (void *)&ptr);      \
        _p;                                                         \
    })

#define MAX_PERCPU_BUFSIZE      (1 << 15) // set by the kernel as an upper bound
#define MAX_STRING_SIZE         4096      // same as PATH_MAX
#define TASK_COMM_LEN           16
#define MAX_BUFFERS             1
#define MAX_PATH_COMPONENTS     20

typedef struct {
    char str[16];
} string_filter_t;

typedef struct {
    char str[64];
}string_path_t;

typedef struct simple_buf {
    u8 buf[MAX_PERCPU_BUFSIZE];
}buf_t;

typedef struct hitchhiker_event_context {
    unsigned long ts;
    int pid;
    int tid;
    int uid;
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

// AUDIT LOG DATA STRUCTS ------------------------------------------------

typedef struct hitchhiker_audit_log {
    hhkr_event_ctx_t ctx;
    hhkr_syscall_data_t syscall_data;
} hhkr_audit_log_t;

// SYSCALLS --------------------------------------------------------------
#define SYS_EXIT    		0x5d
#define SYS_EXIT_GROUP 		0x5e
#define SYS_RT_SIGRETURN 	0x8b
#define SYS_WRITE			0x40




// KERNEL PRIVATE INCLUDES -------------------------------------------------------

// by pahole /path/to/vmlinux > vmlinux.h
struct mount {
	struct hlist_node          mnt_hash;             /*     0    16 */
	struct mount *             mnt_parent;           /*    16     8 */
	struct dentry *            mnt_mountpoint;       /*    24     8 */
	struct vfsmount            mnt;                  /*    32    24 */

	/* XXX last struct has 4 bytes of padding */

	union {
		struct callback_head mnt_rcu __attribute__((__aligned__(8))); /*    56    16 */
		struct llist_node  mnt_llist;            /*    56     8 */
	} __attribute__((__aligned__(8)));               /*    56    16 */
	/* --- cacheline 1 boundary (64 bytes) was 8 bytes ago --- */
	struct mnt_pcp *           mnt_pcp;              /*    72     8 */
	struct list_head           mnt_mounts;           /*    80    16 */
	struct list_head           mnt_child;            /*    96    16 */
	struct list_head           mnt_instance;         /*   112    16 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	const char  *              mnt_devname;          /*   128     8 */
	struct list_head           mnt_list;             /*   136    16 */
	struct list_head           mnt_expire;           /*   152    16 */
	struct list_head           mnt_share;            /*   168    16 */
	struct list_head           mnt_slave_list;       /*   184    16 */
	/* --- cacheline 3 boundary (192 bytes) was 8 bytes ago --- */
	struct list_head           mnt_slave;            /*   200    16 */
	struct mount *             mnt_master;           /*   216     8 */
	struct mnt_namespace *     mnt_ns;               /*   224     8 */
	struct mountpoint *        mnt_mp;               /*   232     8 */
	union {
		struct hlist_node  mnt_mp_list;          /*   240    16 */
		struct hlist_node  mnt_umount;           /*   240    16 */
	};                                               /*   240    16 */
	/* --- cacheline 4 boundary (256 bytes) --- */
	struct list_head           mnt_umounting;        /*   256    16 */
	struct fsnotify_mark_connector * mnt_fsnotify_marks; /*   272     8 */
	__u32                      mnt_fsnotify_mask;    /*   280     4 */
	int                        mnt_id;               /*   284     4 */
	int                        mnt_group_id;         /*   288     4 */
	int                        mnt_expiry_mark;      /*   292     4 */
	struct hlist_head          mnt_pins;             /*   296     8 */
	struct hlist_head          mnt_stuck_children;   /*   304     8 */

	/* size: 312, cachelines: 5, members: 27 */
	/* paddings: 1, sum paddings: 4 */
	/* forced alignments: 1 */
	/* last cacheline: 56 bytes */
};