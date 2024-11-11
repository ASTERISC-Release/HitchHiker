typedef struct hitchhiker_daemon_info {
    unsigned long gpt_id;  /* a.k.a., td_id */
    /* The base virtual address */
    unsigned long virt_addr;
    /* The base physical address */
    unsigned long phys_addr;
    /* Indicates allocated length. Each mmap(offset=0) will allocate a new segment and increase the length */
    unsigned long offset;
    /* total size */
    unsigned long length;
    /* trustd entry point */
    unsigned long __entry;
    /* stack top virtual address */
    unsigned long __sp_top;
} hhkrd_mem_info_t;

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
} hhkr_buf_t;

#define __HHKR_OBS_TYPE_WRAPPER(OBS_PREFIX)	\
	OBS_PREFIX(audit_log),        \
    OBS_PREFIX(app_log),		  \
    OBS_PREFIX(hw_trace),         \
	OBS_PREFIX(net_log)

#define __HHKR_OBS_TYPE(x) HHKR_OBS_ ## x

enum hkkr_obs_type {
	__HHKR_OBS_TYPE_WRAPPER(__HHKR_OBS_TYPE),
	__HHKR_OBS_MAX_ID,
};
#undef __HKKR_OBS_TYPE