#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/mm_types.h>

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
    /* hhkrd entry point */
    unsigned long __entry;
    /* stack top virtual address */
    unsigned long __sp_top;
} hhkrd_mem_info_t;

/* linked list  */
typedef struct hitchhiker_daemon_regions {
    hhkrd_mem_info_t hhkrd_mem_info;
    struct list_head list;
} hhkrd_mem_region_t;


typedef struct hitchhiker_daemon_manager {
    struct mutex lock;
    struct list_head region_head;
} hhkrd_mem_mngr_t;

/* mem structs */
extern hhkrd_mem_mngr_t *hhkrd_mngr;
extern hhkrd_mem_region_t *hhkrd_region;

int hhkrd_memexpand(int gpt_id);
struct page *hhkrd_allocate_memory(unsigned long length, hhkrd_mem_region_t *hhkrd_region, hhkrd_mem_mngr_t *hhkrd_mngr, long gpt_id);
void hhkrd_release_memory(struct page *pages, unsigned long length, hhkrd_mem_region_t *hhkrd_region);
bool hhkrd_mark_region_exec(unsigned long virt_addr, unsigned long length, int elx);