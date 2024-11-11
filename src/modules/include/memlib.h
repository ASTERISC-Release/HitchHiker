#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/mm_types.h>
#include <linux/miscdevice.h>

typedef struct {
    unsigned long gpt_id;  /* a.k.a., td_id */
    /* The base virtual address */
    unsigned long virt_addr;
    /* The base physical address */
    unsigned long phys_addr;
    /* Indicates allocated length. Each mmap() will allocate a new segment and increase the length */
    unsigned long offset;
    /* total size */
    unsigned long length;
    /* trustd entry point */
    unsigned long __entry;
    /* stack top virtual address */
    unsigned long __sp_top;
} td_mem_info_t;


/* linked list  */
typedef struct {
    td_mem_info_t td_mem_info;
    struct list_head list;
} td_mem_region_t;


typedef struct {
    struct miscdevice misc;
    struct mutex lock;
    struct list_head region_head;
} td_mem_mngr_t;

/* mem structs */
extern td_mem_mngr_t *td_mngr;
extern td_mem_region_t *td_region;

struct page *trustd_allocate_memory(unsigned long length, td_mem_region_t *td_region, td_mem_mngr_t *td_mngr, long gpt_id);
void trustd_release_memory(struct page *pages, unsigned long length, td_mem_region_t *td_region);
bool trustd_mark_region_exec(unsigned long virt_addr, unsigned long length, int elx);