#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <uapi/linux/types.h>

#include "cmalib.h"
#include "hhkrd_mgmt.h"
#include <linux/hitchhiker.h>

#define pr_fmt(fmt) "hhkrd_mgmt: " fmt
#define DEBUGLABEL	(0)
struct cma *cma_hhkrd_pool = NULL;

/* mem structs */
hhkrd_mem_mngr_t *hhkrd_mngr;
hhkrd_mem_region_t *hhkrd_region;


int hhkrd_memexpand(int gpt_id) {
	int ret0;
    struct page *page;
    /* update the td_region */
    hhkrd_region = kzalloc(sizeof(hhkrd_region), GFP_KERNEL);
    if (!hhkrd_region) {
        log_err("Failed to kzalloc memory for hhkrd_region.\n");
        return -ENOMEM;
    }
    /* fetch a 64MB region from the allocator */
	page = hhkrd_allocate_memory(HHKRD_EXTEND_MEM_DEFAULT_LENGTH, hhkrd_region, hhkrd_mngr, gpt_id);
    if (!page) {
        log_err("Failed to allocate memory for hhkrd_region.\n");
        return -ENOMEM;
    }
    /* sync monitor */
	ret0 = hitchhiker_smc(HHKRD_MEMEXPAND, hhkrd_region->hhkrd_mem_info.phys_addr, 
	                      hhkrd_region->hhkrd_mem_info.length, 0, 0, 0, 0, 0);
#if DEBUGLABEL
	log_info("hhkrd_memexpand: ret0 = %d.\n", ret0);
#endif
	return ret0;
}

struct page *hhkrd_allocate_memory(unsigned long length, hhkrd_mem_region_t *hhkrd_region, hhkrd_mem_mngr_t *hhkrd_mngr, long gpt_id) {
    struct page *page;
    unsigned int pg_align;
    /* get_order() or 1 or 1 << PAGE_SHIFT? */
    // pg_align = (1 << PAGE_SHIFT); 
    pg_align = get_order(length);
    page = cma_alloc(AL_hhkrd, (length >> PAGE_SHIFT), pg_align, GFP_KERNEL);
	log_info("page = 0x%lx, length = 0x%lx, pg_align = 0x%x.\n",
			 (unsigned long)page, length, pg_align);
    
    if (page && hhkrd_region) {
        /* fill up the region's memory info */
        hhkrd_region->hhkrd_mem_info.phys_addr = (dma_addr_t)page_to_phys(page);
        hhkrd_region->hhkrd_mem_info.virt_addr = (dma_addr_t)page_to_virt(page);
        hhkrd_region->hhkrd_mem_info.length = length;
		hhkrd_region->hhkrd_mem_info.offset = 0;
		/* set memory info's gpt_id */
		if (gpt_id > 0) {
			hhkrd_region->hhkrd_mem_info.gpt_id = (unsigned long)gpt_id;
		}
        /* clear memory content */
		memset((void *)hhkrd_region->hhkrd_mem_info.virt_addr, 0, hhkrd_region->hhkrd_mem_info.length);
        /* add to the manager's region list */
		if (hhkrd_mngr) {
			list_add(&hhkrd_region->list, &hhkrd_mngr->region_head);
		}
    }
    return page;
}

//make the memory Privileged EXEC and User EXEC
static pte_t __pte_mkexec_el0(pte_t pte) {	
	pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
	pte = set_pte_bit(pte, __pgprot(PTE_USER));     /* user accessable */
	pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY)); /* AP[2] */
	pte = clear_pte_bit(pte, __pgprot(PTE_PXN));
	pte = clear_pte_bit(pte, __pgprot(PTE_UXN));
	if DEBUGLABEL
		pr_cont(", mk_pte_el0=%016llx", pte_val(pte));
	return pte;
}

static pte_t __pte_mkexec_el1(pte_t pte) {	
	pte = set_pte_bit(pte, __pgprot(PTE_WRITE));
	pte = clear_pte_bit(pte, __pgprot(PTE_USER));   /* user inaccessable */
	pte = clear_pte_bit(pte, __pgprot(PTE_RDONLY)); /* AP[2] */
	pte = clear_pte_bit(pte, __pgprot(PTE_PXN));
	pte = clear_pte_bit(pte, __pgprot(PTE_UXN));
	if DEBUGLABEL
		pr_cont(", mk_pte_el1=%016llx", pte_val(pte));
	return pte;
}

static inline bool __mark_page_exec(unsigned long addr, int elx)
{
	struct mm_struct *mm;
	pgd_t *pgdp;
	pgd_t pgd;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep, pte;

    /* TTBR0 */
	if (addr < TASK_SIZE) {
		mm = current->active_mm; /* use current's page table in activate_mm */
		if (mm == &init_mm) {
			pr_alert("[%016lx] user address but active_mm is swapper\n", addr);
			return false;
		}
	} 
    /* TTBR1 */
    else if (addr >= VA_START) {
		mm = &init_mm;
	} 
    else {
		pr_alert("[%016lx] address between user and kernel address ranges\n", addr);
		return false;
	}

	if DEBUGLABEL
		pr_alert("%s pgtable: %luk pages, %u-bit VAs, pgdp = %p\n",
		 mm == &init_mm ? "swapper" : "user", PAGE_SIZE / SZ_1K,
		 mm == &init_mm ? VA_BITS : (int) vabits_user, mm->pgd);
	pgdp = pgd_offset(mm, addr);
	pgd = READ_ONCE(*pgdp);
	if DEBUGLABEL
		pr_alert("[%016lx] pgd=%016llx", addr, pgd_val(pgd));
	do {
		if (pgd_none(pgd) || pgd_bad(pgd))
			break;

		pudp = pud_offset(pgdp, addr);
		pud = READ_ONCE(*pudp);
		if DEBUGLABEL
			pr_cont(", pud=%016llx", pud_val(pud));
		if (pud_none(pud) || pud_bad(pud))
			break;

		pmdp = pmd_offset(pudp, addr);
		pmd = READ_ONCE(*pmdp);
		if DEBUGLABEL
			pr_cont(", pmd=%016llx", pmd_val(pmd));
		if (pmd_none(pmd) || pmd_bad(pmd))
			break;
        /* map the pte to a kernel virtual address so that it can be modified */
		ptep = pte_offset_map(pmdp, addr);
		pte = READ_ONCE(*ptep);
		if DEBUGLABEL
			pr_cont(", pte=%016llx", pte_val(pte));
        /* setup pte */
		if(elx == 0)
			set_pte(ptep, __pte_mkexec_el0(*ptep));
		else
			set_pte(ptep, __pte_mkexec_el1(*ptep));
		pte = READ_ONCE(*ptep);
		if DEBUGLABEL
			pr_cont(", new_pte=%016llx", pte_val(pte));
        /* unmap the pte ASAP! */
		pte_unmap(ptep);
	} while(0);
	if DEBUGLABEL
		pr_cont("\n");
	return true;
}

bool hhkrd_mark_region_exec(unsigned long virt_addr, unsigned long length, int elx) {
	int i;
	unsigned long nr_pages = length >> PAGE_SHIFT;
	for (i = 0; i < nr_pages; i++) {
		if (!__mark_page_exec(virt_addr, elx)) {
			return false;
		}
		virt_addr += PAGE_SIZE;
	}
	return true;
}

void hhkrd_release_memory(struct page *pages, unsigned long length, hhkrd_mem_region_t *hhkrd_region) {
	cma_release(AL_hhkrd, pages, (length >> PAGE_SHIFT));
	/* free gpt id */
	if (hhkrd_region) {
		hhkrd_region->hhkrd_mem_info.gpt_id = 0;
	}
}