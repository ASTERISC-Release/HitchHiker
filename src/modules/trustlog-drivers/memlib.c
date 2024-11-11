#include <linux/mm.h>
#include <linux/gfp.h>
#include <uapi/linux/types.h>

#include <cma/cmalib.h>
#include <memlib.h>

#define DEBUGLABEL      (0)
/* cma allocators */
struct cma *cma_logger_pool = NULL;
struct cma *cma_trustd_pool = NULL;

/* mem structs */
td_mem_mngr_t *td_mngr;
td_mem_region_t *td_region;


struct page *trustd_allocate_memory(unsigned long length, td_mem_region_t *td_region, td_mem_mngr_t *td_mngr, long gpt_id) {
    struct page *page;
    unsigned int pg_align;
    /* get_order() or 1 or 1 << PAGE_SHIFT? */
    // pg_align = (1 << PAGE_SHIFT); 
    pg_align = get_order(length);
    page = cma_alloc(AL_trustd, (length >> PAGE_SHIFT), pg_align, GFP_KERNEL);
    
    if (page && td_region) {
        /* fill up the region */
        td_region->td_mem_info.phys_addr = (dma_addr_t)page_to_phys(page);
        td_region->td_mem_info.virt_addr = (dma_addr_t)page_to_virt(page);
        td_region->td_mem_info.length = length;
        td_region->td_mem_info.offset = 0;
        if (gpt_id > 0) {
            td_region->td_mem_info.gpt_id = (unsigned long)gpt_id;
        }
        /* clear content */
        memset((void *)td_region->td_mem_info.virt_addr, 0, td_region->td_mem_info.length);
        /* add to the manager's region list */
        if (td_mngr) {
            list_add(&td_region->list, &td_mngr->region_head);
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

	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep, pte;

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

bool trustd_mark_region_exec(unsigned long virt_addr, unsigned long length, int elx) {
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

void trustd_release_memory(struct page *pages, unsigned long length, td_mem_region_t *td_region) {
    cma_release(AL_trustd, pages, (length >> PAGE_SHIFT));
    /* free gpt id */
    if (td_region) {
        td_region->td_mem_info.gpt_id = 0;
    }
}