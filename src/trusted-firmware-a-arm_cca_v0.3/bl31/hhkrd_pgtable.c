#include <bl31/hhkrd_pgtable.h>
#include <common/debug.h>
#if !ENABLE_HHKRD
#error "ENABLE_HHKRD must be enabled to use the hhkrd page table library."
#endif

spinlock_t pgd_lock;
spinlock_t pmd_lock;

int pgd_none_or_clear_bad(pgd_t *pgd) {
	if ((pgd_none(*pgd) || pgd_bad(*pgd)))
		return 1;
	return 0;
}

int pmd_none_or_clear_bad(pmd_t *pmd) {
	if ((pmd_none(*pmd) || pmd_bad(*pmd)))
		return 1;
	return 0;
}

pmd_t* pmd_offset(pgd_t *pgd, unsigned long address) {
	pgdval_t pmd_addr = pgd_val(*pgd) & (0xFFFFFFFFF000);
	// NOTICE("[pmd_offset] pmd_addr: 0x%lx for addr: 0x%lx.\n",
	// 	(unsigned long)(pmd_addr + pmd_index(address) * sizeof(pmd_t)), address);
	return (pmd_t *)(pmd_addr + pmd_index(address) * sizeof(pmd_t));
}

pte_t* pte_offset(pmd_t *pmd, unsigned long address) {
	pgdval_t pte_addr = pmd_val(*pmd) & (0xFFFFFFFFF000);
	return (pte_t *)(pte_addr + pte_index(address) * sizeof(pte_t));
}

/* allocate a new pmd table (a page) from the mem pool<pmd_phys_addr> */
pmd_t *pmd_alloc_one(hhkrd_pg * td_pg, unsigned long addr) {
	uint64_t pmd = 0;
	if(td_pg->pmd_pages_index < td_pg->td_pmd_pages_number) {
        pmd = td_pg->td_pmd_phys_addr + S_PAGE_SIZE * td_pg->pmd_pages_index;
        td_pg->pmd_pages_index += 1;
	}
	if (!pmd)
		return NULL;
	return (pmd_t *)pmd;
}

/* allocate a new pte table (a page) from the mem pool<pmd_phys_addr> */
pte_t *pte_alloc_one(hhkrd_pg * td_pg, unsigned long addr) {
	uint64_t pte = 0;
	if(td_pg->pte_pages_index < td_pg->td_pte_pages_number) {
		pte = td_pg->td_pte_phys_addr + S_PAGE_SIZE * td_pg->pte_pages_index;
		td_pg->pte_pages_index += 1;
	}
	if (!pte)
		return NULL;
	return (pte_t *)pte;
}

/* free descriptor page */

void pmd_free(hhkrd_pg * td_pg, pmd_t *pmd) {
	if(td_pg->pmd_pages_index > 0) {
		memset((void*) pmd, 0, S_PAGE_SIZE);
		td_pg->pmd_pages_index -= 1;
	}
}

void pte_free(hhkrd_pg * td_pg, pte_t *pte) {
	if(td_pg->pte_pages_index > 0) {
		memset((void*) pte, 0, S_PAGE_SIZE);
		td_pg->pte_pages_index -= 1;
	}
}


static inline void __pgd_populate(pgd_t *pgdp, uint64_t pudp, pgdval_t prot) {
	*pgdp = __pgd(pudp| prot);
	// NOTICE("[__pgd_populate] after populate, pgd_addr: 0x%lx, pgd_val: 0x%lx for pud_addr: 0x%llx.\n",
	// 		(unsigned long)pgdp, pgd_val(*pgdp), pudp);
}

/**
 * populate the current pgdp (pud) -> pudp (pmd)
 * (remind that we use 3-level table)
 */
void pgd_populate(pgd_t *pgdp, pmd_t *pudp) {
	__pgd_populate(pgdp, (uint64_t)pudp, PUD_TYPE_TABLE);
}

static inline void __pmd_populate(pmd_t *pmdp, uint64_t ptep, pgdval_t prot) {
	*pmdp = __pmd(ptep| prot);
}

/**
 * populate the current pmdp -> ptep
 */
void pmd_populate(pmd_t *pmdp, pte_t *ptep) {
	__pmd_populate(pmdp, (uint64_t)ptep, PMD_TYPE_TABLE);
}

static inline int __pmd_alloc(hhkrd_pg * td_pg, pgd_t *pud, unsigned long address) {
	pmd_t *new = pmd_alloc_one(td_pg, address);
	if (!new)
		return -ENOMEM;
	// NOTICE("[__pmd_alloc] alloc pmd_addr: 0x%lx for addr: 0x%lx\n", (unsigned long)new, address);
	spin_lock(&pgd_lock);
	if (!pgd_present(*pud)) {
		pgd_populate(pud, new); /* pgd (pud) - points to -> new pmd */
	} else /* Another has populated it */
		pmd_free(td_pg, new);
	spin_unlock(&pgd_lock);
	return 0;
}

static inline int __pte_alloc(hhkrd_pg * td_pg, pmd_t *pmd, unsigned long address)
{
	pte_t *new = pte_alloc_one(td_pg, address);
	if (!new)
		return -ENOMEM;
	spin_lock(&pmd_lock);
	if (!pmd_present(*pmd)) {
		pmd_populate(pmd, new); /* pmd - points to -> new pte */
	} else
		pte_free(td_pg, new);
	spin_unlock(&pmd_lock);
	return 0;
}

pmd_t *pmd_alloc(hhkrd_pg * td_pg, pgd_t *pgd, unsigned long address) {
	return (pgd_none(*pgd) && __pmd_alloc(td_pg, pgd, address))?
		NULL: pmd_offset(pgd, address);
}

/**
 * alloc a new pte table (page), and 
 * 1) populate its previous `pmd` desc, 
 * 2) return the pte desc (entry) of the corresponding `address` and `pmd` 
 */
pte_t *pte_alloc(hhkrd_pg * td_pg, pmd_t *pmd, unsigned long address) {
	return (pmd_none(*pmd) && __pte_alloc(td_pg, pmd, address))?
		NULL: pte_offset(pmd, address);
}