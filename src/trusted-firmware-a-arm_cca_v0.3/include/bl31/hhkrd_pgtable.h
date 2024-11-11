#ifndef HHKRD_PGTABLE_H
#define HHKRD_PGTABLE_H

#include <stdint.h>
#include <arch.h>
#include <errno.h>
#include <lib/spinlock.h>
#include <arch_helpers.h>

/* hhkrd page table struct */
// reference: https://armv8-ref.codingbelief.com/en/chapter_d4/d42_3_memory_translation_granule_size.html
/*
 * We copy and maintain the page table of hhkrd to mitigate the Igao
 */
/* PGD (=PUD), PMD, PTE */
typedef struct { /* 3-level page table */
    uint64_t td_pgd_phys_addr;
    uint64_t td_pmd_phys_addr;
    uint64_t td_pte_phys_addr;
    uint32_t td_pmd_pages_number;
    uint32_t td_pte_pages_number;
    uint32_t pmd_pages_index;
    uint32_t pte_pages_index;
    uint64_t pg_length;
    uint64_t td_id;
    bool use_mem_pool;
} hhkrd_pg;

// extern spinlock_t pgd_lock;
// extern spinlock_t pmd_lock;

#define PGDIR_SIZE      0x40000000
/* we use 3-level page table, starting from the level-1 table */
#define PGDIR_SHIFT     30      /* index the level-1 translation table */
#define PTRS_PER_PGD    512
#define PGDIR_MASK	    (~(PGDIR_SIZE - 1))
#define PMD_SIZE        0x200000
#define PMD_SHIFT       21     /* index the level-2 translation table */
#define PTRS_PER_PMD    512
#define PMD_MASK		(~(PMD_SIZE - 1))
#define S_PAGE_SIZE     0x1000
#define PAGE_SHIFT      12    /* index the level-3 translation table */
#define PTRS_PER_PTE    512
#define VA_END          0x7fffffffff

typedef unsigned long pgdval_t;
typedef unsigned long pudval_t;
typedef unsigned long pmdval_t;
typedef unsigned long pteval_t;

typedef struct { pgdval_t pgd; } pgd_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pteval_t pte; } pte_t;

#ifndef pgd_addr_end
#define pgd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#endif

#ifndef pmd_addr_end
#define pmd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PMD_SIZE) & PMD_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#endif

#define pgd_index(addr)		                (((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pmd_index(addr)	                	(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(addr)		                (((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

#define pgd_offset_raw(pgd, addr)       	((pgd) + pgd_index(addr))
#define pgd_val(x)	                        ((x).pgd)
#define pmd_val(x)	                        ((x).pmd)
#define pte_val(x)	                        ((x).pte)
#define __pgd(x)	                        ((pgd_t) { (x) } )
#define pgd_none(pgd)		                (!pgd_val(pgd))
#define pgd_bad(pgd)		                (!(pgd_val(pgd) & 2))
#define pgd_present(pgd)	                (pgd_val(pgd))
#define PUD_TYPE_TABLE		                UL(3<<0)
#define PMD_TABLE_BIT		                UL(1<<1)
#define PMD_TYPE_TABLE		                UL(3<<0)
#define __pmd(x)	                        ((pmd_t) { (x) } )
#define pmd_none(pmd)		                (!pmd_val(pmd))
#define pmd_bad(pmd)	                	(!(pmd_val(pmd) & PMD_TABLE_BIT))
#define pmd_present(pmd)	                (pmd_val(pmd))


#define __pte(x)	                        ((pte_t) { (x) } )
#define pte_none(pte)		                (!pte_val(pte))

#define ttbr_val_disable_CnP(val)           (val & (~0x1))

int pgd_none_or_clear_bad(pgd_t *pgd);
int pmd_none_or_clear_bad(pmd_t *pmd);

pmd_t* pmd_offset(pgd_t *pgd, unsigned long address);
pte_t* pte_offset(pmd_t *pmd, unsigned long address);

pmd_t *pmd_alloc(hhkrd_pg * td_pg, pgd_t *pgd, unsigned long address);
pte_t *pte_alloc(hhkrd_pg * td_pg, pmd_t *pmd, unsigned long address);

#endif