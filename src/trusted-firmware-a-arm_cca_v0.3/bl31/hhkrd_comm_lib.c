#include <bl31/hhkrd_comm_lib.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <arch_helpers.h>
#include <plat/common/platform.h>

#if !ENABLE_HHKRD
#error "ENABLE_HHKRD must be enabled to use the hhkrd common library."
#endif

#define KERN_SPACE_MASK     0xffff000000000000

uint64_t hhkrd_virt_to_phys(uint64_t virt_addr) {
    uint64_t par, pa;
    u_register_t scr_el3;
    /* save scr_el3 */
    scr_el3 = read_scr_el3();
    /* mark as Non-secure for address translation */
    write_scr_el3(scr_el3 | SCR_NS_BIT);
    isb();

    if((virt_addr & KERN_SPACE_MASK)) { /* OS virt addr */
        AT(ats1e1r, virt_addr);
    } else {                            /* user virt addr */
        AT(ats1e0r, virt_addr);
    }
	isb();
    /* Use physical address register to return the output address (OA) */
    par = read_par_el1();

    /* restore scr_el3 */
    write_scr_el3(scr_el3);
    isb();
    
    /* check translation result */
    if ((par & PAR_F_MASK)) {
        NOTICE("[td_virt_to_phys] par fault. va: 0x%llx par: 0x%llx fault.\n", virt_addr, par);
        return 0;
    }
    /* extract PA[x:12] from PAR */
    pa = (par & (PAR_ADDR_MASK << PAR_ADDR_SHIFT));
    pa = pa + (virt_addr & 0xfff);

    return pa;
}

size_t hhkrd_strlen_va(uint64_t virt_addr) {
    size_t len = 0;
    len = strlen((char *)hhkrd_virt_to_phys(virt_addr));
    NOTICE("[debug strlen] virt cont: %s. len: %lu.\n", (char *)hhkrd_virt_to_phys(virt_addr), len);
    return len;
}

void hhkrd_memcpy_pa(uint64_t dst_phys_addr, uint64_t src_phys_addr, uint32_t size) {
    if (dst_phys_addr && src_phys_addr)
        memcpy((void *)dst_phys_addr, (void *)src_phys_addr, size);
}

void hhkrd_memcpy_va(uint64_t dst_virt_addr, uint64_t src_virt_addr, uint32_t size) {
    uint64_t dst_phys_addr = hhkrd_virt_to_phys(dst_virt_addr);
    uint64_t src_phys_addr = hhkrd_virt_to_phys(src_virt_addr);

    hhkrd_memcpy_pa(dst_phys_addr, src_phys_addr, size);
}

void hhkrd_path_copy(uint64_t dst_virt_addr, uint64_t src_virt_addr, size_t size) {
    size = min(size, 4096);
    hhkrd_memcpy_va(dst_virt_addr, src_virt_addr, size);
    if (size == 4096) {
        uint64_t dst_phys_addr = hhkrd_virt_to_phys(dst_virt_addr);
        *(char *)(dst_phys_addr + 4095) = '\0';
    }
    NOTICE("path copy path: virt: 0x%llx, cont: %s.\n", dst_virt_addr, (char *)hhkrd_virt_to_phys(dst_virt_addr));
}


void hhkrd_sata_irq_handler(void) {
    unsigned int irq_type;
    irq_type = plat_ic_get_interrupt_type(SATA_IRQ_ID);
    // group = 10000;
    NOTICE("EL3 sata irq handler %d: group: %u.\n", SATA_IRQ_ID, irq_type);
}