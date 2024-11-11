#include <common/debug.h>
#include <bl31/hhkrd_secio.h>
#include <bl31/hhkrd_comm_lib.h>
#include <drivers/delay_timer.h>
#include <lib/mmio.h>

static hhkr_secIO_t secIO = {};
static struct ata_taskfile hhkr_faketf = {};
static int hhkr_tag = 0x2;

/* In FVP's gicv3, we just use a fixed address to indicate job status */
int *hhkr_secIO_job_pending = NULL;


// #define __raw_writel __raw_writel
// static inline void __raw_writel(u32 val, volatile void *addr) {
// 	asm volatile("str %w0, [%1]" : : "rZ" (val), "r" (addr));
// }

// #define writel_relaxed(v,c)	((void)__raw_writel((u32)_htole32(v),(void *)(c)))

// #define mydsb(opt)	   asm volatile("dsb " #opt : : : "memory")
// #define wmb()          mydsb(st)
// #define __iowmb()      wmb()

// #define writel(val, c) ({ NOTICE("writel phys_addr: 0x%lx, val:0x%x.\n", c, val); __iowmb(); writel_relaxed(val, c); })

// static inline uint32_t __REV(uint32_t value) {
//     uint32_t result;
//     __asm__ volatile("rev %0, %1" : "=r" (result) : "r" (value));
//     return result;
// }
// #define _htole32(x)     htole32(x)
#define _htole32(x)     (x)

static inline void writel(uint32_t value, volatile void *addr) {
    __asm__ volatile("dsb sy" ::: "memory");
    uint32_t le_value = _htole32(value);
    mmio_write_32((uintptr_t)addr, le_value);
    __asm__ volatile("dsb sy" ::: "memory");
}

static inline int fake_ata_build_rw_tf(struct ata_taskfile *tf, unsigned long block, u32 n_block, 
                                       unsigned int tf_flags, unsigned int tag) 
{
    tf->flags |= ATA_TFLAG_ISADDR | ATA_TFLAG_DEVICE;
    tf->flags |= tf_flags;
    /* NCQ MODE! */
    tf->protocol = ATA_PROT_NCQ;
    tf->flags |= ATA_TFLAG_LBA | ATA_TFLAG_LBA48;
    if (tf->flags & ATA_TFLAG_WRITE)
        tf->command = ATA_CMD_FPDMA_WRITE;
    else
        tf->command = ATA_CMD_FPDMA_READ;
    tf->nsect = tag << 3;
    tf->hob_feature = (n_block >> 8) & 0xff;
    tf->feature = n_block & 0xff;

    tf->hob_lbah = (block >> 40) & 0xff;
    tf->hob_lbam = (block >> 32) & 0xff;
    tf->hob_lbal = (block >> 24) & 0xff;
    tf->lbah = (block >> 16) & 0xff;
    tf->lbam = (block >> 8) & 0xff;
    tf->lbal = block & 0xff;

    tf->device = ATA_LBA;
    if (tf->flags & ATA_TFLAG_FUA)
        tf->device |= 1 << 7;
    return 0;
}

static void fake_ata_tf_to_fis(struct ata_taskfile *tf, u8 pmp, int is_cmd, u8 *fis) {
    fis[0] = 0x27;			/* Register - Host to Device FIS */
	fis[1] = pmp & 0xf;		/* Port multiplier number*/
	if (is_cmd)
		fis[1] |= (1 << 7);	/* bit 7 indicates Command FIS */

	fis[2] = tf->command;
	fis[3] = tf->feature;

	fis[4] = tf->lbal;
	fis[5] = tf->lbam;
	fis[6] = tf->lbah;
	fis[7] = tf->device;

	fis[8] = tf->hob_lbal;
	fis[9] = tf->hob_lbam;
	fis[10] = tf->hob_lbah;
	fis[11] = tf->hob_feature;

	fis[12] = tf->nsect;
	fis[13] = tf->hob_nsect;
	fis[14] = 0;
	fis[15] = tf->ctl;

	fis[16] = tf->auxiliary & 0xff;
	fis[17] = (tf->auxiliary >> 8) & 0xff;
	fis[18] = (tf->auxiliary >> 16) & 0xff;
	fis[19] = (tf->auxiliary >> 24) & 0xff;
    NOTICE("[fake_ata_tf_to_fis] fis addr: 0x%lx, fis[0]: 0x%x, fis[1]: 0x%x, fis[2]: 0x%x, fis[3]: 0x%x, fis[4]: 0x%x, fis[5]: 0x%x, fis[6]: 0x%x, fis[7]: 0x%x, fis[8]: 0x%x, fis[9]: 0x%x, fis[10]: 0x%x, fis[11]: 0x%x, fis[12]: 0x%x, fis[13]: 0x%x, fis[14]: 0x%x, fis[15]: 0x%x, fis[16]: 0x%x, fis[17]: 0x%x, fis[18]: 0x%x, fis[19]: 0x%x.\n", 
        (unsigned long)fis, fis[0], fis[1], fis[2], fis[3], fis[4], fis[5], fis[6], fis[7], fis[8], fis[9], fis[10], fis[11], fis[12], fis[13], fis[14], fis[15], fis[16], fis[17], fis[18], fis[19]);
}

int hhkrd_secIO_init(u_register_t pp_cmd_tbl, u_register_t pp_cmd_tbl_dma, u_register_t pp_cmd_slot, 
                     u_register_t ahci_port_mmio, u_register_t pmp, u_register_t io_job_pending_addr)
{
    if (!secIO.ahci_port_mmio) {
        secIO.pp_cmd_tbl = (void *)pp_cmd_tbl;               // pp->cmd_tbl
        secIO.pp_cmd_tbl_dma = pp_cmd_tbl_dma;       // pp->cmd_tbl_dma
        secIO.pp_cmd_slot = (hhkr_ahci_cmd_hdr_t *)pp_cmd_slot;      // pp->cmd_slot
        secIO.ahci_port_mmio = ahci_port_mmio;
        secIO.pmp = (int)pmp;
        
        if (io_job_pending_addr)
            hhkr_secIO_job_pending = (int *)io_job_pending_addr;
        else
            NOTICE("hhkrd_secIO_init: io_job_pending_addr is NULL.\n");
        NOTICE("hhkrd_secIO_init: pp_cmd_tbl: 0x%lx, pp_cmd_tbl_dma: 0x%lx, pp_cmd_slot: 0x%lx, ahci_port_mmio: 0x%lx, pmp: %d, pending_status_addr: 0x%lx.\n", 
            (unsigned long)secIO.pp_cmd_tbl, (unsigned long)secIO.pp_cmd_tbl_dma, 
            (unsigned long)secIO.pp_cmd_slot, secIO.ahci_port_mmio, secIO.pmp, (unsigned long)hhkr_secIO_job_pending);
    } else {
        NOTICE("hhkrd_secIO_init: Already initialized.\n");
    } 

    /* In FVP, we just set SCTLR.FIQ = 1 to route the interrupt and simulate */
    write_scr_el3(read_scr_el3() | SCR_FIQ_BIT);
    NOTICE("hhkrd_secIO_init: SCR_EL3: 0x%lx.\n", read_scr_el3());
    return 0;
}

int hhkrd_secIO_assignjob(u_register_t scatterlist_pgs, u_register_t blk_start, u_register_t write_size) 
{
    if (!hhkr_secIO_job_pending) {
        NOTICE("hhkrd_secIO_assignjob: hhkr_secIO_job_pending is NULL.\n");
        return -1;
    }
    while (*hhkr_secIO_job_pending) {
        udelay(1000);
    }
    *hhkr_secIO_job_pending = 1;

    hhkr_scatterlist_pgs_t *hhkr_sc_pgs = (hhkr_scatterlist_pgs_t *)scatterlist_pgs;
    NOTICE("hhkrd_secIO_assignjob: scatterlist_pgs: 0x%lx, blk_start: 0x%lx, write_size: 0x%lx.\n", scatterlist_pgs, blk_start, write_size);
    unsigned long block = blk_start;
    u32 n_block = write_size / BLOCK_SZ;
    unsigned int tf_flags = 0 | ATA_TFLAG_WRITE;
    
    //// fake tf
    fake_ata_build_rw_tf(&hhkr_faketf, block, n_block, tf_flags, hhkr_tag);
    
    /* ahci_qc_prep() */
    void *cmd_tbl = secIO.pp_cmd_tbl + hhkr_tag * AHCI_CMD_TBL_SZ;
    fake_ata_tf_to_fis(&hhkr_faketf, secIO.pmp, 1, cmd_tbl); // ata_tf_to_fis
    
    //// ahci_fill_sg (we always assume a single sg buffer)
    NOTICE("begin to ahci_fill_sg.\n");
    NOTICE("fakesg: pagelink: 0x%lx.\n", hhkr_sc_pgs->sg.page_link);
    
    struct ahci_sg *ahci_sg = cmd_tbl + AHCI_CMD_TBL_HDR_SZ;
    NOTICE("ahci_sg[0].addr physaddr: 0x%lx, .addr_hi phys: 0x%lx, .flags_size phys: 0x%lx.\n",
            (unsigned long)(&ahci_sg[0].addr), (unsigned long)(&ahci_sg[0].addr_hi), (unsigned long)(&ahci_sg[0].flags_size));
    
    // suppose do_dma_sg is done in EL1 
    unsigned long addr = hhkr_sc_pgs->sg.dma_address;
    u32 sg_len = hhkr_sc_pgs->sg.dma_length;
    ahci_sg[0].addr = _htole32((addr & 0xffffffff));
    ahci_sg[0].addr_hi = _htole32(((addr >> 16) >> 16));
    ahci_sg[0].flags_size = _htole32((sg_len - 1));
    NOTICE("ahci_sg[0] dma_addr: 0x%x, addr_hi: 0x%x, flags_size: 0x%x.\n", 
            ahci_sg[0].addr, ahci_sg[0].addr_hi, ahci_sg[0].flags_size);
            
    u32 opts = CMD_FIS_LEN | SG_N_ELEM << 16 | (secIO.pmp << 12) ;
    opts |=  AHCI_CMD_WRITE;
    
    //// ahci_fill_cmd_slots
    unsigned long cmd_tbl_dma = secIO.pp_cmd_tbl_dma + hhkr_tag * AHCI_CMD_TBL_SZ;

    secIO.pp_cmd_slot[hhkr_tag].opts = _htole32(opts);
    secIO.pp_cmd_slot[hhkr_tag].status = 0;
    secIO.pp_cmd_slot[hhkr_tag].tbl_addr = _htole32((cmd_tbl_dma & 0xffffffff));
    secIO.pp_cmd_slot[hhkr_tag].tbl_addr_hi = _htole32(((cmd_tbl_dma >> 16) >> 16));
    NOTICE("fill_cmd_slots. cmd_slot[tag].opts phys: 0x%lx, .status phys: 0x%lx, .tbl_addr phys: 0x%lx, .tbl_addr_hi phys: 0x%lx, cmd_slot[tag] opts: 0x%x, status: 0x%x, tbl_addr: 0x%x, tbl_addr_hi: 0x%x.\n", 
            (unsigned long)&secIO.pp_cmd_slot[hhkr_tag].opts, (unsigned long)&secIO.pp_cmd_slot[hhkr_tag].status, (unsigned long)&secIO.pp_cmd_slot[hhkr_tag].tbl_addr, (unsigned long)&secIO.pp_cmd_slot[hhkr_tag].tbl_addr_hi,
            secIO.pp_cmd_slot[hhkr_tag].opts, secIO.pp_cmd_slot[hhkr_tag].status, secIO.pp_cmd_slot[hhkr_tag].tbl_addr, secIO.pp_cmd_slot[hhkr_tag].tbl_addr_hi);
    // start
    // writel(1 << hhkr_tag, (void *)(secIO.ahci_port_mmio + PORT_SCR_ACT));
    // writel(1 << hhkr_tag, (void *)(secIO.ahci_port_mmio + PORT_CMD_ISSUE));
    return 0;
}