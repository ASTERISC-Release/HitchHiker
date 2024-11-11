#include <linux/io.h>
#include <linux/delay.h>
#include "hhkr_secio_driver_el1.h"

#define DEBUGLABEL      (0)

#ifndef ENV_JUNO
static hhkr_secIO_t secIO = {};
#endif
static struct hhkr_ata_taskfile hhkr_faketf = {};
static int hhkr_tag = 0x2;

/* In FVP's gicv3, we just use a fixed address to indicate job status */
int *hhkr_secIO_job_pending = NULL;

static inline int fake_ata_build_rw_tf(struct hhkr_ata_taskfile *tf, unsigned long block, u32 n_block, 
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
    tf->ctl = 0x8;
#if DEBUGLABEL
    log_info("tf->command = 0x%x, tf->flags = 0x%x, tf->nsect = 0x%x, tf->feature = 0x%x, tf->lbal = 0x%x, tf->lbam = 0x%x, tf->lbah = 0x%x, tf->device = 0x%x, tf->hob_nsect = 0x%x,\n tf->hob_feature = 0x%x, tf->hob_lbal = 0x%x, tf->hob_lbam = 0x%x, tf->hob_lbah = 0x%x, tf->protocol = 0x%x, tf->flags = 0x%lx.\n",
			  tf->command, tf->flags, tf->nsect, tf->feature, tf->lbal, tf->lbam, tf->lbah, tf->device, tf->hob_nsect, tf->hob_feature, tf->hob_lbal, tf->hob_lbam, tf->hob_lbah, tf->protocol, tf->flags);
#endif
    return 0;
}

static void fake_ata_tf_to_fis(struct hhkr_ata_taskfile *tf, u8 pmp, int is_cmd, u8 *fis) {
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
#if DEBUGLABEL
    log_info("fis addr: 0x%lx, fis[0]: 0x%x, fis[1]: 0x%x, fis[2]: 0x%x, fis[3]: 0x%x, fis[4]: 0x%x, fis[5]: 0x%x, fis[6]: 0x%x, fis[7]: 0x%x, fis[8]: 0x%x, fis[9]: 0x%x, fis[10]: 0x%x, fis[11]: 0x%x, fis[12]: 0x%x, fis[13]: 0x%x, fis[14]: 0x%x, fis[15]: 0x%x, fis[16]: 0x%x, fis[17]: 0x%x, fis[18]: 0x%x, fis[19]: 0x%x.\n", 
              (unsigned long)fis, fis[0], fis[1], fis[2], fis[3], fis[4], fis[5], fis[6], fis[7], fis[8], fis[9], fis[10], fis[11], fis[12], fis[13], fis[14], fis[15], fis[16], fis[17], fis[18], fis[19]);
#endif
}

unsigned long hhkr_port_base_mmio_virt;
unsigned long hhkr_port_base_mmio_phys;

int hhkrd_secIO_init_plat(void *pp, unsigned long port_base_mmio_virt) {
    hhkr_port_base_mmio_virt = port_base_mmio_virt;
    hhkr_port_base_mmio_phys = virt_to_phys((void *)hhkr_port_base_mmio_virt);
#if DEBUGLABEL
    log_info("port_base_mmio_virt: 0x%lx, port_base_mmio_phys: 0x%lx.\n",
              hhkr_port_base_mmio_virt, hhkr_port_base_mmio_phys);
#endif
    return 0;
}
EXPORT_SYMBOL(hhkrd_secIO_init_plat);

#ifndef ENV_JUNO
int hhkrd_secIO_init(unsigned long pp_cmd_tbl, unsigned long pp_cmd_tbl_dma, unsigned long pp_cmd_slot, 
                     unsigned long ahci_port_mmio, unsigned long pmp, unsigned long io_job_pending_addr)
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
            log_err("io_job_pending_addr is NULL.\n");
        printk("hhkrd_secIO_init: pp_cmd_tbl: 0x%lx, pp_cmd_tbl_dma: 0x%lx, pp_cmd_slot: 0x%lx, ahci_port_mmio: 0x%lx, pmp: %d, pending_status_addr: 0x%lx.\n", 
            (unsigned long)secIO.pp_cmd_tbl, (unsigned long)secIO.pp_cmd_tbl_dma, 
            (unsigned long)secIO.pp_cmd_slot, secIO.ahci_port_mmio, secIO.pmp, (unsigned long)hhkr_secIO_job_pending);
    } else {
        printk("hhkrd_secIO_init: Already initialized.\n");
    } 
    return 0;
}
EXPORT_SYMBOL(hhkrd_secIO_init);

static int hhkrd_secIO_assignjob_fvp(unsigned long scatterlist_pgs, unsigned long blk_start, unsigned long write_size) 
{
#if DEBUGLABEL
    log_info("assign IO job for FVP at blk: 0x%lx, size: 0x%lx MB (0x%lx BLKs).\n", blk_start, write_size / SZ_1M, write_size / 512);
#endif
    struct hhkr_ahci_sg *ahci_sg;
    unsigned long block, addr, cmd_tbl_dma;
    hhkr_scatterlist_pgs_t *hhkr_sc_pgs;
    void *cmd_tbl;
    unsigned int tf_flags;
    u32 n_block, sg_len, opts;

    if (!hhkr_secIO_job_pending) {
        printk("hhkrd_secIO_assignjob: hhkr_secIO_job_pending is NULL.\n");
        return -1;
    }
    while (*hhkr_secIO_job_pending) {
        udelay(1000);
    }
    /* set IO job pending status */
    *hhkr_secIO_job_pending = 1;

    hhkr_sc_pgs = (hhkr_scatterlist_pgs_t *)scatterlist_pgs;
    printk("hhkrd_secIO_assignjob: scatterlist_pgs: 0x%lx, blk_start: 0x%lx, write_size: 0x%lx.\n", scatterlist_pgs, blk_start, write_size);
    block = blk_start;
    n_block = write_size / BLOCK_SZ;
    tf_flags = 0 | ATA_TFLAG_WRITE;
    
    //// fake tf
    fake_ata_build_rw_tf(&hhkr_faketf, block, n_block, tf_flags, hhkr_tag);
    
    /* ahci_qc_prep() */
    cmd_tbl = secIO.pp_cmd_tbl + hhkr_tag * AHCI_CMD_TBL_SZ;
    fake_ata_tf_to_fis(&hhkr_faketf, secIO.pmp, 1, cmd_tbl); // ata_tf_to_fis
    
    //// ahci_fill_sg (we always assume a single sg buffer)
    printk("begin to ahci_fill_sg.\n");
    printk("fakesg: pagelink: 0x%lx.\n", hhkr_sc_pgs->sg.page_link);
    
    ahci_sg = cmd_tbl + AHCI_CMD_TBL_HDR_SZ;
    printk("ahci_sg[0].addr physaddr: 0x%lx, .addr_hi phys: 0x%lx, .flags_size phys: 0x%lx.\n",
            (unsigned long)(&ahci_sg[0].addr), (unsigned long)(&ahci_sg[0].addr_hi), (unsigned long)(&ahci_sg[0].flags_size));
    
    // suppose do_dma_sg is done in EL1 boot
    addr = hhkr_sc_pgs->sg.dma_address;
    sg_len = hhkr_sc_pgs->sg.dma_length;
    ahci_sg[0].addr = cpu_to_le32((addr & 0xffffffff));
    ahci_sg[0].addr_hi = cpu_to_le32(((addr >> 16) >> 16));
    ahci_sg[0].flags_size = cpu_to_le32((sg_len - 1));
    printk("ahci_sg[0] dma_addr: 0x%x, addr_hi: 0x%x, flags_size: 0x%x.\n", 
            ahci_sg[0].addr, ahci_sg[0].addr_hi, ahci_sg[0].flags_size);
            
    opts = CMD_FIS_LEN | SG_N_ELEM << 16 | (secIO.pmp << 12) ;
    opts |=  AHCI_CMD_WRITE;
    
    //// ahci_fill_cmd_slots
    cmd_tbl_dma = secIO.pp_cmd_tbl_dma + hhkr_tag * AHCI_CMD_TBL_SZ;

    secIO.pp_cmd_slot[hhkr_tag].opts = cpu_to_le32(opts);
    secIO.pp_cmd_slot[hhkr_tag].status = 0;
    secIO.pp_cmd_slot[hhkr_tag].tbl_addr = cpu_to_le32((cmd_tbl_dma & 0xffffffff));
    secIO.pp_cmd_slot[hhkr_tag].tbl_addr_hi = cpu_to_le32(((cmd_tbl_dma >> 16) >> 16));
    printk("fill_cmd_slots. cmd_slot[tag].opts phys: 0x%lx, .status phys: 0x%lx, .tbl_addr phys: 0x%lx, .tbl_addr_hi phys: 0x%lx, cmd_slot[tag] opts: 0x%x, status: 0x%x, tbl_addr: 0x%x, tbl_addr_hi: 0x%x.\n", 
            (unsigned long)&secIO.pp_cmd_slot[hhkr_tag].opts, (unsigned long)&secIO.pp_cmd_slot[hhkr_tag].status, (unsigned long)&secIO.pp_cmd_slot[hhkr_tag].tbl_addr, (unsigned long)&secIO.pp_cmd_slot[hhkr_tag].tbl_addr_hi,
            secIO.pp_cmd_slot[hhkr_tag].opts, secIO.pp_cmd_slot[hhkr_tag].status, secIO.pp_cmd_slot[hhkr_tag].tbl_addr, secIO.pp_cmd_slot[hhkr_tag].tbl_addr_hi);
    // start
    writel(1 << hhkr_tag, (void *)(secIO.ahci_port_mmio + PORT_SCR_ACT));
    writel(1 << hhkr_tag, (void *)(secIO.ahci_port_mmio + PORT_CMD_ISSUE));
    asm volatile("isb" : : : "memory");
    return 0;
}
#endif

#ifdef ENV_JUNO

struct sil24_prb *hhkr_prb = NULL;
unsigned long hhkr_prb_phys = 0;

struct sil24_sge *hhkr_sge = NULL;
unsigned long hhkr_sge_phys = 0;

unsigned long pp_cmd_blk_dma = 0;
unsigned long pp_cmd_blk_phys = 0;

unsigned long pp_cmd_blk_size = 0;
int pmp, _tf_ctl;

unsigned long paddr = 0;
void __iomem *activate = NULL;


// #define HHKR_NON_NCQ

int hhkrd_secIO_init_juno(void *pp, unsigned long port_base_mmio_virt, int pmp, int tf_ctl, 
                           unsigned long io_job_pending_addr) {
    struct sil24_port_priv *_pp = pp;
    union sil24_cmd_block *cb;
    struct sil24_prb *prb;
	struct sil24_sge *sge;
    u16 ctrl, prot;
    hhkr_secIO_job_pending = (int *)io_job_pending_addr;
    *hhkr_secIO_job_pending = 0;
    _tf_ctl = tf_ctl;
    
    hhkrd_secIO_init_plat(pp, port_base_mmio_virt);

    pp_cmd_blk_dma = _pp->cmd_block_dma;
    pp_cmd_blk_phys = virt_to_phys((void *)pp_cmd_blk_dma);  // maybe IOVA...
    pp_cmd_blk_size = sizeof(*_pp->cmd_block);

    /* follow sil24_qc_prep */
    cb = &_pp->cmd_block[hhkr_tag];

    hhkr_prb = prb = &cb->ata.prb;
    hhkr_prb_phys = virt_to_phys((void *)hhkr_prb);
    
    hhkr_sge = sge = cb->ata.sge;
    hhkr_sge_phys = virt_to_phys((void *)hhkr_sge);
    
    prot = 0 | PRB_PROT_WRITE;
#ifndef HHKR_NON_NCQ
    prot |= PRB_PROT_NCQ;
#endif
    ctrl = PRB_CTRL_PROTOCOL;	

    prb->prot = cpu_to_le16(prot);

    /* setup paddr and activate, later mmaped to hhkrd's userspace secure driver */
    paddr = pp_cmd_blk_dma + hhkr_tag * pp_cmd_blk_size; // dma_addr_t
    activate = (void *)hhkr_port_base_mmio_virt + PORT_CMD_ACTIVATE + hhkr_tag * 8;
    unsigned long *paddr_a = (unsigned long *)((void *)hhkr_secIO_job_pending + sizeof(int));
    unsigned long *activate_a = (unsigned long *)((void *)paddr_a + sizeof(unsigned long));
    *paddr_a = paddr;
    *activate_a = activate;
    /* mmap activate MMIO to hhkrd later on */
#if DEBUGLABEL	
    log_info("hhkr_prb phys: 0x%lx, hhkr_sge phys: 0x%lx, pp->cmd_blk_dma: 0x%lx (0x%lx phys?), prb->fis phys: 0x%llx.\n",
              hhkr_prb_phys, hhkr_sge_phys, pp_cmd_blk_dma, pp_cmd_blk_phys, virt_to_phys((void *)(hhkr_prb->fis)));
#endif
    hitchhiker_smc(HHKRD_INIT_SECIO_JUNO, hhkr_prb_phys, hhkr_sge_phys, pp_cmd_blk_dma, pp_cmd_blk_size,
                   hhkr_port_base_mmio_phys, tf_ctl, virt_to_phys((void *)hhkr_secIO_job_pending));
    return 0;
}
EXPORT_SYMBOL(hhkrd_secIO_init_juno);


static int hhkrd_secIO_assignjob_juno(unsigned long scatterlist_pgs, unsigned long blk_start, unsigned long write_size) 
{
    unsigned long block, addr;
    hhkr_scatterlist_pgs_t *hhkr_sg_pgs;

    unsigned int tf_flags;
    u32 n_block, sg_len;
#if DEBUGLABEL
    log_info("assign IO job for JUNO at blk: 0x%lx, size: 0x%lx MB (0x%lx BLKs).\n", blk_start, write_size / SZ_1M, write_size / 512);
#endif
    if (!hhkr_prb || !hhkr_sge) {
        log_info("hhkr_prb or hhkr_sge is NULL.\n");
        return -1;
    }
    // while (*hhkr_secIO_job_pending) {
    //     udelay(1000);
    // }
    /* set IO job pending status */
    *hhkr_secIO_job_pending = 1;

    /* route to EL3's sec driver */
    hhkr_sg_pgs = (hhkr_scatterlist_pgs_t *)scatterlist_pgs;
    hitchhiker_smc(HHKRD_ASSIGN_SECIO_JUNO, hhkr_sg_pgs->pgs_phys_addr, blk_start, write_size, 0, 0, 0, 0);

# if DEBUGLABEL
    log_info("paddr: 0x%lx (phys: 0x%lx), activate: 0x%lx (phys: 0x%lx).\n",
              paddr, (unsigned long)activate,
              (unsigned long)virt_to_phys((void *)paddr), (unsigned long)virt_to_phys((void *)activate));
#endif
    /* we should let hhkrd's userspace driver or EL3 driver to issue MMIOs first */
#ifndef SIL24_HHKRD_USERDRV
    wmb();
    writel((u32)paddr, activate);
	writel((u64)paddr >> 32, activate + 4);
#endif
    return 0;
}
#endif


int hhkrd_secIO_assignjob(unsigned long scatterlist_pgs, unsigned long blk_start, unsigned long write_size) {
#ifdef ENV_JUNO
    return hhkrd_secIO_assignjob_juno(scatterlist_pgs, blk_start, write_size);
#else
    return hhkrd_secIO_assignjob_fvp(scatterlist_pgs, blk_start, write_size);
#endif
}
EXPORT_SYMBOL(hhkrd_secIO_assignjob);