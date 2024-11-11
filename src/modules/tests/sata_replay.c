#include <linux/mm.h>
#include <linux/cma.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/dma-contiguous.h>
#include <linux/arm-smccc.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/stat.h>

#include <linux/genhd.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>

#include <linux/libata.h>
#include <linux/ata.h>
#include <scsi/scsi_host.h>

#include <linux/syscalls.h>
#include <linux/delay.h>

#include <linux/hitchhiker.h>

#define DEV_NAME    "sata-replay"

// record for device instrumentation
#define ENABLE_RECORD_SATA

#define pr_fmt(fmt) "sata-replay: " fmt
struct miscdevice *misc;

#define SATA_DEV_NAME "/dev/sda"

#define DMA_TO_DEVICE 1
#define BLK_SZ          512

#define REPLAY_WRITE_SZ (1 << 20)     // 1MB
// #define REPLAY_WRITE_SZ (1 << 12)  // 4KB
#define N_BLOCK         REPLAY_WRITE_SZ / BLK_SZ
#define START_BLOCK     0 * N_BLOCK
#define FAKE_CHAR       'X'

struct ata_device *ata_dev = NULL;
struct device *dev = NULL;
struct scatterlist *fake_sg = NULL;

extern bool debug_record_sata;
extern bool debug_replay_sata;
extern int *hhkr_secIO_pending_job;
extern bool fetch_debug_record_sata(void);

extern unsigned long hhkr_IO_mem;

enum {
	AHCI_MAX_PORTS		= 32,
	AHCI_MAX_CLKS		= 5,
	AHCI_MAX_SG		= 168, /* hardware max is 64K */
	AHCI_DMA_BOUNDARY	= 0xffffffff,
	AHCI_MAX_CMDS		= 32,
	AHCI_CMD_SZ		= 32,
	AHCI_CMD_SLOT_SZ	= AHCI_MAX_CMDS * AHCI_CMD_SZ,
	AHCI_RX_FIS_SZ		= 256,
	AHCI_CMD_TBL_CDB	= 0x40,
	AHCI_CMD_TBL_HDR_SZ	= 0x80,
	AHCI_CMD_TBL_SZ		= AHCI_CMD_TBL_HDR_SZ + (AHCI_MAX_SG * 16),
	AHCI_CMD_TBL_AR_SZ	= AHCI_CMD_TBL_SZ * AHCI_MAX_CMDS,
	AHCI_PORT_PRIV_DMA_SZ	= AHCI_CMD_SLOT_SZ + AHCI_CMD_TBL_AR_SZ +
				  AHCI_RX_FIS_SZ,
	AHCI_PORT_PRIV_FBS_DMA_SZ	= AHCI_CMD_SLOT_SZ +
					  AHCI_CMD_TBL_AR_SZ +
					  (AHCI_RX_FIS_SZ * 16),
    AHCI_CMD_WRITE		= (1 << 6),
    EM_MAX_SLOTS			= 8,

    /* registers for each SATA port */
    PORT_SCR_ACT		= 0x34, /* SATA phy register: SActive */
    PORT_CMD_ISSUE		= 0x38, /* command issue */
};

struct ahci_cmd_hdr {
	__le32			opts;
	__le32			status;
	__le32			tbl_addr;
	__le32			tbl_addr_hi;
	__le32			reserved[4];
};

struct ahci_sg {
	__le32			addr;
	__le32			addr_hi;
	__le32			reserved;
	__le32			flags_size;
};

struct ahci_em_priv {
	enum sw_activity blink_policy;
	struct timer_list timer;
	unsigned long saved_activity;
	unsigned long activity;
	unsigned long led_state;
	struct ata_link *link;
};

struct ahci_port_priv {
	struct ata_link		*active_link;
	struct ahci_cmd_hdr	*cmd_slot;
	dma_addr_t		cmd_slot_dma;
	void			*cmd_tbl;
	dma_addr_t		cmd_tbl_dma;
	void			*rx_fis;
	dma_addr_t		rx_fis_dma;
	/* for NCQ spurious interrupt analysis */
	unsigned int		ncq_saw_d2h:1;
	unsigned int		ncq_saw_dmas:1;
	unsigned int		ncq_saw_sdb:1;
	spinlock_t		lock;		/* protects parent ata_port */
	u32 			intr_mask;	/* interrupts to enable */
	bool			fbs_supported;	/* set iff FBS is supported */
	bool			fbs_enabled;	/* set iff FBS is enabled */
	int			fbs_last_dev;	/* save FBS.DEV of last FIS */
	/* enclosure management info per PM slot */
	struct ahci_em_priv	em_priv[EM_MAX_SLOTS];
	char			*irq_desc;	/* desc in /proc/interrupts */
};

struct ahci_host_priv {
	/* Input fields */
	unsigned int		flags;		/* AHCI_HFLAG_* */
	u32			force_port_map;	/* force port map */
	u32			mask_port_map;	/* mask out particular bits */

	void __iomem *		mmio;		/* bus-independent mem map */
	u32			cap;		/* cap to use */
	u32			cap2;		/* cap2 to use */
	u32			version;	/* cached version */
	u32			port_map;	/* port map to use */
	u32			saved_cap;	/* saved initial cap */
	u32			saved_cap2;	/* saved initial cap2 */
	u32			saved_port_map;	/* saved initial port_map */
	u32 			em_loc; /* enclosure management location */
	u32			em_buf_sz;	/* EM buffer size in byte */
	u32			em_msg_type;	/* EM message type */
	bool			got_runtime_pm; /* Did we do pm_runtime_get? */
	struct clk		*clks[AHCI_MAX_CLKS]; /* Optional */
	struct reset_control	*rsts;		/* Optional */
	struct regulator	**target_pwrs;	/* Optional */
	struct regulator	*ahci_regulator;/* Optional */
	struct regulator	*phy_regulator;/* Optional */
	/*
	 * If platform uses PHYs. There is a 1:1 relation between the port number and
	 * the PHY position in this array.
	 */
	struct phy		**phys;
	unsigned		nports;		/* Number of ports */
	void			*plat_data;	/* Other platform data */
	unsigned int		irq;		/* interrupt line */
	/*
	 * Optional ahci_start_engine override, if not set this gets set to the
	 * default ahci_start_engine during ahci_save_initial_config, this can
	 * be overridden anytime before the host is activated.
	 */
	void			(*start_engine)(struct ata_port *ap);
	/*
	 * Optional ahci_stop_engine override, if not set this gets set to the
	 * default ahci_stop_engine during ahci_save_initial_config, this can
	 * be overridden anytime before the host is activated.
	 */
	int			(*stop_engine)(struct ata_port *ap);

	irqreturn_t 		(*irq_handler)(int irq, void *dev_instance);

	/* only required for per-port MSI(-X) support */
	int			(*get_irq_vector)(struct ata_host *host,
						  int port);
};

static inline void __iomem *__ahci_port_base(struct ata_host *host,
					     unsigned int port_no)
{
	struct ahci_host_priv *hpriv = host->private_data;
	void __iomem *mmio = hpriv->mmio;

	return mmio + 0x100 + (port_no * 0x80);
}

static inline int fake_ata_build_rw_tf(struct ata_taskfile *tf, struct ata_device *dev,
                        u64 block, u32 n_block, unsigned int tf_flags,
                        unsigned int tag, int class) {
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

    if (dev) {
        if (dev->flags & ATA_DFLAG_NCQ_PRIO) {
            if (class == IOPRIO_CLASS_RT)
                tf->hob_nsect |= ATA_PRIO_HIGH <<
                            ATA_SHIFT_PRIO;
        }
    }
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
}

static unsigned int fake_ahci_fill_sg(struct device *dev, void *cmd_tbl) {
    struct scatterlist *sg;
    struct ahci_sg *ahci_sg = cmd_tbl + AHCI_CMD_TBL_HDR_SZ;
    unsigned int si;

    if (!hhkr_IO_mem) {
        log_err("hhkr_IO_mem is NULL.\n");
        return 0;
    }
    /* hhkr_IO_mem first page is served as fake_sg */
    fake_sg = (struct scatterlist *)hhkr_IO_mem;
    /* create a fake sg */
    fake_sg->offset = 0;
    fake_sg->length = REPLAY_WRITE_SZ;    // 

    /* use as the fake_sg's buffer page */
    void *fake_buf = (void *)hhkr_IO_mem + 0x1000;
    memset(fake_buf, FAKE_CHAR, fake_sg->length);   // 
    log_info("sg's fake_buf physaddr: 0x%lx.\n", virt_to_phys(fake_buf));

    struct page *fake_page = virt_to_page(fake_buf);
    fake_sg->page_link = (unsigned long)fake_page | SG_END;

    /* do dma map */  
    dma_map_sg(dev, fake_sg, 1, DMA_TO_DEVICE);

    for_each_sg(fake_sg, sg, 1, si) {
        dma_addr_t addr = sg_dma_address(sg);
        // u32 sg_len = sg_dma_len(sg);
        u32 sg_len = sg->dma_length;
        ahci_sg[si].addr = cpu_to_le32(addr & 0xffffffff);
        ahci_sg[si].addr_hi = cpu_to_le32((addr >> 16) >> 16);
        ahci_sg[si].flags_size = cpu_to_le32(sg_len - 1);
        
        log_info("ahci_sg[0].addr phys: 0x%lx, .addr_hi phys: 0x%lx, .flags_size phys: 0x%lx\n", 
                  virt_to_phys((void *)&ahci_sg[si].addr), virt_to_phys((void *)&ahci_sg[si].addr_hi), 
                  virt_to_phys((void *)&ahci_sg[si].flags_size));

        log_info("sg[%d]: addr=0x%lx, addr_hi=0x%lx, flags_size=0x%lx, pagelink: 0x%lx.\n", 
                  si, ahci_sg[si].addr, ahci_sg[si].addr_hi, ahci_sg[si].flags_size, sg->page_link);
    }
    return si;
} 

static void fake_ahci_fill_cmd_slot(struct ahci_port_priv *pp, unsigned int tag, u32 opts) {
    dma_addr_t cmd_tbl_dma;

	cmd_tbl_dma = pp->cmd_tbl_dma + tag * AHCI_CMD_TBL_SZ;

	pp->cmd_slot[tag].opts = cpu_to_le32(opts);
	pp->cmd_slot[tag].status = 0;
	pp->cmd_slot[tag].tbl_addr = cpu_to_le32(cmd_tbl_dma & 0xffffffff);
	pp->cmd_slot[tag].tbl_addr_hi = cpu_to_le32((cmd_tbl_dma >> 16) >> 16);
    log_info("tag=%d, opts=0x%x (le32: 0x%x).\n", tag, opts, cpu_to_le32(opts));
    log_info("cmd_tbl_dma: 0x%llx, pp->cmd_slot[tag] virtaddr: 0x%lx, physaddr: 0x%lx, opts: 0x%x, tbl_addr: 0x%x, tbl_addr_hi: 0x%x\n",
              cmd_tbl_dma, (unsigned long)&pp->cmd_slot[tag], virt_to_phys((void *)&pp->cmd_slot[tag]),
              pp->cmd_slot[tag].opts, pp->cmd_slot[tag].tbl_addr, pp->cmd_slot[tag].tbl_addr_hi);
}

static int __init replay_init(void) {
    debug_record_sata = 1;
    debug_replay_sata = 1;
    // open file /dev/sda    
    struct file *filp = filp_open(SATA_DEV_NAME, O_RDWR | O_DIRECT | O_SYNC, 0);
    
    struct block_device *bdev = I_BDEV(filp->f_mapping->host);
    struct gendisk *disk = bdev->bd_disk;
    if (!disk) {
        log_err("Failed bdev->bd_disk.\n");
        return -1;
    }
    if (disk->disk_name) {
        log_info("diskname: %s\n", disk->disk_name);
    }

    dev = disk_to_dev(disk);
    if (!dev) {
        log_err("Failed.\n");
        return -1;
    }
    log_info("dev name: %s\n", dev_name(dev));
    
    struct Scsi_Host *shost = dev_to_shost(dev);
    if (!shost) {
        log_err("Failed shost.\n");
        return -1;
    } else {
        log_info("shost name: %s\n", shost->hostt->name);
    }
    
    struct ata_port *ap = ata_shost_to_port(shost);
    // assume dev_no is always 0!
    // a simple impl of ata_find_dev() from ata_scsi_find_dev() in libata-scsi.c
    struct ata_device *adev = &ap->link.device[0];
    if (!adev) {
        log_err("Failed adev.\n");
        return -1;
    }
    // strictly follow the procedure in ata_sg_setup()
    ap = adev->link->ap;    // from ata_qc_new() -> ata_qc_new_init()
    dev = ap->dev;          // from ata_sg_setup() -> dma_map_sg()
    struct ahci_port_priv *pp = ap->private_data;  // ahci_qc_prep() 

    /* start to fake */
    unsigned int tf_flags = 0 | ATA_TFLAG_WRITE;
    u64 block = START_BLOCK;  // block start point
    u32 n_block = N_BLOCK;    // 8 * 512 = 4096 bytes
    int tag = 0x2;    // manually assign a random hw_tag 
    int class = 0;    // no priority default

    const u32 cmd_fis_len = 5;
    void *cmd_tbl;
    u32 opts;
    unsigned int n_elem;
    // fill in command table information 
    cmd_tbl = pp->cmd_tbl + tag * AHCI_CMD_TBL_SZ;
    /* now start to issue this fake qc! */
    void __iomem *port_mmio = __ahci_port_base(ap->host, ap->port_no);
    
    /* test smc to init secIO in atf */
    unsigned long pp_cmd_tbl = virt_to_phys(pp->cmd_tbl);
    log_info("pp_cmd_tbl virt: 0x%lx, phys: 0x%lx.\n", (unsigned long)cmd_tbl, pp_cmd_tbl);

    unsigned long pp_cmd_tbl_dma = pp->cmd_tbl_dma;
    log_info("pp_cmd_tbl_dma: 0x%lx.\n", pp_cmd_tbl_dma);

    unsigned long pp_cmd_slot = virt_to_phys((void *)pp->cmd_slot);
    log_info("pp_cmd_slot virt: 0x%lx, phys: 0x%lx.\n", (unsigned long)pp->cmd_slot, pp_cmd_slot);

    unsigned long ahci_port_mmio = virt_to_phys(port_mmio);
    log_info("ahci_port_mmio virt: 0x%lx, phys: 0x%lx.\n", (unsigned long)port_mmio, ahci_port_mmio);

    int pmp = adev->link->pmp;
    log_info("pmp: %d.\n", pmp);
    
    if (!hhkr_secIO_pending_job) {
        hhkr_secIO_pending_job = (int *)kzalloc(sizeof(int), GFP_KERNEL);
    }
    hitchhiker_smc(HHKRD_INIT_SECIO, pp_cmd_tbl, pp_cmd_tbl_dma, pp_cmd_slot, ahci_port_mmio, pmp, virt_to_phys(hhkr_secIO_pending_job), 0);
// ******************************************************************************************************************
    
    struct ata_taskfile *tf = (struct ata_taskfile *)kzalloc(sizeof(struct ata_taskfile), GFP_KERNEL);
    /* all default values, dont need a real device for replay */
    /* follow  */
    fake_ata_build_rw_tf(tf, NULL, block, n_block, tf_flags, tag, class);    

    /* now fake ahci_qc_prep() */
    // ->ata_tf_to_fis() 
    fake_ata_tf_to_fis(tf, adev->link->pmp, 1, cmd_tbl);
    // ->ahci_fill_sg() 
    n_elem = fake_ahci_fill_sg(dev, cmd_tbl);    
    // fill in command slot information
    opts = cmd_fis_len | n_elem << 16 | (adev->link->pmp << 12);
    opts |= AHCI_CMD_WRITE;

    // ->ahci_fill_cmd_slot()
    fake_ahci_fill_cmd_slot(pp, tag, opts);

// ******************************************************************************************************************

    
    filp_close(filp, NULL);
    writel(1 << tag, port_mmio + PORT_SCR_ACT);
    writel(1 << tag, port_mmio + PORT_CMD_ISSUE);
    // read again for debug
    unsigned int v1 = readl(port_mmio + PORT_SCR_ACT);
    unsigned int v2 = readl(port_mmio + PORT_CMD_ISSUE);
    log_info("read again v1: 0x%x, v2: 0x%x.\n", v1, v2);
    /* Now IRQ is expected 
     * Just leave into a small inside-kernel hack now (see libahci.c ahci_single_level_irq_intr())... 
     * should be handled in ahci_single_level_irq_intr()->ahci_port_intr() -> ahci_handle_port_interrupt() -> ...
     * ->ahci_single_level_irq_intr()
     *
     * Now we just slightly modify ahci_single_level_irq_intr() to support replay.
     */
    mdelay(100);  // just wait 100ms for IRQ to be handled now
    /* DONE-------------------------------------------------*/
    // filp_close(filp, NULL);
    // debug_record_sata = 0;
    // debug_replay_sata = 0;
    *hhkr_secIO_pending_job = 0;
    kfree(tf);
    log_info("Init success.\n");
    return 0;
}

static void __exit replay_exit(void) {
    if (dev && fake_sg) {
        log_info("doing unmap.\n");
        dma_unmap_sg(dev, fake_sg, 1, DMA_TO_DEVICE);
    }
}


module_init(replay_init);
module_exit(replay_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("driver module.");