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

#include <linux/ioctl.h>
#include <linux/syscalls.h>
#include <linux/hitchhiker.h>

#define DEV_NAME    "sata-replay-el3"

// record for device instrumentation
#define ENABLE_RECORD_SATA

#define pr_fmt(fmt) "sata-replay-el3: " fmt
#define log_info(fmt, arg...) \
    printk(KERN_INFO "[%s][%d] "pr_fmt(fmt)"", __func__, __LINE__, ##arg)
#define log_err(fmt, arg...) \
    printk(KERN_ERR "[%s][%d] "pr_fmt(fmt)"", __func__, __LINE__, ##arg)

struct miscdevice *misc;

#define SATA_DEV_NAME "/dev/sda"

#define DMA_TO_DEVICE 1
#define BLK_SZ          512

// #define REPLAY_WRITE_SZ (1 << 20) * 4             // 4MB
#define REPLAY_WRITE_SZ (1 << 12)  // 4KB
#define N_BLOCK         REPLAY_WRITE_SZ / BLK_SZ
#define START_BLOCK     1 * N_BLOCK
#define FAKE_CHAR       'X'

struct ata_device *ata_dev = NULL;
struct device *dev = NULL;
struct scatterlist *fake_sg = NULL;

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

typedef struct hitchhiker_el3_scatterlist_pgs {
    /* 1. scatterlist */
    struct scatterlist sg;
    /* 2. metadata */
    unsigned long pgs_phys_addr;
    unsigned long pgs_kern_addr;
    unsigned long pgs_user_addr;
    /* 3. buffer */
} hhkr_scatterlist_pgs_t;

extern bool debug_record_sata;
extern bool debug_replay_sata;
extern int *hhkr_secIO_pending_job;
extern bool fetch_debug_record_sata(void);
extern void set_debug_record_sata(bool val);

extern bool fetch_debug_replay_sata(void);
extern void set_debug_replay_sata(bool val);

extern int __hhkr_secure_IO_init(void);
extern int __hhkr_sg_pgs_alloc(struct device *dev, int obs_type, unsigned int buf_size);
extern hhkr_scatterlist_pgs_t *hhkr_obs_sg_pgs[__HHKR_OBS_MAX_ID][2];

static void fill_content(hhkr_scatterlist_pgs_t *hhkr_sg_pg) {
    void *fakebuf = (void *)hhkr_sg_pg + 0x1000;
    memset(fakebuf, FAKE_CHAR, hhkr_sg_pg->sg.length);
}

static inline void __iomem *__ahci_port_base(struct ata_host *host,
					     unsigned int port_no)
{
	struct ahci_host_priv *hpriv = host->private_data;
	void __iomem *mmio = hpriv->mmio;

	return mmio + 0x100 + (port_no * 0x80);
}

// static unsigned int fake_ahci_fill_sg(struct device *dev) {
//     struct scatterlist *sg;
//     unsigned int si;

//     if (!hhkr_IO_mem) {
//         log_err("hhkr_IO_mem is NULL.\n");
//         return 0;
//     }
//     /* hhkr_IO_mem first page is served as fake_sg */
//     hhkr_scatterlist_pgs_t *hhkr_pgs = (hhkr_scatterlist_pgs_t *)hhkr_IO_mem;
//     fake_sg = &hhkr_pgs->sg;
//     /* create a fake sg */
//     fake_sg->offset = 0;
//     // fake_sg->length = 0x1000;
//     fake_sg->length = REPLAY_WRITE_SZ;    // 
//     log_info("fake_sg: 0x%lx.\n", (unsigned long)fake_sg);
//     /* use as the fake_sg's buffer page */
//     void *fake_buf = (void *)hhkr_IO_mem + 0x1000;
//     memset(fake_buf, FAKE_CHAR, fake_sg->length);   // 

//     struct page *fake_page = virt_to_page(fake_buf);
//     fake_sg->page_link = (unsigned long)fake_page | SG_END;

//     /* do dma map */  
//     dma_map_sg(dev, fake_sg, 1, DMA_TO_DEVICE);
//     return si;
// } 

static int __init replay_init(void) {
    set_debug_record_sata(true);
    set_debug_replay_sata(true);
    // // open file /dev/sda    
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
    // /* inspect */
    // log_info("pp->cmd_slot_dma = 0x%llx, pp->cmd_tbl_dma = 0x%llx, pp->rx_fis_dma = 0x%llx, pp->rx_fis = 0x%lx, pp->cmd_slot = 0x%lx, pp->cmd_tbl = 0x%lx.\n",
    //             pp->cmd_slot_dma, pp->cmd_tbl_dma, pp->rx_fis_dma, (unsigned long)pp->rx_fis, (unsigned long)pp->cmd_slot, (unsigned long)pp->cmd_tbl);
    // /* start to fake */
    // unsigned int tf_flags = 0 | ATA_TFLAG_WRITE;
    // u64 block = START_BLOCK;  // block start point
    // u32 n_block = N_BLOCK;    // 8 * 512 = 4096 bytes
    int tag = 0x2;    // manually assign a random hw_tag 
    // int class = 0;    // no priority default
    // struct ata_taskfile *tf = (struct ata_taskfile *)kzalloc(sizeof(struct ata_taskfile), GFP_KERNEL);
    
    // // const u32 cmd_fis_len = 5;
    // // void *cmd_tbl;
    // // u32 opts;
    // unsigned int n_elem;
    // // // fill in command table information 
    // // cmd_tbl = pp->cmd_tbl + tag * AHCI_CMD_TBL_SZ;

    // // // ->ahci_fill_sg() 
    // n_elem = fake_ahci_fill_sg(dev);
    // hhkr_scatterlist_pgs_t *hhkr_pgs = (hhkr_scatterlist_pgs_t *)hhkr_IO_mem;
    // hhkr_pgs->pgs_kern_addr = (unsigned long)hhkr_pgs;
    // hhkr_pgs->pgs_phys_addr = virt_to_phys(hhkr_pgs);
    
    filp_close(filp, NULL);
    void __iomem *port_mmio = __ahci_port_base(ap->host, ap->port_no);
    
    // /* test smc to init secIO in atf */
    // unsigned long pptag_cmd_tbl = virt_to_phys(cmd_tbl);
    // log_info("pptag_cmd_tbl virt: 0x%lx, phys: 0x%lx.\n", (unsigned long)cmd_tbl, pptag_cmd_tbl);
    // unsigned long pptag_cmd_tbl_dma = pp->cmd_tbl_dma + tag * AHCI_CMD_TBL_SZ;
    // log_info("pptag_cmd_tbl_dma: 0x%lx, size: %lu.\n", pptag_cmd_tbl_dma, sizeof(pp->cmd_tbl_dma));
    // unsigned long pptag_cmd_slot = virt_to_phys((void *)&pp->cmd_slot[tag]);
    // log_info("pptag_cmd_slot virt: 0x%lx, phys: 0x%lx.\n", (unsigned long)&pp->cmd_slot[tag], pptag_cmd_slot);
    // unsigned long ahci_port_mmio = virt_to_phys(port_mmio);
    // log_info("ahci_port_mmio virt: 0x%lx, phys: 0x%lx.\n", (unsigned long)port_mmio, ahci_port_mmio);
    // int pmp = adev->link->pmp;
    // log_info("pmp: %d.\n", pmp);
    // /* init */
    // hitchhiker_smc(HHKRD_INIT_SECIO, pptag_cmd_tbl, pptag_cmd_tbl_dma, pptag_cmd_slot, ahci_port_mmio, pmp, 0, 0);
    // init io
    __hhkr_secure_IO_init();

    /* assign */
    *hhkr_secIO_pending_job = 0;
    hhkr_scatterlist_pgs_t *hhkr_pgs = hhkr_obs_sg_pgs[0][0];
    hitchhiker_smc(HHKRD_DO_SECIO, hhkr_pgs->pgs_phys_addr, 0, REPLAY_WRITE_SZ, 0, 0, 0, 0);
    
    writel(1 << tag, port_mmio + PORT_SCR_ACT);
    writel(1 << tag, port_mmio + PORT_CMD_ISSUE);

    int test = *hhkr_secIO_pending_job;
    log_info("dbgprint hhkr_secIO_pending_job: %d (phys addr: 0x%lx) replay_sata: %d.\n", 
              test, (unsigned long)virt_to_phys(hhkr_secIO_pending_job), fetch_debug_replay_sata());
    mdelay(500);
    /* DONE-------------------------------------------------*/

    set_debug_record_sata(false);
    set_debug_replay_sata(false);
    // kfree(tf);
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