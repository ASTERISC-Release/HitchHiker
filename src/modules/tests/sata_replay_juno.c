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

#define DEV_NAME    "sata-replay-juno"

#define SATA_DEV_NAME "/dev/sda"
#define DEBUGLABEL (1)

#include <linux/printk.h>
#include <linux/types.h>
#include <linux/hitchhiker.h>


typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned int  u32;
typedef unsigned char u8;

#define BLOCK_SZ        512
#define DMA_TO_DEVICE   1
#define CMD_FIS_LEN		5
#define SG_N_ELEM	    1

struct cma
{
    unsigned long base_pfn;
    unsigned long count;
    unsigned long *bitmap;
    unsigned int order_per_bit; /* Order of pages represented by one bit */
    struct mutex lock;
#ifdef CONFIG_CMA_DEBUGFS
    struct hlist_head mem_head;
    spinlock_t mem_head_lock;
#endif
    const char *name;
};

/* export from linux kernel */
extern struct cma cma_areas[MAX_CMA_AREAS];
extern unsigned int cma_area_count;

static inline unsigned long cma_bitmap_maxno(struct cma *cma)
{
    return cma->count >> cma->order_per_bit;
}
static inline struct cma *cma_allocator_search(char *name) {
    int i;
    // printk(KERN_INFO "total cma count: %u, %d.\n", cma_area_count, MAX_CMA_AREAS);
    for (i = 0; i < cma_area_count; i++) {
        // printk(KERN_INFO "targ_name: %s, searched_name: %s.\n", name, cma_areas[i].name);
        if (strcmp(name, cma_areas[i].name) == 0)
            return &cma_areas[i];
    }
    return NULL;
}
/* logger buffer pool allocator */
#define CMA_HKKR_BUF_POOL       "bufpool@84400000"
#define CMA_HKKR_RECVD_POOL     "mempool@b0000000"
/* helpers */
extern struct cma *cma_logger_pool;
#define AL_logger   ({  \
    if (!cma_logger_pool) \
        cma_logger_pool = cma_allocator_search(CMA_HKKR_BUF_POOL); \
    (struct cma*)cma_logger_pool;   \
})

struct hhkr_scatterlist {
    unsigned long page_link;
    unsigned int  offset;
    unsigned int  length;
    unsigned long dma_address;
    unsigned int  dma_length;
};

/*
 * =================================================================================
 * Memory Layout (page align)
 * =================================================================================
 * scatterlist sg  |  metadata  | padding | Buffer contains I/O data
 * |<------------------------------------>|<--------------------------------------->
 * |               4 KB                   | 1MB or 4MB by default 
 * =================================================================================
 */
typedef struct hitchhiker_el1_scatterlist_pgs {
    /* 1. scatterlist */
    struct hhkr_scatterlist sg;
    /* 2. metadata */
    unsigned long pgs_phys_addr;
    unsigned long pgs_kern_addr;
    unsigned long pgs_user_addr;
	unsigned int cur_pos;
	unsigned int buf_size;

	unsigned long blk_start;  // write block start
	unsigned long write_size; // write block size
    /* 3. buffer */
} hhkr_scatterlist_pgs_t;




/* build for JUNO's sil24 */
struct sil24_prb {   // all le
	u16	ctrl;
	u16	prot;
	u32	rx_cnt;
	u8	fis[6 * 4];
};

/*
 * Scatter gather entry (SGE) 16 bytes
 */
struct sil24_sge {
	u64	addr;
	u32	cnt;
	u32	flags;
};


enum {
	SIL24_HOST_BAR		= 0,
	SIL24_PORT_BAR		= 2,

	/* sil24 fetches in chunks of 64bytes.  The first block
	 * contains the PRB and two SGEs.  From the second block, it's
	 * consisted of four SGEs and called SGT.  Calculate the
	 * number of SGTs that fit into one page.
	 */
	SIL24_PRB_SZ		= sizeof(struct sil24_prb)
				  + 2 * sizeof(struct sil24_sge),
	SIL24_MAX_SGT		= (PAGE_SIZE - SIL24_PRB_SZ)
				  / (4 * sizeof(struct sil24_sge)),

	/* This will give us one unused SGEs for ATA.  This extra SGE
	 * will be used to store CDB for ATAPI devices.
	 */
	SIL24_MAX_SGE		= 4 * SIL24_MAX_SGT + 1,

	/*
	 * Global controller registers (128 bytes @ BAR0)
	 */
		/* 32 bit regs */
	HOST_SLOT_STAT		= 0x00, /* 32 bit slot stat * 4 */
	HOST_CTRL		= 0x40,
	HOST_IRQ_STAT		= 0x44,
	HOST_PHY_CFG		= 0x48,
	HOST_BIST_CTRL		= 0x50,
	HOST_BIST_PTRN		= 0x54,
	HOST_BIST_STAT		= 0x58,
	HOST_MEM_BIST_STAT	= 0x5c,
	HOST_FLASH_CMD		= 0x70,
		/* 8 bit regs */
	HOST_FLASH_DATA		= 0x74,
	HOST_TRANSITION_DETECT	= 0x75,
	HOST_GPIO_CTRL		= 0x76,
	HOST_I2C_ADDR		= 0x78, /* 32 bit */
	HOST_I2C_DATA		= 0x7c,
	HOST_I2C_XFER_CNT	= 0x7e,
	HOST_I2C_CTRL		= 0x7f,

	/* HOST_SLOT_STAT bits */
	HOST_SSTAT_ATTN		= (1 << 31),

	/* HOST_CTRL bits */
	HOST_CTRL_M66EN		= (1 << 16), /* M66EN PCI bus signal */
	HOST_CTRL_TRDY		= (1 << 17), /* latched PCI TRDY */
	HOST_CTRL_STOP		= (1 << 18), /* latched PCI STOP */
	HOST_CTRL_DEVSEL	= (1 << 19), /* latched PCI DEVSEL */
	HOST_CTRL_REQ64		= (1 << 20), /* latched PCI REQ64 */
	HOST_CTRL_GLOBAL_RST	= (1 << 31), /* global reset */

	/*
	 * Port registers
	 * (8192 bytes @ +0x0000, +0x2000, +0x4000 and +0x6000 @ BAR2)
	 */
	PORT_REGS_SIZE		= 0x2000,

	PORT_LRAM		= 0x0000, /* 31 LRAM slots and PMP regs */
	PORT_LRAM_SLOT_SZ	= 0x0080, /* 32 bytes PRB + 2 SGE, ACT... */

	PORT_PMP		= 0x0f80, /* 8 bytes PMP * 16 (128 bytes) */
	PORT_PMP_STATUS		= 0x0000, /* port device status offset */
	PORT_PMP_QACTIVE	= 0x0004, /* port device QActive offset */
	PORT_PMP_SIZE		= 0x0008, /* 8 bytes per PMP */

		/* 32 bit regs */
	PORT_CTRL_STAT		= 0x1000, /* write: ctrl-set, read: stat */
	PORT_CTRL_CLR		= 0x1004, /* write: ctrl-clear */
	PORT_IRQ_STAT		= 0x1008, /* high: status, low: interrupt */
	PORT_IRQ_ENABLE_SET	= 0x1010, /* write: enable-set */
	PORT_IRQ_ENABLE_CLR	= 0x1014, /* write: enable-clear */
	PORT_ACTIVATE_UPPER_ADDR= 0x101c,
	PORT_EXEC_FIFO		= 0x1020, /* command execution fifo */
	PORT_CMD_ERR		= 0x1024, /* command error number */
	PORT_FIS_CFG		= 0x1028,
	PORT_FIFO_THRES		= 0x102c,
		/* 16 bit regs */
	PORT_DECODE_ERR_CNT	= 0x1040,
	PORT_DECODE_ERR_THRESH	= 0x1042,
	PORT_CRC_ERR_CNT	= 0x1044,
	PORT_CRC_ERR_THRESH	= 0x1046,
	PORT_HSHK_ERR_CNT	= 0x1048,
	PORT_HSHK_ERR_THRESH	= 0x104a,
		/* 32 bit regs */
	PORT_PHY_CFG		= 0x1050,
	PORT_SLOT_STAT		= 0x1800,
	PORT_CMD_ACTIVATE	= 0x1c00, /* 64 bit cmd activate * 31 (248 bytes) */
	PORT_CONTEXT		= 0x1e04,
	PORT_EXEC_DIAG		= 0x1e00, /* 32bit exec diag * 16 (64 bytes, 0-10 used on 3124) */
	PORT_PSD_DIAG		= 0x1e40, /* 32bit psd diag * 16 (64 bytes, 0-8 used on 3124) */
	PORT_SCONTROL		= 0x1f00,
	PORT_SSTATUS		= 0x1f04,
	PORT_SERROR		= 0x1f08,
	PORT_SACTIVE		= 0x1f0c,

	/* PORT_CTRL_STAT bits */
	PORT_CS_PORT_RST	= (1 << 0), /* port reset */
	PORT_CS_DEV_RST		= (1 << 1), /* device reset */
	PORT_CS_INIT		= (1 << 2), /* port initialize */
	PORT_CS_IRQ_WOC		= (1 << 3), /* interrupt write one to clear */
	PORT_CS_CDB16		= (1 << 5), /* 0=12b cdb, 1=16b cdb */
	PORT_CS_PMP_RESUME	= (1 << 6), /* PMP resume */
	PORT_CS_32BIT_ACTV	= (1 << 10), /* 32-bit activation */
	PORT_CS_PMP_EN		= (1 << 13), /* port multiplier enable */
	PORT_CS_RDY		= (1 << 31), /* port ready to accept commands */

	/* PORT_IRQ_STAT/ENABLE_SET/CLR */
	/* bits[11:0] are masked */
	PORT_IRQ_COMPLETE	= (1 << 0), /* command(s) completed */
	PORT_IRQ_ERROR		= (1 << 1), /* command execution error */
	PORT_IRQ_PORTRDY_CHG	= (1 << 2), /* port ready change */
	PORT_IRQ_PWR_CHG	= (1 << 3), /* power management change */
	PORT_IRQ_PHYRDY_CHG	= (1 << 4), /* PHY ready change */
	PORT_IRQ_COMWAKE	= (1 << 5), /* COMWAKE received */
	PORT_IRQ_UNK_FIS	= (1 << 6), /* unknown FIS received */
	PORT_IRQ_DEV_XCHG	= (1 << 7), /* device exchanged */
	PORT_IRQ_8B10B		= (1 << 8), /* 8b/10b decode error threshold */
	PORT_IRQ_CRC		= (1 << 9), /* CRC error threshold */
	PORT_IRQ_HANDSHAKE	= (1 << 10), /* handshake error threshold */
	PORT_IRQ_SDB_NOTIFY	= (1 << 11), /* SDB notify received */

	DEF_PORT_IRQ		= PORT_IRQ_COMPLETE | PORT_IRQ_ERROR |
				  PORT_IRQ_PHYRDY_CHG | PORT_IRQ_DEV_XCHG |
				  PORT_IRQ_UNK_FIS | PORT_IRQ_SDB_NOTIFY,

	/* bits[27:16] are unmasked (raw) */
	PORT_IRQ_RAW_SHIFT	= 16,
	PORT_IRQ_MASKED_MASK	= 0x7ff,
	PORT_IRQ_RAW_MASK	= (0x7ff << PORT_IRQ_RAW_SHIFT),

	/* ENABLE_SET/CLR specific, intr steering - 2 bit field */
	PORT_IRQ_STEER_SHIFT	= 30,
	PORT_IRQ_STEER_MASK	= (3 << PORT_IRQ_STEER_SHIFT),

	/* PORT_CMD_ERR constants */
	PORT_CERR_DEV		= 1, /* Error bit in D2H Register FIS */
	PORT_CERR_SDB		= 2, /* Error bit in SDB FIS */
	PORT_CERR_DATA		= 3, /* Error in data FIS not detected by dev */
	PORT_CERR_SEND		= 4, /* Initial cmd FIS transmission failure */
	PORT_CERR_INCONSISTENT	= 5, /* Protocol mismatch */
	PORT_CERR_DIRECTION	= 6, /* Data direction mismatch */
	PORT_CERR_UNDERRUN	= 7, /* Ran out of SGEs while writing */
	PORT_CERR_OVERRUN	= 8, /* Ran out of SGEs while reading */
	PORT_CERR_PKT_PROT	= 11, /* DIR invalid in 1st PIO setup of ATAPI */
	PORT_CERR_SGT_BOUNDARY	= 16, /* PLD ecode 00 - SGT not on qword boundary */
	PORT_CERR_SGT_TGTABRT	= 17, /* PLD ecode 01 - target abort */
	PORT_CERR_SGT_MSTABRT	= 18, /* PLD ecode 10 - master abort */
	PORT_CERR_SGT_PCIPERR	= 19, /* PLD ecode 11 - PCI parity err while fetching SGT */
	PORT_CERR_CMD_BOUNDARY	= 24, /* ctrl[15:13] 001 - PRB not on qword boundary */
	PORT_CERR_CMD_TGTABRT	= 25, /* ctrl[15:13] 010 - target abort */
	PORT_CERR_CMD_MSTABRT	= 26, /* ctrl[15:13] 100 - master abort */
	PORT_CERR_CMD_PCIPERR	= 27, /* ctrl[15:13] 110 - PCI parity err while fetching PRB */
	PORT_CERR_XFR_UNDEF	= 32, /* PSD ecode 00 - undefined */
	PORT_CERR_XFR_TGTABRT	= 33, /* PSD ecode 01 - target abort */
	PORT_CERR_XFR_MSTABRT	= 34, /* PSD ecode 10 - master abort */
	PORT_CERR_XFR_PCIPERR	= 35, /* PSD ecode 11 - PCI prity err during transfer */
	PORT_CERR_SENDSERVICE	= 36, /* FIS received while sending service */

	/* bits of PRB control field */
	PRB_CTRL_PROTOCOL	= (1 << 0), /* override def. ATA protocol */
	PRB_CTRL_PACKET_READ	= (1 << 4), /* PACKET cmd read */
	PRB_CTRL_PACKET_WRITE	= (1 << 5), /* PACKET cmd write */
	PRB_CTRL_NIEN		= (1 << 6), /* Mask completion irq */
	PRB_CTRL_SRST		= (1 << 7), /* Soft reset request (ign BSY?) */

	/* PRB protocol field */
	PRB_PROT_PACKET		= (1 << 0),
	PRB_PROT_TCQ		= (1 << 1),
	PRB_PROT_NCQ		= (1 << 2),
	PRB_PROT_READ		= (1 << 3),
	PRB_PROT_WRITE		= (1 << 4),
	PRB_PROT_TRANSPARENT	= (1 << 5),

	/*
	 * Other constants
	 */
	SGE_TRM			= (1 << 31), /* Last SGE in chain */
	SGE_LNK			= (1 << 30), /* linked list
						Points to SGT, not SGE */
	SGE_DRD			= (1 << 29), /* discard data read (/dev/null)
						data address ignored */

	SIL24_MAX_CMDS		= 31,

	/* board id */
	BID_SIL3124		= 0,
	BID_SIL3132		= 1,
	BID_SIL3131		= 2,

	/* host flags */
	SIL24_COMMON_FLAGS	= ATA_FLAG_SATA | ATA_FLAG_PIO_DMA |
				  ATA_FLAG_NCQ | ATA_FLAG_ACPI_SATA |
				  ATA_FLAG_AN | ATA_FLAG_PMP,
	SIL24_FLAG_PCIX_IRQ_WOC	= (1 << 24), /* IRQ loss errata on PCI-X */

	IRQ_STAT_4PORTS		= 0xf,
};

struct sil24_ata_block {
	struct sil24_prb prb;
	struct sil24_sge sge[SIL24_MAX_SGE];
};

struct sil24_atapi_block {
	struct sil24_prb prb;
	u8 cdb[16];
	struct sil24_sge sge[SIL24_MAX_SGE];
};

union sil24_cmd_block {
	struct sil24_ata_block ata;
	struct sil24_atapi_block atapi;
};

struct sil24_port_priv {
	union sil24_cmd_block *cmd_block;	/* 32 cmd blocks */
	u64 cmd_block_dma;		/* DMA base addr for them (dma_addr_t) */
	int do_port_rst;
};


struct hhkr_ata_taskfile {
    unsigned long		flags;		/* ATA_TFLAG_xxx */
	u8			protocol;	/* ATA_PROT_xxx */

	u8			ctl;		/* control reg */

	u8			hob_feature;	/* additional data */
	u8			hob_nsect;	/* to support LBA48 */
	u8			hob_lbal;
	u8			hob_lbam;
	u8			hob_lbah;

	u8			feature;
	u8			nsect;
	u8			lbal;
	u8			lbam;
	u8			lbah;

	u8			device;

	u8			command;	/* IO operation */

	u32			auxiliary;	/* auxiliary field */
};


extern bool debug_record_sata;
extern bool debug_replay_sata;
extern int *hhkr_secIO_pending_job;
extern bool fetch_debug_record_sata(void);



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
struct sil24_prb *hhkr_prb = NULL;
unsigned long hhkr_prb_phys = 0;

struct sil24_sge *hhkr_sge = NULL;
unsigned long hhkr_sge_phys = 0;

unsigned long pp_cmd_blk_dma = 0;
unsigned long pp_cmd_blk_phys = 0;

unsigned long pp_cmd_blk_size = 0;
int pmp, _tf_ctl;
struct ata_device *ata_dev = NULL;
struct device *dev = NULL;
hhkr_scatterlist_pgs_t* sg_pgs = NULL;

#define HHKR_NON_NCQ
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
    
    // init plat
    hhkr_port_base_mmio_virt = port_base_mmio_virt;
    hhkr_port_base_mmio_phys = virt_to_phys((void *)hhkr_port_base_mmio_virt);
#if DEBUGLABEL
    log_info("port_base_mmio_virt: 0x%lx, port_base_mmio_phys: 0x%lx.\n",
              hhkr_port_base_mmio_virt, hhkr_port_base_mmio_phys);
#endif

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
#if DEBUGLABEL	
    log_info("hhkr_prb phys: 0x%lx, hhkr_sge phys: 0x%lx, pp->cmd_blk_dma: 0x%lx (0x%lx phys?), prb->fis phys: 0x%llx.\n",
              hhkr_prb_phys, hhkr_sge_phys, pp_cmd_blk_dma, pp_cmd_blk_phys, virt_to_phys((void *)(hhkr_prb->fis)));
#endif
    hitchhiker_smc(HHKRD_INIT_SECIO_JUNO, hhkr_prb_phys, hhkr_sge_phys, pp_cmd_blk_dma, pp_cmd_blk_size,
                   hhkr_port_base_mmio_phys, tf_ctl, virt_to_phys((void *)hhkr_secIO_job_pending));
    return 0;
}



static void print_all_info(unsigned long paddr, unsigned long activate) {
    /* print prb first */
    log_info("prb->ctrl (phys:0x%lx) val: 0x%x.\n", virt_to_phys((void*)&hhkr_prb->ctrl), hhkr_prb->ctrl);
    log_info("prb->prot (phys:0x%lx) val: 0x%x.\n", virt_to_phys((void*)&hhkr_prb->prot), hhkr_prb->prot);
    log_info("prb->rx_cnt (phys:0x%lx) val: 0x%x.\n", virt_to_phys((void*)&hhkr_prb->rx_cnt), hhkr_prb->rx_cnt);
    u8 *fis = hhkr_prb->fis;
    log_info("prb->fis (phys:0x%lx) val:\n", virt_to_phys((void*)fis));
    log_info("===> fis[0]: 0x%x, fis[1]: 0x%x, fis[2]: 0x%x, fis[3]: 0x%x, fis[4]: 0x%x, fis[5]: 0x%x, fis[6]: 0x%x, fis[7]: 0x%x, fis[8]: 0x%x, fis[9]: 0x%x, fis[10]: 0x%x, fis[11]: 0x%x, fis[12]: 0x%x, fis[13]: 0x%x, fis[14]: 0x%x, fis[15]: 0x%x, fis[16]: 0x%x, fis[17]: 0x%x, fis[18]: 0x%x, fis[19]: 0x%x.\n", 
                   fis[0], fis[1], fis[2], fis[3], fis[4], fis[5], fis[6], fis[7], fis[8], fis[9], fis[10], fis[11], fis[12], fis[13], fis[14], fis[15], fis[16], fis[17], fis[18], fis[19]);

    /* print sge then */
    log_info("sge->addr (phys:0x%lx) val: 0x%lx.\n", virt_to_phys((void*)&hhkr_sge->addr), hhkr_sge->addr);
    log_info("sge->cnt (phys:0x%lx) val: 0x%x.\n", virt_to_phys((void*)&hhkr_sge->cnt), hhkr_sge->cnt);
    log_info("sge->flags (phys:0x%lx) val: 0x%x.\n", virt_to_phys((void*)&hhkr_sge->flags), hhkr_sge->flags);
    
    /* print mmios final */
    log_info("paddr (dma): 0x%lx, activate (iomem) phys: 0x%lx.\n", 
              paddr, virt_to_phys((void *)activate));
}


static int hhkrd_secIO_assignjob_juno(unsigned long scatterlist_pgs, unsigned long blk_start, unsigned long write_size) 
{
    unsigned long block, addr, paddr;
    void __iomem *activate;
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

    /* DEBUG EL3 (now do all things unless MMIOs!) */
    hhkr_sg_pgs = (hhkr_scatterlist_pgs_t *)scatterlist_pgs;
    hitchhiker_smc(HHKRD_ASSIGN_SECIO_JUNO, hhkr_sg_pgs->pgs_phys_addr, blk_start, write_size, 0, 0, 0, 0);
    // return 0;
    log_info("\n<INFOS AFTER SMC>:\n\n");
    paddr = pp_cmd_blk_dma + hhkr_tag * pp_cmd_blk_size; // dma_addr_t
    activate = (void *)hhkr_port_base_mmio_virt + PORT_CMD_ACTIVATE + hhkr_tag * 8;
    print_all_info(paddr, activate);

    // /* 0. build the taskfile tf */
    // block = blk_start;
    // n_block = write_size / BLOCK_SZ;
    // tf_flags = 0 | ATA_TFLAG_WRITE;
    // fake_ata_build_rw_tf(&hhkr_faketf, block, n_block, tf_flags, hhkr_tag);
    // (&hhkr_faketf)->ctl = _tf_ctl;
    // /* let's do the top-level ata_qc_issue */

    // /* 1.1 ata_qc_issue => ata_sg_setup */
    // /*
    //  * this has been already done during initialization (dma_map_sg)
    //  * when setting up the hhkr_sg_pgs.
    //  * we just need to extract from the parameter now.
    //  */
    // hhkr_sg_pgs = (hhkr_scatterlist_pgs_t *)scatterlist_pgs;
 
    // /* 1.2 ata_qc_issue => ap->ops->qc_prep(pc) : sil24_qc_prep */

    // /* 1.2.1 sil24_qc_prep => ata_tf_to_fis */
    // fake_ata_tf_to_fis(&hhkr_faketf, pmp, 1, hhkr_prb->fis);

    // /* 1.2.2 sil24_qc_prep => sil24_fill_sg */
    // /* we assume only one sg always! */
    // addr = hhkr_sg_pgs->sg.dma_address;
    // sg_len = hhkr_sg_pgs->sg.dma_length;
    // hhkr_sge->addr = cpu_to_le64(addr);
    // hhkr_sge->cnt = cpu_to_le32(sg_len);
    // hhkr_sge->flags = cpu_to_le32(SGE_TRM);

    // // /* 1.3 ata_qc_issue => ap->ops->qc_issue(qc) : sil24_qc_issue */
    // paddr = pp_cmd_blk_dma + hhkr_tag * pp_cmd_blk_size; // dma_addr_t
    // activate = (void *)hhkr_port_base_mmio_virt + PORT_CMD_ACTIVATE + hhkr_tag * 8;
// # if DEBUGLABEL
//     log_info("paddr: 0x%lx (phys: 0x%lx), activate: 0x%lx (phys: 0x%lx).\n",
//               paddr, (unsigned long)activate,
//               (unsigned long)virt_to_phys((void *)paddr), (unsigned long)virt_to_phys((void *)activate));
// #endif
    // log_info("\n<INFOS AFTER EL1 SELF CONFIG>:\n\n");
    // print_all_info(paddr, activate);
        wmb();
        writel((u32)paddr, activate);
        writel((u64)paddr >> 32, activate + 4);
    return 0;
}


extern int *hhkr_secIO_pending_job;

static int __init replay_init(void) {
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

    int length = PAGE_SIZE + SZ_1M;   // a page for metadata, and a 1MB buffer
    unsigned int pg_align = get_order(length);
    struct page *page = cma_alloc(AL_logger, (length >> PAGE_SHIFT), pg_align, GFP_KERNEL);
    
    sg_pgs = (hhkr_scatterlist_pgs_t*)page_to_virt(page);
    sg_pgs->pgs_kern_addr = (unsigned long)sg_pgs;
    sg_pgs->pgs_phys_addr = (unsigned long)virt_to_phys((void*)sg_pgs);
    sg_pgs->pgs_user_addr = 0;     // unmapped yet.
    sg_pgs->cur_pos = 0;
    sg_pgs->buf_size = SZ_1M;
    /* configure it's scatterlist */
    void *buf_start = (void *)sg_pgs + PAGE_SIZE;
    sg_pgs->sg.page_link = (unsigned long)virt_to_page(buf_start) | SG_END;
    sg_pgs->sg.offset = 0;
    sg_pgs->sg.length = SZ_1M;
    /* fill buf content */
    memset(buf_start, 'C', sg_pgs->buf_size);
    sg_pgs->blk_start = 0x0 + (SZ_1M / BLOCK_SZ) + (SZ_1M / BLOCK_SZ) + (SZ_1M / BLOCK_SZ);
    sg_pgs->write_size = sg_pgs->buf_size;
    // debug_record_sata = 1;
    // debug_replay_sata = 1;
    /* dma_map_sg */
    dma_map_sg(dev, (struct scatterlist *)&(sg_pgs->sg), 1, DMA_TO_DEVICE);
    // debug_record_sata = 0;
    // debug_replay_sata = 0;

    /* init  */
    int SIL24_PORT_BAR = 2;
    int PORT_REGS_SIZE = 0x2000;
    if (!hhkr_secIO_pending_job) {
        hhkr_secIO_pending_job = (int *)kzalloc(sizeof(int), GFP_KERNEL);
    }
    /* 0x8118dc00 */
    unsigned long sil24_port_mmio_virt = ap->host->iomap[SIL24_PORT_BAR] + ap->port_no * PORT_REGS_SIZE;
    hhkrd_secIO_init_juno((void *)ap->private_data, sil24_port_mmio_virt, adev->link->pmp,
                           adev->link->ap->ctl, (unsigned long)hhkr_secIO_pending_job);

    /* assign */
    hhkrd_secIO_assignjob_juno((unsigned long)sg_pgs, sg_pgs->blk_start, sg_pgs->write_size);
    log_info("Init success.\n");
    return 0;
}


static void __exit replay_exit(void) {
    if (dev && sg_pgs) {
        log_info("doing unmap.\n");
        dma_unmap_sg(dev, (struct scatterlist *)&(sg_pgs->sg), 1, DMA_TO_DEVICE);
    }
}


module_init(replay_init);
module_exit(replay_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("driver module.");
