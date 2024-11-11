#ifndef _HHKR_SECIO_DRIVER_EL1_H
#define _HHKR_SECIO_DRIVER_EL1_H

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


/* common ATA includes */
enum {
	ATA_MAX_SECTORS		= 256,
	ATA_MAX_SECTORS_LBA48	= 65535,
	/* struct ata_taskfile flags */
	ATA_TFLAG_LBA48		= (1 << 0), /* enable 48-bit LBA and "HOB" */
	ATA_TFLAG_ISADDR	= (1 << 1), /* enable r/w to nsect/lba regs */
	ATA_TFLAG_DEVICE	= (1 << 2), /* enable r/w to device reg */
	ATA_TFLAG_WRITE		= (1 << 3), /* data dir: host->dev==1 (write) */
	ATA_TFLAG_LBA		= (1 << 4), /* enable LBA */
	ATA_TFLAG_FUA		= (1 << 5), /* enable FUA */
	ATA_TFLAG_POLLING	= (1 << 6), /* set nIEN to 1 and use polling */

    ATA_LBA			= (1 << 6),	/* LBA28 selector */
	ATA_DEVICE_OBS		= (1 << 7) | (1 << 5), /* obs bits in dev reg */
	ATA_CMD_FPDMA_READ	= 0x60,
    ATA_CMD_FPDMA_WRITE	= 0x61,
	ATA_CMD_FLUSH_EXT	= 0xEA,
	ATA_CMD_WRITE		= 0xCA,
	/* struct ata_port flags */
	ATA_FLAG_SLAVE_POSS	= (1 << 0), /* host supports slave dev */
					    /* (doesn't imply presence) */
	ATA_FLAG_SATA		= (1 << 1),
	ATA_FLAG_NO_LPM		= (1 << 2), /* host not happy with LPM */
	ATA_FLAG_NO_LOG_PAGE	= (1 << 5), /* do not issue log page read */
	ATA_FLAG_NO_ATAPI	= (1 << 6), /* No ATAPI support */
	ATA_FLAG_PIO_DMA	= (1 << 7), /* PIO cmds via DMA */
	ATA_FLAG_PIO_LBA48	= (1 << 8), /* Host DMA engine is LBA28 only */
	ATA_FLAG_PIO_POLLING	= (1 << 9), /* use polling PIO if LLD
					     * doesn't handle PIO interrupts */
	ATA_FLAG_NCQ		= (1 << 10), /* host supports NCQ */
	ATA_FLAG_NO_POWEROFF_SPINDOWN = (1 << 11), /* don't spindown before poweroff */
	ATA_FLAG_NO_HIBERNATE_SPINDOWN = (1 << 12), /* don't spindown before hibernation */
	ATA_FLAG_DEBUGMSG	= (1 << 13),
	ATA_FLAG_FPDMA_AA		= (1 << 14), /* driver supports Auto-Activate */
	ATA_FLAG_IGN_SIMPLEX	= (1 << 15), /* ignore SIMPLEX */
	ATA_FLAG_NO_IORDY	= (1 << 16), /* controller lacks iordy */
	ATA_FLAG_ACPI_SATA	= (1 << 17), /* need native SATA ACPI layout */
	ATA_FLAG_AN		= (1 << 18), /* controller supports AN */
	ATA_FLAG_PMP		= (1 << 19), /* controller supports PMP */
	ATA_FLAG_FPDMA_AUX	= (1 << 20), /* controller supports H2DFIS aux field */
	ATA_FLAG_EM		= (1 << 21), /* driver supports enclosure
					      * management */
	ATA_FLAG_SW_ACTIVITY	= (1 << 22), /* driver supports sw activity
					      * led */
	ATA_FLAG_NO_DIPM	= (1 << 23), /* host not happy with DIPM */
	ATA_FLAG_SAS_HOST	= (1 << 24), /* SAS host */
};

enum hhkr_ata_prot_flags {
	/* protocol flags */
	ATA_PROT_FLAG_PIO	= (1 << 0), /* is PIO */
	ATA_PROT_FLAG_DMA	= (1 << 1), /* is DMA */
	ATA_PROT_FLAG_NCQ	= (1 << 2), /* is NCQ */
	ATA_PROT_FLAG_ATAPI	= (1 << 3), /* is ATAPI */

	/* taskfile protocols */
	ATA_PROT_UNKNOWN	= (u8)-1,
	ATA_PROT_NODATA		= 0,
	ATA_PROT_PIO		= ATA_PROT_FLAG_PIO,
	ATA_PROT_DMA		= ATA_PROT_FLAG_DMA,
	ATA_PROT_NCQ_NODATA	= ATA_PROT_FLAG_NCQ,
	ATA_PROT_NCQ		= ATA_PROT_FLAG_DMA | ATA_PROT_FLAG_NCQ,
	ATAPI_PROT_NODATA	= ATA_PROT_FLAG_ATAPI,
	ATAPI_PROT_PIO		= ATA_PROT_FLAG_ATAPI | ATA_PROT_FLAG_PIO,
	ATAPI_PROT_DMA		= ATA_PROT_FLAG_ATAPI | ATA_PROT_FLAG_DMA,
};


/* Definitions for FVP and JUNO */
#ifndef ENV_JUNO   /* build for FVP's ahci */

typedef struct hitchhiker_fvp_ahci_cmd_hdr {
    uint32_t opts;            // le32
    uint32_t status;          // le32
    uint32_t tbl_addr;        // le32
    uint32_t tbl_addr_hi;     // le32
    uint32_t reserved[4];     // le32
} hhkr_ahci_cmd_hdr_t;

typedef struct hitchhiker_fvp_secIO_struct {
    /* necessary information from `ahci_port_priv` (pp) */
    void *pp_cmd_tbl;      // phys addr for cmd_tbl
    unsigned long pp_cmd_tbl_dma;  
    hhkr_ahci_cmd_hdr_t *pp_cmd_slot;     // phys addr for hhkr_ahci_cmd_hdr_t
    /* necessary information from `ata_link` */
    int pmp;
    /* port_base MMIO */
    unsigned long ahci_port_mmio;
} hhkr_secIO_t;

struct hhkr_ahci_sg {   // all __le32
	u32			addr;
	u32 		addr_hi;
	u32			reserved;
	u32			flags_size;
};

enum {
	AHCI_MAX_SG		= 168, /* hardware max is 64K */
	AHCI_DMA_BOUNDARY	= 0xffffffff,
	AHCI_MAX_CMDS		= 32,
	AHCI_CMD_SZ		= 32,
	AHCI_CMD_SLOT_SZ	= AHCI_MAX_CMDS * AHCI_CMD_SZ,
	AHCI_RX_FIS_SZ		= 256,
	AHCI_CMD_TBL_CDB	= 0x40,
	AHCI_CMD_TBL_HDR_SZ	= 0x80,
	AHCI_CMD_TBL_SZ		= AHCI_CMD_TBL_HDR_SZ + (AHCI_MAX_SG * 16),
	AHCI_CMD_WRITE		= (1 << 6),
	/* registers for each SATA port */
    PORT_SCR_ACT		= 0x34, /* SATA phy register: SActive */
    PORT_CMD_ISSUE		= 0x38, /* command issue */
};

#else			/* build for JUNO's sil24 */

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

#endif

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


int hhkrd_secIO_init_plat(void *pp, unsigned long port_base_mmio_virt);

#ifndef ENV_JUNO
int hhkrd_secIO_init(unsigned long pp_cmd_tbl, unsigned long pp_cmd_tbl_dma, unsigned long pp_cmd_slot, 
                     unsigned long ahci_port_mmio, unsigned long pmp, unsigned long io_job_pending_addr);
#else 
int hhkrd_secIO_init_juno(void *pp, unsigned long port_base_mmio_virt, int pmp, 
						  int tf_ctl, unsigned long io_job_pending_addr);
#endif
int hhkrd_secIO_assignjob(unsigned long scatterlist_pgs, unsigned long blk_start, unsigned long write_size);

#endif