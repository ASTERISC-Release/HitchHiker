#ifndef HHKRD_SECIO_H
#define HHKRD_SECIO_H

#include <lib/libc/stdint.h>
#include <lib/libc/endian.h>
#include <arch.h>
#include <errno.h>
#include <lib/spinlock.h>
#include <arch_helpers.h>
#include <plat/arm/common/arm_def.h>

/* hhkrd I/O scatterlist job */
struct scatterlist {
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
typedef struct hitchhiker_el3_scatterlist_pgs {
    /* 1. scatterlist */
    struct scatterlist sg;
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

/* hhkrd replay emulation IO struct */
typedef struct hitchhiker_el3_ahci_cmd_hdr {
    uint32_t opts;            // le32
    uint32_t status;          // le32
    uint32_t tbl_addr;        // le32
    uint32_t tbl_addr_hi;     // le32
    uint32_t reserved[4];     // le32
} hhkr_ahci_cmd_hdr_t;

typedef struct hitchhiker_el3_secIO_struct{
    /* necessary information from `ahci_port_priv` (pp) */
    void *pp_cmd_tbl;      // phys addr for cmd_tbl
    unsigned long pp_cmd_tbl_dma;  
    hhkr_ahci_cmd_hdr_t *pp_cmd_slot;     // phys addr for hhkr_ahci_cmd_hdr_t
    /* necessary information from `ata_link` */
    int pmp;
    /* port_base MMIO */
    unsigned long ahci_port_mmio;
} hhkr_secIO_t;


/* fake structs */
typedef unsigned int  u32;
typedef unsigned char u8;

struct ata_taskfile {
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

struct ahci_sg {   // all __le32
	u32			addr;
	u32 		addr_hi;
	u32			reserved;
	u32			flags_size;
};

#define BLOCK_SZ        512
#define DMA_TO_DEVICE   1
#define CMD_FIS_LEN		5
#define SG_N_ELEM	    1

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

enum {
	/* struct ata_taskfile flags */
	ATA_TFLAG_LBA48		= (1 << 0), /* enable 48-bit LBA and "HOB" */
	ATA_TFLAG_ISADDR	= (1 << 1), /* enable r/w to nsect/lba regs */
	ATA_TFLAG_DEVICE	= (1 << 2), /* enable r/w to device reg */
	ATA_TFLAG_WRITE		= (1 << 3), /* data dir: host->dev==1 (write) */
	ATA_TFLAG_LBA		= (1 << 4), /* enable LBA */
	ATA_TFLAG_FUA		= (1 << 5), /* enable FUA */
	ATA_TFLAG_POLLING	= (1 << 6), /* set nIEN to 1 and use polling */

    ATA_LBA			= (1 << 6),	/* LBA28 selector */
	ATA_CMD_FPDMA_READ	= 0x60,
    ATA_CMD_FPDMA_WRITE	= 0x61,
};

enum ata_prot_flags {
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

int hhkrd_secIO_init(u_register_t pptag_cmd_tbl, u_register_t pptag_cmd_tbl_dma, u_register_t pptag_cmd_slot, 
                     u_register_t ahci_port_mmio, u_register_t pmp, u_register_t io_job_pending_addr);
int hhkrd_secIO_assignjob(u_register_t scatterlist_pgs, u_register_t blk_start, u_register_t write_size);
#endif