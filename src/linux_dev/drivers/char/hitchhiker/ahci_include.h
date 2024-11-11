#include <linux/fs.h>
#include <linux/stat.h>

#include <linux/genhd.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <linux/dma-contiguous.h>

#include <linux/libata.h>
#include <linux/ata.h>
#include <scsi/scsi_host.h>

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
	struct ahci_host_priv *hpriv;
    void __iomem *mmio;
    hpriv = host->private_data;
	mmio = hpriv->mmio;

	return mmio + 0x100 + (port_no * 0x80);
}