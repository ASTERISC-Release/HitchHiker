/*
 * utils_def_exp.h
 */
#define U_(_x) (_x##U)
#define U(_x) U_(_x)
// #define UL(_x) (_x##UL)
// #define ULL(_x) (_x##ULL)
#define L(_x) (_x##L)
#define LL(_x) (_x##LL)

/*
 * smccc.h
 */
/* Flags and error codes */

/* FIDs value */
#define SMC_64 U(1)
#define SMC_32 U(0)
#define SMC_TYPE_FAST UL(1)
#define SMC_TYPE_YIELD UL(0)
#define OEN_ARM_START U(0)
#define OEN_ARM_END U(0)
#define OEN_STD_START			U(4)	/* Standard Service Calls */
/*******************************************************************************
 * Bit definitions inside the function id as per the SMC calling convention
 ******************************************************************************/
#define FUNCID_TYPE_SHIFT U(31)
#define FUNCID_TYPE_MASK U(0x1)
#define FUNCID_TYPE_WIDTH U(1)

#define FUNCID_CC_SHIFT U(30)
#define FUNCID_CC_MASK U(0x1)
#define FUNCID_CC_WIDTH U(1)

#define FUNCID_OEN_SHIFT U(24)
#define FUNCID_OEN_MASK U(0x3f)
#define FUNCID_OEN_WIDTH U(6)

#define FUNCID_NUM_SHIFT U(0)
#define FUNCID_NUM_MASK U(0xffff)
#define FUNCID_NUM_WIDTH U(16)

#define GEN_RMI_FUNCID(smc_cc, func_num) \
    ((SMC_TYPE_FAST << FUNCID_TYPE_SHIFT) | \
    ((smc_cc) << FUNCID_CC_SHIFT) | \
    (OEN_ARM_START << FUNCID_OEN_SHIFT) | \
    ((func_num & FUNCID_NUM_MASK) << FUNCID_NUM_SHIFT))
/**
 * rmi_svc.h
 */
#define RMI_FNUM_REQ_COMPLETE		U(16)
#define RMI_FNUM_VERSION_REQ		U(0)

#define RMI_FNUM_GRAN_NS_REALM		U(1)
#define RMI_FNUM_GRAN_REALM_NS		U(2)

/**
 * gtsi_svc.h
 */
#define GTSI_FID(smc_cc, func_num)			\
	((SMC_TYPE_FAST << FUNCID_TYPE_SHIFT)	|	\
	 ((smc_cc) << FUNCID_CC_SHIFT)		|	\
	 (OEN_STD_START << FUNCID_OEN_SHIFT)	|	\
	 ((func_num) << FUNCID_NUM_SHIFT))

#define GRAN_TRANS_TO_REALM_FNUM	0x100
#define GRAN_TRANS_TO_NS_FNUM		0x101

/**
 * cma module defs
*/
#define CMA_MEM_ALLOCATE        _IOW('m', 1, unsigned int)
#define CMA_MEM_RELEASE         _IOW('m', 2, unsigned int)
#define CMA_EL3_MEMCPY_TEST     _IOW('m', 3, unsigned int)

#define CMA_SMC_EMPTY_TEST      _IOW('m', 4, unsigned int)

#define CMA_TZASC_SETUP         _IOW('m', 5, unsigned int)
#define CMA_TZASC_TEST          _IOW('m', 6, unsigned int)

#define CMA_FAST_MEMCPY_TEST    _IOW('m', 7, unsigned int)

#define MEM_SZ_4KB      1 << 12
#define MEM_SZ_16KB     1 << 14
#define MEM_SZ_32KB     1 << 15
#define MEM_SZ_64KB     1 << 16
#define MEM_SZ_128KB    1 << 17
#define MEM_SZ_256KB    1 << 18
#define MEM_SZ_512KB    1 << 19
#define MEM_SZ_1MB      1 << 20
#define MEM_SZ_4MB      1 << 22
#define MEM_SZ_16MB     1 << 24
#define MEM_SZ_64MB     1 << 26
#define MEM_SZ_256MB    1 << 28

// defined smc
#define GPT_TRANS_PRE       U(0x80000FAF)
#define GPT_TRANS_TEST      U(0x80000FAA)
#define EL3_MEMCPY_TEST     U(0x80000FAB)
#define SMC_EMPTY_TEST      U(0x80000FAC)
#define SMC_TZASC_SETUP     U(0x80000FAD)
#define SMC_TZASC_TEST      U(0x80000FAE)
