#define U_(_x) (_x##U)
#define U(_x) U_(_x)
// #define UL(_x) (_x##UL)
// #define ULL(_x) (_x##ULL)
#define L(_x) (_x##L)
#define LL(_x) (_x##LL)

/* hhkr ioctl */
#define         HHKR_GET_UNMMAPPED_BUF  _IOW('m', 2, unsigned int)
#define         HHKR_MMAP_BUF           _IOW('m', 4, unsigned int)
#define         HHKR_MMAP_MSG_QUEUE     _IOW('m', 5, unsigned int)
#define         HHKR_MMAP_BUF_META_MSG  _IOW('m', 9, unsigned int)
#define         HHKR_MMAP_FREEBACK_WL   _IOW('m', 7, unsigned int)

#define         HHKR_POLICY_CDF_MODE    _IOW('m', 10, unsigned int)

#define         HHKR_MMAP_OMNI_BUF_D    _IOW('m', 11, unsigned int)
#define         HHKR_MEMCPY_MODE        _IOW('m', 13, unsigned int)

#define         HHKR_SECURE_BUF        U(0x80000FF2)
#define         HHKRD_FREEBACK_BUFS    U(0x80000FF3)

/* smc & ioctl */
#define         HHKRD_CREATE           U(0x80000FFE)
#define         HHKRD_EXIT_TEST        U(0x80000FFF)
#define         HHKRD_STATUS           U(0x80001000)
#define         HHKRD_EXCEPTION        U(0x80000F00)
#define         HHKRD_SETPAGE          U(0x80000F01)
#define         HHKRD_MEMEXPAND        U(0x80000F02)
#define         HHKRD_CLONE            U(0x80000F03)

#define         HHKRD_ASSIGN_SHARE     U(0x80000FFD)
#define         HHKRD_DESTROY          U(0x80000FF0)
#define         HHKRD_ENTER            U(0x80000FF1)

#define         HHKR_INIT_OMNI_BUF     U(0x80000F10)
#define         HHKR_WRITE_OMNI_BUF    U(0x80000F11)
/* secure IO */
#define         HHKRD_INIT_SECIO       U(0x80000FF4)
#define         HHKRD_DO_SECIO         U(0x80000FF5)
#define         HHKRD_MMAP_SCATTER     U(0x80000FF6)
#define         HHKRD_ASSIGN_SECIO     U(0x80000FF7)
#define         HHKRD_MMAP_SECIO_STAT  _IOW('m', 12, unsigned int)

/* management */
#define         HHKRD_MAX                          0x2
#define         HHKRD_TASK_SHARED_LENGTH           0x10000    // 64KB
#define         HHKRD_TASK_SIGNAL_STACK_LENGTH     0x4000     // 16KB
#define         EXCEPTION_VECTOR_LENGTH            0x1000     // 4KB
#define         HHKRD_VECTOR_PAGE_TABLE_SPACE      0x1000000  // 16MB
#define         HHKRD_EXTEND_MEM_DEFAULT_LENGTH    0x4000000  // 64MB

/* HHKRD driver */
#define HHKRD_AL_ALLOCATE	        _IOW('m', 1, unsigned int)
#define HHKRD_AL_RELEASE		    _IOW('m', 3, unsigned int)
#define HHKRD_AL_MARK_RELEASE		U(0x80000F04)

/* hhkr secure policy */
#define HHKR_ACT_INTERVAL_POLICY  _IOW('m', 6, unsigned int)
#define HHKR_MMAP_POLICY_ACT_FLAG _IOW('m', 8, unsigned int)