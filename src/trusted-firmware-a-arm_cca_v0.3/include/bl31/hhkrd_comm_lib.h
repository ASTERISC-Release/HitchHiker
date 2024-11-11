#ifndef HHKRD_COMM_LIB_H
#define HHKRD_COMM_LIB_H

#include <lib/libc/stdint.h>
#include <lib/libc/stddef.h>

#define read_el1_sysreg(ctx, offset)         (u_register_t)(read_ctx_reg(get_el1_sysregs_ctx(ctx), offset))
#define write_el1_sysreg(ctx, offset, val)   (write_ctx_reg(get_el1_sysregs_ctx(ctx), offset, val))

#define read_gpreg(ctx, offset)              (u_register_t)(read_ctx_reg(get_gpregs_ctx(ctx), offset))
#define write_gpreg(ctx, offset, val)        (write_ctx_reg(get_gpregs_ctx(ctx), offset, val))

/**
 * macros
 */
#define str_temp(x)                          #x
#define str(x)                               str_temp(x)

#define min(x, y)                            ((x) < (y) ? (x) : (y))
#define max(x, y)                            ((x) > (y) ? (x) : (y))
#define concat_temp(x, y)                    x ## y
#define concat(x, y)                         concat_temp(x, y)
#define concat3(x, y, z)                     concat(concat(x, y), z)

#define MAP(c, f)                            c(f)

uint64_t hhkrd_virt_to_phys(uint64_t virt_addr);

size_t hhkrd_strlen_va(uint64_t virt_addr);

void hhkrd_memcpy_pa(uint64_t dst_phys_addr, uint64_t src_phys_addr, uint32_t size);

void hhkrd_memcpy_va(uint64_t dst_virt_addr, uint64_t src_virt_addr, uint32_t size);

void hhkrd_path_copy(uint64_t dst_virt_addr, uint64_t src_virt_addr, size_t size);
/**
 * common defs
 */
#define         SIGNAL_MAX    32
#define 		SATA_IRQ_ID	  49152

void hhkrd_sata_irq_handler(void);

//syscall required to be compatible
#define SYS_fstat 0x50
#define SYS_ioctl 0x1d
#define SYS_read 0x3f
#define SYS_write 0x40
#define SYS_uname 0xa0
#define SYS_readlinkat 0x4e
#define SYS_openat 0x38
#define SYS_RT_SIGACTION 0x86
#define SYS_RT_SIGPROCMASK 0x87
#define SYS_RT_SIGRETURN 0x8b
#define SYS_futex 0x62
#define SYS_clone 0xdc
#define SYS_prlimit64 0x105
#define SYS_getrlimit 0xa3
#define SYS_CONNECT 0xcb
#define SYS_clock_gettime 0x71
#define SYS_clock_nanosleep 0x73
#define SYS_gettimeofday 0xa9
#define SYS_MUNMAP 0xd7
#define SYS_epoll_ctl 0x15
#define SYS_bind 0xc8
#define SYS_setsockopt 0xd0
#define SYS_nanosleep 0x65
#define SYS_getsockname 0xcc
#define SYS_getpeername 0xcd
#define SYS_accept 0xca
#define SYS_accept4 0xf2
#define SYS_socketpair 0xc7
#define SYS_newfstatat 0x4f
#define SYS_pwrite64 0x44
#define SYS_pread64 0x43
#define SYS_epoll_pwait 0x16
#define SYS_writev 0x42
#define SYS_sendfile 0x47
#define SYS_sendto 0xce
#define SYS_recvfrom 0xcf
#define SYS_sendmsg 0xd3
#define SYS_recvmsg 0xd4
#define SYS_readv 0x41
#define SYS_getrandom 0x116
#define SYS_sysinfo 0xb3
#define SYS_pselect6 0x48
#define SYS_ppoll	0x49
#define SYS_pipe2	0x3b
#define SYS_unlinkat 0x23
#define SYS_fchmodat 0x35
#define SYS_mkdirat 0x22
#define SYS_renameat 0x26
#define SYS_renameat2 0x114
#define SYS_setgroups 0x9f


//syscall struct
#define UTSNAME_SIZE 325
#define STAT_SIZE 128
#define TERMIOX_SIZE 16
#define TERMIO_SIZE 18
#define TERMIOS_SIZE 36
#define TERMIOS2_SIZE 44
#define KTERMIOS_SIZE 44
#define SIGACTION_SIZE 32 
#define SIGSET_SIZE 8
#define RLIMIT64_SIZE 16
#define RLIMIT_SIZE 16
#define FUTEX_SIZE 4
#define __kernel_timespec_SIZE 16
#define timeval_SIZE 16
#define timezone_SIZE 8
#define epoll_event_SIZE 16
#define sockaddr_SIZE 16
#define user_msghdr_SIZE 56
#define fiemap_SIZE 32
#define file_clone_range_SIZE 32
#define space_resv_SIZE 48
#define iovec_SIZE 16
#define sysinfo_SIZE 112
#define fd_set_SIZE 128
#define pollfd_SIZE 8
#define FDS_BITPERLONG	(8*sizeof(long))
#define FDS_LONGS(nr)	(((nr)+FDS_BITPERLONG-1)/FDS_BITPERLONG)
#define FDS_BYTES(nr)	(FDS_LONGS(nr)*sizeof(long))

struct sigaction {
	uint64_t	sa_handler;
};	

struct iovec
{
	uint64_t iov_base;	
	unsigned long iov_len; 
};

struct user_msghdr {
	uint64_t		 msg_name;	/* ptr to socket address structure */
	int		msg_namelen;		/* size of socket address structure */
	struct iovec	 *msg_iov;	/* scatter/gather array */
	unsigned long	msg_iovlen;		/* # elements in msg_iov */
	uint64_t		msg_control;	/* ancillary data */
	unsigned long	msg_controllen;		/* ancillary data buffer length */
	unsigned int	msg_flags;		/* flags on received message */
};

//ioctl cmd
// #define FIDEDUPERANGE	3222836278
#define FS_IOC_RESVSP		1076910120
#define FS_IOC_RESVSP64		1076910122
#define FIBMAP	   1
#define FIOASYNC	0x5452
#define FIOQSIZE	0x5460
#define FS_IOC_FIEMAP 3223348747
#define FIGETBSZ 2
#define FICLONERANGE	1075876877
#define TCGETS		0x5401
#define TCSETS		0x5402
#define TCSETSW		0x5403
#define TCSETSF		0x5404
#define TCGETA		0x5405
#define TCSETA		0x5406
#define TCSETAW		0x5407
#define TCSETAF		0x5408
#define TCSBRK		0x5409
#define TCXONC		0x540A
#define TCFLSH		0x540B
#define TIOCEXCL	0x540C
#define TIOCNXCL	0x540D
#define TIOCSCTTY	0x540E
#define TIOCGPGRP	0x540F
#define TIOCSPGRP	0x5410
#define TIOCOUTQ	0x5411
#define TIOCSTI		0x5412
#define TIOCGWINSZ	0x5413
#define TIOCSWINSZ	0x5414
#define TIOCMGET	0x5415
#define TIOCMBIS	0x5416
#define TIOCMBIC	0x5417
#define TIOCMSET	0x5418
#define TIOCGSOFTCAR	0x5419
#define TIOCSSOFTCAR	0x541A
#define FIONREAD	0x541B
#define TIOCINQ		FIONREAD
#define TIOCLINUX	0x541C
#define TIOCCONS	0x541D
#define TIOCGSERIAL	0x541E
#define TIOCSSERIAL	0x541F
#define TIOCPKT		0x5420
#define FIONBIO		0x5421
#define TIOCNOTTY	0x5422
#define TIOCSETD	0x5423
#define TIOCGETD	0x5424
#define TCSBRKP		0x5425
#define TIOCSBRK	0x5427 
#define TIOCCBRK	0x5428 
#define TIOCGSID	0x5429 
#define TCGETS2		2150388778
#define TCSETS2		1076646955
#define TCSETSW2	1076646956
#define TCSETSF2	1076646957
#define TIOCGRS485	0x542E
#define TIOCSRS485	0x542F
#define TIOCGPTN	2147767344
#define TIOCSPTLCK	2147767344 
#define TIOCGDEV	2147767344
#define TCGETX		0x5432 
#define TCSETX		0x5433
#define TCSETXF		0x5434
#define TCSETXW		0x5435
#define TIOCGLCKTRMIOS	0x5456
#define TIOCSLCKTRMIOS	0x5457
#define TIOCGSOFTCAR	0x5419
#define TIOCSSOFTCAR	0x541A

/* optname */
#define SO_LINGER	13
#define SO_ATTACH_FILTER	26

#endif 