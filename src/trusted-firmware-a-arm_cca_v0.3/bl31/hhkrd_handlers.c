/**
 * OS Services handlers
 */

#include <bl31/hhkrd_handlers.h>
#include <bl31/hhkrd_mgmt.h>
#include <lib/gpt/gpt.h>

#if !ENABLE_HHKRD
#error "ENABLE_HHKRD must be enabled to use the hhkrd os service handlers."
#endif

/* ----------------------------------------------------------------- */
make_syscall_params_handler(read_pread64) {
    /* param extract */
    td_task->syscall_hhkrd_user_addr = read_gpreg(src_ctx, CTX_GPREG_X1);
    td_task->user_buf_size = read_gpreg(src_ctx, CTX_GPREG_X2);
    /* truncate the size if it exceeds the limit */
    uint64_t x2 = read_gpreg(src_ctx, CTX_GPREG_X2);
    td_task->user_buf_size = min(x2, HHKRD_TASK_SHARED_LENGTH);
    /* replace the buffer */
    write_gpreg(src_ctx, CTX_GPREG_X1, td_task->task_shared_virt);
    td_task->is_use_task_shared_virt = true;
    return 0;
}
/* readlinkat(int dirfd, const char *restrict pathname, char *restrict buf, size_t bufsiz); */
make_syscall_params_handler(readlinkat) {
    td_task->syscall_hhkrd_user_addr = read_gpreg(src_ctx, CTX_GPREG_X2);
    td_task->user_buf_size = read_gpreg(src_ctx, CTX_GPREG_X3);
    
    if (td_task->user_buf_size > HHKRD_TASK_SHARED_LENGTH) {    
        td_task->user_buf_size = HHKRD_TASK_SHARED_LENGTH;
    }

    uint64_t share_path_addr = td_task->task_shared_virt + HHKRD_TASK_SHARED_LENGTH - 4096;
    uint64_t user_path_addr = read_gpreg(src_ctx, CTX_GPREG_X1);
    size_t path_size = hhkrd_strlen_va(user_path_addr) + 1;
    hhkrd_path_copy(share_path_addr, user_path_addr, path_size);

    write_gpreg(src_ctx, CTX_GPREG_X1, share_path_addr);
    write_gpreg(src_ctx, CTX_GPREG_X2, td_task->task_shared_virt);
    td_task->is_use_task_shared_virt = true;
    return 0;
}

make_syscall_return_handler(read_pread64_readlinkat) {
    uint64_t res = read_gpreg(src_ctx, CTX_GPREG_X0);
    /* copy the buffer back to the hhkrd userbuf */
    if (res && res <= td_task->user_buf_size) {
        if (td_task->syscall_hhkrd_user_addr)
            hhkrd_memcpy_va(td_task->syscall_hhkrd_user_addr, td_task->task_shared_virt, res);
    }
    return 0;
}
/* ----------------------------------------------------------------- */

/* ---- ssize_t readv(int fd, const struct iovec *iov, int iovcnt); ---- */
make_syscall_params_handler(readv) {
    unsigned long iov_virt = read_gpreg(src_ctx, CTX_GPREG_X1);
    unsigned long iovcnt = read_gpreg(src_ctx, CTX_GPREG_X2);
    td_task->syscall_hhkrd_user_addr = iov_virt;
    td_task->user_buf_size = iovcnt;
    if (iov_virt && iovcnt) {
        hhkrd_memcpy_va(td_task->task_shared_virt, iov_virt, iovcnt * iovec_SIZE);
        uint64_t shared_virt = td_task->task_shared_virt + SHARE_BUF_OFFSET;
        
        struct iovec *vec_phys = (struct iovec *)hhkrd_virt_to_phys(iov_virt);
        struct iovec *share_vec_phys = (struct iovec *)td_task->task_shared_phys;

        for (int i = 0; i < iovcnt; i++) {
            if ((vec_phys[i].iov_len + shared_virt) > (td_task->task_shared_virt + HHKRD_TASK_SHARED_LENGTH)) {
                NOTICE("<sys_param_handle> readv user buf is too large.\n");
                break;
            }
            /* link together */
            share_vec_phys[i].iov_base = shared_virt;
            shared_virt += vec_phys[i].iov_len;
        }
    }
    write_gpreg(src_ctx, CTX_GPREG_X1, td_task->task_shared_virt);
    td_task->is_use_task_shared_virt = true;
    return 0;
}

make_syscall_return_handler(readv) {
    uint64_t ret = read_gpreg(src_ctx, CTX_GPREG_X1);
    if (ret) {

    }
    return 0;
}
/* ---- ssize_t readv(int fd, const struct iovec *iov, int iovcnt); ---- */


/* ----------------------------------------------------------------- */
make_syscall_params_handler(write_pwrite64) {
    td_task->syscall_hhkrd_user_addr = read_gpreg(src_ctx, CTX_GPREG_X1);
    uint64_t x2 = read_gpreg(src_ctx, CTX_GPREG_X2);
    td_task->user_buf_size = min(x2, HHKRD_TASK_SHARED_LENGTH);
    /* 
     * copy the user buffer to the shared buffer, 
     * the OS will operate on this shared buffer later.
     */
    hhkrd_memcpy_va(td_task->task_shared_virt, td_task->syscall_hhkrd_user_addr, td_task->user_buf_size);
    write_gpreg(src_ctx, CTX_GPREG_X1, td_task->task_shared_virt);
    NOTICE("[hhkrd sys_write] now x1: %s.\n", (char *)hhkrd_virt_to_phys(read_gpreg(src_ctx, CTX_GPREG_X1)));
    td_task->is_use_task_shared_virt = true;
    return 0;
}
/* ----------------------------------------------------------------- */

/* ---- ssize_t writev(int fildes, const struct iovec *iov, int iovcnt) ---- */
make_syscall_params_handler(writev) {
    unsigned long iov_virt = read_gpreg(src_ctx, CTX_GPREG_X1);
    unsigned long iovcnt = read_gpreg(src_ctx, CTX_GPREG_X2);
    td_task->syscall_hhkrd_user_addr = iov_virt;
    td_task->user_buf_size = iovec_SIZE;

    if (td_task->syscall_hhkrd_user_addr && iovcnt) {
        struct iovec *vec;
        unsigned long share_virt = td_task->task_shared_virt;
        unsigned long buf_off = td_task->task_shared_virt + SHARE_BUF_OFFSET;

        for (int i = 0; i < iovcnt; i++) {
            /* copy each iovec *iov to the shared buffer */
            if (iov_virt) {
                hhkrd_memcpy_va(share_virt, iov_virt, td_task->user_buf_size);
                uint64_t iov_phys = hhkrd_virt_to_phys(iov_virt);
                vec = (struct iovec*)iov_phys;
                /* length check */
                if ((vec->iov_len + buf_off) > (td_task->task_shared_virt + HHKRD_TASK_SHARED_LENGTH)) {
                    NOTICE("<sys_param_handle> writev user buf is too large.\n");
                    break;
                }
                /* copy each iov->iov_base to the starting from buf_off */
                if (vec->iov_base) {
                    NOTICE("[debug] <sys_param_handle> writev iov_base cont: %s.\n", (char *)hhkrd_virt_to_phys(vec->iov_base));
                    hhkrd_memcpy_va(buf_off, vec->iov_base, vec->iov_len);
                    uint64_t share_phys = hhkrd_virt_to_phys(share_virt);
                    /* link together */
                    ((struct iovec *)share_phys)->iov_base = buf_off;
                    buf_off += vec->iov_len;
                }
                share_virt += iovec_SIZE;
                iov_virt += iovec_SIZE;
            }
        }
    }
    write_gpreg(src_ctx, CTX_GPREG_X1, td_task->task_shared_virt);
    td_task->is_use_task_shared_virt = true;
    return 0;
}
/* ---- ssize_t writev(int fildes, const struct iovec *iov, int iovcnt) ---- */

/* ----------------------------------------------------------------- */
make_syscall_params_handler(ioctl) {
    // unsigned int fd = read_gpreg(src_ctx, CTX_GPREG_X0);
    unsigned int cmd = read_gpreg(src_ctx, CTX_GPREG_X1);
    unsigned int arg = read_gpreg(src_ctx, CTX_GPREG_X2);
    td_task->iotcl_cmd = cmd;
    switch (cmd) {
    /* user buf read from kernel */
    case TCGETS:
    case TCGETS2:
    case TCGETX:
    case TCGETA:
    case TIOCGLCKTRMIOS:
    case TIOCGSOFTCAR:
    case FIOQSIZE:
    case FIGETBSZ:
    case FIONREAD:
        td_task->syscall_hhkrd_user_addr = arg;
        if (cmd == TCGETS || cmd == TIOCGLCKTRMIOS)
            td_task->user_buf_size = TERMIOS_SIZE;
        else if (cmd == TCGETX)
            td_task->user_buf_size = TERMIOX_SIZE;
        else if (cmd == TCGETS2)
            td_task->user_buf_size = TERMIOS2_SIZE;
        else if (cmd == TCGETA)
            td_task->user_buf_size = TERMIO_SIZE;
        else if (cmd == TIOCGSOFTCAR || cmd == FIGETBSZ || cmd == FIONREAD)
            td_task->user_buf_size = sizeof(int);
        else if (cmd == FIOQSIZE)
            td_task->user_buf_size = sizeof(long long);

        write_gpreg(src_ctx, CTX_GPREG_X2, td_task->task_shared_virt);
        td_task->is_use_task_shared_virt = true;
        break;

    /* kernel read from user buf */
    case TCSETSF:
    case TCSETSW:
    case TCSETS:
    case TCSETSF2:
    case TCSETSW2:
    case TCSETS2:
    case TCSETAF:
    case TCSETAW:
    case TCSETA:
    case TIOCSLCKTRMIOS:
    case TCSETX:
    case TCSETXW:
    case TCSETXF:
    case TIOCSSOFTCAR:
    case FIONBIO:
    case FIOASYNC:
    case FS_IOC_FIEMAP:
    case FICLONERANGE:
    case FIBMAP:
    case FS_IOC_RESVSP:
    case FS_IOC_RESVSP64:
        td_task->syscall_hhkrd_user_addr = arg;
        if(cmd == TCSETSF || cmd == TCSETSW || cmd == TCSETS || cmd == TIOCSLCKTRMIOS)
				td_task->user_buf_size = TERMIOS_SIZE;
			else if(cmd == TCSETSF2 || cmd == TCSETSW2 || cmd == TCSETS2)
				td_task->user_buf_size = TERMIOS2_SIZE;
			else if(cmd == TCSETAF || cmd == TCSETAW || cmd == TCSETA)
				td_task->user_buf_size = TERMIO_SIZE;
			else if (cmd == TCSETX || cmd == TCSETXW || cmd == TCSETXF)
				td_task->user_buf_size = TERMIOX_SIZE;
			else if (cmd == TIOCGSOFTCAR || cmd == FIONBIO || cmd == FIOASYNC || cmd == FIBMAP)
				td_task->user_buf_size = sizeof(int);
			else if(cmd == FS_IOC_FIEMAP || FICLONERANGE)
				td_task->user_buf_size = fiemap_SIZE;
			else if (cmd == FS_IOC_RESVSP64 ||cmd == FS_IOC_RESVSP)
				td_task->user_buf_size = space_resv_SIZE;

        hhkrd_memcpy_va(td_task->task_shared_virt, td_task->syscall_hhkrd_user_addr, td_task->user_buf_size);
        write_gpreg(src_ctx, CTX_GPREG_X2, td_task->task_shared_virt);
        td_task->is_use_task_shared_virt = true;
    default:
        break;
    }
    return 0;
}

make_syscall_return_handler(ioctl) {
    uint64_t ret = read_gpreg(src_ctx, CTX_GPREG_X0);
    if (ret == 0 && td_task->syscall_hhkrd_user_addr) {
        switch (td_task->iotcl_cmd) {
        case TCGETS:
        case TCGETS2:
        case TCGETX:
        case TCGETA:
        case TIOCGLCKTRMIOS:
        case TIOCGSOFTCAR:
        case FIOQSIZE:
        case FS_IOC_FIEMAP:
        case FIBMAP:
        case FIONREAD:
            hhkrd_memcpy_va(td_task->syscall_hhkrd_user_addr, td_task->task_shared_virt, td_task->user_buf_size);
            break;	
        }
    }
    return 0;
}
/* ----------------------------------------------------------------- */


/* ----------------------------------------------------------------- */
make_syscall_params_handler(fstat_clockgettime_getrlimit_setgroups) {
    td_task->syscall_hhkrd_user_addr = read_gpreg(src_ctx, CTX_GPREG_X1);
    
    uint64_t gidsetsize;
    
    switch (td_task->wait_syscallno) {
        case SYS_fstat:
            td_task->user_buf_size = STAT_SIZE;
            break;
        case SYS_clock_gettime:
            td_task->user_buf_size = __kernel_timespec_SIZE;
            break;
        case SYS_getrlimit:
            td_task->user_buf_size = RLIMIT_SIZE;
        case SYS_setgroups:
            gidsetsize = read_gpreg(src_ctx, CTX_GPREG_X0);
            if (gidsetsize <= 16384) {
                td_task->user_buf_size = gidsetsize * sizeof(int);
                hhkrd_memcpy_va(td_task->task_shared_virt, td_task->syscall_hhkrd_user_addr, td_task->user_buf_size);
            }
            break;
        default:
            break;
    }

    write_gpreg(src_ctx, CTX_GPREG_X1, td_task->task_shared_virt);
    td_task->is_use_task_shared_virt = true;
    return 0;
}

make_syscall_params_handler(uname_pipe2_sysinfo_nanosleep) {
    td_task->syscall_hhkrd_user_addr = read_gpreg(src_ctx, CTX_GPREG_X0);

    switch (td_task->wait_syscallno) {
    case SYS_uname:
        td_task->user_buf_size = UTSNAME_SIZE;
        break;
    case SYS_pipe2:
        td_task->user_buf_size = 8;
        break;
    case SYS_sysinfo:
        td_task->user_buf_size = sysinfo_SIZE;
        break;
    case SYS_nanosleep:
        td_task->user_buf_size = __kernel_timespec_SIZE;
        hhkrd_memcpy_va(td_task->task_shared_virt, td_task->syscall_hhkrd_user_addr, 
                         td_task->user_buf_size);
        break;
    default:
        break;
    }
    write_gpreg(src_ctx, CTX_GPREG_X0, td_task->task_shared_virt);
    td_task->is_use_task_shared_virt = true;
    return 0;
}


/* int prlimit(pid_t pid, int resource, const struct rlimit *_Nullable new_limit,
               struct rlimit *_Nullable old_limit); */
make_syscall_params_handler(prlimit64) {
    unsigned long old_limit = read_gpreg(src_ctx, CTX_GPREG_X3);
    unsigned long new_limit = read_gpreg(src_ctx, CTX_GPREG_X2);
    td_task->user_buf_size = RLIMIT64_SIZE;
    if (new_limit) {
        hhkrd_memcpy_va(td_task->task_shared_virt + SHARE_BUF_OFFSET, new_limit, td_task->user_buf_size);
        write_gpreg(src_ctx, CTX_GPREG_X2, td_task->task_shared_virt + SHARE_BUF_OFFSET);
    }
    if (old_limit)
        td_task->syscall_hhkrd_user_addr = old_limit;
    write_gpreg(src_ctx, CTX_GPREG_X3, td_task->task_shared_virt);
    td_task->is_use_task_shared_virt = true;
    return 0;
}

make_syscall_return_handler(fstat_newfstatat_sysinfo_uname_prlimit64_getrlimit_pipe2_clockgettime) {
    uint64_t ret = read_gpreg(src_ctx, CTX_GPREG_X0);
    if (ret == 0) {
        /* copy to the user buf */
        if (td_task->syscall_hhkrd_user_addr)
            hhkrd_memcpy_va(td_task->syscall_hhkrd_user_addr, td_task->task_shared_virt, td_task->user_buf_size);
    }
    return 0;
}

make_syscall_params_handler(clock_nanosleep) {
    td_task->syscall_hhkrd_user_addr = read_gpreg(src_ctx, CTX_GPREG_X2);
    td_task->second_syscall_hhkrd_user_addr = read_gpreg(src_ctx, CTX_GPREG_X3);
    td_task->user_buf_size = __kernel_timespec_SIZE;
    td_task->second_user_buf_size = __kernel_timespec_SIZE;

    hhkrd_memcpy_va(td_task->task_shared_virt, td_task->syscall_hhkrd_user_addr, td_task->user_buf_size);
    
    write_gpreg(src_ctx, CTX_GPREG_X2, td_task->task_shared_virt);
    write_gpreg(src_ctx, CTX_GPREG_X3, td_task->task_shared_virt + SHARE_BUF_OFFSET);
    td_task->is_use_task_shared_virt = true;
    return 0;
}

make_syscall_return_handler(clock_nanosleep) {
    int ret = read_gpreg(src_ctx, CTX_GPREG_X0);
    if (ret >= 0 && td_task->second_syscall_hhkrd_user_addr) {
        hhkrd_memcpy_va(td_task->second_syscall_hhkrd_user_addr, td_task->task_shared_virt + SHARE_BUF_OFFSET,
                         td_task->second_user_buf_size);
    }
    return 0;
}
/* ----------------------------------------------------------------- */


make_syscall_params_handler(openat_unlinkat_fchmodat_mkdirat) {
    uint64_t fpath_addr = read_gpreg(src_ctx, CTX_GPREG_X1);
    size_t fpath_size;

    if (fpath_addr) {
        fpath_size = hhkrd_strlen_va(fpath_addr) + 1;
        hhkrd_path_copy(td_task->task_shared_virt, fpath_addr, fpath_size);
    }
    write_gpreg(src_ctx, CTX_GPREG_X1, td_task->task_shared_virt);
    td_task->is_use_task_shared_virt = true;
    return 0;
}

make_syscall_params_handler(renameat_renameat2) {
    uint64_t fpath_addr = read_gpreg(src_ctx, CTX_GPREG_X1);
    size_t fpath_size;

    if (fpath_addr) {
        fpath_size = hhkrd_strlen_va(fpath_addr) + 1;
        hhkrd_path_copy(td_task->task_shared_virt, fpath_addr, fpath_size);
    }
    write_gpreg(src_ctx, CTX_GPREG_X1, td_task->task_shared_virt);
    
    uint64_t fpath_addr_new = read_gpreg(src_ctx, CTX_GPREG_X3);
    if (fpath_addr_new) {
        fpath_size = hhkrd_strlen_va(fpath_addr_new) + 1;
        hhkrd_path_copy(td_task->task_shared_virt + SHARE_BUF_OFFSET, fpath_addr_new, fpath_size);
    }
    write_gpreg(src_ctx, CTX_GPREG_X3, td_task->task_shared_virt + SHARE_BUF_OFFSET);
    td_task->is_use_task_shared_virt = true;
    return 0;
}
// /* int munmap(void *addr, size_t len); */
// make_syscall_params_handler(munmap) {
//     unsigned long addr = read_gpreg(src_ctx, CTX_GPREG_X0);
//     unsigned long len = read_gpreg(src_ctx, CTX_GPREG_X1);
// }


/* ----------------------------------------------------------------- */
make_syscall_params_handler(clone) {
    /* long sys_clone(unsigned long, unsigned long, int __user *, int, int __user *) */
    uint64_t phys_addr;
    td_task->syscall_hhkrd_user_addr = read_gpreg(src_ctx, CTX_GPREG_X2);
    td_task->second_syscall_hhkrd_user_addr = read_gpreg(src_ctx, CTX_GPREG_X3);
    
    /* share with normal OS */
    if ((phys_addr = hhkrd_virt_to_phys(td_task->syscall_hhkrd_user_addr)) != 0) {
        gpt_transition_pas_td_contiguous(phys_addr, S_PAGE_SIZE, GPI_NS, 0);
    }
    /* share with normal OS */
    if ((phys_addr = hhkrd_virt_to_phys(td_task->second_syscall_hhkrd_user_addr)) != 0) {
        gpt_transition_pas_td_contiguous(phys_addr, S_PAGE_SIZE, GPI_NS, 0);
    }
    return 0;
}   

/* ----------------------------------------------------------------- */

/* ----------------------------------------------------------------- */
/* int futex(int *uaddr, int op, int val, const struct timespec *timeout,
             int *uaddr2, int val3); */
make_syscall_params_handler(futex) {
    td_task->task_futex_virt = read_gpreg(src_ctx, CTX_GPREG_X0);
    td_task->task_futex_phys = hhkrd_virt_to_phys(td_task->task_futex_virt);
    td_task->is_use_task_futex_virt = true;
    return 0;
}

make_syscall_return_handler(futex) {
    td_task->is_use_task_futex_virt = false;
    return 0; 
}
/* ----------------------------------------------------------------- */


/* ----------------------------------------------------------------- */
/* int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact); */
make_syscall_params_handler(rt_sigaction) {
    int sig_no = read_gpreg(src_ctx, CTX_GPREG_X0);
    unsigned long act = read_gpreg(src_ctx, CTX_GPREG_X1);
    unsigned long oact = read_gpreg(src_ctx, CTX_GPREG_X2);
    struct sigaction *sig_act = (struct sigaction *)hhkrd_virt_to_phys(act);

    td_task->to_be_registered_signal_handler_addr = sig_act->sa_handler;
    td_task->to_be_registered_signal_no = sig_no;
    NOTICE("SVC_P <rt_sigaction> signal: %d, to be registered addr: 0x%llx.\n",
           sig_no, sig_act->sa_handler);
    
    if (oact) 
        td_task->syscall_hhkrd_user_addr = oact;
    td_task->user_buf_size = SIGACTION_SIZE;
    
    hhkrd_memcpy_va(td_task->task_shared_virt + SHARE_BUF_OFFSET, act, td_task->user_buf_size);

    write_gpreg(src_ctx, CTX_GPREG_X1, td_task->task_shared_virt + SHARE_BUF_OFFSET);
    write_gpreg(src_ctx, CTX_GPREG_X2, td_task->task_shared_virt);
    td_task->is_use_task_shared_virt = true;
    return 0;
}

make_syscall_return_handler(rt_sigaction) {
    register_signal_handles(td_task);

    if (td_task->syscall_hhkrd_user_addr)
        hhkrd_memcpy_va(td_task->syscall_hhkrd_user_addr, td_task->task_shared_virt, td_task->user_buf_size);
    return 0;
}
/* ----------------------------------------------------------------- */

/* ----------------------------------------------------------------- */
/* int sigprocmask(int how, const sigset_t *set, sigset_t *oldset); */
make_syscall_params_handler(rt_sigprocmask) {
    unsigned long new_set = read_gpreg(src_ctx, CTX_GPREG_X1);
    unsigned long old_set = read_gpreg(src_ctx, CTX_GPREG_X2);
    td_task->user_buf_size = SIGSET_SIZE;

    if (new_set) {
        hhkrd_memcpy_va(td_task->task_shared_virt + SHARE_BUF_OFFSET, new_set, td_task->user_buf_size);
        write_gpreg(src_ctx, CTX_GPREG_X1, td_task->task_shared_virt + SHARE_BUF_OFFSET);
    }
    /* old signals will be reserved at this old_set */
    if (old_set) 
        td_task->syscall_hhkrd_user_addr = old_set;
    write_gpreg(src_ctx, CTX_GPREG_X2, td_task->task_shared_virt);
    /* after handle layout: 
     * shared_virt:  (old_set)
     * shared_virt + SHARE_BUF_OFFSET: (new_set)
     */
    td_task->is_use_task_shared_virt = true;
    return 0;
}

make_syscall_return_handler(rt_sigprocmask) {
    uint64_t ret = read_gpreg(src_ctx, CTX_GPREG_X0);
    /* copy back to user buffer */
    if (ret == 0 && td_task->syscall_hhkrd_user_addr)
        hhkrd_memcpy_va(td_task->syscall_hhkrd_user_addr, td_task->task_shared_virt, td_task->user_buf_size);

    return 0;
}
/* ----------------------------------------------------------------- */

/* ----------------------------------------------------------------- */
make_syscall_params_handler(rt_sigreturn) {
    /* allow normal OS to access the hhkrd's signal stack to restore context */
    td_task->is_use_task_signal_stack_virt = true;
    return 0;
}

make_syscall_return_handler(rt_sigreturn) {
    /* restore the signal return pc */
    td_task->task_elr_el1 = td_task->ret_pc_from_signal;
    memset((void *)td_task->task_signal_stack_phys, 0, td_task->task_signal_stack_length);
    td_task->is_use_task_signal_stack_virt = false;
    return 0;
}
/* ----------------------------------------------------------------- */