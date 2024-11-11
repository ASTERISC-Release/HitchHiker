#ifndef HHKRD_HANDLERS_H
#define HHKRD_HANDLERS_H

#include <lib/el3_runtime/context_mgmt.h>
#include <bl31/hhkrd_task.h>
#include <bl31/hhkrd_comm_lib.h>

/* function signatures */
#define make_syscall_params_handler(name)  \
            int concat(__SVC_P_, name) (cpu_context_t *src_ctx, hhkrd_task_t *td_task)
#define syscall_params_handler(name, src_ctx, td_task)  \
            concat(__SVC_P_, name) (src_ctx, td_task)
typedef int (*SVC_P_handler) (cpu_context_t *, hhkrd_task_t *);

#define make_syscall_return_handler(name)  \
            int concat(__SVC_R_, name) (cpu_context_t *src_ctx, hhkrd_task_t *td_task)
#define syscall_return_handler(name, src_ctx, td_task)  \
            concat(__SVC_R_, name) (src_ctx, td_task)
typedef int (*SVC_R_handler) (cpu_context_t *, hhkrd_task_t *);


/* define syscall parameter handlers */
make_syscall_params_handler(clock_nanosleep);
make_syscall_return_handler(clock_nanosleep);

make_syscall_params_handler(fstat_clockgettime_getrlimit_setgroups);
make_syscall_params_handler(uname_pipe2_sysinfo_nanosleep);
make_syscall_params_handler(prlimit64);
make_syscall_return_handler(fstat_newfstatat_sysinfo_uname_prlimit64_getrlimit_pipe2_clockgettime);

make_syscall_params_handler(ioctl);
make_syscall_return_handler(ioctl);

make_syscall_params_handler(readlinkat);
make_syscall_params_handler(read_pread64);
make_syscall_return_handler(read_pread64_readlinkat);

make_syscall_params_handler(readv);
make_syscall_return_handler(readv);

make_syscall_params_handler(write_pwrite64);
make_syscall_params_handler(writev);


make_syscall_params_handler(openat_unlinkat_fchmodat_mkdirat);
make_syscall_params_handler(renameat_renameat2);

/* clone support */
make_syscall_params_handler(clone);
/* futex support */
make_syscall_params_handler(futex);

/* signal support */
make_syscall_params_handler(rt_sigaction);
make_syscall_return_handler(rt_sigaction);

make_syscall_params_handler(rt_sigprocmask);
make_syscall_return_handler(rt_sigprocmask);

make_syscall_params_handler(rt_sigreturn);
make_syscall_return_handler(rt_sigreturn);
#endif