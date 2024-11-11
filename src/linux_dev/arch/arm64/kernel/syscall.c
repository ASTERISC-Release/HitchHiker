// SPDX-License-Identifier: GPL-2.0

#include <linux/compiler.h>
#include <linux/context_tracking.h>
#include <linux/errno.h>
#include <linux/nospec.h>
#include <linux/ptrace.h>
#include <linux/syscalls.h>

#include <asm/daifflags.h>
#include <asm/debug-monitors.h>
#include <asm/fpsimd.h>
#include <asm/syscall.h>
#include <asm/thread_info.h>
#include <asm/unistd.h>
#ifdef CONFIG_HITCHHIKER
#include <linux/hitchhiker.h>
#include <linux/arm-smccc.h>
#include <linux/sched.h>
#include <linux/mman.h>
#endif

long compat_arm_syscall(struct pt_regs *regs, int scno);
long sys_ni_syscall(void);

static long do_ni_syscall(struct pt_regs *regs, int scno)
{
#ifdef CONFIG_COMPAT
	long ret;
	if (is_compat_task()) {
		ret = compat_arm_syscall(regs, scno);
		if (ret != -ENOSYS)
			return ret;
	}
#endif

	return sys_ni_syscall();
}

static long __invoke_syscall(struct pt_regs *regs, syscall_fn_t syscall_fn)
{
	return syscall_fn(regs);
}

static void invoke_syscall(struct pt_regs *regs, unsigned int scno,
			   unsigned int sc_nr,
			   const syscall_fn_t syscall_table[])
{
	long ret;

	if (scno < sc_nr) {
		syscall_fn_t syscall_fn;
		syscall_fn = syscall_table[array_index_nospec(scno, sc_nr)];
		ret = __invoke_syscall(regs, syscall_fn);
	} else {
		ret = do_ni_syscall(regs, scno);
	}

	regs->regs[0] = ret;
}

static inline bool has_syscall_work(unsigned long flags)
{
	return unlikely(flags & _TIF_SYSCALL_WORK);
}

int syscall_trace_enter(struct pt_regs *regs);
void syscall_trace_exit(struct pt_regs *regs);

#ifdef CONFIG_ARM64_ERRATUM_1463225
DECLARE_PER_CPU(int, __in_cortex_a76_erratum_1463225_wa);

static void cortex_a76_erratum_1463225_svc_handler(void)
{
	u32 reg, val;

	if (!unlikely(test_thread_flag(TIF_SINGLESTEP)))
		return;

	if (!unlikely(this_cpu_has_cap(ARM64_WORKAROUND_1463225)))
		return;

	__this_cpu_write(__in_cortex_a76_erratum_1463225_wa, 1);
	reg = read_sysreg(mdscr_el1);
	val = reg | DBG_MDSCR_SS | DBG_MDSCR_KDE;
	write_sysreg(val, mdscr_el1);
	asm volatile("msr daifclr, #8");
	isb();

	/* We will have taken a single-step exception by this point */

	write_sysreg(reg, mdscr_el1);
	__this_cpu_write(__in_cortex_a76_erratum_1463225_wa, 0);
}
#else
static void cortex_a76_erratum_1463225_svc_handler(void) { }
#endif /* CONFIG_ARM64_ERRATUM_1463225 */

static void el0_svc_common(struct pt_regs *regs, int scno, int sc_nr,
			   const syscall_fn_t syscall_table[])
{
	unsigned long flags = current_thread_info()->flags;

	regs->orig_x0 = regs->regs[0];
	regs->syscallno = scno;

	cortex_a76_erratum_1463225_svc_handler();
	local_daif_restore(DAIF_PROCCTX);
	user_exit();

	if (has_syscall_work(flags)) {
		/* set default errno for user-issued syscall(-1) */
		if (scno == NO_SYSCALL)
			regs->regs[0] = -ENOSYS;
		scno = syscall_trace_enter(regs);
		if (scno == NO_SYSCALL)
			goto trace_exit;
	}

	invoke_syscall(regs, scno, sc_nr, syscall_table);

	/*
	 * The tracing status may have changed under our feet, so we have to
	 * check again. However, if we were tracing entry, then we always trace
	 * exit regardless, as the old entry assembly did.
	 */
	if (!has_syscall_work(flags) && !IS_ENABLED(CONFIG_DEBUG_RSEQ)) {
		local_daif_mask();
		flags = current_thread_info()->flags;
		if (!has_syscall_work(flags)) {
			/*
			 * We're off to userspace, where interrupts are
			 * always enabled after we restore the flags from
			 * the SPSR.
			 */
			trace_hardirqs_on();
			return;
		}
		local_daif_restore(DAIF_PROCCTX);
	}

trace_exit:
	syscall_trace_exit(regs);
}

static inline void sve_user_discard(void)
{
	if (!system_supports_sve())
		return;

	clear_thread_flag(TIF_SVE);

	/*
	 * task_fpsimd_load() won't be called to update CPACR_EL1 in
	 * ret_to_user unless TIF_FOREIGN_FPSTATE is still set, which only
	 * happens if a context switch or kernel_neon_begin() or context
	 * modification (sigreturn, ptrace) intervenes.
	 * So, ensure that CPACR_EL1 is already correct for the fast-path case.
	 */
	sve_user_disable();
}

asmlinkage void el0_svc_handler(struct pt_regs *regs)
{
#ifdef CONFIG_HITCHHIKER
	u64 syscallno;
	int gpt_id;
	unsigned long task_shared_virt, signal_stack_virt;
#endif
	sve_user_discard();
#ifdef CONFIG_HITCHHIKER
	syscallno = regs->regs[8];
#endif
	el0_svc_common(regs, regs->regs[8], __NR_syscalls, sys_call_table);
#ifdef CONFIG_HITCHHIKER
	/* 
	 * `sys_hhkrd_exec()` has been done by kernel (execute the do_execve()).
	 *
	 * In the binary load phase, hhkrd's program stack, code, and data has
	 * been remapped to the cma physical region `td_region`.
	 * 
	 * At that point, `current->is_hhkrd` should be set (by sys_hhkrd_exec) 
	 * and `current` should be the hhkrd task
	 */
	if ((syscallno == __NR_hhkrd_exec) && current->is_hhkrd) {
		/* 
		 * forward to hhkrd_driver to invoke smc(HHKRD_CREATE) to create the 
		 * hhkrd td_task struct in atf
		 */
		gpt_id = ksys_ioctl(current->hhkr_ctl_fd, HHKRD_CREATE, 0);
		if (gpt_id < 0) {
			current->is_hhkrd = 0;
			do_group_exit(gpt_id);
		}
		current->gpt_id = gpt_id;
		/*
		 * Once successful, the hhkrd_driver will record the current 
		 * `td_region` in EL3 monitor as the hhkrd's program physical memory (pa1).
		 * 
		 * The driver creates and stores hhkrd's exception vector table 
		 * in a new `exception_table_region`, which is also recorded by 
		 * the EL3 monitor's td_task (pa2).
		 */
		current->is_created = 1; /* smc() handle success */
		/* randomly select task_share_mem VA, and assign a hhkrd_region to map */
		task_shared_virt = ksys_mmap_pgoff(0, HHKRD_TASK_SHARED_LENGTH,
						PROT_READ | PROT_WRITE, MAP_SHARED, current->hhkr_ctl_fd, 0);
		/* randomly select signal stack VA, and assign a hhkrd_region to map */
		signal_stack_virt = ksys_mmap_pgoff(0, HHKRD_TASK_SIGNAL_STACK_LENGTH,
						PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, current->hhkr_ctl_fd, 0);
		/* record in OS's task struct */
		current->task_signal_stack_virt = signal_stack_virt;
		/* forward to update monitor's to update td_task struct HHKRD_ASSIGN_SHARE */
		hitchhiker_smc(HHKRD_ASSIGN_SHARE, current->pid, task_shared_virt, signal_stack_virt,
						0, 0, 0, 0);
		printk(KERN_INFO "<__NR_hhkrd_exec> done. exit kernel...\n");
	}
	/*
	 * back to el0 userspace, will start to the entry point of hhkrd.
	 * Later, `kernel_exit` will invoke smc() to let EL3 monitor handle `hhkrd_sched_in`
	 */
#endif
}

#ifdef CONFIG_COMPAT
asmlinkage void el0_svc_compat_handler(struct pt_regs *regs)
{
	el0_svc_common(regs, regs->regs[7], __NR_compat_syscalls,
		       compat_sys_call_table);
}
#endif
