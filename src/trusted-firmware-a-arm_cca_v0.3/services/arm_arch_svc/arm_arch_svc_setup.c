/*
 * Copyright (c) 2018-2021, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common/debug.h>
#include <common/runtime_svc.h>
#include <lib/cpus/errata_report.h>
#include <lib/cpus/wa_cve_2017_5715.h>
#include <lib/cpus/wa_cve_2018_3639.h>
#include <lib/smccc.h>
#include <services/arm_arch_svc.h>
#include <services/rmi_svc.h>
#include <services/rmmd_svc.h>
#include <smccc_helpers.h>
#include <plat/common/platform.h>
#if ENABLE_HHKRD
#include <bl31/hhkrd_mgmt.h>
#include <bl31/hhkrd_task.h>
#include <bl31/hhkrd_secio.h>
#include <lib/gpt/gpt.h>
#include <lib/el3_runtime/context_mgmt.h>
#endif

#if ENABLE_RME
/* Setup Arm architecture Services */
static int32_t arm_arch_svc_setup(void)
{
	return rmmd_setup();
}
#endif

static int32_t smccc_version(void)
{
	return MAKE_SMCCC_VERSION(SMCCC_MAJOR_VERSION, SMCCC_MINOR_VERSION);
}

static int32_t smccc_arch_features(u_register_t arg1)
{
	switch (arg1) {
	case SMCCC_VERSION:
	case SMCCC_ARCH_FEATURES:
		return SMC_ARCH_CALL_SUCCESS;
	case SMCCC_ARCH_SOC_ID:
		return plat_is_smccc_feature_available(arg1);
#if WORKAROUND_CVE_2017_5715
	case SMCCC_ARCH_WORKAROUND_1:
		if (check_wa_cve_2017_5715() == ERRATA_NOT_APPLIES)
			return 1;
		return 0; /* ERRATA_APPLIES || ERRATA_MISSING */
#endif

#if WORKAROUND_CVE_2018_3639
	case SMCCC_ARCH_WORKAROUND_2: {
#if DYNAMIC_WORKAROUND_CVE_2018_3639
		unsigned long long ssbs;

		/*
		 * Firmware doesn't have to carry out dynamic workaround if the
		 * PE implements architectural Speculation Store Bypass Safe
		 * (SSBS) feature.
		 */
		ssbs = (read_id_aa64pfr1_el1() >> ID_AA64PFR1_EL1_SSBS_SHIFT) &
			ID_AA64PFR1_EL1_SSBS_MASK;

		/*
		 * If architectural SSBS is available on this PE, no firmware
		 * mitigation via SMCCC_ARCH_WORKAROUND_2 is required.
		 */
		if (ssbs != SSBS_UNAVAILABLE)
			return 1;

		/*
		 * On a platform where at least one CPU requires
		 * dynamic mitigation but others are either unaffected
		 * or permanently mitigated, report the latter as not
		 * needing dynamic mitigation.
		 */
		if (wa_cve_2018_3639_get_disable_ptr() == NULL)
			return 1;
		/*
		 * If we get here, this CPU requires dynamic mitigation
		 * so report it as such.
		 */
		return 0;
#else
		/* Either the CPUs are unaffected or permanently mitigated */
		return SMC_ARCH_CALL_NOT_REQUIRED;
#endif
	}
#endif

	/* Fallthrough */

	default:
		return SMC_UNK;
	}
}

/* return soc revision or soc version on success otherwise
 * return invalid parameter */
static int32_t smccc_arch_id(u_register_t arg1)
{
	if (arg1 == SMCCC_GET_SOC_REVISION) {
		return plat_get_soc_revision();
	}
	if (arg1 == SMCCC_GET_SOC_VERSION) {
		return plat_get_soc_version();
	}
	return SMC_ARCH_CALL_INVAL_PARAM;
}

#if ENABLE_HHKRD
unsigned int plat_is_my_cpu_primary(void);

static int32_t hhkrd_status(void) {
    uint64_t scr;
    asm volatile(
        "mrs %0, HCR_EL2\n"
        : "=r"(scr) ::
    );
    NOTICE("<hhkrd_status> hcr_el2: 0x%llx.\n",scr);

    asm volatile(
        "mrs %0, SCR_EL3\n"
        : "=r"(scr) ::
    );
    NOTICE("<hhkrd_status> scr_el3: 0x%llx.\n",scr);

    if (plat_is_my_cpu_primary() == 1U) {
		u_register_t gptbr_el3 = read_gptbr_el3();
		NOTICE("primary CPU gptbr_el3:%lx\n",gptbr_el3);
	}

	if (plat_is_my_cpu_primary() == 0U) {
		u_register_t gptbr_el3 = read_gptbr_el3();
		NOTICE("secondary CPU gptbr_el3:%lx\n",gptbr_el3);
	}
	return MAKE_SMCCC_VERSION(SMCCC_MAJOR_VERSION, SMCCC_MINOR_VERSION);
}
#endif

/*
 * Top-level Arm Architectural Service SMC handler.
 */
static uintptr_t arm_arch_svc_smc_handler(uint32_t smc_fid,
	u_register_t x1,
	u_register_t x2,
	u_register_t x3,
	u_register_t x4,
	void *cookie,
	void *handle,
	u_register_t flags)
{
#if ENABLE_HHKRD
	u_register_t x5, x6, x7;
#endif
	switch (smc_fid) {
	case SMCCC_VERSION:
		SMC_RET1(handle, smccc_version());
	case SMCCC_ARCH_FEATURES:
		SMC_RET1(handle, smccc_arch_features(x1));
	case SMCCC_ARCH_SOC_ID:
		SMC_RET1(handle, smccc_arch_id(x1));
#if ENABLE_HHKRD
	case HHKRD_NEW_TEST:
		x5 = SMC_GET_GP(handle, CTX_GPREG_X5);
		x6 = SMC_GET_GP(handle, CTX_GPREG_X6);
		x7 = SMC_GET_GP(handle, CTX_GPREG_X7);
		SMC_RET1(handle, hhkrd_prog_create(x1, x2, x3, x4, x5, x6, x7));
	case HHKRD_EXCEPTION:
		SMC_RET1(handle, hhkrd_os_exception_request());
	case HHKRD_SETPAGE:
		SMC_RET1(handle, hhkrd_set_page(x1, x2, x3));
	case HHKRD_EXIT_THREAD:
		SMC_RET1(handle, hhkrd_exit_thread(x1, x2));
	case HHKRD_STATUS:
		SMC_RET1(handle, hhkrd_status());
	case HHKRD_ASSIGN_SHARE:
		SMC_RET1(handle, hhkrd_assign_share_mem(x1, x2, x3));
	case HHKRD_ENTER:
		SMC_RET1(handle, hhkrd_sched_in());
	case HHKRD_MEMEXPAND:
		SMC_RET1(handle, hhkrd_memexpand(x1, x2));
	case HHKRD_CLONE:
		SMC_RET1(handle, hhkrd_clone(x1, x2, x3, x4));
	case HHKRD_DESTROY:
		SMC_RET1(handle, hhkrd_destruct(x1, x2));
	case HHKR_SECURE_BUF:
		SMC_RET1(handle, hhkr_secure_buf(x1, x2, x3));
	case HHKRD_FREEBACK_BUFS:
		SMC_RET1(handle, hhkrd_freeback_bufs(x1));
	/* secure IO */
	case HHKRD_INIT_SECIO:
		x5 = SMC_GET_GP(handle, CTX_GPREG_X5);
		x6 = SMC_GET_GP(handle, CTX_GPREG_X6);
		SMC_RET1(handle, hhkrd_secIO_init(x1, x2, x3, x4, x5, x6));
	case HHKRD_DO_SECIO:
		SMC_RET1(handle, hhkrd_secIO_assignjob(x1, x2, x3));
	// case HHKRD_INIT_SECIO_JUNO:
	// 	x5 = SMC_GET_GP(handle, CTX_GPREG_X5);
	// 	x6 = SMC_GET_GP(handle, CTX_GPREG_X6);
	// 	x7 = SMC_GET_GP(handle, CTX_GPREG_X7);
	// 	SMC_RET1(handle, hhkrd_secIO_init_juno(x1, x2, x3, x4, x5, x6, x7));
	// case HHKRD_ASSIGN_SECIO_JUNO:
	// 	SMC_RET1(handle, hhkrd_secIO_assignjob_juno(x1, x2, x3));
	/* omni write */
	case HHKR_INIT_OMNI_BUF:
		SMC_RET1(handle, hhkr_init_omni_buffers(x1, x2));
	case HHKR_WRITE_OMNI_BUF:
		SMC_RET1(handle, hhkr_write_omni_buf(x1, x2));
#endif
#if WORKAROUND_CVE_2017_5715
	case SMCCC_ARCH_WORKAROUND_1:
		/*
		 * The workaround has already been applied on affected PEs
		 * during entry to EL3.  On unaffected PEs, this function
		 * has no effect.
		 */
		SMC_RET0(handle);
#endif
#if WORKAROUND_CVE_2018_3639
	case SMCCC_ARCH_WORKAROUND_2:
		/*
		 * The workaround has already been applied on affected PEs
		 * requiring dynamic mitigation during entry to EL3.
		 * On unaffected or statically mitigated PEs, this function
		 * has no effect.
		 */
		SMC_RET0(handle);
#endif
	default:
#if ENABLE_RME
		/*
		 * RMI functions are allocated from the Arch service range. Call
		 * the RMM dispatcher to handle RMI calls.
		 */
		if (is_rmi_fid(smc_fid)) {
			return rmmd_rmi_handler(smc_fid, x1, x2, x3, x4, cookie,
						handle, flags);
		}
#endif
		WARN("Unimplemented Arm Architecture Service Call: 0x%x \n",
			smc_fid);
		SMC_RET1(handle, SMC_UNK);
	}
}

/* Register Standard Service Calls as runtime service */
DECLARE_RT_SVC(
		arm_arch_svc,
		OEN_ARM_START,
		OEN_ARM_END,
		SMC_TYPE_FAST,
#if ENABLE_RME
		arm_arch_svc_setup,
#else
		NULL,
#endif
		arm_arch_svc_smc_handler
);
