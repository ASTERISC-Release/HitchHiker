#include <linux/mm.h>
#include <linux/cma.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/dma-contiguous.h>
#include <linux/arm-smccc.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <asm/pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <linux/stat.h>

#include <linux/genhd.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>

#define pr_fmt(fmt) "sata-replay: " fmt
#define log_info(fmt, arg...) \
    printk(KERN_INFO "[%s][%d] "pr_fmt(fmt)"", __func__, __LINE__, ##arg)
#define log_err(fmt, arg...) \
    printk(KERN_ERR "[%s][%d] "pr_fmt(fmt)"", __func__, __LINE__, ##arg)


#define ETE_DRIVER_NAME "ete_driver"

// refer to el1_self_hosted_trace example:
// https://developer.arm.com/documentation/102856/0100/Trace-capture-examples/el1-self-hosted-trace-example 

// should be done in EL3
/* this is invoked at bl31_main() */
// static inline void el3_setup_trbe() {
//     asm volatile("MRS x0, MDCR_EL2\n"               
//                  "ORR x0, x0, #(3 << 24)\n"         // E2TB=0b11 Trace Buffer owning Exception level is EL1
//                  "MSR MDCR_EL2, x0\n"
//                  "MRS x0, MDCR_EL3\n"
//                  "ORR x0, x0, #(3 << 24)\n"         // NSTB=0b11 Trace Buffer is non-secure
//                  "MSR MDCR_EL3, x0"
//                  ::: "x0", "cc", "memory"
//     );
// }

typedef struct {
    /* The (kernel space) base virtual address */
    unsigned long virt_addr;
    /* The base physical address */
    unsigned long phys_addr;
    /* Current data position */
    unsigned long cur_pos;
    /* total size */
    unsigned long length;
} log_buf_t;

extern log_buf_t *get_current_log_buf(void);

/* setup TRBE in EL1 */
static inline void setup_trbe(unsigned long base_addr, unsigned long limit_addr) {
    asm volatile(
        "MOV w0, #0\n"
        "LDR x0, =%[base_addr]\n"
        "MSR TRBBASER_EL1, x0\n"   // Trace buffer Base pointer address

        "MOV x0, #0\n"
        "LDR x0, =%[limit_addr]\n"
        "ORR x0, x0, #(3 << 3)\n"  // TM=0b11 Ignore trigger
        "ORR x0, x0, #(3 << 1)\n"  // FM=0b11 circular buffer mode
        "ORR x0, x0, #(1 << 5)\n"  // nVM=0b1 trace buffer pointers are PA
        "MSR TRBLIMITR_EL1, x0\n"  // Trace Buffer Limit pointer address
        
        "LDR x0, =%[base_addr]\n"
        "MSR TRBPTR_EL1, x0"     // PTR: Trace Buffer current write pointer address (PA)
        :: [base_addr] "r" (base_addr), [limit_addr] "r" (limit_addr)
        : "x0", "cc", "memory"
    );

    /* check */
    unsigned long trbbaser_el1, trblimitr_el1, trbptr_el1;
    asm volatile(
        "MRS %[trbbaser_el1], TRBBASER_EL1\n"
        "MRS %[trblimitr_el1], TRBLIMITR_EL1\n"
        "MRS %[trbptr_el1], TRBPTR_EL1\n"
        : [trbbaser_el1] "=r" (trbbaser_el1), [trblimitr_el1] "=r" (trblimitr_el1), [trbptr_el1] "=r" (trbptr_el1)
        :: "cc", "memory"
    );
    log_info("trbbaser_el1: 0x%lx, trblimitr_el1: 0x%lx, trbptr_el1: 0x%lx.\n", 
             trbbaser_el1, trblimitr_el1, trbptr_el1);
}

/* setup ETE in EL1 */
static inline void setup_ete(void) {
    asm volatile(
        "MOV x0, #0\n"                     
        "MSR OSLAR_EL1, x0\n"              // OSLK=0 unlock OS lock register

        "MOV x0, #0\n"
        "ORR x0, x0, #(1 << 12)\n"    // RS=1         Return stack enabled
        "ORR x0, x0, #(1 << 7)\n"     // VMID=1       Virtual context identifier tracing enabled
        "ORR x0, x0, #(1 << 6)\n"     // CID=1        Context identifier tracing enabled
        "ORR x0, x0, #1\n"            // 1=1
        "MSR TRCCONFIGR, x0\n"
        
        "MOV x0, #0xC\n"
        "MSR TRCSYNCPR, x0\n"         // PERIOD=0xC Enable trace protocol synchronization every 4096 bytes of trace
        
        "MOV x0, #0x2\n"
        "MSR TRCTRACEIDR, x0\n"       // TRACEID=0x2 Trace ID for the trace stream

        "MOV x0, #0\n"
        "ORR x0, x0, #(1 << 22)\n"       // EXLEVEL_NS_EL2=1      Trace unit does not generate instruction trace for EL2 in Non-secure state
        //"ORR x0, x0, #(0 << 21)\n"     // EXLEVEL_NS_EL1=0      Trace unit generate instruction trace for EL1 in Non-secure state
        "ORR x0, x0, #(1 << 20)\n"       // EXLEVEL_NS_EL0=1      Trace unit does not generate instruction trace for EL0 in Non-secure state
        "ORR x0, x0, #(1 << 19)\n"       // EXLEVEL_S_EL3=1       Trace unit does not generate instruction trace for EL3 in Secure state
        "ORR x0, x0, #(1 << 18)\n"       // EXLEVEL_S_EL2=1       Trace unit does not generate instruction trace for EL2 in Secure state
        "ORR x0, x0, #(1 << 17)\n"       // EXLEVEL_S_EL1=1       Trace unit does not generate instruction trace for EL1 in Secure state
        "ORR x0, x0, #(1 << 16)\n"       // EXLEVEL_S_EL0=1       Trace unit does not generate instruction trace for EL0 in Secure state
        "ORR x0, x0, #(1 << 9)\n"        // SSSTATUS=1            The ViewInst start/stop functions is in the started state
        "ORR x0, x0, #1\n"               // EVENT.SEL=0b0001      Selects Resource Selector 1
        "MSR TRCVICTLR, x0\n"

        "MOV x0, #0x16\n"                // THRESHOLD=0x16    Sets the threshold value for instruction trace cycle counting to 0x16
        "MSR TRCCCCTLR, x0\n"

        "MOV x0, #0\n"
        "MSR TRCEVENTCTL0R, x0\n"         // Disable all event tracing
        "MSR TRCEVENTCTL1R, x0\n"         // Disable all event tracing
        "MSR TRCSTALLCTLR, x0\n"          // Disable stalling, if implemented
        "MSR TRCTSCTLR, x0\n"             // Disable the timestamp event
        "MSR TRCVIIECTLR, x0\n"           // No address range filtering for logic started
        "MSR TRCVISSCTLR, x0\n"           // No start or stop points for ViewInst
        "MSR TRCBBCTLR, x0\n"             // Deactivate branch broadcasting for all address ranges
        // Program only if TRCIDR4.NUMPC, number of PE Comparator Inputs that are available for tracing, > 0
        // MOV      x0, 0x0
        // MSR      TRCVIPCSSCTLR, x0               // No PE Comparator Input m is not selected as a trace stop resource
        "MOV x0, #0\n"
        "MSR TRCRSR, x0\n"               // Set the trace resource status to 0
        "MOV x0, #3\n"                   // E0TRE=1, E1TRE=1     EL0 and EL1 tracing enabled
        "MSR TRFCR_EL1, x0\n"             
        "ISB"
    );
}

/* enable trbe: TRBE must be enabled before ETE */
static inline void enable_trbe(void) {
    asm volatile(
        "MOV x0, #0\n"
        "MSR TRBSR_EL1, x0\n"       
        
        "MRS x0, TRBLIMITR_EL1\n"
        "ORR x0, x0, #1\n"    // E=1 Enable trace buffer
        "MSR TRBLIMITR_EL1, x0\n"
        "ISB"
    );
}

/* enable ETE */
static inline void enable_ete(void) {
    asm volatile(
        "ISB\n"
        "MOV x0, #0x1\n"
        "MSR TRCPRGCTLR, x0\n"    // EN=1 Enable ETE
        "ISB"
    );
}

static inline void disable_ete(void) {
    asm volatile(
        "STP x0, x1, [sp, #-16]!\n"
        "MRS x0, TRFCR_EL1\n"   // save the current programming of TRFCR_EL1
        "MOV x1, #0x3\n"
        "BIC x1, x0, x1\n"      // clear the values of TRFCR_EL1.ExTRE
        "MSR TRFCR_EL1, x1\n"   // to put the PE in to a prohibited region
        
        "ISB\n"                 // Synchronize the entry to the prohibited region
        "TSB CSYNC\n"           // Ensure that all trace has reached the trace buffer and address translations have taken place 

        "MOV x1, #0\n"
        "MSR TRCPRGCTLR, x1\n"  // EN=0 disable ETE
        
        // wait for TRCSTATR.IDLE==1 and TRCSTATR.PMSTABLE==1
        "poll_idle: ISB\n"
        "MRS x1, TRCSTATR\n"
        "TST x1, #3\n"
        "BEQ poll_idle\n"

        "MSR TRFCR_EL1, x0\n"       // restore the original programming of TRFCR_EL1
        "LDP x0, x1, [sp], #16\n"
        "ISB" ::
        : "x0", "x1", "cc", "memory"
    );
}

static inline void disable_trbe(void) {
    asm volatile(
        "MRS x0, TRBLIMITR_EL1\n"
        "BIC x0, x0, #1\n"        // E=0 Disable trace buffer
        "MSR TRBLIMITR_EL1, x0\n"
        "ISB"
    );   
}

static int __init ete_test_init(void) {
    log_buf_t *cur_buf = get_current_log_buf();
    log_info("cur_buf phys_base: 0x%lx, virt_base: 0x%lx\n", cur_buf->phys_addr, cur_buf->virt_addr);
    /* setup trbe */
    setup_trbe(cur_buf->phys_addr, cur_buf->phys_addr + cur_buf->length);
    /* setup ete */
    setup_ete();
    return 0;
}


static void __exit ete_test_exit(void) {
    disable_ete();
    disable_trbe();
}

module_init(ete_test_init);
module_exit(ete_test_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("chuqi zhang");
MODULE_DESCRIPTION("ete test");