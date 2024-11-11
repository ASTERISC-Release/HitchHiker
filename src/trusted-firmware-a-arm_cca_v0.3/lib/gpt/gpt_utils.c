#include <lib/gpt/gpt_utils.h>

long long gptutils_get_cpu_cycle() {
    long long cur = 0;
    /* performance monitors cycle count register */
    asm volatile("mrs %[result], pmccntr_el0" : [result] "=r" (cur));
    return cur;
}
