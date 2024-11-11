#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args * ctx) {
	int x = bpf_test_call_func();
    bpf_printk("testing. %d\n", x);

    char tempbuf[] = "hahaha";
    bpf_copy_to_buf(tempbuf, 6);
    return 0;
}

char _license[] SEC("license") = "GPL";
