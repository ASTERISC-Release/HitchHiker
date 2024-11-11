// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include "bpf_load.h"

int main(int ac, char **argv)
{
	// FILE *f;
	char filename[256];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	read_trace_pipe();

	return 0;
}
