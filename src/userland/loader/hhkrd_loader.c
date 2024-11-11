#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdarg.h>

#include <arch_def.h>
#include "def.h"


#define DEV_PATH		"/dev/hitchhiker-ctl"
#define HHKRD			"/data/hhkrd-io-test"

#define __NR_hhkrd_exec 436


#define MAX_ARGS 20

int main(int argc, char *argv[], char *envp[])
{
	char *args[MAX_ARGS];

	printf("[omnid_loader] PID=%d\n", getpid());
	
	char *elf_path= "/data/hhkrd-io-test";

    hhkrd_mem_info_t meminfo;
	int hhkr_ctl_fd;

	if ((hhkr_ctl_fd = open(DEV_PATH, O_RDWR, 0)) < 0) {
		printf("Can't open %s\n", DEV_PATH);
		return -1;
	}

    /* disable close_on_exec */
    int flags = fcntl(hhkr_ctl_fd, F_GETFD);
    flags &= ~FD_CLOEXEC;
    fcntl(hhkr_ctl_fd, F_SETFD, flags);

	memset(&meminfo, 0, sizeof(meminfo));
	meminfo.length = 0x400000;    // 4MB

	printf("[hhkrd_loader] Allocate user meminfo address: %p.\n", &meminfo);
    
	/* Allocate CMA memory for hhkrd */
	if (ioctl(hhkr_ctl_fd, HHKRD_AL_ALLOCATE, &meminfo) < 0) {
		printf("TD_AL_ALLOCATE: ioctl failed\n");
		return -1;
	}

    printf("[hhkrd_loader] start hhkrd: %s.\n", HHKRD);

	//load trustd
	syscall(__NR_hhkrd_exec, hhkr_ctl_fd, HHKRD, NULL, NULL);
    // syscall(__NR_hhkrd_exec, hhkr_ctl_fd, elf_path, args, NULL);
	close(hhkr_ctl_fd);
	return 0;
}
