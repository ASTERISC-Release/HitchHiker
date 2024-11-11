#define _GNU_SOURCE
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

#define SHELTER_DEBUG 0

#define DEV_PATH		"/dev/tl-intf"

#define __NR_trustd_exec 436


int main(int argc, char *argv[], char *envp[])
{
	printf("[DEBUG]PID=%d\n", getpid());

	int fd, fd_sda;

	fd = open(DEV_PATH, O_RDWR, 0);
	printf("fd for /dev/tl-intf: %d\n", fd);
	if (fd < 0) {
		printf("Can't open %s\n", DEV_PATH);
		return -1;
	}

    /* cmd 100 */
	if (ioctl(fd, 100, NULL) < 0) {
        printf("ioctl 100 failed\n");
		return -1;
	}

	close(fd);
	return 0;
}