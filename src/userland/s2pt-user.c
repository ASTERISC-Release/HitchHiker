/*
 * Contiguous Memory Allocate Application
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdarg.h>

#include <test_defs.h>

#define DEV_PATH "/dev/s2pt_device"

#define CMD(x)  _IO(77, x)

int main()
{
    void *base;
    int i, fd;

    /* open device */
    fd = open(DEV_PATH, O_RDWR, 0);
    if (fd < 0)
    {
        printf("[s2pt_user] can't open %s\n", DEV_PATH);
        return -1;
    }

    /* prepare tests */
    int test_memsz_arr[] = {MEM_SZ_4KB, MEM_SZ_16KB, MEM_SZ_32KB, MEM_SZ_64KB, MEM_SZ_128KB, MEM_SZ_256KB, MEM_SZ_512KB, MEM_SZ_1MB, MEM_SZ_4MB, MEM_SZ_16MB, MEM_SZ_64MB, MEM_SZ_256MB};

    /* tests */
    for (i = 0; i < sizeof(test_memsz_arr) / sizeof(int); i++)
    {
        
        int test_mem_length = test_memsz_arr[i];
        // ********* start s2pt Transition Test ********
        printf("********* s2pt_user: Start S2PT Transition Test (%u MB).\n",
               test_mem_length / (MEM_SZ_1MB));
        if (ioctl(fd, CMD(11), test_mem_length / (1 << 12)) < 0)
        {
            printf("[s2pt_user] memory allocate failed.\n");
            return -1;
        }
        printf("********* s2pt_user: End S2PT Transition Test (%u MB).\n",
               test_mem_length / (MEM_SZ_1MB));
        // ********* end s2pt Transition Test **********
    }

    /* clean up */
    close(fd);
    return 0;
}