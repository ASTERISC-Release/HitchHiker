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

#define CMA_PATH "/dev/cma_demo"

struct CMA_demo_info
{
    unsigned long virt;
    unsigned long phys;
    unsigned long offset;
    unsigned long length;
};

int main()
{
    struct CMA_demo_info cma_region_info;
    void *base;
    int i, fd;

    /* open device */
    fd = open(CMA_PATH, O_RDWR, 0);
    if (fd < 0)
    {
        printf("[CMA_user] can't open %s\n", CMA_PATH);
        return -1;
    }

    /* tzasc controller initialize in BL31 (only once) */
    if (ioctl(fd, CMA_TZASC_SETUP, NULL) < 0) {
        printf("[CMA_user] tzasc controller setup failed.\n");
        return -1;
    }

    /* fast_memcpy test */
    if (ioctl(fd, CMA_FAST_MEMCPY_TEST, NULL) < 0) {
        printf("[CMA_user] fast memcepy test failed.\n");
    }
    
    /* TZASC transition command invoke
     * In kernel module:
     * 1. transition memory region -> S
     * 2. transition memory region back -> NS
     */
    /* prepare tests */
    int test_memsz_arr[] = {MEM_SZ_1MB, MEM_SZ_4MB, MEM_SZ_16MB, MEM_SZ_64MB, MEM_SZ_256MB};
    
    for (i = 0; i < sizeof(test_memsz_arr) / sizeof(int); i++) {
        memset(&cma_region_info, 0, sizeof(cma_region_info));
        cma_region_info.length = test_memsz_arr[i]; 
        cma_region_info.phys = 0;      /* auto physical address */
        
        printf("********* CMA_user: Start TZASC Test (%lu MB).\n",
            cma_region_info.length / (MEM_SZ_1MB));
        if (ioctl(fd, CMA_TZASC_TEST, &cma_region_info) < 0)
        {
            printf("[CMA_user] tzasc test failed.\n");
            return -1;
        }
        printf("********* CMA_user: End TZASC Test (%lu MB).\n",
            cma_region_info.length / (MEM_SZ_1MB));
    }
    /* clean up */
    close(fd);
    return 0;
}