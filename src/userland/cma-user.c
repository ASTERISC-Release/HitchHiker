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

#define CMA_PATH		"/dev/cma_demo"

struct CMA_demo_info {
	unsigned long virt;
	unsigned long phys;
	unsigned long offset;
	unsigned long length;
};


int main() {
    struct CMA_demo_info cma_region_info;
    void *base;
    int i, fd; 

    /* open device */
    fd = open(CMA_PATH, O_RDWR, 0);
    if (fd < 0) {
        printf("[CMA_user] can't open %s\n", CMA_PATH);
        return -1;
    }

    /* setup tzasc controller */
    // if (ioctl(fd, CMA_TZASC_SETUP, &cma_region_info) < 0) {
    //     printf("[CMA_user] tzasc controller setup failed.\n");
    //     return -1;
    // }

    /* prepare tests */
    int test_memsz_arr[] = {MEM_SZ_4KB, MEM_SZ_16KB, MEM_SZ_32KB, MEM_SZ_64KB, MEM_SZ_128KB, MEM_SZ_256KB, MEM_SZ_512KB, MEM_SZ_1MB, MEM_SZ_4MB, MEM_SZ_16MB, MEM_SZ_64MB, MEM_SZ_256MB};
    
    /* tests */
    for (i = 0; i < sizeof(test_memsz_arr) / sizeof(int); i++) {
        memset(&cma_region_info, 0, sizeof(cma_region_info));
        cma_region_info.length = test_memsz_arr[i]; 
        cma_region_info.phys = 0;      /* auto physical address */
        
        // ********* start GPT Transition Test ********
        printf("********* CMA_user: Start GPT Transition Test (%lu MB).\n",
               cma_region_info.length / (MEM_SZ_1MB));
        if (ioctl(fd, CMA_MEM_ALLOCATE, &cma_region_info) < 0) {
            printf("[CMA_user] cma memory allocate failed.\n");
            return -1;
        }
        printf("********* CMA_user: End GPT Transition Test (%lu MB).\n",
               cma_region_info.length / (MEM_SZ_1MB));
        // ********* end GPT Transition Test **********
        
        /* info */
        printf("[CMA_user] Phys: %#lx - %#lx\n", cma_region_info.phys,
        				cma_region_info.phys + cma_region_info.length);
        printf("[CMA_user] Virt (info): %#lx - %#lx\n", (unsigned long) cma_region_info.virt,
        				(unsigned long)cma_region_info.virt + cma_region_info.length);
        /* release */
        if (ioctl(fd, CMA_MEM_RELEASE, &cma_region_info) < 0) {
            printf("[CMA_user] CMA memory release ioctl failed\n");
            close(fd);
            return -1;
        }

        cma_region_info.length = test_memsz_arr[i];
        cma_region_info.phys = 0; /* auto physical address */

        // ********* start EL3 Memcpy Test ************
        printf("********* CMA_user: Start EL3 memcpy Test (%lu MB).\n",
               cma_region_info.length / (MEM_SZ_1MB));
        if (ioctl(fd, CMA_EL3_MEMCPY_TEST, &cma_region_info) < 0) {
            printf("[CMA_user] CMA_EL3_memcpy_test ioctl failed\n");
            close(fd);
            return -1;
        }
        printf("********* CMA_user: End EL3 memcpy Test (%lu MB).\n",
               cma_region_info.length / (MEM_SZ_1MB));
        // ********* end EL3 Memcpy Test **************

        // ********* start SMC EMPTY Test *************
        printf("********* CMA_user: Start SMC empty Test.\n");
        if (ioctl(fd, CMA_SMC_EMPTY_TEST, 0) < 0) {
            printf("[CMA_user] CMA_SMC_EMPTY_TEST ioctl failed\n");
            close(fd);
            return -1;
        }
        printf("********* CMA_user: End SMC empty Test.\n");
        // ********* end SMC EMPTY Test ***************

        
        // ********* start TZASC Test *****************
        // printf("********* CMA_user: Start TZASC Test (%lu MB).\n",
        //        cma_region_info.length / (MEM_SZ_1MB));
        // if (ioctl(fd, CMA_TZASC_TEST, &cma_region_info) < 0) {
        //     printf("[CMA_user] tzasc test failed.\n");
        //     return -1;
        // }
        // printf("********* CMA_user: End TZASC Test (%lu MB).\n",
        //        cma_region_info.length / (MEM_SZ_1MB));
        // ********* end TZASC Test *******************
    }

    /* clean up */
    close(fd);
    return 0;
}


// backups
/* allocate memory from CMA */
// if (ioctl(fd, CMA_MEM_ALLOCATE, &cma_region_info) < 0) {
//     printf("[CMA_user] cma memory allocate failed.\n");
//     return -1;
// }

// /* mmap physical address into user space */
// base = mmap(NULL, cma_region_info.length, PROT_READ | PROT_WRITE,
//                 MAP_SHARED, fd, cma_region_info.phys);
// if (base == MAP_FAILED) {
//     printf("[CMA_user] mmap failed.\n");
//     close(fd);
//     return -1;
// }
// // char * userbuf = (char *)malloc(sizeof(char) * cma_region_info.length);
// // printf("[CMA_user] prepare to memcpy size: %lu, src: 0x%p, dst: 0x%p.\n",
// //        cma_region_info.length, base, userbuf);
// // memcpy(userbuf, base, sizeof(char) * cma_region_info.length);
// // userbuf[49] = '\0';
// /* info */
// printf("Phys: %#lx - %#lx\n", cma_region_info.phys,
// 				cma_region_info.phys + cma_region_info.length);
// printf("Virt (base): %#lx - %#lx\n", (unsigned long) base,
// 				(unsigned long)base + cma_region_info.length);
// printf("Virt (info): %#lx - %#lx\n", (unsigned long) cma_region_info.virt,
// 				(unsigned long)cma_region_info.virt + cma_region_info.length);

// /* Unmmap */
// munmap(base, cma_region_info.length);
/* free memory from cma */
// if (ioctl(fd, CMA_MEM_RELEASE, &cma_region_info) < 0) {
//     printf("[CMA_user] CMA memory release ioctl failed\n");
// 	close(fd);
// 	return -1;
// }

/* memcpy test */
// if (ioctl(fd, CMA_EL3_MEMCPY_TEST, &cma_region_info) < 0) {
//     printf("[CMA_user] CMA_EL3_memcpy_test ioctl failed\n");
//     close(fd);
//     return -1;
// }
// close(fd);
// return 0;